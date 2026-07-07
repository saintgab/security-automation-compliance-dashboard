#!/usr/bin/env python3
"""
evidence.py -- compliance evidence automation (the "Drata-style" step).

    data/findings.db  â”€â”€â–º  evaluate each catalog control  â”€â”€â–º  hashed evidence
    (same DB the           against matching AWS Security      artifacts + manifest
     dashboard reads)      Hub findings                       + human-readable report

This does NOT re-scan AWS. It re-uses whatever the collector already pulled
into data/findings.db -- the point of automating evidence collection is that
you don't run a separate manual process to prove a control is met; you prove
it from the same system of record the dashboard uses.

Each control gets:
  - a JSON evidence export (raw matching findings, exactly as ingested)
  - a status: PASS / PASS_WITH_EXCEPTION / FAIL / NOT_OBSERVED
  - a SHA-256 hash of that export, so the manifest can prove the evidence
    file wasn't edited after the fact -- the same property a real evidence
    tool needs for an evidence file to be auditable rather than just a log.

Usage:
    python collect.py          # populate the database first
    python evidence.py         # generate an evidence snapshot from it
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from compliance.control_catalog import CONTROL_CATALOG

ROOT = Path(__file__).parent
DB_PATH = ROOT / "data" / "findings.db"
EVIDENCE_ROOT = ROOT / "data" / "evidence"

TERMINAL_PASS = {"resolved"}
EXCEPTION_STATUS = {"accepted_risk"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_evidence_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS evidence_runs (
            evidence_run_id   TEXT PRIMARY KEY,
            generated_at      TEXT NOT NULL,
            control_count     INTEGER NOT NULL,
            pass_count        INTEGER NOT NULL,
            exception_count   INTEGER NOT NULL,
            fail_count        INTEGER NOT NULL,
            not_observed_count INTEGER NOT NULL,
            manifest_path     TEXT NOT NULL
        );
        """
    )
    conn.commit()


def evaluate_control(conn: sqlite3.Connection, control_id: str) -> tuple[str, list[dict]]:
    """
    Returns (status, matching_findings). Matches on the same convention the
    mock Security Hub source uses: finding titles are formatted as
    "{control_id} {description}", e.g. "IAM.1 root account access key exists".
    """
    rows = conn.execute(
        "SELECT * FROM findings WHERE source = 'aws_security_hub' AND title LIKE ? ORDER BY first_seen",
        (f"{control_id} %",),
    ).fetchall()
    matching = [dict(r) for r in rows]

    if not matching:
        return "NOT_OBSERVED", matching

    open_findings = [m for m in matching if m["status"] not in TERMINAL_PASS and m["status"] not in EXCEPTION_STATUS]
    if open_findings:
        return "FAIL", matching

    exceptions = [m for m in matching if m["status"] in EXCEPTION_STATUS]
    if exceptions:
        return "PASS_WITH_EXCEPTION", matching

    return "PASS", matching


def auditor_note(control_id: str, status: str, matching: list[dict], as_of: str) -> str:
    if status == "NOT_OBSERVED":
        return (
            f"No AWS Security Hub findings have been recorded against control {control_id} in this "
            "collection window. This is not, by itself, evidence of compliance -- it means the control "
            "has not triggered a finding. Confirm the underlying Security Hub check is enabled and "
            "actively evaluating this control before relying on this status for an audit response."
        )
    if status == "FAIL":
        n = len([m for m in matching if m["status"] not in TERMINAL_PASS and m["status"] not in EXCEPTION_STATUS])
        return (
            f"Control {control_id} has {n} open, unresolved finding(s) as of {as_of}. "
            "Remediation SLA and severity for this control are defined in AWS_Security_Baseline.docx, "
            "Appendix A. This control cannot be marked satisfied until those findings resolve or move "
            "to a documented risk acceptance."
        )
    if status == "PASS_WITH_EXCEPTION":
        n = len([m for m in matching if m["status"] in EXCEPTION_STATUS])
        return (
            f"Control {control_id} has {n} finding(s) currently under documented risk acceptance "
            "(status: accepted_risk) rather than open or resolved. Per baseline Section 7, each "
            "exception requires a named approver, written justification, and a re-review date within "
            "180 days -- see the risk acceptance record for approver details, which are tracked outside "
            "this pipeline in the exception log."
        )
    return (
        f"All findings previously raised against control {control_id} are resolved as of {as_of}. "
        "No open findings and no active risk-acceptance exceptions exist for this control."
    )


def sha256_of_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_report_markdown(run_id: str, generated_at: str, control_results: list[dict]) -> str:
    total = len(control_results)
    passed = sum(1 for c in control_results if c["status"] == "PASS")
    excepted = sum(1 for c in control_results if c["status"] == "PASS_WITH_EXCEPTION")
    failed = sum(1 for c in control_results if c["status"] == "FAIL")
    not_observed = sum(1 for c in control_results if c["status"] == "NOT_OBSERVED")
    compliance_pct = 100 * (passed + excepted) / total if total else 0.0

    # Build display symbols from Unicode code points.
    # This keeps the Python source file ASCII-safe while the generated Markdown is UTF-8.
    em_dash = chr(0x2014)
    ellipsis = chr(0x2026)
    status_icon = {
        "PASS": chr(0x2705) + " PASS",
        "PASS_WITH_EXCEPTION": chr(0x1F7E3) + " EXCEPTION",
        "FAIL": chr(0x1F534) + " FAIL",
        "NOT_OBSERVED": chr(0x26AA) + " NOT OBSERVED",
    }

    lines = [
        "# Compliance Evidence Report",
        "",
        f"**Evidence run:** `{run_id}`  ",
        f"**Generated:** {generated_at}  ",
        f"**Source of record:** `data/findings.db` (same database the dashboard reads)",
        "",
        f"**Overall control satisfaction: {compliance_pct:.0f}%** "
        f"({passed} pass, {excepted} pass-with-exception, {failed} fail, {not_observed} not observed, of {total} controls)",
        "",
        "| Control | SOC 2 | ISO 27001 | Status | Evidence file | SHA-256 |",
        "|---|---|---|---|---|---|",
    ]

    for c in control_results:
        control_label = f"{c['control_id']} {em_dash} {c['control_name']}"
        short_hash = f"{c['sha256'][:16]}{ellipsis}"

        lines.append(
            f"| {control_label} | {', '.join(c['soc2_criteria'])} | "
            f"{', '.join(c['iso27001_ref'])} | {status_icon[c['status']]} | "
            f"`{c['evidence_file']}` | `{short_hash}` |"
        )

    lines += ["", "## Auditor notes", ""]

    for c in control_results:
        control_label = f"{c['control_id']} {em_dash} {c['control_name']}"
        lines.append(f"**{control_label}**  ")
        lines.append(c["auditor_note"])
        lines.append("")

    return "\n".join(lines)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--db", type=Path, default=DB_PATH)
    args = parser.parse_args()

    if not args.db.exists():
        print(f"No database found at {args.db}. Run collect.py first.")
        return 1

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    ensure_evidence_tables(conn)

    run_id = str(uuid.uuid4())
    generated_at = utc_now_iso()
    run_dir = EVIDENCE_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    control_results = []
    for entry in CONTROL_CATALOG:
        control_id = entry["control_id"]
        status, matching = evaluate_control(conn, control_id)
        note = auditor_note(control_id, status, matching, generated_at)

        evidence_payload = {
            "control_id": control_id,
            "control_name": entry["control_name"],
            "requirement": entry["requirement"],
            "soc2_criteria": entry["soc2_criteria"],
            "iso27001_ref": entry["iso27001_ref"],
            "status": status,
            "evaluated_at": generated_at,
            "evidence_source": "AWS Security Hub findings, ingested via collect.py",
            "matching_findings": matching,
            "auditor_note": note,
        }
        evidence_file = run_dir / f"{control_id}.json"
        evidence_file.write_text(json.dumps(evidence_payload, indent=2, default=str), encoding="utf-8")
        digest = sha256_of_file(evidence_file)

        control_results.append(
            {
                "control_id": control_id,
                "control_name": entry["control_name"],
                "soc2_criteria": entry["soc2_criteria"],
                "iso27001_ref": entry["iso27001_ref"],
                "status": status,
                "evidence_file": str(evidence_file.relative_to(ROOT)),
                "sha256": digest,
                "auditor_note": note,
            }
        )

    manifest = {
        "evidence_run_id": run_id,
        "generated_at": generated_at,
        "controls": control_results,
    }
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    report_md = generate_report_markdown(run_id, generated_at, control_results)
    report_path = run_dir / "Compliance_Evidence_Report.md"
    report_path.write_text(report_md, encoding="utf-8")
    # Also drop a stable "latest" copy for easy linking from a README.
    (EVIDENCE_ROOT / "latest_report.md").write_text(report_md, encoding="utf-8")

    pass_count = sum(1 for c in control_results if c["status"] == "PASS")
    exc_count = sum(1 for c in control_results if c["status"] == "PASS_WITH_EXCEPTION")
    fail_count = sum(1 for c in control_results if c["status"] == "FAIL")
    not_obs_count = sum(1 for c in control_results if c["status"] == "NOT_OBSERVED")

    conn.execute(
        """INSERT INTO evidence_runs
           (evidence_run_id, generated_at, control_count, pass_count, exception_count,
            fail_count, not_observed_count, manifest_path)
           VALUES (?,?,?,?,?,?,?,?)""",
        (run_id, generated_at, len(control_results), pass_count, exc_count, fail_count,
         not_obs_count, str(manifest_path.relative_to(ROOT))),
    )
    conn.commit()
    conn.close()

    print(f"Evidence run {run_id} complete.")
    print(f"  {pass_count} PASS / {exc_count} EXCEPTION / {fail_count} FAIL / {not_obs_count} NOT OBSERVED")
    print(f"  Manifest: {manifest_path}")
    print(f"  Report:   {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

