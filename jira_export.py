#!/usr/bin/env python3
"""
jira_export.py -- export overdue and due-soon findings as Jira-ready tickets.

    data/findings.db  ──►  query overdue/due_soon findings  ──►  data/jira_export.json
                           map to Jira field schema
                           (project, summary, priority, assignee, due date)

This does NOT call the Jira API. It produces a JSON payload in the shape
Jira's REST API expects (POST /rest/api/3/issue), so a real integration is
a one-step addition: replace write_json() with a requests.post() call using
a Jira API token. The output file is also useful as audit evidence of what
was queued for remediation and when.

Why a separate script rather than a --jira flag on collect.py:
  collect.py collects and normalises. jira_export.py exports.
  Single responsibility makes both easier to test, schedule, and explain.

Jira priority mapping (Jira uses different labels than the pipeline):
  critical  →  Highest
  high      →  High
  medium    →  Medium
  low       →  Low
  info      →  Low   (informational findings don't usually warrant tickets)

Usage:
    python collect.py          # populate/refresh the database first
    python jira_export.py      # export actionable findings to Jira format
    python jira_export.py --project SEC --status overdue
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent
DB_PATH = ROOT / "data" / "findings.db"
OUTPUT_PATH = ROOT / "data" / "jira_export.json"

# Jira uses a different priority vocabulary than the pipeline's severity.
# This mapping is explicit here rather than assumed, so it can be audited
# and changed without hunting through the codebase.
JIRA_PRIORITY_MAP = {
    "critical": "Highest",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Low",
}

# Severity → Jira label color (used in the ticket label for visual triage)
SEVERITY_LABEL = {
    "critical": "SEV-CRITICAL",
    "high":     "SEV-HIGH",
    "medium":   "SEV-MEDIUM",
    "low":      "SEV-LOW",
    "info":     "SEV-INFO",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def format_jira_ticket(row: dict, project_key: str) -> dict:
    """
    Produce a Jira REST API v3 issue payload for one finding.

    Fields chosen deliberately:
      - summary:     the finding title, truncated to Jira's 255-char limit
      - priority:    mapped from pipeline severity (see JIRA_PRIORITY_MAP)
      - assignee:    the finding's owner team, as a displayName hint
                     (a real integration would resolve this to an account ID)
      - duedate:     the pipeline's sla_due_date, converted to YYYY-MM-DD
                     (Jira's date-only format -- time component stripped)
      - labels:      severity label + source system for JQL filterability
      - description: structured with risk score, CVEs, asset, evidence source
                     so the ticket is self-contained for the assignee
    """
    sla_due = row["sla_due_date"][:10] if row["sla_due_date"] else None
    cves = row["cve_ids"] if row["cve_ids"] else "None identified"
    summary = row["title"][:255]  # Jira's hard limit

    return {
        "fields": {
            "project":   {"key": project_key},
            "issuetype": {"name": "Bug"},  # Security findings map to Bug in most Jira schemes
            "summary":   summary,
            "priority":  {"name": JIRA_PRIORITY_MAP.get(row["severity"], "Medium")},
            "duedate":   sla_due,
            "labels":    [
                SEVERITY_LABEL.get(row["severity"], "SEV-UNKNOWN"),
                f"source:{row['source']}",
                "security-pipeline",
            ],
            "assignee":  {"displayName": row["owner"]},
            "description": {
                "type":    "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": (
                            f"Risk score: {row['risk_score']}  |  "
                            f"SLA status: {row['sla_status']}  |  "
                            f"Asset criticality: {row['asset_criticality']}\n\n"
                            f"Asset: {row['asset']}\n"
                            f"CVEs: {cves}\n"
                            f"First seen: {row['first_seen']}\n"
                            f"SLA due: {row['sla_due_date']}\n"
                            f"Source: {row['source']}\n\n"
                            f"{row.get('description', '')}"
                        )}]
                    }
                ]
            },
            # Non-standard field -- most Jira projects have a custom field for
            # external tracking IDs. The field name here matches a common
            # convention; adjust to your project's custom field ID.
            "customfield_10100": row["finding_id"],
        },
        # Metadata carried alongside the payload for audit purposes.
        # Stripped before posting to the Jira API in a real integration.
        "_meta": {
            "finding_id":  row["finding_id"],
            "risk_score":  row["risk_score"],
            "sla_status":  row["sla_status"],
            "exported_at": utc_now_iso(),
        }
    }


def query_findings(
    conn: sqlite3.Connection,
    sla_statuses: list[str],
    min_severity: str | None,
) -> list[dict]:
    """
    Pull findings that warrant a Jira ticket: overdue or due_soon by default,
    optionally filtered to a minimum severity.

    Sorted by risk_score descending so the Jira backlog import naturally
    orders by actual risk, not alphabetically or by insertion order.
    """
    placeholders = ",".join("?" * len(sla_statuses))
    query = f"""
        SELECT *
        FROM findings
        WHERE sla_status IN ({placeholders})
          AND status NOT IN ('resolved', 'accepted_risk')
        ORDER BY risk_score DESC
    """
    rows = conn.execute(query, sla_statuses).fetchall()
    results = [dict(r) for r in rows]

    if min_severity:
        order = ["info", "low", "medium", "high", "critical"]
        min_rank = order.index(min_severity) if min_severity in order else 0
        results = [r for r in results if order.index(r["severity"]) >= min_rank]

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--out", type=Path, default=OUTPUT_PATH)
    parser.add_argument(
        "--project", default="SEC",
        help="Jira project key (default: SEC)"
    )
    parser.add_argument(
        "--status",
        nargs="+",
        choices=["overdue", "due_soon", "on_track"],
        default=["overdue", "due_soon"],
        help="SLA statuses to export (default: overdue due_soon)"
    )
    parser.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default=None,
        help="Only export findings at or above this severity"
    )
    args = parser.parse_args()

    if not args.db.exists():
        print(f"No database found at {args.db}. Run collect.py first.")
        return 1

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    findings = query_findings(conn, args.status, args.min_severity)
    conn.close()

    if not findings:
        print("No findings matched the export criteria.")
        return 0

    tickets = [format_jira_ticket(f, args.project) for f in findings]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(tickets, indent=2), encoding="utf-8")

    print(f"Exported {len(tickets)} findings as Jira tickets → {args.out}")
    print(f"  SLA statuses exported: {args.status}")
    print(f"  Project key: {args.project}")
    print()
    print("Top 5 by risk score:")
    for t in tickets[:5]:
        m = t["_meta"]
        f = t["fields"]
        print(
            f"  [{m['risk_score']:>6}]  "
            f"{f['priority']['name']:<8}  "
            f"{f['summary'][:55]:<55}  "
            f"SLA: {m['sla_status']}"
        )

    print()
    print(
        "Note: _meta fields are for audit purposes and should be stripped "
        "before POSTing to the Jira REST API (/rest/api/3/issue)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
