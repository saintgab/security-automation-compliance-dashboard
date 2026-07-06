#!/usr/bin/env python3
"""
collect.py -- entrypoint for the collector stage of the pipeline.

    AWS Security Hub  ─┐
    GitHub Alerts      ├─► collect.py ─► SQLite (data/findings.db) ─► Streamlit dashboard
    Scanner (Tenable)  ─┘                     │
                                               └─► collector_runs (audit trail) ─► evidence report

Usage:
    python collect.py                 # pulls all 3 mock sources, upserts into data/findings.db
    python collect.py --csv           # also writes data/findings_export.csv
    python collect.py --db path/to.db # use a different db file

Re-running this is safe and expected -- it's meant to run on a schedule
(cron / GitHub Actions) the same way a real collector would. Findings are
upserted by finding_id: unchanged findings keep their original first_seen,
so SLA aging is computed correctly across runs.
"""

from __future__ import annotations

import argparse
import csv
import logging
import sqlite3
from pathlib import Path

from collector.db import connect, record_run, upsert_findings
from collector.models import utc_now_iso
from collector.sources import all_sources

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("collect")

ROOT = Path(__file__).parent
DEFAULT_DB = ROOT / "data" / "findings.db"


def export_csv(conn: sqlite3.Connection, out_path: Path) -> None:
    cols = [d[1] for d in conn.execute("PRAGMA table_info(findings)").fetchall()]
    rows = conn.execute(f"SELECT {', '.join(cols)} FROM findings ORDER BY risk_score DESC").fetchall()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        writer.writerows(rows)
    log.info("Exported %d rows to %s", len(rows), out_path)


def print_summary(conn: sqlite3.Connection) -> None:
    print("\n--- Findings by severity ---")
    for row in conn.execute(
        "SELECT severity, COUNT(*) c FROM findings GROUP BY severity "
        "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    ):
        print(f"  {row['severity']:<10} {row['c']}")

    print("\n--- SLA status ---")
    for row in conn.execute("SELECT sla_status, COUNT(*) c FROM findings GROUP BY sla_status ORDER BY c DESC"):
        print(f"  {row['sla_status']:<15} {row['c']}")

    print("\n--- Top 5 by risk score ---")
    for row in conn.execute("SELECT title, asset, owner, risk_score FROM findings ORDER BY risk_score DESC LIMIT 5"):
        print(f"  [{row['risk_score']:>6}]  {row['title'][:50]:<50}  ({row['asset']}, owner: {row['owner']})")

    print("\n--- Open findings by owner ---")
    for row in conn.execute(
        "SELECT owner, COUNT(*) c FROM findings WHERE status NOT IN ('resolved','accepted_risk') "
        "GROUP BY owner ORDER BY c DESC"
    ):
        print(f"  {row['owner']:<20} {row['c']}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--csv", action="store_true", help="Also export data/findings_export.csv")
    args = parser.parse_args()

    started_at = utc_now_iso()
    conn = connect(args.db)

    sources = all_sources()
    all_findings = []
    for source in sources:
        pulled = source.pull()
        log.info("Pulled %d findings from %s", len(pulled), source.name)
        all_findings.extend(pulled)

    new_count, updated_count = upsert_findings(conn, all_findings)
    run_id = record_run(
        conn,
        started_at=started_at,
        sources_pulled=[s.name for s in sources],
        total=len(all_findings),
        new=new_count,
        updated=updated_count,
        notes="mock-mode collection run",
    )
    log.info(
        "Run %s complete: %d findings pulled (%d new, %d updated)",
        run_id, len(all_findings), new_count, updated_count,
    )

    if args.csv:
        export_csv(conn, ROOT / "data" / "findings_export.csv")

    print_summary(conn)
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
