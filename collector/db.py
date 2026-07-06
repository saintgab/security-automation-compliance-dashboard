"""
SQLite persistence layer.

Two tables:
  findings        -- current state of every finding, one row each,
                      upserted on every collector run (idempotent by
                      finding_id).
  collector_runs   -- one row per collector execution: when it ran, what it
                      pulled, and a summary. This is the audit trail --
                      "when was this data last refreshed and what changed"
                      is exactly the question a Drata-style evidence report
                      has to answer, so it's built in from day one rather
                      than bolted on in Day 6.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, utc_now_iso
from .risk import compute_risk_score, sla_due_date, sla_status

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id          TEXT PRIMARY KEY,
    source              TEXT NOT NULL,
    asset               TEXT NOT NULL,
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL,
    cvss_score          REAL,
    cve_ids             TEXT,       -- semicolon-joined
    status              TEXT NOT NULL,
    owner               TEXT NOT NULL,
    asset_criticality   TEXT NOT NULL,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    sla_due_date        TEXT NOT NULL,
    sla_status          TEXT NOT NULL,
    risk_score          REAL NOT NULL,
    description         TEXT,
    first_ingested_at   TEXT NOT NULL,
    last_updated_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collector_runs (
    run_id          TEXT PRIMARY KEY,
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    sources_pulled  TEXT NOT NULL,   -- comma-joined source names
    total_findings  INTEGER NOT NULL,
    new_findings    INTEGER NOT NULL,
    updated_findings INTEGER NOT NULL,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_owner ON findings(owner);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def upsert_findings(conn: sqlite3.Connection, findings: list[Finding]) -> tuple[int, int]:
    """
    Insert new findings, update existing ones -- but preserve the original
    first_seen/first_ingested_at on updates, since re-running the collector
    against an unchanged finding shouldn't reset its SLA clock. Returns
    (new_count, updated_count).
    """
    now = utc_now_iso()
    new_count = 0
    updated_count = 0

    for f in findings:
        existing = conn.execute(
            "SELECT first_seen, first_ingested_at FROM findings WHERE finding_id = ?",
            (f.finding_id,),
        ).fetchone()

        first_seen = existing["first_seen"] if existing else f.first_seen
        first_ingested_at = existing["first_ingested_at"] if existing else now

        due = sla_due_date(first_seen, f.severity)
        as_of = datetime.now(timezone.utc)
        status = sla_status(due, f.status, as_of)
        score = compute_risk_score(f.severity, f.asset_criticality, first_seen, f.status, as_of)

        conn.execute(
            """
            INSERT INTO findings (
                finding_id, source, asset, title, severity, cvss_score, cve_ids,
                status, owner, asset_criticality, first_seen, last_seen,
                sla_due_date, sla_status, risk_score, description,
                first_ingested_at, last_updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(finding_id) DO UPDATE SET
                source=excluded.source, asset=excluded.asset, title=excluded.title,
                severity=excluded.severity, cvss_score=excluded.cvss_score,
                cve_ids=excluded.cve_ids, status=excluded.status, owner=excluded.owner,
                asset_criticality=excluded.asset_criticality, last_seen=excluded.last_seen,
                sla_due_date=excluded.sla_due_date, sla_status=excluded.sla_status,
                risk_score=excluded.risk_score, description=excluded.description,
                last_updated_at=excluded.last_updated_at
            """,
            (
                f.finding_id, f.source, f.asset, f.title, f.severity, f.cvss_score,
                ";".join(f.cve_ids), f.status, f.owner, f.asset_criticality,
                first_seen, f.last_seen, due, status, score, f.description,
                first_ingested_at, now,
            ),
        )
        if existing:
            updated_count += 1
        else:
            new_count += 1

    conn.commit()
    return new_count, updated_count


def record_run(
    conn: sqlite3.Connection,
    started_at: str,
    sources_pulled: list[str],
    total: int,
    new: int,
    updated: int,
    notes: str = "",
) -> str:
    run_id = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO collector_runs
           (run_id, started_at, finished_at, sources_pulled, total_findings,
            new_findings, updated_findings, notes)
           VALUES (?,?,?,?,?,?,?,?)""",
        (run_id, started_at, utc_now_iso(), ",".join(sources_pulled), total, new, updated, notes),
    )
    conn.commit()
    return run_id
