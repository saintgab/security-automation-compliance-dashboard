"""Current-view scope for live AWS Security Hub findings."""

from datetime import datetime, timezone, timedelta

import pandas as pd

MAX_COLLECTION_AGE = timedelta(hours=24)


def current_live_findings(findings, runs, now=None):
    """Return current findings and a reason when data is unusable.

    Requires a recent successful AWS collection, ACTIVE record state,
    and matching last_seen_run_id. Does not alter historical records.
    """
    empty = findings.iloc[0:0].copy()

    if runs.empty:
        return empty, "No recorded AWS collection"

    required = {"record_state", "last_seen_run_id", "source"}
    if not required.issubset(findings.columns):
        return empty, "Collection tracking columns are missing"

    aws_runs = runs[
        runs["sources_pulled"].fillna("").apply(
            lambda sources: "aws_security_hub" in sources.split(",")
        )
    ].copy()

    if aws_runs.empty:
        return empty, "No AWS Security Hub collection recorded"

    aws_runs["finished_at"] = pd.to_datetime(
        aws_runs["finished_at"], utc=True, errors="coerce"
    )
    aws_runs = aws_runs.dropna(subset=["finished_at"])

    if aws_runs.empty:
        return empty, "Collection timestamps are invalid"

    latest = aws_runs.sort_values("finished_at").iloc[-1]
    current_time = pd.Timestamp(
        now if now is not None else datetime.now(timezone.utc)
    )
    if current_time.tzinfo is None:
        current_time = current_time.tz_localize("UTC")
    else:
        current_time = current_time.tz_convert("UTC")

    age = current_time - latest["finished_at"]
    if not pd.Timedelta(0) <= age <= pd.Timedelta(MAX_COLLECTION_AGE):
        return empty, "Latest AWS collection is older than 24 hours or has an invalid future timestamp"

    current = findings.loc[
        (findings["source"] == "aws_security_hub")
        & (findings["record_state"] == "ACTIVE")
        & (findings["last_seen_run_id"] == latest["run_id"])
    ].copy()

    return current, None
