"""
Risk scoring and SLA logic.

This is the one file in the pipeline that encodes a policy decision rather
than just parsing data, so it's written to be read and argued with, not just
executed. Change the constants below, not the formula shape, when you want
to tune it for a different risk appetite.

SLA_DAYS is modeled on CISA Binding Operational Directive 22-01's remediation
windows for internet-facing systems (critical=15d, high=30d) as a familiar,
defensible reference point -- not a claim that this pipeline is BOD 22-01
compliant. Medium/low/info windows are reasonable internal-program defaults,
not drawn from that directive.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

SLA_DAYS: dict[str, int] = {
    "critical": 15,
    "high": 30,
    "medium": 60,
    "low": 90,
    "info": 180,
}

# Base severity weight, before criticality/age adjustment.
SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 15,
    "info": 5,
}

# Multiplies the severity weight based on where the vulnerable asset sits.
# An internet-facing critical is a materially different risk than the same
# CVE on a dev sandbox nobody can reach from outside the VPC.
CRITICALITY_MULTIPLIER: dict[str, float] = {
    "internet_facing": 1.5,
    "internal": 1.0,
    "dev_test": 0.5,
}

# Terminal statuses don't accrue further SLA-age risk -- a resolved finding
# shouldn't keep climbing the risk-score leaderboard.
TERMINAL_STATUSES = {"resolved", "accepted_risk"}


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def sla_due_date(first_seen: str, severity: str) -> str:
    start = _parse_iso(first_seen)
    due = start + timedelta(days=SLA_DAYS.get(severity, 90))
    return due.isoformat(timespec="seconds")


def sla_status(sla_due: str, status: str, as_of: datetime | None = None) -> str:
    """on_track | due_soon (<=5 days) | overdue | resolved | accepted_risk"""
    if status in TERMINAL_STATUSES:
        return status
    as_of = as_of or datetime.now(timezone.utc)
    due = _parse_iso(sla_due)
    days_remaining = (due - as_of).days
    if days_remaining < 0:
        return "overdue"
    if days_remaining <= 5:
        return "due_soon"
    return "on_track"


def compute_risk_score(
    severity: str,
    asset_criticality: str,
    first_seen: str,
    status: str,
    as_of: datetime | None = None,
) -> float:
    """
    risk_score = severity_weight x criticality_multiplier x age_multiplier

    age_multiplier grows linearly with how far past the SLA window a finding
    is, capped at 2x the base score for anything sitting at >=2x its SLA
    (a stalled critical doesn't get infinitely scarier, but it does keep
    outranking newly-discovered ones). Terminal findings get age_multiplier
    frozen at 1.0 so closing a finding actually drops it, rather than
    rewarding "resolved two years late" with a still-high score.
    """
    as_of = as_of or datetime.now(timezone.utc)
    weight = SEVERITY_WEIGHT.get(severity, 5)
    crit_mult = CRITICALITY_MULTIPLIER.get(asset_criticality, 1.0)

    if status in TERMINAL_STATUSES:
        age_mult = 1.0
    else:
        sla_days = SLA_DAYS.get(severity, 90)
        days_open = (as_of - _parse_iso(first_seen)).days
        fraction_of_sla = days_open / sla_days if sla_days else 0
        age_mult = 1.0 + min(max(fraction_of_sla, 0), 2.0)

    return round(weight * crit_mult * age_mult, 1)
