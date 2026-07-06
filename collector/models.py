"""
Shared vocabulary for the pipeline. Every source adapter (AWS Security Hub,
GitHub alerts, scanner) parses its own vendor-specific payload but must land
on this one Finding shape — that's what lets risk.py, db.py, and the
dashboard stay vendor-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

ASSET_CRITICALITY = ["dev_test", "internal", "internet_facing"]


def normalize_severity(cvss: float | None = None, raw_label: str | None = None) -> str:
    """
    Collapse a CVSS score OR a vendor's own severity label into one fixed
    taxonomy. Every source speaks a different dialect for this:
      - AWS Security Hub:   Severity.Label = INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL
      - GitHub code scanning: rule.security_severity_level = low/medium/high/critical
      - Tenable-style scanners: a raw CVSS3 float
    Numeric score wins when present because it's more granular; label is the
    fallback for sources (like GitHub) that only ever emit a label.
    """
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        if cvss > 0.0:
            return "low"
        return "info"
    if raw_label:
        label = raw_label.strip().lower()
        aliases = {"informational": "info", "moderate": "medium"}
        label = aliases.get(label, label)
        if label in SEVERITY_ORDER:
            return label
    return "info"


def infer_asset_criticality(asset_name: str) -> str:
    """
    Deterministic heuristic standing in for a real asset-inventory lookup
    (in production this would query a CMDB / AWS Config / tag data instead
    of guessing from the hostname).
    """
    name = asset_name.lower()
    if any(tok in name for tok in ("public", "prod-lb", "prod-web", "edge", "cdn", "api-gw")):
        return "internet_facing"
    if any(tok in name for tok in ("dev-", "test-", "sandbox", "staging")):
        return "dev_test"
    return "internal"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    finding_id: str
    source: str  # aws_security_hub | github_alerts | scanner
    asset: str
    title: str
    severity: str
    cvss_score: float | None
    cve_ids: list[str] = field(default_factory=list)
    status: str = "open"  # open | in_progress | resolved | accepted_risk
    owner: str = "Unassigned"
    asset_criticality: str = "internal"
    first_seen: str = ""
    last_seen: str = ""
    description: str = ""
