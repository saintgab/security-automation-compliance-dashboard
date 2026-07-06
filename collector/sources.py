"""
One adapter class per source. Each knows how to (a) fetch its own payload
-- live if credentials are present, mock JSON otherwise -- and (b) parse
that vendor-specific shape into the shared Finding model. Pagination/retry
for live calls live inside each adapter's `_fetch_live`, since AWS Security
Hub, GitHub, and a scanner API paginate completely differently; everything
downstream of `.pull()` never has to know that.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .models import Finding, infer_asset_criticality, normalize_severity

log = logging.getLogger("collector.sources")

MOCK_DATA_DIR = Path(__file__).resolve().parent.parent / "mock_data"

# Deterministic owner assignment -- stands in for a real CMDB/asset-tag
# lookup. Kept simple and readable on purpose: interviewers will ask "how
# does ownership get assigned" and "today it's a keyword heuristic, in
# production it'd be a tag lookup" is a fine, honest answer.
OWNER_RULES = [
    (("prod-web", "api-gw", "lb-edge", "cdn"), "AppSec"),
    (("db", "internal-jenkins", "vpn"), "Platform Eng"),
    (("dev-", "staging", "sandbox"), "Engineering (Dev)"),
    (("corp-", "fileserver"), "IT Ops"),
]


def _assign_owner(asset_or_repo: str, default: str) -> str:
    lowered = asset_or_repo.lower()
    for keywords, owner in OWNER_RULES:
        if any(k in lowered for k in keywords):
            return owner
    return default


class SecurityHubSource:
    """AWS Security Hub findings (ASFF format)."""

    name = "aws_security_hub"

    def __init__(self, live_client=None):
        # live_client would be a boto3 securityhub client; None => mock mode.
        self.live_client = live_client

    def pull(self) -> list[Finding]:
        raw_items = self._fetch_live() if self.live_client else self._fetch_mock()
        return [self._parse(item) for item in raw_items]

    def _fetch_mock(self) -> list[dict]:
        path = MOCK_DATA_DIR / "security_hub_findings.json"
        return json.loads(path.read_text())

    def _fetch_live(self) -> list[dict]:  # pragma: no cover
        """
        Real implementation would page through:
            self.live_client.get_findings(Filters={...}, MaxResults=100)
        following NextToken until absent. Left unimplemented here since this
        portfolio build runs in mock mode -- wiring a real AWS account is a
        follow-up, not a rewrite (parsing logic in _parse is unaffected).
        """
        raise NotImplementedError("Live AWS Security Hub pull not wired up in this build")

    @staticmethod
    def _parse(item: dict) -> Finding:
        asset = item["Resources"][0]["Id"].rsplit("/", 1)[-1]
        status_map = {"NEW": "open", "NOTIFIED": "in_progress", "RESOLVED": "resolved", "SUPPRESSED": "accepted_risk"}
        status = status_map.get(item.get("Workflow", {}).get("Status", "NEW"), "open")
        return Finding(
            finding_id=item["Id"],
            source="aws_security_hub",
            asset=asset,
            title=item["Title"],
            severity=normalize_severity(raw_label=item["Severity"]["Label"]),
            cvss_score=None,
            cve_ids=[],
            status=status,
            # Deliberately NOT asset-keyword-based: Security Hub control
            # findings (IAM, S3, KMS, VPC config) are a cloud/platform
            # security team's responsibility regardless of which host
            # tripped the control -- unlike a scanner finding, which is
            # genuinely tied to one host. Routing this by hostname would
            # be the wrong model of who actually fixes an IAM.1 finding.
            owner="Cloud Infra",
            asset_criticality=infer_asset_criticality(asset),
            first_seen=item["CreatedAt"],
            last_seen=item["UpdatedAt"],
            description=item.get("Description", ""),
        )


class GitHubAlertsSource:
    """GitHub code scanning / Dependabot-style alerts."""

    name = "github_alerts"

    def __init__(self, live_token: str | None = None):
        self.live_token = live_token

    def pull(self) -> list[Finding]:
        raw_items = self._fetch_live() if self.live_token else self._fetch_mock()
        return [self._parse(item) for item in raw_items]

    def _fetch_mock(self) -> list[dict]:
        path = MOCK_DATA_DIR / "github_alerts.json"
        return json.loads(path.read_text())

    def _fetch_live(self) -> list[dict]:  # pragma: no cover
        """
        Real implementation: GET /repos/{owner}/{repo}/code-scanning/alerts
        and /dependabot/alerts per repo, paginating on the Link header.
        Left unimplemented in mock mode -- see SecurityHubSource for the
        same note.
        """
        raise NotImplementedError("Live GitHub pull not wired up in this build")

    @staticmethod
    def _parse(item: dict) -> Finding:
        status_map = {"open": "open", "fixed": "resolved", "dismissed": "accepted_risk"}
        status = status_map.get(item["most_recent_instance"]["state"], "open")
        repo = item["repository"]["full_name"]
        return Finding(
            finding_id=f"gh-{repo}-{item['number']}",
            source="github_alerts",
            asset=repo,
            title=item["rule"]["description"],
            severity=normalize_severity(raw_label=item["rule"]["security_severity_level"]),
            cvss_score=None,
            cve_ids=item.get("cve_ids", []),
            status=status,
            owner=_assign_owner(repo, default="AppSec"),
            asset_criticality="internet_facing" if "web-app" in repo or "api" in repo else "internal",
            first_seen=item["created_at"],
            last_seen=item["updated_at"],
            description=item["rule"]["description"],
        )


class ScannerSource:
    """Tenable-style network/host vulnerability scanner export."""

    name = "scanner"

    def __init__(self, live_client=None):
        self.live_client = live_client

    def pull(self) -> list[Finding]:
        raw_items = self._fetch_live() if self.live_client else self._fetch_mock()
        return [self._parse(item) for item in raw_items]

    def _fetch_mock(self) -> list[dict]:
        path = MOCK_DATA_DIR / "scanner_findings.json"
        return json.loads(path.read_text())

    def _fetch_live(self) -> list[dict]:  # pragma: no cover
        """
        Real implementation: paginated GET against
        /workbenches/vulnerabilities with cursor-based pagination and
        429/5xx retry+backoff. Left unimplemented in mock mode.
        """
        raise NotImplementedError("Live scanner pull not wired up in this build")

    @staticmethod
    def _parse(item: dict) -> Finding:
        asset = item["asset"]["hostname"]
        status_map = {"open": "open", "fixed": "resolved", "accepted_risk": "accepted_risk"}
        return Finding(
            finding_id=item["uuid"],
            source="scanner",
            asset=asset,
            title=item["plugin_name"],
            severity=normalize_severity(cvss=item.get("cvss3_base_score")),
            cvss_score=item.get("cvss3_base_score"),
            cve_ids=item.get("cve", []),
            status=status_map.get(item["state"], "open"),
            owner=_assign_owner(asset, default="IT Ops"),
            asset_criticality=infer_asset_criticality(asset),
            first_seen=item["first_found"],
            last_seen=item["last_found"],
            description=item.get("description", ""),
        )


def all_sources() -> list:
    """The three sources the pipeline pulls from each run."""
    return [SecurityHubSource(), GitHubAlertsSource(), ScannerSource()]
