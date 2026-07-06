#!/usr/bin/env python3
"""
Generates three vendor-shaped mock datasets so the collector has something
realistic to ingest without needing live AWS/GitHub/scanner credentials.

Run once (or re-run any time -- it's deterministic via SEED) to regenerate:
    python generate_mock_data.py
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 42
random.seed(SEED)

NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)
HERE = Path(__file__).parent

ASSETS = [
    "prod-web-01.gochekam.internal",
    "prod-web-02.gochekam.internal",
    "prod-api-gw.gochekam.internal",
    "prod-lb-edge.gochekam.internal",
    "internal-db-primary",
    "internal-jenkins-01",
    "internal-vpn-gateway",
    "dev-sandbox-03",
    "staging-web-01",
    "corp-fileserver-02",
]


def days_ago(n: int) -> str:
    return (NOW - timedelta(days=n)).isoformat(timespec="seconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# AWS Security Hub (ASFF-shaped)
# ---------------------------------------------------------------------------
SECURITY_HUB_TEMPLATES = [
    ("IAM.1 root account access key exists", "critical", None),
    ("EC2.19 security group allows unrestricted SSH", "high", None),
    ("S3.8 bucket blocks public access disabled", "critical", None),
    ("CloudTrail.1 not enabled in all regions", "high", None),
    ("KMS.4 key rotation not enabled", "medium", None),
    ("GuardDuty.1 not enabled", "high", None),
    ("EC2.8 IMDSv1 still permitted", "medium", None),
    ("RDS.3 instance not encrypted at rest", "high", None),
    ("VPC.1 default security group allows traffic", "low", None),
    ("Config.1 not enabled", "medium", None),
    ("IAM.22 unused credentials not disabled >90 days", "medium", None),
    ("Lambda.1 function policy grants public access", "critical", None),
]

security_hub_findings = []
for i, (title, sev, _) in enumerate(SECURITY_HUB_TEMPLATES):
    age = random.choice([2, 5, 9, 14, 20, 28, 40, 55, 70, 95])
    asset = random.choice(ASSETS)
    status_pool = ["NEW", "NOTIFIED", "RESOLVED"] if age < 60 else ["NEW", "RESOLVED", "SUPPRESSED"]
    security_hub_findings.append(
        {
            "SchemaVersion": "2018-10-08",
            "Id": f"arn:aws:securityhub:us-east-1:111122223333:finding/{i:04d}",
            "Title": title,
            "Description": f"Security Hub control finding: {title}.",
            "Severity": {"Label": sev.upper()},
            "Resources": [{"Id": f"arn:aws:ec2:us-east-1:111122223333:instance/{asset}", "Type": "AwsEc2Instance"}],
            "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"],
            "CreatedAt": days_ago(age),
            "UpdatedAt": days_ago(max(age - 3, 0)),
            "Workflow": {"Status": random.choice(status_pool)},
            "Compliance": {"Status": "FAILED"},
        }
    )

# ---------------------------------------------------------------------------
# GitHub code scanning / Dependabot alerts
# ---------------------------------------------------------------------------
GITHUB_TEMPLATES = [
    ("Prototype pollution in lodash < 4.17.21", "high", ["CVE-2020-8203"]),
    ("ReDoS in axios < 1.6.0", "medium", ["CVE-2023-45857"]),
    ("Hardcoded AWS secret key detected in commit", "critical", []),
    ("SQL injection via unsanitized query param", "critical", []),
    ("Outdated Django version with known auth bypass", "high", ["CVE-2024-27351"]),
    ("Insecure deserialization in PyYAML < 5.4", "high", ["CVE-2020-14343"]),
    ("Cross-site scripting in unescaped template output", "medium", []),
    ("Weak JWT signing algorithm (none) accepted", "critical", []),
    ("Dependency confusion risk in private package name", "low", []),
    ("Missing rate limiting on password reset endpoint", "medium", []),
]

REPOS = ["gochekam/web-app", "gochekam/api", "gochekam/mobile-android", "gochekam/infra-scripts"]

github_alerts = []
for i, (title, sev, cves) in enumerate(GITHUB_TEMPLATES):
    age = random.choice([1, 4, 8, 12, 18, 25, 35, 45, 60, 80])
    repo = random.choice(REPOS)
    state = "open" if age < 50 else random.choice(["open", "fixed", "dismissed"])
    github_alerts.append(
        {
            "number": 100 + i,
            "rule": {
                "id": f"gh-rule-{i:03d}",
                "description": title,
                "security_severity_level": sev,
            },
            "repository": {"full_name": repo},
            "most_recent_instance": {"state": state},
            "created_at": days_ago(age),
            "updated_at": days_ago(max(age - 2, 0)),
            "cve_ids": cves,
        }
    )

# ---------------------------------------------------------------------------
# Tenable-style scanner export
# ---------------------------------------------------------------------------
SCANNER_TEMPLATES = [
    ("OpenSSL 3.0.x vulnerable to CVE-2024-6119 (DoS)", 7.5, ["CVE-2024-6119"]),
    ("Apache HTTP Server 2.4.x mod_proxy SSRF", 8.6, ["CVE-2024-40725"]),
    ("OpenSSH < 9.8 regreSSHion RCE", 9.8, ["CVE-2024-6387"]),
    ("Outdated TLS 1.0/1.1 still negotiable", 5.3, []),
    ("SMBv1 protocol enabled", 8.1, []),
    ("Self-signed certificate in use on public endpoint", 6.5, []),
    ("Unsupported Ubuntu 18.04 LTS (EOL)", 7.2, []),
    ("Docker daemon exposed on 2375/tcp without TLS", 9.1, []),
    ("Default credentials active on network device", 9.6, []),
    ("Redis instance bound to 0.0.0.0 without auth", 9.0, []),
]

scanner_findings = []
for i, (title, cvss, cves) in enumerate(SCANNER_TEMPLATES):
    age = random.choice([3, 6, 11, 17, 22, 33, 48, 65, 85, 110])
    asset = random.choice(ASSETS)
    state = "open" if age < 70 else random.choice(["open", "fixed", "accepted_risk"])
    scanner_findings.append(
        {
            "uuid": f"scan-{i:04d}-{asset[:4]}",
            "asset": {"hostname": asset},
            "plugin_name": title,
            "cvss3_base_score": cvss,
            "cve": cves,
            "first_found": days_ago(age),
            "last_found": days_ago(max(age - 5, 0)),
            "state": state,
            "source": "tenable_style_scanner",
            "description": f"Network/host scan finding: {title}.",
        }
    )

HERE.joinpath("security_hub_findings.json").write_text(json.dumps(security_hub_findings, indent=2))
HERE.joinpath("github_alerts.json").write_text(json.dumps(github_alerts, indent=2))
HERE.joinpath("scanner_findings.json").write_text(json.dumps(scanner_findings, indent=2))

print(
    f"Generated {len(security_hub_findings)} Security Hub, "
    f"{len(github_alerts)} GitHub, {len(scanner_findings)} scanner findings "
    f"(seed={SEED}) -> {HERE}"
)
