import unittest

from collector.sources import SecurityHubSource


def sample_finding(**overrides):
    finding = {
        "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/example",
        "Title": "S3 bucket should block public access",
        "Description": "Synthetic test finding",
        "Resources": [{
            "Id": "arn:aws:s3:::example-lab-bucket",
            "Type": "AwsS3Bucket",
        }],
        "Severity": {"Label": "HIGH"},
        "Workflow": {"Status": "NEW"},
        "CreatedAt": "2026-11-08T00:00:00Z",
        "UpdatedAt": "2026-11-08T00:00:00Z",
    }
    finding.update(overrides)
    return finding


class SecurityHubNormalizationTests(unittest.TestCase):

    def test_high_severity_finding(self):
        finding = SecurityHubSource._parse(sample_finding())

        self.assertEqual(finding.source, "aws_security_hub")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.status, "open")
        self.assertEqual(finding.owner, "Cloud Infra")

    def test_resolved_workflow(self):
        finding = SecurityHubSource._parse(
            sample_finding(Workflow={"Status": "RESOLVED"})
        )
        self.assertEqual(finding.status, "resolved")

    def test_suppressed_workflow(self):
        finding = SecurityHubSource._parse(
            sample_finding(Workflow={"Status": "SUPPRESSED"})
        )
        self.assertEqual(finding.status, "suppressed")

    def test_notified_workflow(self):
        finding = SecurityHubSource._parse(
            sample_finding(Workflow={"Status": "NOTIFIED"})
        )
        self.assertEqual(finding.status, "in_progress")

    def test_critical_severity(self):
        finding = SecurityHubSource._parse(
            sample_finding(Severity={"Label": "CRITICAL"})
        )
        self.assertEqual(finding.severity, "critical")

    def test_resource_identifier(self):
        finding = SecurityHubSource._parse(sample_finding())
        self.assertEqual(
            finding.asset,
            "arn:aws:s3:::example-lab-bucket"
        )

    def test_missing_required_id_raises_error(self):
        raw = sample_finding()
        del raw["Id"]

        with self.assertRaises(KeyError):
            SecurityHubSource._parse(raw)


if __name__ == "__main__":
    unittest.main()
