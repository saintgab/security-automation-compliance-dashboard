import unittest
from datetime import datetime, timedelta, timezone

from collector.risk import (
    TERMINAL_STATUSES,
    compute_risk_score,
    sla_due_date,
    sla_status,
)
from collector.sources import SecurityHubSource
from evidence import TERMINAL_PASS, EXCEPTION_STATUS


NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


class SuppressionPolicyTests(unittest.TestCase):

    def test_suppressed_is_not_terminal(self):
        self.assertNotIn("suppressed", TERMINAL_STATUSES)

    def test_suppressed_is_not_approved_risk_acceptance(self):
        self.assertNotIn("suppressed", EXCEPTION_STATUS)

    def test_suppressed_is_not_resolved(self):
        self.assertNotIn("suppressed", TERMINAL_PASS)

    def test_suppressed_finding_can_be_overdue(self):
        first_seen = (NOW - timedelta(days=180)).isoformat()
        due = sla_due_date(first_seen, "critical")

        self.assertEqual(
            sla_status(due, "suppressed", NOW),
            "overdue",
        )

    def test_suppressed_finding_continues_aging(self):
        recent = compute_risk_score(
            "high", "internal",
            NOW.isoformat(), "suppressed", NOW
        )
        old = compute_risk_score(
            "high", "internal",
            (NOW - timedelta(days=180)).isoformat(),
            "suppressed", NOW
        )

        self.assertGreater(old, recent)

    def test_securityhub_suppression_mapping(self):
        raw = {
            "Id": "synthetic-suppression-test",
            "Title": "Synthetic suppressed finding",
            "Resources": [{"Id": "test-resource"}],
            "Severity": {"Label": "HIGH"},
            "Workflow": {"Status": "SUPPRESSED"},
            "CreatedAt": NOW.isoformat(),
            "UpdatedAt": NOW.isoformat(),
        }

        finding = SecurityHubSource._parse(raw)

        self.assertEqual(finding.status, "suppressed")


if __name__ == "__main__":
    unittest.main()
