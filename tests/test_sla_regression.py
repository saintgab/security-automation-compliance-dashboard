import unittest
from datetime import datetime, timedelta, timezone

from collector.risk import (
    SLA_DAYS,
    sla_due_date,
    sla_status,
    compute_risk_score,
)

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


class SLARegressionTests(unittest.TestCase):

    def test_deadline_for_each_severity(self):
        for severity, days in SLA_DAYS.items():
            with self.subTest(severity=severity):
                first_seen = NOW.isoformat()
                due = datetime.fromisoformat(
                    sla_due_date(first_seen, severity)
                )
                self.assertEqual(
                    due,
                    NOW + timedelta(days=days),
                )

    def test_open_finding_before_deadline(self):
        due = (NOW + timedelta(days=10)).isoformat()
        self.assertEqual(
            sla_status(due, "open", NOW),
            "on_track",
        )

    def test_due_soon(self):
        due = (NOW + timedelta(days=3)).isoformat()
        self.assertEqual(
            sla_status(due, "open", NOW),
            "due_soon",
        )

    def test_overdue(self):
        due = (NOW - timedelta(days=1)).isoformat()
        self.assertEqual(
            sla_status(due, "open", NOW),
            "overdue",
        )

    def test_exact_deadline(self):
        self.assertEqual(
            sla_status(NOW.isoformat(), "open", NOW),
            "due_soon",
        )

    def test_resolved_remains_resolved(self):
        due = (NOW - timedelta(days=100)).isoformat()
        self.assertEqual(
            sla_status(due, "resolved", NOW),
            "resolved",
        )

    def test_risk_increases_with_age(self):
        days = SLA_DAYS["high"]

        recent = compute_risk_score(
            "high", "internal",
            NOW.isoformat(), "open", NOW
        )
        older = compute_risk_score(
            "high", "internal",
            (NOW - timedelta(days=days)).isoformat(),
            "open", NOW
        )

        self.assertGreater(older, recent)

    def test_resolved_risk_does_not_age(self):
        first_seen = (
            NOW - timedelta(days=365)
        ).isoformat()

        score = compute_risk_score(
            "high", "internal",
            first_seen, "resolved", NOW
        )
        base = compute_risk_score(
            "high", "internal",
            NOW.isoformat(), "resolved", NOW
        )

        self.assertEqual(score, base)


if __name__ == "__main__":
    unittest.main()
