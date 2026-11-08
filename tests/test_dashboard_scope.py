import unittest

import pandas as pd

from dashboard_scope import current_live_findings


NOW = pd.Timestamp("2026-11-08T18:00:00Z")


class DashboardScopeTests(unittest.TestCase):

    def setUp(self):
        self.runs = pd.DataFrame([
            {
                "run_id": "run-1",
                "sources_pulled": "aws_security_hub",
                "finished_at": "2026-11-08T17:30:00Z",
            }
        ])

        self.findings = pd.DataFrame([
            {
                "finding_id": "current",
                "source": "aws_security_hub",
                "record_state": "ACTIVE",
                "last_seen_run_id": "run-1",
            },
            {
                "finding_id": "archived",
                "source": "aws_security_hub",
                "record_state": "ARCHIVED",
                "last_seen_run_id": "run-1",
            },
            {
                "finding_id": "historical",
                "source": "aws_security_hub",
                "record_state": "ACTIVE",
                "last_seen_run_id": "older-run",
            },
        ])

    def test_only_current_active_finding_is_included(self):
        current, warning = current_live_findings(
            self.findings, self.runs, now=NOW
        )
        self.assertIsNone(warning)
        self.assertEqual(current["finding_id"].tolist(), ["current"])

    def test_stale_collection_returns_no_current_findings(self):
        runs = self.runs.copy()
        runs["finished_at"] = "2026-11-05T17:30:00Z"

        current, warning = current_live_findings(
            self.findings, runs, now=NOW
        )
        self.assertTrue(current.empty)
        self.assertIsNotNone(warning)

    def test_missing_collection_returns_no_current_findings(self):
        current, warning = current_live_findings(
            self.findings, self.runs.iloc[0:0], now=NOW
        )
        self.assertTrue(current.empty)
        self.assertIsNotNone(warning)

    def test_future_collection_is_rejected(self):
        runs = self.runs.copy()
        runs["finished_at"] = "2026-11-09T17:30:00Z"

        current, warning = current_live_findings(
            self.findings, runs, now=NOW
        )
        self.assertTrue(current.empty)
        self.assertIsNotNone(warning)


if __name__ == "__main__":
    unittest.main()
