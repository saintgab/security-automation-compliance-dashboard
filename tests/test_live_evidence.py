import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from collector.db import connect, upsert_findings, record_run, record_collection_observations
from collector.sources import SecurityHubSource
from evidence import evaluate_control


class LiveEvidenceTests(unittest.TestCase):

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.conn = connect(Path(self.tmp.name) / "evidence.db")
        from collector.models import utc_now_iso
        self.run_id = record_run(
            self.conn,
            utc_now_iso(),
            ["aws_security_hub"],
            0, 0, 0,
        )

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def add(self, finding_id, compliance, record="ACTIVE",
            workflow="open", title="S3 bucket access check"):
        workflow_map = {
            "open": "NEW",
            "in_progress": "NOTIFIED",
            "resolved": "RESOLVED",
            "suppressed": "SUPPRESSED",
        }

        raw = {
            "Id": finding_id,
            "Title": title,
            "Resources": [{"Id": "arn:aws:s3:::synthetic-bucket"}],
            "Severity": {"Label": "HIGH"},
            "Workflow": {"Status": workflow_map[workflow]},
            "Compliance": {
                "SecurityControlId": "S3.8",
                "Status": compliance,
            },
            "RecordState": record,
            "CreatedAt": "2026-11-08T00:00:00Z",
            "UpdatedAt": "2026-11-08T00:00:00Z",
        }

        finding = SecurityHubSource._parse(raw)
        upsert_findings(self.conn, [finding])
        from collector.models import utc_now_iso
        record_collection_observations(
            self.conn, [finding], self.run_id, utc_now_iso()
        )
        self.conn.commit()

    def test_failed_assessment_without_control_id_in_title(self):
        self.add("finding-1", "FAILED")
        status, rows = evaluate_control(self.conn, "S3.8", live=True)
        self.assertEqual(status, "FAIL")
        self.assertEqual(len(rows), 1)

    def test_passed_assessment(self):
        self.add("finding-2", "PASSED")
        status, _ = evaluate_control(self.conn, "S3.8", live=True)
        self.assertEqual(status, "PASS")

    def test_suppressed_failed_finding_is_still_failed(self):
        self.add("finding-3", "FAILED", workflow="suppressed")
        status, _ = evaluate_control(self.conn, "S3.8", live=True)
        self.assertEqual(status, "FAIL")

    def test_archived_finding_excluded(self):
        self.add("finding-4", "FAILED", record="ARCHIVED")
        status, rows = evaluate_control(self.conn, "S3.8", live=True)
        self.assertEqual(status, "NOT_OBSERVED")
        self.assertEqual(rows, [])

    def test_warning_is_not_a_pass(self):
        self.add("finding-5", "WARNING")
        status, _ = evaluate_control(self.conn, "S3.8", live=True)
        self.assertEqual(status, "NOT_OBSERVED")

    def test_failed_wins_over_passed(self):
        self.add("finding-6", "PASSED")
        self.add("finding-7", "FAILED")
        status, _ = evaluate_control(self.conn, "S3.8", live=True)
        self.assertEqual(status, "FAIL")


    def test_stale_collection_cannot_pass(self):
        self.add("stale-pass", "PASSED")

        self.conn.execute(
            """UPDATE collector_runs
               SET finished_at = ?
               WHERE run_id = ?""",
            ("2020-01-01T00:00:00+00:00", self.run_id),
        )
        self.conn.commit()

        status, rows = evaluate_control(
            self.conn, "S3.8", live=True
        )

        self.assertEqual(status, "NOT_OBSERVED")
        self.assertEqual(rows, [])

    def test_missing_from_latest_collection_cannot_pass(self):
        self.add("historical-pass", "PASSED")

        from collector.models import utc_now_iso

        record_run(
            self.conn,
            utc_now_iso(),
            ["aws_security_hub"],
            0, 0, 0,
        )

        status, rows = evaluate_control(
            self.conn, "S3.8", live=True
        )

        self.assertEqual(status, "NOT_OBSERVED")
        self.assertEqual(rows, [])

    def test_missing_from_latest_collection_cannot_fail(self):
        self.add("historical-failure", "FAILED")

        from collector.models import utc_now_iso

        record_run(
            self.conn,
            utc_now_iso(),
            ["aws_security_hub"],
            0, 0, 0,
        )

        status, rows = evaluate_control(
            self.conn, "S3.8", live=True
        )

        self.assertEqual(status, "NOT_OBSERVED")
        self.assertEqual(rows, [])

    def test_not_available_is_not_pass(self):
        self.add("unavailable-assessment", "NOT_AVAILABLE")

        status, _ = evaluate_control(
            self.conn, "S3.8", live=True
        )

        self.assertEqual(status, "NOT_OBSERVED")


if __name__ == "__main__":
    unittest.main()
