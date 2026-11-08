import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import collect


class FakePaginator:
    def __init__(self, pages=None, error=None):
        self.pages = pages or []
        self.error = error

    def paginate(self, **kwargs):
        if self.error:
            raise self.error
        yield from self.pages


class FakeClient:
    def __init__(self, paginator):
        self.paginator = paginator

    def get_paginator(self, name):
        assert name == "get_findings"
        return self.paginator


class FakeSession:
    def __init__(self, client):
        self.aws_client = client

    def client(self, service, **kwargs):
        assert service == "securityhub"
        return self.aws_client


class CollectorIntegrationTests(unittest.TestCase):

    def run_collector(self, directory, paginator):
        args = [
            "collect.py",
            "--source", "aws-security-hub",
            "--aws-region", "us-east-1",
        ]

        with (
            patch.object(sys, "argv", args),
            patch.object(collect, "ROOT", Path(directory)),
            patch("boto3.Session",
                  return_value=FakeSession(FakeClient(paginator))),
        ):
            return collect.main()

    def test_failed_api_does_not_create_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PermissionError):
                self.run_collector(
                    tmp,
                    FakePaginator(error=PermissionError("Access denied")),
                )

            self.assertFalse(
                (Path(tmp) / "data/securityhub_live.db").exists()
            )

    def test_empty_response_creates_successful_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_collector(
                tmp, FakePaginator([{"Findings": []}])
            )

            self.assertEqual(result, 0)

            db = Path(tmp) / "data/securityhub_live.db"
            self.assertTrue(db.exists())

            with sqlite3.connect(db) as conn:
                findings = conn.execute(
                    "SELECT COUNT(*) FROM findings"
                ).fetchone()[0]

                runs = conn.execute(
                    "SELECT COUNT(*) FROM collector_runs"
                ).fetchone()[0]

            self.assertEqual(findings, 0)
            self.assertEqual(runs, 1)

    def test_realistic_finding_is_ingested(self):
        raw = {
            "Id": "synthetic-aws-integration-001",
            "Title": "Synthetic S3 security finding",
            "Description": "Integration test only",
            "Resources": [{
                "Id": "arn:aws:s3:::synthetic-test-bucket",
                "Type": "AwsS3Bucket",
            }],
            "Severity": {"Label": "HIGH"},
            "Workflow": {"Status": "NEW"},
            "CreatedAt": "2026-11-08T00:00:00Z",
            "UpdatedAt": "2026-11-08T00:00:00Z",
        }

        with tempfile.TemporaryDirectory() as tmp:
            self.run_collector(
                tmp,
                FakePaginator([{"Findings": [raw]}]),
            )

            db = Path(tmp) / "data/securityhub_live.db"

            with sqlite3.connect(db) as conn:
                row = conn.execute(
                    "SELECT severity, status, source "
                    "FROM findings WHERE finding_id = ?",
                    (raw["Id"],),
                ).fetchone()

            self.assertIsNotNone(row)
            self.assertEqual(
                row,
                ("high", "open", "aws_security_hub"),
            )

    def test_live_collection_does_not_touch_mock_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            mock_db = Path(tmp) / "data/findings.db"
            mock_db.parent.mkdir(parents=True)
            mock_db.write_bytes(b"mock-database-sentinel")

            self.run_collector(
                tmp, FakePaginator([{"Findings": []}])
            )

            self.assertEqual(
                mock_db.read_bytes(),
                b"mock-database-sentinel",
            )


if __name__ == "__main__":
    unittest.main()
