import unittest

from collector.sources import SecurityHubSource


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages
        self.kwargs = None

    def paginate(self, **kwargs):
        self.kwargs = kwargs
        yield from self.pages


class FakeClient:
    def __init__(self, paginator):
        self.paginator = paginator
        self.operation = None

    def get_paginator(self, operation):
        self.operation = operation
        return self.paginator


class FailingPaginator:
    def paginate(self, **kwargs):
        raise PermissionError("Access denied")
        yield


class SecurityHubLiveTests(unittest.TestCase):

    def test_collects_multiple_pages(self):
        paginator = FakePaginator([
            {"Findings": [{"Id": "finding-1"}]},
            {"Findings": [{"Id": "finding-2"}]},
        ])
        client = FakeClient(paginator)

        result = SecurityHubSource(live_client=client)._fetch_live()

        self.assertEqual(
            [item["Id"] for item in result],
            ["finding-1", "finding-2"],
        )
        self.assertEqual(client.operation, "get_findings")
        self.assertEqual(
            paginator.kwargs["PaginationConfig"]["PageSize"],
            100,
        )

    def test_empty_result_is_not_mock_data(self):
        client = FakeClient(FakePaginator([{"Findings": []}]))
        result = SecurityHubSource(live_client=client)._fetch_live()
        self.assertEqual(result, [])

    def test_live_api_failure_is_not_silently_ignored(self):
        client = FakeClient(FailingPaginator())

        with self.assertRaises(PermissionError):
            SecurityHubSource(live_client=client)._fetch_live()


if __name__ == "__main__":
    unittest.main()
