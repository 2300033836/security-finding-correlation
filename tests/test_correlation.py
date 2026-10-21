import unittest

from src.correlate import (
    are_correlated,
    find_correlations
)


class TestCorrelation(unittest.TestCase):

    def test_same_host_and_same_port(self):

        finding1 = {
            "finding_id": "F001",
            "host": "192.168.1.10",
            "port": 80
        }

        finding2 = {
            "finding_id": "F002",
            "host": "192.168.1.10",
            "port": 80
        }

        self.assertTrue(
            are_correlated(
                finding1,
                finding2
            )
        )


    def test_same_host_different_port(self):

        finding1 = {
            "finding_id": "F001",
            "host": "192.168.1.10",
            "port": 80
        }

        finding2 = {
            "finding_id": "F002",
            "host": "192.168.1.10",
            "port": 443
        }

        self.assertTrue(
            are_correlated(
                finding1,
                finding2
            )
        )


    def test_different_host(self):

        finding1 = {
            "finding_id": "F001",
            "host": "192.168.1.10",
            "port": 80
        }

        finding2 = {
            "finding_id": "F002",
            "host": "192.168.1.20",
            "port": 80
        }

        self.assertFalse(
            are_correlated(
                finding1,
                finding2
            )
        )


    def test_find_correlations(self):

        findings = [
            {
                "finding_id": "F001",
                "host": "192.168.1.10",
                "port": 80
            },
            {
                "finding_id": "F002",
                "host": "192.168.1.10",
                "port": 80
            },
            {
                "finding_id": "F003",
                "host": "192.168.1.20",
                "port": 443
            }
        ]

        correlations = find_correlations(
            findings
        )

        self.assertEqual(
            len(correlations),
            1
        )

        self.assertEqual(
            correlations[0]["reason"],
            "Same host and same port"
        )


    def test_same_host_and_same_port_different_findings(self):

        findings = [
            {
                "finding_id": "F001",
                "title": "Open HTTP Port",
                "host": "192.168.1.10",
                "port": 80
            },
            {
                "finding_id": "F002",
                "title": "Missing Security Headers",
                "host": "192.168.1.10",
                "port": 80
            }
        ]

        correlations = find_correlations(
            findings
        )

        self.assertEqual(
            len(correlations),
            1
        )

        self.assertEqual(
            correlations[0]["reason"],
            "Same host and same port"
        )


    def test_same_host_different_port_can_be_correlated(self):

        finding1 = {
            "finding_id": "F001",
            "title": "Open HTTP Port",
            "host": "192.168.1.10",
            "port": 80
        }

        finding2 = {
            "finding_id": "F002",
            "title": "SQL Injection",
            "host": "192.168.1.10",
            "port": 8080
        }

        correlations = find_correlations(
            [finding1, finding2]
        )

        self.assertEqual(
            len(correlations),
            1
        )

        self.assertEqual(
            correlations[0]["reason"],
            "Same host"
        )


if __name__ == "__main__":
    unittest.main()