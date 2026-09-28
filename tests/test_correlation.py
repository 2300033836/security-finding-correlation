import unittest

from src.correlate import are_correlated, find_correlations


class TestCorrelation(unittest.TestCase):

    def setUp(self):

        self.finding1 = {
            "finding_id": "F001",
            "source_tool": "Nmap",
            "title": "Open SSH Port",
            "description": "SSH service is accessible on port 22",
            "severity": "medium",
            "host": "192.168.1.10",
            "port": 22
        }

        self.finding2 = {
            "finding_id": "F002",
            "source_tool": "ZAP",
            "title": "SQL Injection",
            "description": "A user input parameter appears vulnerable to SQL injection",
            "severity": "high",
            "host": "192.168.1.10",
            "port": 8080
        }

        self.finding3 = {
            "finding_id": "F003",
            "source_tool": "Nuclei",
            "title": "Open HTTP Port",
            "description": "HTTP service is accessible on port 80",
            "severity": "low",
            "host": "192.168.1.20",
            "port": 80
        }


    def test_findings_on_same_host_are_correlated(self):

        result = are_correlated(
            self.finding1,
            self.finding2
        )

        print("\nSame host correlation:", result)

        self.assertTrue(result)


    def test_findings_on_different_hosts_are_not_correlated(self):

        result = are_correlated(
            self.finding1,
            self.finding3
        )

        print("\nDifferent host correlation:", result)

        self.assertFalse(result)


    def test_find_correlations(self):

        findings = [
            self.finding1,
            self.finding2,
            self.finding3
        ]

        correlations = find_correlations(findings)

        print("\nCorrelations found:")

        for correlation in correlations:
            print(correlation)

        self.assertEqual(
            len(correlations),
            1
        )

        self.assertEqual(
            correlations[0]["finding1"],
            "F001"
        )

        self.assertEqual(
            correlations[0]["finding2"],
            "F002"
        )

        self.assertEqual(
            correlations[0]["reason"],
            "Same host"
        )


if __name__ == "__main__":
    unittest.main()