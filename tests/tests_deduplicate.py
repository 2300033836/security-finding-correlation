import unittest

from src.deduplicate import are_duplicates, merge_findings
from src.find_duplicates import merge_duplicate_findings


class TestDeduplication(unittest.TestCase):

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
            "source_tool": "Nuclei",
            "title": "SSH Service Exposed",
            "description": "An SSH service is exposed on port 22",
            "severity": "medium",
            "host": "192.168.1.10",
            "port": 22
        }

        self.finding3 = {
            "finding_id": "F003",
            "source_tool": "ZAP",
            "title": "SQL Injection",
            "description": "A user input parameter appears vulnerable to SQL injection",
            "severity": "high",
            "host": "192.168.1.10",
            "port": 8080
        }

        self.finding4 = {
            "finding_id": "F004",
            "source_tool": "Semgrep",
            "title": "Potential SQL Injection",
            "description": "User-controlled input may reach a SQL query without proper validation",
            "severity": "high",
            "host": "192.168.1.10",
            "port": 8080
        }

        self.finding5 = {
            "finding_id": "F005",
            "source_tool": "ZAP",
            "title": "Cross-Site Scripting",
            "description": "A user input parameter appears vulnerable to cross-site scripting",
            "severity": "high",
            "host": "192.168.1.10",
            "port": 8080
        }


    def test_ssh_findings_are_duplicates(self):

        is_duplicate, similarity = are_duplicates(
            self.finding1,
            self.finding2
        )

        print("\nSSH similarity:", similarity)

        self.assertTrue(is_duplicate)


    def test_sql_findings_are_duplicates(self):

        is_duplicate, similarity = are_duplicates(
            self.finding3,
            self.finding4
        )

        print("\nSQL similarity:", similarity)

        self.assertTrue(is_duplicate)


    def test_sql_and_xss_are_not_duplicates(self):

        is_duplicate, similarity = are_duplicates(
            self.finding3,
            self.finding5
        )

        print("\nSQL vs XSS similarity:", similarity)

        self.assertFalse(is_duplicate)


    def test_merge_findings(self):

        merged = merge_findings(
            self.finding1,
            self.finding2
        )

        print("\nMerged finding:")
        print(merged)

        self.assertEqual(
            merged["finding_id"],
            "F001"
        )

        self.assertEqual(
            merged["source_tools"],
            ["Nmap", "Nuclei"]
        )


    def test_automatic_merge(self):

        findings = [
            self.finding1,
            self.finding2,
            self.finding3,
            self.finding4
        ]

        merged_findings = merge_duplicate_findings(
            findings
        )

        print("\nAutomatically merged findings:")

        for finding in merged_findings:
            print(finding)

        self.assertEqual(
            len(merged_findings),
            2
        )


if __name__ == "__main__":
    unittest.main()