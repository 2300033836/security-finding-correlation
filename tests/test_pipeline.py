import unittest

from src.main import process_findings


class TestPipeline(unittest.TestCase):

    def setUp(self):

        self.findings = [
            {
                "tool": "Nmap",
                "title": "Open SSH Port",
                "description": "SSH service is accessible on port 22",
                "severity": "medium",
                "host": "192.168.1.10",
                "port": 22
            },
            {
                "tool": "Nuclei",
                "title": "SSH Service Exposed",
                "description": "An SSH service is exposed on port 22",
                "severity": "medium",
                "host": "192.168.1.10",
                "port": 22
            },
            {
                "tool": "Semgrep",
                "title": "Potential SQL Injection",
                "description": "User-controlled input may reach a SQL query without proper validation",
                "severity": "high",
                "host": "192.168.1.10",
                "port": 8080
            },
            {
                "tool": "ZAP",
                "title": "SQL Injection",
                "description": "A user input parameter appears vulnerable to SQL injection",
                "severity": "high",
                "host": "192.168.1.10",
                "port": 8080
            }
        ]


    def test_complete_pipeline(self):

        result = process_findings(
            self.findings
        )

        print("\n--- Pipeline Result ---")

        print(
            "Original findings:",
            result["original_count"]
        )

        print(
            "Duplicate pairs:",
            len(result["duplicate_pairs"])
        )

        print(
            "Merged findings:",
            len(result["merged_findings"])
        )

        print(
            "Correlations:",
            len(result["correlations"])
        )


        # ------------------------------------------
        # Check original findings
        # ------------------------------------------

        self.assertEqual(
            result["original_count"],
            4
        )


        # ------------------------------------------
        # Check duplicate detection
        # ------------------------------------------

        self.assertEqual(
            len(result["duplicate_pairs"]),
            2
        )


        # ------------------------------------------
        # Check merged findings
        # ------------------------------------------

        self.assertEqual(
            len(result["merged_findings"]),
            2
        )


                # ------------------------------------------
        # Check correlation
        #
        # Current rule:
        # Findings on the same host are correlated.
        #
        # After deduplication, the two remaining
        # findings are:
        #
        # SSH  -> port 22
        # SQL  -> port 8080
        #
        # They are on the same host, so they are
        # correlated.
        # ------------------------------------------

        self.assertEqual(
            len(result["correlations"]),
            1
        )


if __name__ == "__main__":
    unittest.main()