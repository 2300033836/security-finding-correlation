import unittest

from src.parsers.semgrep_parser import parse_semgrep_json


class TestSemgrepParser(unittest.TestCase):

    def test_parse_semgrep_json(self):

        findings = parse_semgrep_json(
            "input/semgrep_results.json"
        )

        self.assertEqual(
            len(findings),
            2
        )

        self.assertEqual(
            findings[0]["tool"],
            "Semgrep"
        )

        self.assertEqual(
            findings[0]["title"],
            "python.sql.injection"
        )

        self.assertEqual(
            findings[0]["severity"],
            "high"
        )

        self.assertEqual(
            findings[1]["severity"],
            "medium"
        )

        self.assertEqual(
            findings[0]["host"],
            "192.168.1.10"
        )

        self.assertEqual(
            findings[0]["port"],
            8080
        )


if __name__ == "__main__":
    unittest.main()