import unittest

from src.loaders import load_semgrep_findings


class TestSemgrepLoader(unittest.TestCase):

    def test_load_semgrep_findings(self):

        findings = load_semgrep_findings(
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
            findings[0]["host"],
            "192.168.1.10"
        )

        self.assertEqual(
            findings[0]["port"],
            8080
        )


if __name__ == "__main__":
    unittest.main()