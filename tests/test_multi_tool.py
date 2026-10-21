import unittest

from src.multi_loader import load_all_findings


class TestMultiToolPipeline(unittest.TestCase):

    def test_multi_tool_pipeline(self):

        findings = load_all_findings(
            "input/nmap_results.json",
            "input/nuclei_results.json",
            "input/semgrep_results.json"
        )

        self.assertEqual(
            len(findings),
            8
        )

        tools = [
            finding["tool"]
            for finding in findings
        ]

        self.assertIn(
            "Nmap",
            tools
        )

        self.assertIn(
            "Nuclei",
            tools
        )

        self.assertIn(
            "Semgrep",
            tools
        )


if __name__ == "__main__":
    unittest.main()