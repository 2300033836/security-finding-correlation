import unittest

from src.pipeline import run_pipeline


class TestMultiToolPipeline(unittest.TestCase):

    def test_multi_tool_pipeline(self):

        result = run_pipeline(
            (
                "input/nmap_results.json",
                "input/nuclei_results.json",
                "input/semgrep_results.json"
            ),
            "multi"
        )

        self.assertEqual(
            result["original_count"],
            8
        )

        self.assertEqual(
            len(result["normalized_findings"]),
            8
        )

        self.assertGreaterEqual(
            len(result["duplicate_pairs"]),
            1
        )

        self.assertLess(
            len(result["merged_findings"]),
            8
        )


if __name__ == "__main__":
    unittest.main()