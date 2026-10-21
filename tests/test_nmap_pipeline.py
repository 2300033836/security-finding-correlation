import unittest

from src.pipeline import run_pipeline


class TestNmapPipeline(unittest.TestCase):

    def test_nmap_pipeline(self):

        result = run_pipeline(
            "input/nmap_results.json",
            input_type="nmap"
        )


        # -----------------------------------------
        # Check raw/normalized findings
        # -----------------------------------------

        self.assertEqual(
            result["original_count"],
            3
        )


        self.assertEqual(
            len(result["normalized_findings"]),
            3
        )


        # -----------------------------------------
        # Check merged findings
        # -----------------------------------------

        self.assertEqual(
            len(result["merged_findings"]),
            3
        )


        # -----------------------------------------
        # Check finding contents
        # -----------------------------------------

        first_finding = (
            result["normalized_findings"][0]
        )


        self.assertEqual(
            first_finding["source_tool"],
            "Nmap"
        )


        self.assertEqual(
            first_finding["host"],
            "192.168.1.10"
        )


        self.assertEqual(
            first_finding["port"],
            22
        )


if __name__ == "__main__":
    unittest.main()