import unittest

from src.parsers.nuclei_parser import parse_nuclei_json
from src.loaders import load_nuclei_findings


class TestNucleiParser(unittest.TestCase):

    def test_nuclei_parser(self):

        findings = parse_nuclei_json(
            "input/nuclei_results.json"
        )

        self.assertEqual(
            len(findings),
            3
        )

        self.assertEqual(
            findings[0]["tool"],
            "Nuclei"
        )

        self.assertEqual(
            findings[0]["host"],
            "192.168.1.10"
        )

        self.assertEqual(
            findings[0]["port"],
            22
        )


class TestNucleiLoader(unittest.TestCase):

    def test_nuclei_loader(self):

        findings = load_nuclei_findings(
            "input/nuclei_results.json"
        )

        self.assertEqual(
            len(findings),
            3
        )


if __name__ == "__main__":
    unittest.main()