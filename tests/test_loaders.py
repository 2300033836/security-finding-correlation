import unittest

from src.loaders import load_nmap_findings


class TestLoaders(unittest.TestCase):

    def test_load_nmap_findings(self):

        findings = load_nmap_findings(
            "input/nmap_results.json"
        )

        # We expect 3 open ports
        self.assertEqual(
            len(findings),
            3
        )

        # Check that the parser output
        # follows our common finding structure
        first_finding = findings[0]

        self.assertEqual(
            first_finding["tool"],
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