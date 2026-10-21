import unittest

from src.parsers.nmap_parser import parse_nmap_json


class TestNmapParser(unittest.TestCase):

    def test_nmap_parser(self):

        findings = parse_nmap_json(
            "input/nmap_results.json"
        )

        # We have 3 open ports
        self.assertEqual(
            len(findings),
            3
        )

        # Check first finding
        self.assertEqual(
            findings[0]["tool"],
            "Nmap"
        )

        self.assertEqual(
            findings[0]["host"],
            "192.168.1.10"
        )

        self.assertEqual(
            findings[0]["port"],
            22
        )

        self.assertEqual(
            findings[0]["title"],
            "Open SSH Port"
        )

        # Check second finding
        self.assertEqual(
            findings[1]["host"],
            "192.168.1.10"
        )

        self.assertEqual(
            findings[1]["port"],
            80
        )

        # Check third finding
        self.assertEqual(
            findings[2]["host"],
            "192.168.1.20"
        )

        self.assertEqual(
            findings[2]["port"],
            443
        )


if __name__ == "__main__":
    unittest.main()