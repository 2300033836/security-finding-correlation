
from src.deduplicate import are_duplicates, merge_findings
from src.find_duplicates import merge_duplicate_findings


def finding(fid, tool, severity):
    return {
        "finding_id": fid,
        "source_tool": tool,
        "title": "SQL Injection",
        "description": "User input reaches a SQL query without validation",
        "severity": severity,
        "host": "192.168.1.10",
        "port": 8080,
    }


def test_three_findings_merge_into_one():
    items = [
        finding("F001", "Nmap", "medium"),
        finding("F002", "Nuclei", "high"),
        finding("F003", "Semgrep", "critical"),
    ]

    merged = merge_duplicate_findings(items)

    assert len(merged) == 1, f"Expected 1 merged record, got {len(merged)}"
    assert merged[0]["severity"] == "critical"
    assert set(merged[0]["source_tools"]) == {
        "Nmap", "Nuclei", "Semgrep"
    }
    print("PASS: Three findings merge, all tools and highest severity retained")


def test_unknown_location_never_matches():
    a = finding("F004", "Nuclei", "high")
    b = finding("F005", "Semgrep", "high")

    a["host"] = "unknown"
    b["host"] = "unknown"
    a["port"] = None
    b["port"] = None

    is_duplicate, score = are_duplicates(a, b)

    assert not is_duplicate
    assert score == 0.0
    print("PASS: Unknown locations are not merged")


def test_different_ports_do_not_match():
    a = finding("F006", "Nuclei", "high")
    b = finding("F007", "Semgrep", "high")
    b["port"] = 443

    is_duplicate, score = are_duplicates(a, b)

    assert not is_duplicate
    assert score == 0.0
    print("PASS: Findings on different ports remain separate")


if __name__ == "__main__":
    test_three_findings_merge_into_one()
    test_unknown_location_never_matches()
    test_different_ports_do_not_match()
    print("\nAll deduplication validation tests passed.")
