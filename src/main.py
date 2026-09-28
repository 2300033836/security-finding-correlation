import json

from src.normalize import normalize_finding
from src.find_duplicates import find_duplicate_pairs, merge_duplicate_findings
from src.correlate import find_correlations


def process_findings(findings):
    # Step 1: Normalize
    normalized_findings = []

    for index, finding in enumerate(findings, start=1):
        finding_id = f"F{index:03d}"

        normalized = normalize_finding(
            finding,
            finding_id
        )

        normalized_findings.append(normalized)

    # Step 2: Find duplicates
    duplicate_pairs = find_duplicate_pairs(
        normalized_findings
    )

    # Step 3: Merge duplicates
    merged_findings = merge_duplicate_findings(
        normalized_findings
    )

    # Step 4: Find correlations
    correlations = find_correlations(
        merged_findings
    )

    return {
        "original_count": len(findings),
        "normalized_findings": normalized_findings,
        "duplicate_pairs": duplicate_pairs,
        "merged_findings": merged_findings,
        "correlations": correlations
    }


if __name__ == "__main__":

    with open("data/sample_findings.json", "r") as file:
        findings = json.load(file)

    result = process_findings(findings)

    print("Original findings:", result["original_count"])

    print("\nDuplicate pairs:")
    for pair in result["duplicate_pairs"]:
        print(
            pair["finding1"],
            "<->",
            pair["finding2"],
            "| Similarity:",
            pair["similarity"]
        )

    print("\nMerged findings:")
    for finding in result["merged_findings"]:
        print(finding)

    print("\nCorrelations:")
    for correlation in result["correlations"]:
        print(
            correlation["finding1"],
            "<->",
            correlation["finding2"],
            "| Reason:",
            correlation["reason"]
        )