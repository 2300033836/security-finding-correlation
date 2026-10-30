
from src.pipeline import run_pipeline

# Run the three duplicate-test reports.
result = run_pipeline(
    (
        "input/nmap_duplicate_test.json",
        "input/nuclei_duplicate_test.jsonl",
        "input/semgrep_duplicate_test.json"
    ),
    "multi"
)

print("\n========== FINAL RESULT ==========")
print("Original findings:", result["original_count"])
print("Duplicate matches:", len(result["duplicate_pairs"]))
print("Merged findings:", len(result["merged_findings"]))
print("Correlations:", len(result["correlations"]))

print("\n========== DUPLICATES ==========")
for duplicate in result["duplicate_pairs"]:
    print(duplicate)

print("\n========== MERGED FINDINGS ==========")
for finding in result["merged_findings"]:
    print(finding)

print("\n========== CORRELATIONS ==========")
for correlation in result["correlations"]:
    print(correlation)
