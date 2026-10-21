
from src.pipeline import run_pipeline

# Run Nmap XML + real Nuclei JSONL + Semgrep JSON
result = run_pipeline(
    (
        "input/nmap_results.json",
        "input/nuclei_real_results.json",
        "input/semgrep_results.json"
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
