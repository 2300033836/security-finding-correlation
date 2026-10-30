
import json
from pathlib import Path
from datetime import datetime, timezone

from src.main import process_findings

from src.loaders import (
    load_nmap_findings,
    load_nuclei_findings,
    load_semgrep_findings
)

from src.multi_loader import load_all_findings

from database.db import (
    clear_pipeline_results,
    insert_findings,
    insert_duplicate_matches,
    insert_correlations
)


def run_pipeline(input_file, input_type="json"):

    # 1. Load security findings
    if input_type == "nmap":
        findings = load_nmap_findings(input_file)

    elif input_type == "nuclei":
        findings = load_nuclei_findings(input_file)

    elif input_type == "semgrep":
        findings = load_semgrep_findings(input_file)

    elif input_type == "multi":
        nmap_file, nuclei_file, semgrep_file = input_file

        findings = load_all_findings(
            nmap_file,
            nuclei_file,
            semgrep_file
        )

    else:
        with open(input_file, "r", encoding="utf-8") as file:
            findings = json.load(file)

    print("Raw findings:", len(findings))

    # 2. Process findings
    result = process_findings(findings)

    print("Normalized findings:", len(result["normalized_findings"]))
    print("Duplicate matches:", len(result["duplicate_pairs"]))
    print("Merged findings:", len(result["merged_findings"]))
    print("Correlations:", len(result["correlations"]))

    # 3. Save results to database
    clear_pipeline_results()

    insert_findings(result["merged_findings"])
    insert_duplicate_matches(result["duplicate_pairs"])
    insert_correlations(result["correlations"])

    # 4. Generate JSON report
    base_dir = Path(__file__).resolve().parent.parent

    reports_dir = base_dir / "reports"
    reports_dir.mkdir(exist_ok=True)

    report_file = reports_dir / "security_report.json"

    report = {
        "metadata": {
            "project": "Security Finding Correlation",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_type": input_type,
            "tools": ["Nmap", "Nuclei", "Semgrep"]
        },

        "summary": {
            "original_findings": result["original_count"],
            "duplicate_matches": len(result["duplicate_pairs"]),
            "consolidated_findings": len(result["merged_findings"]),
            "correlations": len(result["correlations"])
        },

        "duplicate_matches": result["duplicate_pairs"],

        "consolidated_findings": result["merged_findings"],

        "correlations": result["correlations"]
    }

    with open(report_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    print("\nReport generated:")
    print(report_file)

    print("\nPipeline completed successfully!")

    return result
