import json

from src.main import process_findings
from database.db import (
    insert_findings,
    insert_duplicate_matches,
    insert_correlations
)


with open("data/sample_findings.json", "r") as file:
    findings = json.load(file)
# Run the complete pipeline
result = process_findings(findings)

# Insert merged findings into MySQL
insert_findings(result["merged_findings"])

# Insert duplicate matches into MySQL
insert_duplicate_matches(result["duplicate_pairs"])

# Insert correlations into MySQL
insert_correlations(result["correlations"])


print("Complete pipeline results inserted into MySQL!")