from database.db import get_all_findings


findings = get_all_findings()

print("Findings stored in database:")

for finding in findings:
    print(finding)