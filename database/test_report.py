from database.db import get_all_findings


findings = get_all_findings()

print("\n========== SECURITY FINDINGS REPORT ==========\n")

print("Total consolidated findings:", len(findings))

print("\nFindings:\n")

for finding in findings:
    print("Finding ID :", finding["finding_id"])
    print("Tools      :", finding["source_tool"])
    print("Title      :", finding["title"])
    print("Severity   :", finding["severity"])
    print("Host       :", finding["host"])
    print("Port       :", finding["port"])
    print("----------------------------------------------")