
try:
    from src.deduplicate import are_duplicates, merge_findings
except ModuleNotFoundError:
    from deduplicate import are_duplicates, merge_findings


def find_duplicate_pairs(findings):
    duplicate_pairs = []

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):

            finding1 = findings[i]
            finding2 = findings[j]

            is_duplicate, similarity = are_duplicates(
                finding1,
                finding2
            )

            if is_duplicate:
                host1 = finding1.get("host")
                host2 = finding2.get("host")

                port1 = finding1.get("port")
                port2 = finding2.get("port")

                duplicate_pairs.append({
                    "finding1": finding1["finding_id"],
                    "finding2": finding2["finding_id"],
                    "similarity": similarity,
                    "host_match": bool(
                        host1 and host2 and
                        str(host1).strip().lower() ==
                        str(host2).strip().lower()
                    ),
                    "port_match": bool(
                        port1 is not None and
                        port2 is not None and
                        str(port1).strip() ==
                        str(port2).strip()
                    ),
                    "host": host1,
                    "port": port1
                })

    return duplicate_pairs


def merge_duplicate_findings(findings):
    merged_findings = []
    used_findings = set()

    for i in range(len(findings)):
        if findings[i]["finding_id"] in used_findings:
            continue

        current_finding = findings[i]

        for j in range(i + 1, len(findings)):
            if findings[j]["finding_id"] in used_findings:
                continue

            is_duplicate, similarity = are_duplicates(
                current_finding,
                findings[j]
            )

            if is_duplicate:
                current_finding = merge_findings(
                    current_finding,
                    findings[j]
                )

                used_findings.add(findings[j]["finding_id"])

        merged_findings.append(current_finding)

    return merged_findings
