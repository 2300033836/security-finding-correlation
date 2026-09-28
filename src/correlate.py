def are_correlated(finding1, finding2):
    same_host = finding1["host"] == finding2["host"]

    different_finding = (
        finding1["finding_id"] != finding2["finding_id"]
    )

    return same_host and different_finding


def find_correlations(findings):
    correlations = []

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):

            finding1 = findings[i]
            finding2 = findings[j]

            if are_correlated(finding1, finding2):
                correlations.append({
                    "finding1": finding1["finding_id"],
                    "finding2": finding2["finding_id"],
                    "reason": "Same host"
                })

    return correlations