
def get_source_tools(finding):
    tools = finding.get("source_tools")

    if not tools:
        tool = finding.get("source_tool")
        tools = [tool] if tool else []

    return {str(tool).strip().lower() for tool in tools if tool}


def are_correlated(finding1, finding2):
    id1 = finding1.get("finding_id")
    id2 = finding2.get("finding_id")

    if not id1 or not id2 or id1 == id2:
        return False

    host1 = finding1.get("host")
    host2 = finding2.get("host")
    port1 = finding1.get("port")
    port2 = finding2.get("port")

    # Require the same known host and same known port.
    if not host1 or host1 == "unknown" or host1 != host2:
        return False

    if port1 is None or port2 is None or str(port1) != str(port2):
        return False

    # Require separate scanner sources for this contextual relationship.
    tools1 = get_source_tools(finding1)
    tools2 = get_source_tools(finding2)

    if not tools1 or not tools2 or tools1.intersection(tools2):
        return False

    return True


def get_correlation_reason(finding1, finding2):
    return "Same host and same port across separate tool sources (contextual; not proof of causation)"


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
                    "reason": get_correlation_reason(finding1, finding2)
                })

    return correlations
