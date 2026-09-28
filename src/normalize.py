def normalize_finding(finding, finding_id):
    normalized = {
        "finding_id": finding_id,
        "source_tool": finding.get("tool"),
        "title": finding.get("title"),
        "description": finding.get("description"),
        "severity": finding.get("severity"),
        "host": finding.get("host"),
        "port": finding.get("port")
    }

    return normalized