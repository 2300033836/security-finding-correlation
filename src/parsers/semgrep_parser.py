
import json


def parse_semgrep_json(file_path):

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Support both Semgrep JSON formats:
    # 1. Top-level list
    # 2. Standard object containing "results"
    if isinstance(data, dict):
        data = data.get("results", [])

    if not isinstance(data, list):
        raise ValueError("Invalid Semgrep JSON structure.")

    findings = []

    for result in data:

        check_id = result.get("check_id", "Unknown check")

        extra = result.get("extra", {})

        message = extra.get(
            "message",
            "No description available"
        )

        severity = extra.get("severity", "unknown")

        path = result.get("path", "Unknown file")

        metadata = extra.get("metadata", {})

        host = result.get("host") or metadata.get("host", "unknown")

        port = result.get("port") or metadata.get("port")

        if severity == "ERROR":
            normalized_severity = "high"
        elif severity == "WARNING":
            normalized_severity = "medium"
        else:
            normalized_severity = "low"

        finding = {
            "tool": "Semgrep",
            "title": check_id,
            "description": message,
            "severity": normalized_severity,
            "host": host,
            "port": port,
            "file": path
        }

        findings.append(finding)

    return findings
