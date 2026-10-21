import json


def parse_semgrep_json(file_path):

    with open(file_path, "r") as file:
        data = json.load(file)

    findings = []
    

    for result in data:

        check_id = result.get(
            "check_id",
            "Unknown check"
        )

        extra = result.get(
            "extra",
            {}
        )

        message = extra.get(
            "message",
            "No description available"
        )

        severity = extra.get(
            "severity",
            "unknown"
        )

        path = result.get(
            "path",
            "Unknown file"
        )

        host = result.get(
            "host",
            "unknown"
        )

        port = result.get(
            "port",
            None
        )

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