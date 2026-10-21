
from urllib.parse import urlsplit


def normalize_finding(finding, finding_id):
    """
    Convert Nmap, Nuclei, and Semgrep findings into a common format.
    Supports both already-normalized fields and native scanner fields.
    """

    info = finding.get("info")
    if not isinstance(info, dict):
        info = {}

    extra = finding.get("extra")
    if not isinstance(extra, dict):
        extra = {}

    # Identify the scanner.
    source_tool = (
        finding.get("source_tool")
        or finding.get("tool")
    )

    if not source_tool:
        if "template-id" in finding or "template_id" in finding:
            source_tool = "Nuclei"
        elif "check_id" in finding or "results" in finding:
            source_tool = "Semgrep"
        else:
            source_tool = "Unknown"

    # Extract the vulnerability title.
    title = (
        finding.get("title")
        or info.get("name")
        or finding.get("check_id")
        or finding.get("template-id")
        or finding.get("template_id")
        or finding.get("name")
        or "Untitled finding"
    )

    # Extract its description.
    description = (
        finding.get("description")
        or info.get("description")
        or finding.get("message")
        or extra.get("message")
        or ""
    )

    # Extract severity from the relevant scanner fields.
    severity = (
        finding.get("severity")
        or info.get("severity")
        or extra.get("severity")
        or "unknown"
    )

    # Get host and port, using the URL if necessary.
    host = finding.get("host")
    port = finding.get("port")

    matched_url = (
        finding.get("matched-at")
        or finding.get("matched_at")
        or finding.get("url")
    )

    if matched_url:
        try:
            parsed_url = urlsplit(matched_url)

            if not host:
                host = parsed_url.hostname

            if not port:
                port = parsed_url.port
        except (ValueError, TypeError):
            pass

    return {
        "finding_id": finding_id,
        "source_tool": source_tool,
        "title": title,
        "description": description,
        "severity": str(severity).lower(),
        "host": host or "unknown",
        "port": port
    }
