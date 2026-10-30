
from urllib.parse import urlsplit


def normalize_severity(severity):
    severity = str(severity or "unknown").strip().lower()

    severity_mapping = {
        "critical": "critical",
        "high": "high",
        "error": "high",
        "medium": "medium",
        "moderate": "medium",
        "warning": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "unknown": "unknown",
    }

    return severity_mapping.get(severity, "unknown")


def normalize_host(host):
    if not host:
        return "unknown"

    host = str(host).strip()

    try:
        if "://" in host:
            return (urlsplit(host).hostname or "unknown").lower()

        # Handle host:port values such as 10.20.1.10:2222.
        if host.count(":") == 1:
            hostname, port = host.rsplit(":", 1)

            if port.isdigit():
                return hostname.lower()

    except ValueError:
        pass

    return host.strip("/").lower()


def normalize_port(port, matched_url=None, host=None):
    # Prefer an explicitly supplied port.
    if port is not None and str(port).strip():
        try:
            return int(port)
        except (ValueError, TypeError):
            pass

    # Extract an embedded port from the host field.
    if host:
        host = str(host).strip()

        try:
            if "://" in host:
                parsed = urlsplit(host)
                if parsed.port is not None:
                    return parsed.port

            elif host.count(":") == 1:
                hostname, embedded_port = host.rsplit(":", 1)

                if embedded_port.isdigit():
                    return int(embedded_port)

        except ValueError:
            pass

    # Extract a port from a matched URL or host:port value.
    if matched_url:
        matched_url = str(matched_url).strip()

        try:
            if "://" in matched_url:
                return urlsplit(matched_url).port

            if matched_url.count(":") == 1:
                hostname, embedded_port = matched_url.rsplit(":", 1)

                if embedded_port.isdigit():
                    return int(embedded_port)

        except ValueError:
            pass

    return None


def normalize_finding(finding, finding_id):
    info = finding.get("info") or {}
    extra = finding.get("extra") or {}

    metadata = (
        extra.get("metadata")
        or finding.get("metadata")
        or {}
    )

    # Identify the source security tool.
    source_tool = (
        finding.get("source_tool")
        or finding.get("tool")
    )

    if not source_tool:
        if "template-id" in finding or "template_id" in finding:
            source_tool = "Nuclei"

        elif "check_id" in finding:
            source_tool = "Semgrep"

        elif "ports" in finding or "address" in finding:
            source_tool = "Nmap"

        else:
            source_tool = "Unknown"

    # Preserve the tools that contributed to this finding.
    source_tools = finding.get("source_tools") or []

    if isinstance(source_tools, str):
        source_tools = [source_tools]

    if source_tool and source_tool not in source_tools:
        source_tools = list(source_tools) + [source_tool]

    # Extract title.
    title = (
        finding.get("title")
        or info.get("name")
        or finding.get("check_id")
        or finding.get("template-id")
        or finding.get("template_id")
        or finding.get("name")
        or "Untitled finding"
    )

    # Extract description.
    description = (
        finding.get("description")
        or info.get("description")
        or finding.get("message")
        or extra.get("message")
        or ""
    )

    # Normalize severity.
    severity = normalize_severity(
        finding.get("severity")
        or info.get("severity")
        or extra.get("severity")
    )

    # Extract URL and location information.
    matched_url = (
        finding.get("matched-at")
        or finding.get("matched_at")
        or finding.get("url")
        or finding.get("endpoint")
    )

    host_value = (
        finding.get("host")
        or finding.get("address")
        or metadata.get("host")
    )

    port_value = (
        finding.get("port")
        or metadata.get("port")
    )

    host = normalize_host(host_value)

    port = normalize_port(
        port_value,
        matched_url,
        host_value
    )

    # Extract endpoint.
    endpoint = finding.get("endpoint")

    if not endpoint and matched_url:
        try:
            if "://" in str(matched_url):
                parsed = urlsplit(str(matched_url))

                if parsed.path and parsed.path != "/":
                    endpoint = parsed.path

        except ValueError:
            pass

    # Extract service.
    service = (
        finding.get("service")
        or metadata.get("service")
    )

    if isinstance(service, dict):
        service = (
            service.get("name")
            or service.get("product")
        )

    # Extract technology.
    technology = (
        finding.get("technology")
        or metadata.get("technology")
        or metadata.get("product")
    )

    # Extract file and rule information.
    file_path = (
        finding.get("file")
        or finding.get("path")
    )

    template_id = (
        finding.get("template-id")
        or finding.get("template_id")
    )

    rule_id = (
        finding.get("check_id")
        or finding.get("rule_id")
    )

    # Extract tags.
    tags = (
        finding.get("tags")
        or info.get("tags")
        or []
    )

    if isinstance(tags, str):
        tags = [
            tag.strip()
            for tag in tags.split(",")
            if tag.strip()
        ]

    # Extract references.
    references = (
        finding.get("references")
        or info.get("reference")
        or []
    )

    if isinstance(references, str):
        references = [references]

    # Build normalized finding.
    normalized = {
        "finding_id": finding_id,
        "source_tool": source_tool,
        "source_tools": list(source_tools),
        "title": str(title),
        "description": str(description),
        "severity": severity,
        "host": host,
        "port": port,
        "metadata": metadata.copy(),
    }

    # Preserve optional information when available.
    if matched_url:
        normalized["url"] = matched_url

    if endpoint:
        normalized["endpoint"] = endpoint

    if service:
        normalized["service"] = service

    if technology:
        normalized["technology"] = technology

    if file_path:
        normalized["file"] = file_path

    if template_id:
        normalized["template_id"] = template_id

    if rule_id:
        normalized["rule_id"] = rule_id

    if tags:
        normalized["tags"] = tags

    if references:
        normalized["references"] = references

    return normalized
