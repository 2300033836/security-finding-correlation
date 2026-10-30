
import re

try:
    from src.similarity import calculate_similarity
except ImportError:
    from similarity import calculate_similarity


SIMILARITY_THRESHOLD = 0.80

SEVERITY_RANK = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def normalize_text(value):
    return " ".join(str(value or "").casefold().split())


def normalize_host(value):
    from urllib.parse import urlsplit

    host = str(value or "").strip().lower()

    if not host or host == "unknown":
        return ""

    try:
        if "://" in host:
            host = urlsplit(host).hostname or ""
    except ValueError:
        return ""

    return host.rstrip(".")


def normalize_port(value):
    if value is None or str(value).strip() == "":
        return ""

    try:
        return str(int(value))
    except (ValueError, TypeError):
        return str(value).strip()


def get_location_match(finding1, finding2):
    host1 = normalize_host(finding1.get("host"))
    host2 = normalize_host(finding2.get("host"))

    if not host1 or host1 != host2:
        return False

    port1 = normalize_port(finding1.get("port"))
    port2 = normalize_port(finding2.get("port"))

    return bool(port1 and port2 and port1 == port2)


def get_finding_category(finding):
    """Identify a known vulnerability or service-detection category."""

    text = " ".join([
        normalize_text(finding.get("title")),
        normalize_text(finding.get("description")),
        normalize_text(finding.get("template_id")),
        normalize_text(finding.get("rule_id")),
    ])

    # Vulnerability categories.
    if re.search(r"sql[\s._-]*injection|\bsqli\b", text):
        return "vulnerability:sql-injection"

    if re.search(r"cross[\s-]*site scripting|\bxss\b", text):
        return "vulnerability:xss"

    if "missing security headers" in text:
        return "vulnerability:missing-security-headers"

    # Service detection categories.
    if re.search(r"\bssh\b", text) and re.search(
        r"open|exposed|accessible|service", text
    ):
        return "service:ssh"

    if re.search(r"\bhttps\b", text) and re.search(
        r"open|exposed|accessible|service", text
    ):
        return "service:https"

    if re.search(r"\bhttp\b", text) and re.search(
        r"open|exposed|accessible|service", text
    ):
        return "service:http"

    return None


def are_duplicates(finding1, finding2):
    """Compare findings using location, known categories and semantics."""

    if not get_location_match(finding1, finding2):
        return False, 0.0

    category1 = get_finding_category(finding1)
    category2 = get_finding_category(finding2)

    # Matching known vulnerability/service categories at the same
    # host and port provide strong evidence of a duplicate.
    if category1 and category1 == category2:
        return True, 0.95

    # Different known categories must not be merged just because
    # their descriptions happen to sound similar.
    if category1 and category2 and category1 != category2:
        return False, 0.0

    title1 = normalize_text(finding1.get("title"))
    title2 = normalize_text(finding2.get("title"))

    description1 = normalize_text(finding1.get("description"))
    description2 = normalize_text(finding2.get("description"))

    if not title1 or not title2:
        return False, 0.0

    title_similarity = calculate_similarity(title1, title2)

    if description1 and description2:
        description_similarity = calculate_similarity(
            description1, description2
        )
        similarity = (
            0.45 * title_similarity
            + 0.55 * description_similarity
        )
    else:
        similarity = title_similarity

    if title_similarity < 0.60:
        return False, float(similarity)

    return (
        similarity >= SIMILARITY_THRESHOLD,
        float(similarity)
    )


def merge_findings(finding1, finding2):
    """Merge duplicates and preserve scanner sources and severity."""

    merged = finding1.copy()

    for field, value in finding2.items():
        if field not in merged or merged[field] in (None, "", [], {}):
            merged[field] = value

    source_tools = []

    for finding in (finding1, finding2):
        existing = finding.get("source_tools") or []

        if isinstance(existing, str):
            existing = [existing]

        source_tool = finding.get("source_tool") or finding.get("tool")

        candidates = list(existing)

        if source_tool:
            candidates.append(source_tool)

        for tool in candidates:
            if tool and tool not in source_tools:
                source_tools.append(tool)

    merged["source_tools"] = source_tools

    severity1 = str(
        finding1.get("severity") or "unknown"
    ).lower()

    severity2 = str(
        finding2.get("severity") or "unknown"
    ).lower()

    rank1 = SEVERITY_RANK.get(severity1, -1)
    rank2 = SEVERITY_RANK.get(severity2, -1)

    if rank2 > rank1:
        merged["severity"] = finding2.get("severity")

    return merged
