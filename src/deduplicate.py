
try:
    from src.similarity import calculate_similarity
except ImportError:
    from similarity import calculate_similarity


SIMILARITY_THRESHOLD = 0.70

SEVERITY_RANK = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}



def are_duplicates(finding1, finding2):
    """Identify duplicate findings at the same location."""

    host1 = str(finding1.get("host") or "").strip().lower()
    host2 = str(finding2.get("host") or "").strip().lower()

    port1 = str(finding1.get("port") or "").strip()
    port2 = str(finding2.get("port") or "").strip()

    if not host1 or not host2 or host1 == "unknown" or host2 == "unknown":
        return False, 0.0

    if not port1 or not port2 or port1 != port2:
        return False, 0.0

    title1 = str(finding1.get("title") or "").strip()
    title2 = str(finding2.get("title") or "").strip()

    desc1 = str(finding1.get("description") or "").strip()
    desc2 = str(finding2.get("description") or "").strip()

    if not title1 or not title2:
        return False, 0.0

    # Exact title and description match at the same location.
    if title1.casefold() == title2.casefold() and desc1.casefold() == desc2.casefold():
        return True, 1.0

    # Different titles need a much stronger semantic match.
    title_similarity = float(calculate_similarity(title1, title2))

    if title_similarity < 0.85 or not desc1 or not desc2:
        return False, title_similarity

    description_similarity = float(calculate_similarity(desc1, desc2))
    similarity = 0.6 * title_similarity + 0.4 * description_similarity

    return similarity >= 0.85, similarity



def merge_findings(finding1, finding2):
    """Merge duplicate records and preserve source tools and severity."""

    merged = finding1.copy()

    for field in ("title", "description"):
        if not merged.get(field) and finding2.get(field):
            merged[field] = finding2[field]

    source_tools = []

    for finding in (finding1, finding2):
        existing = finding.get("source_tools", [])

        if isinstance(existing, str):
            existing = [existing]

        candidates = list(existing or [])

        source_tool = finding.get("source_tool")
        if source_tool:
            candidates.append(source_tool)

        for tool in candidates:
            if tool and tool not in source_tools:
                source_tools.append(tool)

    merged["source_tools"] = source_tools

    severity1 = str(finding1.get("severity") or "").lower()
    severity2 = str(finding2.get("severity") or "").lower()

    rank1 = SEVERITY_RANK.get(severity1, -1)
    rank2 = SEVERITY_RANK.get(severity2, -1)

    if rank2 > rank1:
        merged["severity"] = finding2.get("severity")

    return merged
