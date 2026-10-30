
try:
    from src.similarity import calculate_similarity
except ImportError:
    from similarity import calculate_similarity


DUPLICATE_THRESHOLD = 0.80
MIN_RELATIONSHIP_SIMILARITY = 0.35

CONTEXT_FIELDS = (
    "endpoint",
    "url",
    "service",
    "technology",
    "application",
    "asset",
)


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


def get_source_tools(finding):
    tools = finding.get("source_tools") or []

    if isinstance(tools, str):
        tools = [tools]

    source_tool = finding.get("source_tool") or finding.get("tool")

    if source_tool:
        tools = list(tools) + [source_tool]

    return {
        str(tool).strip().lower()
        for tool in tools
        if tool and str(tool).strip()
    }


def normalize_context(value):
    from urllib.parse import urlsplit

    if value is None:
        return ""

    value = str(value).strip().lower()

    if not value or value == "unknown":
        return ""

    try:
        if "://" in value:
            parsed = urlsplit(value)
            value = parsed.path or "/"
    except ValueError:
        return ""

    return value.rstrip("/")


def get_technical_context(finding):
    context = set()
    metadata = finding.get("metadata") or {}

    if not isinstance(metadata, dict):
        metadata = {}

    for field in CONTEXT_FIELDS:
        value = finding.get(field)

        if value is None:
            value = metadata.get(field)

        normalized = normalize_context(value)

        if normalized:
            context.add(normalized)

    return context


def get_location_match(finding1, finding2):
    host1 = normalize_host(finding1.get("host"))
    host2 = normalize_host(finding2.get("host"))

    if not host1 or host1 != host2:
        return False

    port1 = normalize_port(finding1.get("port"))
    port2 = normalize_port(finding2.get("port"))

    if not port1 or not port2 or port1 != port2:
        return False

    return True


def get_finding_category(finding):
    text = normalize_text(
        str(finding.get("title") or "")
        + " "
        + str(finding.get("description") or "")
        + " "
        + str(finding.get("rule_id") or "")
    )

    if any(term in text for term in (
        "sql injection",
        "sql-injection",
        "sqli",
        "sql.injection",
    )):
        return "sql_injection"

    if any(term in text for term in (
        "cross-site scripting",
        "cross site scripting",
        "xss",
    )):
        return "xss"

    if any(term in text for term in (
        "missing security headers",
        "security header",
    )):
        return "security_headers"

    if any(term in text for term in (
        "ssh service",
        "open ssh",
    )):
        return "ssh_service"

    if any(term in text for term in (
        "https service",
        "open https",
    )):
        return "https_service"

    if any(term in text for term in (
        "http service",
        "open http",
    )):
        return "http_service"

    return "other"


def get_semantic_similarity(finding1, finding2):
    title1 = normalize_text(finding1.get("title"))
    title2 = normalize_text(finding2.get("title"))

    description1 = normalize_text(finding1.get("description"))
    description2 = normalize_text(finding2.get("description"))

    if not title1 or not title2:
        return 0.0, 0.0, 0.0

    title_similarity = calculate_similarity(title1, title2)

    description_similarity = 0.0

    if description1 and description2:
        description_similarity = calculate_similarity(
            description1,
            description2
        )

        overall_similarity = (
            0.45 * title_similarity
            + 0.55 * description_similarity
        )
    else:
        overall_similarity = title_similarity

    return (
        float(title_similarity),
        float(description_similarity),
        float(overall_similarity)
    )


def are_correlated(finding1, finding2):
    """Identify distinct findings with meaningful shared evidence."""

    id1 = finding1.get("finding_id")
    id2 = finding2.get("finding_id")

    if not id1 or not id2 or id1 == id2:
        return False

    if not get_location_match(finding1, finding2):
        return False

    tools1 = get_source_tools(finding1)
    tools2 = get_source_tools(finding2)

    if not tools1 or not tools2 or tools1 == tools2:
        return False

    category1 = get_finding_category(finding1)
    category2 = get_finding_category(finding2)

    # Different vulnerability categories at the same host and port
    # can represent a meaningful contextual relationship.
    if (
        category1 in ("sql_injection", "xss", "security_headers")
        and category2 in ("sql_injection", "xss", "security_headers")
        and category1 != category2
    ):
        return True

    title_similarity, description_similarity, overall_similarity = (
        get_semantic_similarity(finding1, finding2)
    )

    # Highly similar findings are more likely duplicates.
    if (
        title_similarity >= DUPLICATE_THRESHOLD
        and overall_similarity >= DUPLICATE_THRESHOLD
    ):
        return False

    context1 = get_technical_context(finding1)
    context2 = get_technical_context(finding2)

    if context1.intersection(context2):
        return True

    return overall_similarity >= MIN_RELATIONSHIP_SIMILARITY


def get_correlation_reason(finding1, finding2):
    host = normalize_host(finding1.get("host"))
    port = normalize_port(finding1.get("port"))

    tools1 = get_source_tools(finding1)
    tools2 = get_source_tools(finding2)

    category1 = get_finding_category(finding1)
    category2 = get_finding_category(finding2)

    title_similarity, description_similarity, overall_similarity = (
        get_semantic_similarity(finding1, finding2)
    )

    if category1 != category2 and category1 != "other" and category2 != "other":
        explanation = (
            f"Different finding categories ({category1} and {category2}) "
            "affect the same host and port"
        )
    else:
        shared_context = (
            get_technical_context(finding1)
            & get_technical_context(finding2)
        )

        if shared_context:
            evidence = ", ".join(sorted(shared_context))
            explanation = f"Shared technical context: {evidence}"
        else:
            explanation = (
                "Semantic relationship between distinct finding descriptions"
            )

    return (
        f"Same host ({host}) and port ({port}); "
        f"scanner sources ({', '.join(sorted(tools1 | tools2))}); "
        f"{explanation}; "
        f"semantic similarity: {overall_similarity:.3f}. "
        "This is a contextual relationship, not proof of causation."
    )


def find_correlations(findings):
    """Find meaningful relationships among consolidated findings."""

    correlations = []

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):

            finding1 = findings[i]
            finding2 = findings[j]

            if are_correlated(finding1, finding2):
                correlations.append({
                    "finding1": finding1["finding_id"],
                    "finding2": finding2["finding_id"],
                    "reason": get_correlation_reason(
                        finding1,
                        finding2
                    )
                })

    return correlations
