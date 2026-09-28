try:
    from src.similarity import calculate_similarity
except ModuleNotFoundError:
    from similarity import calculate_similarity


SIMILARITY_THRESHOLD = 0.70


def are_duplicates(finding1, finding2):
    same_host = finding1["host"] == finding2["host"]
    same_port = finding1["port"] == finding2["port"]

    text1 = finding1["title"] + ". " + finding1["description"]
    text2 = finding2["title"] + ". " + finding2["description"]

    similarity = calculate_similarity(text1, text2)

    is_duplicate = (
        same_host
        and same_port
        and similarity >= SIMILARITY_THRESHOLD
    )

    return is_duplicate, similarity


def merge_findings(finding1, finding2):
    merged_finding = {
        "finding_id": finding1["finding_id"],
        "title": finding1["title"],
        "description": finding1["description"],
        "severity": finding1["severity"],
        "host": finding1["host"],
        "port": finding1["port"],
        "source_tools": [
            finding1["source_tool"],
            finding2["source_tool"]
        ]
    }

    return merged_finding