
import json
from pathlib import Path


def extract_findings(data):
    """Extract finding records from common Nuclei JSON structures."""

    if isinstance(data, list):
        return [
            item for item in data
            if isinstance(item, dict)
        ]

    if isinstance(data, dict):
        # Handle common report wrappers.
        for key in ("results", "findings", "issues"):
            if isinstance(data.get(key), list):
                return extract_findings(data[key])

        return [data]

    return []


def parse_nuclei_json(file_path):
    """
    Parse Nuclei reports in:
    1. Standard JSON format
    2. JSON array format
    3. JSONL format (one JSON object per line)
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Nuclei report not found: {path}"
        )

    if path.suffix.lower() not in (".json", ".jsonl"):
        raise ValueError(
            "Unsupported Nuclei format. Use .json or .jsonl"
        )

    with path.open("r", encoding="utf-8-sig") as file:
        content = file.read().strip()

    if not content:
        return []

    # First, attempt standard JSON parsing.
    try:
        data = json.loads(content)
        return extract_findings(data)

    except json.JSONDecodeError:
        pass

    # If standard JSON fails, parse as JSONL.
    findings = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        if not line:
            continue

        try:
            item = json.loads(line)

        except json.JSONDecodeError as error:
            raise ValueError(
                f"Invalid Nuclei JSON/JSONL at "
                f"line {line_number}: {error}"
            ) from error

        findings.extend(extract_findings(item))

    return findings
