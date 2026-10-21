
import json
from pathlib import Path


def parse_nuclei_json(file_path):
    """
    Parse Nuclei output in JSONL format (one JSON object per line)
    or standard JSON format (a single object/list).
    """
    path = Path(file_path)

    with path.open("r", encoding="utf-8-sig") as file:
        content = file.read().strip()

    if not content:
        return []

    # First, try parsing the file as one standard JSON document.
    try:
        data = json.loads(content)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            # Some tools wrap findings in a results list.
            if isinstance(data.get("results"), list):
                return data["results"]
            return [data]

    except json.JSONDecodeError:
        pass

    # If that failed, parse it as JSON Lines (JSONL).
    findings = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        if not line:
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Invalid Nuclei JSON/JSONL at line {line_number}: {error}"
            ) from error

        if isinstance(item, dict):
            findings.append(item)
        elif isinstance(item, list):
            findings.extend(
                entry for entry in item if isinstance(entry, dict)
            )

    return findings
