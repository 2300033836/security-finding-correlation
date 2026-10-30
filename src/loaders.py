
from pathlib import Path

from src.parsers.nmap_parser import (
    parse_nmap_json,
    parse_nmap_xml
)

from src.parsers.nuclei_parser import parse_nuclei_json
from src.parsers.semgrep_parser import parse_semgrep_json


def validate_file(file_path, supported_formats, tool_name):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"{tool_name} report not found: {file_path}"
        )

    if path.suffix.lower() not in supported_formats:
        formats = ", ".join(supported_formats)

        raise ValueError(
            f"Unsupported {tool_name} format. "
            f"Supported formats: {formats}"
        )

    if path.stat().st_size == 0:
        raise ValueError(
            f"{tool_name} report is empty: {path.name}"
        )

    return path


def load_nmap_findings(file_path):
    path = validate_file(
        file_path,
        [".xml", ".json"],
        "Nmap"
    )

    if path.suffix.lower() == ".xml":
        return parse_nmap_xml(path)

    return parse_nmap_json(path)


def load_nuclei_findings(file_path):
    path = validate_file(
        file_path,
        [".json", ".jsonl"],
        "Nuclei"
    )

    return parse_nuclei_json(path)


def load_semgrep_findings(file_path):
    path = validate_file(
        file_path,
        [".json"],
        "Semgrep"
    )

    return parse_semgrep_json(path)
