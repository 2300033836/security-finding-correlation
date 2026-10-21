from pathlib import Path

from src.parsers.nmap_parser import (
    parse_nmap_json,
    parse_nmap_xml
)

from src.parsers.nuclei_parser import parse_nuclei_json
from src.parsers.semgrep_parser import parse_semgrep_json


def load_nmap_findings(file_path):
    file_extension = Path(file_path).suffix.lower()

    if file_extension == ".xml":
        findings = parse_nmap_xml(file_path)
    elif file_extension == ".json":
        findings = parse_nmap_json(file_path)
    else:
        raise ValueError(
            "Unsupported Nmap file format. "
            "Use .xml or .json"
        )

    return findings


def load_nuclei_findings(file_path):
    findings = parse_nuclei_json(file_path)
    return findings


def load_semgrep_findings(file_path):
    findings = parse_semgrep_json(file_path)
    return findings