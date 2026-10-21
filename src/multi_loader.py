from src.loaders import (
    load_nmap_findings,
    load_nuclei_findings,
    load_semgrep_findings
)


def load_all_findings(
    nmap_file,
    nuclei_file,
    semgrep_file
):

    nmap_findings = load_nmap_findings(
        nmap_file
    )

    nuclei_findings = load_nuclei_findings(
        nuclei_file
    )

    semgrep_findings = load_semgrep_findings(
        semgrep_file
    )

    all_findings = (
        nmap_findings
        + nuclei_findings
        + semgrep_findings
    )

    return all_findings