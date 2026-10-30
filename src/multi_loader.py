
from src.loaders import (
    load_nmap_findings,
    load_nuclei_findings,
    load_semgrep_findings
)


def load_all_findings(
    nmap_file=None,
    nuclei_file=None,
    semgrep_file=None
):
    """
    Load findings from any combination of Nmap,
    Nuclei, and Semgrep reports.
    """

    all_findings = []

    if nmap_file:
        all_findings.extend(
            load_nmap_findings(nmap_file)
        )

    if nuclei_file:
        all_findings.extend(
            load_nuclei_findings(nuclei_file)
        )

    if semgrep_file:
        all_findings.extend(
            load_semgrep_findings(semgrep_file)
        )

    if not all_findings:
        raise ValueError(
            "No security findings were found in the uploaded reports."
        )

    return all_findings
