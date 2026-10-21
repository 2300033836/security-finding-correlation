# Security Finding Deduplication and Correlation

## Project Overview

This project is a vulnerability management platform that processes security findings from multiple security tools. It aims to reduce duplicate findings, identify relationships between findings, and generate a consolidated security report.

## Objectives

- Normalize findings into a common format.
- Identify and merge duplicate findings using semantic similarity.
- Correlate findings that may be related.
- Generate a consolidated JSON report.
- Display results through a web dashboard.

## Technologies Used

- Python
- Flask
- Sentence Transformers (`all-MiniLM-L6-v2`)
- MySQL
- HTML
- Git and GitHub

## Workflow

1. **Input:** Upload supported security scan reports.
2. **Normalization:** Convert findings into a common data structure.
3. **Deduplication:** Identify and merge likely duplicate findings.
4. **Correlation:** Identify potentially related findings.
5. **Reporting:** Generate a consolidated JSON report.
6. **Dashboard:** Display findings and summary statistics in a browser.

## Supported Security Tools

The project currently includes report-processing support for Nmap, Nuclei, and Semgrep. Input formats depend on the implemented parsers.

## Requirements

- Python installed on your computer.
- Git installed.
- MySQL configured if database functionality is required.

## Setup

Clone the repository:

```bash
git clone https://github.com/2300033836/security-finding-correlation.git
cd security-finding-correlation
```

Create and activate a virtual environment on Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Install the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run the Dashboard

From the project root, run:

```bash
python -m src.app
```

Then open the local URL printed in the terminal in your browser.

Configure MySQL and the application's database settings if the dashboard requires a database connection.

## Output

The application displays summary statistics, consolidated findings, correlation results, and an option to download the generated JSON report.

## Important Note

This is an academic prototype. Similarity-based deduplication and correlation results require validation; a reported relationship does not necessarily prove causation. Use authorized security scan reports only.
