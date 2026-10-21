# Deduplicating and Correlating Findings Across Multiple Security Tools

## Project Overview

This project is a cybersecurity vulnerability management system that processes security findings collected from multiple security testing tools.

Different security tools may report the same underlying vulnerability using different titles, descriptions, or formats. This creates duplicate findings and makes vulnerability management difficult.

The system normalizes findings, identifies potential duplicates using semantic similarity, merges duplicate results, identifies relationships between distinct findings, and generates a consolidated security report.

## Current Workflow

Raw Security Findings → Normalization → Semantic Similarity → Deduplication → Merge Duplicate Findings → Correlation → Consolidated Report → Web Dashboard

## Technologies Used

- Python
- Flask
- Sentence Transformers
- SBERT
- all-MiniLM-L6-v2
- MySQL
- HTML
- Git and GitHub
- VS Code

## Supported Security Tools

The current prototype includes report-processing support for:

- Nmap
- Nuclei
- Semgrep

Input formats depend on the implemented parsers.

## Current Implementation

The prototype accepts supported security scan reports and converts their findings into a common structure.

Each finding may contain:

- Security tool
- Finding title
- Description
- Severity
- Host
- Port

### 1. Normalization

Converts findings from different security tools into a consistent data structure.

### 2. Semantic Similarity

Uses the `all-MiniLM-L6-v2` sentence-transformer model to compare finding titles and descriptions.

### 3. Deduplication

Uses semantic similarity together with host and port information to identify potential duplicates. A similarity threshold of `0.70` is currently used as a baseline.

### 4. Duplicate Merging

Merges findings identified as duplicates while retaining information about their source tools.

### 5. Correlation

Performs basic correlation between distinct findings, including findings associated with the same host. These relationships are preliminary and require further validation.

### 6. Reporting and Dashboard

Generates a consolidated JSON report and displays findings, summary statistics, and correlation results through a Flask web dashboard. The dashboard supports uploading multiple scan reports and downloading the generated report.

## Example

Two security tools might report:

- `Open SSH Port`
- `SSH Service Exposed`

Although their wording differs, both findings may refer to the same exposed SSH service.

The system compares their semantic similarity and checks host and port information before deciding whether they are potential duplicates.

## Installation and Setup

### Prerequisites

- Python
- Git
- MySQL, if database functionality is required

### 1. Clone the Repository

```bash
git clone https://github.com/2300033836/security-finding-correlation.git
cd security-finding-correlation
```

### 2. Create a Virtual Environment

On Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure the Database

If the application requires MySQL, install and start MySQL, create the required database, and configure the connection settings according to the project's database code. Do not commit database passwords or other secrets to GitHub.

### 5. Run the Application

From the project root:

```bash
python -m src.app
```

Open the local address printed in the terminal in your web browser.

## Testing

Run the automated test suite:

```bash
python -m unittest discover -s tests -v
```

## Project Limitations and Future Improvements

- Improve duplicate detection accuracy across different security tools.
- Reduce false-positive correlations between unrelated vulnerabilities.
- Validate similarity thresholds against labeled test data.
- Improve database configuration and portability.
- Evaluate the application using larger and more diverse security scan reports.
- Consider deploying the dashboard to a hosted environment.

## Important Note

This project is an academic prototype. Similarity scores and correlations are indicators that require validation; a reported relationship does not prove that two findings are identical or causally related. Use authorized security scan reports only.
