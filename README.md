# Deduplicating and Correlating Findings Across Multiple Security Tools

## Project Overview

This project is a cybersecurity vulnerability management system that processes security findings collected from multiple security testing tools.

Different security tools may report the same underlying vulnerability using different titles, descriptions, or formats. This can create duplicate findings and make vulnerability management difficult.

The system aims to normalize these findings, identify duplicate findings using semantic similarity, merge duplicate results, identify relationships between distinct findings, and generate a consolidated result.

## Current Workflow

Raw Security Findings
        ↓
Normalization
        ↓
Semantic Similarity
        ↓
Deduplication
        ↓
Merge Duplicate Findings
        ↓
Correlation
        ↓
Consolidated Results

## Current Technologies

- Python
- Sentence Transformers
- SBERT
- all-MiniLM-L6-v2
- Git
- GitHub
- VS Code

## Current Implementation

The current prototype accepts security findings in JSON format.

Each finding contains information such as:

- Security tool
- Finding title
- Description
- Severity
- Host
- Port

The system normalizes these findings into a common structure.

For duplicate detection, the system uses the `all-MiniLM-L6-v2` sentence-transformer model to calculate semantic similarity between findings.

Currently, a similarity threshold of `0.70` is used as a baseline for duplicate detection.

Findings identified as duplicates are merged and their source tools are retained.

After deduplication, the system performs basic correlation between distinct findings occurring on the same host.

## Example

Two tools may report:

Although the wording is different, they may represent the same underlying issue.

The system uses semantic similarity together with host and port information to determine whether they should be treated as duplicates.

## Testing

The project includes automated tests for:

- Deduplication
- Duplicate merging
- Correlation
- End-to-end pipeline processing

Run the complete test suite with:


python -m unittest discover -s tests -v
