# AI Supply-Chain Security Scanner

## Project Purpose
The AI Supply-Chain Security Scanner is a research prototype designed to analyze AI and software artifacts for security vulnerabilities, malicious indicators, and supply-chain risks. It provides a foundational framework to evaluate files and codebase artifacts systematically.

## Research Motivation
With the rapid integration of AI and third-party dependencies into critical workflows, the software supply chain has become a major target for attacks. This tool aims to provide an extensible, modular platform to study and detect these threats in both traditional software and AI artifacts.

## Current Architecture
The current application (Version 1) is built with a modular, lightweight architecture:
- **Frontend**: Streamlit dashboard for a clean and simple UI.
- **Backend**: Python-based static analysis engine and rule-based risk classification.
- **Storage**: Local SQLite database for persistence of artifacts, scans, and findings.

## Version 1 Functionality
- File upload and metadata extraction (size, timestamp, type).
- Streaming SHA-256 hash calculation for large files.
- Modular static analysis using Python AST to detect suspicious indicators (e.g., `os.system`, `eval`, `subprocess`, hardcoded secrets).
- Transparent, rule-based risk scoring system (0-100) with heuristic classifications (SAFE, LOW, MEDIUM, HIGH, CRITICAL).
- Local persistence of scan histories and findings.

## Setup Instructions
1. Ensure Python 3.9+ is installed on your system.
2. Clone this repository.

## How to Install Dependencies
Run the following command to install the required dependencies:
```bash
pip install -r requirements.txt
```

## How to Run the Dashboard
Start the Streamlit dashboard by running:
```bash
streamlit run app/dashboard/app.py
```

## Limitations
- **No Dynamic Execution**: This version relies solely on static analysis. It does not execute code to observe runtime behavior.
- **Heuristic Indicators**: Findings are based on heuristics. The presence of indicators like `os.system` does not inherently mean an artifact is malicious.
- **No ML Classification**: Risk scores are strictly rule-based in this version.
- **Local Only**: No cloud synchronization or central database is implemented yet.

## Planned Future Architecture
- **Version 2**: Improved static analysis and dependency analysis.
- **Version 3**: Disposable victim VM, dynamic analysis, filesystem monitoring, process monitoring, and network monitoring.
- **Version 4**: Firestore synchronization and Cloud Storage for larger evidence.
- **Version 5**: Machine-learning-assisted risk classification and larger research dataset.
