# Sentinel: AI PHI Risk Scanner

A Streamlit-based application for detecting Protected Health Information (PHI) in documents to ensure HIPAA compliance.

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-v1.28+-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Overview

Sentinel PHI Scanner is designed for Healthcare Information Management (HIM) professionals to automatically detect and assess PHI risks in documents. The tool uses pattern-based detection to identify various types of sensitive health information and provides comprehensive compliance reports.

## Features

- **Multi-format Support**: Scan PDF, TXT, DOC, and DOCX files
- **Smart PHI Detection**: Identifies SSN, MRN, DOB, patient names, addresses, and more
- **Risk Assessment**: Automatic risk scoring (Low/Moderate/High) based on findings
- **Confidence Scoring**: Each detection includes a confidence percentage
- **Export Options**: Generate reports in Markdown, CSV, or JSON formats
- **HIPAA Compliance**: Designed with healthcare privacy regulations in mind
- **User-friendly Interface**: Clean, intuitive Streamlit interface

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/KentuckyToThe/sentinel-phi-scanner.git
cd sentinel-phi-scanner
