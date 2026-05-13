# SOC Log Analysis and Threat Detection Platform

A professional SOC (Security Operations Center) and SIEM-style web application for:

- log ingestion
- security event parsing
- threat detection
- MITRE ATT&CK mapping
- SOC analytics visualization
- enterprise alert monitoring

Built using:
- FastAPI
- React
- TailwindCSS
- Chart.js
- Python

---

# Features

## SOC Features
- Multi-format log ingestion
- Threat detection engine
- MITRE ATT&CK enrichment
- SOC analytics dashboard
- Alert visualization
- Security reporting interface
- Multi-page SOC workflow

---

# Detection Capabilities

## Supported Detections

- SQL Injection
- XSS Attacks
- Reconnaissance Scanning
- 404 Spike Detection
- Sensitive Endpoint Scanning

---

# MITRE ATT&CK Mapping

Current ATT&CK support:

| Technique ID | Technique |
|---|---|
| T1190 | Exploit Public-Facing Application |
| T1059 | Command and Scripting Interpreter |
| T1595 | Active Scanning |

---

# Dashboard Features

## Analytics
- Severity distribution charts
- Attack category charts
- MITRE tactic visualization
- Alert analytics

## Navigation
- Dashboard page
- Alerts page
- Reports page

---

# Tech Stack

## Frontend
- React
- TailwindCSS
- Axios
- Chart.js
- Lucide React

## Backend
- FastAPI
- Uvicorn
- Python

---

# Project Structure

```text
soc-web-platform/
│
├── backend/
├── frontend/
├── logs/
├── rules/
├── docs/
├── tests/
│
├── README.md
├── PROJECT_PROGRESS.md
├── TASKS.md
├── CHANGELOG.md
└── ROADMAP.md
