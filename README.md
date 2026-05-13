# Web-Based SOC Log Analysis and Threat Detection Platform

## Overview

This project is a professional SOC (Security Operations Center) and SIEM (Security Information and Event Management) simulation platform.

The system allows users to upload HTTP access logs, analyze them for malicious activity, generate alerts, map attacks to MITRE ATT&CK techniques, and visualize findings in a professional SOC dashboard.

Primary dataset:
- NASA Kennedy Space Center HTTP Access Logs

---

# Features

## Current Features
- FastAPI backend initialization
- React frontend initialization
- TailwindCSS configuration
- Git repository setup
- Project tracking system

## Planned Features
- Log upload system
- Regex-based parser engine
- Threat detection engine
- MITRE ATT&CK mapping
- SOC dashboard
- Alert center
- Reporting module
- Threat intelligence module

---

# Tech Stack

## Frontend
- React.js
- TailwindCSS
- Chart.js
- Axios

## Backend
- Python 3
- FastAPI
- Uvicorn

## Database
- SQLite
- PostgreSQL-ready architecture

---

# Project Structure

soc-web-platform/
│
├── backend/
├── frontend/
├── logs/
├── rules/
├── docs/
├── tests/
│
├── PROJECT_PROGRESS.md
├── TASKS.md
├── CHANGELOG.md
├── ROADMAP.md
├── README.md
└── requirements.txt

---

# Backend Setup

## Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
