# Detection Guide

## Authentication Attacks

- Failed login detection creates low-severity alerts for failed SSH or login events.
- Brute-force detection groups repeated failures by source IP and raises high or critical severity.
- MITRE mapping: `T1110 Brute Force`.

## Web Attacks

- SQL injection detection checks URL and query content for patterns such as `UNION SELECT`, boolean bypasses, SQL comments, and metadata table references.
- XSS detection checks for script tags, JavaScript handlers, and encoded payloads.
- MITRE mapping: `T1190 Exploit Public-Facing Application`.

## Reconnaissance

- Sensitive endpoint detection flags requests to paths such as `/admin`, `/.env`, `/phpmyadmin`, `/server-status`, and backup files.
- 404 spike detection identifies repeated failed path discovery from a single source.
- Request spike detection flags sources that generate unusually high traffic compared with the dataset.
- MITRE mapping: `T1595 Active Scanning`.

## IOC Extraction

The platform extracts:

- IP addresses
- URLs
- Domains
- Hash-like values

## Alert Fields

Each alert includes timestamp, severity, attack type, source IP, description, evidence, analyst recommendation, and MITRE ATT&CK mapping.
