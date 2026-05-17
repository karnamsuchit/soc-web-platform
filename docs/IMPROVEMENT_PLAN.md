# SOC Platform Improvement Plan

## Current Repository Assessment

The project has a useful FastAPI foundation and a clear SOC/SIEM direction, but the implementation is still early-stage. The backend can upload, parse, and run several basic detections against Apache-style logs. The frontend folders are currently empty, uploaded files are committed into the repository, and the README describes several capabilities that are not yet implemented.

## Key Weak Areas

- Frontend UI is missing, so the project cannot yet demonstrate a SOC workflow visually.
- Parser support is narrow: Apache-style HTTP logs and a limited CSV parser only.
- Detection logic uses simple substring matching and does not produce analyst-friendly alert context.
- No normalized event schema, alert IDs, timestamps, evidence fields, or detection summaries.
- No IOC extraction for IPs, URLs, paths, user agents, hashes, or domains.
- MITRE ATT&CK mapping exists but is sparse and includes some weak mappings.
- Uploaded sample files live in `backend/uploads`, which should be runtime data, not portfolio content.
- Documentation overstates current functionality and needs setup, usage, architecture, and examples.
- No tests or verification scripts exist for parser/detection behavior.
- No detection rule files exist, making the detection logic harder to explain to recruiters.

## Phase 1: SOC Backend Foundation

- Normalize parsed events into consistent security event objects.
- Support Apache/common HTTP logs, JSON logs, CSV logs, and simple auth/syslog-style lines.
- Add alert IDs, event categories, evidence, affected assets, source IPs, timestamps, and severity.
- Improve detections for failed logins, brute force, reconnaissance, SQL injection, XSS, suspicious IPs, sensitive paths, and anomaly-style request spikes.
- Add IOC extraction and detection summaries.
- Expand MITRE ATT&CK mappings for practical blue-team explanations.
- Add realistic sample logs under `sample_logs/`.

## Phase 2: SOC Dashboard Frontend

- Build a dark SOC-style React dashboard.
- Add metric cards for total events, alerts, critical/high findings, IOC count, and top source IP.
- Add severity distribution, alert category breakdown, timeline, and MITRE panels.
- Add log viewer with IOC highlighting and alert detail panels.
- Keep the UI portfolio-ready without turning it into a generic admin dashboard.

## Phase 3: Detection Rules and Analyst Workflow

- Add `detection_rules/` with readable YAML/JSON rule definitions.
- Show rule names, descriptions, ATT&CK technique IDs, severity, and analyst recommendations.
- Add alert triage states such as `new`, `investigating`, and `closed` if persistence is added.
- Add exportable IOC and alert summaries.

## Phase 4: Documentation and Portfolio Polish

- Rewrite README with accurate features, architecture, setup, screenshots placeholders, and usage flow.
- Add docs for parsing formats, detection examples, MITRE mappings, and sample investigation workflow.
- Add screenshots after the frontend is running.
- Keep future improvements realistic: SQLite persistence, Docker, auth, WebSocket updates, report export.

## Phase 5: Testing and Hardening

- Add parser and detection unit tests.
- Validate file uploads by size and extension.
- Keep uploaded runtime data out of git.
- Add `.gitignore` entries for uploads, cache files, virtual environments, and frontend build output.
- Add simple CI-ready test commands.

