import hashlib
import re
from collections import Counter, defaultdict
from urllib.parse import unquote_plus


SQLI_PATTERNS = [
    r"(?i)(\bor\b|\band\b)\s+['\"]?\d['\"]?\s*=\s*['\"]?\d",
    r"(?i)union\s+(all\s+)?select",
    r"(?i)information_schema",
    r"(?i)(drop|alter|truncate)\s+table",
    r"(?i)(sleep|benchmark)\s*\(",
    r"(?i)--|/\*|\*/",
]

XSS_PATTERNS = [
    r"(?i)<\s*script",
    r"(?i)javascript:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)<\s*img",
]

SENSITIVE_PATHS = [
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/config",
    "/server-status",
    "/backup",
    "/debug",
    "/cgi-bin",
]

SUSPICIOUS_IPS = {
    "185.220.101.32": "Known Tor exit node example",
    "45.155.205.233": "Known scanner example",
    "203.0.113.66": "Threat intel watchlist example",
}

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")


def run_detection_engine(parsed_logs):
    alerts = []

    try:
        alerts.extend(detect_suspicious_ips(parsed_logs))
        alerts.extend(detect_failed_logins(parsed_logs))
        alerts.extend(detect_brute_force(parsed_logs))
        alerts.extend(detect_sqli(parsed_logs))
        alerts.extend(detect_xss(parsed_logs))
        alerts.extend(detect_scanning(parsed_logs))
        alerts.extend(detect_404_spikes(parsed_logs))
        alerts.extend(detect_request_spikes(parsed_logs))

        alerts = [_with_alert_id(alert) for alert in alerts]
        return {
            "total_alerts": len(alerts),
            "alerts": alerts,
            "summary": build_detection_summary(parsed_logs, alerts),
            "iocs": extract_iocs(parsed_logs, alerts),
        }
    except Exception as error:
        return {
            "total_alerts": 0,
            "alerts": [],
            "summary": {},
            "iocs": {},
            "error": str(error),
        }


def detect_suspicious_ips(events):
    alerts = []
    matched_sources = defaultdict(list)
    for event in events:
        ip = event.get("source_ip")
        if ip in SUSPICIOUS_IPS:
            matched_sources[ip].append(event)

    for ip, ip_events in matched_sources.items():
        alerts.append(
            build_alert(
                "Suspicious IP",
                "high",
                ip_events[-1],
                "Source IP matched the local SOC threat watchlist.",
                evidence={
                    "watchlist_reason": SUSPICIOUS_IPS[ip],
                    "related_events": len(ip_events),
                },
                recommendation="Review related activity from this IP and block if confirmed malicious.",
            )
        )
    return alerts


def detect_failed_logins(events):
    alerts = []
    for event in events:
        if _is_failed_login(event):
            alerts.append(
                build_alert(
                    "Failed Login",
                    "low",
                    event,
                    "Failed authentication event observed.",
                    evidence={"username": event.get("username")},
                    recommendation="Correlate with additional failures from the same source or username.",
                )
            )
    return alerts


def detect_brute_force(events):
    failures = defaultdict(list)
    for event in events:
        if _is_failed_login(event):
            failures[event.get("source_ip") or "unknown"].append(event)

    alerts = []
    for source_ip, failed_events in failures.items():
        if len(failed_events) >= 5:
            alerts.append(
                build_alert(
                    "Brute Force",
                    "critical" if len(failed_events) >= 10 else "high",
                    failed_events[-1],
                    "Multiple failed login attempts from the same source.",
                    evidence={
                        "failed_attempts": len(failed_events),
                        "usernames": sorted({event.get("username") for event in failed_events if event.get("username")}),
                    },
                    recommendation="Investigate the source, reset impacted accounts if needed, and apply rate limiting.",
                )
            )
    return alerts


def detect_sqli(events):
    alerts = []
    for event in events:
        target = _event_url_text(event)
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, target):
                alerts.append(
                    build_alert(
                        "SQL Injection",
                        "high",
                        event,
                        "HTTP request contains SQL injection indicators.",
                        evidence={"matched_pattern": pattern, "url": event.get("url")},
                        recommendation="Check application logs, validate input handling, and review WAF coverage.",
                    )
                )
                break
    return alerts


def detect_xss(events):
    alerts = []
    for event in events:
        target = _event_url_text(event)
        for pattern in XSS_PATTERNS:
            if re.search(pattern, target):
                alerts.append(
                    build_alert(
                        "XSS Attempt",
                        "high",
                        event,
                        "HTTP request contains cross-site scripting payload indicators.",
                        evidence={"matched_pattern": pattern, "url": event.get("url")},
                        recommendation="Review output encoding and input validation on the affected route.",
                    )
                )
                break
    return alerts


def detect_scanning(events):
    alerts = []
    for event in events:
        path = str(event.get("path") or event.get("url") or "").lower()
        matched = [sensitive for sensitive in SENSITIVE_PATHS if sensitive in path]
        if matched:
            alerts.append(
                build_alert(
                    "Reconnaissance Activity",
                    "medium",
                    event,
                    "Request targeted administrative or sensitive paths commonly used during recon.",
                    evidence={"matched_paths": matched, "status": event.get("status")},
                    recommendation="Review source activity and confirm whether the path should be exposed.",
                )
            )
    return alerts


def detect_404_spikes(events):
    ip_404_count = defaultdict(list)
    for event in events:
        if event.get("status") == 404:
            ip_404_count[event.get("source_ip") or "unknown"].append(event)

    alerts = []
    for source_ip, failed_events in ip_404_count.items():
        if len(failed_events) >= 5:
            alerts.append(
                build_alert(
                    "404 Spike",
                    "medium",
                    failed_events[-1],
                    "Repeated 404 responses from one source can indicate path discovery or scanning.",
                    evidence={"not_found_count": len(failed_events)},
                    recommendation="Inspect requested paths and correlate with user-agent/source reputation.",
                )
            )
    return alerts


def detect_request_spikes(events):
    counts = Counter(event.get("source_ip") or "unknown" for event in events if event.get("source_ip"))
    if not counts:
        return []

    average = sum(counts.values()) / len(counts)
    alerts = []
    for source_ip, count in counts.items():
        if count >= 15 and count >= average * 3:
            last_event = next(event for event in reversed(events) if event.get("source_ip") == source_ip)
            alerts.append(
                build_alert(
                    "Request Spike",
                    "medium",
                    last_event,
                    "Source generated significantly more events than the rest of the dataset.",
                    evidence={"event_count": count, "dataset_average": round(average, 2)},
                    recommendation="Review whether the traffic pattern is expected automation, scanning, or abuse.",
                )
            )
    return alerts


def build_alert(alert_type, severity, event, description, evidence=None, recommendation=None):
    return {
        "type": alert_type,
        "severity": severity,
        "timestamp": event.get("timestamp"),
        "source_ip": event.get("source_ip"),
        "username": event.get("username"),
        "url": event.get("url"),
        "path": event.get("path"),
        "status": event.get("status"),
        "category": _alert_category(alert_type),
        "description": description,
        "evidence": evidence or {},
        "recommendation": recommendation,
        "source_event": {
            "line_number": event.get("line_number"),
            "source_format": event.get("source_format"),
            "raw": event.get("raw"),
        },
    }


def build_detection_summary(events, alerts):
    severity_counts = Counter(alert.get("severity", "unknown") for alert in alerts)
    category_counts = Counter(alert.get("category", "unknown") for alert in alerts)
    top_sources = Counter(event.get("source_ip") for event in events if event.get("source_ip")).most_common(5)

    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_sources],
        "unique_source_ips": len({event.get("source_ip") for event in events if event.get("source_ip")}),
        "failed_login_events": sum(1 for event in events if _is_failed_login(event)),
    }


def extract_iocs(events, alerts=None):
    text_values = []
    for event in events:
        text_values.extend(str(value) for value in event.values() if value)
    for alert in alerts or []:
        text_values.extend(str(value) for value in alert.values() if value)

    blob = "\n".join(text_values)
    ips = sorted(set(IP_PATTERN.findall(blob)))
    domains = sorted(set(DOMAIN_PATTERN.findall(blob)) - set(["HTTP"]))
    hashes = sorted(set(HASH_PATTERN.findall(blob)))
    urls = sorted({event.get("url") for event in events if event.get("url")})

    return {
        "ips": ips,
        "domains": domains,
        "hashes": hashes,
        "urls": urls,
        "total_iocs": len(ips) + len(domains) + len(hashes) + len(urls),
    }


def _with_alert_id(alert):
    seed = "|".join(
        str(alert.get(field) or "")
        for field in ["type", "severity", "timestamp", "source_ip", "url", "description"]
    )
    return {"alert_id": f"ALERT-{hashlib.sha1(seed.encode()).hexdigest()[:10].upper()}", **alert}


def _event_url_text(event):
    return unquote_plus(" ".join(str(event.get(field) or "") for field in ["url", "path", "query", "raw"]))


def _is_failed_login(event):
    if event.get("category") == "authentication" and event.get("action") == "failed":
        return True
    return event.get("status") in [401, 403] and "login" in str(event.get("path") or event.get("url") or "").lower()


def _alert_category(alert_type):
    categories = {
        "Suspicious IP": "threat_intel",
        "Failed Login": "authentication",
        "Brute Force": "credential_access",
        "SQL Injection": "web_attack",
        "XSS Attempt": "web_attack",
        "Reconnaissance Activity": "reconnaissance",
        "404 Spike": "reconnaissance",
        "Request Spike": "anomaly",
    }
    return categories.get(alert_type, "general")
