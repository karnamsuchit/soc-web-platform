from collections import defaultdict


SQLI_PATTERNS = [
    "' OR '1'='1",
    '" OR "1"="1',
    "union select",
    "drop table",
    "information_schema",
]

XSS_PATTERNS = [
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
]

SCAN_PATTERNS = [
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/config",
]


def detect_404_spikes(parsed_logs):

    ip_404_count = defaultdict(int)

    alerts = []

    for log in parsed_logs:

        if log.get("status") == 404:

            ip_404_count[log.get("ip")] += 1

    for ip, count in ip_404_count.items():

        if count >= 5:

            alerts.append({
                "type": "404 Spike",
                "severity": "medium",
                "ip": ip,
                "count": count,
                "description": "Excessive 404 responses detected"
            })

    return alerts


def detect_sqli(parsed_logs):

    alerts = []

    for log in parsed_logs:

        url = str(log.get("url", "")).lower()

        for pattern in SQLI_PATTERNS:

            if pattern in url:

                alerts.append({
                    "type": "SQL Injection",
                    "severity": "high",
                    "ip": log.get("ip"),
                    "url": log.get("url"),
                    "description": "Potential SQL injection attempt detected"
                })

    return alerts


def detect_xss(parsed_logs):

    alerts = []

    for log in parsed_logs:

        url = str(log.get("url", "")).lower()

        for pattern in XSS_PATTERNS:

            if pattern in url:

                alerts.append({
                    "type": "XSS Attempt",
                    "severity": "high",
                    "ip": log.get("ip"),
                    "url": log.get("url"),
                    "description": "Potential XSS payload detected"
                })

    return alerts


def detect_scanning(parsed_logs):

    alerts = []

    for log in parsed_logs:

        url = str(log.get("url", "")).lower()

        for pattern in SCAN_PATTERNS:

            if pattern in url:

                alerts.append({
                    "type": "Reconnaissance Activity",
                    "severity": "medium",
                    "ip": log.get("ip"),
                    "url": log.get("url"),
                    "description": "Suspicious scanning activity detected"
                })

    return alerts


def run_detection_engine(parsed_logs):

    all_alerts = []

    all_alerts.extend(
        detect_404_spikes(parsed_logs)
    )

    all_alerts.extend(
        detect_sqli(parsed_logs)
    )

    all_alerts.extend(
        detect_xss(parsed_logs)
    )

    all_alerts.extend(
        detect_scanning(parsed_logs)
    )

    return {
        "total_alerts": len(all_alerts),
        "alerts": all_alerts
    }
