MITRE_MAPPINGS = {
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "XSS Attempt": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "Reconnaissance Activity": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "404 Spike": {
        "technique_id": "T1595.002",
        "technique_name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
    },
    "Request Spike": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
    },
    "Failed Login": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "Suspicious IP": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
}


def map_alerts_to_mitre(alerts):
    enriched_alerts = []

    for alert in alerts:
        alert_type = alert.get("type")
        mitre_data = MITRE_MAPPINGS.get(
            alert_type,
            {
                "technique_id": "UNKNOWN",
                "technique_name": "Unknown Technique",
                "tactic": "Unknown",
            },
        )
        enriched_alerts.append({**alert, "mitre": mitre_data})

    return enriched_alerts
