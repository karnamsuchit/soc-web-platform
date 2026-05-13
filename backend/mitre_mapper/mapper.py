MITRE_MAPPINGS = {

    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "severity": "high"
    },

    "XSS Attempt": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "severity": "high"
    },

    "Reconnaissance Activity": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "severity": "medium"
    },

    "404 Spike": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "severity": "medium"
    }
}


def map_alerts_to_mitre(alerts):

    enriched_alerts = []

    for alert in alerts:

        alert_type = alert.get("type")

        mitre_data = MITRE_MAPPINGS.get(alert_type)

        if mitre_data:

            enriched_alert = {
                **alert,
                "mitre": mitre_data
            }

        else:

            enriched_alert = {
                **alert,
                "mitre": {
                    "technique_id": "UNKNOWN",
                    "technique_name": "Unknown Technique",
                    "tactic": "Unknown",
                    "severity": alert.get(
                        "severity",
                        "low"
                    )
                }
            }

        enriched_alerts.append(
            enriched_alert
        )

    return enriched_alerts
