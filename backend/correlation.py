from datetime import datetime


SCENARIOS = {
    "account-takeover": {
        "name": "Account Takeover + Data Exfiltration",
        "description": "A compromised employee identity escalates privileges and exports confidential data.",
        "events": [
            {"id": "EVT-101", "time": "10:00", "source": "Identity", "type": "failed_login", "label": "8 failed login attempts", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "VPN", "base_severity": 18},
            {"id": "EVT-102", "time": "10:04", "source": "Identity", "type": "suspicious_login", "label": "Successful login from unfamiliar location", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "VPN", "base_severity": 42},
            {"id": "EVT-103", "time": "10:07", "source": "IAM", "type": "privilege_escalation", "label": "Administrator privilege granted", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "Admin Console", "base_severity": 63},
            {"id": "EVT-104", "time": "10:12", "source": "File Server", "type": "sensitive_access", "label": "Confidential finance folder accessed", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "Finance Vault", "base_severity": 68},
            {"id": "EVT-105", "time": "10:18", "source": "Firewall", "type": "data_exfiltration", "label": "2 GB outbound transfer to unknown host", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "External Host", "base_severity": 90},
            {"id": "EVT-106", "time": "10:20", "source": "Endpoint", "type": "defense_evasion", "label": "Endpoint protection disabled", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "EDR Agent", "base_severity": 76},
        ],
    },
    "benign-login": {
        "name": "Benign Authentication Noise",
        "description": "A legitimate employee mistypes a password before a normal login.",
        "events": [
            {"id": "EVT-201", "time": "11:02", "source": "Identity", "type": "failed_login", "label": "2 failed login attempts", "user": "maya@acme.io", "ip": "10.0.2.15", "device": "DEV-08", "resource": "Email", "base_severity": 12},
            {"id": "EVT-202", "time": "11:04", "source": "Identity", "type": "normal_login", "label": "Successful login from known device", "user": "maya@acme.io", "ip": "10.0.2.15", "device": "DEV-08", "resource": "Email", "base_severity": 5},
            {"id": "EVT-203", "time": "11:08", "source": "Email", "type": "normal_activity", "label": "Normal mailbox activity", "user": "maya@acme.io", "ip": "10.0.2.15", "device": "DEV-08", "resource": "Email", "base_severity": 3},
        ],
    },
}


STAGES = {
    "failed_login": "Credential Attack",
    "suspicious_login": "Account Compromise",
    "privilege_escalation": "Privilege Escalation",
    "sensitive_access": "Collection",
    "data_exfiltration": "Data Exfiltration",
    "defense_evasion": "Defense Evasion",
    "normal_login": "Verified Login",
    "normal_activity": "Normal Activity",
}


def minutes(value):
    parsed = datetime.strptime(value, "%H:%M")
    return parsed.hour * 60 + parsed.minute


def correlation_reason(left, right):
    reasons = []
    if left["user"] == right["user"]:
        reasons.append("same user")
    if left["device"] == right["device"]:
        reasons.append("same device")
    if left["ip"] == right["ip"]:
        reasons.append("same IP")
    gap = minutes(right["time"]) - minutes(left["time"])
    if 0 <= gap <= 15:
        reasons.append(f"{gap}-minute gap")
    return ", ".join(reasons)


def build_links(events):
    links = []
    for index in range(len(events) - 1):
        reason = correlation_reason(events[index], events[index + 1])
        if reason:
            links.append({"from": events[index]["id"], "to": events[index + 1]["id"], "reason": reason})
    return links


def severity(events):
    event_types = {event["type"] for event in events}
    factors = []
    score = max(event["base_severity"] for event in events)
    if "suspicious_login" in event_types:
        factors.append({"label": "Suspicious successful login", "points": 8})
        score += 8
    if "privilege_escalation" in event_types:
        factors.append({"label": "Privilege escalation", "points": 10})
        score += 10
    if "sensitive_access" in event_types:
        factors.append({"label": "Sensitive resource accessed", "points": 8})
        score += 8
    if "data_exfiltration" in event_types:
        factors.append({"label": "Large outbound data transfer", "points": 12})
        score += 12
    score = min(score, 100)
    level = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 35 else "low"
    return score, level, factors


def get_scenarios():
    return [{"id": key, "name": value["name"], "description": value["description"], "event_count": len(value["events"])} for key, value in SCENARIOS.items()]


def analyze_scenario(scenario_id):
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        return None
    events = scenario["events"]
    links = build_links(events)
    score, level, factors = severity(events)
    malicious = level in {"high", "critical"}
    title = "Account Takeover with Data Exfiltration" if malicious else "Benign Authentication Activity"
    summary = (
        "Repeated authentication failures were followed by a successful login from an unfamiliar source. "
        "The same identity obtained elevated privileges, accessed confidential data, transferred a large volume externally, and disabled endpoint protection."
        if malicious
        else "The user recovered from two failed login attempts on a known device and continued normal mailbox activity. No wider attack sequence was found."
    )
    actions = (
        ["Disable the affected identity", "Revoke active sessions", "Block the suspicious source IP", "Isolate the endpoint", "Preserve logs and begin forensic review"]
        if malicious
        else ["Keep the identity under routine monitoring", "Close as benign after analyst verification"]
    )
    return {
        "incident_id": "INC-2026-0918-001" if malicious else "INC-2026-0918-002",
        "title": title,
        "severity": level,
        "score": score,
        "status": "awaiting_review",
        "summary": summary,
        "events": [{**event, "stage": STAGES[event["type"]]} for event in events],
        "links": links,
        "factors": factors,
        "indicators": [
            {"type": "IP", "value": events[0]["ip"], "status": "suspicious" if malicious else "trusted"},
            {"type": "Identity", "value": events[0]["user"], "status": "compromised" if malicious else "verified"},
            {"type": "Device", "value": events[0]["device"], "status": "at-risk" if malicious else "known"},
        ],
        "recommended_actions": actions,
        "metrics": {"raw_alerts": len(events), "correlated_alerts": len(events) if malicious else 0, "incidents": 1 if malicious else 0, "noise_reduced": 0 if malicious else len(events)},
    }

