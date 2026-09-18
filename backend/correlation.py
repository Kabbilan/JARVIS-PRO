from datetime import datetime
from uuid import uuid4


SCENARIOS = {
    "account-takeover": {
        "name": "Account Takeover",
        "description": "Repeated login failures are followed by a suspicious successful login and privilege escalation.",
        "events": [
            {"id": "EVT-101", "time": "10:00", "source": "Identity", "type": "failed_login", "label": "8 failed login attempts", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "VPN", "base_severity": 18},
            {"id": "EVT-102", "time": "10:04", "source": "Identity", "type": "suspicious_login", "label": "Successful login from unfamiliar location", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "VPN", "base_severity": 42},
            {"id": "EVT-103", "time": "10:07", "source": "IAM", "type": "privilege_escalation", "label": "Administrator privilege granted", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "Admin Console", "base_severity": 72},
            {"id": "EVT-104", "time": "10:11", "source": "Endpoint", "type": "defense_evasion", "label": "Endpoint protection tampering detected", "user": "arun@acme.io", "ip": "185.20.10.8", "device": "DEV-17", "resource": "EDR Agent", "base_severity": 76},
        ],
    },
    "data-exfiltration": {
        "name": "Data Exfiltration",
        "description": "Sensitive data is collected and transferred to an unusual external destination.",
        "events": [
            {"id": "EVT-301", "time": "14:00", "source": "File Server", "type": "sensitive_access", "label": "Confidential customer records accessed", "user": "dev@acme.io", "ip": "10.0.4.22", "device": "DEV-31", "resource": "Customer Records", "base_severity": 68},
            {"id": "EVT-302", "time": "14:05", "source": "File Server", "type": "sensitive_access", "label": "Large batch of confidential files collected", "user": "dev@acme.io", "ip": "10.0.4.22", "device": "DEV-31", "resource": "Customer Records", "base_severity": 72},
            {"id": "EVT-303", "time": "14:10", "source": "Firewall", "type": "data_exfiltration", "label": "2.4 GB outbound transfer to unknown host", "user": "dev@acme.io", "ip": "10.0.4.22", "device": "DEV-31", "resource": "External Host", "base_severity": 90},
            {"id": "EVT-304", "time": "14:13", "source": "Endpoint", "type": "defense_evasion", "label": "Security telemetry interrupted after transfer", "user": "dev@acme.io", "ip": "10.0.4.22", "device": "DEV-31", "resource": "EDR Agent", "base_severity": 76},
        ],
    },
    "benign-login": {
        "name": "Benign Activity",
        "description": "A legitimate employee mistypes a password before a normal login.",
        "events": [
            {"id": "EVT-201", "time": "11:02", "source": "Identity", "type": "failed_login", "label": "2 failed login attempts", "user": "maya@acme.io", "ip": "10.0.2.15", "device": "DEV-08", "resource": "Email", "base_severity": 12},
            {"id": "EVT-202", "time": "11:04", "source": "Identity", "type": "normal_login", "label": "Successful login from known device", "user": "maya@acme.io", "ip": "10.0.2.15", "device": "DEV-08", "resource": "Email", "base_severity": 5},
            {"id": "EVT-203", "time": "11:08", "source": "Email", "type": "normal_activity", "label": "Normal mailbox activity", "user": "maya@acme.io", "ip": "10.0.2.15", "device": "DEV-08", "resource": "Email", "base_severity": 3},
        ],
    },
}

STAGES = {
    "failed_login": "Credential Attack", "suspicious_login": "Account Compromise",
    "privilege_escalation": "Privilege Escalation", "sensitive_access": "Collection",
    "data_exfiltration": "Data Exfiltration", "defense_evasion": "Defense Evasion",
    "normal_login": "Verified Login", "normal_activity": "Normal Activity",
}

DEFAULT_SEVERITY = {
    "failed_login": 15, "suspicious_login": 40, "privilege_escalation": 60,
    "sensitive_access": 65, "data_exfiltration": 85, "defense_evasion": 70,
    "normal_login": 5, "normal_activity": 3,
}

MITRE_TECHNIQUES = {
    "failed_login": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "suspicious_login": {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    "privilege_escalation": {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"},
    "sensitive_access": {"id": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "data_exfiltration": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "defense_evasion": {"id": "T1562.001", "name": "Impair Defenses", "tactic": "Defense Evasion"},
}


def minutes(value):
    parsed = datetime.strptime(value, "%H:%M")
    return parsed.hour * 60 + parsed.minute


def normalize_event(event, index):
    event_type = str(event.get("type", "normal_activity")).strip().lower().replace(" ", "_")
    return {
        "id": str(event.get("id") or f"RAW-{index + 1:03d}"),
        "time": str(event.get("time") or "00:00"),
        "source": str(event.get("source") or "Unknown"),
        "type": event_type,
        "label": str(event.get("label") or event_type.replace("_", " ").title()),
        "user": str(event.get("user") or "unknown"),
        "ip": str(event.get("ip") or "unknown"),
        "device": str(event.get("device") or "unknown"),
        "resource": str(event.get("resource") or "Unknown"),
        "base_severity": max(0, min(int(event.get("base_severity", DEFAULT_SEVERITY.get(event_type, 10))), 100)),
    }


def correlation_reason(left, right):
    reasons = []
    if left["user"] != "unknown" and left["user"] == right["user"]:
        reasons.append("same user")
    if left["device"] != "unknown" and left["device"] == right["device"]:
        reasons.append("same device")
    if left["ip"] != "unknown" and left["ip"] == right["ip"]:
        reasons.append("same IP")
    shared_entity_count = len(reasons)
    gap = minutes(right["time"]) - minutes(left["time"])
    if shared_entity_count == 0 or not 0 <= gap <= 15:
        return ""
    reasons.append(f"{gap}-minute gap")
    return ", ".join(reasons)


def build_links(events):
    links = []
    for right_index in range(1, len(events)):
        candidates = []
        for left_index in range(right_index):
            reason = correlation_reason(events[left_index], events[right_index])
            if reason:
                shared_entities = reason.count("same ")
                gap = minutes(events[right_index]["time"]) - minutes(events[left_index]["time"])
                candidates.append((shared_entities, -gap, left_index, reason))
        if candidates:
            _, _, left_index, reason = max(candidates)
            links.append({
                "from": events[left_index]["id"],
                "to": events[right_index]["id"],
                "reason": reason,
            })
    return links


def severity(events):
    event_types = {event["type"] for event in events}
    factors = []
    score = max(event["base_severity"] for event in events)
    additions = [
        ("suspicious_login", "Suspicious successful login", 8),
        ("privilege_escalation", "Privilege escalation", 10),
        ("sensitive_access", "Sensitive resource accessed", 8),
        ("data_exfiltration", "Large outbound data transfer", 12),
        ("defense_evasion", "Security control evasion", 7),
    ]
    for event_type, label, points in additions:
        if event_type in event_types:
            factors.append({"label": label, "points": points})
            score += points
    score = min(score, 100)
    level = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 35 else "low"
    return score, level, factors


def build_result(events, incident_id=None):
    if not events:
        return None
    events = sorted(events, key=lambda event: minutes(event["time"]))
    links = build_links(events)
    score, level, factors = severity(events)
    event_types = {event["type"] for event in events}
    malicious = level in {"high", "critical"} and len(links) > 0

    if "data_exfiltration" in event_types and "privilege_escalation" in event_types:
        title = "Account Compromise with Data Exfiltration"
    elif "data_exfiltration" in event_types:
        title = "Possible Data Exfiltration"
    elif "suspicious_login" in event_types and "privilege_escalation" in event_types:
        title = "Account Takeover"
    elif malicious:
        title = "Correlated Security Incident"
    else:
        title = "Benign or Low-Risk Activity"

    correlated_ids = {link["from"] for link in links} | {link["to"] for link in links}
    correlated_count = len(correlated_ids) if malicious else 0
    correlated_events = [event for event in events if event["id"] in correlated_ids]
    story_events = correlated_events if malicious else events
    stages = [STAGES.get(event["type"], event["type"].replace("_", " ").title()) for event in story_events]
    summary = (
        f"SentraPixel correlated {correlated_count} of {len(events)} alerts using identity, device, IP and time evidence. "
        f"Observed attack progression: {' -> '.join(stages)}."
        if malicious else
        f"SentraPixel analyzed {len(events)} alerts but did not find a high-confidence malicious attack chain."
    )
    actions = (
        ["Disable the affected identity", "Revoke active sessions", "Block the suspicious source IP",
         "Isolate the endpoint", "Preserve logs and begin forensic review"]
        if malicious else
        ["Keep the identity under routine monitoring", "Close as benign after analyst verification"]
    )
    anchor = max(correlated_events or events, key=lambda event: event["base_severity"])
    shared_evidence = sum(reason.count("same ") for reason in (link["reason"] for link in links))
    confidence = min(99, 35 + len(links) * 12 + shared_evidence * 4) if malicious else max(15, 55 - len(events) * 5)
    techniques = []
    for event in events:
        technique = MITRE_TECHNIQUES.get(event["type"])
        if technique and not any(item["id"] == technique["id"] for item in techniques):
            techniques.append({**technique, "evidence": f'{event["id"]}: {event["label"]}'})
    return {
        "incident_id": incident_id or f"INC-{uuid4().hex[:10].upper()}",
        "title": title, "severity": level, "score": score, "status": "awaiting_review",
        "summary": summary,
        "confidence": confidence,
        "confidence_basis": f"{len(links)} evidence links across {shared_evidence} shared entity matches",
        "events": [{**event, "stage": STAGES.get(event["type"], event["type"].replace("_", " ").title())} for event in events],
        "links": links, "factors": factors,
        "mitre_techniques": techniques,
        "indicators": [
            {"type": "IP", "value": anchor["ip"], "status": "suspicious" if malicious else "observed"},
            {"type": "Identity", "value": anchor["user"], "status": "compromised" if malicious else "observed"},
            {"type": "Device", "value": anchor["device"], "status": "at-risk" if malicious else "observed"},
        ],
        "recommended_actions": actions,
        "metrics": {
            "raw_alerts": len(events), "correlated_alerts": correlated_count,
            "incidents": 1 if malicious else 0, "noise_reduced": len(events) - correlated_count,
        },
    }


def analyze_events(raw_events):
    events = [normalize_event(event, index) for index, event in enumerate(raw_events)]
    return build_result(events)


def get_scenarios():
    return [{"id": key, "name": value["name"], "description": value["description"], "event_count": len(value["events"])} for key, value in SCENARIOS.items()]


def analyze_scenario(scenario_id):
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        return None
    incident_ids = {
        "account-takeover": "INC-2026-0918-001",
        "data-exfiltration": "INC-2026-0918-002",
        "benign-login": "INC-2026-0918-003",
    }
    return build_result(scenario["events"], incident_ids.get(scenario_id))
