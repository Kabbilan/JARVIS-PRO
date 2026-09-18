from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any
import re

ALIASES = {
    "timestamp": ("timestamp", "event_time", "datetime", "time"),
    "id": ("id", "event_id", "alert_id"),
    "type": ("type", "action", "event_type", "category"),
    "ip": ("ip", "source_ip", "src_ip"),
    "resource": ("resource", "destination_ip", "dst_ip", "destination"),
    "user": ("user", "username", "account"),
    "device": ("device", "hostname", "host", "endpoint"),
    "label": ("label", "message", "description"),
    "base_severity": ("base_severity", "severity", "priority"),
    "source": ("source", "product", "vendor"),
}

KNOWN_TYPES = {
    "failed_login", "suspicious_login", "privilege_escalation", "sensitive_access",
    "data_exfiltration", "defense_evasion", "normal_login", "normal_activity",
    "malware", "c2_connection",
}

SEVERITY_WORDS = {"informational": 5, "info": 5, "low": 20, "medium": 50, "moderate": 50, "high": 75, "critical": 95}


class UnsupportedAlertSchema(ValueError):
    pass


def _pick(alert: dict[str, Any], canonical: str):
    for key in ALIASES[canonical]:
        if key in alert and alert[key] not in (None, ""):
            return alert[key], key
    return None, None


def _parse_timestamp(value: Any) -> datetime:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%H:%M")
        except ValueError as exc:
            raise UnsupportedAlertSchema("Valid JSON, but unsupported security-alert schema. Timestamp format is not recognized.") from exc
        now = datetime.now(ZoneInfo("Asia/Kolkata"))
        parsed = parsed.replace(year=now.year, month=now.month, day=now.day, tzinfo=ZoneInfo("Asia/Kolkata"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ZoneInfo("Asia/Kolkata"))
    return parsed


def _severity(value: Any):
    if value is None:
        return None
    if isinstance(value, str) and not value.strip().isdigit():
        return SEVERITY_WORDS.get(value.strip().lower())
    try:
        return max(0, min(int(value), 100))
    except (TypeError, ValueError):
        return None


def normalize_uploaded_alert(alert: dict[str, Any], index: int = 0):
    if not isinstance(alert, dict):
        raise UnsupportedAlertSchema("Valid JSON, but unsupported security-alert schema. Alerts must be JSON objects.")

    timestamp_value, timestamp_key = _pick(alert, "timestamp")
    type_value, type_key = _pick(alert, "type")
    if timestamp_value is None or type_value is None:
        raise UnsupportedAlertSchema("Valid JSON, but unsupported security-alert schema. No recognizable timestamp/type fields found.")

    event_type = str(type_value).strip().lower().replace(" ", "_").replace("-", "_")
    if event_type not in KNOWN_TYPES:
        raise UnsupportedAlertSchema(f"Valid JSON, but unsupported security-alert schema. Security event type '{event_type}' cannot be inferred safely.")

    parsed = _parse_timestamp(timestamp_value)
    canonical = parsed.astimezone(timezone.utc)
    display = canonical.astimezone(ZoneInfo("Asia/Kolkata"))

    result = {
        "timestamp": canonical.isoformat(),
        "time": display.strftime("%H:%M"),
        "type": event_type,
    }
    mappings = {"timestamp": timestamp_key, "type": type_key}
    for field in ("id", "ip", "resource", "user", "device", "label", "base_severity", "source"):
        value, source_key = _pick(alert, field)
        if value is not None:
            result[field] = _severity(value) if field == "base_severity" else str(value)
            mappings[field] = source_key

    result.setdefault("id", f"RAW-{index + 1:03d}")
    result.setdefault("source", "Unknown")
    result.setdefault("label", event_type.replace("_", " ").title())
    result.setdefault("user", "unknown")
    result.setdefault("ip", "unknown")
    result.setdefault("device", "unknown")
    result.setdefault("resource", "Unknown")
    return result, mappings


def _walk_objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_objects(child)


def _report_incidents(payload):
    if not isinstance(payload, dict):
        return []
    report = payload.get("soc_report", payload)
    if not isinstance(report, dict):
        return []
    report_time = report.get("timestamp") or report.get("datetime") or report.get("event_time")
    incidents = report.get("active_incidents") or report.get("incidents")
    if not report_time or not isinstance(incidents, list):
        return []
    converted = []
    for item in incidents:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or item.get("message") or item.get("description") or "").lower()
        # Only map explicit, security-meaningful phrases; never invent an attack type from arbitrary text.
        phrase_map = {
            "failed login": "failed_login", "brute force": "failed_login",
            "suspicious login": "suspicious_login", "impossible travel": "suspicious_login",
            "privilege escalation": "privilege_escalation",
            "data exfiltration": "data_exfiltration", "exfiltration": "data_exfiltration",
            "outbound traffic": "c2_connection", "command and control": "c2_connection",
            "malware": "malware", "ransomware": "malware",
            "defense evasion": "defense_evasion",
        }
        event_type = next((kind for phrase, kind in phrase_map.items() if phrase in title), None)
        if not event_type:
            continue
        converted.append({
            "timestamp": item.get("timestamp") or report_time,
            "event_id": item.get("id") or item.get("event_id"),
            "action": event_type,
            "severity": item.get("severity"),
            "message": item.get("title") or item.get("message"),
            "source_ip": item.get("source_ip") or item.get("src_ip"),
            "username": item.get("user") or item.get("username"),
            "hostname": item.get("device") or item.get("hostname"),
        })
    return converted


def normalize_upload(payload: Any):
    # First handle known wrappers and raw arrays/objects.
    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        candidates = payload["alerts"]
    else:
        candidates = [payload] if isinstance(payload, dict) else []

    normalized, feedback, rejected = [], {}, []
    for index, alert in enumerate(candidates):
        try:
            event, mappings = normalize_uploaded_alert(alert, index)
            normalized.append(event)
            for canonical, source_key in mappings.items():
                if source_key:
                    feedback[f"{source_key} → {canonical}"] = True
        except UnsupportedAlertSchema:
            rejected.append(alert)

    # Generic nested JSON: discover embedded alert-like objects anywhere in the document.
    if not normalized and isinstance(payload, (dict, list)):
        for obj in _walk_objects(payload):
            try:
                event, mappings = normalize_uploaded_alert(obj, len(normalized))
                normalized.append(event)
                for canonical, source_key in mappings.items():
                    if source_key:
                        feedback[f"{source_key} → {canonical}"] = True
            except UnsupportedAlertSchema:
                pass

    # SOC reports/incident summaries: safely adapt recognized incident semantics into events.
    if not normalized:
        for alert in _report_incidents(payload):
            event, mappings = normalize_uploaded_alert(alert, len(normalized))
            normalized.append(event)
            for canonical, source_key in mappings.items():
                if source_key:
                    feedback[f"{source_key} → {canonical}"] = True
        if normalized:
            feedback["SOC report → security events"] = True

    if not normalized:
        raise UnsupportedAlertSchema("Valid JSON, but no safely inferable security events were found. SentraPixel searched nested objects, common wrappers, aliases, and SOC incident summaries.")

    if len(normalized) > 500:
        raise UnsupportedAlertSchema("Security alert upload must contain between 1 and 500 alerts.")
    return normalized, list(feedback)
