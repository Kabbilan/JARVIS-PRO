from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any

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


def normalize_upload(payload: Any):
    if isinstance(payload, list):
        alerts = payload
    elif isinstance(payload, dict) and "alerts" in payload:
        alerts = payload["alerts"]
    elif isinstance(payload, dict):
        alerts = [payload]
    else:
        raise UnsupportedAlertSchema("Valid JSON, but unsupported security-alert schema.")

    if not isinstance(alerts, list) or not 1 <= len(alerts) <= 500:
        raise UnsupportedAlertSchema("Security alert upload must contain between 1 and 500 alerts.")

    normalized, feedback = [], {}
    for index, alert in enumerate(alerts):
        event, mappings = normalize_uploaded_alert(alert, index)
        normalized.append(event)
        for canonical, source_key in mappings.items():
            if source_key:
                feedback[f"{source_key} → {canonical}"] = True
    return normalized, list(feedback)
