import logging
import os
from datetime import datetime, timezone
from typing import Any

from supabase import Client, create_client


logger = logging.getLogger("sentrapixel.database")
_incident_cache: dict[str, dict[str, Any]] = {}


def get_supabase() -> Client | None:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SECRET_KEY")
    if not url or not key:
        return None
    return create_client(url, key)


def incident_row(incident: dict[str, Any]) -> dict[str, Any]:
    return {
        "incident_id": incident["incident_id"], "title": incident["title"],
        "severity": incident["severity"], "score": incident["score"],
        "status": incident.get("status", "open"), "summary": incident.get("summary"),
        "factors": incident.get("factors", []), "indicators": incident.get("indicators", []),
        "recommended_actions": incident.get("recommended_actions", []),
        "metrics": incident.get("metrics", {}),
    }


def save_incident(incident: dict[str, Any]) -> bool:
    row = incident_row(incident)
    existing = _incident_cache.get(row["incident_id"], {})
    _incident_cache[row["incident_id"]] = {
        **existing, **incident,
        "created_at": existing.get("created_at") or datetime.now(timezone.utc).isoformat(),
    }
    client = get_supabase()
    if not client:
        return True
    try:
        client.table("incidents").upsert(row, on_conflict="incident_id").execute()
        events = [{
            "incident_id": incident["incident_id"], "event_id": event.get("id", "unknown"),
            "stage": event.get("stage"), "event_time": event.get("time"),
            "event_type": event.get("type"), "details": event,
        } for event in incident.get("events", [])]
        if events:
            client.table("incident_events").upsert(events, on_conflict="incident_id,event_id").execute()
        return True
    except Exception as exc:
        logger.exception("Supabase incident save failed: %s", exc)
        return False


def list_incidents(limit: int = 50) -> list[dict[str, Any]]:
    client = get_supabase()
    if client:
        try:
            response = client.table("incidents").select("*").order("created_at", desc=True).limit(limit).execute()
            if response.data is not None:
                return response.data
        except Exception as exc:
            logger.exception("Supabase incident history read failed: %s", exc)
    return sorted(_incident_cache.values(), key=lambda row: row.get("created_at", ""), reverse=True)[:limit]


def get_incident(incident_id: str) -> dict[str, Any] | None:
    cached = _incident_cache.get(incident_id)
    if cached:
        return cached
    client = get_supabase()
    if not client:
        return None
    try:
        incident_response = client.table("incidents").select("*").eq("incident_id", incident_id).limit(1).execute()
        if not incident_response.data:
            return None
        incident = incident_response.data[0]
        event_response = client.table("incident_events").select("details").eq("incident_id", incident_id).order("event_time").execute()
        events = [row.get("details", {}) for row in (event_response.data or [])]
        investigation_response = client.table("investigations").select("provider,narrative,evidence,next_steps,created_at").eq("incident_id", incident_id).order("created_at", desc=True).limit(1).execute()
        if events:
            from correlation import build_result
            reconstructed = build_result(events, incident_id)
            incident = {**reconstructed, **incident, "events": reconstructed["events"], "links": reconstructed["links"]}
        else:
            incident["events"] = []
            incident["links"] = []
        incident["investigation"] = investigation_response.data[0] if investigation_response.data else None
        return incident
    except Exception as exc:
        logger.exception("Supabase incident detail read failed: %s", exc)
        return None


def incident_summary(incidents: list[dict[str, Any]]) -> dict[str, int]:
    total_alerts = sum(int(row.get("metrics", {}).get("raw_alerts", 0)) for row in incidents)
    noise_reduced = sum(int(row.get("metrics", {}).get("noise_reduced", 0)) for row in incidents)
    return {
        "total": len(incidents),
        "critical": sum(row.get("severity") == "critical" for row in incidents),
        "approved": sum(row.get("status") == "approved" for row in incidents),
        "pending": sum(row.get("status") in {"open", "awaiting_review", None} for row in incidents),
        "total_alerts": total_alerts,
        "noise_reduced": noise_reduced,
        "noise_reduction_percent": round((noise_reduced / total_alerts) * 100) if total_alerts else 0,
    }


def save_investigation(incident_id: str, investigation: dict[str, Any]) -> bool:
    if incident_id in _incident_cache:
        _incident_cache[incident_id]["investigation"] = investigation
    client = get_supabase()
    if not client:
        return True
    try:
        client.table("investigations").insert({
            "incident_id": incident_id, "provider": investigation["provider"],
            "narrative": investigation["narrative"], "evidence": investigation.get("evidence", []),
            "next_steps": investigation.get("next_steps", []),
        }).execute()
        return True
    except Exception as exc:
        logger.exception("Supabase investigation save failed: %s", exc)
        return False


def save_review(incident_id: str, decision: str) -> bool:
    if incident_id in _incident_cache:
        _incident_cache[incident_id]["status"] = decision
    client = get_supabase()
    if not client:
        return True
    try:
        client.table("analyst_reviews").insert({"incident_id": incident_id, "decision": decision}).execute()
        client.table("incidents").update({"status": decision}).eq("incident_id", incident_id).execute()
        return True
    except Exception as exc:
        logger.exception("Supabase review save failed: %s", exc)
        return False
