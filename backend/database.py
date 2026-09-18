import os
from typing import Any

from supabase import Client, create_client


def get_supabase() -> Client | None:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SECRET_KEY")
    if not url or not key:
        return None
    return create_client(url, key)


def save_incident(incident: dict[str, Any]) -> bool:
    client = get_supabase()
    if not client:
        return False

    row = {
        "incident_id": incident["incident_id"],
        "title": incident["title"],
        "severity": incident["severity"],
        "score": incident["score"],
        "status": incident.get("status", "open"),
        "summary": incident.get("summary"),
        "factors": incident.get("factors", []),
        "indicators": incident.get("indicators", []),
        "recommended_actions": incident.get("recommended_actions", []),
        "metrics": incident.get("metrics", {}),
    }
    client.table("incidents").upsert(row, on_conflict="incident_id").execute()

    events = []
    for event in incident.get("events", []):
        events.append({
            "incident_id": incident["incident_id"],
            "event_id": event.get("id", "unknown"),
            "stage": event.get("stage"),
            "event_time": event.get("time"),
            "event_type": event.get("type"),
            "details": event,
        })
    if events:
        client.table("incident_events").upsert(
            events, on_conflict="incident_id,event_id"
        ).execute()
    return True


def save_investigation(incident_id: str, investigation: dict[str, Any]) -> bool:
    client = get_supabase()
    if not client:
        return False
    client.table("investigations").insert({
        "incident_id": incident_id,
        "provider": investigation["provider"],
        "narrative": investigation["narrative"],
        "evidence": investigation.get("evidence", []),
        "next_steps": investigation.get("next_steps", []),
    }).execute()
    return True


def save_review(incident_id: str, decision: str) -> bool:
    client = get_supabase()
    if not client:
        return False
    client.table("analyst_reviews").insert({
        "incident_id": incident_id,
        "decision": decision,
    }).execute()
    return True
