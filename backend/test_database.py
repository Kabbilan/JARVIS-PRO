from correlation import analyze_scenario
from database import incident_summary, list_incidents, save_incident, save_review


def test_incident_history_and_review_without_supabase(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
    incident = analyze_scenario("account-takeover")
    assert save_incident(incident)
    saved = next(item for item in list_incidents() if item["incident_id"] == incident["incident_id"])
    assert saved["severity"] == "critical"
    assert saved["created_at"]
    assert save_review(incident["incident_id"], "approved")
    reviewed = next(item for item in list_incidents() if item["incident_id"] == incident["incident_id"])
    assert reviewed["status"] == "approved"
    summary = incident_summary(list_incidents())
    assert summary["total"] >= 1
    assert summary["critical"] >= 1
    assert summary["approved"] >= 1
