import time

from fastapi.testclient import TestClient

import main


client = TestClient(main.app)


def test_investigation_deadline_returns_fallback(monkeypatch):
    monkeypatch.setenv("GEMINI_DEADLINE_SECONDS", "0.01")
    monkeypatch.setattr(main, "generate_investigation", lambda incident: time.sleep(0.1))
    response = client.post("/api/investigate/account-takeover")
    assert response.status_code == 200
    assert response.json()["investigation"]["provider"] == "fallback"


def test_unknown_scenario_returns_404():
    assert client.post("/api/analyze/not-a-scenario").status_code == 404


def test_empty_alerts_rejected():
    assert client.post("/api/analyze-alerts", json={"alerts": []}).status_code == 422


def test_invalid_review_decision_rejected():
    response = client.post("/api/review", json={"incident_id": "INC-TEST", "decision": "maybe"})
    assert response.status_code == 422


def test_review_approved(monkeypatch):
    saved = {}
    monkeypatch.setattr(main, "save_review", lambda incident_id, decision: saved.update(incident_id=incident_id, decision=decision) or True)
    response = client.post("/api/review", json={"incident_id": "INC-TEST", "decision": "approved")
    assert response.status_code == 200
    assert response.json()["decision"] == "approved"
    assert saved == {"incident_id": "INC-TEST", "decision": "approved"}


def test_incident_history_shape(monkeypatch):
    monkeypatch.setattr(main, "list_incidents", lambda: [])
    response = client.get("/api/incidents")
    assert response.status_code == 200
    body = response.json()
    assert body["incidents"] == []
    assert body["summary"]["total"] == 0


def test_report_is_pdf(monkeypatch):
    monkeypatch.setattr(main, "generate_investigation", lambda incident: main.fallback_investigation(incident))
    response = client.get("/api/report/account-takeover")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF")
