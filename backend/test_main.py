import time

from fastapi.testclient import TestClient

import main


def test_investigation_deadline_returns_fallback(monkeypatch):
    monkeypatch.setenv("GEMINI_DEADLINE_SECONDS", "0.01")
    monkeypatch.setattr(main, "generate_investigation", lambda incident: time.sleep(0.1))
    response = TestClient(main.app).post("/api/investigate/account-takeover")
    assert response.status_code == 200
    assert response.json()["investigation"]["provider"] == "fallback"
