from ai_agent import fallback_investigation, fallback_response_plan, generate_agent_pipeline, generate_investigation, verify_agent_outputs
from correlation import analyze_events, analyze_scenario


def test_account_takeover_is_critical():
    result = analyze_scenario("account-takeover")
    assert result["severity"] == "critical"
    assert result["title"] == "Account Takeover"
    assert len(result["links"]) == 3
    assert result["events"][1]["stage"] == "Account Compromise"
    assert result["confidence"] >= 80
    assert {item["id"] for item in result["mitre_techniques"]} >= {"T1110", "T1078", "T1098"}


def test_data_exfiltration_is_separate_and_critical():
    result = analyze_scenario("data-exfiltration")
    assert result["severity"] == "critical"
    assert result["title"] == "Possible Data Exfiltration"
    assert result["metrics"]["incidents"] == 1
    assert result["events"][2]["stage"] == "Data Exfiltration"


def test_benign_login_stays_low():
    result = analyze_scenario("benign-login")
    assert result["severity"] == "low"
    assert result["metrics"]["incidents"] == 0
    assert result["confidence"] < 60


def test_raw_alerts_are_normalized_and_correlated():
    alerts = [
        {"time": "09:00", "type": "failed login", "user": "sam@acme.io", "ip": "8.8.8.8", "device": "D-1"},
        {"time": "09:04", "type": "suspicious_login", "user": "sam@acme.io", "ip": "8.8.8.8", "device": "D-1"},
        {"time": "09:08", "type": "data_exfiltration", "user": "sam@acme.io", "ip": "8.8.8.8", "device": "D-1"},
    ]
    result = analyze_events(alerts)
    assert result["severity"] == "critical"
    assert result["metrics"]["incidents"] == 1
    assert result["events"][0]["type"] == "failed_login"
    assert len(result["links"]) == 2


def test_unrelated_noise_does_not_break_or_inflate_attack_chain():
    alerts = [
        {"id": "A", "time": "09:00", "type": "failed_login", "user": "sam@acme.io", "ip": "8.8.8.8", "device": "D-1"},
        {"id": "NOISE", "time": "09:02", "type": "normal_activity", "user": "alex@acme.io", "ip": "10.0.0.2", "device": "D-9"},
        {"id": "B", "time": "09:04", "type": "suspicious_login", "user": "sam@acme.io", "ip": "8.8.8.8", "device": "D-1"},
        {"id": "C", "time": "09:08", "type": "data_exfiltration", "user": "sam@acme.io", "ip": "8.8.8.8", "device": "D-1"},
    ]
    result = analyze_events(alerts)
    assert result["severity"] == "critical"
    assert result["metrics"]["correlated_alerts"] == 3
    assert result["metrics"]["noise_reduced"] == 1
    assert {link["to"] for link in result["links"]} == {"B", "C"}


def test_time_proximity_alone_is_not_correlation_evidence():
    alerts = [
        {"time": "09:00", "type": "normal_activity", "user": "one@acme.io", "ip": "10.0.0.1", "device": "D-1"},
        {"time": "09:01", "type": "data_exfiltration", "user": "two@acme.io", "ip": "10.0.0.2", "device": "D-2"},
    ]
    result = analyze_events(alerts)
    assert result["links"] == []
    assert result["metrics"]["incidents"] == 0
    assert result["metrics"]["noise_reduced"] == 2


def test_investigation_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    incident = analyze_scenario("data-exfiltration")
    investigation = generate_investigation(incident)
    assert investigation["provider"] == "fallback"
    assert investigation["narrative"]
    assert investigation["evidence"]
    assert investigation["next_steps"]


def test_multi_agent_pipeline_has_safe_fallback(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    incident = analyze_scenario("account-takeover")
    pipeline = generate_agent_pipeline(incident)
    assert pipeline["investigation"]["provider"] == "fallback"
    assert pipeline["response_plan"]["human_approval_required"] is True
    assert pipeline["verification"]["verdict"] == "verified"
    assert pipeline["verification"]["checks_passed"] == pipeline["verification"]["checks_total"]


def test_verifier_flags_low_evidence_activity():
    incident = analyze_scenario("benign-login")
    investigation = fallback_investigation(incident)
    response_plan = fallback_response_plan(incident)
    verification = verify_agent_outputs(incident, investigation, response_plan)
    assert verification["verdict"] == "needs_review"
    assert verification["warnings"]
