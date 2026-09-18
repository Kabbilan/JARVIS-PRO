from ai_agent import fallback_investigation, fallback_response_plan, generate_agent_pipeline, generate_investigation, verify_agent_outputs
from correlation import analyze_event_batch, analyze_events, analyze_scenario


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
    assert result["title"] == "Uncorrelated High-Risk Alert — Data Exfiltration Signal"
    assert result["classification"] == "uncorrelated_high_risk_signal"
    assert "not a confirmed data-exfiltration incident" in result["summary"]
    assert "source alert severity" in result["classification_reason"]
    assert len(result["missing_evidence"]) == 3


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


def test_batch_analysis_creates_independent_incidents_and_keeps_noise_out():
    alerts = [
        {"id": "A1", "time": "09:00", "type": "failed_login", "user": "a@corp.io", "ip": "1.1.1.1", "device": "DA"},
        {"id": "A2", "time": "09:04", "type": "suspicious_login", "user": "a@corp.io", "ip": "1.1.1.1", "device": "DA"},
        {"id": "A3", "time": "09:08", "type": "privilege_escalation", "user": "a@corp.io", "ip": "1.1.1.1", "device": "DA"},
        {"id": "B1", "time": "10:00", "type": "sensitive_access", "user": "b@corp.io", "ip": "2.2.2.2", "device": "DB"},
        {"id": "B2", "time": "10:05", "type": "data_exfiltration", "user": "b@corp.io", "ip": "2.2.2.2", "device": "DB"},
        {"id": "C1", "time": "11:00", "type": "malware", "user": "c@corp.io", "ip": "3.3.3.3", "device": "DC"},
        {"id": "C2", "time": "11:03", "type": "c2_connection", "user": "c@corp.io", "ip": "3.3.3.3", "device": "DC"},
        {"id": "N1", "time": "12:00", "type": "normal_activity", "user": "noise@corp.io", "ip": "10.0.0.9", "device": "DN"},
    ]
    result = analyze_event_batch(alerts)
    assert result["raw_alerts"] == 8
    assert result["incident_count"] == 3
    assert result["correlated_alerts"] == 7
    assert result["uncorrelated_alerts"] == 1
    assert {item["title"] for item in result["incidents"]} == {
        "Account Takeover", "Possible Data Exfiltration", "Correlated Malware / C2 Activity"
    }
    ids = [item["incident_id"] for item in result["incidents"]]
    assert len(ids) == len(set(ids))


def test_batch_does_not_merge_disconnected_users_devices_or_ips():
    alerts = [
        {"id": "X1", "time": "09:00", "type": "data_exfiltration", "user": "x@corp.io", "ip": "4.4.4.4", "device": "DX", "base_severity": 95},
        {"id": "Y1", "time": "09:01", "type": "privilege_escalation", "user": "y@corp.io", "ip": "5.5.5.5", "device": "DY", "base_severity": 90},
    ]
    result = analyze_event_batch(alerts)
    assert result["incident_count"] == 0
    assert result["correlated_alerts"] == 0
    assert result["uncorrelated_alerts"] == 2


def test_vendor_attack_chain_correlates_by_case_and_semantics():
    alerts = [
        {"id":"E1","timestamp":"2026-09-19T03:10:05+00:00","time":"08:40","type":"phishing","incident_key":"INC-2026-8891","user":"jdoe@company.com","ip":"192.168.1.50","device":"unknown","base_severity":60},
        {"id":"E2","timestamp":"2026-09-19T03:12:44+00:00","time":"08:42","type":"execution","incident_key":"INC-2026-8891","user":"jdoe@company.com","ip":"192.168.1.50","device":"WS-JDOE-01","base_severity":75},
        {"id":"E3","timestamp":"2026-09-19T03:13:02+00:00","time":"08:43","type":"c2_connection","incident_key":"INC-2026-8891","user":"unknown","ip":"192.168.1.50","device":"WS-JDOE-01","base_severity":80},
        {"id":"E4","timestamp":"2026-09-19T03:16:19+00:00","time":"08:46","type":"privilege_escalation","incident_key":"INC-2026-8891","user":"jdoe@company.com","ip":"unknown","device":"WS-JDOE-01","base_severity":85},
    ]
    result=analyze_event_batch(alerts)
    assert result["raw_alerts"]==4
    assert result["incident_count"]==1
    assert result["correlated_alerts"]==4
    assert result["uncorrelated_alerts"]==0
