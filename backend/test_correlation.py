from correlation import analyze_events, analyze_scenario


def test_account_takeover_is_critical():
    result = analyze_scenario("account-takeover")
    assert result["severity"] == "critical"
    assert result["score"] == 100
    assert len(result["links"]) == 5
    assert result["events"][-2]["stage"] == "Data Exfiltration"


def test_benign_login_stays_low():
    result = analyze_scenario("benign-login")
    assert result["severity"] == "low"
    assert result["metrics"]["incidents"] == 0


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
