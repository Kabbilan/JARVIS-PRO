from correlation import analyze_scenario


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

