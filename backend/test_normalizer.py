from normalizer import normalize_upload
from correlation import analyze_event_batch

def run(payload):
    alerts,_=normalize_upload(payload); return alerts,analyze_event_batch(alerts)

def test_nested_ransomware():
    a,b=run({"timestamp":"2026-09-19T03:10:12Z","event_type":"ransomware_detected","severity":"CRITICAL","host_info":{"hostname":"DC-SERVER-01","ip_address":"10.0.1.10","user_account":"SYSTEM"},"attack_details":{"command_line":"vssadmin delete shadows","files_encrypted_count":1450}})
    assert len(a)==1 and a[0]["type"]=="malware" and a[0]["device"]=="DC-SERVER-01"
    assert b["standalone_count"]==1 and b["uncorrelated_alerts"]==0

def test_vendor_chain():
    p=[
      {"timestamp":"2026-09-19T03:10:05Z","incident_id":"INC-X","event_type":"email_received","actor":{"user":"jdoe","ip":"192.168.1.50"}},
      {"timestamp":"2026-09-19T03:12:44Z","incident_id":"INC-X","event_type":"process_creation","actor":{"user":"jdoe","host":"WS1","ip":"192.168.1.50"},"details":{"command_line":"powershell","macro_executed":True}},
      {"timestamp":"2026-09-19T03:13:02Z","incident_id":"INC-X","event_type":"network_connection","actor":{"host":"WS1","ip":"192.168.1.50"},"details":{"threat_intel_match":"known_c2"}},
      {"timestamp":"2026-09-19T03:16:19Z","incident_id":"INC-X","event_type":"privilege_escalation","actor":{"user":"jdoe","host":"WS1"}}]
    a,b=run(p)
    assert len(a)==4 and len({x["id"] for x in a})==4
    assert all(x.get("incident_key")=="INC-X" for x in a)
    assert b["incident_count"]==1 and b["correlated_alerts"]==4 and b["uncorrelated_alerts"]==0

def test_wrapped_alias_chain():
    p={"alerts":[{"event_time":"2026-09-19 03:00:00","alert_id":"A1","category":"failed login","username":"u","src_ip":"1.2.3.4","hostname":"PC1","priority":"high"},{"event_time":"2026-09-19 03:04:00","alert_id":"A2","category":"suspicious login","username":"u","src_ip":"1.2.3.4","hostname":"PC1","priority":"high"},{"event_time":"2026-09-19 03:08:00","alert_id":"A3","category":"privilege escalation","username":"u","src_ip":"1.2.3.4","hostname":"PC1","priority":"critical"}]}
    a,b=run(p); assert len(a)==3 and b["incident_count"]==1 and b["correlated_alerts"]==3

def test_independent_critical_alerts_stay_separate():
    p=[{"timestamp":"2026-09-19T04:00:00Z","event_type":"data_exfiltration_alert","severity":"CRITICAL","source_device":{"hostname":"FIN1","ip_address":"10.0.0.1","user":"a"}},{"timestamp":"2026-09-19T04:01:00Z","event_type":"ransomware_detected","severity":"CRITICAL","host_info":{"hostname":"SRV2","ip_address":"10.0.0.2","user_account":"SYSTEM"}}]
    a,b=run(p); assert len(a)==2 and b["incident_count"]==0 and b["standalone_count"]==2

def test_missing_timestamp_and_nested_extraction():
    a,_=run({"event_type":"data_exfiltration_alert","severity":"CRITICAL","source_device":{"hostname":"FIN4","ip_address":"192.168.10.45","user":"john"},"destination_device":{"ip_address":"185.220.101.5"},"exfiltration_details":{"bytes_sent":524288000}})
    assert a[0]["timestamp_inferred"] is True and a[0]["device"]=="FIN4" and a[0]["ip"]=="192.168.10.45" and a[0]["user"]=="john" and a[0]["destination_ip"]=="185.220.101.5" and a[0]["bytes_sent"]==524288000
