from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from typing import Any
import hashlib, json, re, os

ALIASES = {
    "timestamp": ("timestamp","event_time","datetime","time","date","created_at","created","occurred_at","observed_at","first_seen","last_seen","start_time"),
    "id": ("id","event_id","alert_id","incident_id","uuid","uid","eventid"),
    "type": ("type","action","event_type","category","event_name","name","rule_name","signature","alert_type","threat_type"),
    "ip": ("ip","source_ip","src_ip","client_ip","remote_ip","ip_address"),
    "resource": ("resource","destination_ip","dst_ip","destination","target","target_ip","url","domain","file"),
    "user": ("user","username","account","principal","actor","email"),
    "device": ("device","hostname","host","endpoint","computer","machine","asset"),
    "label": ("label","message","description","title","summary","reason"),
    "base_severity": ("base_severity","severity","priority","risk","risk_score","score"),
    "source": ("source","product","vendor","sensor","provider","service"),
}
KNOWN_TYPES={"failed_login","suspicious_login","privilege_escalation","sensitive_access","data_exfiltration","defense_evasion","normal_login","normal_activity","malware","c2_connection"}
SEVERITY_WORDS={"informational":5,"info":5,"low":20,"medium":50,"moderate":50,"high":75,"critical":95}
PHRASES={
 "failed login":"failed_login","login failed":"failed_login","authentication failure":"failed_login","brute force":"failed_login",
 "suspicious login":"suspicious_login","impossible travel":"suspicious_login","anomalous login":"suspicious_login",
 "privilege escalation":"privilege_escalation","admin privilege":"privilege_escalation",
 "sensitive access":"sensitive_access","sensitive file":"sensitive_access",
 "data exfiltration":"data_exfiltration","exfiltration":"data_exfiltration","large outbound":"data_exfiltration",
 "defense evasion":"defense_evasion","disable antivirus":"defense_evasion","disable security":"defense_evasion",
 "malware":"malware","ransomware":"malware","trojan":"malware","malicious file":"malware",
 "command and control":"c2_connection","c2":"c2_connection","outbound traffic":"c2_connection","beacon":"c2_connection",
 "normal login":"normal_login","successful login":"normal_login","benign":"normal_activity","normal activity":"normal_activity",
}
class UnsupportedAlertSchema(ValueError): pass

def _pick(a,k):
    lower={str(x).lower():x for x in a}
    for alias in ALIASES[k]:
        if alias in lower:
            real=lower[alias]; v=a[real]
            if v not in (None,""): return v,real
    return None,None

def _walk(v):
    if isinstance(v,dict):
        yield v
        for x in v.values(): yield from _walk(x)
    elif isinstance(v,list):
        for x in v: yield from _walk(x)

def _parse_time(v):
    s=str(v).strip()
    if s.endswith("Z"): s=s[:-1]+"+00:00"
    for parser in (lambda:datetime.fromisoformat(s),lambda:datetime.strptime(s,"%Y-%m-%d %H:%M:%S"),lambda:datetime.strptime(s,"%Y/%m/%d %H:%M:%S")):
        try:
            d=parser()
            return d.replace(tzinfo=ZoneInfo("Asia/Kolkata")) if d.tzinfo is None else d
        except ValueError: pass
    return None

def _sev(v):
    if v is None:return None
    if isinstance(v,str) and not v.strip().replace(".","",1).isdigit(): return SEVERITY_WORDS.get(v.lower().strip())
    try:return max(0,min(int(float(v)),100))
    except:return None

def _infer_type(a):
    v,k=_pick(a,"type")
    text=" ".join(str(x) for x in [v,a.get("title"),a.get("message"),a.get("description"),a.get("summary"),a.get("reason"),a.get("signature"),a.get("rule_name")] if x).lower()
    semantic_text=text.replace("_"," ").replace("-"," ").replace("."," ").replace("/"," ")
    semantic_text=" ".join(semantic_text.split())
    direct=str(v).strip().lower().replace(" ","_").replace("-","_") if v is not None else ""
    # Vendor event names commonly add wrappers such as *_alert, *_event, *_detected.
    stripped=direct
    for suffix in ("_notification","_detection","_detected","_warning","_alert","_event"):
        if stripped.endswith(suffix):
            stripped=stripped[:-len(suffix)]
            break
    if direct in KNOWN_TYPES:return direct,k
    if stripped in KNOWN_TYPES:return stripped,k
    for phrase,t in PHRASES.items():
        if phrase in semantic_text:return t,k or "semantic_text"
    # Unknown security events remain analyzable without pretending they are a known attack.
    security_keys={"severity","priority","risk","risk_score","source_ip","src_ip","destination_ip","dst_ip","hostname","user","username","event_id","alert_id","incident_id","rule_name","signature"}
    if any(str(x).lower() in security_keys for x in a): return "normal_activity",k or "security_context"
    return None,None

def _nearest_time(obj, root):
    v,k=_pick(obj,"timestamp")
    d=_parse_time(v) if v is not None else None
    if d:return d,k,False
    if isinstance(root,dict):
        for x in _walk(root):
            v2,k2=_pick(x,"timestamp")
            d2=_parse_time(v2) if v2 is not None else None
            if d2:return d2,k2,True
    return datetime.now(timezone.utc),None,True


def _flatten(obj, prefix="", out=None):
    out = out or {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                _flatten(value, path, out)
            else:
                out[path.lower()] = value
                out.setdefault(str(key).lower(), value)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            _flatten(value, f"{prefix}[{i}]", out)
    return out


def _deep_value(flat, *keys):
    for key in keys:
        key = key.lower()
        if key in flat and flat[key] not in (None, ""):
            return flat[key]
    for path, value in flat.items():
        for key in keys:
            if path.endswith("." + key.lower()) and value not in (None, ""):
                return value
    return None


def _enrich_nested(event, alert):
    flat = _flatten(alert)
    source_host = _deep_value(flat, "source_device.hostname", "source.hostname", "src.hostname", "hostname")
    source_ip = _deep_value(flat, "source_device.ip_address", "source_device.ip", "source.ip", "src.ip", "source_ip", "src_ip")
    source_user = _deep_value(flat, "source_device.user", "source.user", "actor.user", "username", "user")
    dest_ip = _deep_value(flat, "destination_device.ip_address", "destination_device.ip", "destination.ip", "dst.ip", "destination_ip", "dst_ip")
    dest_domain = _deep_value(flat, "destination_device.domain", "destination.domain", "dst.domain", "domain")
    if event.get("device") in (None, "unknown"): event["device"] = str(source_host) if source_host else "unknown"
    if event.get("ip") in (None, "unknown"): event["ip"] = str(source_ip) if source_ip else "unknown"
    if event.get("user") in (None, "unknown"): event["user"] = str(source_user) if source_user else "unknown"
    if event.get("resource") in (None, "Unknown"): event["resource"] = str(dest_ip or dest_domain) if (dest_ip or dest_domain) else "Unknown"

    extras = {
        "destination_ip": dest_ip,
        "destination_domain": dest_domain,
        "bytes_sent": _deep_value(flat, "exfiltration_details.bytes_sent", "network.bytes_sent", "bytes_sent", "sent_bytes"),
        "file_count": _deep_value(flat, "exfiltration_details.file_count", "file_count"),
        "protocol": _deep_value(flat, "exfiltration_details.protocol", "network.protocol", "protocol"),
        "archive_name": _deep_value(flat, "exfiltration_details.archive_name", "archive_name", "file_name"),
        "tool_used": _deep_value(flat, "exfiltration_details.tool_used", "process.name", "tool_used"),
        "anomaly_score": _deep_value(flat, "alert_metadata.anomaly_score", "anomaly_score"),
        "mitre_tactic": _deep_value(flat, "alert_metadata.mitre_tactic", "mitre.tactic", "mitre_tactic"),
        "mitre_technique": _deep_value(flat, "alert_metadata.mitre_technique", "mitre.technique", "mitre_technique"),
        "action_taken": _deep_value(flat, "alert_metadata.action_taken", "action_taken", "disposition"),
    }
    event.update({k: v for k, v in extras.items() if v not in (None, "")})
    return event

def normalize_uploaded_alert(a,index=0,root=None):
    if not isinstance(a,dict):raise UnsupportedAlertSchema("Alert is not an object")
    t,tk=_infer_type(a)
    if not t:raise UnsupportedAlertSchema("No security meaning found")
    d,timekey,inferred=_nearest_time(a,root if root is not None else a)
    canonical=d.astimezone(timezone.utc); display=canonical.astimezone(ZoneInfo("Asia/Kolkata"))
    r={"timestamp":canonical.isoformat(),"time":display.strftime("%H:%M"),"type":t}
    m={"type":tk}
    if timekey:m["timestamp"]=timekey
    for field in ("id","ip","resource","user","device","label","base_severity","source"):
        v,k=_pick(a,field)
        if v is not None:
            r[field]=_sev(v) if field=="base_severity" else str(v);m[field]=k
    if "id" not in r:
        raw=json.dumps(a,sort_keys=True,default=str).encode();r["id"]="AUTO-"+hashlib.sha1(raw).hexdigest()[:10].upper()
    r.setdefault("source","Unknown");r.setdefault("label",str(_pick(a,"label")[0] or t.replace("_"," ").title()))
    r.setdefault("user","unknown");r.setdefault("ip","unknown");r.setdefault("device","unknown");r.setdefault("resource","Unknown")
    r=_enrich_nested(r,a)
    if inferred:r["timestamp_inferred"]=True
    if tk in ("semantic_text","security_context") or t=="normal_activity" and _pick(a,"type")[0] not in ("normal_activity","normal_login"):r["type_inferred"]=True
    return r,m

def _ai_normalize(payload):
    api_key=os.getenv("GEMINI_API_KEY")
    if not api_key:return []
    try:
        from google import genai
        from google.genai import types
        client=genai.Client(api_key=api_key,http_options=types.HttpOptions(timeout=int(os.getenv("GEMINI_TIMEOUT_MS","10000"))))
        schema={"type":"object","properties":{"events":{"type":"array","items":{"type":"object","properties":{"timestamp":{"type":["string","null"]},"type":{"type":"string"},"id":{"type":["string","null"]},"source":{"type":["string","null"]},"label":{"type":["string","null"]},"user":{"type":["string","null"]},"ip":{"type":["string","null"]},"device":{"type":["string","null"]},"resource":{"type":["string","null"]},"base_severity":{"type":["integer","null"]}},"required":["type"],"additionalProperties":True}}},"required":["events"],"additionalProperties":False}
        prompt=("Normalize the supplied SECURITY telemetry into SentraPixel events. Extract actual evidence only; do not invent identities, IPs, devices, timestamps, or attack facts. Map vendor-specific event names to the closest of: "+", ".join(sorted(KNOWN_TYPES))+". If no exact attack class is supported, use normal_activity. Missing timestamp must be null. Severity is 0-100. Return every independently identifiable security event. JSON:\n"+json.dumps(payload,default=str)[:60000])
        response=client.models.generate_content(model=os.getenv("GEMINI_MODEL","gemini-2.5-flash"),contents=prompt,config=types.GenerateContentConfig(response_mime_type="application/json",response_schema=schema))
        data=json.loads(response.text or "{}")
        return data.get("events",[]) if isinstance(data,dict) else []
    except Exception:return []


def normalize_upload(payload:Any):
    if not isinstance(payload,(dict,list)):raise UnsupportedAlertSchema("Valid JSON, but it does not contain objects that can be normalized.")
    objects=list(_walk(payload))
    # Prefer leaf/event objects, avoiding report/container dictionaries when children contain events.
    candidates=[]
    for o in objects:
        child_dicts=[x for v in o.values() if isinstance(v,(dict,list)) for x in _walk(v)]
        has_event_child=any(_infer_type(x)[0] for x in child_dicts)
        if not has_event_child:candidates.append(o)
    normalized=[];feedback={};seen=set()
    for o in candidates:
        try:
            event,m=normalize_uploaded_alert(o,len(normalized),payload)
            if event["id"] in seen:continue
            seen.add(event["id"]);normalized.append(event)
            for canonical,src in m.items():
                if src:feedback[f"{src} → {canonical}"]=True
        except UnsupportedAlertSchema:pass
    if not normalized:
        for raw in _ai_normalize(payload):
            if not isinstance(raw,dict):continue
            try:
                event,m=normalize_uploaded_alert(raw,len(normalized),payload)
                if event["id"] in seen:continue
                seen.add(event["id"]);normalized.append(event)
            except UnsupportedAlertSchema:pass
        if normalized:feedback["unknown schema → Gemini structured normalization"]=True
    if not normalized:
        raise UnsupportedAlertSchema("Valid JSON, but no security-relevant alert/event objects could be identified deterministically or by the AI normalization fallback.")
    if len(normalized)>500:raise UnsupportedAlertSchema("Security alert upload must contain between 1 and 500 alerts.")
    if any(x.get("timestamp_inferred") for x in normalized):feedback["missing timestamp → ingestion time/report timestamp"]=True
    if any(x.get("type_inferred") for x in normalized):feedback["unknown event names → preserved as unclassified security activity"]=True
    return normalized,list(feedback)
