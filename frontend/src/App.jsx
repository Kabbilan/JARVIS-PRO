import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, BrainCircuit, CheckCircle2, ChevronRight, CircleDot, Clock3, Database, Download, FileJson, FileSearch, Fingerprint, Link2, ListChecks, LoaderCircle, LockKeyhole, Network, Radar, RefreshCw, SearchCheck, Server, ShieldCheck, Upload, Wifi, XCircle } from "lucide-react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const scenarioCatalog = [
  { id: "account-takeover", label: "Account Takeover", description: "Trace suspicious authentication, privilege escalation, and identity compromise.", icon: Fingerprint },
  { id: "data-exfiltration", label: "Data Exfiltration", description: "Investigate sensitive data access and unusual outbound transfer activity.", icon: Database },
  { id: "benign-login", label: "Benign Activity", description: "Validate normal user activity and reduce authentication alert noise.", icon: ShieldCheck },
];
const fallbackScenarios = [
  { id: "account-takeover", name: "Account Takeover", description: "Repeated login failures are followed by suspicious access and privilege escalation.", event_count: 4 },
  { id: "data-exfiltration", name: "Data Exfiltration", description: "Sensitive data is collected and transferred to an unusual external destination.", event_count: 4 },
  { id: "benign-login", name: "Benign Authentication Noise", description: "Legitimate password mistakes followed by normal activity.", event_count: 3 },
];
const loadingStages = ["Normalizing telemetry", "Linking shared entities", "Calculating severity", "Building incident story"];
const sampleAlerts = JSON.stringify([
  { id: "SIEM-001", time: "09:00", source: "Identity", type: "failed_login", label: "12 failed login attempts", user: "analyst@company.com", ip: "198.51.100.24", device: "LAP-042", base_severity: 20 },
  { id: "SIEM-002", time: "09:04", source: "Identity", type: "suspicious_login", label: "Successful login from unusual location", user: "analyst@company.com", ip: "198.51.100.24", device: "LAP-042", base_severity: 45 },
  { id: "SIEM-003", time: "09:09", source: "Firewall", type: "data_exfiltration", label: "Large outbound transfer detected", user: "analyst@company.com", ip: "198.51.100.24", device: "LAP-042", base_severity: 88 }
], null, 2);


const demoEventTemplates = [
  { severity: "critical", type: "credential_access", source: "Identity", title: "Impossible travel sign-in accepted", description: "A successful sign-in followed repeated failures from a new location.", user: "analyst@company.com", ip: "198.51.100.24", device: "LAP-042" },
  { severity: "high", type: "data_exfiltration", source: "DLP", title: "Large outbound transfer detected", description: "Sensitive archive volume exceeded the normal user baseline.", user: "analyst@company.com", ip: "198.51.100.24", device: "LAP-042" },
  { severity: "high", type: "privilege_escalation", source: "EDR", title: "Suspicious privilege escalation", description: "A user process attempted to gain elevated local privileges.", user: "analyst@company.com", ip: "10.20.4.18", device: "LAP-042" },
  { severity: "medium", type: "malware_behavior", source: "Endpoint", title: "Encoded PowerShell activity", description: "Endpoint telemetry observed an encoded PowerShell command chain.", user: "svc-reports", ip: "10.20.8.31", device: "FIN-WS-19" },
  { severity: "medium", type: "network_anomaly", source: "Firewall", title: "Unusual outbound destination", description: "A workstation contacted an external destination not seen in the recent baseline.", user: "jlee", ip: "10.20.14.12", device: "OPS-WS-07" },
  { severity: "low", type: "authentication", source: "Identity", title: "Repeated password failures", description: "Multiple failed sign-ins were observed before a normal authentication.", user: "maria@company.com", ip: "203.0.113.44", device: "HR-LAP-08" },
  { severity: "low", type: "email_security", source: "Email Gateway", title: "Suspicious attachment quarantined", description: "The gateway quarantined an attachment before delivery.", user: "finance@company.com", ip: "192.0.2.61", device: "MAIL-GW-02" },
];

function normalizeSeverity(value) {
  if (typeof value === "number") {
    if (value >= 80) return "critical";
    if (value >= 60) return "high";
    if (value >= 35) return "medium";
    return "low";
  }
  const severity = String(value || "low").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(severity)) return severity;
  if (severity === "warning" || severity === "warn") return "medium";
  return "low";
}

function normalizeEventTimestamp(value, index = 0) {
  if (typeof value === "string" && /^\d{2}:\d{2}(:\d{2})?$/.test(value)) {
    const [hours, minutes, seconds = "0"] = value.split(":").map(Number);
    const date = new Date();
    date.setHours(hours, minutes, seconds, 0);
    return date.toISOString();
  }
  const parsed = value ? new Date(value) : new Date(Date.now() - index * 1000);
  return Number.isNaN(parsed.getTime()) ? new Date(Date.now() - index * 1000).toISOString() : parsed.toISOString();
}

function normalizeLiveEvent(item, index = 0) {
  const timestamp = normalizeEventTimestamp(item.timestamp || item.created_at || item.time, index);
  const severity = normalizeSeverity(item.severity ?? item.base_severity ?? item.score ?? item.risk_score);
  return {
    id: String(item.id || item.event_id || item.alert_id || `EVT-${Date.parse(timestamp) || Date.now()}-${index}`),
    timestamp,
    sortTime: Date.parse(timestamp) || Date.now() - index,
    severity,
    type: String(item.type || item.alert_type || item.event_type || item.stage || "security_alert"),
    source: String(item.source || item.product || item.vendor || item.sensor || "SOC Sensor"),
    title: String(item.title || item.label || item.message || item.description || "Security event detected"),
    description: String(item.description || item.details || item.message || item.label || "No additional event description was supplied."),
    user: item.user || item.username || item.account || "",
    ip: item.ip || item.source_ip || item.src_ip || "",
    device: item.device || item.hostname || item.host || "",
    raw: item,
  };
}

function createDemoEvent(templateIndex = 0, offsetSeconds = 0) {
  const template = demoEventTemplates[templateIndex % demoEventTemplates.length];
  const timestamp = new Date(Date.now() - offsetSeconds * 1000).toISOString();
  return normalizeLiveEvent({
    ...template,
    id: `DEMO-${Date.parse(timestamp)}-${templateIndex}`,
    timestamp,
  });
}

function createDemoSeedEvents() {
  const offsets = [0, 18, 43, 76, 118, 164, 225];
  return offsets.map((offset, index) => createDemoEvent(index, offset));
}

function createDemoIncomingEvent() {
  const slot = Math.floor(Date.now() / 4500) % demoEventTemplates.length;
  return createDemoEvent(slot, 0);
}

function formatEventType(value) {
  return String(value || "security alert").replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatEventTimestamp(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value || "-") : date.toLocaleString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", day: "2-digit", month: "short" });
}

function App() {
  const [scenarios, setScenarios] = useState(fallbackScenarios);
  const [selected, setSelected] = useState("account-takeover");
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingStage, setLoadingStage] = useState(0);
  const [review, setReview] = useState(null);
  const [reviewing, setReviewing] = useState("");
  const [investigation, setInvestigation] = useState(null);
  const [investigating, setInvestigating] = useState(false);
  const [investigationError, setInvestigationError] = useState("");
  const [reporting, setReporting] = useState(false);
  const [reportError, setReportError] = useState("");
  const [error, setError] = useState("");
  const [apiOnline, setApiOnline] = useState(null);
  const [inputMode, setInputMode] = useState("scenario");
  const [alertText, setAlertText] = useState(sampleAlerts);
  const [currentAlerts, setCurrentAlerts] = useState(null);
  const [view, setView] = useState("command");
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [historySummary, setHistorySummary] = useState({ total: 0, critical: 0, approved: 0, pending: 0, noise_reduction_percent: 0 });
  const [liveEvents, setLiveEvents] = useState([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState("");
  const [streamMode, setStreamMode] = useState("connecting");

  useEffect(() => {
    fetch(`${API}/api/scenarios`).then((response) => {
      if (!response.ok) throw new Error();
      setApiOnline(true);
      return response.json();
    }).then(setScenarios).catch(() => setApiOnline(false));
  }, []);

  useEffect(() => {
    if (!loading) return undefined;
    setLoadingStage(0);
    const timer = window.setInterval(() => setLoadingStage((current) => Math.min(current + 1, loadingStages.length - 1)), 650);
    return () => window.clearInterval(timer);
  }, [loading]);

  useEffect(() => {
    if (view !== "events") return undefined;
    loadLiveEvents({ silent: liveEvents.length > 0 });
    const pollTimer = window.setInterval(() => loadLiveEvents({ silent: true }), 12000);
    const simulationTimer = streamMode === "demo" ? window.setInterval(() => {
      setLiveEvents((current) => [createDemoIncomingEvent(), ...current].slice(0, 80));
    }, 4500) : null;
    return () => {
      window.clearInterval(pollTimer);
      if (simulationTimer) window.clearInterval(simulationTimer);
    };
  }, [view, streamMode]);

  const selectedMeta = useMemo(() => scenarios.find((scenario) => scenario.id === selected), [scenarios, selected]);
  const availableScenarioIds = new Set(scenarios.map((scenario) => scenario.id));

  function chooseScenario(id) {
    setInputMode("scenario");
    setSelected(id);
    setIncident(null);
    setCurrentAlerts(null);
    setInvestigation(null);
    setInvestigationError("");
    setReview(null);
    setReportError("");
    setError("");
  }

  function switchInputMode(mode) {
    setInputMode(mode);
    setIncident(null);
    setCurrentAlerts(null);
    setInvestigation(null);
    setInvestigationError("");
    setReview(null);
    setReportError("");
    setError("");
  }

  async function loadLiveEvents({ silent = false } = {}) {
    if (!silent) setEventsLoading(true);
    try {
      const response = await fetch(`${API}/api/events`, { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error("events-endpoint-unavailable");
      const payload = await response.json();
      const rawEvents = Array.isArray(payload) ? payload : payload.events ?? payload.alerts ?? payload.data;
      if (!Array.isArray(rawEvents)) throw new Error("invalid-events-payload");
      const normalized = rawEvents.map(normalizeLiveEvent).sort((a, b) => b.sortTime - a.sortTime);
      setLiveEvents(normalized);
      setEventsError("");
      setStreamMode("live");
      setApiOnline(true);
    } catch {
      setStreamMode("demo");
      setEventsError("Live events endpoint is unavailable. Demo stream is active and will switch to the backend automatically when /api/events becomes available.");
      setLiveEvents((current) => current.length ? current : createDemoSeedEvents());
    } finally {
      if (!silent) setEventsLoading(false);
    }
  }

  function openLiveEvents() {
    setView("events");
  }

  function openInvestigation() {
    setView("command");
    window.setTimeout(() => document.getElementById("investigation-agent")?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  }

  async function runAnalysis() {
    if (inputMode === "scenario" && !availableScenarioIds.has(selected)) {
      setError("Data Exfiltration scenario is waiting for the backend API. Add scenario ID: data-exfiltration.");
      return;
    }
    setLoading(true); setReview(null); setError("");
    try {
      let alerts = null;
      if (inputMode === "custom") {
        const parsed = JSON.parse(alertText);
        alerts = Array.isArray(parsed) ? parsed : parsed.alerts;
        if (!Array.isArray(alerts) || !alerts.length) throw new Error("invalid-alerts");
      }
      const response = await fetch(inputMode === "custom" ? `${API}/api/analyze-alerts` : `${API}/api/analyze/${selected}`, {
        method: "POST",
        headers: inputMode === "custom" ? { "Content-Type": "application/json" } : undefined,
        body: inputMode === "custom" ? JSON.stringify({ alerts }) : undefined,
      });
      if (!response.ok) throw new Error();
      setIncident(await response.json()); setApiOnline(true);
      setCurrentAlerts(alerts);
      runInvestigation(alerts);
    } catch (analysisError) {
      if (analysisError.message === "invalid-alerts" || analysisError instanceof SyntaxError) setError("Invalid JSON. Provide a non-empty alert array or an object with an alerts array.");
      else { setError("Correlation engine unavailable. Confirm the FastAPI service is running on port 8000."); setApiOnline(false); }
    } finally { setLoading(false); }
  }

  async function runInvestigation(alerts = currentAlerts) {
    setInvestigating(true); setInvestigation(null); setInvestigationError("");
    try {
      const custom = Array.isArray(alerts);
      const response = await fetch(custom ? `${API}/api/investigate-alerts` : `${API}/api/investigate/${selected}`, {
        method: "POST",
        headers: custom ? { "Content-Type": "application/json" } : undefined,
        body: custom ? JSON.stringify({ alerts }) : undefined,
      });
      if (!response.ok) throw new Error();
      const result = await response.json();
      setInvestigation(result.investigation);
    } catch {
      setInvestigationError("Investigation Agent response unavailable. The correlated incident remains available below.");
    } finally { setInvestigating(false); }
  }

  async function submitReview(decision) {
    setReviewing(decision); setError("");
    try {
      const response = await fetch(`${API}/api/review`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ incident_id: incident.incident_id, decision }) });
      if (!response.ok) throw new Error();
      setReview(await response.json());
    } catch { setError("Review action could not be saved. Check the backend connection and try again."); }
    finally { setReviewing(""); }
  }

  async function openHistory() {
    setView("incidents"); setHistoryLoading(true); setHistoryError("");
    try {
      const response = await fetch(`${API}/api/incidents`);
      if (!response.ok) throw new Error();
      const result = await response.json();
      setHistory(result.incidents || []); setHistorySummary(result.summary || {}); setApiOnline(true);
    } catch {
      setHistoryError("Incident history is unavailable. Check the backend connection."); setApiOnline(false);
    } finally { setHistoryLoading(false); }
  }

  async function downloadReport() {
    setReporting(true); setReportError("");
    try {
      const custom = Array.isArray(currentAlerts);
      const response = await fetch(custom ? `${API}/api/report-alerts` : `${API}/api/report/${selected}`, {
        method: custom ? "POST" : "GET",
        headers: custom ? { "Content-Type": "application/json" } : undefined,
        body: custom ? JSON.stringify({ alerts: currentAlerts }) : undefined,
      });
      if (!response.ok) throw new Error();
      const url = window.URL.createObjectURL(await response.blob());
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `SentraPixel-${incident.incident_id}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      setReportError("Incident report could not be generated. Check the backend connection and retry.");
    } finally { setReporting(false); }
  }

  return <div className="app-shell">
    <aside>
      <div className="brand"><div className="brand-mark"><ShieldCheck /></div><div><strong>SentraPixel</strong><span>Autonomous SOC Intelligence Platform</span></div></div>
      <nav aria-label="Primary navigation"><button className={view === "command" ? "active" : ""} onClick={() => setView("command")}><Radar /> Command Center</button><button className={view === "events" ? "active" : ""} onClick={openLiveEvents}><Activity /> Live Events</button><button className={view === "incidents" ? "active" : ""} onClick={openHistory}><AlertTriangle /> Incidents</button><button onClick={openInvestigation}><BrainCircuit /> AI Investigation</button></nav>
      <div className={`system-card ${apiOnline === false ? "offline" : ""}`}><span className="pulse" /> {apiOnline === null ? "CONNECTING TO ENGINE" : apiOnline === false ? "ENGINE DISCONNECTED" : "CORRELATION ENGINE ONLINE"}<small>{apiOnline === null ? "Verifying production API" : apiOnline === false ? "Backend connection unavailable" : "Rules, evidence, and analyst review active"}</small></div>
    </aside>
    <main>
      <header><div><p className="eyebrow">FC-04 / SECURITY OPERATIONS</p><h1>{view === "command" ? "Incident Correlation Command Center" : view === "events" ? "Live Security Events" : "Incident History"}</h1><p>{view === "command" ? "Correlate fragmented alerts into an evidence-backed incident." : view === "events" ? "Monitor incoming SOC alerts, triage severity, and inspect event evidence in real time." : "Review analyzed incidents, severity, score, and analyst decisions."}</p></div><div className="analyst"><span>KM</span><div><strong>Lead Analyst</strong><small>Human approval enabled</small></div></div></header>

      {view === "incidents" ? <IncidentHistory incidents={history} summary={historySummary} loading={historyLoading} error={historyError} onRefresh={openHistory} onBack={() => setView("command")} /> : view === "events" ? <LiveEvents events={liveEvents} loading={eventsLoading} error={eventsError} mode={streamMode} onRefresh={() => loadLiveEvents()} onBack={() => setView("command")} /> : <>
      <section className="scenario-panel">
        <div className="panel-heading"><div><p className="section-label">INVESTIGATION INPUT</p><h2>{inputMode === "scenario" ? "Choose an investigation scenario" : "Analyze your own security alerts"}</h2></div><span className="api-label"><CircleDot /> Live API</span></div>
        <div className="input-tabs"><button className={inputMode === "scenario" ? "active" : ""} onClick={() => switchInputMode("scenario")}><Radar /> Demo scenarios</button><button className={inputMode === "custom" ? "active" : ""} onClick={() => switchInputMode("custom")}><FileJson /> JSON alerts</button></div>
        {inputMode === "scenario" ? <div className="scenario-grid">{scenarioCatalog.map(({ id, label, description, icon: Icon }) => {
          const ready = availableScenarioIds.has(id);
          return <button key={id} className={`scenario-option ${selected === id ? "selected" : ""}`} onClick={() => chooseScenario(id)}><span className="scenario-icon"><Icon /></span><span className="scenario-copy"><strong>{label}</strong><small>{description}</small></span><span className={`availability ${ready ? "ready" : "pending"}`}>{ready ? "READY" : "API PENDING"}</span></button>;
        })}</div> : <div className="custom-alerts"><div className="upload-row"><label className="file-button"><Upload /> Upload JSON<input type="file" accept=".json,application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) file.text().then(setAlertText).catch(() => setError("The selected file could not be read.")); event.target.value = ""; }} /></label><button onClick={() => setAlertText(sampleAlerts)}>Load sample</button><span>1–500 alerts · HH:MM time required</span></div><textarea value={alertText} onChange={(event) => setAlertText(event.target.value)} spellCheck="false" aria-label="Security alerts JSON" /></div>}
        <div className="scenario-footer"><p>{inputMode === "scenario" ? selectedMeta?.description || scenarioCatalog.find((item) => item.id === selected)?.description : "Paste or upload normalized SIEM alerts. SentraPixel will correlate shared identity, device, IP, and time evidence."}</p><button className="primary" onClick={runAnalysis} disabled={loading}>{loading ? <><LoaderCircle className="button-spinner" /> ANALYZING</> : <>{inputMode === "custom" ? "ANALYZE ALERTS" : "ANALYZE SCENARIO"} <ChevronRight /></>}</button></div>
        {error && <div className="error" role="alert"><XCircle />{error}</div>}
      </section>

      {!incident && !loading && <section className="empty-state"><div className="scanner"><Radar /></div><p>Telemetry ready</p><span>Choose a scenario to reconstruct its attack chain and evidence.</span></section>}
      {loading && <section className="analysis-loader"><div className="loader-visual"><span className="orbit one" /><span className="orbit two" /><BrainCircuit /></div><div><p className="section-label">CORRELATION IN PROGRESS</p><h2>{loadingStages[loadingStage]}</h2><span>SentraPixel is connecting identity, device, IP, and event evidence.</span></div><div className="stage-track">{loadingStages.map((stage, index) => <span key={stage} className={index <= loadingStage ? "complete" : ""} />)}</div></section>}

      {incident && <>
        <section className="metrics"><Metric label="Raw alerts" value={incident.metrics.raw_alerts} tone="blue" /><Metric label="Correlated" value={incident.metrics.correlated_alerts} tone="violet" /><Metric label="Incidents" value={incident.metrics.incidents} tone="red" /><Metric label="Noise reduced" value={incident.metrics.noise_reduced} tone="green" /></section>
        <section className={`incident-hero ${incident.severity}`}><div><div className="incident-meta"><span>{incident.incident_id}</span><span>{incident.status.replace("_", " ")}</span></div><h2>{incident.title}</h2><p>{incident.summary}</p></div><div className="risk-orb"><strong>{incident.score}</strong><span>RISK SCORE</span><em>{incident.severity}</em></div></section>
        <div className="content-grid">
          <section className="card attack-card"><CardTitle icon={<Clock3 />} label="ATTACK TIMELINE" title="Evidence-linked event sequence" /><div className="chain">{incident.events.map((event, index) => <div className="chain-row" key={event.id}><div className="time">{event.time}</div><div className={`node ${index === incident.events.length - 1 ? "last" : ""}`}><span>{index + 1}</span></div><div className="event"><div><b>{event.stage}</b><small>{event.id} · {event.source}</small></div><p>{event.label}</p><EvidenceLink links={incident.links} eventId={event.id} /></div></div>)}</div></section>
          <div className="right-column">
            <section className="card"><CardTitle icon={<BrainCircuit />} label="INVESTIGATION SUMMARY" title="Evidence-grounded narrative" /><p className="narrative">{incident.summary}</p><div className="grounded"><CheckCircle2 /> Generated from correlated telemetry only</div></section>
            <section className="card"><CardTitle icon={<FileSearch />} label="SEVERITY EVIDENCE" title="Risk score breakdown" /><div className="score-bar"><span style={{ width: `${incident.score}%` }} /></div><div className="factor-list">{incident.factors.length ? incident.factors.map((factor) => <div key={factor.label}><span>{factor.label}</span><b>+{factor.points}</b></div>) : <p>No critical escalation factors found.</p>}</div></section>
            <section className="card"><CardTitle icon={<Network />} label="SUSPICIOUS INDICATORS" title="Entities under investigation" /><div className="indicators">{incident.indicators.map((item) => <div key={item.type}><span>{item.type}</span><strong>{item.value}</strong><em>{item.status}</em></div>)}</div></section>
          </div>
        </div>
        <section className="card agent-card" id="investigation-agent">
          <CardTitle icon={<BrainCircuit />} label="GEMINI INVESTIGATION AGENT" title="AI-assisted incident investigation" />
          {investigating && <div className="agent-loading"><LoaderCircle className="button-spinner" /><div><strong>Investigating correlated evidence</strong><span>Building a grounded narrative and analyst next steps.</span></div></div>}
          {investigationError && <div className="agent-error"><AlertTriangle />{investigationError}<button onClick={() => runInvestigation()}>Retry</button></div>}
          {investigation && <div className="agent-grid">
            <div className="agent-narrative"><p className="agent-label"><BrainCircuit /> NARRATIVE</p><p>{investigation.narrative}</p><span className="provider-badge">{investigation.provider === "gemini" ? "GEMINI GENERATED" : "DETERMINISTIC FALLBACK"}</span></div>
            <div className="agent-list"><p className="agent-label"><SearchCheck /> CORRELATED EVIDENCE</p><ol>{investigation.evidence.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol></div>
            <div className="agent-list"><p className="agent-label"><ListChecks /> NEXT STEPS</p><ol>{investigation.next_steps.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol></div>
          </div>}
        </section>
        <section className="card response-card"><div className="response-heading"><CardTitle icon={<LockKeyhole />} label="HUMAN-IN-THE-LOOP" title="Recommended containment plan" /><button className="report-button" onClick={downloadReport} disabled={reporting}>{reporting ? <LoaderCircle className="button-spinner" /> : <Download />}{reporting ? "Generating report" : "Download incident report"}</button></div><div className="actions">{incident.recommended_actions.map((action, index) => <div key={action}><span>{String(index + 1).padStart(2, "0")}</span>{action}</div>)}</div>{reportError && <div className="error" role="alert"><XCircle />{reportError}</div>}{!review ? <div className="review-buttons"><button className="reject" onClick={() => submitReview("rejected")} disabled={Boolean(reviewing)}>{reviewing === "rejected" ? <LoaderCircle className="button-spinner" /> : <XCircle />} Reject plan</button><button className="approve" onClick={() => submitReview("approved")} disabled={Boolean(reviewing)}>{reviewing === "approved" ? <LoaderCircle className="button-spinner" /> : <CheckCircle2 />} Approve simulated response</button></div> : <div className={`review-result ${review.decision}`}>{review.decision === "approved" ? <CheckCircle2 /> : <XCircle />}{review.message}</div>}</section>
      </>}
      </>}
    </main>
  </div>;
}

function Metric({ label, value, tone, caption = "current scenario" }) { return <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong><small>{caption}</small></div>; }
function CardTitle({ icon, label, title }) { return <div className="card-title"><span>{icon}</span><div><p className="section-label">{label}</p><h3>{title}</h3></div></div>; }
function EvidenceLink({ links, eventId }) {
  const link = links.find((item) => item.to === eventId);
  return link ? <em><Link2 size={12}/>{link.reason}</em> : null;
}

function LiveEvents({ events, loading, error, mode, onRefresh, onBack }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const [selectedId, setSelectedId] = useState("");

  const sources = useMemo(() => [...new Set(events.map((event) => event.source).filter(Boolean))].sort(), [events]);
  const filtered = useMemo(() => [...events]
    .sort((a, b) => b.sortTime - a.sortTime)
    .filter((event) => {
      const searchable = `${event.id} ${event.title} ${event.type} ${event.source} ${event.user} ${event.ip} ${event.device}`.toLowerCase();
      const matchesQuery = searchable.includes(query.trim().toLowerCase());
      const matchesSeverity = severity === "all" || event.severity === severity;
      const matchesSource = source === "all" || event.source === source;
      return matchesQuery && matchesSeverity && matchesSource;
    }), [events, query, severity, source]);

  const selectedEvent = events.find((event) => event.id === selectedId) || null;
  const criticalCount = events.filter((event) => event.severity === "critical").length;
  const elevatedCount = events.filter((event) => ["critical", "high"].includes(event.severity)).length;

  return <section className="live-events-panel">
    <div className="live-events-heading">
      <div><p className="section-label">REAL-TIME TELEMETRY</p><h2>Security event stream</h2><span>Newest alerts stay at the top. Select any event to inspect its full context.</span></div>
      <div className="stream-actions">
        <span className={`stream-badge ${mode}`}>{mode === "live" ? <Wifi /> : mode === "demo" ? <Activity /> : <LoaderCircle className="button-spinner" />}{mode === "live" ? "LIVE API" : mode === "demo" ? "DEMO STREAM" : "CONNECTING"}</span>
        <button onClick={onRefresh} disabled={loading}>{loading ? <LoaderCircle className="button-spinner" /> : <RefreshCw />} Refresh</button>
        <button onClick={onBack}>Command Center</button>
      </div>
    </div>

    {error && <div className="stream-notice" role="status"><AlertTriangle /><div><strong>Live source not connected</strong><span>{error}</span></div></div>}

    {!loading && events.length > 0 && <div className="live-metrics">
      <Metric label="Events in stream" value={events.length} tone="blue" caption="latest buffer" />
      <Metric label="Critical" value={criticalCount} tone="red" caption="highest priority" />
      <Metric label="High + critical" value={elevatedCount} tone="violet" caption="needs triage" />
      <Metric label="Sources" value={sources.length} tone="green" caption="reporting sensors" />
    </div>}

    <div className="live-filterbar">
      <label className="event-search"><SearchCheck /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search ID, type, source, user, IP..." /></label>
      <select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Filter by severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
      <select value={source} onChange={(event) => setSource(event.target.value)} aria-label="Filter by source"><option value="all">All sources</option>{sources.map((item) => <option key={item} value={item}>{item}</option>)}</select>
      <span>{filtered.length} shown</span>
    </div>

    {loading && !events.length ? <div className="live-state"><LoaderCircle className="button-spinner" /><strong>Connecting to event stream</strong><span>Checking the backend for incoming SOC telemetry.</span></div>
      : !events.length ? <div className="live-state"><Server /><strong>No events received yet</strong><span>The live endpoint is connected but the event stream is currently empty.</span></div>
      : !filtered.length ? <div className="live-state compact"><SearchCheck /><strong>No matching events</strong><span>Change the search text or filters to show more alerts.</span></div>
      : <div className={`live-events-layout ${selectedEvent ? "has-selection" : ""}`}>
        <div className="live-event-list" role="list" aria-label="Security events">
          {filtered.map((event) => <button key={event.id} type="button" role="listitem" className={`live-event-row ${selectedId === event.id ? "selected" : ""}`} onClick={() => setSelectedId(event.id)}>
            <span className={`event-severity-dot ${event.severity}`} />
            <span className="live-event-copy">
              <span className="event-topline"><span className={`severity-pill ${event.severity}`}>{event.severity}</span><strong>{event.title}</strong></span>
              <span className="event-meta"><span>{formatEventType(event.type)}</span><span>{event.source}</span><span>{formatEventTimestamp(event.timestamp)}</span></span>
            </span>
            <ChevronRight className="event-chevron" />
          </button>)}
        </div>

        <div className={`event-detail-card ${selectedEvent ? "open" : ""}`}>
          {selectedEvent ? <>
            <div className="event-detail-heading"><div><p className="section-label">EVENT DETAILS</p><h3>{selectedEvent.title}</h3></div><span className={`severity-pill ${selectedEvent.severity}`}>{selectedEvent.severity}</span></div>
            <div className="event-detail-grid">
              <div><span>Event ID</span><strong>{selectedEvent.id}</strong></div>
              <div><span>Timestamp</span><strong>{formatEventTimestamp(selectedEvent.timestamp)}</strong></div>
              <div><span>Alert type</span><strong>{formatEventType(selectedEvent.type)}</strong></div>
              <div><span>Source</span><strong>{selectedEvent.source}</strong></div>
              <div><span>User</span><strong>{selectedEvent.user || "Not supplied"}</strong></div>
              <div><span>Source IP</span><strong>{selectedEvent.ip || "Not supplied"}</strong></div>
              <div><span>Device</span><strong>{selectedEvent.device || "Not supplied"}</strong></div>
            </div>
            <div className="event-description"><span>Evidence summary</span><p>{selectedEvent.description}</p></div>
            <details className="raw-event"><summary>Raw event payload</summary><pre>{JSON.stringify(selectedEvent.raw, null, 2)}</pre></details>
          </> : <div className="event-detail-empty"><Activity /><strong>Select an event</strong><span>Click any alert in the stream to inspect its source, timestamp, entities, and raw payload.</span></div>}
        </div>
      </div>}
  </section>;
}

function IncidentHistory({ incidents, summary, loading, error, onRefresh, onBack }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const filtered = useMemo(() => incidents.filter((item) => {
    const matchesQuery = `${item.title} ${item.incident_id}`.toLowerCase().includes(query.toLowerCase());
    const matchesSeverity = severity === "all" || item.severity === severity;
    const matchesStatus = status === "all" || item.status === status;
    return matchesQuery && matchesSeverity && matchesStatus;
  }), [incidents, query, severity, status]);
  return <section className="history-panel">
    <div className="history-toolbar"><div><p className="section-label">CASE RECORDS</p><h2>Analyzed incidents</h2></div><div><button onClick={onBack}>New analysis</button><button className="refresh" onClick={onRefresh} disabled={loading}>{loading ? <LoaderCircle className="button-spinner" /> : <Activity />} Refresh</button></div></div>
    {error && <div className="error" role="alert"><XCircle />{error}</div>}
    {!loading && incidents.length > 0 && <><div className="history-metrics"><Metric label="Total cases" value={summary.total ?? incidents.length} tone="blue" caption="all recorded" /><Metric label="Critical" value={summary.critical ?? 0} tone="red" caption="needs attention" /><Metric label="Approved" value={summary.approved ?? 0} tone="green" caption="analyst reviewed" /><Metric label="Noise reduced" value={`${summary.noise_reduction_percent ?? 0}%`} tone="violet" caption="across alerts" /></div><div className="history-filters"><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search incident or ID" /><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">All statuses</option><option value="awaiting_review">Awaiting review</option><option value="approved">Approved</option><option value="rejected">Rejected</option></select><span>{filtered.length} of {incidents.length} cases</span></div></>}
    {loading ? <div className="history-state"><LoaderCircle className="button-spinner" /><span>Loading incident history</span></div> : !incidents.length ? <div className="history-state"><FileSearch /><strong>No incidents recorded yet</strong><span>Run a demo scenario or upload security alerts to create the first incident.</span><button onClick={onBack}>Open Command Center</button></div> : !filtered.length ? <div className="history-state compact"><SearchCheck /><strong>No matching incidents</strong><span>Change or clear the current filters.</span></div> : <div className="incident-table-wrap"><table className="incident-table"><thead><tr><th>Incident</th><th>Severity</th><th>Score</th><th>Alerts</th><th>Status</th><th>Created</th></tr></thead><tbody>{filtered.map((item) => <tr key={item.incident_id}><td><strong>{item.title}</strong><small>{item.incident_id}</small></td><td><span className={`severity-pill ${item.severity}`}>{item.severity}</span></td><td className="score-cell">{item.score}</td><td>{item.metrics?.raw_alerts ?? "-"}</td><td><span className={`status-pill ${item.status}`}>{String(item.status || "open").replace("_", " ")}</span></td><td>{item.created_at ? new Date(item.created_at).toLocaleString() : "Current session"}</td></tr>)}</tbody></table></div>}
  </section>;
}
export default App;
