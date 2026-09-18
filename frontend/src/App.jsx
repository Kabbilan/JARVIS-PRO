import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, BrainCircuit, CheckCircle2, ChevronRight, CircleDot, Clock3, Database, Download, FileJson, FileSearch, Fingerprint, Link2, ListChecks, LoaderCircle, LockKeyhole, Network, Radar, SearchCheck, ShieldCheck, Upload, XCircle } from "lucide-react";

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

  return <div className="app-shell">\n
    <aside>
      <div className="brand"><div className="brand-mark"><ShieldCheck /></div><div><strong>SentraPixel</strong><span>Autonomous SOC Intelligence Platform</span></div></div>
      <nav aria-label="Primary navigation"><button className={view === "command" ? "active" : ""} onClick={() => setView("command")}><Radar /> Command Center</button><button className={view === "live" ? "active" : ""} onClick={() => setView("live")}><Activity /> Live Events</button><button className={view === "incidents" ? "active" : ""} onClick={openHistory}><AlertTriangle /> Incidents</button><button onClick={() => { setView("command"); window.setTimeout(() => document.querySelector(".agent-card")?.scrollIntoView({ behavior: "smooth" }), 0); }}><BrainCircuit /> AI Investigation</button></nav>
      <div className={`system-card ${apiOnline === false ? "offline" : ""}`}><span className="pulse" /> {apiOnline === null ? "CONNECTING TO ENGINE" : apiOnline === false ? "ENGINE DISCONNECTED" : "CORRELATION ENGINE ONLINE"}<small>{apiOnline === null ? "Verifying production API" : apiOnline === false ? "Backend connection unavailable" : "Rules, evidence, and analyst review active"}</small></div>
    </aside>
    <main>
      <header><div><p className="eyebrow">FC-04 / SECURITY OPERATIONS</p><h1>{view === "command" ? "Incident Correlation Command Center" : view === "live" ? "Live Security Events" : "Incident History"}</h1><p>{view === "command" ? "Correlate fragmented alerts into an evidence-backed incident." : view === "live" ? "Monitor incoming SOC telemetry and investigate suspicious activity." : "Review analyzed incidents, severity, score, and analyst decisions."}</p></div><div className="analyst"><span>KM</span><div><strong>Lead Analyst</strong><small>Human approval enabled</small></div></div></header>

      {view === "incidents" ? <IncidentHistory incidents={history} summary={historySummary} loading={historyLoading} error={historyError} onRefresh={openHistory} onBack={() => setView("command")} /> : view === "live" ? <LiveEvents onAnalyze={() => setView("command")} /> : <>
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
            <section className="card risk-breakdown-card"><CardTitle icon={<FileSearch />} label="SEVERITY EVIDENCE" title="Risk score composition" />{(() => { const additions = incident.factors.reduce((sum, factor) => sum + factor.points, 0); const base = Math.max(0, incident.score - Math.min(additions, incident.score)); const factorEvidence = { "Suspicious successful login": "Detected suspicious_login event", "Privilege escalation": "Detected privilege_escalation event", "Sensitive resource accessed": "Detected sensitive_access event", "Large outbound data transfer": "Detected data_exfiltration event", "Security control evasion": "Detected defense_evasion event" }; const highestEvent = [...incident.events].sort((x, y) => (y.base_severity || 0) - (x.base_severity || 0))[0]; const parts = [{ label: "Base alert severity", points: base, evidence: highestEvent ? `${highestEvent.id}: ${highestEvent.label} — base severity ${highestEvent.base_severity}` : "Highest-severity correlated alert" }, ...incident.factors.map((factor) => ({ label: factor.label, points: Math.min(factor.points, Math.max(0, incident.score)), evidence: factorEvidence[factor.label] || "Detected correlated security factor" }))].filter((part) => part.points > 0); const total = parts.reduce((sum, part) => sum + part.points, 0) || 1; let cursor = 0; const stops = parts.map((part, index) => { const start = cursor; cursor += (part.points / total) * 100; return `var(--risk-c${index % 6}) ${start}% ${cursor}%`; }).join(", "); return <><div className="risk-breakdown"><div className="risk-donut factor-donut" style={{ background: `conic-gradient(${stops})` }}><div className="risk-donut-center"><strong>{incident.score}</strong><span>RISK SCORE</span></div></div><div className="risk-legend">{parts.map((part, index) => <div className="risk-legend-row" key={`${part.label}-${index}`}><span className={`risk-dot factor-dot-${index % 6}`} /><span><span className="risk-factor-name">{part.label}</span><small className="risk-evidence">{part.evidence}</small></span><b>{Math.round((part.points / total) * 100)}% <small>({part.points} pts)</small></b></div>)}</div></div><div className="risk-evidence-graph"><div className="risk-graph-title">Evidence → score contribution</div>{parts.map((part, index) => <div className="risk-graph-row" key={`graph-${part.label}-${index}`}><div className="risk-graph-meta"><span>{part.label}</span><b>{Math.round((part.points / total) * 100)}%</b></div><div className="risk-graph-track"><span className={`risk-graph-fill graph-fill-${index % 6}`} style={{ width: `${Math.max(3, (part.points / total) * 100)}%` }} /></div><small>{part.evidence}</small></div>)}</div><p className="risk-explain">Pie = score composition. Bars = evidence-backed contribution of each detected factor.</p></>; })()}</section>
            <section className="card"><CardTitle icon={<Network />} label="SUSPICIOUS INDICATORS" title="Entities under investigation" /><div className="indicators">{incident.indicators.map((item) => <div key={item.type}><span>{item.type}</span><strong>{item.value}</strong><em>{item.status}</em></div>)}</div></section>
          </div>
        </div>
        <section className="card agent-card">
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
function LiveEvents({ onAnalyze }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const events = [
    { id: "EVT-2048", time: "13:08:42", severity: "critical", type: "Data Exfiltration", source: "Firewall", detail: "Large outbound transfer to an unusual destination" },
    { id: "EVT-2047", time: "13:08:17", severity: "high", type: "Privilege Escalation", source: "Identity", detail: "Administrative privilege granted after suspicious login" },
    { id: "EVT-2046", time: "13:07:54", severity: "medium", type: "Suspicious Login", source: "Identity", detail: "Authentication from an unusual location" },
    { id: "EVT-2045", time: "13:07:21", severity: "low", type: "Failed Login", source: "SIEM", detail: "Repeated password failures detected" },
    { id: "EVT-2044", time: "13:06:48", severity: "high", type: "Malware Alert", source: "Endpoint", detail: "Suspicious process execution blocked on LAP-042" }
  ];
  const filtered = events.filter((event) => {
    const text = `${event.type} ${event.source} ${event.detail} ${event.id}`.toLowerCase();
    return text.includes(query.toLowerCase()) && (severity === "all" || event.severity === severity);
  });
  return <section className="history-panel">
    <div className="history-toolbar"><div><p className="section-label">LIVE TELEMETRY</p><h2>Incoming security events</h2></div><div><span className="api-label"><CircleDot /> STREAM ACTIVE</span><button className="refresh" onClick={onAnalyze}><Radar /> Analyze events</button></div></div>
    <div className="history-metrics"><Metric label="Events visible" value={events.length} tone="blue" caption="demo stream" /><Metric label="Critical" value={events.filter(e => e.severity === "critical").length} tone="red" caption="immediate attention" /><Metric label="High risk" value={events.filter(e => e.severity === "high").length} tone="violet" caption="investigate" /><Metric label="Sources" value={new Set(events.map(e => e.source)).size} tone="green" caption="telemetry feeds" /></div>
    <div className="history-filters"><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search event, source, or ID" /><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><span>{filtered.length} events</span></div>
    {!filtered.length ? <div className="history-state compact"><SearchCheck /><strong>No matching live events</strong><span>Change or clear the current filters.</span></div> : <div className="incident-table-wrap"><table className="incident-table"><thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>Source</th><th>Details</th></tr></thead><tbody>{filtered.map((event) => <tr key={event.id}><td className="score-cell">{event.time}</td><td><strong>{event.type}</strong><small>{event.id}</small></td><td><span className={`severity-pill ${event.severity}`}>{event.severity}</span></td><td>{event.source}</td><td>{event.detail}</td></tr>)}</tbody></table></div>}
  </section>;
}

export default App;
