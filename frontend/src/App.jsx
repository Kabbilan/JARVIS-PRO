import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, ArrowLeft, BrainCircuit, CheckCircle2, ChevronRight, CircleDot, Clock3, Database, Download, FileJson, FileSearch, Fingerprint, Link2, ListChecks, LoaderCircle, LockKeyhole, Network, Radar, SearchCheck, ShieldCheck, Upload, XCircle } from "lucide-react";

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
  const [batch, setBatch] = useState(null);
  const [analysisReturnView, setAnalysisReturnView] = useState("command");
  const [loading, setLoading] = useState(false);
  const [loadingStage, setLoadingStage] = useState(0);
  const [review, setReview] = useState(null);
  const [reviewing, setReviewing] = useState("");
  const [safetyGate, setSafetyGate] = useState(false);
  const [containmentAction, setContainmentAction] = useState("monitor");
  const [reviewReason, setReviewReason] = useState("");
  const [impactAcknowledged, setImpactAcknowledged] = useState(false);
  const [investigation, setInvestigation] = useState(null);
  const [investigating, setInvestigating] = useState(false);
  const [investigationError, setInvestigationError] = useState("");
  const [responsePlan, setResponsePlan] = useState(null);
  const [verification, setVerification] = useState(null);
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
  const [reopenedIncident, setReopenedIncident] = useState(false);

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
    setBatch(null);
    setCurrentAlerts(null);
    setInvestigation(null);
    setResponsePlan(null); setVerification(null);
    setInvestigationError("");
    setReview(null);
    setReportError("");
    setError("");
  }

  function switchInputMode(mode) {
    setInputMode(mode);
    setIncident(null);
    setBatch(null);
    setCurrentAlerts(null);
    setInvestigation(null);
    setResponsePlan(null); setVerification(null);
    setInvestigationError("");
    setReview(null);
    setReportError("");
    setError("");
  }

  function openCommandCenter() {
    setView("command");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function openAnalysis() {
    if (!incident && !loading) {
      openCommandCenter();
      return;
    }
    setView("analysis");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function runAnalysis() {
    if (inputMode === "scenario" && !availableScenarioIds.has(selected)) {
      setError("Data Exfiltration scenario is waiting for the backend API. Add scenario ID: data-exfiltration.");
      return;
    }
    setLoading(true); setIncident(null); setBatch(null); setInvestigation(null); setResponsePlan(null); setVerification(null); setReview(null); setError(""); setReopenedIncident(false); setView("analysis");
    window.scrollTo({ top: 0, behavior: "smooth" });
    try {
      let alerts = null;
      if (inputMode === "custom") {
        const parsed = JSON.parse(alertText);
        alerts = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.alerts) ? parsed.alerts : parsed && typeof parsed === "object" ? [parsed] : null;
        if (!Array.isArray(alerts) || !alerts.length) throw new Error("invalid-alerts");
      }
      const response = await fetch(inputMode === "custom" ? `${API}/api/analyze-alerts` : `${API}/api/analyze/${selected}`, {
        method: "POST",
        headers: inputMode === "custom" ? { "Content-Type": "application/json" } : undefined,
        body: inputMode === "custom" ? JSON.stringify(alerts.length === 1 ? alerts[0] : { alerts }) : undefined,
      });
      if (!response.ok) {
        const failure = await response.json().catch(() => ({}));
        throw new Error(failure.detail || "request-failed");
      }
      const result = await response.json();
      setApiOnline(true);
      setCurrentAlerts(alerts);
      if (inputMode === "custom") {
        setBatch(result);
        setView("batch");
      } else {
        setIncident(result);
        runInvestigation(null);
      }
    } catch (analysisError) {
      if (analysisError instanceof SyntaxError) setError("Invalid JSON. Check the JSON syntax and retry.");
      else if (analysisError.message === "invalid-alerts") setError("Valid JSON, but no security alerts were found.");
      else if (analysisError.message && analysisError.message !== "request-failed") setError(analysisError.message);
      else { setError("Correlation engine unavailable. Confirm the FastAPI service is running."); setApiOnline(false); }
      setView("command");
    } finally { setLoading(false); }
  }

  async function runInvestigation(alerts = currentAlerts) {
    setInvestigating(true); setInvestigation(null); setResponsePlan(null); setVerification(null); setInvestigationError("");
    try {
      const custom = Array.isArray(alerts);
      const response = await fetch(custom ? `${API}/api/investigate-alerts` : `${API}/api/investigate/${selected}`, {
        method: "POST",
        headers: custom ? { "Content-Type": "application/json" } : undefined,
        body: custom ? JSON.stringify({ alerts }) : undefined,
      });
      if (!response.ok) throw new Error();
      const result = await response.json();
      setInvestigation(result.investigation); setResponsePlan(result.response_plan); setVerification(result.verification);
    } catch {
      setInvestigationError("Investigation Agent response unavailable. The correlated incident remains available below.");
    } finally { setInvestigating(false); }
  }

  async function runIncidentInvestigation(incidentId) {
    setInvestigating(true); setInvestigationError("");
    try {
      const response = await fetch(`${API}/api/incidents/${incidentId}/investigate`, { method: "POST" });
      if (!response.ok) throw new Error();
      const result = await response.json();
      setInvestigation(result.investigation); setResponsePlan(result.response_plan); setVerification(result.verification);
    } catch {
      setInvestigationError("Investigation Agent response unavailable. The correlated incident remains available below.");
    } finally { setInvestigating(false); }
  }

  async function submitReview(decision, action = containmentAction) {
    setReviewing(decision); setError("");
    try {
      const response = await fetch(`${API}/api/review`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ incident_id: incident.incident_id, decision, action, reason: reviewReason, acknowledged: impactAcknowledged }) });
      if (!response.ok) throw new Error((await response.json()).detail || "Review failed");
      setReview(await response.json());
      setSafetyGate(false);
    } catch (reviewError) { setError(reviewError.message || "Review action could not be saved. Check the backend connection and try again."); }
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

  async function openIncident(incidentId, source = "incidents") {
    setLoading(true); setIncident(null); setInvestigation(null); setResponsePlan(null); setVerification(null); setError(""); setView("analysis");
    window.scrollTo({ top: 0, behavior: "smooth" });
    try {
      const response = await fetch(`${API}/api/incidents/${incidentId}`);
      if (!response.ok) throw new Error();
      const result = await response.json();
      setIncident({ ...result, _openedFromBatch: source === "batch" }); setInvestigation(result.investigation || null); setResponsePlan(result.investigation?.response_plan || null); setVerification(result.investigation?.verification || null); setReopenedIncident(true); setApiOnline(true);
      if (!result.investigation) runIncidentInvestigation(incidentId);
    } catch {
      setError("Incident details could not be loaded. Return to Incident History and retry."); setApiOnline(false);
    } finally { setLoading(false); }
  }

  function backFromAnalysis() {
    if (batch) {
      setView("batch");
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    if (analysisReturnView === "incidents") {
      openHistory();
      return;
    }
    openCommandCenter();
  }

  async function downloadReport() {
    setReporting(true); setReportError("");
    try {
      const custom = Array.isArray(currentAlerts);
      const detailUrl = reopenedIncident ? `${API}/api/incidents/${incident.incident_id}/report` : null;
      const response = await fetch(detailUrl || (custom ? `${API}/api/report-alerts` : `${API}/api/report/${selected}`), {
        method: detailUrl ? "GET" : custom ? "POST" : "GET",
        headers: !detailUrl && custom ? { "Content-Type": "application/json" } : undefined,
        body: !detailUrl && custom ? JSON.stringify({ alerts: currentAlerts }) : undefined,
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
      <nav aria-label="Primary navigation"><button className={view === "command" ? "active" : ""} onClick={openCommandCenter}><Radar /> Command Center</button><button className={view === "live" ? "active" : ""} onClick={() => setView("live")}><Activity /> Live Events</button><button className={view === "incidents" ? "active" : ""} onClick={openHistory}><AlertTriangle /> Incidents</button><button className={view === "analysis" ? "active" : ""} onClick={openAnalysis}><BrainCircuit /> Analysis</button></nav>
      <div className={`system-card ${apiOnline === false ? "offline" : ""}`}><span className="pulse" /> {apiOnline === null ? "CONNECTING TO ENGINE" : apiOnline === false ? "ENGINE DISCONNECTED" : "CORRELATION ENGINE ONLINE"}<small>{apiOnline === null ? "Verifying production API" : apiOnline === false ? "Backend connection unavailable" : "Rules, evidence, and analyst review active"}</small></div>
    </aside>
    <main>
      <header><div><p className="eyebrow">FC-04 / SECURITY OPERATIONS</p><h1>{view === "command" ? "Incident Correlation Command Center" : view === "live" ? "Live Security Events" : view === "analysis" ? "Security Analysis Workspace" : view === "batch" ? "Batch Analysis Summary" : "Incident History"}</h1><p>{view === "command" ? "Correlate fragmented alerts into an evidence-backed incident." : view === "live" ? "Monitor incoming SOC telemetry and investigate suspicious activity." : view === "analysis" ? "Review correlated evidence, risk, AI findings, and response actions in one focused workspace." : view === "batch" ? "One upload, independently clustered security incidents, with unrelated alerts kept separate." : "Review analyzed incidents, severity, score, and analyst decisions."}</p></div><div className="analyst"><span>KM</span><div><strong>Lead Analyst</strong><small>Human approval enabled</small></div></div></header>

      {view === "batch" && batch ? <BatchAnalysisSummary batch={batch} onOpen={(incidentId) => openIncident(incidentId, "batch")} onBack={openCommandCenter} /> : view === "incidents" ? <IncidentHistory incidents={history} summary={historySummary} loading={historyLoading} error={historyError} onRefresh={openHistory} onBack={openCommandCenter} onOpen={openIncident} /> : view === "live" ? <LiveEvents onAnalyze={openCommandCenter} /> : view === "command" ? <>
      <section className="scenario-panel">
        <div className="panel-heading"><div><p className="section-label">INVESTIGATION INPUT</p><h2>{inputMode === "scenario" ? "Choose an investigation scenario" : "Analyze your own security alerts"}</h2></div><span className="api-label"><CircleDot /> Live API</span></div>
        <div className="input-tabs"><button className={inputMode === "scenario" ? "active" : ""} onClick={() => switchInputMode("scenario")}><Radar /> Demo scenarios</button><button className={inputMode === "custom" ? "active" : ""} onClick={() => switchInputMode("custom")}><FileJson /> JSON alerts</button></div>
        {inputMode === "scenario" ? <div className="scenario-grid">{scenarioCatalog.map(({ id, label, description, icon: Icon }) => {
          const ready = availableScenarioIds.has(id);
          return <button key={id} className={`scenario-option ${selected === id ? "selected" : ""}`} onClick={() => chooseScenario(id)}><span className="scenario-icon"><Icon /></span><span className="scenario-copy"><strong>{label}</strong><small>{description}</small></span><span className={`availability ${ready ? "ready" : "pending"}`}>{ready ? "READY" : "API PENDING"}</span></button>;
        })}</div> : <div className="custom-alerts"><div className="upload-row"><label className="file-button"><Upload /> Upload JSON<input type="file" accept=".json,application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) file.text().then(setAlertText).catch(() => setError("The selected file could not be read.")); event.target.value = ""; }} /></label><button onClick={() => setAlertText(sampleAlerts)}>Load sample</button><span>Flexible security JSON · timestamps auto-normalized</span></div><textarea value={alertText} onChange={(event) => setAlertText(event.target.value)} spellCheck="false" aria-label="Security alerts JSON" /></div>}
        <div className="scenario-footer"><p>{inputMode === "scenario" ? selectedMeta?.description || scenarioCatalog.find((item) => item.id === selected)?.description : "Paste or upload security JSON from SIEM, EDR, firewall, identity tools, or SOC reports. SentraPixel auto-normalizes recognized telemetry before correlation."}</p><button className="primary" onClick={runAnalysis} disabled={loading}>{loading ? <><LoaderCircle className="button-spinner" /> ANALYZING</> : <>{inputMode === "custom" ? "ANALYZE ALERTS" : "ANALYZE SCENARIO"} <ChevronRight /></>}</button></div>
        {error && <div className="error" role="alert"><XCircle />{error}</div>}
      </section>

      <section className="empty-state"><div className="scanner"><Radar /></div><p>Telemetry ready</p><span>Choose a scenario or upload alerts. Results will open in the dedicated Analysis workspace.</span></section>
      </> : <section className="analysis-workspace">
      <div className="analysis-toolbar"><button onClick={() => { if (incident?._openedFromBatch && batch) { setView("batch"); window.scrollTo({ top: 0, behavior: "smooth" }); } else if (reopenedIncident) { openHistory(); } else { openCommandCenter(); } }}><ArrowLeft /> {incident?._openedFromBatch && batch ? "Back to Batch Summary" : reopenedIncident ? "Back to Incidents" : "Back to Command Center"}</button><div><span className="analysis-crumb">COMMAND CENTER / ANALYSIS</span>{incident && <strong>{incident.incident_id}</strong>}</div><span className={`analysis-status ${loading ? "processing" : "complete"}`}><CircleDot />{loading ? "ANALYSIS IN PROGRESS" : "ANALYSIS COMPLETE"}</span></div>
      {error && <div className="error" role="alert"><XCircle />{error}</div>}
      {loading && <section className="analysis-loader"><div className="loader-visual"><span className="orbit one" /><span className="orbit two" /><BrainCircuit /></div><div><p className="section-label">CORRELATION IN PROGRESS</p><h2>{loadingStages[loadingStage]}</h2><span>SentraPixel is connecting identity, device, IP, and event evidence.</span></div><div className="stage-track">{loadingStages.map((stage, index) => <span key={stage} className={index <= loadingStage ? "complete" : ""} />)}</div></section>}

      {incident && <>
        <section className="metrics"><Metric label="Raw alerts" value={incident.metrics.raw_alerts} tone="blue" /><Metric label="Correlated" value={incident.metrics.correlated_alerts} tone="violet" /><Metric label="Correlation confidence" value={`${incident.confidence ?? 70}%`} tone="red" caption={incident.confidence_basis || "evidence confidence"} /><Metric label="Noise reduced" value={incident.metrics.noise_reduced} tone="green" /></section>
        <section className={`incident-hero ${incident.severity}`}><div><div className="incident-meta"><span>{incident.incident_id}</span><span>{incident.status.replace("_", " ")}</span></div><h2>{incident.title}</h2><p>{incident.summary}</p></div><div className="risk-orb"><strong>{incident.score}</strong><span>RISK SCORE</span><em>{incident.severity}</em></div></section>
        <div className="content-grid">
          <section className="card attack-card"><CardTitle icon={<Clock3 />} label="ATTACK TIMELINE" title="Evidence-linked event sequence" /><div className="chain">{incident.events.map((event, index) => <div className="chain-row" key={event.id}><div className="time">{event.time}</div><div className={`node ${index === incident.events.length - 1 ? "last" : ""}`}><span>{index + 1}</span></div><div className="event"><div><b>{event.stage}</b><small>{event.id} · {event.source}</small></div><p>{event.label}</p><EvidenceLink links={incident.links} eventId={event.id} /></div></div>)}</div></section>
          <div className="right-column">
            <section className="card"><CardTitle icon={<BrainCircuit />} label="INVESTIGATION SUMMARY" title="Evidence-grounded narrative" /><p className="narrative">{incident.summary}</p><div className={`classification-box ${incident.classification || "legacy"}`}><strong>{String(incident.classification || "analysis result").replaceAll("_", " ")}</strong><span>{incident.classification_reason || incident.confidence_basis}</span>{incident.missing_evidence?.length > 0 && <ul>{incident.missing_evidence.map((item) => <li key={item}>{item}</li>)}</ul>}</div><div className="grounded">{incident.metrics.correlated_alerts > 0 ? <CheckCircle2 /> : <AlertTriangle />} {incident.metrics.correlated_alerts > 0 ? "Conclusion supported by correlated telemetry" : "No evidence-linked chain — analyst validation required"}</div></section>
            <section className={`card risk-breakdown-card severity-${incident.severity}`}><CardTitle icon={<FileSearch />} label="SEVERITY EVIDENCE" title="Risk score composition" />{(() => { const additions = incident.factors.reduce((sum, factor) => sum + factor.points, 0); const base = Math.max(0, incident.score - Math.min(additions, incident.score)); const factorEvidence = { "Suspicious successful login": "Detected suspicious_login event", "Privilege escalation": "Detected privilege_escalation event", "Sensitive resource accessed": "Detected sensitive_access event", "Large outbound data transfer": "Detected data_exfiltration event", "Security control evasion": "Detected defense_evasion event" }; const highestEvent = [...incident.events].sort((x, y) => (y.base_severity || 0) - (x.base_severity || 0))[0]; const parts = [{ label: "Base alert severity", points: base, evidence: highestEvent ? `${highestEvent.id}: ${highestEvent.label} — base severity ${highestEvent.base_severity}` : "Highest-severity correlated alert" }, ...incident.factors.map((factor) => ({ label: factor.label, points: Math.min(factor.points, Math.max(0, incident.score)), evidence: factorEvidence[factor.label] || "Detected correlated security factor" }))].filter((part) => part.points > 0); const total = parts.reduce((sum, part) => sum + part.points, 0) || 1; let cursor = 0; const stops = parts.map((part, index) => { const start = cursor; cursor += (part.points / total) * 100; return `var(--risk-c${index % 6}) ${start}% ${cursor}%`; }).join(", "); return <><div className="risk-breakdown"><div className="risk-donut factor-donut" style={{ background: `conic-gradient(${stops})` }}><div className="risk-donut-center"><strong>{incident.score}</strong><span>RISK SCORE</span></div></div><div className="risk-legend">{parts.map((part, index) => <div className="risk-legend-row" key={`${part.label}-${index}`}><span className={`risk-dot factor-dot-${index % 6}`} /><span><span className="risk-factor-name">{part.label}</span><small className="risk-evidence">{part.evidence}</small></span><b>{Math.round((part.points / total) * 100)}% <small>({part.points} pts)</small></b></div>)}</div></div><div className="risk-evidence-graph"><div className="risk-graph-title">Evidence → score contribution</div>{parts.map((part, index) => <div className="risk-graph-row" key={`graph-${part.label}-${index}`}><div className="risk-graph-meta"><span>{part.label}</span><b>{Math.round((part.points / total) * 100)}%</b></div><div className="risk-graph-track"><span className={`risk-graph-fill graph-fill-${index % 6}`} style={{ width: `${Math.max(3, (part.points / total) * 100)}%` }} /></div><small>{part.evidence}</small></div>)}</div><div className="alert-time-graph"><div className="risk-graph-title">Alert evidence timeline</div><div className="alert-time-axis">{incident.events.map((event, index) => <div className="alert-time-node" key={event.id}><span className="alert-time">{event.time}</span><span className={`alert-node severity-${event.base_severity >= 65 ? "high" : event.base_severity >= 35 ? "medium" : "low"}`} /><span className="alert-stage">{event.stage}</span><small>{event.id} · {event.label}</small>{index < incident.events.length - 1 && <span className="alert-connector" />}</div>)}</div></div><p className="risk-explain">Pie = score composition. Bars = factor contribution. Timeline = exact alert time and evidence used to reconstruct the incident.</p></>; })()}</section>
            <section className="card"><CardTitle icon={<Network />} label="SUSPICIOUS INDICATORS" title="Entities under investigation" /><div className="indicators">{incident.indicators.map((item) => <div key={item.type}><span>{item.type}</span><strong>{item.value}</strong><em>{item.status}</em></div>)}</div></section>
            {incident.mitre_techniques?.length > 0 && <section className="card mitre-card"><CardTitle icon={<Radar />} label="MITRE ATT&CK" title="Observed adversary techniques" /><div className="mitre-list">{incident.mitre_techniques.map((technique) => <div key={technique.id}><span>{technique.id}</span><div><strong>{technique.name}</strong><small>{technique.tactic} · {technique.evidence}</small></div></div>)}</div></section>}
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
        {(responsePlan || verification) && <section className="multi-agent-grid">
          {responsePlan && <article className="card planner-card"><CardTitle icon={<ListChecks />} label="RESPONSE PLANNER AGENT" title="Containment and recovery plan" /><div className="agent-meta"><span className={`priority ${responsePlan.priority}`}>{responsePlan.priority} priority</span><span className="provider-badge">{responsePlan.provider === "gemini" ? "GEMINI GENERATED" : "DETERMINISTIC FALLBACK"}</span></div><div className="plan-columns"><div><p className="agent-label">IMMEDIATE ACTIONS</p><ol>{responsePlan.immediate_actions.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol></div><div><p className="agent-label">PRESERVE EVIDENCE</p><ol>{responsePlan.evidence_to_preserve.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol></div><div><p className="agent-label">RECOVERY</p><ol>{responsePlan.recovery_steps.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol></div></div><div className="approval-lock"><LockKeyhole /> Plan only — human approval required before execution</div></article>}
          {verification && <article className={`card verifier-card ${verification.verdict}`}><CardTitle icon={<ShieldCheck />} label="INDEPENDENT VERIFIER" title="Evidence and safety validation" /><div className="verification-score"><strong>{verification.checks_passed}/{verification.checks_total}</strong><div><span>{verification.verdict.replace("_", " ")}</span><small>{verification.provider === "evidence-policy" ? "DETERMINISTIC EVIDENCE CHECK" : "AI VERIFIED"}</small></div></div><div className="verification-list">{verification.supported_checks.map((item, index) => <p className="passed" key={`${item}-${index}`}><CheckCircle2 />{item}</p>)}{verification.warnings.map((item, index) => <p className="warning" key={`${item}-${index}`}><AlertTriangle />{item}</p>)}</div></article>}
        </section>}
        <section className="card response-card">
          <div className="response-heading"><CardTitle icon={<LockKeyhole />} label="HUMAN-IN-THE-LOOP" title="Safe containment decision" /><button className="report-button" onClick={downloadReport} disabled={reporting}>{reporting ? <LoaderCircle className="button-spinner" /> : <Download />}{reporting ? "Generating report" : "Download incident report"}</button></div>
          <div className="actions">{(responsePlan?.immediate_actions || incident.recommended_actions).map((action, index) => <div key={action}><span>{String(index + 1).padStart(2, "0")}</span>{action}</div>)}</div>
          <div className="safety-policy"><ShieldCheck /><div><strong>Permanent blocking is disabled</strong><span>SentraPixel permits monitoring or reversible temporary containment only. Permanent action requires separate second-party authorization.</span></div></div>
          {reportError && <div className="error" role="alert"><XCircle />{reportError}</div>}
          {!review && !safetyGate && <div className="review-buttons"><button className="reject" onClick={() => setSafetyGate(true)}><XCircle /> Review as false positive</button><button className="approve" onClick={() => { setContainmentAction((incident.confidence || 0) < 60 ? "monitor" : "temporary_containment"); setSafetyGate(true); }}><LockKeyhole /> Open safety gate</button></div>}
          {!review && safetyGate && <div className="containment-gate">
            <div className="impact-preview"><div><span>AI confidence</span><strong>{incident.confidence || 0}%</strong></div><div><span>Risk severity</span><strong>{incident.severity}</strong></div><div><span>Potential impact</span><strong>{containmentAction === "temporary_containment" ? "Access interruption" : "No service interruption"}</strong></div></div>
            <label>Safe response action<select value={containmentAction} onChange={(event) => { setContainmentAction(event.target.value); setImpactAcknowledged(false); }}><option value="monitor">Monitor only</option><option value="temporary_containment" disabled={(incident.confidence || 0) < 60}>Temporary containment (15 min)</option><option value="permanent_block" disabled>Permanent block — second approval required</option></select></label>
            <label>Analyst reason<textarea value={reviewReason} onChange={(event) => setReviewReason(event.target.value)} placeholder="Enter the evidence or business context behind this decision" /></label>
            {containmentAction === "temporary_containment" && <label className="impact-check"><input type="checkbox" checked={impactAcknowledged} onChange={(event) => setImpactAcknowledged(event.target.checked)} /> I reviewed the affected identity/device and accept the temporary service impact. Rollback remains available.</label>}
            {(incident.confidence || 0) < 60 && <div className="confidence-warning"><AlertTriangle /> Low confidence: containment is locked. Monitor or mark this case as a false positive.</div>}
            <div className="review-buttons"><button className="reject" onClick={() => submitReview("false_positive", "restore_access")} disabled={Boolean(reviewing) || !reviewReason.trim()}>{reviewing === "false_positive" ? <LoaderCircle className="button-spinner" /> : <XCircle />} Mark false positive & restore</button><button onClick={() => setSafetyGate(false)}>Cancel</button><button className="approve" onClick={() => submitReview("approved")} disabled={Boolean(reviewing) || !reviewReason.trim() || (containmentAction === "temporary_containment" && !impactAcknowledged)}>{reviewing === "approved" ? <LoaderCircle className="button-spinner" /> : <CheckCircle2 />} Confirm safe action</button></div>
          </div>}
          {review && <div className={`review-result ${review.decision}`}>{review.decision === "approved" ? <CheckCircle2 /> : <XCircle />}<div><strong>{review.message}</strong><span>{review.reason || "Decision recorded in the incident audit trail."}</span></div></div>}
        </section>
      </>}
      </section>}
    </main>
  </div>;
}

function BatchAnalysisSummary({ batch, onOpen, onBack }) {
  return <section className="batch-summary">
    <div className="batch-toolbar"><div><p className="section-label">CUSTOM JSON / CORRELATION RESULT</p><h2>Independent incidents detected</h2><p>{batch.batch_id} · Disconnected alerts are not allowed to influence another incident.</p></div><button onClick={onBack}><ArrowLeft /> New upload</button></div>
    <div className="batch-metrics">
      <Metric label="Raw Alerts" value={batch.raw_alerts} tone="blue" caption="uploaded telemetry" />
      <Metric label="Incidents Found" value={batch.incident_count} tone="red" caption="independent clusters" />
      <Metric label="Correlated Alerts" value={batch.correlated_alerts} tone="violet" caption="inside incidents" />
      <Metric label="Uncorrelated Alerts" value={batch.uncorrelated_alerts} tone="green" caption="kept separate" />
    </div>
    {batch.incidents?.length ? <div className="batch-incidents">{batch.incidents.map((item) => <button className="batch-incident-card" key={item.incident_id} onClick={() => onOpen(item.incident_id)}>
      <div><span className="batch-id">{item.incident_id}</span><span className={`severity-pill ${item.severity}`}>{item.severity}</span></div>
      <h3>{item.title}</h3>
      <p>{item.classification_reason}</p>
      <footer><span><Network /> {item.metrics?.correlated_alerts || item.events?.length || 0} correlated alerts</span><span>Risk {item.score} · Confidence {item.confidence}%</span><ChevronRight /></footer>
    </button>)}</div> : <div className="history-state"><ShieldCheck /><strong>No correlated malicious incidents found</strong><span>{batch.uncorrelated_alerts} alerts remain uncorrelated and were not forced into an incident.</span></div>}
    {batch.uncorrelated_alerts > 0 && <div className="batch-noise"><ShieldCheck /><div><strong>{batch.uncorrelated_alerts} alerts isolated from incident scoring</strong><span>These alerts remain available as uncorrelated telemetry. They do not change incident title, severity, confidence, MITRE mapping, or risk score.</span></div></div>}
  </section>;
}

function Metric({ label, value, tone, caption = "current scenario" }) { return <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong><small>{caption}</small></div>; }
function CardTitle({ icon, label, title }) { return <div className="card-title"><span>{icon}</span><div><p className="section-label">{label}</p><h3>{title}</h3></div></div>; }
function EvidenceLink({ links, eventId }) {
  const link = links.find((item) => item.to === eventId);
  return link ? <em><Link2 size={12}/>{link.reason}</em> : null;
}
function IncidentHistory({ incidents, summary, loading, error, onRefresh, onBack, onOpen }) {
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
    {!loading && incidents.length > 0 && <><div className="history-metrics"><Metric label="Total cases" value={summary.total ?? incidents.length} tone="blue" caption="all recorded" /><Metric label="Critical" value={summary.critical ?? 0} tone="red" caption="needs attention" /><Metric label="Approved" value={summary.approved ?? 0} tone="green" caption="analyst reviewed" /><Metric label="Noise reduced" value={`${summary.noise_reduction_percent ?? 0}%`} tone="violet" caption="across alerts" /></div><SocAnalytics incidents={incidents} summary={summary} /><div className="history-filters"><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search incident or ID" /><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">All statuses</option><option value="awaiting_review">Awaiting review</option><option value="approved">Approved</option><option value="rejected">Rejected</option></select><span>{filtered.length} of {incidents.length} cases</span></div></>}
    {loading ? <div className="history-state"><LoaderCircle className="button-spinner" /><span>Loading incident history</span></div> : !incidents.length ? <div className="history-state"><FileSearch /><strong>No incidents recorded yet</strong><span>Run a demo scenario or upload security alerts to create the first incident.</span><button onClick={onBack}>Open Command Center</button></div> : !filtered.length ? <div className="history-state compact"><SearchCheck /><strong>No matching incidents</strong><span>Change or clear the current filters.</span></div> : <div className="incident-table-wrap"><table className="incident-table"><thead><tr><th>Incident</th><th>Severity</th><th>Score</th><th>Alerts</th><th>Status</th><th>Created</th></tr></thead><tbody>{filtered.map((item) => <tr key={item.incident_id} className="clickable-row" tabIndex="0" onClick={() => onOpen(item.incident_id)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") onOpen(item.incident_id); }}><td><strong>{item.title}</strong><small>{item.incident_id} · Open analysis →</small></td><td><span className={`severity-pill ${item.severity}`}>{item.severity}</span></td><td className="score-cell">{item.score}</td><td>{item.metrics?.raw_alerts ?? "-"}</td><td><span className={`status-pill ${item.status}`}>{String(item.status || "open").replace("_", " ")}</span></td><td>{item.created_at ? new Date(item.created_at).toLocaleString() : "Current session"}</td></tr>)}</tbody></table></div>}
  </section>;
}

function SocAnalytics({ incidents, summary }) {
  const counts = ["critical", "high", "medium", "low"].map((level) => ({ level, count: incidents.filter((item) => item.severity === level).length }));
  const max = Math.max(1, ...counts.map((item) => item.count));
  const reviewed = (summary.approved || 0) + incidents.filter((item) => item.status === "rejected").length;
  const readiness = Math.round((reviewed / Math.max(1, incidents.length)) * 100);
  return <section className="soc-analytics"><div><p className="section-label">SEVERITY DISTRIBUTION</p><div className="severity-bars">{counts.map((item) => <div key={item.level}><span>{item.level}</span><div><i className={item.level} style={{ width: `${(item.count / max) * 100}%` }} /></div><b>{item.count}</b></div>)}</div></div><div className="readiness-ring" style={{ "--readiness": `${readiness * 3.6}deg` }}><span><strong>{readiness}%</strong><small>REVIEWED</small></span></div><div className="analytics-copy"><p className="section-label">SOC OUTCOME</p><strong>{summary.noise_reduction_percent || 0}% alert noise reduced</strong><span>{summary.total_alerts || 0} alerts processed across {incidents.length} recorded investigations.</span></div></section>;
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
