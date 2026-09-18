import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, BrainCircuit, CheckCircle2, ChevronRight, CircleDot, Clock3, Database, FileSearch, Fingerprint, Link2, ListChecks, LoaderCircle, LockKeyhole, Network, Radar, SearchCheck, ShieldCheck, XCircle } from "lucide-react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const scenarioCatalog = [
  { id: "account-takeover", label: "Account Takeover", description: "Trace suspicious authentication, privilege escalation, and identity compromise.", icon: Fingerprint },
  { id: "data-exfiltration", label: "Data Exfiltration", description: "Investigate sensitive data access and unusual outbound transfer activity.", icon: Database },
  { id: "benign-login", label: "Benign Activity", description: "Validate normal user activity and reduce authentication alert noise.", icon: ShieldCheck },
];
const fallbackScenarios = [
  { id: "account-takeover", name: "Account Takeover + Data Exfiltration", description: "Compromised identity escalates privileges and exports confidential data.", event_count: 6 },
  { id: "benign-login", name: "Benign Authentication Noise", description: "Legitimate password mistakes followed by normal activity.", event_count: 3 },
];
const loadingStages = ["Normalizing telemetry", "Linking shared entities", "Calculating severity", "Building incident story"];

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
  const [error, setError] = useState("");
  const [apiOnline, setApiOnline] = useState(null);

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
    setSelected(id);
    setIncident(null);
    setInvestigation(null);
    setInvestigationError("");
    setReview(null);
    setError("");
  }

  async function runAnalysis() {
    if (!availableScenarioIds.has(selected)) {
      setError("Data Exfiltration scenario is waiting for the backend API. Add scenario ID: data-exfiltration.");
      return;
    }
    setLoading(true); setReview(null); setError("");
    try {
      const response = await fetch(`${API}/api/analyze/${selected}`, { method: "POST" });
      if (!response.ok) throw new Error();
      setIncident(await response.json()); setApiOnline(true);
      runInvestigation(selected);
    } catch {
      setError("Correlation engine unavailable. Confirm the FastAPI service is running on port 8000."); setApiOnline(false);
    } finally { setLoading(false); }
  }

  async function runInvestigation(scenarioId) {
    setInvestigating(true); setInvestigation(null); setInvestigationError("");
    try {
      const response = await fetch(`${API}/api/investigate/${scenarioId}`, { method: "POST" });
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

  return <div className="app-shell">
    <aside>
      <div className="brand"><div className="brand-mark"><ShieldCheck /></div><div><strong>SentraPixel</strong><span>Autonomous SOC Intelligence Platform</span></div></div>
      <nav aria-label="Primary navigation"><button className="active"><Radar /> Command Center</button><button><Activity /> Live Events</button><button><AlertTriangle /> Incidents</button><button><BrainCircuit /> AI Investigation</button></nav>
      <div className={`system-card ${apiOnline === false ? "offline" : ""}`}><span className="pulse" /> {apiOnline === false ? "ENGINE DISCONNECTED" : "CORRELATION ENGINE ONLINE"}<small>{apiOnline === false ? "Waiting for FastAPI on port 8000" : "Rules, evidence, and analyst review active"}</small></div>
    </aside>
    <main>
      <header><div><p className="eyebrow">FC-04 / SECURITY OPERATIONS</p><h1>Incident Correlation Command Center</h1><p>Correlate fragmented alerts into an evidence-backed incident.</p></div><div className="analyst"><span>KM</span><div><strong>Lead Analyst</strong><small>Human approval enabled</small></div></div></header>

      <section className="scenario-panel">
        <div className="panel-heading"><div><p className="section-label">DEMO CONTROL</p><h2>Choose an investigation scenario</h2></div><span className="api-label"><CircleDot /> Live API</span></div>
        <div className="scenario-grid">{scenarioCatalog.map(({ id, label, description, icon: Icon }) => {
          const ready = availableScenarioIds.has(id);
          return <button key={id} className={`scenario-option ${selected === id ? "selected" : ""}`} onClick={() => chooseScenario(id)}><span className="scenario-icon"><Icon /></span><span className="scenario-copy"><strong>{label}</strong><small>{description}</small></span><span className={`availability ${ready ? "ready" : "pending"}`}>{ready ? "READY" : "API PENDING"}</span></button>;
        })}</div>
        <div className="scenario-footer"><p>{selectedMeta?.description || scenarioCatalog.find((item) => item.id === selected)?.description}</p><button className="primary" onClick={runAnalysis} disabled={loading}>{loading ? <><LoaderCircle className="button-spinner" /> ANALYZING</> : <>ANALYZE SCENARIO <ChevronRight /></>}</button></div>
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
        <section className="card agent-card">
          <CardTitle icon={<BrainCircuit />} label="GEMINI INVESTIGATION AGENT" title="AI-assisted incident investigation" />
          {investigating && <div className="agent-loading"><LoaderCircle className="button-spinner" /><div><strong>Investigating correlated evidence</strong><span>Building a grounded narrative and analyst next steps.</span></div></div>}
          {investigationError && <div className="agent-error"><AlertTriangle />{investigationError}<button onClick={() => runInvestigation(selected)}>Retry</button></div>}
          {investigation && <div className="agent-grid">
            <div className="agent-narrative"><p className="agent-label"><BrainCircuit /> NARRATIVE</p><p>{investigation.narrative}</p><span className="provider-badge">{investigation.provider === "gemini" ? "GEMINI GENERATED" : "DETERMINISTIC FALLBACK"}</span></div>
            <div className="agent-list"><p className="agent-label"><SearchCheck /> CORRELATED EVIDENCE</p><ol>{investigation.evidence.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol></div>
            <div className="agent-list"><p className="agent-label"><ListChecks /> NEXT STEPS</p><ol>{investigation.next_steps.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol></div>
          </div>}
        </section>
        <section className="card response-card"><CardTitle icon={<LockKeyhole />} label="HUMAN-IN-THE-LOOP" title="Recommended containment plan" /><div className="actions">{incident.recommended_actions.map((action, index) => <div key={action}><span>{String(index + 1).padStart(2, "0")}</span>{action}</div>)}</div>{!review ? <div className="review-buttons"><button className="reject" onClick={() => submitReview("rejected")} disabled={Boolean(reviewing)}>{reviewing === "rejected" ? <LoaderCircle className="button-spinner" /> : <XCircle />} Reject plan</button><button className="approve" onClick={() => submitReview("approved")} disabled={Boolean(reviewing)}>{reviewing === "approved" ? <LoaderCircle className="button-spinner" /> : <CheckCircle2 />} Approve simulated response</button></div> : <div className={`review-result ${review.decision}`}>{review.decision === "approved" ? <CheckCircle2 /> : <XCircle />}{review.message}</div>}</section>
      </>}
    </main>
  </div>;
}

function Metric({ label, value, tone }) { return <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong><small>current scenario</small></div>; }
function CardTitle({ icon, label, title }) { return <div className="card-title"><span>{icon}</span><div><p className="section-label">{label}</p><h3>{title}</h3></div></div>; }
function EvidenceLink({ links, eventId }) {
  const link = links.find((item) => item.to === eventId);
  return link ? <em><Link2 size={12}/>{link.reason}</em> : null;
}
export default App;
