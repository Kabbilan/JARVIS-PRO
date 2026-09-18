import { useEffect, useState } from "react";
import { Activity, AlertTriangle, BrainCircuit, CheckCircle2, ChevronRight, Clock3, Link2, Radar, ShieldCheck, Sparkles, XCircle } from "lucide-react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const fallbackScenarios = [
  { id: "account-takeover", name: "Account Takeover + Data Exfiltration", description: "Compromised identity escalates privileges and exports confidential data.", event_count: 6 },
  { id: "benign-login", name: "Benign Authentication Noise", description: "Legitimate password mistakes followed by normal activity.", event_count: 3 },
];

function App() {
  const [scenarios, setScenarios] = useState(fallbackScenarios);
  const [selected, setSelected] = useState("account-takeover");
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(false);
  const [review, setReview] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API}/api/scenarios`).then((r) => r.json()).then(setScenarios).catch(() => {});
  }, []);

  async function runAnalysis() {
    setLoading(true);
    setReview(null);
    setError("");
    try {
      const response = await fetch(`${API}/api/analyze/${selected}`, { method: "POST" });
      if (!response.ok) throw new Error("Analysis failed");
      setIncident(await response.json());
    } catch {
      setError("Correlation engine unavailable. Start the FastAPI service on port 8000.");
    } finally {
      setLoading(false);
    }
  }

  async function submitReview(decision) {
    const response = await fetch(`${API}/api/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: incident.incident_id, decision }),
    });
    setReview(await response.json());
  }

  const severityClass = incident?.severity || "low";

  return (
    <div className="app-shell">
      <aside>
        <div className="brand"><div className="brand-mark"><ShieldCheck /></div><div><strong>AEGIS</strong><span>Autonomous SOC</span></div></div>
        <nav>
          <button className="active"><Radar /> Command Center</button>
          <button><Activity /> Live Events</button>
          <button><AlertTriangle /> Incidents</button>
          <button><BrainCircuit /> AI Investigation</button>
        </nav>
        <div className="system-card"><span className="pulse" /> CORRELATION ENGINE ONLINE<small>Hybrid rules + evidence AI</small></div>
      </aside>

      <main>
        <header><div><p className="eyebrow">FC-04 / SECURITY OPERATIONS</p><h1>Incident Correlation Command Center</h1><p>Turn fragmented alerts into one explainable attack story.</p></div><div className="analyst"><span>KM</span><div><strong>Lead Analyst</strong><small>Human approval enabled</small></div></div></header>

        <section className="scenario-panel">
          <div><p className="section-label">DEMO SCENARIO</p><h2>Stream security telemetry</h2></div>
          <div className="scenario-controls">
            <select value={selected} onChange={(e) => { setSelected(e.target.value); setIncident(null); }}>
              {scenarios.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.event_count} alerts</option>)}
            </select>
            <button className="primary" onClick={runAnalysis} disabled={loading}>{loading ? "CORRELATING..." : "RUN CORRELATION"}<ChevronRight /></button>
          </div>
          <p className="scenario-description">{scenarios.find((item) => item.id === selected)?.description}</p>
          {error && <div className="error"><XCircle />{error}</div>}
        </section>

        {!incident && !loading && <section className="empty-state"><div className="scanner"><Radar /></div><p>Waiting for telemetry</p><span>Select a scenario and run the correlation engine.</span></section>}
        {loading && <section className="empty-state"><div className="scanner spin"><Radar /></div><p>Connecting the evidence</p><span>Normalizing events · matching entities · reconstructing attack chain</span></section>}

        {incident && <>
          <section className="metrics">
            <Metric label="Raw alerts" value={incident.metrics.raw_alerts} tone="blue" />
            <Metric label="Correlated" value={incident.metrics.correlated_alerts} tone="violet" />
            <Metric label="Incidents" value={incident.metrics.incidents} tone="red" />
            <Metric label="Noise reduced" value={incident.metrics.noise_reduced} tone="green" />
          </section>

          <section className={`incident-hero ${severityClass}`}>
            <div><p className="section-label">{incident.incident_id}</p><h2>{incident.title}</h2><p>{incident.summary}</p></div>
            <div className="risk-orb"><strong>{incident.score}</strong><span>RISK SCORE</span><em>{incident.severity}</em></div>
          </section>

          <div className="content-grid">
            <section className="card attack-card"><CardTitle icon={<Link2 />} label="ATTACK CHAIN" title="Evidence-linked event sequence" />
              <div className="chain">
                {incident.events.map((event, index) => <div className="chain-row" key={event.id}>
                  <div className="time">{event.time}</div><div className={`node ${index === incident.events.length - 1 ? "last" : ""}`}><span>{index + 1}</span></div>
                  <div className="event"><div><b>{event.stage}</b><small>{event.id} · {event.source}</small></div><p>{event.label}</p>{incident.links[index] && <em><Link2 size={12}/>{incident.links[index].reason}</em>}</div>
                </div>)}
              </div>
            </section>

            <div className="right-column">
              <section className="card"><CardTitle icon={<Sparkles />} label="AI INVESTIGATION" title="Grounded incident narrative" /><p className="narrative">{incident.summary}</p><div className="grounded"><CheckCircle2 /> Generated only from correlated evidence</div></section>
              <section className="card"><CardTitle icon={<AlertTriangle />} label="SEVERITY EVIDENCE" title="Why this score was assigned" />
                <div className="factor-list">{incident.factors.length ? incident.factors.map((factor) => <div key={factor.label}><span>{factor.label}</span><b>+{factor.points}</b></div>) : <p>No critical escalation factors found.</p>}</div>
              </section>
              <section className="card"><CardTitle icon={<Radar />} label="INDICATORS" title="Entities under investigation" /><div className="indicators">{incident.indicators.map((item) => <div key={item.type}><span>{item.type}</span><strong>{item.value}</strong><em>{item.status}</em></div>)}</div></section>
            </div>
          </div>

          <section className="card response-card"><CardTitle icon={<ShieldCheck />} label="HUMAN-IN-THE-LOOP" title="Recommended containment plan" />
            <div className="actions">{incident.recommended_actions.map((action, index) => <div key={action}><span>{String(index + 1).padStart(2, "0")}</span>{action}</div>)}</div>
            {!review ? <div className="review-buttons"><button className="reject" onClick={() => submitReview("rejected")}><XCircle /> Reject plan</button><button className="approve" onClick={() => submitReview("approved")}><CheckCircle2 /> Approve simulated response</button></div> : <div className={`review-result ${review.decision}`}><CheckCircle2 />{review.message}</div>}
          </section>
        </>}
      </main>
    </div>
  );
}

function Metric({ label, value, tone }) { return <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong><small>current scenario</small></div>; }
function CardTitle({ icon, label, title }) { return <div className="card-title"><span>{icon}</span><div><p className="section-label">{label}</p><h3>{title}</h3></div></div>; }

export default App;

