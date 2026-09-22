import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, BarChart3, Bell, BrainCircuit, CheckCircle2, CircleDot, Database, FileSearch, Fingerprint, Globe2, Link2, ListChecks, LockKeyhole, Network, Radar, RefreshCw, Search, Settings, ShieldCheck, SlidersHorizontal, UserRound, Waypoints, XCircle, Zap } from "lucide-react";
import "./soc-modules.css";

const API=import.meta.env.VITE_API_URL||"http://localhost:8000";
const titles={
  posture:["Security Posture","Operational readiness, review load, and defensive coverage."],
  alerts:["Alert Center","Prioritize stored security incidents by severity, score, and analyst state."],
  detection:["Threat Detection","Review high-risk detections and the evidence that caused them to surface."],
  anomaly:["Anomaly Detection","Surface unusual or high-severity activity that still needs corroborating evidence."],
  "system-health":["System Health","Check SentraPixel API reachability and operational safety controls."],
  evidence:["Evidence Explorer","Inspect event, identity, device, IP, and correlation evidence for a selected incident."],
  timeline:["Attack Timeline","Reconstruct the selected incident as an ordered sequence of security events."],
  mitre:["MITRE ATT&CK","Explore evidence-backed ATT&CK mappings generated from observed event types."],
  "entity-graph":["Entity Graph","Explore relationships between users, devices, IP addresses, resources, and incidents."],
  "case-notes":["Case Notes","Keep analyst notes for investigation handoff and review inside this browser session."],
  hunt:["Threat Hunting","Hunt across incident titles, summaries, indicators, events, and stored entities."],
  intel:["Threat Intelligence","Build an internal intelligence view from indicators observed across SentraPixel incidents."],
  ioc:["IOC Lookup","Search locally observed IPs, identities, devices, and resources across stored incidents."],
  domain:["IP / Domain Analysis","Search locally observed network resources and URLs across incident evidence."],
  vulnerability:["Vulnerability Intel","Review observed assets that should be checked by an external vulnerability source."],
  assets:["Asset Intelligence","Build an asset view from devices and resources observed in incident telemetry."],
  "ue-analytics":["User & Entity Analytics","Profile identities and entities based on their observed event activity."],
  response:["Response Center","Review response-ready incidents and route consequential actions through analyst approval."],
  actions:["Recommended Actions","Aggregate evidence-grounded response recommendations from current incidents."],
  containment:["Containment Actions","Track incidents eligible for temporary containment and those still missing confidence."],
  approval:["Approval Center","Review incidents waiting for an explicit analyst decision."],
  playbooks:["Response Playbooks","Use structured analyst-guided playbooks for common incident classes."],
  escalations:["Escalations","Surface high-priority incidents that should be escalated for analyst attention."],
  "false-positive":["False Positive Review","Review analyst-dismissed incidents and tune future triage decisions."],
  risk:["Risk Analytics","Understand the current risk distribution across recorded incidents."],
  trends:["Incident Trends","Track recorded incident activity and severity distribution."],
  "detection-analytics":["Detection Analytics","Measure severity distribution, alert volume, and correlation efficiency."],
  insights:["AI Insights","Identify incidents with stored investigation output and separate AI narrative from deterministic evidence."],
  sla:["SLA Analytics","Track pending high-risk cases and analyst review pressure."],
  reports:["Incident Reports","Open incidents and generate evidence-backed PDF reports from the existing report workflow."],
  executive:["Executive Reports","Summarize risk, incident state, and operational outcomes for stakeholders."],
  sources:["Data Sources","Inspect telemetry sources currently represented in stored incident evidence."],
  integrations:["Integrations","View SentraPixel service connectivity and integration boundaries."],
  rules:["Detection Rules","Review the deterministic correlation and safety rules that drive SentraPixel."],
  "rule-builder":["Rule Builder","Draft correlation and detection rule concepts without changing production logic."],
  automation:["Automation","Configure safe analyst-assist workflow toggles for this session."],
  audit:["Audit Logs","Review incident creation and analyst decision state as an operational audit stream."],
  notifications:["Notifications","Review current SOC notifications generated from risk and review state."],
  settings:["Settings","Configure local workspace preferences for this analyst session."]
};
const severityRank={critical:4,high:3,medium:2,low:1};

function Severity({value="low"}){return <span className={"wm-sev "+value}>{value}</span>}
function Metric({label,value,sub,tone=""}){return <article className={"wm-metric "+tone}><span>{label}</span><strong>{value}</strong><small>{sub}</small></article>}
function Empty({icon:Icon=Radar,title="No data yet",text="Analyze telemetry to populate this workspace."}){return <div className="wm-empty"><Icon/><strong>{title}</strong><span>{text}</span></div>}

function collect(incidents){
  const events=incidents.flatMap(i=>(i.events||[]).map(e=>({...e,incident_id:i.incident_id,incident_title:i.title,severity:i.severity,score:i.score})));
  const indicators=incidents.flatMap(i=>(i.indicators||[]).map(x=>({...x,incident_id:i.incident_id,severity:i.severity,score:i.score})));
  return {events,indicators};
}

function IncidentList({items,onPick}){
 if(!items.length)return <Empty icon={FileSearch} title="No matching incidents"/>;
 return <div className="wm-rows">{items.map(x=><button key={x.incident_id} onClick={()=>onPick?.(x)} className="wm-row">
   <span className={"wm-dot "+x.severity}/><div><strong>{x.title||"Security Incident"}</strong><small>{x.incident_id} · {x.status||"awaiting_review"}</small></div>
   <b>{x.score??0}</b><Severity value={x.severity}/><span>›</span>
 </button>)}</div>
}

function FilteredIncidents({incidents,onPick,initial="all"}){
 const[q,setQ]=useState(""),[filter,setFilter]=useState(initial);
 const items=useMemo(()=>incidents.filter(x=>{
   const ok=filter==="all"||x.severity===filter||x.status===filter;
   const hay=[x.title,x.incident_id,x.summary,x.status].join(" ").toLowerCase();
   return ok&&hay.includes(q.toLowerCase());
 }).sort((a,b)=>(severityRank[b.severity]||0)-(severityRank[a.severity]||0)||((b.score||0)-(a.score||0))),[incidents,q,filter]);
 return <section className="wm-panel"><div className="wm-toolbar"><label><Search/><input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search incidents"/></label><select value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">All states</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="awaiting_review">Awaiting review</option><option value="approved">Approved</option><option value="false_positive">False positive</option></select></div><IncidentList items={items} onPick={onPick}/></section>
}

function IntelSearch({incidents,mode}){
 const[q,setQ]=useState("");
 const {events,indicators}=collect(incidents);
 const results=useMemo(()=>{
   const needle=q.trim().toLowerCase(); if(!needle)return [];
   const a=indicators.filter(x=>[x.type,x.value,x.status,x.incident_id].join(" ").toLowerCase().includes(needle));
   const b=events.filter(x=>[x.ip,x.user,x.device,x.resource,x.label,x.type,x.source,x.incident_id].join(" ").toLowerCase().includes(needle)).map(e=>({type:"Event",value:e.label||e.type,status:e.source,incident_id:e.incident_id,extra:[e.ip,e.user,e.device,e.resource].filter(Boolean).join(" · ")}));
   return [...a,...b].slice(0,40);
 },[q,events,indicators]);
 return <section className="wm-panel intel-search"><div className="wm-search-hero"><Search/><div><strong>{mode==="hunt"?"Hunt across stored telemetry":"Search observed intelligence"}</strong><span>Queries run against evidence already recorded by SentraPixel.</span></div><input value={q} onChange={e=>setQ(e.target.value)} placeholder={mode==="hunt"?"user, device, IP, technique, keyword":"IP, identity, device, URL, indicator"}/></div>{q?<div className="intel-results">{results.length?results.map((r,i)=><article key={i}><span>{r.type}</span><strong>{r.value||"Observed indicator"}</strong><small>{r.incident_id} · {r.status||"observed"}</small>{r.extra&&<p>{r.extra}</p>}</article>):<Empty icon={Search} title="No local evidence matched" text="This search does not call an external reputation provider."/ >}</div>:<Empty icon={Radar} title="Ready to search" text="Enter a value to inspect evidence already observed by SentraPixel."/>}</section>
}

function DetailDriven({incidents,type}){
 const[selected,setSelected]=useState(null);
 useEffect(()=>{if(!selected&&incidents.length)setSelected(incidents[0])},[incidents,selected]);
 if(!selected)return <Empty/>;
 const events=selected.events||[], links=selected.links||[], techniques=selected.mitre_techniques||[];
 return <div className="wm-split"><section className="wm-panel compact-list"><div className="wm-panel-title"><strong>Incident scope</strong><small>{incidents.length} recorded cases</small></div><IncidentList items={incidents.slice(0,12)} onPick={setSelected}/></section><section className="wm-panel detail-pane"><div className="wm-detail-head"><div><Severity value={selected.severity}/><h2>{selected.title}</h2><p>{selected.incident_id} · score {selected.score} · confidence {selected.confidence??"—"}%</p></div></div>
 {type==="evidence"&&<><div className="wm-evidence-grid">{(selected.indicators||[]).map((x,i)=><article key={i}><span>{x.type}</span><strong>{x.value}</strong><small>{x.status}</small></article>)}</div><div className="wm-section-title">Correlation evidence</div>{links.length?links.map((x,i)=><div className="wm-link-row" key={i}><Link2/><b>{x.from}</b><span>→</span><b>{x.to}</b><small>{x.reason}</small></div>):<Empty icon={Link2} title="No correlation links" text="This incident may be a standalone high-risk signal or low-risk activity."/>}</>}
 {type==="timeline"&&<div className="wm-timeline">{events.map((e,i)=><article key={e.id||i}><i/><span>{e.time||e.timestamp||"--:--"}</span><div><strong>{e.stage||e.type}</strong><p>{e.label}</p><small>{e.source} · {e.user} · {e.device}</small></div></article>)}</div>}
 {type==="mitre"&&<div className="wm-tech-grid">{techniques.length?techniques.map((t,i)=><article key={i}><span>{t.id}</span><strong>{t.name}</strong><b>{t.tactic}</b><small>{t.evidence}</small></article>):<Empty icon={Network} title="No ATT&CK mappings stored"/>}</div>}
 {type==="correlation"&&<><div className="wm-metrics"><Metric label="Raw alerts" value={selected.metrics?.raw_alerts||events.length} sub="Events analyzed"/><Metric label="Correlated" value={selected.metrics?.correlated_alerts||0} sub="Evidence-linked alerts" tone="green"/><Metric label="Links" value={links.length} sub="Entity/time relationships" tone="blue"/><Metric label="Confidence" value={(selected.confidence??0)+"%"} sub={selected.confidence_basis||"Evidence basis"}/></div>{links.length?links.map((x,i)=><div className="wm-link-row" key={i}><Link2/><b>{x.from}</b><span>→</span><b>{x.to}</b><small>{x.reason}</small></div>):<Empty icon={Link2} title="No evidence links found"/>}</>}
 </section></div>
}

function ReportWorkspace({incidents,openIncident}){
 const[busy,setBusy]=useState("");
 async function download(incident){
  setBusy(incident.incident_id);
  try{
   const res=await fetch(`${API}/api/incidents/${incident.incident_id}/report`);if(!res.ok)throw new Error();
   const blob=await res.blob(),url=URL.createObjectURL(blob),a=document.createElement("a");
   a.href=url;a.download=`SentraPixel-${incident.incident_id}.pdf`;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
  }catch{window.alert("Report generation failed. Check the SentraPixel backend connection.");}
  finally{setBusy("")}
 }
 return <section className="wm-panel"><div className="wm-panel-title"><strong>Evidence-backed incident reports</strong><small>{incidents.length} report-ready cases</small></div>{incidents.length?incidents.map(i=><article className="wm-report-row" key={i.incident_id}><div><Severity value={i.severity}/><strong>{i.title}</strong><small>{i.incident_id} · score {i.score}</small></div><button onClick={()=>openIncident(i.incident_id)}><FileSearch/> Open</button><button onClick={()=>download(i)} disabled={busy===i.incident_id}><Database/> {busy===i.incident_id?"Generating…":"PDF"}</button></article>):<Empty icon={FileSearch} title="No reports available"/>}</section>
}

function EntityWorkspace({incidents,mode}){
 const {events}=collect(incidents);
 const field=mode==="users"?"user":mode==="assets"?"device":"resource";
 const counts={};
 events.forEach(e=>{const v=e[field];if(v&&v!=="unknown"&&v!=="Unknown")counts[v]=(counts[v]||0)+1});
 const rows=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,30);
 return <><div className="wm-metrics"><Metric label="Observed entities" value={rows.length} sub={mode==="users"?"Unique identities":"Unique assets/resources"}/><Metric label="Telemetry events" value={events.length} sub="Evidence population" tone="blue"/><Metric label="High-risk cases" value={incidents.filter(i=>["critical","high"].includes(i.severity)).length} sub="Priority context" tone="red"/></div><section className="wm-panel"><div className="wm-panel-title"><strong>{mode==="users"?"Identity activity":"Asset activity"}</strong><small>Derived from stored incident telemetry</small></div><div className="wm-entity-grid">{rows.length?rows.map(([name,count],i)=><article key={name}><div className="entity-rank">{String(i+1).padStart(2,"0")}</div>{mode==="users"?<UserRound/>:<Database/>}<div><strong>{name}</strong><span>{count} observed event{count===1?"":"s"}</span></div><b>{count}</b></article>):<Empty icon={Database} title="No entities observed"/>}</div></section></>
}

function EntityGraphWorkspace({incidents}){
 const {events}=collect(incidents);
 const users=[...new Set(events.map(e=>e.user).filter(x=>x&&x!=="unknown"))].slice(0,4);
 const devices=[...new Set(events.map(e=>e.device).filter(x=>x&&x!=="unknown"))].slice(0,4);
 const ips=[...new Set(events.map(e=>e.ip).filter(x=>x&&x!=="unknown"))].slice(0,4);
 return <section className="wm-panel"><div className="wm-panel-title"><strong>Relationship graph</strong><small>Identity → device → IP → incident</small></div><div className="entity-graph-stage"><div className="graph-col"><span>IDENTITIES</span>{users.map(x=><b key={x}>{x}</b>)}</div><div className="graph-links">⇄<small>evidence links</small></div><div className="graph-col"><span>DEVICES</span>{devices.map(x=><b key={x}>{x}</b>)}</div><div className="graph-links">⇄<small>network</small></div><div className="graph-col"><span>IP ADDRESSES</span>{ips.map(x=><b key={x}>{x}</b>)}</div><div className="graph-links">⇄<small>cases</small></div><div className="graph-col"><span>INCIDENTS</span>{incidents.slice(0,4).map(x=><b key={x.incident_id}>{x.incident_id}</b>)}</div></div></section>
}

function CaseNotes(){
 const[note,setNote]=useState(()=>localStorage.getItem("sentrapixel-case-notes")||"");
 const[saved,setSaved]=useState(Boolean(note));
 function save(){localStorage.setItem("sentrapixel-case-notes",note);setSaved(true)}
 return <section className="wm-panel case-notes"><div className="wm-panel-title"><strong>Analyst case notes</strong><small>Stored locally in this browser</small></div><textarea value={note} onChange={e=>{setNote(e.target.value);setSaved(false)}} placeholder="Add investigation notes, handoff context, evidence questions, or follow-up items…"/><div><span>{saved?"Saved locally":"Unsaved changes"}</span><button onClick={save}><FileSearch/> Save notes</button></div></section>
}

function SystemHealthWorkspace(){
 const[state,setState]=useState({loading:true,ok:false});
 useEffect(()=>{fetch(`${API}/api/health`).then(r=>setState({loading:false,ok:r.ok})).catch(()=>setState({loading:false,ok:false}))},[]);
 return <><div className="wm-metrics"><Metric label="API status" value={state.loading?"…":state.ok?"ONLINE":"OFFLINE"} sub="SentraPixel backend" tone={state.ok?"green":"red"}/><Metric label="Approval gate" value="ON" sub="Human review enforced" tone="green"/><Metric label="Auto permanent block" value="OFF" sub="Safety control" tone="blue"/><Metric label="Correlation window" value="15m" sub="Entity + time evidence"/></div><section className="wm-panel health-grid"><article><CircleDot/><div><strong>Incident API</strong><span>{state.ok?"Reachable and responding":"Not reachable from this client"}</span></div></article><article><ShieldCheck/><div><strong>Deterministic correlation</strong><span>Evidence relationships remain separate from AI interpretation.</span></div></article><article><LockKeyhole/><div><strong>Response guardrail</strong><span>Consequential response remains behind analyst approval.</span></div></article></section></>
}

function VulnerabilityWorkspace({incidents}){
 const {events}=collect(incidents);const assets=[...new Set(events.flatMap(e=>[e.device,e.resource]).filter(x=>x&&x!=="unknown"&&x!=="Unknown"))];
 return <><div className="wm-note"><ShieldCheck/><div><strong>External CVE feed not configured</strong><span>This workspace identifies observed assets to investigate; it does not invent vulnerability findings.</span></div></div><section className="wm-panel"><div className="wm-entity-grid">{assets.slice(0,30).map((a,i)=><article key={a}><div className="entity-rank">{String(i+1).padStart(2,"0")}</div><ShieldCheck/><div><strong>{a}</strong><span>Observed in SentraPixel telemetry</span></div><b>CHECK</b></article>)}</div></section></>
}

function PlaybookWorkspace(){
 const books=[["Account Takeover","Validate identity → revoke sessions → review privilege changes → temporary containment → analyst approval"],["Data Exfiltration","Validate transfer → identify destination → preserve logs → isolate affected endpoint → approval"],["Malware / C2","Validate process → inspect network indicators → isolate endpoint → preserve evidence → hunt related hosts"],["Uncorrelated High Risk","Validate source alert → collect supporting telemetry → monitor entity → avoid automatic blocking"]];
 return <section className="wm-panel"><div className="wm-playbooks">{books.map(([name,steps],i)=><article key={name}><span>PB-{String(i+1).padStart(2,"0")}</span><div><strong>{name}</strong><p>{steps}</p></div><button>Analyst guided</button></article>)}</div></section>
}

function RuleBuilder(){
 const[name,setName]=useState("Suspicious identity + privilege escalation"),[windowMins,setWindowMins]=useState(15),[severity,setSeverity]=useState("high");
 return <section className="wm-panel rule-builder"><div className="wm-note"><SlidersHorizontal/><div><strong>Draft mode</strong><span>This builder previews rule logic only; production detection logic is not modified.</span></div></div><div className="rule-fields"><label><span>Rule name</span><input value={name} onChange={e=>setName(e.target.value)}/></label><label><span>Correlation window</span><input type="number" min="1" max="60" value={windowMins} onChange={e=>setWindowMins(e.target.value)}/></label><label><span>Severity</span><select value={severity} onChange={e=>setSeverity(e.target.value)}><option>medium</option><option>high</option><option>critical</option></select></label></div><div className="rule-preview"><span>PREVIEW</span><strong>{name}</strong><code>WHEN shared_entity(user OR device OR ip) WITHIN {windowMins}m AND attack_sequence = true THEN severity = {severity}</code></div></section>
}

function AutomationWorkspace(){
 const[items,setItems]=useState({refresh:true,notify:true,contain:false,report:true});
 const rows=[["refresh","Auto-refresh telemetry","Refresh analyst workspaces when new evidence is available."],["notify","Priority notifications","Surface critical/high review items."],["contain","Automatic containment","Kept off; consequential response requires analyst approval."],["report","Report readiness","Keep evidence-backed incident reports ready for generation."]];
 return <section className="wm-panel settings-list">{rows.map(([k,n,d])=><label key={k}><div><strong>{n}</strong><span>{d}</span></div><input type="checkbox" checked={items[k]} disabled={k==="contain"} onChange={e=>setItems(v=>({...v,[k]:e.target.checked}))}/></label>)}</section>
}

function NotificationWorkspace({incidents,openIncident}){
 const rows=incidents.filter(i=>["critical","high"].includes(i.severity)||["open","awaiting_review"].includes(i.status)).slice(0,20);
 return <section className="wm-panel"><div className="wm-notifications">{rows.length?rows.map(i=><button key={i.incident_id} onClick={()=>openIncident(i.incident_id)}><Bell/><div><strong>{i.title}</strong><span>{i.incident_id} · {i.severity} · {i.status||"awaiting_review"}</span></div><Severity value={i.severity}/></button>):<Empty icon={Bell} title="No priority notifications"/>}</div></section>
}

function SLAWorkspace({incidents}){
 const pending=incidents.filter(i=>["open","awaiting_review",null,undefined].includes(i.status));
 const critical=pending.filter(i=>i.severity==="critical").length,high=pending.filter(i=>i.severity==="high").length;
 return <><div className="wm-metrics"><Metric label="Pending cases" value={pending.length} sub="Review queue"/><Metric label="Critical pending" value={critical} sub="Target: immediate" tone="red"/><Metric label="High pending" value={high} sub="Target: priority" tone="amber"/><Metric label="SLA pressure" value={critical?"HIGH":high?"MEDIUM":"LOW"} sub="Derived from queue severity" tone={critical?"red":high?"amber":"green"}/></div><FilteredIncidents incidents={pending} onPick={()=>{}}/></>
}

function ModuleBody({id,incidents,summary,navigate,openIncident}){
 const {events,indicators}=collect(incidents);
 const critical=incidents.filter(x=>x.severity==="critical").length, high=incidents.filter(x=>x.severity==="high").length, pending=incidents.filter(x=>["open","awaiting_review",null,undefined].includes(x.status)).length;
 if(["alerts","detection","anomaly"].includes(id)) return <FilteredIncidents incidents={id==="detection"?incidents.filter(x=>["critical","high"].includes(x.severity)):id==="anomaly"?incidents.filter(x=>x.classification==="uncorrelated_high_risk_signal"||x.standalone):incidents} onPick={x=>openIncident(x.incident_id)}/>;
 if(["evidence","timeline","mitre","correlation"].includes(id)) return <DetailDriven incidents={incidents} type={id}/>;
 if(["ioc","ip","domain","hunt","intel"].includes(id)) return <IntelSearch incidents={incidents} mode={id}/>;
 if(id==="posture") return <><div className="wm-metrics"><Metric label="Recorded incidents" value={summary.total||incidents.length} sub="Current knowledge base"/><Metric label="Critical" value={critical} sub="Immediate review" tone="red"/><Metric label="Awaiting review" value={pending} sub="Human decision queue" tone="amber"/><Metric label="Noise reduced" value={(summary.noise_reduction_percent||0)+"%"} sub="Correlation efficiency" tone="green"/></div><section className="wm-panel"><div className="posture-bars"><p><span>Correlation workflow</span><b>Active</b></p><p><span>Human approval gate</span><b>Enforced</b></p><p><span>Permanent auto-block</span><b className="warn">Disabled by design</b></p><p><span>Stored incident coverage</span><b>{incidents.length?"Available":"Waiting for data"}</b></p></div></section></>;
 if(["response","approval","containment","false-positive"].includes(id)){
   let list=incidents;
   if(id==="approval")list=incidents.filter(x=>["open","awaiting_review",null,undefined].includes(x.status));
   if(id==="containment")list=incidents.filter(x=>["critical","high"].includes(x.severity));
   if(id==="false-positive")list=incidents.filter(x=>x.status==="false_positive");
   return <><div className="wm-metrics"><Metric label="Awaiting analyst" value={pending} sub="Explicit review needed" tone="amber"/><Metric label="High/Critical" value={critical+high} sub="Priority response cases" tone="red"/><Metric label="Approved" value={summary.approved||incidents.filter(x=>x.status==="approved").length} sub="Reviewed cases" tone="green"/></div><FilteredIncidents incidents={list} onPick={x=>openIncident(x.incident_id)}/><div className="wm-note"><LockKeyhole/><div><strong>Safety boundary</strong><span>Temporary containment requires confidence and acknowledgement. Permanent blocking is not executed automatically by SentraPixel.</span></div></div></>;
 }
 if(id==="actions"){
   const actions=new Map(); incidents.forEach(i=>(i.recommended_actions||[]).forEach(a=>actions.set(a,(actions.get(a)||0)+1)));
   return <section className="wm-panel"><div className="wm-action-grid">{[...actions.entries()].sort((a,b)=>b[1]-a[1]).map(([a,n])=><article key={a}><ListChecks/><div><strong>{a}</strong><span>Recommended in {n} recorded incident{n===1?"":"s"}</span></div></article>)}</div></section>;
 }
 if(["risk","trends","detection-analytics","executive"].includes(id)){
   const sev=["critical","high","medium","low"].map(k=>[k,incidents.filter(x=>x.severity===k).length]);
   const max=Math.max(1,...sev.map(x=>x[1]));
   return <><div className="wm-metrics"><Metric label="Total incidents" value={incidents.length} sub="Recorded cases"/><Metric label="Total alerts" value={summary.total_alerts||events.length} sub="Analyzed telemetry"/><Metric label="Critical + High" value={critical+high} sub="Priority risk" tone="red"/><Metric label="Noise reduced" value={(summary.noise_reduction_percent||0)+"%"} sub="Correlation efficiency" tone="green"/></div><section className="wm-panel"><div className="wm-panel-title"><strong>Severity distribution</strong><small>Recorded incident population</small></div><div className="wm-bars">{sev.map(([k,n])=><div key={k}><span>{k}</span><i><b className={k} style={{width:(n/max*100)+"%"}}/></i><strong>{n}</strong></div>)}</div></section><FilteredIncidents incidents={incidents} onPick={x=>openIncident(x.incident_id)}/></>;
 }
 if(id==="insights"){
   const investigated=incidents.filter(x=>x.investigation);
   return <section className="wm-panel">{investigated.length?investigated.map(i=><article className="wm-insight" key={i.incident_id}><BrainCircuit/><div><strong>{i.title}</strong><span>{i.investigation?.provider||"AI/fallback provider"} · {i.incident_id}</span><p>{i.investigation?.narrative||"Investigation output stored for this incident."}</p></div></article>):<Empty icon={BrainCircuit} title="No stored AI investigations" text="Open an incident and run AI Investigation to populate this workspace."/>}</section>;
 }
 if(["reports","report-history"].includes(id)) return <ReportWorkspace incidents={incidents} openIncident={openIncident}/>;
 if(id==="sources"){
   const counts={};events.forEach(e=>{counts[e.source||"Unknown"]=(counts[e.source||"Unknown"]||0)+1});
   return <section className="wm-panel"><div className="wm-source-grid">{Object.entries(counts).length?Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([name,n])=><article key={name}><Database/><strong>{name}</strong><span>{n} observed events</span></article>):<Empty icon={Database} title="No telemetry sources recorded"/>}</div></section>;
 }
 if(id==="integrations") return <section className="wm-panel"><div className="wm-integration-grid"><article><CheckCircle2/><strong>SentraPixel API</strong><span>Core incidents, analysis, investigation, review and reports</span></article><article><Database/><strong>Supabase</strong><span>Optional persistence when backend environment variables are configured</span></article><article><BrainCircuit/><strong>AI Investigation Provider</strong><span>Backend pipeline uses configured provider with deterministic fallback</span></article><article><Globe2/><strong>External Threat Intel</strong><span>Not configured in this workspace; local evidence is shown without external reputation claims</span></article></div></section>;
 if(id==="rules") return <section className="wm-panel rules"><article><Link2/><div><strong>Entity correlation</strong><span>Shared user, device, IP or incident key plus a 15-minute time window.</span></div></article><article><Waypoints/><div><strong>Attack-sequence relationships</strong><span>Known transitions strengthen evidence-backed progression.</span></div></article><article><AlertTriangle/><div><strong>Standalone high-risk handling</strong><span>High severity without supporting links remains an unverified signal, not a confirmed attack chain.</span></div></article><article><LockKeyhole/><div><strong>Response safety</strong><span>Low-confidence cases cannot be temporarily contained and permanent auto-blocking is disabled.</span></div></article></section>;
 if(id==="audit") return <section className="wm-panel"><div className="wm-audit">{incidents.map((i,index)=><article key={i.incident_id}><span>{String(index+1).padStart(2,"0")}</span><i/><div><strong>{i.incident_id}</strong><p>{i.title}</p><small>Status: {i.status||"awaiting_review"} · severity: {i.severity} · score: {i.score}</small></div></article>)}</div></section>;
 if(id==="settings") return <SettingsPanel/>;
 return <Empty/>;
}

function SettingsPanel(){
 const[compact,setCompact]=useState(false),[motion,setMotion]=useState(true),[auto,setAuto]=useState(true);
 return <section className="wm-panel settings-list"><label><div><strong>Compact analyst density</strong><span>Reduce spacing in data-heavy workspaces.</span></div><input type="checkbox" checked={compact} onChange={e=>setCompact(e.target.checked)}/></label><label><div><strong>Interface motion</strong><span>Allow subtle Digital Twin and status animations.</span></div><input type="checkbox" checked={motion} onChange={e=>setMotion(e.target.checked)}/></label><label><div><strong>Auto-refresh incident data</strong><span>Refresh module data periodically while this session is open.</span></div><input type="checkbox" checked={auto} onChange={e=>setAuto(e.target.checked)}/></label><div className="wm-note"><Settings/><div><strong>Session preference preview</strong><span>These controls are local UI preferences and do not change backend security policy.</span></div></div></section>;
}

export default function SocModule({id,navigate,openIncident}){
 const[incidents,setIncidents]=useState([]),[summary,setSummary]=useState({}),[loading,setLoading]=useState(true),[error,setError]=useState("");
 const meta=titles[id]||["SOC Workspace","SentraPixel security operations workspace."];
 async function load(){
  setLoading(true);setError("");
  try{
   const res=await fetch(`${API}/api/incidents`);if(!res.ok)throw new Error();
   const body=await res.json();const rows=body.incidents||[];
   const detailed=await Promise.all(rows.slice(0,30).map(async row=>{try{const r=await fetch(`${API}/api/incidents/${row.incident_id}`);return r.ok?await r.json():row}catch{return row}}));
   setIncidents(detailed);setSummary(body.summary||{});
  }catch{setError("SentraPixel incident API is unavailable. Existing analysis features remain accessible from Upload & Analyze.");}
  finally{setLoading(false)}
 }
 useEffect(()=>{load()},[id]);
 return <div className="soc-module-overlay wm-overlay"><div className="wm-head"><div><p>SENTRAPIXEL / {id.replaceAll("-"," ").toUpperCase()}</p><h1>{meta[0]}</h1><span>{meta[1]}</span></div><button onClick={load} disabled={loading}><RefreshCw className={loading?"spin":""}/> Refresh data</button></div>
 {error&&<div className="wm-error"><XCircle/>{error}</div>}
 {loading?<div className="wm-loading"><Radar/><strong>Synchronizing SOC evidence</strong><span>Loading incident data and detailed event context…</span></div>:<ModuleBody id={id} incidents={incidents} summary={summary} navigate={navigate} openIncident={openIncident}/>}
 </div>
}