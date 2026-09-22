import { useMemo, useState } from "react";
import { Activity, AlertTriangle, BarChart3, BrainCircuit, ChevronDown, ChevronRight, Database, FileSearch, Fingerprint, Globe2, History, Link2, ListChecks, LockKeyhole, Network, Radar, Search, Settings, ShieldCheck, SlidersHorizontal, Upload, Waypoints } from "lucide-react";
import "./soc-shell.css";

const groups = [
  { label: "COMMAND", items: [
    ["command","SOC Overview",Radar], ["live","Live Monitoring",Activity], ["posture","Security Posture",ShieldCheck]
  ]},
  { label: "DETECTION", items: [
    ["alerts","Alert Center",AlertTriangle], ["upload","Upload & Analyze",Upload], ["detection","Threat Detection",Radar], ["correlation","Correlation Engine",Link2], ["anomaly","Anomaly Detection",Activity]
  ]},
  { label: "INVESTIGATION", items: [
    ["analysis","AI Investigation",BrainCircuit], ["incidents","Incident Workbench",FileSearch], ["evidence","Evidence Explorer",Fingerprint], ["timeline","Attack Timeline",Waypoints], ["mitre","MITRE ATT&CK",Network]
  ]},
  { label: "INTELLIGENCE", items: [
    ["intel","Threat Intelligence",Globe2], ["ioc","IOC Lookup",Search], ["ip","IP Reputation",Network], ["domain","Domain / URL Analysis",Globe2], ["hunt","Threat Hunting",Radar]
  ]},
  { label: "RESPONSE", items: [
    ["response","Response Center",LockKeyhole], ["actions","Recommended Actions",ListChecks], ["containment","Containment Queue",ShieldCheck], ["approval","Approval Center",LockKeyhole], ["false-positive","False Positive Review",ShieldCheck]
  ]},
  { label: "ANALYTICS", items: [
    ["risk","Risk Analytics",BarChart3], ["trends","Incident Trends",BarChart3], ["detection-analytics","Detection Analytics",Activity], ["insights","AI Insights",BrainCircuit]
  ]},
  { label: "REPORTING", items: [
    ["reports","Incident Reports",FileSearch], ["executive","Executive Reports",BarChart3], ["report-history","Report History",History]
  ]},
  { label: "SYSTEM", items: [
    ["sources","Data Sources",Database], ["integrations","Integrations",Link2], ["rules","Detection Rules",SlidersHorizontal], ["audit","Audit Logs",History], ["settings","Settings",Settings]
  ]}
];

const native = { command:"Command Center", live:"Live Events", incidents:"Incidents", analysis:"Analysis", upload:"Command Center", correlation:"Command Center", reports:"Incidents", "report-history":"Incidents", trends:"Incidents", risk:"Incidents" };

const copy = {
  posture:["Security Posture","Unified visibility into current exposure, analyst review readiness, and defensive coverage."],
  alerts:["Alert Center","Triage security alerts by severity, source, confidence, and investigation state."],
  detection:["Threat Detection","Review detections produced by identity, endpoint, network, and correlation signals."],
  anomaly:["Anomaly Detection","Surface behavior that deviates from expected identity, device, and network activity."],
  evidence:["Evidence Explorer","Inspect the entities and telemetry that support each incident conclusion."],
  timeline:["Attack Timeline","Reconstruct an incident as an ordered, evidence-linked attack sequence."],
  mitre:["MITRE ATT&CK","Map observed behavior to ATT&CK tactics and techniques without treating mappings as proof by themselves."],
  intel:["Threat Intelligence","Enrich suspicious indicators with external and internal context."],
  ioc:["IOC Lookup","Investigate IP addresses, domains, URLs, hashes, users, and devices from one workspace."],
  ip:["IP Reputation","Review reputation and contextual evidence for suspicious network addresses."],
  domain:["Domain / URL Analysis","Inspect domains and URLs for suspicious indicators and investigation context."],
  hunt:["Threat Hunting","Search across telemetry for related identities, devices, indicators, and attack patterns."],
  response:["Response Center","Coordinate reversible containment and analyst-approved response actions."],
  actions:["Recommended Actions","Review evidence-grounded response recommendations before execution."],
  containment:["Containment Queue","Track temporary containment requests, expiry, rollback, and approval state."],
  approval:["Approval Center","Keep consequential response actions behind explicit human authorization."],
  "false-positive":["False Positive Review","Review dismissed detections and preserve analyst reasoning for future tuning."],
  "detection-analytics":["Detection Analytics","Understand alert volume, correlation quality, severity distribution, and noise reduction."],
  insights:["AI Insights","Review AI-generated investigation narratives separately from deterministic evidence."],
  executive:["Executive Reports","Summarize incident volume, risk, response status, and SOC outcomes for stakeholders."],
  sources:["Data Sources","Manage SIEM, identity, endpoint, firewall, and uploaded JSON telemetry sources."],
  integrations:["Integrations","Connect intelligence, notification, storage, and security services."],
  rules:["Detection Rules","Review correlation and detection logic used by the deterministic analysis layer."],
  audit:["Audit Logs","Track investigations, analyst decisions, response actions, and report activity."],
  settings:["Settings","Configure workspace behavior, safety controls, integrations, and analyst preferences."]
};

function triggerNative(label){
  const buttons=[...document.querySelectorAll(".app-shell > aside nav button")];
  buttons.find(b=>b.textContent.includes(label))?.click();
}

export default function SocShell({children}){
  const [active,setActive]=useState("command");
  const [collapsed,setCollapsed]=useState(false);
  const [open,setOpen]=useState(()=>Object.fromEntries(groups.map(g=>[g.label,true])));
  const module=useMemo(()=>copy[active],[active]);

  function select(id){
    setActive(id);
    if(native[id]) triggerNative(native[id]);
    window.scrollTo({top:0,behavior:"smooth"});
  }

  return <div className={`soc-shell ${collapsed?"soc-collapsed":""}`}>
    <aside className="soc-sidebar">
      <div className="soc-brand"><div className="soc-logo"><ShieldCheck/></div>{!collapsed&&<div><strong>SentraPixel</strong><span>Autonomous SOC</span></div>}<button onClick={()=>setCollapsed(v=>!v)} aria-label="Toggle sidebar"><ChevronRight/></button></div>
      <div className="soc-nav">
        {groups.map(group=><section key={group.label}>
          {!collapsed&&<button className="soc-group" onClick={()=>setOpen(v=>({...v,[group.label]:!v[group.label]}))}><span>{group.label}</span>{open[group.label]?<ChevronDown/>:<ChevronRight/>}</button>}
          {(collapsed||open[group.label])&&<div>{group.items.map(([id,label,Icon])=><button title={label} key={id} className={active===id?"active":""} onClick={()=>select(id)}><Icon/><span>{label}</span></button>)}</div>}
        </section>)}
      </div>
      <div className="soc-engine"><span/><div><strong>ENGINE ONLINE</strong>{!collapsed&&<small>Evidence + human review</small>}</div></div>
    </aside>
    <div className="soc-content">
      {children}
      {module&&<div className="soc-module-overlay">
        <div className="soc-module-head"><div><p>SENTRAPIXEL / {active.replaceAll("-"," ").toUpperCase()}</p><h1>{module[0]}</h1><span>{module[1]}</span></div><button onClick={()=>select("command")}><Radar/> Open SOC Overview</button></div>
        <div className="soc-module-grid">
          <article><Activity/><strong>Workspace ready</strong><span>This module is connected to the SentraPixel navigation shell and ready for live data integration.</span></article>
          <article><ShieldCheck/><strong>Evidence first</strong><span>Deterministic evidence stays distinct from AI-generated interpretation.</span></article>
          <article><LockKeyhole/><strong>Human approval</strong><span>Consequential response actions remain behind analyst review.</span></article>
        </div>
        <div className="soc-module-empty"><BrainCircuit/><h2>{module[0]}</h2><p>{module[1]}</p><small>Module workspace · SentraPixel SOC Intelligence Platform</small></div>
      </div>}
    </div>
  </div>
}