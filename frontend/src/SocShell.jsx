import { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, BarChart3, Bell, BrainCircuit, CheckCircle2, ChevronDown,
  ChevronRight, CircleDot, Database, FileSearch, Fingerprint, Globe2, History,
  Link2, ListChecks, LockKeyhole, Menu, Network, Radar, Search, Settings,
  ShieldCheck, SlidersHorizontal, Sun, Upload, UserRound, Waypoints, Zap
} from "lucide-react";
import "./soc-shell.css";
import SocModule from "./SocModules";

const API=import.meta.env.VITE_API_URL||"http://localhost:8000";

const groups=[
  {label:"",items:[["command","SOC Overview",Radar]]},
  {label:"MONITORING",items:[["live","Live Events",Activity],["alerts","Alert Center",AlertTriangle],["detection","Threat Detection",ShieldCheck],["anomaly","Anomaly Detection",Zap]]},
  {label:"INVESTIGATION",items:[["analysis","Investigation",BrainCircuit],["evidence","Evidence Explorer",Fingerprint],["timeline","Attack Timeline",Waypoints],["mitre","MITRE ATT&CK",Network],["hunt","Threat Hunting",Search]]},
  {label:"INTELLIGENCE",items:[["intel","Threat Intelligence",Globe2],["ioc","IOC Lookup",Search],["domain","IP / Domain Analysis",Globe2],["posture","Vulnerability Intel",ShieldCheck]]},
  {label:"RESPONSE",items:[["response","Response Center",Waypoints],["containment","Containment Actions",LockKeyhole],["approval","Approval Center",CheckCircle2],["false-positive","False Positive Review",ListChecks]]},
  {label:"ANALYTICS",items:[["risk","Risk Analytics",BarChart3],["reports","Incident Reports",FileSearch],["executive","Executive Reports",BarChart3]]},
  {label:"MANAGEMENT",items:[["sources","Data Sources",Database],["integrations","Integrations",Link2],["rules","Detection Rules",SlidersHorizontal],["audit","Audit Logs",History],["settings","Settings",Settings]]}
];

const native={live:"Live Events",analysis:"Analysis",upload:"Command Center",incidents:"Incidents"};

function triggerNative(label){
  [...document.querySelectorAll(".app-shell > aside nav button")].find(b=>b.textContent.includes(label))?.click();
}
function severityRank(value){return {critical:4,high:3,medium:2,low:1}[value]||0}
function sevClass(value="low"){return String(value).toLowerCase().replaceAll(" ","-")}

function MiniSpark({points="2,16 7,11 12,14 17,7 22,9 27,4 32,8 37,6 42,11 47,3"}){
  return <svg className="mini-spark" viewBox="0 0 50 20" aria-hidden="true"><polyline points={points}/></svg>;
}

function WorldThreatMap(){
  const nodes=[
    [214,120,"low"],[305,142,"low"],[397,102,"critical"],[430,88,"high"],
    [542,128,"critical"],[615,151,"high"],[354,160,"low"],[502,188,"high"],[692,216,"low"]
  ];
  return <div className="map-stage">
    <svg viewBox="0 0 840 300" className="world-map" role="img" aria-label="Global threat activity visualization">
      <g className="world-land">
        <path d="M77 82l34-30 54-20 63 12 37 31-22 26-41 4-13 36-36 20-43-15-17-31z"/>
        <path d="M210 157l25 9 27 42-3 49-21 33-18-34 4-39-17-32z"/>
        <path d="M347 64l35-20 47 4 20 21-20 15-22-8-17 12-26-9z"/>
        <path d="M380 96l49 9 37 31-6 39-26 33-31-17-10-45-27-25z"/>
        <path d="M442 62l63-24 87 8 84 28 68 28-11 34-59 3-40-23-43 7-23 31-34-18-31 4-15-31-53-14z"/>
        <path d="M640 205l44-18 46 15 12 30-29 23-43-8-19-21z"/>
      </g>
      <g className="attack-lines">
        <path className="line critical" d="M214 120 Q315 40 397 102"/>
        <path className="line blue" d="M305 142 Q402 115 542 128"/>
        <path className="line critical" d="M430 88 Q505 55 542 128"/>
        <path className="line blue" d="M354 160 Q430 125 615 151"/>
        <path className="line critical" d="M542 128 Q618 112 692 216"/>
      </g>
      {nodes.map(([x,y,t],i)=><g key={i} className={"map-node "+t} transform={"translate("+x+" "+y+")"}><circle r="10" className="pulse-ring"/><circle r="4"/><circle r="1.5" className="core"/></g>)}
    </svg>
    <div className="map-side map-origins"><strong>Top Attack Origins</strong><p><span>●</span> External IPs <b>28</b></p><p><span>●</span> Identity <b>19</b></p><p><span>●</span> Endpoint <b>11</b></p><p><span>●</span> Firewall <b>7</b></p><p><span>●</span> Email <b>6</b></p></div>
    <div className="map-side map-targets"><strong>Top Targeted Assets</strong><p><Database/> Web Servers <b>26</b></p><p><UserRound/> User Endpoints <b>18</b></p><p><Database/> Database <b>12</b></p><p><Globe2/> Cloud Services <b>9</b></p><p><ShieldCheck/> Email Gateway <b>7</b></p></div>
    <div className="map-badge"><ShieldCheck/><div><strong>Live Attack Map</strong><span>Evidence visualization</span></div></div>
  </div>;
}

function Overview({select,openIncident}){
  const[data,setData]=useState({incidents:[],summary:{}});
  const[details,setDetails]=useState([]);
  const[now,setNow]=useState(new Date());

  useEffect(()=>{
    let mounted=true;
    fetch(`${API}/api/incidents`).then(r=>r.ok?r.json():Promise.reject()).then(async body=>{
      if(!mounted)return;
      setData(body);
      const rows=(body.incidents||[]).slice(0,8);
      const full=await Promise.all(rows.map(async row=>{
        try{const r=await fetch(`${API}/api/incidents/${row.incident_id}`);return r.ok?await r.json():row}catch{return row}
      }));
      if(mounted)setDetails(full);
    }).catch(()=>{});
    const timer=setInterval(()=>setNow(new Date()),1000);
    return()=>{mounted=false;clearInterval(timer)};
  },[]);

  const incidents=data.incidents||[],summary=data.summary||{};
  const sorted=[...incidents].sort((a,b)=>severityRank(b.severity)-severityRank(a.severity)||(b.score||0)-(a.score||0));
  const critical=incidents.filter(x=>x.severity==="critical").length;
  const high=incidents.filter(x=>x.severity==="high").length;
  const pending=incidents.filter(x=>["open","awaiting_review",null,undefined].includes(x.status)).length;
  const contained=incidents.filter(x=>x.status==="approved").length;
  const avgConfidence=details.length?Math.round(details.reduce((n,x)=>n+(Number(x.confidence)||0),0)/details.length):0;

  const events=details.flatMap(i=>(i.events||[]).map(e=>({...e,incident_id:i.incident_id,severity:i.severity,score:i.score}))).sort((a,b)=>(b.time||"").localeCompare(a.time||"")).slice(0,9);
  const fallback=[
    {time:"10:12:31",label:"Data Exfiltration",id:"EVT-2081",severity:"critical",source:"Firewall"},
    {time:"10:11:07",label:"Privilege Escalation",id:"EVT-2080",severity:"high",source:"Identity"},
    {time:"10:09:44",label:"Suspicious Login",id:"EVT-2079",severity:"medium",source:"Endpoint"},
    {time:"10:08:17",label:"Failed Login",id:"EVT-2078",severity:"low",source:"SIEM"},
    {time:"10:06:55",label:"Malware Detected",id:"EVT-2077",severity:"high",source:"Endpoint"},
    {time:"10:05:32",label:"Unusual API Access",id:"EVT-2076",severity:"medium",source:"Cloud"}
  ];
  const eventRows=events.length?events.map((e,i)=>({time:e.time||"--:--",label:e.label||e.type||"Security Event",id:e.id||"EVT-"+(2081-i),severity:e.base_severity>=85?"critical":e.base_severity>=65?"high":e.base_severity>=35?"medium":"low",source:e.source||"Unknown"})):fallback;

  const techniques={};
  details.forEach(i=>(i.mitre_techniques||[]).forEach(t=>{techniques[t.id]=techniques[t.id]||{...t,count:0};techniques[t.id].count++}));
  const techniqueRows=Object.values(techniques).sort((a,b)=>b.count-a.count).slice(0,5);
  const techniqueFallback=[
    {id:"T1078",name:"Valid Accounts",count:22},{id:"T1041",name:"Exfiltration Over C2",count:18},
    {id:"T1490",name:"Inhibit System Recovery",count:12},{id:"T1059",name:"Command & Scripting",count:9},{id:"T1021",name:"Remote Services",count:7}
  ];
  const tech=techniqueRows.length?techniqueRows:techniqueFallback;
  const techMax=Math.max(...tech.map(x=>x.count),1);

  const trend=[16,18,14,19,22,28,34];
  const securityScore=Math.max(0,Math.min(100,78-critical*4-high*2+contained*3));
  const top=sorted[0];

  return <div className="exact-dashboard">
    <div className="dashboard-heading">
      <div><p>SOC COMMAND CENTER</p><h1>Security Operations Overview</h1><span>Detect. Investigate. Respond. Stay Ahead.</span></div>
      <div className="status-cluster">
        <div className="status-stats"><div><UserRound/><strong>3</strong><span>Active Analysts</span></div><div><CircleDot/><strong>92%</strong><span>System Health</span></div><div><Zap/><strong>0.4s</strong><span>Avg. Response</span></div></div>
        <div className="clock-card"><span>{now.toLocaleDateString("en-US",{weekday:"short",day:"2-digit",month:"short",year:"numeric"})}</span><strong>{now.toLocaleTimeString("en-GB")}</strong><b><i/> LIVE</b></div>
      </div>
    </div>

    <div className="exact-kpis">
      <button className="kpi red" onClick={()=>select("alerts")}><div className="kpi-icon"><ShieldCheck/></div><div><strong>{critical}</strong><span>Critical</span><small>↑ Priority threats</small></div><MiniSpark/></button>
      <button className="kpi amber" onClick={()=>select("detection")}><div className="kpi-icon"><AlertTriangle/></div><div><strong>{high}</strong><span>High Risk</span><small>↑ Needs investigation</small></div><MiniSpark points="2,16 7,14 12,9 17,11 22,4 27,7 32,2 37,5 42,12 47,8"/></button>
      <button className="kpi blue" onClick={()=>select("analysis")}><div className="kpi-icon"><Search/></div><div><strong>{pending}</strong><span>Investigating</span><small>↓ Analyst queue</small></div><MiniSpark points="2,17 8,13 13,14 18,10 24,11 29,6 34,9 39,5 44,7 48,2"/></button>
      <button className="kpi green" onClick={()=>select("response")}><div className="kpi-icon"><CheckCircle2/></div><div><strong>{contained}</strong><span>Contained</span><small>↑ Reviewed actions</small></div><MiniSpark points="2,15 7,12 12,14 17,10 22,12 27,7 32,8 37,4 42,6 47,2"/></button>
      <button className="kpi violet" onClick={()=>select("insights")}><div className="kpi-icon"><BrainCircuit/></div><div><strong>{avgConfidence||92}%</strong><span>AI Confidence</span><small>↑ Evidence confidence</small></div><MiniSpark points="2,16 7,13 12,15 17,9 22,10 27,6 32,8 37,5 42,9 47,4"/></button>
    </div>

    <div className="dashboard-main-grid">
      <section className="exact-card global-threat">
        <header><div><Globe2/><strong>Global Threat Activity</strong></div><div className="map-legend"><span className="critical">● Critical</span><span className="high">● High</span><span className="medium">● Medium</span><span className="low">● Low</span></div><button>Last 24 hours <ChevronDown/></button></header>
        <WorldThreatMap/>
      </section>

      <section className="exact-card live-events-card">
        <header><div><Activity/><strong>Live Security Events</strong></div><button onClick={()=>select("live")}>View All <ChevronRight/></button></header>
        <div className="exact-event-table">
          <div className="event-head"><span>Time</span><span>Event</span><span>Severity</span><span>Source</span></div>
          {eventRows.map((e,i)=><button key={e.id+i} onClick={()=>select("live")} className="event-line"><i className={sevClass(e.severity)}/><span>{e.time}</span><div><strong>{e.label}</strong><small>{e.id}</small></div><b className={"severity-pill "+sevClass(e.severity)}>{e.severity}</b><em>{e.source}</em></button>)}
        </div>
      </section>
    </div>

    <div className="dashboard-bottom-grid">
      <section className="exact-card trend-card">
        <header><div><BarChart3/><strong>Incident Trends</strong></div><button>Last 7 days <ChevronDown/></button></header>
        <div className="trend-legend"><span className="critical">● Critical</span><span className="high">● High</span><span className="medium">● Medium</span><span className="low">● Low</span></div>
        <div className="trend-bars">{trend.map((v,i)=><div key={i}><div className="stack"><i className="low" style={{height:(v*.28)+"%"}}/><i className="medium" style={{height:(v*.24)+"%"}}/><i className="high" style={{height:(v*.25)+"%"}}/><i className="critical" style={{height:(v*.23)+"%"}}/></div><span>Sep {16+i}</span></div>)}</div>
      </section>

      <section className="exact-card posture-card-exact">
        <header><div><ShieldCheck/><strong>Security Posture</strong></div><ChevronRight/></header>
        <div className="score-wrap"><div className="score-ring" style={{"--score":securityScore}}><div><strong>{securityScore}</strong><span>Security Score</span><b>+12%</b></div></div><div className="posture-list"><p><span><i className="cyan"/>Endpoint Security</span><b>82</b></p><p><span><i className="green"/>Identity Security</span><b>76</b></p><p><span><i className="violet"/>Network Security</span><b>71</b></p><p><span><i className="yellow"/>Data Protection</span><b>85</b></p><p><span><i className="blue"/>Cloud Security</span><b>79</b></p></div></div>
      </section>

      <section className="exact-card mitre-card-exact">
        <header><div><Network/><strong>MITRE ATT&CK</strong></div><button onClick={()=>select("mitre")}>View All <ChevronRight/></button></header>
        <span className="card-sub">Top Techniques (Last 24h)</span>
        <div className="mitre-bars">{tech.map((t,i)=><div key={t.id}><p><span>{t.id} · {t.name}</span><b>{t.count}</b></p><i><b style={{width:(t.count/techMax*100)+"%"}}/></i></div>)}</div>
      </section>

      <section className="exact-card copilot-card-exact">
        <header><div><BrainCircuit/><strong>AI Investigation Copilot</strong></div><ChevronRight/></header>
        <div className="copilot-alert"><BrainCircuit/><div><strong>{top?top.title:"3 new high-risk alerts detected."}</strong><span>{top?("Recommend reviewing "+top.incident_id+" before response."): "Recommend reviewing data exfiltration evidence."}</span></div></div>
        <div className="copilot-buttons"><button onClick={()=>select("analysis")}>Explain this alert</button><button onClick={()=>select("incidents")}>Show related incidents</button><button onClick={()=>select("actions")}>Recommended actions</button></div>
        <div className="copilot-input"><input placeholder="Ask the AI copilot…" onKeyDown={e=>{if(e.key==="Enter")select("analysis")}}/><button onClick={()=>select("analysis")}><ChevronRight/></button></div>
      </section>
    </div>
  </div>;
}

export default function SocShell({children}){
  const[active,setActive]=useState("command");
  const[collapsed,setCollapsed]=useState(false);
  const[mobileOpen,setMobileOpen]=useState(false);
  const[search,setSearch]=useState("");

  useEffect(()=>{
    const sync=(event)=>{
      const map={live:"live",incidents:"incidents",analysis:"analysis",batch:"analysis"};
      if(map[event.detail])setActive(map[event.detail]);
      else if(event.detail==="command")setActive(current=>current==="command"?"command":"upload");
    };
    window.addEventListener("sentrapixel:view",sync);
    return()=>window.removeEventListener("sentrapixel:view",sync);
  },[]);

  function select(id){
    setActive(id);
    setMobileOpen(false);
    if(native[id])triggerNative(native[id]);
    window.scrollTo({top:0,behavior:"smooth"});
  }
  function openIncident(incidentId){
    setActive("analysis");
    setMobileOpen(false);
    window.dispatchEvent(new CustomEvent("sentrapixel:open-incident",{detail:incidentId}));
    window.scrollTo({top:0,behavior:"smooth"});
  }
  function submitSearch(event){
    event.preventDefault();
    if(search.trim())select("hunt");
  }

  return <div className={"soc-shell exact-shell "+(collapsed?"soc-collapsed ":"")+(mobileOpen?"mobile-nav-open":"")}>
    <aside className="soc-sidebar exact-sidebar">
      <div className="soc-brand exact-brand">
        <div className="brand-shield"><ShieldCheck/></div>
        {!collapsed&&<div><strong>Sentra<span>Pixel</span></strong><small>Autonomous SOC Intelligence</small></div>}
      </div>
      <nav className="exact-nav">
        {groups.map(group=><section key={group.label||"overview"}>
          {!collapsed&&group.label&&<p>{group.label}</p>}
          {group.items.map(([id,label,Icon])=><button key={id} title={label} className={active===id?"active":""} onClick={()=>select(id)}><Icon/><span>{label}</span>{id==="alerts"&&!collapsed&&<b>{Math.max(0,12)}</b>}</button>)}
        </section>)}
      </nav>
      <button className="ai-online" onClick={()=>select("analysis")}><BrainCircuit/><div><span>AI Copilot</span><strong><i/> Online</strong></div></button>
    </aside>

    <header className="global-topbar">
      <button className="menu-toggle desktop-menu" onClick={()=>setCollapsed(v=>!v)}><Menu/></button><button className="menu-toggle mobile-menu" onClick={()=>setMobileOpen(v=>!v)}><Menu/></button>
      <form className="global-search" onSubmit={submitSearch}><Search/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search events, IPs, domains, users, incidents…"/><kbd>Ctrl + K</kbd></form>
      <div className="topbar-actions"><button className="bell"><Bell/><b>3</b></button><button><Sun/></button><div className="top-user"><span>KM</span><div><strong>Kabbilan M</strong><small>SOC Analyst</small></div><ChevronDown/></div></div>
    </header>

    {mobileOpen&&<button className="mobile-backdrop" aria-label="Close navigation" onClick={()=>setMobileOpen(false)}/>}
    <div className="soc-content exact-content">
      {children}
      {active==="command"?<div className="soc-module-overlay overview-overlay exact-overview-overlay"><Overview select={select} openIncident={openIncident}/></div>:native[active]?null:<SocModule id={active} navigate={select} openIncident={openIncident}/>}
    </div>
  </div>;
}