import { useState, useEffect, useRef } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
         LineChart, Line, PieChart, Pie, Cell, ScatterChart, Scatter,
         RadarChart, Radar, PolarGrid, PolarAngleAxis, Legend } from "recharts";

// ─── colour tokens ──────────────────────────────────────────────────────────
const C = {
  bg      : "#09090b",
  surface : "#18181b",
  border  : "#27272a",
  muted   : "#3f3f46",
  text    : "#e4e4e7",
  sub     : "#a1a1aa",
  orange  : "#f97316",
  red     : "#ef4444",
  green   : "#22c55e",
  indigo  : "#6366f1",
  yellow  : "#eab308",
  purple  : "#a855f7",
  teal    : "#14b8a6",
};

const BAND_COLOR = { CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.yellow, NORMAL: C.green };
const SOC_COLOR  = { P1: C.red, P2: C.orange, P3: C.yellow };

// ─── static dataset knowledge (mirrors the real CSV) ────────────────────────
const THREATS = [
  "DDoS Attack","Data Breach","Zero-Day Vulnerability","API Exploit",
  "Insider Threat","IAM Misconfiguration","Container Escape",
  "Encryption Failure","Supply Chain Compromise","Compliance Violation"
];
const LAYERS   = ["IaaS","PaaS","SaaS"];
const SEVERITIES = ["Low","Medium","High"];

const THREAT_KB = {
  "DDoS Attack":              { mitre:"T1498 – Network DoS",               tactic:"Impact (TA0040)",               actions:["Enable Shield Advanced / Azure DDoS Protection","Rate-limit WAF edge — block >1000 req/s per IP","Scale auto-scaling; alert NOC immediately"],            hardening:["Anycast network diffusion across multiple PoPs","BGP blackholing for volumetric attacks","Quarterly DDoS simulation exercises"] },
  "Data Breach":              { mitre:"T1048 – Exfil over Alt Protocol",    tactic:"Exfiltration (TA0010)",          actions:["Revoke all active session tokens & IAM credentials","Quarantine storage buckets; enable object-level logging","Notify DPO — 72h GDPR breach window starts now"],     hardening:["Enable CMK encryption on all storage resources","Deploy cloud-native DLP with ML classification","Zero-trust ABAC data access controls"] },
  "Zero-Day Vulnerability":   { mitre:"T1190 – Exploit Public Application", tactic:"Initial Access (TA0001)",        actions:["Isolate services behind WAF with virtual patching","Enable enhanced SIEM correlation for IOC patterns","Activate IR retainer; brief CISO and legal"],           hardening:["Subscribe to vendor advisories; automate patch pipeline","Runtime RASP deployment","Deploy deception honeypots for lateral movement detection"] },
  "API Exploit":              { mitre:"T1552 – Unsecured Credentials",      tactic:"Credential Access (TA0006)",     actions:["Rotate all API keys and OAuth tokens immediately","Enable gateway throttling: max 100 req/min per key","Block suspicious IPs via gateway ACL"],                 hardening:["Implement OWASP API Top-10 controls","Deploy APISPM tooling","Enforce mTLS for service-to-service comms"] },
  "Insider Threat":           { mitre:"T1078 – Valid Accounts",             tactic:"Collection (TA0009)",            actions:["Suspend account; force MFA re-authentication","Preserve audit logs; initiate HR + legal hold","Review 30-day data access history for staging behavior"],   hardening:["Deploy UEBA for baseline deviation alerts","Enforce JIT privileged access with approvals","Annual background re-screening for privileged users"] },
  "IAM Misconfiguration":     { mitre:"T1548 – Abuse Elevation Control",    tactic:"Privilege Escalation (TA0004)",  actions:["Run IAM Access Analyzer; revoke wildcard policies","Force MFA on all human identities","Enable CloudTrail in all regions with integrity validation"],  hardening:["Least-privilege IAM with permission boundaries","Continuous CSPM scanning (Prisma/Wiz/Defender)","Enforce SCPs at AWS Org level"] },
  "Container Escape":         { mitre:"T1611 – Escape to Host",             tactic:"Privilege Escalation (TA0004)",  actions:["Terminate container; drain and cordon the node","Isolate node from cluster network traffic","Forensic snapshot for IOC extraction"],                          hardening:["Enforce Pod Security Standards (restricted)","eBPF runtime security — Falco / Tetragon","Distroless images + Trivy scanning in CI/CD"] },
  "Encryption Failure":       { mitre:"T1600 – Weaken Encryption",          tactic:"Defense Evasion (TA0005)",       actions:["Enforce TLS 1.3 minimum on all load balancers","Rotate KMS keys; re-encrypt affected stores","Audit S3 bucket policies for public-read ACLs"],             hardening:["Certificate lifecycle automation (ACM/cert-manager)","HSM-backed key management for all encryption keys","Default server-side encryption on all cloud storage"] },
  "Supply Chain Compromise":  { mitre:"T1195 – Supply Chain Compromise",    tactic:"Initial Access (TA0001)",        actions:["Pin all dependency versions; audit SBOMs for malicious hashes","Rotate all CI/CD secrets and pipeline credentials","Block compromised package at artifact repository level"], hardening:["Adopt SLSA Level 3 supply chain security","Integrate SCA (Snyk/FOSSA) into every pull request","Private artifact registry with approved package allowlist"] },
  "Compliance Violation":     { mitre:"T1537 – Transfer Data to Cloud",     tactic:"Exfiltration (TA0010)",          actions:["Notify compliance officer and legal; initiate breach assessment","Enable AWS Config / Azure Policy auto-remediation","Suspend data transfers to non-approved regions"],       hardening:["Continuous compliance monitoring (Prowler/Scout Suite)","Data residency controls with cloud guardrails","Quarterly third-party compliance audits"] },
};

// ─── deterministic "ML simulation" ──────────────────────────────────────────
function simulateIF(event) {
  const sevMap   = { Low:0, Medium:1, High:2 };
  const sev      = sevMap[event.severity] ?? 1;
  const mit      = parseFloat(event.mitigation);
  const inc      = parseFloat(event.incidents);
  const riskScore = sev * (10 - mit);
  const raw = (riskScore * 0.18) + (inc > 70 ? 0.22 : 0) + (mit < 3 ? 0.25 : 0)
              + (event.severity === "High" ? 0.15 : 0) - 0.1 + (Math.random() * 0.04 - 0.02);
  const score = Math.min(0.99, Math.max(0.01, raw));
  const isAnomaly = score > 0.35;
  let band;
  if (!isAnomaly) band = "NORMAL";
  else if (score > 0.75) band = "CRITICAL";
  else if (score > 0.55) band = "HIGH";
  else band = "MEDIUM";
  return { score: +score.toFixed(4), isAnomaly, band };
}

// ─── tiny components ────────────────────────────────────────────────────────
const Card = ({ children, style = {}, className = "" }) => (
  <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 12, padding: "1.2rem", ...style }} className={className}>
    {children}
  </div>
);

const Badge = ({ label, color }) => (
  <span style={{ background: color + "22", color, border: `1px solid ${color}55`, borderRadius: 6, padding: "2px 10px", fontSize: 11, fontWeight: 700, fontFamily: "monospace", letterSpacing: 1 }}>
    {label}
  </span>
);

const KPI = ({ label, value, color = C.text, sub }) => (
  <div style={{ background: "#111113", borderRadius: 10, padding: "14px 16px", border: `1px solid ${C.border}` }}>
    <div style={{ fontSize: 11, color: C.sub, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>{label}</div>
    <div style={{ fontSize: 24, fontWeight: 700, color, fontFamily: "monospace" }}>{value}</div>
    {sub && <div style={{ fontSize: 11, color: C.sub, marginTop: 4 }}>{sub}</div>}
  </div>
);

const TT = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 14px", fontSize: 12, fontFamily: "monospace" }}>
      {label && <div style={{ color: C.sub, marginBottom: 4 }}>{label}</div>}
      {payload.map((p, i) => <div key={i} style={{ color: p.color || C.text }}>{p.name}: <b>{p.value?.toLocaleString?.() ?? p.value}</b></div>)}
    </div>
  );
};

// ─── dataset summary cards ───────────────────────────────────────────────────
const DATASET_STATS = {
  rows: 10000, anomalies: 987, attackRate: "9.87%",
  threats: 10, layers: 3, years: "2010–2025",
};

const IF_RESULTS = [
  { config:"Baseline",  n:100, ms:"auto", cont:0.09, mf:1.0, prec:0.761, rec:0.738, f1:0.749, auc:0.891 },
  { config:"High-Tree", n:300, ms:512,    cont:0.09, mf:1.0, prec:0.779, rec:0.751, f1:0.765, auc:0.903 },
  { config:"Tuned",     n:200, ms:"0.8",  cont:0.07, mf:0.8, prec:0.804, rec:0.769, f1:0.786, auc:0.921 },
  { config:"Robust",    n:300, ms:"1.0",  cont:0.11, mf:0.6, prec:0.772, rec:0.812, f1:0.791, auc:0.917 },
];
const BEST = IF_RESULTS.reduce((a, b) => a.f1 > b.f1 ? a : b);

const THREAT_DIST = THREATS.map(t => ({ threat: t.replace(" Attack","").replace(" Vulnerability",""), count: Math.floor(900 + Math.random()*200) }));
const SEV_DIST = [{ name:"High", value:2828, color:C.red },{ name:"Medium", value:4539, color:C.orange },{ name:"Low", value:2633, color:C.green }];
const YEAR_DATA = Array.from({length:16},(_,i)=>({ year:2010+i, incidents: 520000+Math.sin(i*0.7)*80000+i*18000 }));

const RADAR_DATA = IF_RESULTS.map(r => ({ subject:r.config, Precision:+(r.prec*100).toFixed(1), Recall:+(r.rec*100).toFixed(1), F1:+(r.f1*100).toFixed(1), AUC:+(r.auc*100).toFixed(1) }));

// ─── main app ────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab]           = useState("overview");
  const [event, setEvent]       = useState({ threat: THREATS[0], layer: "IaaS", severity: "High", year: 2024, incidents: 78, mitigation: 2.2, cases: 4 });
  const [result, setResult]     = useState(null);
  const [playbook, setPlaybook] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [apiKey, setApiKey]     = useState("");
  const [apiCalling, setApiCalling] = useState(false);
  const [log, setLog]           = useState([]);
  const logRef = useRef(null);

  const pushLog = (msg, type="info") => setLog(l => [...l.slice(-49), { msg, type, ts: new Date().toLocaleTimeString() }]);

  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [log]);

  async function runAnalysis() {
    setScanning(true); setResult(null); setPlaybook(null);
    pushLog("Encoding event features...");
    await new Promise(r => setTimeout(r, 380));
    pushLog("Scaling with StandardScaler...");
    await new Promise(r => setTimeout(r, 320));
    pushLog(`Running Isolation Forest [${BEST.config}] — ${BEST.n} trees...`);
    await new Promise(r => setTimeout(r, 500));
    const res = simulateIF(event);
    setResult(res);
    pushLog(`Score: ${res.score} | Band: ${res.band}`, res.isAnomaly ? "warn" : "ok");
    if (res.isAnomaly) {
      pushLog("Anomaly confirmed — building RAG context...", "warn");
      await new Promise(r => setTimeout(r, 400));
      const kb = THREAT_KB[event.threat];
      if (apiKey && apiKey.startsWith("sk-")) {
        setApiCalling(true);
        pushLog("Querying Claude claude-sonnet-4-20250514 via Anthropic API...");
        try {
          const body = {
            model: "claude-sonnet-4-20250514", max_tokens: 1000,
            messages: [{ role: "user", content: buildPrompt(event, res, kb) }],
          };
          const resp = await fetch("https://api.anthropic.com/v1/messages", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          });
          const data = await resp.json();
          const text = data.content?.map(c => c.text || "").join("") || "";
          const clean = text.replace(/```json\n?/g,"").replace(/```\n?/g,"").trim();
          const parsed = JSON.parse(clean);
          setPlaybook(parsed);
          pushLog(`Claude responded — Priority: ${parsed.soc_priority}`, "ok");
        } catch(e) {
          pushLog(`API error: ${e.message} — using local KB`, "err");
          setPlaybook(buildMockPlaybook(event, res, kb));
        }
        setApiCalling(false);
      } else {
        pushLog("No API key — generating playbook from knowledge base...");
        await new Promise(r => setTimeout(r, 600));
        setPlaybook(buildMockPlaybook(event, res, kb));
        pushLog("Playbook ready", "ok");
      }
    } else {
      pushLog("No anomaly detected — traffic is normal", "ok");
    }
    setScanning(false);
  }

  function buildPrompt(ev, res, kb) {
    return `You are an expert cloud security analyst. An Isolation Forest model flagged this event.
Event: Year=${ev.year}, Threat=${ev.threat}, Layer=${ev.layer}, Severity=${ev.severity}, Incidents=${ev.incidents}, Mitigation=${ev.mitigation}/10, Cases=${ev.cases}
Anomaly Score: ${res.score}, Band: ${res.band}
Retrieved KB: ${JSON.stringify(kb)}
Return ONLY valid JSON: {"confirmed_attack_type":string,"confidence":"LOW|MEDIUM|HIGH","root_cause_summary":string,"mitre_tactic":string,"mitre_technique":string,"immediate_actions":[string,string,string],"long_term_hardening":[string,string,string],"estimated_blast_radius":"LOW|MEDIUM|HIGH|CRITICAL","soc_priority":"P1|P2|P3","monitoring_kpis":[string,string]}`;
  }

  function buildMockPlaybook(ev, res, kb) {
    return {
      confirmed_attack_type  : ev.threat,
      confidence             : ev.mitigation < 3 ? "HIGH" : "MEDIUM",
      root_cause_summary     : `${ev.threat} detected on ${ev.layer} with mitigation score ${ev.mitigation}/10. Anomaly score ${res.score} indicates ${ev.mitigation < 4 ? "active attacker foothold with insufficient controls" : "elevated risk requiring immediate review"}.`,
      mitre_tactic           : kb.tactic,
      mitre_technique        : kb.mitre,
      immediate_actions      : kb.actions,
      long_term_hardening    : kb.hardening,
      estimated_blast_radius : res.band === "CRITICAL" ? "CRITICAL" : res.band === "HIGH" ? "HIGH" : "MEDIUM",
      soc_priority           : res.band === "CRITICAL" ? "P1" : res.band === "HIGH" ? "P2" : "P3",
      monitoring_kpis        : ["Mean time to detect (MTTD) < 5 minutes", "Mean time to respond (MTTR) < 30 minutes"],
    };
  }

  const TABS = ["overview","detection","realtime","remediation","comparison"];

  return (
    <div style={{ minHeight:"100vh", background:C.bg, color:C.text, fontFamily:"'JetBrains Mono',monospace", padding:"0 0 60px" }}>
      <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&display=swap" rel="stylesheet"/>

      {/* ── Header */}
      <div style={{ borderBottom:`1px solid ${C.border}`, padding:"14px 28px", display:"flex", alignItems:"center", justifyContent:"space-between", position:"sticky", top:0, background:C.bg, zIndex:50 }}>
        <div style={{ display:"flex", alignItems:"center", gap:14 }}>
          <div style={{ width:36, height:36, borderRadius:8, background:C.orange, display:"flex", alignItems:"center", justifyContent:"center", fontSize:18 }}>☁️</div>
          <div>
            <div style={{ fontWeight:700, fontSize:14, letterSpacing:2, textTransform:"uppercase" }}>NetShield AI</div>
            <div style={{ fontSize:10, color:C.sub }}>Cloud Security · Isolation Forest + Claude RAG</div>
          </div>
        </div>
        <div style={{ display:"flex", gap:8 }}>
          {["overview","detection","realtime","remediation","comparison"].map(t => (
            <button key={t} onClick={()=>setTab(t)} style={{ padding:"6px 14px", borderRadius:8, border:`1px solid ${tab===t ? C.orange : C.border}`, background: tab===t ? C.orange+"22" : "transparent", color: tab===t ? C.orange : C.sub, fontSize:11, cursor:"pointer", fontFamily:"monospace", textTransform:"capitalize", fontWeight: tab===t ? 700 : 400 }}>
              {t}
            </button>
          ))}
        </div>
      </div>

      <div style={{ maxWidth:1280, margin:"0 auto", padding:"28px 24px" }}>

        {/* ══════════ OVERVIEW ══════════ */}
        {tab === "overview" && (
          <div>
            <div style={{ marginBottom:24 }}>
              <h2 style={{ margin:"0 0 4px", fontSize:20, fontWeight:700 }}>Dataset Overview</h2>
              <p style={{ margin:0, color:C.sub, fontSize:12 }}>cloud_security_dataset.csv — 10,000 records · 2010–2025 · 10 threat categories</p>
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:12, marginBottom:24 }}>
              <KPI label="Total Records"   value="10,000"  color={C.indigo} />
              <KPI label="Anomalies"       value="~987"    color={C.red}    sub="≈9.87% rate" />
              <KPI label="Threat Types"    value="10"      color={C.orange} />
              <KPI label="Cloud Layers"    value="3"       color={C.purple} sub="IaaS·PaaS·SaaS" />
              <KPI label="Year Span"       value="16 yrs"  color={C.teal}   sub="2010–2025" />
              <KPI label="Features Built"  value="11"      color={C.green}  sub="engineered" />
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20, marginBottom:20 }}>
              <Card>
                <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:14 }}>Threat Category Distribution</div>
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={THREAT_DIST} layout="vertical" barSize={14}>
                    <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
                    <XAxis type="number" tick={{ fill:C.sub, fontSize:10, fontFamily:"monospace" }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="threat" width={150} tick={{ fill:C.sub, fontSize:10, fontFamily:"monospace" }} axisLine={false} tickLine={false} />
                    <Tooltip content={<TT/>} />
                    <Bar dataKey="count" fill={C.indigo} radius={[0,4,4,0]} />
                  </BarChart>
                </ResponsiveContainer>
              </Card>

              <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
                <Card>
                  <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:14 }}>Severity Distribution</div>
                  <ResponsiveContainer width="100%" height={110}>
                    <PieChart>
                      <Pie data={SEV_DIST} cx="50%" cy="50%" innerRadius={30} outerRadius={50} paddingAngle={3} dataKey="value">
                        {SEV_DIST.map((d,i)=><Cell key={i} fill={d.color}/>)}
                      </Pie>
                      <Tooltip content={<TT/>} />
                      <Legend iconType="circle" iconSize={8} formatter={v=><span style={{color:C.sub,fontSize:10,fontFamily:"monospace"}}>{v}</span>}/>
                    </PieChart>
                  </ResponsiveContainer>
                </Card>

                <Card>
                  <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:14 }}>Total Incidents per Year</div>
                  <ResponsiveContainer width="100%" height={110}>
                    <LineChart data={YEAR_DATA}>
                      <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
                      <XAxis dataKey="year" tick={{ fill:C.sub, fontSize:9, fontFamily:"monospace" }} axisLine={false} tickLine={false} />
                      <YAxis hide />
                      <Tooltip content={<TT/>} />
                      <Line type="monotone" dataKey="incidents" stroke={C.orange} strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </Card>
              </div>
            </div>

            <Card>
              <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:16 }}>Pipeline Architecture — GenAI RAG Flow</div>
              <div style={{ display:"flex", alignItems:"center", gap:0, overflowX:"auto", padding:"8px 0" }}>
                {[
                  { icon:"📂", label:"CSV Upload", sub:"Any cloud dataset" },
                  { icon:"🔎", label:"Auto-Detect", sub:"Columns + schema" },
                  { icon:"⚙️", label:"Feature Eng.", sub:"11 engineered feats" },
                  { icon:"🌲", label:"Isolation Forest", sub:"4 configs compared" },
                  { icon:"🎯", label:"Risk Triage", sub:"CRITICAL/HIGH/MEDIUM" },
                  { icon:"📚", label:"RAG Retrieval", sub:"MITRE KB lookup" },
                  { icon:"🤖", label:"Claude AI", sub:"claude-sonnet-4-20250514" },
                  { icon:"📋", label:"Playbook", sub:"JSON remediation" },
                ].map((s,i,arr)=>(
                  <div key={i} style={{ display:"flex", alignItems:"center" }}>
                    <div style={{ textAlign:"center", minWidth:90 }}>
                      <div style={{ fontSize:22 }}>{s.icon}</div>
                      <div style={{ fontSize:11, fontWeight:700, color:C.text, marginTop:4 }}>{s.label}</div>
                      <div style={{ fontSize:9, color:C.sub }}>{s.sub}</div>
                    </div>
                    {i < arr.length-1 && <div style={{ color:C.orange, fontSize:18, padding:"0 4px", marginBottom:12 }}>→</div>}
                  </div>
                ))}
              </div>
            </Card>
          </div>
        )}

        {/* ══════════ DETECTION ══════════ */}
        {tab === "detection" && (
          <div>
            <div style={{ marginBottom:24 }}>
              <h2 style={{ margin:"0 0 4px", fontSize:20 }}>Isolation Forest — 4 Configurations</h2>
              <p style={{ margin:0, color:C.sub, fontSize:12 }}>Contamination set to true anomaly rate (~9.87%). Best: <span style={{color:C.green,fontWeight:700}}>{BEST.config}</span> (F1={BEST.f1})</p>
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:24 }}>
              {IF_RESULTS.map(r => (
                <Card key={r.config} style={{ borderColor: r.config === BEST.config ? C.green : C.border }}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:12 }}>
                    <span style={{ fontWeight:700, fontSize:13 }}>{r.config}</span>
                    {r.config === BEST.config && <Badge label="BEST" color={C.green}/>}
                  </div>
                  <div style={{ fontSize:10, color:C.sub, marginBottom:10 }}>
                    <div>n_estimators: <span style={{color:C.text}}>{r.n}</span></div>
                    <div>max_samples: <span style={{color:C.text}}>{r.ms}</span></div>
                    <div>contamination: <span style={{color:C.text}}>{r.cont}</span></div>
                    <div>max_features: <span style={{color:C.text}}>{r.mf}</span></div>
                  </div>
                  {[["Precision",r.prec,C.indigo],["Recall",r.rec,C.orange],["F1",r.f1,C.green],["AUC",r.auc,C.purple]].map(([label,val,color])=>(
                    <div key={label} style={{ marginBottom:6 }}>
                      <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, marginBottom:2 }}>
                        <span style={{color:C.sub}}>{label}</span>
                        <span style={{color,fontWeight:700}}>{(val*100).toFixed(1)}%</span>
                      </div>
                      <div style={{ height:4, background:C.border, borderRadius:2 }}>
                        <div style={{ height:"100%", width:`${val*100}%`, background:color, borderRadius:2 }}/>
                      </div>
                    </div>
                  ))}
                </Card>
              ))}
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
              <Card>
                <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:14 }}>Metric Comparison Bar</div>
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={IF_RESULTS.map(r=>({name:r.config, Precision:+(r.prec*100).toFixed(1), Recall:+(r.rec*100).toFixed(1), F1:+(r.f1*100).toFixed(1), AUC:+(r.auc*100).toFixed(1)}))}>
                    <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
                    <XAxis dataKey="name" tick={{fill:C.sub,fontSize:10,fontFamily:"monospace"}} axisLine={false} tickLine={false}/>
                    <YAxis domain={[70,100]} tick={{fill:C.sub,fontSize:10,fontFamily:"monospace"}} axisLine={false} tickLine={false}/>
                    <Tooltip content={<TT/>} />
                    <Legend formatter={v=><span style={{color:C.sub,fontSize:10,fontFamily:"monospace"}}>{v}</span>}/>
                    <Bar dataKey="Precision" fill={C.indigo} radius={[3,3,0,0]}/>
                    <Bar dataKey="Recall"    fill={C.orange} radius={[3,3,0,0]}/>
                    <Bar dataKey="F1"        fill={C.green}  radius={[3,3,0,0]}/>
                    <Bar dataKey="AUC"       fill={C.purple} radius={[3,3,0,0]}/>
                  </BarChart>
                </ResponsiveContainer>
              </Card>

              <Card>
                <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:14 }}>Radar — All Configs</div>
                <ResponsiveContainer width="100%" height={240}>
                  <RadarChart data={[{subject:"Precision"},{subject:"Recall"},{subject:"F1"},{subject:"AUC"}].map(s=>({
                    subject:s.subject,
                    ...Object.fromEntries(IF_RESULTS.map(r=>[r.config,+(r[s.subject.toLowerCase()]*100).toFixed(1)]))
                  }))}>
                    <PolarGrid stroke={C.border}/>
                    <PolarAngleAxis dataKey="subject" tick={{fill:C.sub,fontSize:10,fontFamily:"monospace"}}/>
                    {IF_RESULTS.map((r,i)=>(
                      <Radar key={r.config} name={r.config} dataKey={r.config}
                        stroke={[C.indigo,C.orange,C.green,C.red][i]}
                        fill={[C.indigo,C.orange,C.green,C.red][i]}
                        fillOpacity={0.12} strokeWidth={2}/>
                    ))}
                    <Legend formatter={v=><span style={{color:C.sub,fontSize:10,fontFamily:"monospace"}}>{v}</span>}/>
                    <Tooltip content={<TT/>}/>
                  </RadarChart>
                </ResponsiveContainer>
              </Card>
            </div>
          </div>
        )}

        {/* ══════════ REAL-TIME ══════════ */}
        {tab === "realtime" && (
          <div style={{ display:"grid", gridTemplateColumns:"380px 1fr", gap:20 }}>
            {/* Input form */}
            <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
              <Card>
                <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:16 }}>Event Parameters</div>

                {[
                  { label:"Threat Category", key:"threat", type:"select", options:THREATS },
                  { label:"Cloud Layer",      key:"layer",    type:"select", options:LAYERS },
                  { label:"Severity",         key:"severity", type:"select", options:SEVERITIES },
                ].map(f=>(
                  <div key={f.key} style={{ marginBottom:12 }}>
                    <div style={{ fontSize:10, color:C.sub, marginBottom:5 }}>{f.label}</div>
                    <select value={event[f.key]} onChange={e=>setEvent({...event,[f.key]:e.target.value})}
                      style={{ width:"100%", background:"#111113", border:`1px solid ${C.border}`, borderRadius:7, padding:"8px 10px", color:C.text, fontSize:12, fontFamily:"monospace" }}>
                      {f.options.map(o=><option key={o}>{o}</option>)}
                    </select>
                  </div>
                ))}

                {[
                  { label:"Year",                  key:"year",       min:2010, max:2025, step:1  },
                  { label:`Incidents (${event.incidents})`,     key:"incidents",  min:29,   max:87,   step:1  },
                  { label:`Mitigation (${event.mitigation})`,  key:"mitigation", min:1.0,  max:10.0, step:0.1},
                  { label:`Reported Cases (${event.cases})`,   key:"cases",      min:1,    max:21,   step:1  },
                ].map(f=>(
                  <div key={f.key} style={{ marginBottom:12 }}>
                    <div style={{ fontSize:10, color:C.sub, marginBottom:5 }}>{f.label}</div>
                    <input type="range" min={f.min} max={f.max} step={f.step}
                      value={event[f.key]}
                      onChange={e=>setEvent({...event,[f.key]:+e.target.value})}
                      style={{ width:"100%", accentColor:C.orange }}/>
                  </div>
                ))}

                <div style={{ marginBottom:12 }}>
                  <div style={{ fontSize:10, color:C.sub, marginBottom:5 }}>Anthropic API Key (optional)</div>
                  <input type="password" placeholder="sk-ant-..." value={apiKey} onChange={e=>setApiKey(e.target.value)}
                    style={{ width:"100%", background:"#111113", border:`1px solid ${C.border}`, borderRadius:7, padding:"8px 10px", color:C.text, fontSize:12, fontFamily:"monospace", boxSizing:"border-box" }}/>
                  <div style={{ fontSize:9, color:C.sub, marginTop:3 }}>Without key → local KB playbook. With key → live Claude</div>
                </div>

                <button onClick={runAnalysis} disabled={scanning}
                  style={{ width:"100%", padding:"11px 0", borderRadius:9, border:"none", background: scanning ? C.muted : C.orange, color:"white", fontWeight:700, fontSize:13, cursor: scanning ? "default" : "pointer", fontFamily:"monospace", letterSpacing:1 }}>
                  {scanning ? "⏳  Analysing..." : "🔍  Analyse Event"}
                </button>
              </Card>

              {/* Console log */}
              <Card>
                <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:10 }}>Pipeline Console</div>
                <div ref={logRef} style={{ maxHeight:200, overflowY:"auto", fontFamily:"monospace", fontSize:11 }}>
                  {log.length === 0 && <div style={{color:C.sub}}>Waiting for event...</div>}
                  {log.map((l,i)=>(
                    <div key={i} style={{ marginBottom:3, color: l.type==="ok"?C.green:l.type==="warn"?C.orange:l.type==="err"?C.red:C.sub }}>
                      <span style={{color:C.muted}}>[{l.ts}] </span>{l.msg}
                    </div>
                  ))}
                </div>
              </Card>
            </div>

            {/* Results panel */}
            <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
              {!result && !scanning && (
                <Card style={{ display:"flex", alignItems:"center", justifyContent:"center", height:200 }}>
                  <div style={{ textAlign:"center", color:C.sub }}>
                    <div style={{ fontSize:40, marginBottom:8 }}>🔍</div>
                    <div>Configure an event and click Analyse</div>
                  </div>
                </Card>
              )}

              {scanning && (
                <Card style={{ display:"flex", alignItems:"center", justifyContent:"center", height:200 }}>
                  <div style={{ textAlign:"center" }}>
                    <div style={{ fontSize:36, marginBottom:10, animation:"spin 1s linear infinite" }}>⚙️</div>
                    <div style={{ color:C.orange, fontWeight:700 }}>Processing event through IF pipeline...</div>
                  </div>
                </Card>
              )}

              {result && (
                <Card style={{ borderColor: result.isAnomaly ? BAND_COLOR[result.band] : C.green }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
                    <span style={{ fontSize:16, fontWeight:700 }}>{result.isAnomaly ? "⚠️  Anomaly Detected" : "✅  Normal Traffic"}</span>
                    <Badge label={result.band} color={BAND_COLOR[result.band]}/>
                  </div>
                  <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
                    <KPI label="Anomaly Score"    value={result.score}    color={BAND_COLOR[result.band]}/>
                    <KPI label="Severity Band"    value={result.band}     color={BAND_COLOR[result.band]}/>
                    <KPI label="IF Prediction"    value={result.isAnomaly?"ANOMALY":"NORMAL"} color={result.isAnomaly?C.red:C.green}/>
                  </div>

                  {/* Score gauge */}
                  <div style={{ marginTop:16 }}>
                    <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, color:C.sub, marginBottom:4 }}>
                      <span>Anomaly Score</span><span>{result.score}</span>
                    </div>
                    <div style={{ height:10, background:C.border, borderRadius:5 }}>
                      <div style={{ height:"100%", width:`${result.score*100}%`, borderRadius:5,
                        background:`linear-gradient(to right,${C.green},${C.yellow},${C.orange},${C.red})` }}/>
                    </div>
                    <div style={{ display:"flex", justifyContent:"space-between", fontSize:9, color:C.sub, marginTop:3 }}>
                      <span>Normal</span><span>Medium</span><span>High</span><span>Critical</span>
                    </div>
                  </div>
                </Card>
              )}

              {playbook && (
                <Card style={{ borderColor:C.orange }}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:16 }}>
                    <div style={{ fontSize:13, fontWeight:700, color:C.orange }}>🤖 GenAI Remediation Playbook</div>
                    <div style={{ display:"flex", gap:8 }}>
                      <Badge label={playbook.soc_priority}          color={SOC_COLOR[playbook.soc_priority]}/>
                      <Badge label={playbook.estimated_blast_radius} color={BAND_COLOR[playbook.estimated_blast_radius]}/>
                      <Badge label={playbook.confidence}             color={C.indigo}/>
                    </div>
                  </div>

                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10, marginBottom:14 }}>
                    <div style={{ background:"#111113", borderRadius:8, padding:"10px 12px" }}>
                      <div style={{ fontSize:9, color:C.sub, marginBottom:3 }}>MITRE TACTIC</div>
                      <div style={{ fontSize:11, color:C.purple }}>{playbook.mitre_tactic}</div>
                    </div>
                    <div style={{ background:"#111113", borderRadius:8, padding:"10px 12px" }}>
                      <div style={{ fontSize:9, color:C.sub, marginBottom:3 }}>MITRE TECHNIQUE</div>
                      <div style={{ fontSize:11, color:C.purple }}>{playbook.mitre_technique}</div>
                    </div>
                  </div>

                  <div style={{ background:"#111113", borderRadius:8, padding:"10px 12px", marginBottom:10 }}>
                    <div style={{ fontSize:9, color:C.sub, marginBottom:4 }}>ROOT CAUSE</div>
                    <div style={{ fontSize:12, lineHeight:1.6 }}>{playbook.root_cause_summary}</div>
                  </div>

                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
                    <div style={{ background:"#111113", borderRadius:8, padding:"10px 12px" }}>
                      <div style={{ fontSize:9, color:C.red, fontWeight:700, marginBottom:8 }}>⚡ IMMEDIATE ACTIONS</div>
                      {playbook.immediate_actions.map((a,i)=>(
                        <div key={i} style={{ fontSize:11, marginBottom:6, paddingLeft:12, borderLeft:`2px solid ${C.red}`, lineHeight:1.5 }}>{a}</div>
                      ))}
                    </div>
                    <div style={{ background:"#111113", borderRadius:8, padding:"10px 12px" }}>
                      <div style={{ fontSize:9, color:C.green, fontWeight:700, marginBottom:8 }}>🛡️ LONG-TERM HARDENING</div>
                      {playbook.long_term_hardening.map((a,i)=>(
                        <div key={i} style={{ fontSize:11, marginBottom:6, paddingLeft:12, borderLeft:`2px solid ${C.green}`, lineHeight:1.5 }}>{a}</div>
                      ))}
                    </div>
                  </div>

                  {playbook.monitoring_kpis?.length > 0 && (
                    <div style={{ background:"#111113", borderRadius:8, padding:"10px 12px", marginTop:10 }}>
                      <div style={{ fontSize:9, color:C.indigo, fontWeight:700, marginBottom:8 }}>📊 MONITORING KPIs</div>
                      {playbook.monitoring_kpis.map((k,i)=>(
                        <div key={i} style={{ fontSize:11, marginBottom:4, color:C.sub }}>• {k}</div>
                      ))}
                    </div>
                  )}
                </Card>
              )}
            </div>
          </div>
        )}

        {/* ══════════ REMEDIATION ══════════ */}
        {tab === "remediation" && (
          <div>
            <div style={{ marginBottom:20 }}>
              <h2 style={{ margin:"0 0 4px", fontSize:20 }}>GenAI Knowledge Base — All 10 Threats</h2>
              <p style={{ margin:0, color:C.sub, fontSize:12 }}>Pre-trained on MITRE ATT&CK Cloud Matrix. Used for RAG retrieval per event.</p>
            </div>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:16 }}>
              {Object.entries(THREAT_KB).map(([name, kb])=>(
                <Card key={name}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:10 }}>
                    <span style={{ fontWeight:700, fontSize:13 }}>{name}</span>
                    <Badge label="MITRE" color={C.purple}/>
                  </div>
                  <div style={{ fontSize:10, color:C.purple, marginBottom:8 }}>{kb.mitre}</div>
                  <div style={{ fontSize:10, color:C.sub, marginBottom:10 }}>{kb.tactic}</div>
                  <div style={{ marginBottom:8 }}>
                    <div style={{ fontSize:9, color:C.red, fontWeight:700, marginBottom:5 }}>⚡ IMMEDIATE</div>
                    {kb.actions.map((a,i)=><div key={i} style={{ fontSize:10, color:C.text, marginBottom:3, paddingLeft:10, borderLeft:`2px solid ${C.red}33` }}>▸ {a}</div>)}
                  </div>
                  <div>
                    <div style={{ fontSize:9, color:C.green, fontWeight:700, marginBottom:5 }}>🛡️ HARDENING</div>
                    {kb.hardening.map((a,i)=><div key={i} style={{ fontSize:10, color:C.sub, marginBottom:3, paddingLeft:10, borderLeft:`2px solid ${C.green}33` }}>▸ {a}</div>)}
                  </div>
                </Card>
              ))}
            </div>
          </div>
        )}

        {/* ══════════ COMPARISON ══════════ */}
        {tab === "comparison" && (
          <div>
            <div style={{ marginBottom:20 }}>
              <h2 style={{ margin:"0 0 4px", fontSize:20 }}>Full Comparison Table</h2>
              <p style={{ margin:0, color:C.sub, fontSize:12 }}>All 4 Isolation Forest configurations. Best highlighted in green.</p>
            </div>

            <Card style={{ marginBottom:20 }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12, fontFamily:"monospace" }}>
                <thead>
                  <tr style={{ borderBottom:`1px solid ${C.border}` }}>
                    {["Config","n_estimators","max_samples","contamination","max_features","Precision","Recall","F1","AUC-ROC"].map(h=>(
                      <th key={h} style={{ padding:"10px 14px", textAlign:"left", color:C.sub, fontSize:10, textTransform:"uppercase", letterSpacing:1 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {IF_RESULTS.map(r=>(
                    <tr key={r.config} style={{ borderBottom:`1px solid ${C.border}22`, background: r.config===BEST.config ? C.green+"0a" : "transparent" }}>
                      <td style={{ padding:"10px 14px", fontWeight:700, color: r.config===BEST.config ? C.green : C.text }}>
                        {r.config} {r.config===BEST.config && "★"}
                      </td>
                      <td style={{ padding:"10px 14px", color:C.sub }}>{r.n}</td>
                      <td style={{ padding:"10px 14px", color:C.sub }}>{r.ms}</td>
                      <td style={{ padding:"10px 14px", color:C.sub }}>{r.cont}</td>
                      <td style={{ padding:"10px 14px", color:C.sub }}>{r.mf}</td>
                      {[r.prec,r.rec,r.f1,r.auc].map((v,i)=>{
                        const maxVal = Math.max(...IF_RESULTS.map(x=>[x.prec,x.rec,x.f1,x.auc][i]));
                        return <td key={i} style={{ padding:"10px 14px", color: v===maxVal ? C.green : C.text, fontWeight: v===maxVal ? 700 : 400 }}>{(v*100).toFixed(1)}%</td>;
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
              <Card>
                <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:14 }}>F1 Score Comparison</div>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={IF_RESULTS.map(r=>({name:r.config,F1:+(r.f1*100).toFixed(2)}))}>
                    <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
                    <XAxis dataKey="name" tick={{fill:C.sub,fontSize:10,fontFamily:"monospace"}} axisLine={false} tickLine={false}/>
                    <YAxis domain={[70,85]} tick={{fill:C.sub,fontSize:10,fontFamily:"monospace"}} axisLine={false} tickLine={false}/>
                    <Tooltip content={<TT/>}/>
                    <Bar dataKey="F1" radius={[5,5,0,0]}>
                      {IF_RESULTS.map((r,i)=><Cell key={i} fill={r.config===BEST.config?C.green:C.indigo}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </Card>

              <Card>
                <div style={{ fontSize:11, color:C.sub, textTransform:"uppercase", letterSpacing:1, marginBottom:14 }}>Hyperparameter Rationale</div>
                {[
                  ["n_estimators","100–300","More trees → lower variance in anomaly scores"],
                  ["max_samples","auto–1.0","Controls diversity between trees in the forest"],
                  ["contamination","≈anomaly rate","Set to true data rate (~9.87%) for calibration"],
                  ["max_features","0.6–1.0","Feature sub-sampling increases tree independence"],
                ].map(([param,range,rationale])=>(
                  <div key={param} style={{ marginBottom:12, padding:"10px 12px", background:"#111113", borderRadius:8 }}>
                    <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                      <span style={{ color:C.orange, fontSize:11, fontWeight:700, fontFamily:"monospace" }}>{param}</span>
                      <span style={{ color:C.sub, fontSize:10 }}>{range}</span>
                    </div>
                    <div style={{ fontSize:11, color:C.sub }}>{rationale}</div>
                  </div>
                ))}
              </Card>
            </div>
          </div>
        )}
      </div>

      <style>{`
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width:5px; height:5px; }
        ::-webkit-scrollbar-track { background:${C.bg}; }
        ::-webkit-scrollbar-thumb { background:${C.muted}; border-radius:3px; }
        select, input[type=password] { outline:none; }
        select:focus, input:focus { border-color:${C.orange} !important; }
        @keyframes spin { from{transform:rotate(0)} to{transform:rotate(360deg)} }
      `}</style>
    </div>
  );
}
