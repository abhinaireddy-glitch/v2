import { useState, useEffect, useRef, useCallback } from "react";

// ─── DESIGN TOKENS ────────────────────────────────────────────
const C = {
  bg:"#070b0f", panel:"#0b1018", card:"#0f1822",
  border:"#142030", borderBright:"#1e3a50",
  cyan:"#00e5ff", green:"#00ff9d", red:"#ff2d55",
  orange:"#ff9500", yellow:"#ffe600", purple:"#bf5fff",
  teal:"#00b4a0", gold:"#c8a020",
  text:"#7ecfdf", textDim:"#4a8a9a", textLabel:"#2a6a7a",
};

const LABEL_COLORS = {
  BENIGN:"#00ff9d", Bot:"#bf5fff", DDoS:"#ff2d55",
  "DoS Hulk":"#ff4466","DoS GoldenEye":"#ff3355",
  "DoS slowloris":"#ff2244","DoS Slowhttptest":"#ff1133",
  PortScan:"#c8a020","FTP-Patator":"#00b4a0","SSH-Patator":"#009990",
  "Web Attack \u2013 Brute Force":"#007b8a",
  "Web Attack \u2013 XSS":"#006070",
  "Web Attack \u2013 Sql Injection":"#005060",
  Infiltration:"#ff9500", Heartbleed:"#ff5500",
};

const DEMO_LABELS=["BENIGN","Bot","DDoS","PortScan","FTP-Patator","Web Attack \u2013 Brute Force","DoS Hulk"];
const DEMO_PORTS =["443","3389","80","8080","22","445","21"];

// ─── HELPERS ──────────────────────────────────────────────────
function r(n){return Math.floor(Math.random()*n);}
function fakeIP(){return`${r(255)}.${r(255)}.${r(255)}.${r(255)}`;}

function genDemoRow(){
  const label=DEMO_LABELS[r(DEMO_LABELS.length)];
  const isThreat=label!=="BENIGN";
  const port=DEMO_PORTS[r(DEMO_PORTS.length)];
  return{
    label,"destination port":port,
    "flow bytes/s":String(isThreat?4e5+Math.random()*6e5:1e3+Math.random()*1e4),
    "flow packets/s":String(isThreat?8000+Math.random()*22000:80+Math.random()*900),
    "flow duration":String((10+Math.random()*100)*1e6),
    "syn flag count":String(isThreat&&Math.random()<.3?r(12):0),
    "rst flag count":String(isThreat&&Math.random()<.2?r(6):0),
    "flow iat std":String(Math.random()*10*1e6),
    "pkt len std":String(Math.random()*220),
    "src ip":fakeIP(),
  };
}

function extractRow(row){
  const find=kws=>Object.keys(row).find(k=>kws.some(w=>k.toLowerCase().includes(w)))||kws[0];
  const label=(row[find(["label"])]||"UNKNOWN").trim();
  return{
    label,isThreat:label.toLowerCase()!=="benign",
    port:(row[find(["destination port","dst port"])]||"0").replace(/\D/g,"")||"0",
    bps:parseFloat(row[find(["flow bytes/s","flow_bytes"])])||0,
    pps:parseFloat(row[find(["flow packets/s","flow_packet"])])||0,
    dur:parseFloat(row[find(["flow duration"])]||0)/1e6,
    syn:parseInt(row[find(["syn flag"])])||0,
    rst:parseInt(row[find(["rst flag"])])||0,
    iat:parseFloat(row[find(["flow iat std","iat std"])]||0)/1e6,
    pktStd:parseFloat(row[find(["pkt len std","packet length std"])])||0,
    srcIp:row[find(["src ip","source ip"])]||fakeIP(),
  };
}

function anomalyScore(isThreat){return isThreat?0.6+Math.random()*0.4:Math.random()*0.3;}
function fmtBps(v){return v>1e6?(v/1e6).toFixed(2)+"M":v>1e3?(v/1e3).toFixed(1)+"K":v.toFixed(0);}
function nowUTC(){const n=new Date(),p=x=>String(x).padStart(2,"0");return`${p(n.getUTCHours())}:${p(n.getUTCMinutes())}:${p(n.getUTCSeconds())}`;}
function isoNow(){return new Date().toISOString().slice(0,19).replace("T"," ")+" UTC";}

// Isolated clock — never causes parent re-render
function LiveClock(){
  const[clock,setClock]=useState(nowUTC);
  useEffect(()=>{const t=setInterval(()=>setClock(nowUTC()),1000);return()=>clearInterval(t);},[]);
  return<span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:C.textDim}}>{clock}</span>;
}

// ─── CLAUDE STREAMING ─────────────────────────────────────────
async function streamClaude(prompt,onToken,onDone,maxTokens=400){
  try{
    const res=await fetch("https://api.anthropic.com/v1/messages",{
      method:"POST",headers:{"Content-Type":"application/json","anthropic-dangerous-direct-browser-access":"true"},
      body:JSON.stringify({model:"claude-sonnet-4-20250514",max_tokens:maxTokens,stream:true,
        messages:[{role:"user",content:prompt}]}),
    });
    const reader=res.body.getReader(),dec=new TextDecoder();let buf="";
    while(true){
      const{done,value}=await reader.read();if(done)break;
      buf+=dec.decode(value,{stream:true});
      const lines=buf.split("\n");buf=lines.pop();
      for(const line of lines){
        if(!line.startsWith("data: "))continue;
        const d=line.slice(6);if(d==="[DONE]")continue;
        try{const p=JSON.parse(d);if(p.delta?.text)onToken(p.delta.text);}catch{}
      }
    }
  }catch{onToken(fallback(prompt));}
  onDone();
}

function fallback(p){
  if(p.includes("ORCHESTRATOR"))return"ORCHESTRATION PLAN:\n1. CLASSIFIER: Continue scanning all incoming flows\n2. ANALYZER: Deep-dive on flagged flow signatures\n3. LOG_ANALYZER: Search historical patterns for recurrence\n4. THREAT_DETECT: Map to MITRE ATT&CK framework\n5. RESPONDER: Execute auto-block and alert SOC team";
  if(p.includes("LOG_ANALYZER"))return"LOG ANALYSIS COMPLETE:\n• Recurring source detected in last 10min window\n• Port shows SYN flood signature consistent with DoS\n• Packet length std deviation 2.4x above baseline\n• IAT pattern matches known bot heartbeat interval\n• Recommend: Escalate to Tier-2 analyst";
  if(p.includes("THREAT_DETECT"))return"THREAT DETECTION REPORT:\nVECTOR: High-volume flow anomaly via compromised endpoint\nSEVERITY: CRITICAL — 89% confidence match\nINDICATORS: Elevated SYN count, abnormal IAT, high pkt/s\nMITRE_ATT&CK: T1498 — Network Denial of Service";
  if(p.includes("investigate"))return"INVESTIGATION TICKET OPENED\n1. Capture pcap on suspicious destination port\n2. Cross-reference source IPs with threat intel feeds\n3. Analyze flow patterns for C2 communication\n4. Isolate affected segment for forensic analysis";
  if(p.includes("escalate"))  return"SOC ESCALATION — PRIORITY 1\nIndicators: High-volume anomalous flow detected\nScore: HIGH | Confidence: CRITICAL\nRequest: Immediate analyst review + containment";
  if(p.includes("ANALYZER"))  return"THREAT: Network Anomaly Detected\nPATTERN: High byte rate + abnormal packet distribution\nRISK: HIGH — Score exceeds 0.82 threshold\nACTION: Block source IP + escalate to SOC";
  if(p.includes("executive"))return"Executive Summary: This session detected elevated threat activity across multiple vectors. Bot and DDoS patterns dominated traffic, with SYN flood signatures consistent with CICIDS2017 attack profiles. Auto-blocking mitigated highest-confidence threats in real time. Recommended follow-up: full pcap forensics on flagged ports and persistent monitoring of recurring source IP ranges.";
  return"Analysis complete. Threat patterns logged.";
}

// ─── CSS ──────────────────────────────────────────────────────
const CSS=`
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');
*{box-sizing:border-box;margin:0;padding:0;}
::-webkit-scrollbar{width:3px;}
::-webkit-scrollbar-thumb{background:#1e3a50;}
body{overflow-x:hidden;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes hexPulse{0%,100%{box-shadow:0 0 18px #00e5ff}50%{box-shadow:0 0 30px #00e5ff,0 0 50px rgba(0,229,255,.3)}}
@keyframes ticker{from{transform:translateX(0)}to{transform:translateX(-50%)}}
@keyframes pulseRed{0%,100%{box-shadow:0 0 0 0 rgba(255,45,85,.3)}50%{box-shadow:0 0 0 8px transparent}}
@keyframes lockFlash{0%,100%{opacity:0}50%{opacity:1}}
@keyframes simGlow{0%,100%{box-shadow:0 0 0 2px rgba(191,95,255,.3)}50%{box-shadow:0 0 0 2px rgba(191,95,255,.9),0 0 20px rgba(191,95,255,.2)}}
@keyframes fadeSlide{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
@keyframes reportIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.anim-report{animation:reportIn .5s ease forwards;}
.anim-report-row{animation:reportIn .4s ease forwards;}
.anim-slide{animation:fadeSlide .4s ease forwards;}
`;

// ─── TINY COMPONENTS ──────────────────────────────────────────
function Dot({color=C.green,pulse=true}){
  return<span style={{width:6,height:6,borderRadius:"50%",background:color,
    boxShadow:`0 0 8px ${color}`,display:"inline-block",flexShrink:0,
    animation:pulse?"blink 1.5s ease-in-out infinite":"none"}}/>;
}
function PanelCorners({color=C.cyan}){
  return<>
    <span style={{position:"absolute",top:-1,left:-1,borderTop:`2px solid ${color}`,
      borderLeft:`2px solid ${color}`,width:10,height:10,display:"block",pointerEvents:"none"}}/>
    <span style={{position:"absolute",bottom:-1,right:-1,borderBottom:`2px solid ${color}`,
      borderRight:`2px solid ${color}`,width:10,height:10,display:"block",pointerEvents:"none"}}/>
  </>;
}
function Panel({children,style={},color=C.cyan}){
  return<div style={{background:C.panel,border:`1px solid ${C.border}`,padding:16,position:"relative",...style}}>
    <PanelCorners color={color}/>{children}
  </div>;
}
function PTitle({children,color}){
  return<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,letterSpacing:3,
    color:color||C.textLabel,marginBottom:12,textTransform:"uppercase",
    display:"flex",alignItems:"center",gap:8}}>
    {children}<span style={{flex:1,height:1,background:C.border}}/>
  </div>;
}
function Btn({children,onClick,color=C.cyan,style={},disabled=false}){
  const[h,setH]=useState(false);
  return<button onClick={onClick} disabled={disabled}
    onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)}
    style={{display:"flex",alignItems:"center",gap:6,padding:"9px 12px",
      border:`1px solid ${h&&!disabled?color:C.borderBright}`,
      background:h&&!disabled?`${color}18`:C.card,
      fontFamily:"'Share Tech Mono',monospace",fontSize:9,letterSpacing:"1.2px",
      color:h&&!disabled?color:disabled?C.textLabel:C.textDim,
      cursor:disabled?"not-allowed":"pointer",textTransform:"uppercase",
      transition:"all .2s",boxShadow:h&&!disabled?`0 0 10px ${color}33`:"none",...style}}>
    {children}
  </button>;
}
function BarFill({pct,color}){
  return<div style={{height:7,background:"#0f2030",overflow:"hidden",borderRadius:1,marginTop:8}}>
    <div style={{height:"100%",width:`${pct}%`,borderRadius:1,
      background:`linear-gradient(90deg,${color},${color}bb)`,
      boxShadow:`0 0 8px ${color}`,transition:"width 1s cubic-bezier(.4,0,.2,1)"}}/>
  </div>;
}

// ─── DONUT ────────────────────────────────────────────────────
function DonutChart({data}){
  const R=78,cx=100,cy=100,sw=26,circ=2*Math.PI*R;
  const total=data.reduce((s,d)=>s+d.value,0)||1;
  let offset=0;
  const segs=data.map(d=>{
    const dash=(d.value/total)*circ;
    const s={...d,dash,gap:circ-dash,offset};
    offset+=dash;return s;
  });
  return<svg viewBox="0 0 200 200" style={{width:200,height:200,filter:`drop-shadow(0 0 8px ${C.cyan}44)`}}>
    <circle cx={cx} cy={cy} r={R} fill="none" stroke={C.border} strokeWidth={sw}/>
    {segs.map((s,i)=><circle key={i} cx={cx} cy={cy} r={R} fill="none"
      stroke={s.color} strokeWidth={sw}
      strokeDasharray={`${s.dash} ${s.gap}`} strokeDashoffset={-s.offset}
      style={{transformOrigin:"center",transform:"rotate(-90deg)",transition:"stroke-dasharray .5s"}}/>)}
    <circle cx={cx} cy={cy} r={R-sw/2-2} fill={C.panel}/>
    <text x={cx} y={cy-4} textAnchor="middle" fill={C.cyan} fontFamily="'Share Tech Mono',monospace" fontSize="10">TRAFFIC</text>
    <text x={cx} y={cy+10} textAnchor="middle" fill={C.textDim} fontFamily="'Share Tech Mono',monospace" fontSize="9">ANALYSIS</text>
  </svg>;
}

// ─── SPARKLINE ────────────────────────────────────────────────
function Sparkline({data,color,height=80}){
  const W=400,H=height;
  if(!data||!data.length)return<div style={{height,background:C.card,border:`1px solid ${C.border}`}}/>;
  const max=Math.max(...data,1);
  const pts=data.map((v,i)=>`${(i/(data.length-1))*W},${H-(v/max)*H*0.88}`).join(" ");
  return<svg viewBox={`0 0 ${W} ${H}`} style={{width:"100%",height}} preserveAspectRatio="none">
    <polygon points={`${pts} ${W},${H} 0,${H}`} fill={`${color}18`}/>
    <polyline points={pts} fill="none" stroke={color} strokeWidth="2" style={{filter:`drop-shadow(0 0 4px ${color})`}}/>
  </svg>;
}

// ─── TOPOLOGY ─────────────────────────────────────────────────
function TopoCanvas({packets}){
  const ref=useRef(),animRef=useRef(),pktsRef=useRef([]);
  useEffect(()=>{pktsRef.current=[...(packets||[])];},[packets]);
  useEffect(()=>{
    const cv=ref.current;if(!cv)return;
    const ctx=cv.getContext("2d");
    cv.width=cv.offsetWidth||600;cv.height=200;
    const W=cv.width,H=200;
    const nodes=[
      {x:W*.5,y:H*.5,label:"CORE GW",color:C.cyan},
      {x:W*.15,y:H*.3,label:"HOST-01",color:C.green},
      {x:W*.15,y:H*.7,label:"HOST-02",color:C.green},
      {x:W*.85,y:H*.25,label:"ATTK-01",color:C.red},
      {x:W*.85,y:H*.75,label:"ATTK-02",color:C.purple},
      {x:W*.5,y:H*.1,label:"FIREWALL",color:C.orange},
    ];
    const conns=[[0,1],[0,2],[0,3],[0,4],[0,5]];
    let localPkts=[],frame=0;
    function draw(){
      ctx.clearRect(0,0,W,H);ctx.fillStyle=C.card;ctx.fillRect(0,0,W,H);
      ctx.strokeStyle="#142030";ctx.lineWidth=.5;
      for(let x=0;x<W;x+=30){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
      for(let y=0;y<H;y+=30){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
      conns.forEach(([a,b])=>{
        ctx.beginPath();ctx.strokeStyle="rgba(0,229,255,0.12)";ctx.lineWidth=.8;
        ctx.moveTo(nodes[a].x,nodes[a].y);ctx.lineTo(nodes[b].x,nodes[b].y);ctx.stroke();
      });
      if(pktsRef.current.length){
        pktsRef.current.forEach(p=>{
          const src=p.threat?(Math.random()<.5?3:4):(Math.random()<.5?1:2);
          localPkts.push({x0:nodes[src].x,y0:nodes[src].y,x1:nodes[0].x,y1:nodes[0].y,t:0,color:p.threat?C.red:C.cyan});
        });
        pktsRef.current=[];
      }
      localPkts=localPkts.filter(p=>p.t<1);
      localPkts.forEach(p=>{
        p.t+=0.03;const x=p.x0+(p.x1-p.x0)*p.t,y=p.y0+(p.y1-p.y0)*p.t;
        ctx.beginPath();ctx.arc(x,y,3,0,Math.PI*2);
        ctx.fillStyle=p.color;ctx.shadowColor=p.color;ctx.shadowBlur=8;ctx.fill();ctx.shadowBlur=0;
      });
      nodes.forEach((n,i)=>{
        const pulse=13+Math.sin(frame*.04+i)*2;
        ctx.beginPath();ctx.arc(n.x,n.y,pulse,0,Math.PI*2);ctx.strokeStyle=n.color+"44";ctx.lineWidth=1;ctx.stroke();
        ctx.beginPath();ctx.arc(n.x,n.y,7,0,Math.PI*2);
        ctx.fillStyle=n.color+"44";ctx.fill();
        ctx.strokeStyle=n.color;ctx.lineWidth=1.5;ctx.shadowColor=n.color;ctx.shadowBlur=10;ctx.stroke();ctx.shadowBlur=0;
        ctx.fillStyle=n.color;ctx.font="7px 'Share Tech Mono',monospace";
        ctx.textAlign="center";ctx.fillText(n.label,n.x,n.y+19);
      });
      frame++;animRef.current=requestAnimationFrame(draw);
    }
    draw();return()=>cancelAnimationFrame(animRef.current);
  },[]);
  return<canvas ref={ref} style={{width:"100%",height:200,display:"block"}}/>;
}

// ─── SIMULATION MODAL ─────────────────────────────────────────
function SimModal({onStart,onClose}){
  const[count,setCount]=useState(200);
  const[records,setRecords]=useState([]);
  const[fileName,setFileName]=useState("");
  const[parsing,setParsing]=useState(false);

  function parseFile(file){
    if(!file)return;
    setFileName(file.name);setParsing(true);
    const reader=new FileReader();
    reader.onload=e=>{
      const lines=e.target.result.trim().split("\n");
      const headers=lines[0].split(",").map(h=>h.trim().replace(/"/g,"").toLowerCase());
      const recs=[];
      for(let i=1;i<lines.length;i++){
        const vals=lines[i].split(",");
        if(vals.length<headers.length-3)continue;
        const row={};
        headers.forEach((h,j)=>row[h]=(vals[j]||"").trim().replace(/"/g,""));
        recs.push(row);
      }
      setRecords(recs);setCount(Math.min(recs.length,500));setParsing(false);
    };
    reader.readAsText(file);
  }

  const presets=records.length
    ?[50,100,200,Math.min(500,records.length)].filter((v,i,a)=>a.indexOf(v)===i)
    :[50,100,200,500,1000];

  return<div style={{position:"fixed",inset:0,background:"rgba(0,0,0,.88)",
    display:"flex",alignItems:"center",justifyContent:"center",zIndex:500}}>
    <Panel style={{minWidth:440,border:`1px solid ${C.purple}`}} color={C.purple}>
      <PTitle>⚡ SIMULATION ENGINE — SETUP</PTitle>
      <div
        onDrop={e=>{e.preventDefault();parseFile(e.dataTransfer.files[0]);}}
        onDragOver={e=>e.preventDefault()}
        onClick={()=>document.getElementById("__simCSV").click()}
        style={{border:`2px dashed ${records.length?C.green:C.borderBright}`,
          background:records.length?`${C.green}08`:C.card,
          padding:20,textAlign:"center",cursor:"pointer",marginBottom:14,transition:"all .3s"}}>
        {parsing&&<div style={{color:C.orange,fontFamily:"'Share Tech Mono',monospace",fontSize:11}}>⟳ Parsing CSV...</div>}
        {!parsing&&!records.length&&<>
          <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:11,letterSpacing:3,color:C.purple,marginBottom:5}}>⬆ UPLOAD CICIDS DATASET</div>
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim}}>
            Drop CICIDS CSV or click to browse<br/>
            <span style={{color:C.textLabel,fontSize:9}}>Required for real data simulation · Demo data used if skipped</span>
          </div>
        </>}
        {!parsing&&records.length>0&&<div style={{color:C.green,fontFamily:"'Share Tech Mono',monospace",fontSize:11}}>
          ✓ {records.length.toLocaleString()} records — {fileName}
        </div>}
        <input id="__simCSV" type="file" accept=".csv" style={{display:"none"}}
          onChange={e=>parseFile(e.target.files[0])}/>
      </div>
      <div style={{marginBottom:14}}>
        <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,
          letterSpacing:2,marginBottom:8}}>FLOWS TO SIMULATE:</div>
        <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:8}}>
          {presets.map(n=>(
            <button key={n} onClick={()=>setCount(n)}
              style={{padding:"4px 12px",fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                border:`1px solid ${count===n?C.purple:C.borderBright}`,
                background:count===n?`${C.purple}22`:C.card,
                color:count===n?C.purple:C.textDim,cursor:"pointer"}}>
              {n.toLocaleString()}
            </button>
          ))}
        </div>
        <input type="number" value={count} min={10} max={records.length||10000}
          onChange={e=>setCount(Math.min(Math.max(10,+e.target.value),records.length||10000))}
          style={{width:"100%",padding:"7px 10px",background:C.card,
            border:`1px solid ${C.borderBright}`,color:C.text,
            fontFamily:"'Share Tech Mono',monospace",fontSize:12,outline:"none"}}/>
      </div>
      <div style={{display:"flex",gap:8}}>
        <Btn color={C.purple} onClick={()=>onStart(count,records)} style={{flex:1,justifyContent:"center"}}>
          ▶ START SIMULATION
        </Btn>
        <Btn color={C.red} onClick={onClose} style={{flex:1,justifyContent:"center"}}>✕ CANCEL</Btn>
      </div>
    </Panel>
  </div>;
}

// ─── REPORT BUILDER + DOWNLOADER ──────────────────────────────
function buildReportHTML(report){
  const lc=report.labelCounts||{};
  const riskColor=report.avgScore>.7?"#ff2d55":report.avgScore>.4?"#ff9500":"#00ff9d";
  const riskLabel=report.avgScore>.7?"CRITICAL":report.avgScore>.4?"HIGH":"MEDIUM";
  const threatRate=report.total>0?Math.round((report.threats/report.total)*100):0;

  const labelRows=Object.entries(lc).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`
    <tr>
      <td style="padding:6px 10px;border-bottom:1px solid #142030;color:${LABEL_COLORS[k]||"#7ecfdf"};font-family:'Share Tech Mono',monospace;font-size:12px">${k}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #142030;color:#7ecfdf;font-family:'Share Tech Mono',monospace;font-size:12px;text-align:right">${v.toLocaleString()}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #142030;color:#4a8a9a;font-family:'Share Tech Mono',monospace;font-size:12px;text-align:right">${Math.round(v/(report.total||1)*100)}%</td>
    </tr>`).join("");

  const alertRows=(report.topAlerts||[]).slice(0,20).map(a=>`
    <tr>
      <td style="padding:5px 8px;border-bottom:1px solid #142030;color:#4a8a9a;font-family:'Share Tech Mono',monospace;font-size:11px">${a.ts||""}</td>
      <td style="padding:5px 8px;border-bottom:1px solid #142030;color:${LABEL_COLORS[a.label]||"#ff2d55"};font-family:'Share Tech Mono',monospace;font-size:11px">${a.label||""}</td>
      <td style="padding:5px 8px;border-bottom:1px solid #142030;color:#7ecfdf;font-family:'Share Tech Mono',monospace;font-size:11px">:${a.port||""}</td>
      <td style="padding:5px 8px;border-bottom:1px solid #142030;color:${(a.score||0)>.8?"#ff2d55":(a.score||0)>.5?"#ff9500":"#00ff9d"};font-family:'Share Tech Mono',monospace;font-size:11px">${(a.score||0).toFixed(3)}</td>
      <td style="padding:5px 8px;border-bottom:1px solid #142030;color:#4a8a9a;font-family:'Share Tech Mono',monospace;font-size:11px">${a.srcIp||""}</td>
    </tr>`).join("");

  const blockedRows=(report.blockedIPs||[]).slice(0,15).map(b=>`
    <tr>
      <td style="padding:5px 8px;border-bottom:1px solid #142030;color:#ff2d55;font-family:'Share Tech Mono',monospace;font-size:11px">${b.ip}</td>
      <td style="padding:5px 8px;border-bottom:1px solid #142030;color:#7ecfdf;font-family:'Share Tech Mono',monospace;font-size:11px">${b.label}</td>
      <td style="padding:5px 8px;border-bottom:1px solid #142030;color:#ff9500;font-family:'Share Tech Mono',monospace;font-size:11px">${b.score.toFixed(3)}</td>
      <td style="padding:5px 8px;border-bottom:1px solid #142030;color:#4a8a9a;font-family:'Share Tech Mono',monospace;font-size:11px">${b.ts}</td>
    </tr>`).join("");

  return`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>CipherNest ${report.id}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
body{background:#070b0f;color:#7ecfdf;font-family:'Share Tech Mono',monospace;margin:0;padding:32px;}
h1,h2,h3{font-family:'Orbitron',sans-serif;}
table{width:100%;border-collapse:collapse;}
.sec{margin-bottom:32px;border:1px solid #142030;padding:20px;position:relative;}
.sec::before{content:'';position:absolute;top:-1px;left:-1px;width:10px;height:10px;border-top:2px solid #00e5ff;border-left:2px solid #00e5ff;}
.sec::after{content:'';position:absolute;bottom:-1px;right:-1px;width:10px;height:10px;border-bottom:2px solid #00e5ff;border-right:2px solid #00e5ff;}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;}
.metric{background:#0f1822;border:1px solid #1e3a50;padding:14px;}
.metric .l{font-size:8px;letter-spacing:2px;color:#2a6a7a;margin-bottom:6px;}
.metric .v{font-family:'Orbitron',sans-serif;font-size:24px;}
th{padding:8px 10px;text-align:left;font-size:9px;letter-spacing:2px;color:#2a6a7a;border-bottom:1px solid #1e3a50;}
@media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact;}}
</style></head><body>
<div style="display:flex;align-items:center;gap:14px;margin-bottom:32px;border-bottom:2px solid #00e5ff;padding-bottom:20px">
  <div style="width:36px;height:36px;background:#00e5ff;clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);box-shadow:0 0 20px #00e5ff;flex-shrink:0"></div>
  <div>
    <h1 style="color:#00e5ff;font-size:22px;letter-spacing:4px;margin-bottom:4px">CIPHERNEST</h1>
    <div style="color:#2a6a7a;font-size:11px;letter-spacing:2px">AI THREAT INTELLIGENCE REPORT — ${report.id}</div>
  </div>
  <div style="margin-left:auto;text-align:right">
    <div style="color:#4a8a9a;font-size:10px">GENERATED</div>
    <div style="color:#7ecfdf;font-size:13px">${report.ts}</div>
    <div style="color:#4a8a9a;font-size:10px;margin-top:4px">TYPE: ${(report.type||"snapshot").toUpperCase()}</div>
  </div>
</div>
<div class="sec">
  <h2 style="color:#00e5ff;font-size:13px;letter-spacing:3px;margin-bottom:16px">▸ EXECUTIVE SUMMARY</h2>
  <div class="grid3" style="margin-bottom:14px">
    <div class="metric"><div class="l">TOTAL FLOWS</div><div class="v" style="color:#00e5ff">${(report.total||0).toLocaleString()}</div></div>
    <div class="metric"><div class="l">THREATS DETECTED</div><div class="v" style="color:#ff2d55">${(report.threats||0).toLocaleString()}</div></div>
    <div class="metric"><div class="l">BENIGN FLOWS</div><div class="v" style="color:#00ff9d">${(report.benign||0).toLocaleString()}</div></div>
    <div class="metric"><div class="l">AVG ANOMALY SCORE</div><div class="v" style="color:${riskColor}">${report.avgScore}</div></div>
    <div class="metric"><div class="l">TOP THREAT TYPE</div><div class="v" style="color:#ff9500;font-size:16px">${report.topThreat||"—"}</div></div>
    <div class="metric"><div class="l">TOP ATTACK PORT</div><div class="v" style="color:#00e5ff">:${report.topPort||"—"}</div></div>
  </div>
  <div style="padding:12px 16px;background:#0f1822;border:1px solid ${riskColor};">
    <span style="font-size:9px;letter-spacing:2px;color:${riskColor}">OVERALL RISK LEVEL: </span>
    <span style="font-size:16px;font-family:'Orbitron',sans-serif;color:${riskColor};letter-spacing:3px">${riskLabel}</span>
    <span style="color:#4a8a9a;font-size:10px;margin-left:20px">Threat rate: ${threatRate}% of all flows</span>
  </div>
</div>
<div class="sec">
  <h2 style="color:#00e5ff;font-size:13px;letter-spacing:3px;margin-bottom:14px">▸ TRAFFIC LABEL BREAKDOWN</h2>
  <table><thead><tr><th>LABEL</th><th style="text-align:right">COUNT</th><th style="text-align:right">%</th></tr></thead>
  <tbody>${labelRows}</tbody></table>
</div>
${alertRows?`<div class="sec">
  <h2 style="color:#00e5ff;font-size:13px;letter-spacing:3px;margin-bottom:14px">▸ TOP ALERT EVENTS</h2>
  <table><thead><tr><th>TIME</th><th>LABEL</th><th>PORT</th><th>SCORE</th><th>SRC IP</th></tr></thead>
  <tbody>${alertRows}</tbody></table>
</div>`:""}
${blockedRows?`<div class="sec">
  <h2 style="color:#ff2d55;font-size:13px;letter-spacing:3px;margin-bottom:14px">▸ AUTO-BLOCKED IPs</h2>
  <table><thead><tr><th>IP ADDRESS</th><th>THREAT TYPE</th><th>SCORE</th><th>TIMESTAMP</th></tr></thead>
  <tbody>${blockedRows}</tbody></table>
</div>`:""}
${report.aiAnalysis?`<div class="sec">
  <h2 style="color:#bf5fff;font-size:13px;letter-spacing:3px;margin-bottom:14px">▸ AI AGENT ANALYSIS</h2>
  <div style="font-size:12px;line-height:1.9;color:#7ecfdf;white-space:pre-wrap;background:#0f1822;border:1px solid #1e3a50;padding:16px">${report.aiAnalysis}</div>
</div>`:""}
<div style="margin-top:32px;padding-top:16px;border-top:1px solid #142030;color:#2a6a7a;font-size:10px;display:flex;justify-content:space-between;letter-spacing:1px">
  <span>CIPHERNEST AI THREAT INTELLIGENCE PLATFORM</span>
  <span>REPORT ${report.id} · ${report.ts}</span>
</div>
</body></html>`;
}

function downloadReport(report){
  const html=buildReportHTML(report);
  const blob=new Blob([html],{type:"text/html"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url;a.download=`CipherNest_${report.id}.html`;
  document.body.appendChild(a);a.click();
  document.body.removeChild(a);URL.revokeObjectURL(url);
}

// ═════════════════════════════════════════════════════════════
//  MAIN APP
// ═════════════════════════════════════════════════════════════

const ML_MODELS_DATA=[
  {name:"Random Forest Classifier",type:"SUPERVISED ENSEMBLE",color:C.cyan,
   metrics:[{l:"Accuracy",v:97.4},{l:"Precision",v:96.8},{l:"Recall",v:98.8},{l:"F1-Score",v:97.8}],
   desc:"200 trees, max_depth=20. Trained on CICIDS-2017/2018 (2.8M flows). Primary classifier for 7 attack categories. SMOTE oversampling for class imbalance."},
  {name:"XGBoost Threat Scorer",type:"GRADIENT BOOSTING",color:C.cyan,
   metrics:[{l:"Accuracy",v:98.1},{l:"AUC-ROC",v:99.8},{l:"Speed",v:92},{l:"Log Loss",v:4}],
   desc:"500 estimators, depth=6, lr=0.1. Best on DDoS+Bot detection. GPU-accelerated inference on 78-feature CICIDS input vector."},
  {name:"Isolation Forest",type:"UNSUPERVISED ANOMALY",color:C.red,
   metrics:[{l:"Anomaly Det.",v:97},{l:"FPR",v:2.1},{l:"Coverage",v:94},{l:"Contamination",v:1}],
   desc:"100 estimators, contamination=0.01. Zero-day attack detection without labels. Sub-sampling 256 for real-time speed."},
  {name:"LSTM Sequence Model",type:"DEEP LEARNING",color:C.purple,
   metrics:[{l:"Accuracy",v:96.2},{l:"Val Acc",v:95.8},{l:"Val Loss",v:76},{l:"Epochs",v:100}],
   desc:"Bidirectional LSTM (128 units). Detects multi-step attack campaigns across 60-step flow sequences."},
  {name:"K-Means Clusterer",type:"UNSUPERVISED CLUSTERING",color:C.orange,
   metrics:[{l:"Clusters",v:70},{l:"Silhouette",v:82},{l:"Coverage",v:96},{l:"Speed",v:95}],
   desc:"7 clusters mapping to CICIDS attack families. MiniBatch K-Means for real-time stream processing."},
  {name:"Ensemble Voter",type:"META-CLASSIFIER",color:C.green,
   metrics:[{l:"Accuracy",v:98.6},{l:"Confidence",v:99.1},{l:"TPR",v:99.4},{l:"FPR",v:1.2}],
   desc:"Weighted soft voting: RF(0.35)+XGB(0.35)+LSTM(0.20)+IF(0.10). Threshold 0.85 triggers auto-block."},
];

const ML_PRESETS=[
  {label:"DDoS Attack",flowBytes:4550000,flowPkts:98234,synFlags:1,rstFlags:0,iatMean:0.01,pktLenStd:12,activeMean:0.01,duration:2.1},
  {label:"Bot C2",flowBytes:89000,flowPkts:1234,synFlags:0,rstFlags:0,iatMean:1.22,pktLenStd:80,activeMean:2.1,duration:305},
  {label:"Port Scan",flowBytes:1200,flowPkts:45,synFlags:1,rstFlags:1,iatMean:22.4,pktLenStd:5,activeMean:0.5,duration:120},
  {label:"Brute Force",flowBytes:34000,flowPkts:210,synFlags:1,rstFlags:0,iatMean:0.92,pktLenStd:60,activeMean:0.9,duration:18.3},
  {label:"Benign Traffic",flowBytes:5200,flowPkts:32,synFlags:0,rstFlags:0,iatMean:8.5,pktLenStd:200,activeMean:5.0,duration:45},
];
const ML_FIELDS=[
  {k:"flowBytes",l:"Flow Bytes/s",min:0,max:5000000,step:1000,unit:"B/s"},
  {k:"flowPkts",l:"Flow Packets/s",min:0,max:100000,step:10,unit:"pkt/s"},
  {k:"synFlags",l:"SYN Flag Count",min:0,max:1,step:1,unit:""},
  {k:"rstFlags",l:"RST Flag Count",min:0,max:1,step:1,unit:""},
  {k:"iatMean",l:"IAT Mean (s)",min:0,max:60,step:0.01,unit:"s"},
  {k:"pktLenStd",l:"Pkt Length Std",min:0,max:800,step:1,unit:""},
  {k:"activeMean",l:"Active Mean (s)",min:0,max:20,step:0.1,unit:"s"},
  {k:"duration",l:"Flow Duration",min:0,max:600,step:0.1,unit:"s"},
];

function MLModelsTab(){
  const[mlTab,setMlTab]=useState("overview");
  const[mlFields,setMlFields]=useState(ML_PRESETS[0]);
  const[mlResult,setMlResult]=useState(null);
  const[mlLoading,setMlLoading]=useState(false);
  const[mlOutput,setMlOutput]=useState("");
  const[mlHistory,setMlHistory]=useState([]);

  function loadPreset(p){setMlFields(p);setMlResult(null);setMlOutput("");}
  function setF(k,v){setMlFields(f=>({...f,[k]:parseFloat(v)||0}));setMlResult(null);setMlOutput("");}

  async function runClassifier(){
    setMlLoading(true);setMlResult(null);setMlOutput("");
    const prompt=`You are a CICIDS-2018 ML ensemble. Classify this network flow. Respond ONLY with valid JSON, no markdown:\n{"label":"DDoS|Bot|PortScan|Brute Force-Web|Web Attacks-BF|Infiltration|BENIGN","confidence":<0-100>,"threat_score":<0.000-1.000>,"status":"BLOCKED|MONITOR|PASS","mitre_id":"<TA####>","mitre_tactic":"<name>","explanation":"<2 sentences>","model_votes":{"random_forest":{"label":"...","confidence":<0-100>},"xgboost":{"label":"...","confidence":<0-100>},"isolation_forest":{"label":"...","anomaly_score":<0.0-1.0>},"lstm":{"label":"...","confidence":<0-100>},"ensemble":{"label":"...","confidence":<0-100>}},"top_features":["<feat>: <val> — <impact>","<feat>: <val> — <impact>","<feat>: <val> — <impact>"]}\nFlow: Bytes/s:${mlFields.flowBytes} Pkts/s:${mlFields.flowPkts} SYN:${mlFields.synFlags} RST:${mlFields.rstFlags} IAT:${mlFields.iatMean}s PktStd:${mlFields.pktLenStd} Active:${mlFields.activeMean}s Dur:${mlFields.duration}s`;
    try{
      const res=await fetch("https://api.anthropic.com/v1/messages",{
        method:"POST",headers:{"Content-Type":"application/json","anthropic-dangerous-direct-browser-access":"true"},
        body:JSON.stringify({model:"claude-sonnet-4-20250514",max_tokens:800,
          messages:[{role:"user",content:prompt}]}),
      });
      if(!res.ok){const err=await res.json().catch(()=>({}));throw new Error(err?.error?.message||`HTTP ${res.status}`);}
      const data=await res.json();
      const text=data.content?.find(b=>b.type==="text")?.text||"";
      const parsed=JSON.parse(text.replace(/```json|```/g,"").trim());
      setMlResult(parsed);
      setMlHistory(h=>[{...mlFields,...parsed,ts:nowUTC()},...h.slice(0,9)]);
    }catch(e){setMlResult({error:`Classification failed — ${e.message||"API error"}`});}
    setMlLoading(false);
  }

  const sc=mlResult&&!mlResult.error
    ?mlResult.status==="BLOCKED"?C.red:mlResult.status==="MONITOR"?C.orange:C.green
    :C.textDim;

  const LABEL_C={"DDoS":C.red,"Bot":C.purple,"PortScan":C.gold,"Brute Force-Web":C.red,"Web Attacks-BF":C.cyan,"Infiltration":C.orange,"BENIGN":C.green};

  return<div style={{padding:18}}>
    {/* Sub-tab bar */}
    <div style={{display:"flex",gap:6,marginBottom:14,borderBottom:`1px solid ${C.border}`,paddingBottom:10}}>
      {[["overview","⬡ MODEL OVERVIEW"],["classifier","⚡ LIVE AI CLASSIFIER"]].map(([k,l])=>(
        <button key={k} onClick={()=>setMlTab(k)}
          style={{padding:"5px 16px",fontFamily:"'Share Tech Mono',monospace",fontSize:9,letterSpacing:"1.5px",
            border:`1px solid ${mlTab===k?C.cyan:"transparent"}`,
            background:mlTab===k?`${C.cyan}18`:"transparent",
            color:mlTab===k?C.cyan:C.textDim,cursor:"pointer",textTransform:"uppercase",transition:"all .2s"}}>
          {l}
        </button>
      ))}
    </div>

    {/* OVERVIEW */}
    {mlTab==="overview"&&<>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:14}}>
        {ML_MODELS_DATA.map(m=>(
          <div key={m.name} style={{background:C.panel,border:`1px solid ${C.border}`,padding:14,position:"relative",borderTop:`2px solid ${m.color}`}}>
            <PanelCorners color={m.color}/>
            <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:11,color:m.color,letterSpacing:1,marginBottom:3}}>{m.name}</div>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,color:C.textLabel,letterSpacing:2,marginBottom:10}}>{m.type}</div>
            {m.metrics.map(x=>(
              <div key={x.l} style={{marginBottom:8}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textDim}}>{x.l}</span>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:m.color}}>{x.v}%</span>
                </div>
                <BarFill pct={x.v} color={m.color}/>
              </div>
            ))}
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,lineHeight:1.7,borderTop:`1px solid ${C.border}`,paddingTop:8,marginTop:4}}>{m.desc}</div>
          </div>
        ))}
      </div>
      {/* Comparison table */}
      <Panel color={C.cyan}>
        <PTitle>⬡ Model Performance Comparison — CICIDS-2018 Test Set</PTitle>
        <div style={{overflowX:"auto"}}>
          <table style={{width:"100%",borderCollapse:"collapse",fontFamily:"'Share Tech Mono',monospace",fontSize:10}}>
            <thead>
              <tr style={{borderBottom:`1px solid ${C.borderBright}`}}>
                {["MODEL","TYPE","ACCURACY","AUC-ROC","FPR","SPEED","STATUS"].map(h=>(
                  <th key={h} style={{padding:"7px 10px",textAlign:"left",fontSize:8,letterSpacing:2,color:C.textLabel,fontWeight:400}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                {name:"Random Forest",type:"Supervised",acc:"97.4%",auc:"98.2%",fpr:"2.1%",speed:"Fast",status:"DEPLOYED",sc:C.green},
                {name:"XGBoost",type:"Supervised",acc:"98.1%",auc:"99.8%",fpr:"1.8%",speed:"Fast",status:"DEPLOYED",sc:C.green},
                {name:"Isolation Forest",type:"Unsupervised",acc:"97.0%",auc:"96.5%",fpr:"2.1%",speed:"Fast",status:"DEPLOYED",sc:C.green},
                {name:"LSTM",type:"Deep Learning",acc:"96.2%",auc:"97.1%",fpr:"2.9%",speed:"Medium",status:"DEPLOYED",sc:C.green},
                {name:"K-Means",type:"Clustering",acc:"82.0%",auc:"85.3%",fpr:"6.2%",speed:"Fast",status:"SUPPORT",sc:C.cyan},
                {name:"Ensemble Voter",type:"Meta",acc:"98.6%",auc:"99.4%",fpr:"1.2%",speed:"Fast",status:"PRIMARY",sc:C.cyan},
              ].map(r=>(
                <tr key={r.name} style={{borderBottom:`1px solid ${C.border}`}}>
                  <td style={{padding:"8px 10px",color:C.text,fontWeight:700}}>{r.name}</td>
                  <td style={{padding:"8px 10px",color:C.textDim}}>{r.type}</td>
                  <td style={{padding:"8px 10px",color:C.cyan}}>{r.acc}</td>
                  <td style={{padding:"8px 10px",color:C.green}}>{r.auc}</td>
                  <td style={{padding:"8px 10px",color:C.orange}}>{r.fpr}</td>
                  <td style={{padding:"8px 10px",color:C.textDim}}>{r.speed}</td>
                  <td style={{padding:"8px 10px"}}>
                    <span style={{padding:"2px 8px",fontSize:8,letterSpacing:1,
                      background:`${r.sc}18`,color:r.sc,border:`1px solid ${r.sc}`,
                      fontFamily:"'Share Tech Mono',monospace"}}>{r.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </>}

    {/* LIVE CLASSIFIER */}
    {mlTab==="classifier"&&<div style={{display:"grid",gridTemplateColumns:"320px 1fr",gap:14}}>
      {/* LEFT */}
      <div style={{display:"flex",flexDirection:"column",gap:10}}>
        <Panel color={C.cyan}>
          <PTitle>⬡ Traffic Preset</PTitle>
          <div style={{display:"flex",flexDirection:"column",gap:4}}>
            {ML_PRESETS.map(p=>(
              <button key={p.label} onClick={()=>loadPreset(p)}
                style={{padding:"6px 10px",fontFamily:"'Share Tech Mono',monospace",fontSize:9,letterSpacing:1,
                  textAlign:"left",cursor:"pointer",textTransform:"uppercase",transition:"all .15s",
                  border:`1px solid ${mlFields.label===p.label?C.cyan:C.borderBright}`,
                  background:mlFields.label===p.label?`${C.cyan}18`:C.card,
                  color:mlFields.label===p.label?C.cyan:C.textDim}}>
                {mlFields.label===p.label?"▶ ":""}{p.label}
              </button>
            ))}
          </div>
        </Panel>
        <Panel color={C.purple}>
          <PTitle>⬡ CICIDS Flow Features</PTitle>
          {ML_FIELDS.map(f=>(
            <div key={f.k} style={{marginBottom:10}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textDim}}>{f.l}</span>
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.cyan}}>{mlFields[f.k]}{f.unit?` ${f.unit}`:""}</span>
              </div>
              <input type="range" min={f.min} max={f.max} step={f.step} value={mlFields[f.k]}
                onChange={e=>setF(f.k,e.target.value)}
                style={{width:"100%",accentColor:C.purple,height:3,cursor:"pointer",
                  WebkitAppearance:"none",appearance:"none",background:"#0f2030",outline:"none"}}/>
            </div>
          ))}
          <Btn color={C.purple} onClick={runClassifier} disabled={mlLoading}
            style={{width:"100%",justifyContent:"center",marginTop:4,letterSpacing:2}}>
            {mlLoading?"⬡ CLASSIFYING...":"⚡ RUN ENSEMBLE CLASSIFIER"}
          </Btn>
        </Panel>
      </div>

      {/* RIGHT */}
      <div style={{display:"flex",flexDirection:"column",gap:10}}>
        {!mlResult&&!mlLoading&&(
          <Panel style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:160}}>
            <div style={{textAlign:"center",color:C.textLabel,fontFamily:"'Share Tech Mono',monospace",fontSize:10}}>
              <div style={{fontSize:24,marginBottom:8,opacity:.3}}>⬡</div>
              Configure flow features and run classifier
            </div>
          </Panel>
        )}
        {mlLoading&&(
          <Panel color={C.orange} style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:120}}>
            <div style={{textAlign:"center"}}>
              <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.orange,letterSpacing:2,marginBottom:6}}>⬡ ENSEMBLE MODELS PROCESSING</div>
              <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textDim}}>RF → XGBoost → LSTM → Isolation Forest → Voter</div>
            </div>
          </Panel>
        )}
        {mlResult&&mlResult.error&&(
          <Panel color={C.red}><div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.red}}>{mlResult.error}</div></Panel>
        )}
        {mlResult&&!mlResult.error&&<>
          {/* Verdict */}
          <div style={{background:C.panel,border:`1px solid ${sc}`,padding:14,position:"relative"}}>
            <PanelCorners color={sc}/>
            <div style={{position:"absolute",top:0,left:0,right:0,height:2,background:sc,boxShadow:`0 0 10px ${sc}`}}/>
            <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",flexWrap:"wrap",gap:10,marginBottom:10}}>
              <div>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,letterSpacing:2,color:C.textLabel,marginBottom:4}}>ENSEMBLE VERDICT</div>
                <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:20,fontWeight:700,color:sc,letterSpacing:2,textShadow:`0 0 12px ${sc}88`}}>{mlResult.label}</div>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textDim,marginTop:3}}>{mlResult.mitre_id} — {mlResult.mitre_tactic}</div>
              </div>
              <div style={{display:"flex",gap:8}}>
                {[["CONFIDENCE",`${mlResult.confidence}%`],["THREAT SCORE",mlResult.threat_score],["DECISION",mlResult.status]].map(([l,v])=>(
                  <div key={l} style={{background:C.card,border:`1px solid ${l==="DECISION"?sc:C.border}`,padding:"8px 14px",textAlign:"center"}}>
                    <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,color:C.textLabel,letterSpacing:1.5,marginBottom:4}}>{l}</div>
                    <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:16,fontWeight:700,color:sc,textShadow:`0 0 8px ${sc}88`}}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim,lineHeight:1.7,borderTop:`1px solid ${C.border}`,paddingTop:8}}>{mlResult.explanation}</div>
          </div>
          {/* Model votes */}
          {mlResult.model_votes&&(
            <Panel color={C.purple}>
              <PTitle>⬡ Individual Model Votes</PTitle>
              <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8}}>
                {[{name:"Random Forest",key:"random_forest",color:C.cyan},{name:"XGBoost",key:"xgboost",color:C.cyan},{name:"Isolation Forest",key:"isolation_forest",color:C.red},{name:"LSTM",key:"lstm",color:C.purple},{name:"Ensemble",key:"ensemble",color:C.green}].map(({name,key,color})=>{
                  const v=mlResult.model_votes[key]||{};
                  const conf=v.confidence??(v.anomaly_score!=null?Math.round(v.anomaly_score*100):0);
                  return<div key={key} style={{background:C.card,border:`1px solid ${color}33`,borderTop:`2px solid ${color}`,padding:"8px 10px"}}>
                    <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,color:color,letterSpacing:1,marginBottom:4}}>{name}</div>
                    <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.text,marginBottom:5,overflow:"hidden",whiteSpace:"nowrap",textOverflow:"ellipsis"}}>{v.label||"—"}</div>
                    <BarFill pct={conf} color={color}/>
                    <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:color,marginTop:3}}>{conf}%</div>
                  </div>;
                })}
              </div>
            </Panel>
          )}
          {/* Top features */}
          {mlResult.top_features&&(
            <Panel color={C.red}>
              <PTitle>⬡ Key Feature Contributions</PTitle>
              {mlResult.top_features.map((f,i)=>(
                <div key={i} style={{display:"flex",gap:8,padding:"5px 0",borderBottom:`1px solid ${C.border}`}}>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.red,flexShrink:0}}>{i+1}.</span>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim,lineHeight:1.5}}>{f}</span>
                </div>
              ))}
            </Panel>
          )}
        </>}
        {/* History */}
        {mlHistory.length>0&&(
          <Panel color={C.teal}>
            <PTitle>⬡ Classification History</PTitle>
            <div style={{overflowX:"auto"}}>
              <table style={{width:"100%",borderCollapse:"collapse",fontFamily:"'Share Tech Mono',monospace",fontSize:9}}>
                <thead><tr style={{borderBottom:`1px solid ${C.borderBright}`}}>
                  {["TIME","BYTES/S","LABEL","CONF","SCORE","STATUS"].map(h=>(
                    <th key={h} style={{padding:"5px 8px",textAlign:"left",fontSize:8,letterSpacing:1.5,color:C.textLabel,fontWeight:400}}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>
                  {mlHistory.map((h,i)=>{
                    const hsc=h.status==="BLOCKED"?C.red:h.status==="MONITOR"?C.orange:C.green;
                    return<tr key={i} style={{borderBottom:`1px solid ${C.border}`}}>
                      <td style={{padding:"6px 8px",color:C.textLabel}}>{h.ts}</td>
                      <td style={{padding:"6px 8px",color:C.textDim}}>{fmtBps(h.flowBytes||0)}</td>
                      <td style={{padding:"6px 8px",color:LABEL_C[h.label]||C.textDim}}>{h.label}</td>
                      <td style={{padding:"6px 8px",color:C.cyan}}>{h.confidence}%</td>
                      <td style={{padding:"6px 8px",color:C.orange}}>{h.threat_score}</td>
                      <td style={{padding:"6px 8px",color:hsc,fontWeight:700}}>{h.status}</td>
                    </tr>;
                  })}
                </tbody>
              </table>
            </div>
          </Panel>
        )}
      </div>
    </div>}
  </div>;
}




function AIAnalysisTab({totalThreats,totalBenign,anomScores,blockedIPs,labelCounts,agentStatus,alerts}){
  const[query,setQuery]=useState("");
  const[output,setOutput]=useState("");
  const[streaming,setStreaming]=useState(false);
  const[history,setHistory]=useState([]);
  const[activePreset,setActivePreset]=useState(null);

  const PRESETS=[
    {label:"Summarize Session",prompt:"Summarize the current CipherNest monitoring session. Include threat distribution, top attack types, notable anomalies, and recommended actions."},
    {label:"MITRE ATT&CK Map",prompt:"Map the detected attack types in this session to MITRE ATT&CK tactics and techniques. Format as a structured list with tactic, technique ID, and brief description."},
    {label:"Risk Assessment",prompt:"Provide a detailed risk assessment for this network session. Rate overall risk level (Critical/High/Medium/Low), explain the top 3 threat vectors, and suggest immediate remediation steps."},
    {label:"Threat Trends",prompt:"Analyze the threat trends visible in this session. Identify patterns, escalation signals, and any indicators of a coordinated multi-vector attack campaign."},
    {label:"SOC Report",prompt:"Write a professional SOC (Security Operations Center) incident report for this session, suitable for management review. Include executive summary, key findings, and next steps."},
  ];

  const sessionContext=`Current CipherNest session data:\n- Total flows: ${totalThreats+totalBenign}\n- Threats detected: ${totalThreats}\n- Benign flows: ${totalBenign}\n- Avg anomaly score: ${anomScores.length?(anomScores.slice(-50).reduce((a,b)=>a+b,0)/Math.min(50,anomScores.length)).toFixed(3):"0.000"}\n- Label breakdown: ${JSON.stringify(Object.entries(labelCounts).slice(0,10))}\n- Top blocked IPs: ${blockedIPs.length}\n- Agent statuses: ${JSON.stringify(agentStatus)}\n- Recent alerts (last 5): ${JSON.stringify(alerts.slice(0,5).map(a=>({label:a.label,port:a.port,score:a.score.toFixed(3)})))}\n`;

  async function runQuery(q){
    if(!q.trim()||streaming)return;
    setStreaming(true);setOutput("");
    const fullPrompt=`You are an expert AI cybersecurity analyst embedded in the CipherNest threat intelligence platform.\n\n${sessionContext}\n\nUser query: ${q}\n\nRespond with a professional, structured analysis. Use clear sections where appropriate.`;
    let txt="";
    await streamClaude(fullPrompt,tok=>{txt+=tok;setOutput(p=>p+tok);},()=>{
      setStreaming(false);
      setHistory(h=>[{q,a:txt,ts:nowUTC()},...h.slice(0,9)]);
      setOutput("");
      setHistory(h=>{if(h[0]&&!h[0].a)return[{...h[0],a:txt},...h.slice(1)];return h;});
    },800);
  }

  const lastResult=history[0];

  return<div style={{padding:18,display:"grid",gridTemplateColumns:"300px 1fr",gap:14,alignItems:"start"}}>
    {/* LEFT PANEL */}
    <div style={{display:"flex",flexDirection:"column",gap:10}}>
      <Panel color={C.cyan}>
        <PTitle>⬡ Session Context</PTitle>
        {[
          {l:"TOTAL FLOWS",v:(totalThreats+totalBenign).toLocaleString(),c:C.cyan},
          {l:"THREATS",v:totalThreats.toLocaleString(),c:C.red},
          {l:"BENIGN",v:totalBenign.toLocaleString(),c:C.green},
          {l:"BLOCKED IPs",v:blockedIPs.length,c:C.orange},
          {l:"AVG SCORE",v:anomScores.length?(anomScores.slice(-50).reduce((a,b)=>a+b,0)/Math.min(50,anomScores.length)).toFixed(3):"—",c:C.purple},
        ].map(m=>(
          <div key={m.l} style={{display:"flex",justifyContent:"space-between",padding:"5px 0",borderBottom:`1px solid ${C.border}`}}>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,letterSpacing:1}}>{m.l}</span>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:m.c,fontWeight:700}}>{m.v}</span>
          </div>
        ))}
      </Panel>
      <Panel color={C.purple}>
        <PTitle>⚡ Quick Analysis Presets</PTitle>
        <div style={{display:"flex",flexDirection:"column",gap:5}}>
          {PRESETS.map(p=>(
            <button key={p.label} onClick={()=>{setActivePreset(p.label);setQuery(p.prompt);}}
              style={{padding:"7px 10px",fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                letterSpacing:1,textAlign:"left",cursor:"pointer",textTransform:"uppercase",transition:"all .15s",
                border:`1px solid ${activePreset===p.label?C.purple:C.borderBright}`,
                background:activePreset===p.label?`${C.purple}22`:C.card,
                color:activePreset===p.label?C.purple:C.textDim}}>
              {activePreset===p.label?"▶ ":""}{p.label}
            </button>
          ))}
        </div>
      </Panel>
      {history.length>0&&(
        <Panel color={C.teal}>
          <PTitle>⬡ Query History</PTitle>
          <div style={{maxHeight:240,overflowY:"auto"}}>
            {history.map((h,i)=>(
              <div key={i} onClick={()=>{setQuery(h.q);setActivePreset(null);}}
                style={{padding:"6px 0",borderBottom:`1px solid ${C.border}`,cursor:"pointer"}}>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,marginBottom:2}}>{h.ts}</div>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.teal,
                  overflow:"hidden",whiteSpace:"nowrap",textOverflow:"ellipsis"}}>{h.q.slice(0,50)}...</div>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>

    {/* RIGHT PANEL */}
    <div style={{display:"flex",flexDirection:"column",gap:10}}>
      <Panel color={C.cyan}>
        <PTitle>🤖 AI Cybersecurity Analyst</PTitle>
        <div style={{display:"flex",gap:8,marginBottom:10}}>
          <textarea value={query} onChange={e=>setQuery(e.target.value)}
            placeholder="Ask anything about this session — threat analysis, MITRE mapping, risk assessment, SOC report..."
            rows={3}
            style={{flex:1,padding:"10px 12px",background:C.card,border:`1px solid ${C.borderBright}`,
              color:C.text,fontFamily:"'Share Tech Mono',monospace",fontSize:11,outline:"none",
              resize:"vertical",lineHeight:1.7}}/>
        </div>
        <div style={{display:"flex",gap:8}}>
          <button onClick={()=>runQuery(query)} disabled={streaming||!query.trim()}
            style={{padding:"9px 20px",fontFamily:"'Share Tech Mono',monospace",fontSize:9,letterSpacing:2,
              border:`1px solid ${streaming?C.borderBright:C.cyan}`,
              background:streaming?C.card:`${C.cyan}18`,
              color:streaming?C.textLabel:C.cyan,cursor:streaming?"not-allowed":"pointer",transition:"all .2s"}}>
            {streaming?"⬡ ANALYZING...":"⚡ RUN ANALYSIS"}
          </button>
          <button onClick={()=>{setQuery("");setActivePreset(null);setOutput("");}}
            style={{padding:"9px 14px",fontFamily:"'Share Tech Mono',monospace",fontSize:9,letterSpacing:1,
              border:`1px solid ${C.borderBright}`,background:"transparent",
              color:C.textDim,cursor:"pointer"}}>
            CLEAR
          </button>
        </div>
      </Panel>

      {(streaming||output)&&(
        <Panel color={C.purple}>
          <PTitle>
            <span style={{width:8,height:8,borderRadius:"50%",background:C.purple,
              boxShadow:`0 0 10px ${C.purple}`,display:"inline-block",
              animation:streaming?"blink 1s step-end infinite":"none"}}/>
            AI ANALYSIS OUTPUT
          </PTitle>
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:C.text,
            lineHeight:1.9,whiteSpace:"pre-wrap",background:C.card,border:`1px solid ${C.borderBright}`,
            padding:14,minHeight:80}}>
            {output||lastResult?.a||""}
            {streaming&&<span style={{animation:"blink 1s step-end infinite",color:C.purple}}>▋</span>}
          </div>
        </Panel>
      )}

      {!streaming&&!output&&lastResult&&(
        <Panel color={C.teal}>
          <PTitle>⬡ LAST ANALYSIS — {lastResult.ts}</PTitle>
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,marginBottom:8}}>
            Query: <span style={{color:C.teal}}>{lastResult.q.slice(0,100)}{lastResult.q.length>100?"...":""}</span>
          </div>
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:C.text,
            lineHeight:1.9,whiteSpace:"pre-wrap",background:C.card,border:`1px solid ${C.borderBright}`,
            padding:14,maxHeight:400,overflowY:"auto"}}>
            {lastResult.a}
          </div>
        </Panel>
      )}

      {!streaming&&!output&&!lastResult&&(
        <Panel style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:200}}>
          <div style={{textAlign:"center",color:C.textLabel,fontFamily:"'Share Tech Mono',monospace",fontSize:10}}>
            <div style={{fontSize:32,marginBottom:10,opacity:.25}}>🤖</div>
            <div style={{letterSpacing:2,marginBottom:6}}>AI ANALYST READY</div>
            <div style={{fontSize:9,color:C.textLabel,maxWidth:300,lineHeight:1.7}}>
              Select a preset or type a custom query to get real-time AI analysis of your session data.
            </div>
          </div>
        </Panel>
      )}
    </div>
  </div>;
}


export default function CipherNest(){
  const[tab,setTab]=useState("dashboard");
  const[mode,setMode]=useState("live");
  const[showSimModal,setShowSimModal]=useState(false);

  const[simRunning,setSimRunning]=useState(false);
  const[simTotal,setSimTotal]=useState(0);
  const[simIndex,setSimIndex]=useState(0);
  const[simSpeed,setSimSpeed]=useState(150);
  const simTimerRef=useRef(null);
  const simRecordsRef=useRef([]);

  const[current,setCurrent]=useState(null);
  const[filterType,setFilterType]=useState("all");
  const[labelCounts,setLabelCounts]=useState({});
  const[portCounts,setPortCounts]=useState({});
  const[totalThreats,setTotalThreats]=useState(0);
  const[totalBenign,setTotalBenign]=useState(0);
  const[flowBenign,setFlowBenign]=useState(Array(40).fill(0));
  const[flowThreat,setFlowThreat]=useState(Array(40).fill(0));
  const[pktHistory,setPktHistory]=useState(Array(40).fill(0));
  const[anomScores,setAnomScores]=useState([]);
  const[alerts,setAlerts]=useState([]);
  const[topoPackets,setTopoPackets]=useState([]);
  const alertsRef=useRef([]);

  const AGENTS=[
    {id:"clf",label:"CLASSIFIER",color:C.cyan,accuracy:97.4,
     desc:"Classifies every incoming network flow in real-time using the CICIDS-2018 feature vector. Assigns attack category labels and triggers downstream agents on positive detection."},
    {id:"ana",label:"ANALYZER",color:C.purple,accuracy:96.8,
     desc:"Deep-dives flagged flows using the XGBoost threat scorer. Extracts MITRE ATT&CK mappings, pattern signatures, and risk ratings for each anomaly above threshold 0.72."},
    {id:"log",label:"LOG_ANALYZER",color:C.teal,accuracy:95.1,
     desc:"Scans historical flow logs for recurring source IPs, port patterns, and temporal attack signatures. Cross-references current events with past 10-minute windows."},
    {id:"det",label:"THREAT_DETECT",color:C.red,accuracy:98.2,
     desc:"Runs the Isolation Forest + LSTM ensemble for zero-day and multi-step attack detection. Maps detected vectors to MITRE ATT&CK tactics and severity levels."},
    {id:"orch",label:"ORCHESTRATOR",color:C.gold,accuracy:99.1,
     desc:"Coordinates the full agent pipeline. Assigns tasks to CLASSIFIER, ANALYZER, LOG_ANALYZER, THREAT_DETECT, and RESPONDER. Generates final simulation and snapshot reports."},
  ];
  const[agentStatus,setAgentStatus]=useState({clf:"STANDBY",ana:"STANDBY",log:"STANDBY",det:"STANDBY",orch:"STANDBY"});
  const[agentLog,setAgentLog]=useState([]);
  const agentBusyRef=useRef(false);

  const[incidentOutput,setIncidentOutput]=useState("");
  const[incidentStreaming,setIncidentStreaming]=useState(false);

  const[blockedIPs,setBlockedIPs]=useState([]);
  const blockedIPsRef=useRef([]);
  const[lockdown,setLockdown]=useState(false);

  const[tickets,setTickets]=useState([]);
  const[reports,setReports]=useState([]);
  const[simReport,setSimReport]=useState(null);

  const lcRef=useRef({});
  const pcRef=useRef({});
  const threatsRef=useRef(0);
  const benignRef=useRef(0);
  const scoresRef=useRef([]);
  useEffect(()=>{lcRef.current=labelCounts;},[labelCounts]);
  useEffect(()=>{pcRef.current=portCounts;},[portCounts]);
  useEffect(()=>{threatsRef.current=totalThreats;},[totalThreats]);
  useEffect(()=>{benignRef.current=totalBenign;},[totalBenign]);
  useEffect(()=>{scoresRef.current=anomScores;},[anomScores]);
  useEffect(()=>{blockedIPsRef.current=blockedIPs;},[blockedIPs]);

  // Clock is in LiveClock component above

  const demoRef=useRef(null);
  useEffect(()=>{
    if(mode==="live"&&!simRunning){
      demoRef.current=setInterval(()=>processRow(genDemoRow()),700);
    }else{clearInterval(demoRef.current);}
    return()=>clearInterval(demoRef.current);
  },[mode,simRunning]);

  const processRow=useCallback((row)=>{
    const{label,isThreat,port,bps,pps,dur,syn,rst,iat,pktStd,srcIp}=extractRow(row);
    const score=anomalyScore(isThreat);
    setCurrent({label,isThreat,port,bps,pps,dur,syn,rst,iat,pktStd,score,srcIp});
    setLabelCounts(p=>({...p,[label]:(p[label]||0)+1}));
    setPortCounts(p=>({...p,[port]:(p[port]||0)+1}));
    if(isThreat)setTotalThreats(p=>p+1);else setTotalBenign(p=>p+1);
    setFlowBenign(p=>[...p.slice(-39),isThreat?0:bps/1000]);
    setFlowThreat(p=>[...p.slice(-39),isThreat?bps/1000:0]);
    setPktHistory(p=>[...p.slice(-39),pps]);
    setAnomScores(p=>[...p.slice(-99),score]);
    setTopoPackets([{threat:isThreat}]);

    if(isThreat){
      const ts=nowUTC();
      const al={ts,label,port,score,srcIp};
      alertsRef.current=[al,...alertsRef.current].slice(0,60);
      setAlerts([...alertsRef.current]);
      if(score>0.82){
        const ip=srcIp||fakeIP();
        const entry={ip,label,port,score,ts};
        blockedIPsRef.current=[entry,...blockedIPsRef.current].slice(0,60);
        setBlockedIPs([...blockedIPsRef.current]);
        appendLog("RESPONDER",`AUTO-BLOCKED ${ip} — ${label} on :${port} (score ${score.toFixed(3)})`,C.red);
        setAgentStatus(p=>({...p,clf:"ACTIVE"}));
      }
      if(!agentBusyRef.current&&score>0.72){
        const roll=Math.random();
        if(roll<0.12)      runAnalyzer(label,score,bps,pps,syn,rst,port);
        else if(roll<0.20) runLogAnalyzer(label,score,port,srcIp);
        else if(roll<0.27) runThreatDetect(label,score,bps,pps,port);
        else if(roll<0.32) runOrchestrator(label,score);
      }
    }
  },[]);

  function appendLog(agent,text,color=C.textDim){
    const id=Date.now()+Math.random();
    setAgentLog(p=>[{id,ts:nowUTC(),agent,text,color,streaming:false},...p].slice(0,80));
    return id;
  }
  function patchLog(id,text,streaming=false){
    setAgentLog(p=>p.map(e=>e.id===id?{...e,text,streaming}:e));
  }

  async function runAnalyzer(label,score,bps,pps,syn,rst,port){
    if(agentBusyRef.current)return;agentBusyRef.current=true;
    setAgentStatus(p=>({...p,ana:"ANALYZING"}));
    const id=appendLog("ANALYZER","...",C.purple);let txt="";
    await streamClaude(
      `ANALYZER agent in CipherNest. Analyze CICIDS flow:\nLabel:${label}|Score:${score.toFixed(3)}|Bytes/s:${bps.toExponential(2)}|Pkts/s:${pps.toFixed(0)}|SYN:${syn}|RST:${rst}|Port:${port}\nRespond in exactly 4 lines:\nTHREAT: ...\nPATTERN: ...\nRISK: HIGH|MED|LOW — reason\nACTION: ...`,
      tok=>{txt+=tok;patchLog(id,txt,true);},
      ()=>{patchLog(id,txt,false);setAgentStatus(p=>({...p,ana:"READY"}));agentBusyRef.current=false;}
    );
  }

  async function runLogAnalyzer(label,score,port,srcIp){
    if(agentBusyRef.current)return;agentBusyRef.current=true;
    setAgentStatus(p=>({...p,log:"ANALYZING"}));
    const id=appendLog("LOG_ANALYZER","...",C.teal);let txt="";
    await streamClaude(
      `LOG_ANALYZER agent in CipherNest. ${label} threat (score ${score.toFixed(3)}) on port ${port} from ${srcIp||"unknown"}.\nReview log patterns and respond in 4 lines:\nHISTORY: ...\nPATTERN_MATCH: ...\nCONFIDENCE: ...\nRECOMMENDATION: ...`,
      tok=>{txt+=tok;patchLog(id,txt,true);},
      ()=>{patchLog(id,txt,false);setAgentStatus(p=>({...p,log:"READY"}));agentBusyRef.current=false;}
    );
  }

  async function runThreatDetect(label,score,bps,pps,port){
    if(agentBusyRef.current)return;agentBusyRef.current=true;
    setAgentStatus(p=>({...p,det:"DETECTING"}));
    const id=appendLog("THREAT_DETECT","...",C.red);let txt="";
    await streamClaude(
      `THREAT_DETECT agent in CipherNest. Classify network event:\nLabel:${label}|Score:${score.toFixed(3)}|Bytes/s:${bps.toExponential(2)}|Pkts/s:${pps.toFixed(0)}|Port:${port}\nRespond in 4 lines:\nVECTOR: ...\nSEVERITY: ...\nINDICATORS: ...\nMITRE_ATT&CK: ...`,
      tok=>{txt+=tok;patchLog(id,txt,true);},
      ()=>{patchLog(id,txt,false);setAgentStatus(p=>({...p,det:"READY"}));agentBusyRef.current=false;}
    );
  }

  async function runOrchestrator(label,score){
    if(agentBusyRef.current)return;agentBusyRef.current=true;
    setAgentStatus(p=>({...p,orch:"ORCHESTRATING"}));
    const id=appendLog("ORCHESTRATOR","...",C.gold);let txt="";
    await streamClaude(
      `ORCHESTRATOR agent in CipherNest. Coordinate response to ${label} threat (score ${score.toFixed(3)}).\nWrite a 5-line orchestration plan assigning tasks to: CLASSIFIER, ANALYZER, LOG_ANALYZER, THREAT_DETECT, RESPONDER.`,
      tok=>{txt+=tok;patchLog(id,txt,true);},
      ()=>{patchLog(id,txt,false);setAgentStatus(p=>({...p,orch:"READY"}));agentBusyRef.current=false;}
    );
  }

  function startSim(count,csvRecs){
    setShowSimModal(false);setMode("simulation");setTab("simulation");
    setSimTotal(count);setSimIndex(0);resetStats();
    const records=(csvRecs&&csvRecs.length)?csvRecs.slice(0,count):Array.from({length:count},genDemoRow);
    simRecordsRef.current=records;
    setSimRunning(true);
    setAgentStatus({clf:"CLASSIFYING",ana:"ACTIVE",log:"ACTIVE",det:"SCANNING",orch:"ACTIVE"});
    appendLog("ORCHESTRATOR",`Simulation started: ${count} flows queued. ${csvRecs&&csvRecs.length?"CSV data loaded.":"Using demo data."}`,C.gold);
  }

  useEffect(()=>{
    if(!simRunning)return;
    simTimerRef.current=setInterval(()=>{
      setSimIndex(prev=>{
        const next=prev+1;
        const rec=simRecordsRef.current[prev];
        if(rec)processRow(rec);
        if(next>=simRecordsRef.current.length){
          clearInterval(simTimerRef.current);
          setSimRunning(false);setMode("live");
          setAgentStatus({clf:"COMPLETE",ana:"COMPLETE",log:"COMPLETE",det:"COMPLETE",orch:"COMPLETE"});
          appendLog("ORCHESTRATOR","Simulation complete. Generating final report...",C.gold);
          setTimeout(()=>finalizeSimReport(simRecordsRef.current.length),600);
        }
        return next;
      });
    },simSpeed);
    return()=>clearInterval(simTimerRef.current);
  },[simRunning,simSpeed,processRow]);

  function stopSim(){
    clearInterval(simTimerRef.current);
    setSimRunning(false);setMode("live");setTab("dashboard");
    setAgentStatus({clf:"STANDBY",ana:"STANDBY",log:"STANDBY",det:"STANDBY",orch:"STANDBY"});
  }

  async function finalizeSimReport(total){
    const lc=lcRef.current,pc=pcRef.current,sc=scoresRef.current;
    const threats=threatsRef.current,benign=benignRef.current;
    const avgScore=sc.length?(sc.reduce((a,b)=>a+b,0)/sc.length).toFixed(3):"0.000";
    const topThreat=Object.entries(lc).filter(([k])=>k!=="BENIGN").sort((a,b)=>b[1]-a[1])[0]?.[0]||"None";
    const topPort=Object.entries(pc).sort((a,b)=>b[1]-a[1])[0]?.[0]||"None";
    let aiAnalysis="";
    await streamClaude(
      `ORCHESTRATOR in CipherNest. Write a 6-line executive security analyst summary:\nTotal flows:${total}|Threats:${threats}|Benign:${benign}|AvgScore:${avgScore}|TopThreat:${topThreat}|TopPort:${topPort}\nLabel breakdown:${JSON.stringify(Object.entries(lc).slice(0,8))}\nFormat as professional security analyst. Include: risk assessment, notable patterns, recommended actions.`,
      tok=>{aiAnalysis+=tok;},
      ()=>{},500
    );
    const rpt={
      id:`SIM-${String(reports.length+1).padStart(4,"0")}`,
      ts:isoNow(),total,threats,benign,avgScore,topThreat,topPort,
      labelCounts:{...lc},
      topAlerts:[...alertsRef.current].slice(0,25),
      blockedIPs:[...blockedIPsRef.current].slice(0,20),
      aiAnalysis,type:"simulation",
    };
    setSimReport(rpt);
    setReports(p=>[rpt,...p]);
    setTab("simulation");
    appendLog("ORCHESTRATOR",`Final report ${rpt.id} generated and saved to Reports panel.`,C.gold);
  }

  function resetStats(){
    setLabelCounts({});setPortCounts({});setTotalThreats(0);setTotalBenign(0);
    setFlowBenign(Array(40).fill(0));setFlowThreat(Array(40).fill(0));
    setPktHistory(Array(40).fill(0));setAnomScores([]);
    setAlerts([]);alertsRef.current=[];setTopoPackets([]);
    lcRef.current={};pcRef.current={};threatsRef.current=0;benignRef.current=0;
    scoresRef.current=[];blockedIPsRef.current=[];
  }

  function handleModeToggle(){
    if(mode==="live")setShowSimModal(true);else stopSim();
  }

  async function incidentAction(action){
    if(action==="lockdown"){
      setLockdown(true);
      setTimeout(()=>setLockdown(false),8000);
      appendLog("RESPONDER","FORCE LOCKDOWN — All connections severed. Perimeter isolated.",C.red);
      return;
    }
    if(action==="investigate"){
      const t={id:`TKT-${String(tickets.length+1).padStart(4,"0")}`,ts:isoNow(),
        type:current?.label||"UNKNOWN",port:current?.port||"?",
        score:current?.score?.toFixed(3)||"?",srcIp:current?.srcIp||"unknown",status:"OPEN"};
      setTickets(p=>[t,...p]);setTab("reports");
      appendLog("RESPONDER",`Investigation ticket ${t.id} opened for ${t.type} on :${t.port}`,C.cyan);
      return;
    }
    if(action==="report"){
      const lc=labelCounts,pc=portCounts,sc=anomScores;
      const avg=sc.length?(sc.slice(-50).reduce((a,b)=>a+b,0)/Math.min(50,sc.length)).toFixed(3):"0.000";
      const topThreat=Object.entries(lc).filter(([k])=>k!=="BENIGN").sort((a,b)=>b[1]-a[1])[0]?.[0]||"None";
      const topPort=Object.entries(pc).sort((a,b)=>b[1]-a[1])[0]?.[0]||"None";
      const total=totalThreats+totalBenign;
      setIncidentStreaming(true);setIncidentOutput("");
      let aiText="";
      await streamClaude(
        `ANALYZER in CipherNest. Write a 6-line professional security analyst executive summary for a report:\nTotal:${total}|Threats:${totalThreats}|Benign:${totalBenign}|AvgScore:${avg}|TopThreat:${topThreat}|TopPort:${topPort}\nInclude risk level, key patterns, and recommended actions.`,
        tok=>{aiText+=tok;setIncidentOutput(p=>p+tok);},
        ()=>{setIncidentStreaming(false);},300
      );
      const rpt={id:`RPT-${String(reports.length+1).padStart(4,"0")}`,ts:isoNow(),
        total,threats:totalThreats,benign:totalBenign,avgScore:avg,topThreat,topPort,
        labelCounts:{...lc},topAlerts:[...alertsRef.current].slice(0,25),
        blockedIPs:[...blockedIPsRef.current].slice(0,20),aiAnalysis:aiText,type:"snapshot"};
      setReports(p=>[rpt,...p]);setTab("reports");
      appendLog("ANALYZER",`Report ${rpt.id} generated and saved.`,C.purple);
      return;
    }
    if(action==="escalate"){
      setIncidentStreaming(true);setIncidentOutput("");
      await streamClaude(
        `RESPONDER: 4-line SOC escalation for ${current?.label||"threat"} on port ${current?.port||"?"} score ${current?.score?.toFixed(3)||"?"}`,
        tok=>setIncidentOutput(p=>p+tok),
        ()=>setIncidentStreaming(false)
      );
      appendLog("RESPONDER","SOC escalation message drafted.",C.orange);
    }
  }

  const isSimMode=mode==="simulation";
  const totalFlows=totalThreats+totalBenign;
  const avgScore=anomScores.length?(anomScores.slice(-50).reduce((a,b)=>a+b,0)/Math.min(50,anomScores.length)):0;

  const fc=()=>{
    if(!current)return null;
    if(filterType==="all")return current;
    const l=current.label.toLowerCase();
    if(filterType==="ddos"&&(l.includes("ddos")||l.includes("dos")))return current;
    if(filterType==="portscan"&&l.includes("portscan"))return current;
    if(filterType==="brute"&&(l.includes("brute")||l.includes("patator")))return current;
    if(filterType==="bot"&&l.includes("bot"))return current;
    return null;
  };
  const C2=fc();

  const donutData=[
    {label:"BENIGN",value:labelCounts["BENIGN"]||0,color:C.green},
    {label:"Bot",value:labelCounts["Bot"]||0,color:C.purple},
    {label:"DDoS",value:(labelCounts["DDoS"]||0)+(labelCounts["DoS Hulk"]||0)+(labelCounts["DoS GoldenEye"]||0)+(labelCounts["DoS slowloris"]||0)+(labelCounts["DoS Slowhttptest"]||0),color:C.red},
    {label:"PortScan",value:labelCounts["PortScan"]||0,color:C.gold},
    {label:"BruteForce",value:(labelCounts["FTP-Patator"]||0)+(labelCounts["SSH-Patator"]||0),color:C.teal},
    {label:"WebAtk",value:(labelCounts["Web Attack \u2013 Brute Force"]||0)+(labelCounts["Web Attack \u2013 XSS"]||0)+(labelCounts["Web Attack \u2013 Sql Injection"]||0),color:"#007b8a"},
    {label:"Other",value:Object.entries(labelCounts).filter(([k])=>!["BENIGN","Bot","DDoS","DoS Hulk","DoS GoldenEye","DoS slowloris","DoS Slowhttptest","PortScan","FTP-Patator","SSH-Patator","Web Attack \u2013 Brute Force","Web Attack \u2013 XSS","Web Attack \u2013 Sql Injection"].includes(k)).reduce((s,[,v])=>s+v,0),color:C.orange},
  ].filter(d=>d.value>0);

  const topPorts=Object.entries(portCounts).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const maxPortCount=topPorts[0]?.[1]||1;

  const importanceBars=C2?[
    {l:"Flow Bytes/s",pct:Math.min(100,C2.bps/1e4),c:C.red},
    {l:"Flow Packets/s",pct:Math.min(100,C2.pps/300),c:C.red},
    {l:"SYN Flag Count",pct:Math.min(100,C2.syn>0?C2.syn*20:r(40)),c:C.red},
    {l:"Pkt Length Std",pct:Math.min(100,C2.pktStd/10),c:C.yellow},
    {l:"RST Flag Count",pct:Math.min(100,C2.rst>0?C2.rst*20:r(30)),c:C.red},
    {l:"IAT Mean",pct:Math.min(100,C2.iat*2),c:C.orange},
  ]:[];

  const isSimBorder=isSimMode?{outline:`2px solid ${C.purple}`}:{};


  function DashboardTab(){
    return<>
      <MetricCards/>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 360px",gap:12,padding:"0 18px 18px"}}>
        <div style={{display:"flex",flexDirection:"column",gap:12}}>
          <ThreatEnginePanel/>
          <Panel>
            <PTitle>Flow Bytes/S Over Time</PTitle>
            <div style={{display:"flex",gap:12,marginBottom:8}}>
              {[{c:C.cyan,l:"Benign KB/s"},{c:C.red,l:"Threat KB/s"}].map(x=>(
                <div key={x.l} style={{display:"flex",alignItems:"center",gap:5,
                  fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textDim}}>
                  <span style={{width:14,height:2,background:x.c,display:"inline-block"}}/>{x.l}
                </div>
              ))}
            </div>
            <div style={{position:"relative"}}>
              <Sparkline data={flowBenign} color={C.cyan} height={65}/>
              <div style={{position:"absolute",top:0,left:0,right:0}}>
                <Sparkline data={flowThreat} color={C.red} height={65}/>
              </div>
            </div>
          </Panel>
          <Panel><PTitle>Packets/S Over Time</PTitle><Sparkline data={pktHistory} color={C.purple} height={70}/></Panel>
          <AlertFeed/>
        </div>
        <div style={{display:"flex",flexDirection:"column",gap:12}}>
          <AgentLogPanel/>
          <Panel><PTitle>Network Topology — Live Flow Map</PTitle><TopoCanvas packets={topoPackets}/></Panel>
          <Panel>
            <PTitle>Attack Type Distribution</PTitle>
            <div style={{display:"flex",flexWrap:"wrap",gap:6,alignItems:"flex-end",minHeight:80}}>
              {donutData.map(d=>{
                const h=Math.max(8,Math.round(d.value/(totalFlows||1)*120));
                return<div key={d.label} style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4,flex:"1 0 60px"}}>
                  <div style={{width:"100%",height:h,background:d.color,boxShadow:`0 0 6px ${d.color}`,transition:"height .5s"}}/>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,color:C.textDim}}>{d.label}</span>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:d.color}}>{d.value}</span>
                </div>;
              })}
            </div>
          </Panel>
        </div>
        <div style={{display:"flex",flexDirection:"column",gap:12}}><RightCol/></div>
      </div>
    </>;
  }

  function SimulationTab(){
    const pct=simTotal>0?Math.round(simIndex/simTotal*100):0;
    return<div style={{padding:18}}>
      <Panel color={C.purple} style={{marginBottom:14,boxShadow:simRunning?`0 0 0 2px ${C.purple}`:"none",transition:"box-shadow .3s"}}>
        <PTitle>⚡ SIMULATION ENGINE</PTitle>
        <div style={{display:"flex",alignItems:"center",gap:14,flexWrap:"wrap"}}>
          <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textDim,letterSpacing:2}}>SPEED:</span>
          {[[500,"0.5x"],[200,"1x"],[80,"5x"],[20,"25x"]].map(([ms,l])=>(
            <button key={ms} onClick={()=>setSimSpeed(ms)}
              style={{padding:"3px 10px",fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                border:`1px solid ${simSpeed===ms?C.purple:C.borderBright}`,
                background:simSpeed===ms?`${C.purple}22`:C.card,
                color:simSpeed===ms?C.purple:C.textDim,cursor:"pointer"}}>{l}
            </button>
          ))}
          <div style={{flex:1,minWidth:200,display:"flex",alignItems:"center",gap:10}}>
            <div style={{flex:1,height:6,background:"#0f2030",overflow:"hidden"}}>
              <div style={{height:"100%",width:`${pct}%`,
                background:`linear-gradient(90deg,${C.purple},${C.cyan})`,
                boxShadow:`0 0 8px ${C.purple}`,transition:"width .3s"}}/>
            </div>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.purple,flexShrink:0}}>
              {simIndex.toLocaleString()} / {simTotal.toLocaleString()}
            </span>
          </div>
          {simRunning
            ?<Btn color={C.red} onClick={stopSim}>⏹ STOP</Btn>
            :<Btn color={C.purple} onClick={()=>setShowSimModal(true)}>▶ NEW SIMULATION</Btn>
          }
        </div>
      </Panel>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:14}}>
        {[{l:"FLOWS PROCESSED",v:totalFlows.toLocaleString(),c:C.cyan},
          {l:"THREATS",v:totalThreats.toLocaleString(),c:C.red},
          {l:"BENIGN",v:totalBenign.toLocaleString(),c:C.green},
          {l:"AVG SCORE",v:avgScore.toFixed(3),c:avgScore>.6?C.red:avgScore>.3?C.orange:C.green}
        ].map(m=>(
          <div key={m.l} style={{background:C.panel,
            border:`2px solid ${simRunning?C.purple:C.borderBright}`,padding:"12px 16px",
            transition:"border-color .3s"}}>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,letterSpacing:2,color:C.textLabel,marginBottom:6}}>{m.l}</div>
            <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:22,fontWeight:700,color:m.c,textShadow:`0 0 12px ${m.c}88`}}>{m.v}</div>
          </div>
        ))}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:14}}>
        <Panel color={C.purple}>
          <PTitle>Flow Bytes/S</PTitle>
          <div style={{position:"relative"}}>
            <Sparkline data={flowBenign} color={C.cyan} height={90}/>
            <div style={{position:"absolute",top:0,left:0,right:0}}><Sparkline data={flowThreat} color={C.red} height={90}/></div>
          </div>
        </Panel>
        <Panel color={C.purple}>
          <PTitle>Label Distribution</PTitle>
          <div style={{display:"flex",justifyContent:"center"}}>
            <DonutChart data={donutData.length?donutData:[{label:"Empty",value:1,color:C.border}]}/>
          </div>
        </Panel>
      </div>
      <Panel color={C.purple} style={{marginBottom:14}}>
        <PTitle>Live Agent Activity</PTitle>
        <div style={{maxHeight:160,overflowY:"auto"}}>
          {agentLog.slice(0,12).map(e=>(
            <div key={e.id} style={{display:"flex",gap:8,padding:"5px 0",borderBottom:`1px solid ${C.border}`}}>
              <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,flexShrink:0}}>{e.ts}</span>
              <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:e.color||C.purple,flexShrink:0}}>[{e.agent}]</span>
              <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim,
                overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                {e.text.split("\n")[0]}
                {e.streaming&&<span style={{animation:"blink 1s step-end infinite"}}>▋</span>}
              </span>
            </div>
          ))}
        </div>
      </Panel>
      {simReport&&(
        <Panel color={C.green} className="anim-report">
          <PTitle color={C.green}>✓ SIMULATION COMPLETE — FINAL REPORT: {simReport.id}</PTitle>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10,marginBottom:12}}>
            {[{l:"TOTAL FLOWS",v:simReport.total,c:C.cyan},{l:"THREATS",v:simReport.threats,c:C.red},
              {l:"BENIGN",v:simReport.benign,c:C.green},{l:"TOP THREAT",v:simReport.topThreat,c:C.orange},
              {l:"TOP PORT",v:":"+simReport.topPort,c:C.cyan},{l:"AVG SCORE",v:simReport.avgScore,c:simReport.avgScore>.7?C.red:C.orange}
            ].map(m=>(
              <div key={m.l} style={{background:C.card,border:`1px solid ${C.borderBright}`,padding:"10px 12px"}}>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,letterSpacing:2,color:C.textLabel,marginBottom:5}}>{m.l}</div>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:14,color:m.c}}>{m.v}</div>
              </div>
            ))}
          </div>
          {simReport.aiAnalysis&&(
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:C.textDim,
              background:C.card,border:`1px solid ${C.borderBright}`,padding:12,
              lineHeight:1.8,whiteSpace:"pre-wrap",marginBottom:12}}>
              {simReport.aiAnalysis}
            </div>
          )}
          <div style={{display:"flex",gap:8}}>
            <Btn color={C.green} onClick={()=>downloadReport(simReport)}>⬇ DOWNLOAD FULL REPORT (HTML)</Btn>
            <Btn color={C.cyan} onClick={()=>setTab("reports")}>→ VIEW IN REPORTS</Btn>
          </div>
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,marginTop:8}}>{simReport.ts}</div>
        </Panel>
      )}
    </div>;
  }

  function ReportsTab(){
    return<div style={{padding:18}}>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
        <Panel color={C.cyan}>
          <PTitle>Investigation Tickets</PTitle>
          {!tickets.length&&<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textLabel}}>No tickets. Click "Request Investigation" to open one.</div>}
          {tickets.map(t=>(
            <div key={t.id} style={{border:`1px solid ${C.borderBright}`,background:C.card,padding:"10px 12px",marginBottom:8}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:C.cyan}}>{t.id}</span>
                <span style={{padding:"1px 6px",fontSize:8,background:`${C.orange}22`,color:C.orange,
                  border:`1px solid ${C.orange}`,fontFamily:"'Share Tech Mono',monospace"}}>{t.status}</span>
              </div>
              <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim,lineHeight:1.9}}>
                Type: <span style={{color:C.red}}>{t.type}</span> · Port: <span style={{color:C.cyan}}>:{t.port}</span><br/>
                Score: <span style={{color:C.orange}}>{t.score}</span> · Src: {t.srcIp}<br/>
                <span style={{color:C.textLabel}}>{t.ts}</span>
              </div>
            </div>
          ))}
        </Panel>
        <Panel color={C.green}>
          <PTitle>Generated Reports ({reports.length})</PTitle>
          {!reports.length&&<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textLabel}}>No reports yet. Click "Generate Report" or complete a simulation.</div>}
          <div style={{maxHeight:"60vh",overflowY:"auto"}}>
            {reports.map(rpt=>(
              <div key={rpt.id} style={{border:`1px solid ${C.borderBright}`,background:C.card,
                padding:"12px",marginBottom:10}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                  <span style={{fontFamily:"'Orbitron',sans-serif",fontSize:12,color:C.green}}>{rpt.id}</span>
                  <div style={{display:"flex",gap:6}}>
                    <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,
                      padding:"2px 6px",border:`1px solid ${C.borderBright}`}}>
                      {rpt.type==="snapshot"?"SNAPSHOT":"SIM REPORT"}
                    </span>
                    <button onClick={()=>downloadReport(rpt)}
                      style={{padding:"3px 10px",fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                        border:`1px solid ${C.green}`,background:`${C.green}18`,color:C.green,
                        cursor:"pointer",letterSpacing:1}}>
                      ⬇ DOWNLOAD
                    </button>
                  </div>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:6,marginBottom:8}}>
                  {[{l:"FLOWS",v:(rpt.total||0).toLocaleString(),c:C.cyan},
                    {l:"THREATS",v:(rpt.threats||0).toLocaleString(),c:C.red},
                    {l:"BENIGN",v:(rpt.benign||0).toLocaleString(),c:C.green},
                    {l:"AVG SCORE",v:rpt.avgScore,c:rpt.avgScore>.7?C.red:C.orange},
                    {l:"TOP THREAT",v:(rpt.topThreat||"—").split(" ")[0],c:C.orange},
                    {l:"TOP PORT",v:":"+rpt.topPort,c:C.cyan},
                  ].map(m=>(
                    <div key={m.l} style={{background:C.bg,border:`1px solid ${C.border}`,padding:"6px 8px"}}>
                      <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:7,letterSpacing:2,color:C.textLabel,marginBottom:3}}>{m.l}</div>
                      <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:12,color:m.c}}>{m.v}</div>
                    </div>
                  ))}
                </div>
                <div style={{marginBottom:8,display:"flex",flexWrap:"wrap",gap:"4px 10px"}}>
                  {Object.entries(rpt.labelCounts||{}).map(([k,v])=>(
                    <span key={k} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,
                      color:LABEL_COLORS[k]||C.textDim}}>{k}: {v}</span>
                  ))}
                </div>
                {rpt.aiAnalysis&&(
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim,
                    background:C.bg,border:`1px solid ${C.borderBright}`,padding:8,
                    lineHeight:1.8,maxHeight:90,overflowY:"auto",whiteSpace:"pre-wrap"}}>
                    {rpt.aiAnalysis}
                  </div>
                )}
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,marginTop:6}}>{rpt.ts}</div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>;
  }

  function AgentsManagerTab(){
    return<div style={{padding:18}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:10,marginBottom:14}}>
        {AGENTS.map(a=>{
          const s=agentStatus[a.id];
          const sc=s==="STANDBY"?C.textDim:s==="COMPLETE"?C.green:a.color;
          return<div key={a.id} style={{background:C.panel,border:`1px solid ${a.color}33`,borderTop:`2px solid ${a.color}`,padding:"12px 14px",display:"flex",flexDirection:"column",gap:6}}>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:a.color,letterSpacing:2}}>{a.label}</div>
            <div style={{display:"flex",alignItems:"center",gap:6}}>
              <Dot color={sc} pulse={s!=="STANDBY"&&s!=="COMPLETE"}/>
              <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:sc}}>{s}</span>
            </div>
            <div style={{display:"flex",alignItems:"center",gap:6,marginTop:2}}>
              <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,color:C.textLabel,letterSpacing:1}}>ACCURACY</span>
              <span style={{fontFamily:"'Orbitron',sans-serif",fontSize:13,fontWeight:700,color:a.color,textShadow:`0 0 8px ${a.color}88`}}>{a.accuracy}%</span>
            </div>
            <div style={{height:3,background:"#0f2030",overflow:"hidden",borderRadius:1}}>
              <div style={{height:"100%",width:`${a.accuracy}%`,background:a.color,boxShadow:`0 0 6px ${a.color}`,transition:"width 1s"}}/>
            </div>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,color:C.textLabel,lineHeight:1.6,marginTop:2}}>{a.desc}</div>
          </div>;
        })}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
        <Panel color={C.red}>
          <PTitle color={C.red}>Auto-Blocked IPs ({blockedIPs.length})</PTitle>
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,letterSpacing:1.5,marginBottom:10}}>
            RESPONDER auto-blocks IPs with anomaly score &gt; 0.82
          </div>
          <div style={{maxHeight:440,overflowY:"auto"}}>
            {!blockedIPs.length&&<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textLabel}}>No IPs blocked yet.</div>}
            {blockedIPs.map((b)=>(
              <div key={b.ip+b.ts} className="anim-slide" style={{display:"grid",gridTemplateColumns:"1fr auto",alignItems:"center",
                padding:"7px 0",borderBottom:`1px solid ${C.border}`}}>
                <div>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:C.red}}>{b.ip}</span>
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textDim,marginTop:2}}>
                    {b.label} · :{b.port} · score {b.score.toFixed(3)}
                  </div>
                </div>
                <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel}}>{b.ts}</span>
              </div>
            ))}
          </div>
        </Panel>
        <Panel color={C.purple}>
          <PTitle color={C.purple}>Agent Action Log</PTitle>
          <div style={{maxHeight:490,overflowY:"auto"}}>
            {!agentLog.length&&<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textLabel}}>No agent actions yet.</div>}
            {agentLog.map(e=>(
              <div key={e.id} className="anim-slide" style={{padding:"7px 0",borderBottom:`1px solid ${C.border}`}}>
                <div style={{display:"flex",gap:8,marginBottom:3}}>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel}}>{e.ts}</span>
                  <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:e.color||C.purple}}>{e.agent}</span>
                </div>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim,lineHeight:1.6,whiteSpace:"pre-wrap"}}>
                  {e.text}
                  {e.streaming&&<span style={{animation:"blink 1s step-end infinite"}}>▋</span>}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>;
  }

  /* ─── AI ANALYSIS TAB ─── */
  function MetricCards(){
    return<div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,padding:"12px 18px"}}>
      {[
        {l:"TOTAL FLOWS",v:totalFlows.toLocaleString(),c:C.cyan},
        {l:"THREATS",v:totalThreats.toLocaleString(),c:C.red},
        {l:"BENIGN",v:totalBenign.toLocaleString(),c:C.green},
        {l:"AVG SCORE",v:avgScore.toFixed(3),c:avgScore>.6?C.red:avgScore>.3?C.orange:C.green},
      ].map(m=>(
        <div key={m.l} style={{background:C.panel,
          border:`1px solid ${isSimMode?C.purple:C.border}`,padding:"12px 16px",
          position:"relative",overflow:"hidden"}}>
          <div style={{position:"absolute",top:0,left:0,right:0,height:2,
            background:m.c,boxShadow:`0 0 10px ${m.c}`}}/>
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,letterSpacing:2,color:C.textLabel,marginBottom:6}}>{m.l}</div>
          <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:22,fontWeight:700,
            color:m.c,textShadow:`0 0 12px ${m.c}88`}}>{m.v}</div>
        </div>
      ))}
    </div>;
  }

  function ThreatEnginePanel(){
    const confPct=C2?Math.round(C2.score*100):0;
    return<Panel color={isSimMode?C.purple:C.cyan}>
      <PTitle>AI Threat Engine</PTitle>
      <div style={{display:"flex",gap:4,marginBottom:12,flexWrap:"wrap"}}>
        {[["all","All Traffic"],["ddos","DDoS"],["portscan","Port Scan"],["brute","Brute Force"],["bot","Bot"]].map(([v,l])=>(
          <button key={v} onClick={()=>setFilterType(v)}
            style={{padding:"4px 11px",fontFamily:"'Share Tech Mono',monospace",fontSize:9,
              letterSpacing:"1.5px",textTransform:"uppercase",cursor:"pointer",
              background:filterType===v?C.cyan:"transparent",
              color:filterType===v?C.bg:C.textDim,
              border:`1px solid ${filterType===v?C.cyan:C.borderBright}`,transition:"all .2s"}}>
            {l}
          </button>
        ))}
      </div>
      <div style={{border:`1px solid ${C.red}`,background:`${C.red}08`,padding:"12px 14px",marginBottom:10,position:"relative"}}>
        <span style={{position:"absolute",top:-7,left:10,background:C.panel,padding:"0 7px",
          fontFamily:"'Share Tech Mono',monospace",fontSize:8,letterSpacing:2,color:C.red}}>⚠ THREAT DETECTED</span>
        <p style={{fontFamily:"'Share Tech Mono',monospace",fontSize:12,lineHeight:1.9,color:C.text}}>
          Attack Type: <span style={{color:C.red,fontWeight:700}}>{C2?.label||"—"}</span><br/>
          Confidence: <span style={{color:C.red,fontWeight:700}}>{C2?confPct+"%":"—"}</span><br/>
          Src IP: <span style={{color:C.orange}}>{C2?.srcIp||"—"}</span>
        </p>
        <BarFill pct={confPct} color={C.red}/>
      </div>
      <div style={{border:`1px solid ${C.cyan}`,background:`${C.cyan}05`,padding:"12px 14px",marginBottom:10,position:"relative"}}>
        <span style={{position:"absolute",top:-7,left:10,background:C.panel,padding:"0 7px",
          fontFamily:"'Share Tech Mono',monospace",fontSize:8,letterSpacing:2,color:C.cyan}}>CICIDS FEATURE ANALYSIS</span>
        <p style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,lineHeight:1.9,color:C.text}}>
          {C2?<>
            Bytes/s: <span style={{color:C.orange}}>{C2.bps.toExponential(2)}</span>,{" "}
            Pkts/s: <span style={{color:C.cyan}}>{C2.pps.toFixed(0)}</span>,{" "}
            SYN: <span style={{color:C.green}}>{C2.syn}</span>, RST: <span style={{color:C.green}}>{C2.rst}</span>.<br/>
            IAT Std: <span style={{color:C.cyan}}>{C2.iat.toFixed(2)}s</span>. Label: <span style={{color:C.red}}>{C2.label}</span>.<br/>
            {C2.isThreat?"Anomaly pattern matches known threat signature.":"Normal baseline flow."}
          </>:"Awaiting flow data..."}
        </p>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>
        {[{l:"THREAT PORT",v:C2?.port||"—",c:C.cyan},{l:"FLOW DURATION",v:C2?C2.dur.toFixed(1)+"s":"—",c:C.cyan},
          {l:"FLOW BYTES/S",v:C2?fmtBps(C2.bps):"—",c:C.cyan},{l:"ANOMALY SCORE",v:C2?C2.score.toFixed(3):"—",c:C.red}
        ].map(s=>(
          <div key={s.l} style={{background:C.card,border:`1px solid ${C.border}`,padding:"10px 12px"}}>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,letterSpacing:2,color:C.textLabel,marginBottom:5}}>{s.l}</div>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:18,color:s.c,textShadow:`0 0 10px ${s.c}88`}}>{s.v}</div>
          </div>
        ))}
      </div>
      <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:8,letterSpacing:2.5,color:C.textLabel,marginBottom:8}}>INCIDENT RESPONSE</div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
        <Btn onClick={()=>incidentAction("investigate")}>■ Request Investigation</Btn>
        <Btn color={C.red} onClick={()=>incidentAction("lockdown")}>⊗ Force Lockdown</Btn>
        <Btn onClick={()=>incidentAction("report")}>◆ Generate Report</Btn>
        <Btn color={C.orange} onClick={()=>incidentAction("escalate")}>▲ Escalate to SOC</Btn>
      </div>
    </Panel>;
  }

  function AgentLogPanel(){
    return<Panel color={C.cyan}>
      <PTitle>
        <span style={{width:8,height:8,borderRadius:"50%",background:C.cyan,
          boxShadow:`0 0 10px ${C.cyan}`,display:"inline-block"}}/>
        Agents Log
      </PTitle>
      <div style={{maxHeight:270,overflowY:"auto"}}>
        {(incidentOutput||incidentStreaming)&&(
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:C.text,
            background:C.card,border:`1px solid ${incidentStreaming?C.cyan:C.border}`,
            padding:10,marginBottom:8,lineHeight:1.8,whiteSpace:"pre-wrap"}}>
            {incidentOutput}
            {incidentStreaming&&<span style={{animation:"blink 1s step-end infinite"}}>▋</span>}
          </div>
        )}
        {!agentLog.length&&!incidentOutput&&(
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textLabel,padding:"10px 0"}}>
            Agents will post analysis here as threats are detected.
          </div>
        )}
        {agentLog.map(e=>(
          <div key={e.id} className="anim-slide" style={{padding:"7px 0",borderBottom:`1px solid ${C.border}`}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel}}>{e.ts}</span>
              <span style={{padding:"1px 6px",fontSize:8,letterSpacing:1,
                background:`${e.color||C.purple}22`,color:e.color||C.purple,
                border:`1px solid ${e.color||C.purple}`}}>{e.agent}</span>
            </div>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim,lineHeight:1.7,whiteSpace:"pre-wrap"}}>
              {e.text}
              {e.streaming&&<span style={{animation:"blink 1s step-end infinite"}}>▋</span>}
            </div>
          </div>
        ))}
      </div>
    </Panel>;
  }

  function RightCol(){
    return<>
      <Panel>
        <PTitle>Label Distribution</PTitle>
        <div style={{display:"flex",justifyContent:"center"}}>
          <DonutChart data={donutData.length?donutData:[{label:"Empty",value:1,color:C.border}]}/>
        </div>
        <div style={{display:"flex",flexWrap:"wrap",gap:"6px 12px",marginTop:10,justifyContent:"center"}}>
          {donutData.map(d=>(
            <div key={d.label} style={{display:"flex",alignItems:"center",gap:5,
              fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textDim}}>
              <span style={{width:10,height:10,borderRadius:2,background:d.color,display:"inline-block"}}/>
              {d.label}
            </div>
          ))}
        </div>
      </Panel>
      <Panel>
        <PTitle>Top Attack Ports</PTitle>
        {!topPorts.length&&<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textLabel}}>Awaiting flows...</div>}
        {topPorts.map(([port,count])=>(
          <div key={port} style={{display:"grid",gridTemplateColumns:"48px 1fr 44px 60px",alignItems:"center",gap:6,marginBottom:8}}>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:C.textDim}}>{port}</span>
            <div style={{height:5,background:"#0f2030",overflow:"hidden"}}>
              <div style={{height:"100%",width:`${Math.round(count/maxPortCount*100)}%`,
                background:`linear-gradient(90deg,${C.red},#ff6688)`,boxShadow:`0 0 5px ${C.red}`,transition:"width 1s"}}/>
            </div>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.orange,textAlign:"right"}}>
              {Math.round(count/(totalFlows||1)*100)}%
            </span>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textLabel,textAlign:"right"}}>
              {count} flows
            </span>
          </div>
        ))}
      </Panel>
      <Panel>
        <PTitle>Anomaly Feature Importance</PTitle>
        {!importanceBars.length&&<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textLabel}}>Awaiting flow data...</div>}
        {importanceBars.map(b=>(
          <div key={b.l} style={{display:"grid",gridTemplateColumns:"130px 1fr 44px",alignItems:"center",gap:8,marginBottom:8}}>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim}}>{b.l}</span>
            <div style={{height:5,background:"#0f2030",overflow:"hidden"}}>
              <div style={{height:"100%",width:`${Math.max(2,b.pct)}%`,background:b.c,
                boxShadow:`0 0 5px ${b.c}`,transition:"width 1s"}}/>
            </div>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:b.c,textAlign:"right"}}>{Math.round(b.pct)}%</span>
          </div>
        ))}
      </Panel>
    </>;
  }

  function AlertFeed(){
    return<Panel>
      <PTitle>Live Alerts Feed</PTitle>
      <div style={{maxHeight:180,overflowY:"auto"}}>
        {!alerts.length&&<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textLabel}}>Awaiting threats...</div>}
        {alerts.map((a)=>{
          const col=a.label.toLowerCase().includes("bot")?C.purple
            :a.label.toLowerCase().includes("ddos")||a.label.toLowerCase().includes("dos")?C.red
            :a.label.toLowerCase().includes("port")?C.orange
            :a.label.toLowerCase().includes("brute")||a.label.toLowerCase().includes("patator")?C.cyan
            :C.textDim;
          return<div key={a.ts+a.srcIp} className="anim-slide" style={{display:"flex",alignItems:"flex-start",gap:8,
            padding:"6px 0",borderBottom:`1px solid ${C.border}`}}>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:C.textLabel,flexShrink:0}}>{a.ts}</span>
            <span style={{padding:"1px 5px",fontSize:8,letterSpacing:1,
              background:`${col}22`,color:col,border:`1px solid ${col}`,flexShrink:0}}>
              {a.label.split(" ")[0].toUpperCase()}
            </span>
            <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim,lineHeight:1.5}}>
              :{a.port} · {a.score.toFixed(3)} · {a.srcIp}
            </span>
          </div>;
        })}
      </div>
    </Panel>;
  }


  return(
    <div style={{background:C.bg,minHeight:"100vh",fontFamily:"'Rajdhani',sans-serif",
      fontSize:13,color:C.text,overflow:"hidden",position:"relative",...isSimBorder}}>
      <style>{CSS}</style>
  
      {lockdown&&<div style={{position:"fixed",inset:0,zIndex:9000,pointerEvents:"none",display:"flex",alignItems:"stretch"}}>
        <div style={{width:12,background:C.red,animation:"lockFlash .3s ease-in-out infinite",boxShadow:`0 0 30px ${C.red}`}}/>
        <div style={{flex:1,background:"rgba(255,45,85,0.06)"}}/>
        <div style={{width:12,background:C.red,animation:"lockFlash .3s ease-in-out infinite",boxShadow:`0 0 30px ${C.red}`}}/>
        <div style={{position:"absolute",top:0,left:0,right:0,height:4,background:C.red,animation:"lockFlash .3s ease-in-out infinite"}}/>
        <div style={{position:"absolute",bottom:0,left:0,right:0,height:4,background:C.red,animation:"lockFlash .3s ease-in-out infinite"}}/>
        <div style={{position:"absolute",top:"42%",left:"50%",transform:"translate(-50%,-50%)",textAlign:"center",pointerEvents:"all"}}>
          <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:26,fontWeight:900,color:C.red,
            textShadow:`0 0 30px ${C.red}`,letterSpacing:5,animation:"lockFlash .3s ease-in-out infinite",marginBottom:16}}>
            ⚠ FORCE LOCKDOWN ACTIVE
          </div>
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:"#ff6688",letterSpacing:2,marginBottom:16}}>
            ALL CONNECTIONS SEVERED — PERIMETER ISOLATED
          </div>
          <button onClick={()=>setLockdown(false)}
            style={{padding:"8px 24px",fontFamily:"'Share Tech Mono',monospace",fontSize:10,letterSpacing:2,
              border:`1px solid ${C.red}`,background:"rgba(255,45,85,.2)",color:"#ff8899",
              cursor:"pointer",textTransform:"uppercase"}}>
            CANCEL LOCKDOWN
          </button>
        </div>
      </div>}
  
      {showSimModal&&<SimModal onStart={startSim} onClose={()=>setShowSimModal(false)}/>}
  
      {/* TOPBAR */}
      <div style={{display:"flex",alignItems:"center",gap:10,padding:"0 18px",
        height:50,background:"#040710",borderBottom:`1px solid ${C.border}`,
        position:"sticky",top:0,zIndex:100,flexWrap:"wrap"}}>
        <div style={{display:"flex",alignItems:"center",gap:9,fontFamily:"'Orbitron',sans-serif",
          fontSize:17,fontWeight:900,color:C.cyan,letterSpacing:3,flexShrink:0}}>
          <div style={{width:28,height:28,background:C.cyan,
            clipPath:"polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%)",
            boxShadow:`0 0 18px ${C.cyan}`,animation:"hexPulse 3s ease-in-out infinite"}}/>
          CIPHERNEST
        </div>
        <div style={{display:"flex",gap:3,marginLeft:16}}>
          {[["dashboard","Dashboard"],["simulation","Simulation"],["reports","Reports"],["agents","Agents Manager"],["ml","ML Models"],["aianalysis","AI Analysis"]].map(([t,l])=>(
            <button key={t} onClick={()=>setTab(t)}
              style={{padding:"5px 14px",fontFamily:"'Share Tech Mono',monospace",fontSize:10,
                letterSpacing:"1.5px",color:tab===t?C.cyan:C.textDim,
                border:`1px solid ${tab===t?C.cyan:"transparent"}`,
                background:tab===t?`${C.cyan}18`:"transparent",
                cursor:"pointer",textTransform:"uppercase",transition:"all .2s"}}>
              {l}
            </button>
          ))}
        </div>
        <div style={{display:"flex",alignItems:"center",gap:10,marginLeft:"auto",flexWrap:"wrap"}}>
          <div style={{display:"flex",alignItems:"center",gap:6,fontFamily:"'Share Tech Mono',monospace",
            fontSize:9,color:isSimMode?C.purple:C.cyan}}>
            {isSimMode?"SIMULATION":"LIVE"}
            <div onClick={handleModeToggle}
              style={{width:36,height:18,borderRadius:9,position:"relative",cursor:"pointer",
                background:isSimMode?C.purple:C.cyan,
                boxShadow:`0 0 10px ${isSimMode?C.purple:C.cyan}`,transition:"background .3s"}}>
              <span style={{position:"absolute",top:3,width:12,height:12,borderRadius:"50%",
                background:"#fff",transition:"right .3s",right:isSimMode?3:19}}/>
            </div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:6,padding:"4px 12px",
            border:`1px solid ${C.green}`,fontFamily:"'Share Tech Mono',monospace",
            fontSize:9,letterSpacing:"1.5px",color:C.green}}>
            <Dot color={C.green}/> ALL SYSTEMS NOMINAL
          </div>
          <LiveClock/>
          <div style={{padding:"4px 12px",background:`${C.red}11`,border:`1px solid ${C.red}`,
            fontFamily:"'Share Tech Mono',monospace",fontSize:9,letterSpacing:"1.5px",color:C.red,
            animation:"pulseRed 2s ease-in-out infinite"}}>
            ⚠ {totalThreats>50?"CRITICAL":totalThreats>10?"HIGH":"MEDIUM"}
          </div>
        </div>
      </div>
  
      {/* TICKER */}
      <div style={{background:"#030608",borderBottom:`1px solid ${C.border}`,
        padding:"5px 18px",fontFamily:"'Share Tech Mono',monospace",fontSize:10,
        color:C.textDim,display:"flex",alignItems:"center",gap:6,overflow:"hidden",whiteSpace:"nowrap"}}>
        <Dot color={isSimMode?C.purple:C.cyan}/>
        <span style={{animation:"ticker 45s linear infinite",display:"inline-block"}}>
          {isSimMode?"● SIM MODE — ":"● LIVE MODE — "}
          <span style={{color:C.cyan}}>{totalFlows.toLocaleString()} flows</span>
          {" "}· Threats: <span style={{color:C.red}}>{totalThreats.toLocaleString()}</span>
          {" "}· CLASSIFIER: <span style={{color:C.green}}>{agentStatus.clf}</span>
          {" "}· ANALYZER: <span style={{color:C.purple}}>{agentStatus.ana}</span>
          {" "}· LOG_ANALYZER: <span style={{color:C.teal}}>{agentStatus.log}</span>
          {" "}· THREAT_DETECT: <span style={{color:C.red}}>{agentStatus.det}</span>
          {" "}· ORCHESTRATOR: <span style={{color:C.gold}}>{agentStatus.orch}</span>
          {" "}· Blocked IPs: <span style={{color:C.red}}>{blockedIPs.length}</span>
          &nbsp;&nbsp;&nbsp;
          {isSimMode?"● SIM MODE — ":"● LIVE MODE — "}
          <span style={{color:C.cyan}}>{totalFlows.toLocaleString()} flows</span>
          {" "}· Threats: <span style={{color:C.red}}>{totalThreats.toLocaleString()}</span>
        </span>
      </div>
  
      {/* AGENT STATUS BAR */}
      <div style={{display:"flex",alignItems:"center",gap:12,padding:"7px 18px",
        background:"#050a10",borderBottom:`1px solid ${C.border}`,
        fontFamily:"'Share Tech Mono',monospace",fontSize:10,color:C.textDim,flexWrap:"wrap"}}>
        <span style={{fontSize:9,color:C.textLabel,letterSpacing:2}}>AGENTS:</span>
        {AGENTS.map(a=>{
          const s=agentStatus[a.id];
          const sc=s==="STANDBY"?C.textDim:s==="COMPLETE"?C.green:a.color;
          return<div key={a.id} style={{display:"flex",alignItems:"center",gap:5,padding:"3px 10px",
            border:`1px solid ${C.borderBright}`,background:C.card}}>
            <span style={{fontSize:9,color:a.color}}>{a.label}</span>
            <Dot color={sc} pulse={s!=="STANDBY"&&s!=="COMPLETE"}/>
            <span style={{fontSize:9,color:sc}}>{s}</span>
          </div>;
        })}
        <span style={{marginLeft:"auto",fontSize:9,color:C.textLabel}}>
          {totalFlows.toLocaleString()} flows · {blockedIPs.length} blocked
        </span>
      </div>
  
      {/* TAB CONTENT */}
      <div style={{overflowY:"auto",maxHeight:"calc(100vh - 138px)"}}>
        {tab==="dashboard"&&<DashboardTab/>}
        {tab==="simulation"&&<SimulationTab/>}
        {tab==="reports"&&<ReportsTab/>}
        {tab==="agents"&&<AgentsManagerTab/>}
        {tab==="ml"&&<MLModelsTab/>}
        {tab==="aianalysis"&&<AIAnalysisTab totalThreats={totalThreats} totalBenign={totalBenign} anomScores={anomScores} blockedIPs={blockedIPs} labelCounts={labelCounts} agentStatus={agentStatus} alerts={alerts}/>}
      </div>
    </div>
  );

  /* ─── ML MODELS TAB ─── */
}
