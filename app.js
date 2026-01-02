// app.js — STEP 2: Smarter Intelligence (no UI changes)
(() => {
  "use strict";

  /* ================= CONFIG ================= */
  const CONFIG = {
    thresholds: { warn: 40, block: 70 },
    entropy: { minLength: 24, high: 4.6, score: 30 },
    confidence: { base: 52, scoreW: 0.38, sigW: 3.2, max: 98 },
    maxLines: 2500,
    redirectKeys: new Set([
      "redirect","redirect_uri","redirecturl","return","returnto",
      "continue","next","url","dest","destination","target"
    ])
  };

  /* ================= UTIL ================= */
  const $ = (id) => document.getElementById(id);
  const clamp = (n,a,b)=>Math.max(a,Math.min(b,n));
  const safeTrim = (v)=>(v??"").toString().trim();

  function clearNode(n){ if(!n) return; while(n.firstChild) n.removeChild(n.firstChild); }

  function entropyNumber(str){
    const s=(str??"").toString(); if(!s.length) return 0;
    const f={}; for(const c of s) f[c]=(f[c]||0)+1;
    let H=0; for(const k in f){ const p=f[k]/s.length; H-=p*Math.log2(p); }
    return Number(H.toFixed(2));
  }

  /* ================= ENGINE ================= */
  const RX = {
    url:/^https?:\/\/\S+$/i,
    ipv4:/^(?:\d{1,3}\.){3}\d{1,3}$/,
    logLine:/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+ip=/
  };

  const RULES = {
    SQLI: [/union\s+select/i,/or\s+1\s*=\s*1/i,/drop\s+table/i,/sleep\s*\(/i],
    XSS: [/<script/i,/javascript:/i,/onerror\s*=/i,/eval\s*\(/i],
    CMDI:[/;\s*(cat|ls|id|whoami|curl|wget)/i,/&&/i],
    LFI: [/\.\.\//i,/\/etc\/passwd/i,/system32/i]
  };

  function classifyBehavior(score, signalCount){
    if(score>=CONFIG.thresholds.block || signalCount>=3) return "malicious";
    if(score>=CONFIG.thresholds.warn || signalCount===2) return "suspicious";
    return "benign";
  }

  function analyzeLine(line){
    const raw=safeTrim(line);
    let score=0;
    const sigs=new Set();
    const reasons=new Set();
    const actions=new Set();

    const decoded=raw;

    /* Apply rules (aggregation-aware) */
    let categoriesHit=0;
    for(const [cat,patterns] of Object.entries(RULES)){
      let hit=false;
      for(const re of patterns){
        if(re.test(decoded)){
          hit=true;
          sigs.add(cat);
        }
      }
      if(hit) categoriesHit++;
    }

    /* Scoring logic */
    if(sigs.has("SQLI")) score=Math.max(score,90);
    if(sigs.has("XSS")) score=Math.max(score,88);
    if(sigs.has("CMDI")) score=Math.max(score,85);
    if(sigs.has("LFI")) score=Math.max(score,90);

    /* Aggregation bonus */
    if(categoriesHit>=2) score+=10;
    if(categoriesHit>=3) score+=20;

    /* Entropy */
    const ent=entropyNumber(decoded);
    if(decoded.length>=CONFIG.entropy.minLength && ent>=CONFIG.entropy.high){
      score=Math.max(score,CONFIG.entropy.score);
      sigs.add("OBFUSCATION");
    }

    score=clamp(score,0,100);

    const decision =
      score>=CONFIG.thresholds.block ? "BLOCK" :
      score>=CONFIG.thresholds.warn ? "WARN" : "ALLOW";

    const behavior = classifyBehavior(score,sigs.size);

    const confRaw =
      CONFIG.confidence.base +
      score*CONFIG.confidence.scoreW +
      sigs.size*CONFIG.confidence.sigW;

    const confidence=Math.round(clamp(confRaw,0,CONFIG.confidence.max));

    /* Actions (unchanged outwardly) */
    if(decision==="BLOCK"){
      actions.add("Block this input in the pipeline.");
      actions.add("Investigate source and sanitize server-side.");
    }else if(decision==="WARN"){
      actions.add("Proceed with caution and verify context.");
    }else{
      actions.add("No immediate threat detected.");
    }

    return {
      input:raw,
      type:RX.url.test(decoded)?"URL":RX.logLine.test(decoded)?"Log":"Data",
      decision,
      score,
      confidence,
      entropy:ent,
      sigs:[...sigs],
      reasons:[...reasons],
      actions:[...actions],
      /* INTERNAL (for next steps) */
      behavior
    };
  }

  /* ================= UI (unchanged) ================= */
  function setVerdictUI(peakScore,peakConf){
    $("riskVal").textContent=`${peakScore}%`;
    $("confVal").textContent=`${peakConf}%`;
    const v=$("verdict");
    if(peakScore>=CONFIG.thresholds.block){
      v.textContent="DANGER"; v.style.color="var(--bad)";
    }else if(peakScore>=CONFIG.thresholds.warn){
      v.textContent="SUSPICIOUS"; v.style.color="var(--warn)";
    }else{
      v.textContent="SECURE"; v.style.color="var(--ok)";
    }
  }

  function resetUI(){
    $("input").value="";
    $("verdict").textContent="---";
    $("verdict").style.color="";
    $("riskVal").textContent="0%";
    $("confVal").textContent="0%";
    clearNode($("signals")); clearNode($("reasons"));
    clearNode($("actions")); clearNode($("tableBody"));
  }

  function renderScan(results){
    clearNode($("signals")); clearNode($("reasons"));
    clearNode($("actions")); clearNode($("tableBody"));
    let ps=0,pc=0;
    const sigs=new Set(),acts=new Set();
    for(const r of results){
      ps=Math.max(ps,r.score); pc=Math.max(pc,r.confidence);
      r.sigs.forEach(s=>sigs.add(s)); r.actions.forEach(a=>acts.add(a));
      const tr=document.createElement("tr");
      tr.innerHTML=`
        <td class="mono">${r.input.slice(0,220)}</td>
        <td>${r.type}</td>
        <td><span class="tag ${r.decision==="BLOCK"?"t-bad":r.decision==="WARN"?"t-warn":"t-ok"}">${r.decision}</span></td>
        <td>${r.score}%</td>
        <td>${r.confidence}%</td>
        <td>${r.entropy}</td>`;
      $("tableBody").appendChild(tr);
    }
    setVerdictUI(ps,pc);
    sigs.forEach(s=>{const c=document.createElement("span");c.className="chip";c.textContent=s;$("signals").appendChild(c);});
    acts.forEach(a=>{const li=document.createElement("li");li.textContent=a;$("actions").appendChild(li);});
  }

  function runScan(){
    const raw=safeTrim($("input").value);
    if(!raw){ resetUI(); return; }
    let lines=raw.split("\n").map(safeTrim).filter(Boolean);
    if(lines.length>CONFIG.maxLines) lines=lines.slice(0,CONFIG.maxLines);
    renderScan(lines.map(analyzeLine));
  }

  function bind(){
    $("btnRun").onclick=runScan;
    $("btnClear").onclick=resetUI;
    $("btnTestA").onclick=()=>{$("input").value="SELECT * FROM users WHERE 1=1;\n<script>alert(1)</script>";runScan();};
    $("btnTestB").onclick=()=>{$("input").value="Normal log entry\nhttps://example.com/login?redirect=http://evil.com";runScan();};
    $("btnExport").onclick=()=>{};
  }

  document.addEventListener("DOMContentLoaded",bind);
})();
