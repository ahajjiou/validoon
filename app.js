// app.js
(() => {
  "use strict";

  // ---------------- CONFIG ----------------
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

  // ---------------- STEP 2 : BEHAVIOR INTELLIGENCE ----------------
  const SUSPICIOUS_SIGNALS = new Set([
    "REDIRECT_PARAM",
    "AUTH_ENDPOINT",
    "BASE64_DECODE",
    "URL_DECODE",
    "HIGH_ENTROPY",
    "INSECURE_HTTP",
    "HOMOGRAPH_RISK",
    "MALFORMED_URL"
  ]);

  // ---------------- UTIL ----------------
  const $ = (id) => document.getElementById(id);

  function clearNode(node){
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function clamp(n, a, b){ return Math.max(a, Math.min(b, n)); }
  function safeTrim(v){ return (v ?? "").toString().trim(); }

  function isMostlyPrintable(str){
    if (!str) return false;
    const cleaned = str.replace(/[^\x20-\x7E]/g, "");
    return cleaned.length / str.length >= 0.7;
  }

  function entropyNumber(str){
    const s = (str ?? "").toString();
    const len = s.length;
    if (!len) return 0;
    const freq = Object.create(null);
    for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
    let H = 0;
    for (const f of Object.values(freq)){
      const p = f / len;
      H -= p * Math.log2(p);
    }
    return Number(H.toFixed(2));
  }

  function tryB64Decode(s){
    const cur = safeTrim(s);
    if (!cur || cur.length < 24) return null;
    if (cur.length % 4 !== 0) return null;
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cur)) return null;
    try {
      const decoded = atob(cur);
      if (!decoded || !isMostlyPrintable(decoded)) return null;
      return decoded;
    } catch { return null; }
  }

  function tryUrlDecode(s){
    const cur = safeTrim(s);
    if (!/%[0-9a-f]{2}/i.test(cur)) return null;
    try{
      const u = decodeURIComponent(cur);
      return (u && u !== cur) ? u : null;
    } catch { return null; }
  }

  // ---------------- ENGINE ----------------
  const RX = {
    url: /^https?:\/\/\S+$/i,
    ipv4: /^(?:\d{1,3}\.){3}\d{1,3}$/,
    logLine: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+ip=.+\bmethod=\w+\b.+\broute=/
  };

  const RULES = {
    SQLI: [
      { re:/\bunion\s+all\s+select\b/i, score:95, sig:"SQLI_UNION_ALL", why:"UNION ALL SELECT indicates SQL injection attempt." },
      { re:/\bor\s+1\s*=\s*1\b/i, score:92, sig:"SQLI_TAUTOLOGY", why:"OR 1=1 tautology detected (SQLi)." }
    ],
    XSS: [
      { re:/<script\b/i, score:92, sig:"XSS_SCRIPT", why:"<script> tag found (XSS payload)." },
      { re:/javascript:/i, score:90, sig:"XSS_JS_URL", why:"javascript: URL detected." }
    ],
    CMDI: [
      { re:/;.*\b(cat|ls|id|whoami)\b/i, score:90, sig:"CMD_CHAIN", why:"Command chaining detected." }
    ],
    LFI: [
      { re:/\.\.\/|\.\.%2f/i, score:85, sig:"PATH_TRAVERSAL", why:"Directory traversal detected." }
    ]
  };

  function decodePipeline(input){
    let cur = safeTrim(input);
    const layers = [];
    if (!cur) return { decoded:"", layers };

    const u = tryUrlDecode(cur);
    if (u){ cur = u; layers.push("URL_DECODE"); }

    const b = tryB64Decode(cur);
    if (b){ cur = b; layers.push("BASE64_DECODE"); }

    return { decoded: cur, layers };
  }

  function applyRules(decoded, sigs, reasons, scoreRef){
    for (const rules of Object.values(RULES)){
      for (const r of rules){
        if (r.re.test(decoded)){
          scoreRef.value = Math.max(scoreRef.value, r.score);
          sigs.add(r.sig);
          reasons.add(r.why);
        }
      }
    }
  }

  function analyzeLine(line){
    const raw = safeTrim(line);
    const { decoded, layers } = decodePipeline(raw);

    const sigs = new Set(layers);
    const reasons = new Set();
    const actions = new Set();
    const scoreRef = { value: 0 };

    applyRules(decoded, sigs, reasons, scoreRef);

    if (RX.url.test(decoded)){
      try{
        const u = new URL(decoded);
        if (u.protocol !== "https:"){
          sigs.add("INSECURE_HTTP");
          reasons.add("URL uses HTTP.");
          scoreRef.value += 20;
        }
        for (const k of u.searchParams.keys()){
          if (CONFIG.redirectKeys.has(k.toLowerCase())){
            sigs.add("REDIRECT_PARAM");
            reasons.add("Redirect parameter detected.");
            scoreRef.value += 15;
          }
        }
      } catch {
        sigs.add("MALFORMED_URL");
        scoreRef.value += 25;
      }
    }

    const ent = entropyNumber(decoded);
    if (decoded.length >= CONFIG.entropy.minLength && ent >= CONFIG.entropy.high){
      sigs.add("HIGH_ENTROPY");
      reasons.add("High entropy content.");
      scoreRef.value = Math.max(scoreRef.value, CONFIG.entropy.score);
    }

    const score = clamp(scoreRef.value, 0, 100);

    // -------- STEP 2 : BEHAVIOR CLASSIFICATION --------
    const suspiciousHits = [...sigs].filter(s => SUSPICIOUS_SIGNALS.has(s)).length;

    let behavior = "benign";
    if (score >= CONFIG.thresholds.block) behavior = "malicious";
    else if (score >= CONFIG.thresholds.warn || suspiciousHits >= 2) behavior = "suspicious";

    const decision =
      behavior === "malicious" ? "BLOCK" :
      behavior === "suspicious" ? "WARN" :
      "ALLOW";

    const confidence = Math.round(
      clamp(CONFIG.confidence.base + score * 0.4 + sigs.size * 3, 0, CONFIG.confidence.max)
    );

    return {
      input: raw,
      type: RX.url.test(decoded) ? "URL" : "Data",
      decision,
      behavior,
      score,
      confidence,
      entropy: ent,
      sigs: [...sigs],
      reasons: [...reasons],
      actions: decision === "BLOCK"
        ? ["Block input","Investigate source","Sanitize server-side"]
        : decision === "WARN"
        ? ["Proceed with caution","Verify context"]
        : ["No action required"]
    };
  }

  // ---------------- UI ----------------
  function runScan(){
    const raw = safeTrim($("input").value);
    if (!raw) return;

    const lines = raw.split("\n").map(safeTrim).filter(Boolean);
    const results = lines.map(analyzeLine);

    clearNode($("tableBody"));
    let peak = 0;

    for (const r of results){
      peak = Math.max(peak, r.score);
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${r.input}</td>
        <td>${r.type}</td>
        <td><span class="tag ${r.decision === "BLOCK" ? "t-bad" : r.decision === "WARN" ? "t-warn" : "t-ok"}">${r.decision}</span></td>
        <td>${r.score}%</td>
        <td>${r.confidence}%</td>
        <td>${r.entropy}</td>`;
      $("tableBody").appendChild(tr);
    }

    $("verdict").textContent = peak >= 70 ? "DANGER" : peak >= 40 ? "SUSPICIOUS" : "SECURE";
    $("riskVal").textContent = peak + "%";
    $("confVal").textContent = Math.max(...results.map(r => r.confidence)) + "%";
  }

  function bind(){
    $("btnRun").addEventListener("click", runScan);
    $("btnClear").addEventListener("click", () => location.reload());
  }

  document.addEventListener("DOMContentLoaded", bind);
})();
