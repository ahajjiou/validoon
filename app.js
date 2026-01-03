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
    ]),
    storage: {
      keyLastInput: "validoon:lastInput:v1"
    }
  };

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
      if (!decoded) return null;
      if (!isMostlyPrintable(decoded)) return null;
      return decoded;
    } catch {
      return null;
    }
  }

  function tryUrlDecode(s){
    const cur = safeTrim(s);
    if (!/%[0-9a-f]{2}/i.test(cur)) return null;
    try{
      const u = decodeURIComponent(cur);
      if (u && u !== cur) return u;
      return null;
    } catch {
      return null;
    }
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
      { re:/\bunion\s+select\b/i, score:90, sig:"SQLI_UNION", why:"UNION SELECT indicates SQL injection attempt." },
      { re:/\bor\s+1\s*=\s*1\b/i, score:92, sig:"SQLI_TAUTOLOGY", why:"OR 1=1 tautology detected (SQLi)." },
      { re:/\b(drop\s+table|truncate\s+table)\b/i, score:95, sig:"SQLI_DDL", why:"DROP/TRUNCATE detected (destructive SQL)." },
      { re:/\b(delete\s+from)\b/i, score:90, sig:"SQLI_DELETE", why:"DELETE FROM detected (destructive SQL risk)." },
      { re:/\b(information_schema|pg_catalog)\b/i, score:90, sig:"SQLI_META", why:"Metadata enumeration patterns detected." },
      { re:/\b(waitfor\s+delay|sleep\s*\(|benchmark\s*\()\b/i, score:88, sig:"SQLI_TIME", why:"Time-based SQLi indicator detected." }
    ],
    XSS: [
      { re:/<script\b/i, score:92, sig:"XSS_SCRIPT", why:"<script> tag found (XSS payload)." },
      { re:/on(?:error|load|click|mouseover|focus|submit)\s*=/i, score:90, sig:"XSS_EVT", why:"Inline event handler detected." },
      { re:/javascript:/i, score:90, sig:"XSS_JS_URL", why:"javascript: URL detected." },
      { re:/\beval\s*\(/i, score:88, sig:"XSS_EVAL", why:"eval() detected (dangerous sink)." },
      { re:/\b(document\.cookie|localStorage|sessionStorage|document\.location|location\.href)\b/i, score:85, sig:"XSS_SINK", why:"Sensitive browser object access detected." }
    ],
    CMDI: [
      { re:/(?:;|\|\||&&)\s*(?:cat|ls|whoami|id|wget|curl|nc|bash|sh|powershell|cmd)\b/i, score:90, sig:"CMD_CHAIN", why:"Shell command chaining detected (command injection risk)." },
      { re:/\b(?:rm\s+-rf|del\s+\/f\s+\/q)\b/i, score:95, sig:"CMD_DESTRUCT", why:"Destructive command detected." }
    ],
    LFI: [
      { re:/\.\.\/|\.\.%2f|%2e%2e%2f/i, score:85, sig:"PATH_TRAVERSAL", why:"Directory traversal pattern detected." },
      { re:/\/etc\/passwd\b/i, score:92, sig:"LFI_ETC_PASSWD", why:"Attempt to access /etc/passwd detected." },
      { re:/c:\\windows\\system32/i, score:90, sig:"LFI_SYSTEM32", why:"Attempt to access Windows system32 detected." }
    ]
  };

  function decodePipeline(input){
    let cur = safeTrim(input);
    const layers = [];
    if (!cur) return { decoded:"", layers };

    try{
      const n0 = cur.normalize("NFKC");
      if (n0 !== cur){ cur = n0; layers.push("UNICODE_NFKC"); }
    } catch {}

    const u = tryUrlDecode(cur);
    if (u){ cur = u; layers.push("URL_DECODE"); }

    const b = tryB64Decode(cur);
    if (b){ cur = b; layers.push("BASE64_DECODE"); }

    try{
      const n1 = cur.normalize("NFKC");
      if (n1 !== cur){ cur = n1; layers.push("UNICODE_NFKC_POST"); }
    } catch {}

    return { decoded: cur, layers };
  }

  function urlIntel(urlStr, sigs, reasons, scoreRef){
    let score = scoreRef.value;
    try{
      const u = new URL(urlStr);
      const host = u.hostname || "";
      const path = (u.pathname || "").toLowerCase();

      if (u.protocol !== "https:"){
        score += 20; sigs.add("INSECURE_HTTP");
        reasons.add("URL uses HTTP (unencrypted).");
      }

      if (/[^\u0000-\u007F]/.test(host) || /xn--/i.test(host)){
        score += 40; sigs.add("HOMOGRAPH_RISK");
        reasons.add("Suspicious host (non-ASCII or punycode) indicates homograph/phishing risk.");
      }

      for (const k of u.searchParams.keys()){
        const key = (k || "").toLowerCase();
        if (CONFIG.redirectKeys.has(key)){
          score += 15; sigs.add("REDIRECT_PARAM");
          reasons.add("Potential open-redirect parameter present.");
          break;
        }
      }

      if (/(^|\/)(login|signin|sign-in|auth|oauth|sso)(\/|$)/i.test(path)){
        score += 12; sigs.add("AUTH_ENDPOINT");
        reasons.add("Authentication-related endpoint detected.");
      }

      if (RX.ipv4.test(host)){
        score += 22; sigs.add("IP_HOST");
        reasons.add("URL host is an IP address (phishing risk).");
      }
    } catch {
      score = Math.max(score, 25);
      sigs.add("MALFORMED_URL");
      reasons.add("Malformed URL-like input detected.");
    }

    scoreRef.value = clamp(score, 0, 100);
  }

  function applyRules(decoded, sigs, reasons, scoreRef){
    for (const [group, rules] of Object.entries(RULES)){
      for (const r of rules){
        if (r.re.test(decoded)){
          scoreRef.value = Math.max(scoreRef.value, r.score);
          sigs.add(`${group}:${r.sig}`);
          reasons.add(r.why);
        }
      }
    }
  }

  function analyzeLine(line){
    const raw = safeTrim(line);
    const { decoded, layers } = decodePipeline(raw);

    const scoreRef = { value: 0 };
    const sigs = new Set(layers);
    const reasons = new Set();
    const actions = new Set();

    applyRules(decoded, sigs, reasons, scoreRef);

    if (RX.url.test(decoded)){
      urlIntel(decoded, sigs, reasons, scoreRef);
    }

    const ent = entropyNumber(decoded);
    if (decoded.length >= CONFIG.entropy.minLength && ent >= CONFIG.entropy.high){
      scoreRef.value = Math.max(scoreRef.value, CONFIG.entropy.score);
      sigs.add("HIGH_ENTROPY");
      reasons.add("High entropy content suggests token/obfuscation.");
    }

    const score = clamp(scoreRef.value, 0, 100);
    const decision = score >= CONFIG.thresholds.block ? "BLOCK" : (score >= CONFIG.thresholds.warn ? "WARN" : "ALLOW");

    const sigCount = sigs.size;
    const confRaw = CONFIG.confidence.base + (score * CONFIG.confidence.scoreW) + (sigCount * CONFIG.confidence.sigW);
    const confidence = Math.round(clamp(confRaw, 0, CONFIG.confidence.max));

    if (decision === "BLOCK"){
      actions.add("Block this input in the pipeline.");
      actions.add("Inspect logs for related activity and source.");
      actions.add("Sanitize/validate server-side before processing.");
      if ([...sigs].some(s => s.startsWith("SQLI:"))) actions.add("Ensure parameterized queries / prepared statements.");
      if ([...sigs].some(s => s.startsWith("XSS:"))) actions.add("Apply output encoding + CSP on affected pages.");
      if ([...sigs].some(s => s.startsWith("CMDI:"))) actions.add("Remove direct shell execution or strictly whitelist args.");
      if ([...sigs].some(s => s.startsWith("LFI:"))) actions.add("Block traversal patterns and harden file access.");
    } else if (decision === "WARN"){
      actions.add("Proceed with caution; verify context and source.");
      actions.add("If URL: open in isolated environment and verify domain carefully.");
    } else {
      actions.add("No immediate threat detected. Routine monitoring only.");
    }

    let type = "Data";
    if (RX.logLine.test(decoded)) type = "Log";
    if (RX.url.test(decoded)) type = "URL";
    if (score >= CONFIG.thresholds.block) type = "Exploit";

    return {
      input: raw,
      decoded,
      type,
      decision,
      score,
      confidence,
      entropy: ent,
      sigs: [...sigs],
      reasons: [...reasons].slice(0, 10),
      actions: [...actions]
    };
  }

  // ---------------- STORAGE (Step 4) ----------------
  function saveLastInput(){
    try{
      const v = safeTrim($("input")?.value);
      if (v) localStorage.setItem(CONFIG.storage.keyLastInput, v);
    } catch {}
  }

  function restoreLastInput(){
    try{
      const v = localStorage.getItem(CONFIG.storage.keyLastInput);
      if (v && $("input")) $("input").value = v;
    } catch {}
  }

  // ---------------- UI ----------------
  function setVerdictUI(peakScore, peakConf){
    const verdictEl = $("verdict");
    const riskEl = $("riskVal");
    const confEl = $("confVal");

    riskEl.textContent = `${peakScore}%`;
    confEl.textContent = `${peakConf}%`;

    if (peakScore >= CONFIG.thresholds.block){
      verdictEl.textContent = "DANGER";
      verdictEl.style.color = "var(--bad)";
    } else if (peakScore >= CONFIG.thresholds.warn){
      verdictEl.textContent = "SUSPICIOUS";
      verdictEl.style.color = "var(--warn)";
    } else {
      verdictEl.textContent = "SECURE";
      verdictEl.style.color = "var(--ok)";
    }
  }

  function resetUI(){
    const input = $("input");
    if (input) input.value = "";

    const verdictEl = $("verdict");
    verdictEl.textContent = "---";
    verdictEl.style.color = "";

    $("riskVal").textContent = "0%";
    $("confVal").textContent = "0%";

    clearNode($("signals"));
    clearNode($("reasons"));
    clearNode($("actions"));
    clearNode($("tableBody"));
  }

  function renderScan(results){
    clearNode($("signals"));
    clearNode($("reasons"));
    clearNode($("actions"));
    clearNode($("tableBody"));

    let peakScore = 0;
    let peakConf = 0;

    const allSigs = new Set();
    const allReasons = new Set();
    const allActions = new Set();

    for (const r of results){
      peakScore = Math.max(peakScore, r.score);
      peakConf = Math.max(peakConf, r.confidence);

      r.sigs.forEach(s => allSigs.add(s));
      r.reasons.forEach(x => allReasons.add(x));
      r.actions.forEach(x => allActions.add(x));

      const tr = document.createElement("tr");

      const tdSeg = document.createElement("td");
      tdSeg.className = "mono";
      tdSeg.textContent = r.input.length > 220 ? (r.input.slice(0, 220) + "…") : r.input;

      const tdType = document.createElement("td");
      tdType.textContent = r.type;

      const tdDec = document.createElement("td");
      const tag = document.createElement("span");
      tag.className = "tag " + (r.decision === "BLOCK" ? "t-bad" : (r.decision === "WARN" ? "t-warn" : "t-ok"));
      tag.textContent = r.decision;
      tdDec.appendChild(tag);

      const tdScore = document.createElement("td");
      tdScore.textContent = `${r.score}%`;

      const tdConf = document.createElement("td");
      tdConf.textContent = `${r.confidence}%`;

      const tdEnt = document.createElement("td");
      tdEnt.textContent = String(r.entropy);

      tr.append(tdSeg, tdType, tdDec, tdScore, tdConf, tdEnt);
      $("tableBody").appendChild(tr);
    }

    setVerdictUI(peakScore, peakConf);

    [...allSigs].slice(0, 30).forEach(s => {
      const ch = document.createElement("span");
      ch.className = "chip";
      ch.textContent = s;
      $("signals").appendChild(ch);
    });

    [...allReasons].slice(0, 6).forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      $("reasons").appendChild(li);
    });

    if (!allActions.size) allActions.add("No immediate action required.");
    [...allActions].slice(0, 8).forEach(a => {
      const li = document.createElement("li");
      li.textContent = a;
      $("actions").appendChild(li);
    });
  }

  function runScan(){
    const raw = safeTrim($("input").value);
    if (!raw){
      resetUI();
      return;
    }

    let lines = raw.split("\n").map(s => safeTrim(s)).filter(Boolean);
    if (lines.length > CONFIG.maxLines) lines = lines.slice(0, CONFIG.maxLines);

    const results = lines.map(analyzeLine);
    renderScan(results);

    // Step 4 retention
    saveLastInput();
  }

  function exportJSON(){
    const raw = safeTrim($("input").value);
    if (!raw) return;

    let lines = raw.split("\n").map(s => safeTrim(s)).filter(Boolean);
    if (!lines.length) return;
    if (lines.length > CONFIG.maxLines) lines = lines.slice(0, CONFIG.maxLines);

    const data = lines.map(analyzeLine);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type:"application/json" });
    const a = document.createElement("a");
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = "validoon_forensic.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ---------------- TEST SUITES ----------------
  function loadTestA(){
    $("input").value =
`https://accounts.google.com/signin/v2/identifier?service=mail&continue=https://mail.google.com/mail/
http://example.com/login?redirect=https://evil.invalid
https://xn--pple-43d.com/login
https://аpple.com/login
SELECT * FROM users WHERE id='1' OR 1=1;
UNION ALL SELECT username,password FROM users;
<script>alert(1)</script>
id; whoami && cat /etc/passwd
../../../etc/passwd
Ym9sdC5uZXQvc2VjdXJpdHk=`;
  }

  function loadTestB(){
    $("input").value =
`2026-01-02T10:12:02Z ip=91.203.12.44 method=GET route=/auth/login status=200 dur_ms=124 uid=0 cid=c184920 ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36"
2026-01-02T10:12:07Z ip=91.203.12.44 method=GET route=/auth/login?redirect=http://example.com status=302 dur_ms=88 uid=0 cid=c184920 ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36"
2026-01-02T10:12:11Z ip=185.11.22.9 method=GET route=/api/v1/search?q=report status=200 dur_ms=41 uid=42 cid=c553210 ua="Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0"
2026-01-02T10:12:15Z ip=185.11.22.9 method=GET route=SELECT * FROM users WHERE '1'='1'; status=400 dur_ms=9 uid=0 cid=c553210 ua="Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0"
2026-01-02T10:12:19Z ip=5.6.7.8 method=GET route=<script>fetch('x')</script> status=400 dur_ms=7 uid=0 cid=c993771 ua="Mozilla/5.0 (Android 14; Pixel 7) AppleWebKit/537.36 Chrome/121.0 Mobile Safari/537.36"
Normal entry: user_id=42 action=view_report`;
  }

  // ---------------- STEP 4 UI BUTTON ----------------
  function testAnotherInput(){
    // Keep lastInput saved (Retention), only reset the screen for a new run
    resetUI();
    const inp = $("input");
    if (inp){
      inp.focus();
    }
  }

  // ---------------- WIRE EVENTS ----------------
  function bind(){
    // Required elements (if any missing, scanning can’t work)
    const required = ["btnRun","btnClear","btnTestA","btnTestB","btnExport","input","verdict","riskVal","confVal","signals","reasons","actions","tableBody"];
    for (const id of required){
      if (!$(id)){
        console.error(`Validoon: missing required element #${id}`);
        return;
      }
    }

    $("btnRun").addEventListener("click", runScan);
    $("btnClear").addEventListener("click", resetUI);
    $("btnTestA").addEventListener("click", () => { loadTestA(); runScan(); });
    $("btnTestB").addEventListener("click", () => { loadTestB(); runScan(); });
    $("btnExport").addEventListener("click", exportJSON);

    // Optional: Step 4 button (should exist now)
    const btnAnother = $("btnAnother");
    if (btnAnother){
      btnAnother.addEventListener("click", testAnotherInput);
    }

    $("input").addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runScan();
    });

    // Restore last input (Retention)
    restoreLastInput();
  }

  document.addEventListener("DOMContentLoaded", bind);
})();
