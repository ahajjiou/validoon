/* Validoon - minimal local triage engine (no network). */
/* v1.0 */

(() => {
  "use strict";

  // ---------- DOM helpers ----------
  const $ = (id) => document.getElementById(id);
  const el = {
    btnRun: $("btnRun"),
    btnExport: $("btnExport"),
    btnTestA: $("btnTestA"),
    btnTestB: $("btnTestB"),
    btnClear: $("btnClear"),
    input: $("inputStream"),

    verdictLabel: $("verdictLabel"),
    peakSeverity: $("peakSeverity"),
    confidence: $("confidence"),

    countScans: $("countScans"),
    countAllow: $("countAllow"),
    countWarn: $("countWarn"),
    countBlock: $("countBlock"),

    activeSignals: $("activeSignals"),
    primaryReasons: $("primaryReasons"),
    remediationSteps: $("remediationSteps"),
    tableBody: $("resultsTableBody"),
  };

  // Guard: if any required element is missing, show a clear error (instead of blank page)
  const requiredIds = [
    "btnRun","btnExport","btnTestA","btnTestB","btnClear","inputStream",
    "verdictLabel","peakSeverity","confidence",
    "countScans","countAllow","countWarn","countBlock",
    "activeSignals","primaryReasons","remediationSteps","resultsTableBody"
  ];
  for (const id of requiredIds) {
    if (!$(id)) {
      console.error(`Validoon: missing element #${id}`);
      return;
    }
  }

  // ---------- Test payloads ----------
  const TEST_A = [
    "https://example.com/",
    "Normal entry: user_id=42 action=view_report",
    "hello world"
  ].join("\n");

  const TEST_B = [
    "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https://mail.google.com/mail/",
    "http://example.com/login?redirect=https://evil.invalid",
    "SELECT * FROM users WHERE id='1' OR 1=1;",
    "<script>alert(1)</script>",
    "../..//etc/passwd",
    "VGhpcyBpcyBhIHRlc3QgYmFzZTY0IHBheWxvYWQ="
  ].join("\n");

  // ---------- Core detection ----------
  const RX = {
    url: /^(https?:\/\/|www\.)/i,
    insecureHttp: /^http:\/\//i,
    redirectParam: /(?:\?|&)(?:redirect|redir|return|returnto|continue|next|url)=/i,
    authEndpoint: /\/(signin|login|oauth|authorize|auth)\b/i,
    sqlTautology: /\b(or)\s+1\s*=\s*1\b/i,
    sqlUnionAll: /\bunion\s+all\s+select\b/i,
    xssScript: /<\s*script\b|onerror\s*=|onload\s*=/i,
    lfiEtcPasswd: /(\.\.\/)+|\/etc\/passwd\b/i,
    base64Like: /^(?:[A-Za-z0-9+\/]{20,}={0,2})$/,
    cmdChain: /(\&\&|\|\||;)\s*(curl|wget|powershell|bash|sh)\b/i,
    homoglyphRisk: /[^\x00-\x7F]/, // non-ASCII
  };

  function shannonEntropy(str) {
    if (!str) return 0;
    const s = String(str);
    const map = new Map();
    for (const ch of s) map.set(ch, (map.get(ch) || 0) + 1);
    let ent = 0;
    for (const [, count] of map) {
      const p = count / s.length;
      ent -= p * Math.log2(p);
    }
    return Number(ent.toFixed(2));
  }

  function analyzeLine(line) {
    const text = String(line || "").trim();
    if (!text) return null;

    const signals = [];
    const reasons = [];
    const remediation = [];

    // type heuristic
    let type = "Data";
    if (RX.url.test(text)) type = "URL";
    if (RX.sqlUnionAll.test(text) || RX.sqlTautology.test(text)) type = "Exploit";
    if (RX.xssScript.test(text) || RX.lfiEtcPasswd.test(text) || RX.cmdChain.test(text)) type = "Exploit";

    // signals
    if (RX.redirectParam.test(text)) signals.push("REDIRECT_PARAM");
    if (RX.authEndpoint.test(text)) signals.push("AUTH_ENDPOINT");
    if (RX.insecureHttp.test(text)) signals.push("INSECURE_HTTP");
    if (RX.sqlTautology.test(text)) signals.push("SQLI_SQL_TAUTOLOGY");
    if (RX.sqlUnionAll.test(text)) signals.push("SQLI_SQL_UNION_ALL");
    if (RX.xssScript.test(text)) signals.push("XSS_XSS_SCRIPT");
    if (RX.lfiEtcPasswd.test(text)) signals.push("LFI_LFI_ETC_PASSWD");
    if (RX.cmdChain.test(text)) signals.push("CMDI_CMD_CHAIN");

    // base64 (only if looks like base64 and has high-ish entropy)
    const ent = shannonEntropy(text);
    const looksBase64 = RX.base64Like.test(text) && ent >= 4.0;
    if (looksBase64) signals.push("BASE64_DECODE");

    // homoglyph risk (only meaningful for URL-ish strings or domain-like)
    if ((type === "URL" || /[a-z0-9.-]+\.[a-z]{2,}/i.test(text)) && RX.homoglyphRisk.test(text)) {
      signals.push("HOMOGRAPH_RISK");
    }

    // scoring
    let severity = 0;
    const add = (pts, why, fix) => {
      severity += pts;
      if (why) reasons.push(why);
      if (fix) remediation.push(fix);
    };

    if (signals.includes("INSECURE_HTTP")) add(25, "URL uses HTTP (unencrypted).", "Prefer HTTPS; block plain HTTP in production.");
    if (signals.includes("REDIRECT_PARAM")) add(25, "Potential open-redirect parameter present.", "Validate/allowlist redirect targets; avoid user-controlled redirect URLs.");
    if (signals.includes("AUTH_ENDPOINT")) add(15, "Authentication-related endpoint detected.", "Treat auth endpoints as high-sensitivity; enable extra logging and throttling.");
    if (signals.includes("HOMOGRAPH_RISK")) add(20, "Suspicious host (non-ASCII) indicates possible homoglyph/phishing risk.", "Normalize to punycode, alert, and verify domain ownership.");
    if (signals.includes("SQLI_SQL_TAUTOLOGY")) add(35, "OR 1=1 tautology detected (SQLi).", "Use parameterized queries/prepared statements; sanitize and validate server-side.");
    if (signals.includes("SQLI_SQL_UNION_ALL")) add(45, "UNION ALL SELECT indicates SQL injection attempt.", "Block payloads; enforce parameterization and WAF rules.");
    if (signals.includes("XSS_XSS_SCRIPT")) add(40, "<script> or inline event handler indicates XSS payload.", "Escape/encode output; apply CSP; sanitize input; use template auto-escaping.");
    if (signals.includes("LFI_LFI_ETC_PASSWD")) add(45, "Directory traversal / /etc/passwd pattern detected.", "Normalize paths; deny traversal; restrict file access to allowlist directories.");
    if (signals.includes("CMDI_CMD_CHAIN")) add(45, "Command chaining pattern detected.", "Never pass user input to shell; use safe APIs; block metacharacters.");
    if (signals.includes("BASE64_DECODE")) add(10, "High-entropy base64-like payload detected.", "Decode and inspect in isolated environment; log for incident response.");

    // Decision thresholds
    // 0-24 ALLOW, 25-59 WARN, >=60 BLOCK
    let decision = "ALLOW";
    if (severity >= 60) decision = "BLOCK";
    else if (severity >= 25) decision = "WARN";

    // confidence heuristic
    let confidence = 52; // baseline like your UI
    confidence += Math.min(40, signals.length * 8);
    if (type === "Exploit") confidence += 10;
    confidence = Math.max(10, Math.min(99, confidence));

    // ensure unique reasons/steps
    const uniq = (arr) => [...new Set(arr)];

    // If nothing detected: add a safe message
    const finalReasons = reasons.length ? uniq(reasons) : ["No immediate threat detected. Routine monitoring only."];
    const finalRem = remediation.length ? uniq(remediation) : ["Proceed with caution; verify context and source."];

    return {
      segment: text,
      type,
      decision,
      severity: Math.min(99, severity),
      confidence,
      entropy: ent,
      signals: uniq(signals),
      reasons: finalReasons,
      remediation: finalRem,
    };
  }

  function analyzeAll(lines) {
    const results = [];
    for (const line of lines) {
      const r = analyzeLine(line);
      if (r) results.push(r);
    }
    return results;
  }

  // ---------- Rendering ----------
  function clearChildren(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function chip(text) {
    const d = document.createElement("span");
    d.className = "chip";
    d.textContent = text;
    return d;
  }

  function badge(decision) {
    const span = document.createElement("span");
    span.className = "badge badge--" + decision.toLowerCase();
    span.textContent = decision;
    return span;
  }

  function setVerdictTheme(label) {
    // set class on root for theming via CSS
    const root = document.documentElement;
    root.classList.remove("theme-allow","theme-warn","theme-block");
    if (label === "SECURE") root.classList.add("theme-allow");
    else if (label === "SUSPICIOUS") root.classList.add("theme-warn");
    else if (label === "DANGER") root.classList.add("theme-block");
  }

  function computeSystemVerdict(results) {
    if (!results.length) {
      return { label: "—", peakSeverity: 0, confidence: 0 };
    }
    let peak = 0;
    let conf = 0;

    let anyBlock = false;
    let anyWarn = false;

    for (const r of results) {
      peak = Math.max(peak, r.severity);
      conf = Math.max(conf, r.confidence);
      if (r.decision === "BLOCK") anyBlock = true;
      else if (r.decision === "WARN") anyWarn = true;
    }

    let label = "SECURE";
    if (anyBlock) label = "DANGER";
    else if (anyWarn) label = "SUSPICIOUS";

    return { label, peakSeverity: peak, confidence: conf };
  }

  function render(results) {
    // counters
    const scans = results.length;
    const allow = results.filter(r => r.decision === "ALLOW").length;
    const warn  = results.filter(r => r.decision === "WARN").length;
    const block = results.filter(r => r.decision === "BLOCK").length;

    el.countScans.textContent = String(scans);
    el.countAllow.textContent = String(allow);
    el.countWarn.textContent  = String(warn);
    el.countBlock.textContent = String(block);

    const sys = computeSystemVerdict(results);
    el.verdictLabel.textContent = sys.label;
    el.peakSeverity.textContent = `${sys.peakSeverity}%`;
    el.confidence.textContent = `${sys.confidence}%`;

    setVerdictTheme(sys.label);

    // active signals (union)
    const signalSet = new Set();
    for (const r of results) for (const s of r.signals) signalSet.add(s);

    clearChildren(el.activeSignals);
    const sigArr = [...signalSet].slice(0, 16);
    if (!sigArr.length) el.activeSignals.appendChild(chip("NONE"));
    else for (const s of sigArr) el.activeSignals.appendChild(chip(s));

    // reasons (from the most severe line)
    clearChildren(el.primaryReasons);
    clearChildren(el.remediationSteps);

    if (!results.length) {
      const li1 = document.createElement("li");
      li1.textContent = "Paste one item per line, then click Execute Scan.";
      el.primaryReasons.appendChild(li1);

      const li2 = document.createElement("li");
      li2.textContent = "Use Test A/B to validate the pipeline.";
      el.remediationSteps.appendChild(li2);
    } else {
      const top = results.slice().sort((a,b) => (b.severity - a.severity) || (b.confidence - a.confidence))[0];
      for (const r of top.reasons.slice(0, 6)) {
        const li = document.createElement("li");
        li.textContent = r;
        el.primaryReasons.appendChild(li);
      }
      for (const step of top.remediation.slice(0, 6)) {
        const li = document.createElement("li");
        li.textContent = step;
        el.remediationSteps.appendChild(li);
      }
    }

    // table
    clearChildren(el.tableBody);
    if (!results.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.className = "muted";
      td.textContent = "No results yet.";
      tr.appendChild(td);
      el.tableBody.appendChild(tr);
      return;
    }

    for (const r of results) {
      const tr = document.createElement("tr");

      const tdSeg = document.createElement("td");
      tdSeg.className = "mono";
      tdSeg.textContent = r.segment;

      const tdType = document.createElement("td");
      tdType.textContent = r.type;

      const tdDec = document.createElement("td");
      tdDec.appendChild(badge(r.decision));

      const tdSev = document.createElement("td");
      tdSev.textContent = `${r.severity}%`;

      const tdConf = document.createElement("td");
      tdConf.textContent = `${r.confidence}%`;

      const tdEnt = document.createElement("td");
      tdEnt.textContent = String(r.entropy);

      tr.appendChild(tdSeg);
      tr.appendChild(tdType);
      tr.appendChild(tdDec);
      tr.appendChild(tdSev);
      tr.appendChild(tdConf);
      tr.appendChild(tdEnt);

      el.tableBody.appendChild(tr);
    }
  }

  function exportJSON(results) {
    const payload = {
      generated_at: new Date().toISOString(),
      engine: "validoon-local",
      results
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "validoon_report.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ---------- Events ----------
  function runScan() {
    const lines = el.input.value.split("\n").map(s => s.trim()).filter(Boolean);
    const results = analyzeAll(lines);
    window.__VALIDOON_LAST__ = results; // for debugging/export
    render(results);
  }

  function clearAll() {
    el.input.value = "";
    window.__VALIDOON_LAST__ = [];
    render([]);
  }

  el.btnRun.addEventListener("click", runScan);
  el.btnExport.addEventListener("click", () => exportJSON(window.__VALIDOON_LAST__ || []));
  el.btnTestA.addEventListener("click", () => { el.input.value = TEST_A; runScan(); });
  el.btnTestB.addEventListener("click", () => { el.input.value = TEST_B; runScan(); });
  el.btnClear.addEventListener("click", clearAll);

  // First render
  render([]);

})();
