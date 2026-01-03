// app.js
(() => {
  "use strict";

  // ---------- Safe DOM helpers (prevents "null.addEventListener" crash) ----------
  const $ = (id) => document.getElementById(id);
  const on = (id, evt, fn) => {
    const el = $(id);
    if (!el) return false;
    el.addEventListener(evt, fn);
    return true;
  };

  // ---------- Tests ----------
  const TEST_A = [
    "https://example.com/",
    "hello world",
    "<script>alert(1)</script>",
    "SELECT * FROM users WHERE 1=1 OR 1=1",
    ".././../etc/passwd",
    "powershell -enc SQBFAFgA",
    "https://accounts.google.com/signin/oauth/authorize?redirect_uri=https://evil.com"
  ].join("\n");

  const TEST_B = [
    "https://login.microsoftonline.com/common/oauth2/authorize?redirect_uri=https://evil.com",
    "cmd.exe /c whoami",
    "base64: YWxlcnQoMSk7",
    "normal_entry: user_id=2 action=view_report",
    "http://xn--pple-43d.com/login",
    "DROP TABLE users; --",
    "https://evl1.tld/payload.sh | sh"
  ].join("\n");

  // ---------- Heuristics ----------
  const RE = {
    url: /\bhttps?:\/\/[^\s]+/i,
    ip: /\b\d{1,3}(?:\.\d{1,3}){3}\b/,
    xss: /<\s*script\b|onerror\s*=|onload\s*=|javascript:/i,
    sql: /\b(select|union|drop|insert|update|delete)\b.*\b(from|into|where)\b|\bor\s+1\s*=\s*1\b|--|;--/i,
    cmd: /\b(cmd\.exe|powershell|bash\s+-c|sh\s+-c|curl\s+.*\|\s*sh|wget\s+.*\|\s*sh)\b/i,
    lfi: /\.\.\/|\/etc\/passwd|windows\\system32|boot\.ini/i,
    auth: /\boauth\b|\bauthorize\b|\btoken\b|\blogin\b/i,
    redirect: /\bredirect_uri=|returnUrl=|next=|continue=|url=|dest=/i,
    homograph: /xn--/i,
    base64ish: /\b(?:[A-Za-z0-9+\/]{16,}={0,2})\b/,
  };

  function shannonEntropy(str) {
    // simple entropy estimate
    if (!str) return 0;
    const s = str.trim();
    if (!s) return 0;
    const map = new Map();
    for (const ch of s) map.set(ch, (map.get(ch) || 0) + 1);
    let ent = 0;
    const n = s.length;
    for (const [, c] of map) {
      const p = c / n;
      ent -= p * Math.log2(p);
    }
    return +ent.toFixed(2);
  }

  function classifyLine(line) {
    const raw = (line || "").trim();
    const entropy = shannonEntropy(raw);

    const hits = [];
    const score = (label, sev, conf) => hits.push({ label, sev, conf });

    // Type
    let type = "Data";
    if (RE.url.test(raw)) type = "URL";
    if (RE.xss.test(raw)) type = "Exploit";
    if (RE.sql.test(raw)) type = "Exploit";
    if (RE.cmd.test(raw)) type = "Exploit";
    if (RE.lfi.test(raw)) type = "Exploit";

    // Signals
    if (RE.redirect.test(raw)) score("REDIRECT_PARAM", 55, 90);
    if (RE.auth.test(raw) && RE.url.test(raw)) score("AUTH_ENDPOINT", 45, 80);
    if (RE.xss.test(raw)) score("XSS/JS_SCRIPT", 85, 85);
    if (RE.sql.test(raw)) score("SQL:SQLI_TAUTOLOGY", 75, 85);
    if (/\bunion\b.*\bselect\b/i.test(raw)) score("SQL:SQLI_UNION_ALL", 80, 80);
    if (RE.cmd.test(raw)) score("CMD:CMD_CHAIN", 85, 85);
    if (RE.lfi.test(raw)) score("LFI:ETC_PASSWD", 80, 75);
    if (RE.homograph.test(raw)) score("HOMOGRAPH_RISK", 60, 70);
    if (RE.base64ish.test(raw) && raw.length > 40) score("BASE64_DECODE", 35, 70);
    if (entropy >= 4.2 && raw.length >= 30) score("OBFUSCATION", 35, 67);

    // Decision aggregation
    let peak = 0;
    let conf = 0;

    for (const h of hits) {
      if (h.sev > peak) peak = h.sev;
      if (h.conf > conf) conf = h.conf;
    }

    // fallback for empty
    if (!raw) {
      return { input: "", type: "Empty", decision: "ALLOW", severity: 0, confidence: 0, entropy };
    }

    let decision = "ALLOW";
    if (peak >= 80) decision = "BLOCK";
    else if (peak >= 45) decision = "WARN";

    // If redirect param + auth endpoint, nudge to WARN
    if (decision === "ALLOW") {
      const hasRedirect = hits.some(h => h.label === "REDIRECT_PARAM");
      const hasAuth = hits.some(h => h.label === "AUTH_ENDPOINT");
      if (hasRedirect && hasAuth) {
        decision = "WARN";
        peak = Math.max(peak, 50);
        conf = Math.max(conf, 74);
      }
    }

    // If looks like downloader piping to shell, hard block
    if (/\b(curl|wget)\b.*\|\s*(sh|bash)\b/i.test(raw)) {
      decision = "BLOCK";
      peak = Math.max(peak, 90);
      conf = Math.max(conf, 90);
      score("DOWNLOAD_TOOL", 90, 90);
    }

    // Keep within [0..100]
    peak = Math.min(100, Math.max(0, peak));
    conf = Math.min(100, Math.max(0, conf));

    return {
      input: raw,
      type,
      decision,
      severity: peak,
      confidence: conf,
      entropy,
      hits,
    };
  }

  function buildReasonsAndSteps(summary) {
    const reasons = [];
    const steps = [];

    if (summary.block > 0) {
      reasons.push("High-severity exploit patterns detected.");
      steps.push("Block this input in the pipeline.");
      steps.push("Do NOT open. Verify domain ownership carefully.");
    }
    if (summary.warn > 0) {
      reasons.push("Suspicious parameters / authentication context detected.");
      steps.push("Proceed with caution. Verify context and source.");
    }
    if (summary.signals.includes("HOMOGRAPH_RISK")) {
      reasons.push("Suspicious host (punycode) indicates homograph/phishing risk.");
      steps.push("Inspect the domain in a safe environment and compare with the legitimate domain.");
    }
    if (summary.signals.includes("REDIRECT_PARAM")) {
      reasons.push("Potential open-redirect parameter present.");
      steps.push("Validate redirect destinations and enforce allowlist.");
    }
    if (reasons.length === 0) {
      reasons.push("No immediate threat detected. Routine monitoring only.");
      steps.push("Keep standard logging and monitoring.");
    }

    return { reasons, steps };
  }

  // ---------- UI ----------
  function badge(decision) {
    if (decision === "ALLOW") return `<span class="badge ok">ALLOW</span>`;
    if (decision === "WARN") return `<span class="badge warn">WARN</span>`;
    return `<span class="badge bad">BLOCK</span>`;
  }

  function setVerdict(verdict, peak, conf) {
    const banner = $("verdictBanner");
    const title = $("verdictTitle");
    if (!banner || !title) return;

    banner.classList.remove("verdict-secure", "verdict-suspicious", "verdict-danger");

    if (verdict === "SECURE") banner.classList.add("verdict-secure");
    if (verdict === "SUSPICIOUS") banner.classList.add("verdict-suspicious");
    if (verdict === "DANGER") banner.classList.add("verdict-danger");

    title.textContent = verdict;

    const peakEl = $("peakSeverity");
    const confEl = $("confidence");
    if (peakEl) peakEl.textContent = `${peak}%`;
    if (confEl) confEl.textContent = `${conf}%`;
  }

  function renderChips(signalsMap) {
    const wrap = $("signalsChips");
    if (!wrap) return;

    const entries = Array.from(signalsMap.entries())
      .sort((a,b) => b[1] - a[1])
      .slice(0, 12);

    if (entries.length === 0) {
      wrap.innerHTML = `<span class="chip ok">NO_SIGNALS</span>`;
      return;
    }

    wrap.innerHTML = entries.map(([k, n]) => {
      let cls = "ok";
      if (k.startsWith("SQL") || k.startsWith("CMD") || k.startsWith("XSS") || k === "DOWNLOAD_TOOL") cls = "bad";
      else if (k.includes("REDIRECT") || k.includes("AUTH") || k.includes("HOMOGRAPH") || k.includes("OBFUSCATION")) cls = "warn";
      return `<span class="chip ${cls}">${k} <span style="opacity:.7">x${n}</span></span>`;
    }).join("");
  }

  function renderLists(reasons, steps) {
    const r = $("reasonsList");
    const s = $("stepsList");
    if (r) r.innerHTML = reasons.map(x => `<li>${escapeHtml(x)}</li>`).join("");
    if (s) s.innerHTML = steps.map(x => `<li>${escapeHtml(x)}</li>`).join("");
  }

  function escapeHtml(str){
    return String(str)
      .replaceAll("&","&amp;")
      .replaceAll("<","&lt;")
      .replaceAll(">","&gt;")
      .replaceAll('"',"&quot;")
      .replaceAll("'","&#039;");
  }

  function renderTable(rows) {
    const body = $("findingsBody");
    if (!body) return;

    if (!rows.length) {
      body.innerHTML = `<tr class="empty"><td colspan="6">No results yet. Paste input then click Execute Scan.</td></tr>`;
      return;
    }

    body.innerHTML = rows.map(r => `
      <tr>
        <td class="mono">${escapeHtml(r.input)}</td>
        <td>${escapeHtml(r.type)}</td>
        <td>${badge(r.decision)}</td>
        <td>${r.severity}%</td>
        <td>${r.confidence}%</td>
        <td>${r.entropy}</td>
      </tr>
    `).join("");
  }

  function updateStats(summary) {
    const set = (id, v) => { const el=$(id); if (el) el.textContent = String(v); };
    set("statScans", summary.scans);
    set("statAllow", summary.allow);
    set("statWarn", summary.warn);
    set("statBlock", summary.block);
  }

  function computeVerdict(summary) {
    // SECURE / SUSPICIOUS / DANGER
    if (summary.block > 0) return "DANGER";
    if (summary.warn > 0) return "SUSPICIOUS";
    return "SECURE";
  }

  function scan() {
    const input = $("inputStream");
    if (!input) return;

    const lines = input.value.split("\n").map(x => x.trim()).filter(Boolean);
    const rows = lines.map(classifyLine);

    const summary = {
      scans: rows.length,
      allow: rows.filter(r => r.decision === "ALLOW").length,
      warn: rows.filter(r => r.decision === "WARN").length,
      block: rows.filter(r => r.decision === "BLOCK").length,
      peakSeverity: rows.reduce((m, r) => Math.max(m, r.severity), 0),
      confidence: rows.reduce((m, r) => Math.max(m, r.confidence), 0),
      signals: [],
      signalsMap: new Map(),
      rows
    };

    for (const r of rows) {
      for (const h of r.hits) {
        summary.signalsMap.set(h.label, (summary.signalsMap.get(h.label) || 0) + 1);
      }
    }
    summary.signals = Array.from(summary.signalsMap.keys());

    const verdict = computeVerdict(summary);
    setVerdict(verdict, summary.peakSeverity, summary.confidence);
    renderChips(summary.signalsMap);
    updateStats(summary);

    const { reasons, steps } = buildReasonsAndSteps(summary);
    renderLists(reasons, steps);

    renderTable(rows);

    // store last report for export
    window.__VALIDOON_REPORT__ = {
      generatedAt: new Date().toISOString(),
      verdict,
      peakSeverity: summary.peakSeverity,
      confidence: summary.confidence,
      counts: { scans: summary.scans, allow: summary.allow, warn: summary.warn, block: summary.block },
      signals: Array.from(summary.signalsMap.entries()).map(([label, count]) => ({ label, count })),
      rows: summary.rows.map(r => ({
        input: r.input,
        type: r.type,
        decision: r.decision,
        severity: r.severity,
        confidence: r.confidence,
        entropy: r.entropy,
        hits: r.hits
      }))
    };
  }

  function exportJSON() {
    const report = window.__VALIDOON_REPORT__;
    const payload = report ? JSON.stringify(report, null, 2) : JSON.stringify({ error: "No report yet. Click Execute Scan first." }, null, 2);

    const blob = new Blob([payload], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = `validoon_report_${new Date().toISOString().replaceAll(":","-")}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();

    URL.revokeObjectURL(url);
  }

  function clearAll() {
    const input = $("inputStream");
    if (input) input.value = "";

    renderTable([]);
    renderChips(new Map());
    updateStats({ scans:0, allow:0, warn:0, block:0 });
    renderLists(["No immediate threat detected. Routine monitoring only."], ["Keep standard logging and monitoring."]);
    setVerdict("SECURE", 0, 0);

    window.__VALIDOON_REPORT__ = null;
  }

  // ---------- Modal ----------
  function openModal() {
    const b = $("modalBackdrop");
    if (!b) return;
    b.classList.remove("hidden");
    b.setAttribute("aria-hidden", "false");
  }
  function closeModal() {
    const b = $("modalBackdrop");
    if (!b) return;
    b.classList.add("hidden");
    b.setAttribute("aria-hidden", "true");
  }

  // ---------- Boot ----------
  function boot() {
    // Wire buttons safely
    on("btnScan", "click", scan);
    on("btnExport", "click", exportJSON);
    on("btnClear", "click", clearAll);

    on("btnLoadA", "click", () => { const i=$("inputStream"); if(i){ i.value = TEST_A; } });
    on("btnLoadB", "click", () => { const i=$("inputStream"); if(i){ i.value = TEST_B; } });

    on("btnInfo", "click", openModal);
    on("btnCloseModal", "click", closeModal);

    // Close modal on backdrop click
    const backdrop = $("modalBackdrop");
    if (backdrop) {
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) closeModal();
      });
    }

    // Initial state
    clearAll();
  }

  // Because script uses "defer", DOM is ready; still safe:
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
