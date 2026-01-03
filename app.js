(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const on = (el, ev, fn) => el && el.addEventListener(ev, fn);

  // ---- Tests
  const TEST_A = [
    "https://example.com/",
    "https://accounts.google.com/signin/v2/identifier",
    "http://example.com/login?redirect=https://evil.invalid",
    "SELECT * FROM users WHERE id='1' OR 1=1;",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "Normal entry: user_id=42 action=view_report",
    "hello world"
  ].join("\n");

  const TEST_B = [
    "https://xn--pple-43d.com/login",
    "UNION ALL SELECT username, password FROM users;",
    "cmd.exe /c whoami",
    "base64: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "../..//..//windows/system32/drivers/etc/hosts",
    "Normal entry: user_id=9 action=download_report"
  ].join("\n");

  // ---- Helpers
  function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

  // crude entropy (for “obfuscation-ish” feel)
  function entropy(str) {
    if (!str) return 0;
    const s = String(str);
    const map = new Map();
    for (const ch of s) map.set(ch, (map.get(ch) || 0) + 1);
    let e = 0;
    for (const [, c] of map) {
      const p = c / s.length;
      e -= p * Math.log2(p);
    }
    return Math.round(e * 100) / 100;
  }

  function classify(line) {
    const l = line.trim();
    if (!l) return { type: "Empty" };

    if (/^https?:\/\//i.test(l)) return { type: "URL" };
    if (/select\s+|union\s+all\s+select|or\s+1\s*=\s*1/i.test(l)) return { type: "Exploit" };
    if (/<script\b|onerror\s*=|javascript:/i.test(l)) return { type: "Exploit" };
    if (/\.\.\/|\/etc\/passwd|windows\\system32|\\system32/i.test(l)) return { type: "Exploit" };
    if (/base64\s*:/i.test(l) || /^[A-Za-z0-9+/]{40,}={0,2}$/.test(l)) return { type: "Data" };
    return { type: "Data" };
  }

  function scanLine(line) {
    const l = line.trim();
    const signals = [];
    const reasons = [];
    let sev = 0;
    let conf = 52;

    // URL signals
    if (/^http:\/\//i.test(l)) {
      signals.push("INSECURE_HTTP");
      reasons.push("URL uses HTTP (unencrypted).");
      sev += 18; conf += 12;
    }
    if (/redirect=|returnUrl=|next=|continue=/i.test(l)) {
      signals.push("REDIRECT_PARAM");
      reasons.push("Potential open-redirect parameter present.");
      sev += 22; conf += 12;
    }
    if (/accounts\.|login|signin|auth/i.test(l) && /^https?:\/\//i.test(l)) {
      signals.push("AUTH_ENDPOINT");
      reasons.push("Authentication-related endpoint detected.");
      sev += 10; conf += 6;
    }
    // homograph-ish / punycode hint
    if (/xn--/i.test(l)) {
      signals.push("HOMOGRAPH_RISK");
      reasons.push("Suspicious host (punycode) indicates homograph/phishing risk.");
      sev += 22; conf += 10;
    }

    // SQLi signals
    if (/or\s+1\s*=\s*1/i.test(l)) {
      signals.push("SQLI:SQLI_TAUTOLOGY");
      reasons.push("OR 1=1 tautology detected (SQLi).");
      sev += 35; conf += 18;
    }
    if (/union\s+all\s+select/i.test(l)) {
      signals.push("SQLI:SQLI_UNION_ALL");
      reasons.push("UNION ALL SELECT indicates SQL injection attempt.");
      sev += 35; conf += 18;
    }

    // XSS signals
    if (/<script\b/i.test(l)) {
      signals.push("XSS:XSS_SCRIPT");
      reasons.push("<script> tag found (XSS payload).");
      sev += 30; conf += 15;
    }

    // LFI / traversal
    if (/\.\.\/|\/etc\/passwd/i.test(l)) {
      signals.push("LFI:LFI_ETC_PASSWD");
      reasons.push("Directory traversal pattern detected.");
      sev += 30; conf += 15;
    }

    // base64
    if (/base64\s*:/i.test(l) || /^[A-Za-z0-9+/]{40,}={0,2}$/.test(l)) {
      signals.push("BASE64_DECODE");
      reasons.push("Base64/encoded content detected (possible obfuscation).");
      sev += 10; conf += 6;
    }

    // cmd chain
    if (/cmd\.exe|powershell|bash\s+-c|;\s*rm\s+-rf/i.test(l)) {
      signals.push("CMD:CMD_CHAIN");
      reasons.push("Command execution chain pattern detected.");
      sev += 35; conf += 18;
    }

    sev = clamp(sev, 0, 100);
    conf = clamp(conf, 0, 99);

    const decision = sev >= 70 ? "BLOCK" : sev >= 35 ? "WARN" : "ALLOW";

    const steps = [];
    if (decision !== "ALLOW") {
      steps.push("Proceed with caution; verify context and source.");
      if (/^https?:\/\//i.test(l)) steps.push("If URL: open in isolated environment and verify domain carefully.");
      steps.push("Block this input in the pipeline.");
      steps.push("Inspect logs for related activity and source.");
      if (signals.some(s => s.startsWith("SQLI"))) steps.push("Ensure parameterized queries / prepared statements.");
      if (signals.includes("XSS:XSS_SCRIPT")) steps.push("Apply output encoding + CSP on affected pages.");
      if (signals.includes("LFI:LFI_ETC_PASSWD")) steps.push("Sanitize/validate server-side paths before processing.");
    } else {
      steps.push("No immediate threat detected. Routine monitoring only.");
    }

    const t = classify(l).type;
    return {
      segment: l,
      type: t,
      decision,
      severity: sev,
      confidence: conf,
      entropy: entropy(l),
      signals,
      reasons,
      steps
    };
  }

  function renderTable(rows) {
    const body = $("#tblBody");
    if (!body) return;

    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="6" class="empty">No results yet.</td></tr>`;
      return;
    }

    body.innerHTML = rows.map(r => {
      const badge = r.decision === "ALLOW" ? "ok" : r.decision === "WARN" ? "warn" : "bad";
      return `
        <tr>
          <td class="mono">${escapeHtml(r.segment)}</td>
          <td>${escapeHtml(r.type)}</td>
          <td><span class="pill ${badge}">${r.decision}</span></td>
          <td>${r.severity}%</td>
          <td>${r.confidence}%</td>
          <td>${r.entropy}</td>
        </tr>
      `;
    }).join("");
  }

  function renderVerdict(rows) {
    const verdictLabel = $("#verdictLabel");
    const kpiSeverity = $("#kpiSeverity");
    const kpiConfidence = $("#kpiConfidence");
    const chips = $("#chips");
    const reasons = $("#reasons");
    const steps = $("#steps");

    const miniScans = $("#miniScans");
    const miniAllow = $("#miniAllow");
    const miniWarn = $("#miniWarn");
    const miniBlock = $("#miniBlock");

    const total = rows.length;
    const allow = rows.filter(r => r.decision === "ALLOW").length;
    const warn = rows.filter(r => r.decision === "WARN").length;
    const block = rows.filter(r => r.decision === "BLOCK").length;

    const peakSev = total ? Math.max(...rows.map(r => r.severity)) : 0;
    const peakConf = total ? Math.max(...rows.map(r => r.confidence)) : 0;

    let overall = "—";
    if (total) overall = peakSev >= 70 ? "DANGER" : peakSev >= 35 ? "SUSPICIOUS" : "SECURE";

    if (verdictLabel) {
      verdictLabel.textContent = overall;
      verdictLabel.className = "verdictLabel " + (overall === "SECURE" ? "ok" : overall === "SUSPICIOUS" ? "warn" : overall === "DANGER" ? "bad" : "");
    }
    if (kpiSeverity) kpiSeverity.textContent = `${peakSev}%`;
    if (kpiConfidence) kpiConfidence.textContent = `${peakConf}%`;

    if (miniScans) miniScans.textContent = String(total);
    if (miniAllow) miniAllow.textContent = String(allow);
    if (miniWarn) miniWarn.textContent = String(warn);
    if (miniBlock) miniBlock.textContent = String(block);

    // signals summary
    const sigSet = new Set();
    rows.forEach(r => r.signals.forEach(s => sigSet.add(s)));
    const sigs = Array.from(sigSet).slice(0, 12);

    if (chips) {
      chips.innerHTML = sigs.map(s => `<span class="chip">${escapeHtml(s)}</span>`).join("") || `<span class="muted">No signals.</span>`;
    }

    // reasons/steps from the highest severity row
    const worst = total ? rows.slice().sort((a,b) => b.severity - a.severity)[0] : null;

    if (reasons) {
      reasons.innerHTML = worst ? worst.reasons.map(x => `<li>${escapeHtml(x)}</li>`).join("") : `<li class="muted">Run a scan to see reasons.</li>`;
    }
    if (steps) {
      steps.innerHTML = worst ? worst.steps.map(x => `<li>${escapeHtml(x)}</li>`).join("") : `<li class="muted">Run a scan to see remediation steps.</li>`;
    }
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function runScan() {
    const txt = $("#txtInput");
    const raw = txt ? txt.value : "";
    const lines = raw.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
    const rows = lines.map(scanLine);
    renderTable(rows);
    renderVerdict(rows);
    window.__VALIDOON_LAST__ = { ts: Date.now(), rows };
  }

  function exportJSON() {
    const data = window.__VALIDOON_LAST__ || { ts: Date.now(), rows: [] };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `validoon_report_${data.ts}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 500);
  }

  // Modal
  function openModal() {
    const m = $("#modal");
    if (!m) return;
    m.classList.add("open");
    m.setAttribute("aria-hidden", "false");
  }
  function closeModal() {
    const m = $("#modal");
    if (!m) return;
    m.classList.remove("open");
    m.setAttribute("aria-hidden", "true");
  }

  // ---- Boot
  document.addEventListener("DOMContentLoaded", () => {
    // Bind safely (won't crash if an element is missing)
    on($("#btnRun"), "click", runScan);
    on($("#btnExport"), "click", exportJSON);
    on($("#btnClear"), "click", () => {
      const t = $("#txtInput");
      if (t) t.value = "";
      renderTable([]);
      renderVerdict([]);
      window.__VALIDOON_LAST__ = { ts: Date.now(), rows: [] };
    });

    on($("#btnLoadA"), "click", () => { const t = $("#txtInput"); if (t) t.value = TEST_A; });
    on($("#btnLoadB"), "click", () => { const t = $("#txtInput"); if (t) t.value = TEST_B; });

    on($("#btnInfo"), "click", openModal);
    on($("#btnCloseModal"), "click", closeModal);
    on($("#modalBackdrop"), "click", closeModal);
    on(document, "keydown", (e) => { if (e.key === "Escape") closeModal(); });

    // Initial clean render
    renderTable([]);
    renderVerdict([]);

    // If there were previous console errors, this guarantees UI still binds.
    console.log("Validoon boot OK");
  });
})();
