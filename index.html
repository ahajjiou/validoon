// app.js
(() => {
  "use strict";

  // --------- CONFIG ---------
  const CONFIG = {
    thresholds: { warn: 40, block: 70 },
    entropy: { minLength: 24, highEntropyThreshold: 4.6, baseScore: 30 },
    confidence: { base: 52, scoreWeight: 0.38, signalsWeight: 3.2, max: 98 },
    maxLines: 2500,
    redirectKeys: [
      "redirect", "redirect_uri", "redirecturl", "return", "returnto",
      "continue", "next", "url", "dest", "destination", "target"
    ]
  };

  // --------- DETECTION RULES (triage only) ---------
  const RULES = {
    SQLI: [
      { re: /\bunion\s+all\s+select\b/i, score: 96, sig: "UNION_ALL", reason: "UNION ALL SELECT pattern (SQL injection)." },
      { re: /\bunion\s+select\b/i, score: 92, sig: "UNION", reason: "UNION SELECT pattern (SQL injection)." },
      { re: /\bor\s+1\s*=\s*1\b/i, score: 94, sig: "TAUTOLOGY", reason: "SQL tautology OR 1=1 detected." },
      { re: /\b(drop\s+table|truncate\s+table)\b/i, score: 96, sig: "DESTRUCTIVE", reason: "Destructive SQL keyword detected (DROP/TRUNCATE)." },
      { re: /\b(delete\s+from)\b/i, score: 90, sig: "DELETE", reason: "DELETE FROM detected (potential destructive SQL)." },
      { re: /\b(information_schema|pg_catalog)\b/i, score: 90, sig: "META_ENUM", reason: "Database metadata enumeration keywords detected." },
      { re: /\b(xp_cmdshell)\b/i, score: 98, sig: "XPCMDSHELL", reason: "xp_cmdshell detected (OS-level SQLi attempt)." },
      { re: /\b(load_file|into\s+outfile)\b/i, score: 92, sig: "FILE_RW", reason: "SQL file read/write function detected (LOAD_FILE/OUTFILE)." },
      { re: /\b(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)\b/i, score: 90, sig: "TIME_BASED", reason: "Time-based SQL injection indicator detected." }
    ],
    XSS: [
      { re: /<script\b/i, score: 92, sig: "SCRIPT_TAG", reason: "Script tag found (XSS payload indicator)." },
      { re: /on(?:error|load|click|mouseover|focus|submit)\s*=/i, score: 90, sig: "EVENT_HANDLER", reason: "Inline event handler attribute detected." },
      { re: /javascript:/i, score: 90, sig: "JS_URL", reason: "javascript: URL detected (XSS vector)." },
      { re: /\beval\s*\(/i, score: 88, sig: "EVAL", reason: "eval() detected (dangerous sink)." },
      { re: /\b(document\.cookie|localStorage|sessionStorage|document\.location|location\.href)\b/i, score: 85, sig: "SENSITIVE_SINK", reason: "Sensitive browser objects referenced (XSS intent)." },
      { re: /innerHTML\s*=/i, score: 80, sig: "INNERHTML", reason: "innerHTML assignment detected (DOM XSS sink)." },
      { re: /src\s*=\s*["']?\s*data:/i, score: 80, sig: "DATA_URL", reason: "data: URL in src detected (XSS risk)." }
    ],
    CMD: [
      { re: /(?:;|\|\||&&)\s*(?:cat|ls|whoami|id|wget|curl|nc|bash|sh|powershell|cmd)\b/i, score: 90, sig: "CHAINING", reason: "Shell command chaining detected (command injection risk)." },
      { re: /\b(?:rm\s+-rf|del\s+\/f\s+\/q)\b/i, score: 96, sig: "DESTRUCTIVE", reason: "Destructive command detected (rm -rf / del /f /q)." }
    ],
    LFI: [
      { re: /(\.\.\/|\.\.%2f|%2e%2e%2f)/i, score: 86, sig: "TRAVERSAL", reason: "Directory traversal pattern detected (../ or encoded)." },
      { re: /\/etc\/passwd\b/i, score: 92, sig: "ETC_PASSWD", reason: "Attempt to access /etc/passwd detected." },
      { re: /c:\\windows\\system32/i, score: 90, sig: "SYSTEM32", reason: "Attempt to access Windows system32 path detected." }
    ]
  };

  // --------- ENGINE ---------
  class ValidoonEngine {
    static RX = {
      url: /^https?:\/\/\S+$/i,
      ipv4: /^(?:\d{1,3}\.){3}\d{1,3}$/,
      b64: /^[A-Za-z0-9+/]+={0,2}$/,
      logLine: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+ip=.+\bmethod=\w+\b.+\broute=/
    };

    static safeTrim(s) { return (s ?? "").toString().trim(); }

    static entropyNumber(str) {
      const s = (str ?? "").toString();
      const len = s.length;
      if (!len) return 0;
      const freq = Object.create(null);
      for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
      let H = 0;
      for (const f of Object.values(freq)) {
        const p = f / len;
        H -= p * Math.log2(p);
      }
      return Number(H.toFixed(2));
    }

    static decode(text) {
      let cur = this.safeTrim(text);
      const layers = [];
      if (!cur) return { decoded: "", layers };

      // 1) Unicode NFKC
      try {
        const n0 = cur.normalize("NFKC");
        if (n0 !== cur) { cur = n0; layers.push("UNICODE_NFKC"); }
      } catch {}

      // 2) URL decode if looks encoded
      try {
        if (/%[0-9a-f]{2}/i.test(cur)) {
          const u = decodeURIComponent(cur);
          if (u && u !== cur) { cur = u; layers.push("URL_DECODE"); }
        }
      } catch {}

      // 3) Base64 decode (safe heuristic)
      try {
        const looksB64 = this.RX.b64.test(cur) && cur.length >= 24 && (cur.length % 4 === 0);
        if (looksB64) {
          const decoded = atob(cur);
          const printable = decoded.replace(/[^\x20-\x7E]/g, "").length;
          if (decoded.length && (printable / decoded.length) >= 0.7) {
            cur = decoded;
            layers.push("BASE64_DECODE");
          }
        }
      } catch {}

      // 4) Unicode again
      try {
        const n1 = cur.normalize("NFKC");
        if (n1 !== cur) { cur = n1; layers.push("UNICODE_NFKC_POST"); }
      } catch {}

      return { decoded: cur, layers };
    }

    static urlIntel(urlStr, sigs, reasons, scoreRef) {
      let score = scoreRef.value;
      try {
        const u = new URL(urlStr);
        const host = u.hostname || "";
        const path = (u.pathname || "").toLowerCase();

        if (u.protocol !== "https:") {
          score += 20;
          sigs.push("URL:INSECURE_HTTP");
          reasons.push("URL uses HTTP (unencrypted).");
        }

        if (/[^\u0000-\u007F]/.test(host) || /xn--/i.test(host)) {
          score += 40;
          sigs.push("URL:HOMOGRAPH_RISK");
          reasons.push("Suspicious host (non-ASCII or punycode) indicates homograph risk.");
        }

        const keys = Array.from(u.searchParams.keys()).map(k => k.toLowerCase());
        if (keys.some(k => CONFIG.redirectKeys.includes(k))) {
          score += 15;
          sigs.push("URL:REDIRECT_PARAM");
          reasons.push("Potential redirect parameter present (open redirect risk).");
        }

        if (/(^|\/)(login|signin|sign-in|auth|oauth|sso)(\/|$)/i.test(path)) {
          score += 12;
          sigs.push("URL:AUTH_ENDPOINT");
          reasons.push("Authentication-related endpoint detected.");
        }

        if (this.RX.ipv4.test(host)) {
          score += 22;
          sigs.push("URL:IP_HOST");
          reasons.push("URL host is an IP address (phishing risk).");
        }
      } catch {
        score = Math.max(score, 25);
        sigs.push("URL:MALFORMED");
        reasons.push("Malformed URL-like input detected.");
      }
      scoreRef.value = Math.min(score, 100);
    }

    static applyRules(decoded, sigs, reasons, scoreRef) {
      const apply = (cat, rules) => {
        for (const r of rules) {
          if (r.re.test(decoded)) {
            scoreRef.value = Math.max(scoreRef.value, r.score);
            sigs.push(`${cat}:${r.sig}`);
            reasons.push(r.reason);
          }
        }
      };
      apply("SQLI", RULES.SQLI);
      apply("XSS", RULES.XSS);
      apply("CMD", RULES.CMD);
      apply("LFI", RULES.LFI);
    }

    static analyze(text) {
      const raw = this.safeTrim(text);
      const { decoded, layers } = this.decode(raw);

      const sigs = [...layers];
      const reasons = [];
      const actions = new Set();
      const scoreRef = { value: 0 };

      // Apply detection rules
      this.applyRules(decoded, sigs, reasons, scoreRef);

      // URL intelligence
      if (this.RX.url.test(decoded)) this.urlIntel(decoded, sigs, reasons, scoreRef);

      // Entropy / obfuscation
      const ent = this.entropyNumber(decoded);
      if (ent > CONFIG.entropy.highEntropyThreshold && decoded.length >= CONFIG.entropy.minLength) {
        scoreRef.value = Math.max(scoreRef.value, CONFIG.entropy.baseScore);
        sigs.push("OBF:HIGH_ENTROPY");
        reasons.push("High entropy content (possible token/obfuscation).");
      }

      const score = Math.min(scoreRef.value, 100);
      const decision = score >= CONFIG.thresholds.block ? "BLOCK" : (score >= CONFIG.thresholds.warn ? "WARN" : "ALLOW");

      const uniqSigs = Array.from(new Set(sigs));
      const confRaw =
        CONFIG.confidence.base +
        (score * CONFIG.confidence.scoreWeight) +
        (uniqSigs.length * CONFIG.confidence.signalsWeight);
      const confidence = Math.round(Math.min(confRaw, CONFIG.confidence.max));

      // Actions (triage)
      if (decision === "BLOCK") {
        actions.add("Block this input in the pipeline.");
        actions.add("Inspect logs for related activity.");
        actions.add("Sanitize/validate server-side before processing.");
        if (uniqSigs.some(s => s.startsWith("SQLI:"))) actions.add("Use parameterized queries (prepared statements).");
        if (uniqSigs.some(s => s.startsWith("XSS:"))) actions.add("Apply strict output encoding + CSP.");
        if (uniqSigs.some(s => s.startsWith("CMD:"))) actions.add("Remove/whitelist any shell execution paths.");
        if (uniqSigs.some(s => s.startsWith("LFI:"))) actions.add("Normalize paths + restrict file access to allowlist.");
      } else if (decision === "WARN") {
        actions.add("Proceed with caution; verify context and source.");
        actions.add("If this is user input, apply stricter validation rules.");
      } else {
        actions.add("No immediate threat detected.");
      }

      // Type classification
      const isUrl = this.RX.url.test(decoded);
      const isLog = this.RX.logLine.test(decoded);
      let type = "Data";
      if (score >= CONFIG.thresholds.block) type = "Exploit";
      else if (isUrl) type = "URL";
      else if (isLog) type = "Log";

      return {
        input: raw,
        decoded,
        type,
        decision,
        score,
        confidence,
        entropy: ent,
        sigs: uniqSigs,
        reasons: Array.from(new Set(reasons)).slice(0, 10),
        actions: Array.from(actions)
      };
    }
  }

  // --------- UI ---------
  const $ = (id) => document.getElementById(id);

  function clearNode(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function setVerdict(peakScore) {
    const v = $("verdict");
    if (!v) return;
    if (peakScore >= CONFIG.thresholds.block) {
      v.textContent = "DANGER";
      v.style.color = "var(--bad)";
    } else if (peakScore >= CONFIG.thresholds.warn) {
      v.textContent = "SUSPICIOUS";
      v.style.color = "var(--warn)";
    } else {
      v.textContent = "SECURE";
      v.style.color = "var(--ok)";
    }
  }

  function resetUI() {
    const input = $("input");
    if (input) input.value = "";
    const v = $("verdict");
    if (v) { v.textContent = "---"; v.style.color = ""; }
    if ($("riskVal")) $("riskVal").textContent = "0%";
    if ($("confVal")) $("confVal").textContent = "0%";
    clearNode($("signals"));
    clearNode($("reasons"));
    clearNode($("actions"));
    clearNode($("tableBody"));
  }

  function renderRow(result) {
    const tr = document.createElement("tr");

    const tdSeg = document.createElement("td");
    tdSeg.className = "mono";
    tdSeg.textContent = result.input;

    const tdType = document.createElement("td");
    tdType.textContent = result.type;

    const tdDec = document.createElement("td");
    const tag = document.createElement("span");
    tag.className = "tag " + (result.decision === "BLOCK" ? "tag-danger" : (result.decision === "WARN" ? "tag-warn" : "tag-safe"));
    tag.textContent = result.decision;
    tdDec.appendChild(tag);

    const tdScore = document.createElement("td");
    tdScore.textContent = `${result.score}%`;

    const tdConf = document.createElement("td");
    tdConf.textContent = `${result.confidence}%`;

    const tdEnt = document.createElement("td");
    tdEnt.textContent = String(result.entropy);

    tr.append(tdSeg, tdType, tdDec, tdScore, tdConf, tdEnt);
    return tr;
  }

  function runScan() {
    const inputEl = $("input");
    const raw = (inputEl && inputEl.value) ? inputEl.value : "";
    let lines = raw.split("\n").map(s => s.trim()).filter(Boolean);

    clearNode($("tableBody"));
    clearNode($("signals"));
    clearNode($("reasons"));
    clearNode($("actions"));

    if (!lines.length) { resetUI(); return; }

    if (lines.length > CONFIG.maxLines) lines = lines.slice(0, CONFIG.maxLines);

    let peakScore = 0;
    let peakConf = 0;

    const allSigs = new Set();
    const allReasons = new Set();
    const allActions = new Set();

    for (const line of lines) {
      const r = ValidoonEngine.analyze(line);
      peakScore = Math.max(peakScore, r.score);
      peakConf = Math.max(peakConf, r.confidence);
      r.sigs.forEach(s => allSigs.add(s));
      r.reasons.forEach(s => allReasons.add(s));
      r.actions.forEach(s => allActions.add(s));
      $("tableBody").appendChild(renderRow(r));
    }

    $("riskVal").textContent = `${peakScore}%`;
    $("confVal").textContent = `${peakConf}%`;
    setVerdict(peakScore);

    allSigs.forEach(s => {
      const ch = document.createElement("span");
      ch.className = "chip";
      ch.textContent = s;
      $("signals").appendChild(ch);
    });

    Array.from(allReasons).slice(0, 8).forEach(txt => {
      const li = document.createElement("li");
      li.textContent = txt;
      $("reasons").appendChild(li);
    });

    if (!allActions.size) allActions.add("No immediate action required.");
    allActions.forEach(txt => {
      const li = document.createElement("li");
      li.textContent = txt;
      $("actions").appendChild(li);
    });
  }

  function exportJSON() {
    const inputEl = $("input");
    const raw = (inputEl && inputEl.value) ? inputEl.value : "";
    const lines = raw.split("\n").map(s => s.trim()).filter(Boolean).slice(0, CONFIG.maxLines);
    if (!lines.length) return;

    const data = lines.map(l => ValidoonEngine.analyze(l));
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });

    const a = document.createElement("a");
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = "validoon_report.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // --------- TESTS ---------
  const TEST_A = [
    "hello",
    "Normal application log segment: user_id=42 action=view_report",
    "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https://mail.google.com/mail/",
    "http://example.com/login?redirect=https://evil.com",
    "Ym9sdC5uZXQvc2VjdXJpdHk=",
    "https://xn--pple-43d.com/login"
  ].join("\n");

  const TEST_B = [
    "SELECT * FROM users WHERE id='1' OR 1=1;",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "http://host/app?file=../../../../etc/passwd",
    "id; whoami && cat /etc/passwd",
    "https://example.com/auth/login?returnto=https://evil.example"
  ].join("\n");

  // --------- EVENTS (guaranteed by defer) ---------
  function bind() {
    const btnRun = $("btnRun");
    const btnTestA = $("btnTestA");
    const btnTestB = $("btnTestB");
    const btnClear = $("btnClear");
    const btnExport = $("btnExport");
    const inputEl = $("input");

    if (!btnRun || !btnClear || !btnExport || !inputEl) {
      // If IDs mismatch, fail loudly for debugging.
      console.error("Validoon: Missing required DOM elements. Check index.html IDs.");
      return;
    }

    btnRun.addEventListener("click", runScan);
    btnClear.addEventListener("click", resetUI);
    btnExport.addEventListener("click", exportJSON);

    if (btnTestA) btnTestA.addEventListener("click", () => { inputEl.value = TEST_A; });
    if (btnTestB) btnTestB.addEventListener("click", () => { inputEl.value = TEST_B; });

    // Optional: Ctrl+Enter runs scan
    inputEl.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runScan();
    });
  }

  bind();
})();
```0
