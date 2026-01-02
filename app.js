// app.js
(() => {
  "use strict";

  // -------------------- Config --------------------
  const CONFIG = {
    thresholds: { warn: 40, block: 70 },
    entropy: { minLength: 24, high: 4.6, baseScore: 30 },
    confidence: { base: 55, scoreWeight: 0.35, signalsWeight: 3.0, max: 98 },
    maxLines: 2500,
    redirectKeys: new Set([
      "redirect", "redirect_uri", "redirecturl", "return", "returnto",
      "continue", "next", "url", "dest", "destination", "target"
    ])
  };

  // -------------------- Utilities --------------------
  const $ = (id) => document.getElementById(id);

  function clearNode(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function safeTrim(s) {
    return (s ?? "").toString().trim();
  }

  function entropyNumber(str) {
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

  // crypto-safe-ish random (for test generation if needed later)
  const hasCrypto = typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function";
  function rand01() {
    if (hasCrypto) {
      const r = new Uint32Array(1);
      crypto.getRandomValues(r);
      return r[0] / 0x100000000;
    }
    return Math.random();
  }
  function rngInt(min, max) {
    return Math.floor(rand01() * (max - min + 1)) + min;
  }

  // -------------------- Engine --------------------
  class ValidoonEngine {
    static RX = {
      url: /^https?:\/\/\S+$/i,
      ipv4: /^(?:\d{1,3}\.){3}\d{1,3}$/,
      b64: /^[A-Za-z0-9+/]+={0,2}$/,

      // detection (triage-level, not exhaustive)
      sqli: [
        { re: /\bunion\s+all\s+select\b/i, score: 95, signal: "SQLI_UNION_ALL", reason: "UNION ALL SELECT indicates SQL injection." },
        { re: /\bunion\s+select\b/i, score: 90, signal: "SQLI_UNION", reason: "UNION SELECT indicates SQL injection." },
        { re: /\bor\s+1\s*=\s*1\b/i, score: 92, signal: "SQLI_TAUTOLOGY", reason: "SQL tautology (OR 1=1) detected." },
        { re: /\b(drop\s+table|truncate\s+table)\b/i, score: 95, signal: "SQLI_DESTRUCTIVE", reason: "Destructive SQL keyword detected." },
        { re: /\b(delete\s+from)\b/i, score: 90, signal: "SQLI_DELETE", reason: "DELETE FROM detected (potential destructive SQL)." },
        { re: /\b(information_schema|pg_catalog)\b/i, score: 90, signal: "SQLI_METADATA", reason: "Database metadata enumeration detected." },
        { re: /\bxp_cmdshell\b/i, score: 98, signal: "SQLI_XPCMDSHELL", reason: "xp_cmdshell indicates OS-level injection attempt." },
        { re: /\b(load_file|into\s+outfile)\b/i, score: 92, signal: "SQLI_FILE_IO", reason: "SQL file read/write primitives detected." },
        { re: /\b(sleep\s*\(|waitfor\s+delay)\b/i, score: 88, signal: "SQLI_TIME", reason: "Time-based SQLi indicator detected." }
      ],
      xss: [
        { re: /<script\b/i, score: 92, signal: "XSS_SCRIPT_TAG", reason: "Script tag found (XSS payload indicator)." },
        { re: /javascript:/i, score: 90, signal: "XSS_JS_URL", reason: "javascript: URL detected (XSS vector)." },
        { re: /on(?:error|load|click|mouseover|focus|submit)\s*=/i, score: 90, signal: "XSS_EVENT_HANDLER", reason: "Inline event handler detected (XSS vector)." },
        { re: /\beval\s*\(/i, score: 88, signal: "XSS_EVAL", reason: "eval() detected (dangerous sink)." },
        { re: /\b(document\.cookie|localStorage|sessionStorage|location\.href|document\.location)\b/i, score: 85, signal: "XSS_SENSITIVE", reason: "Access to sensitive browser objects detected." },
        { re: /innerHTML\s*=/i, score: 80, signal: "XSS_INNERHTML", reason: "innerHTML assignment detected (DOM XSS sink)." }
      ],
      traversal: [
        { re: /(\.\.\/|\.\.%2f|%2e%2e%2f)/i, score: 85, signal: "PATH_TRAVERSAL", reason: "Directory traversal pattern detected (../)." },
        { re: /\/etc\/passwd\b/i, score: 92, signal: "LFI_ETC_PASSWD", reason: "Attempt to access /etc/passwd detected." },
        { re: /c:\\\\windows\\\\system32/i, score: 90, signal: "LFI_SYSTEM32", reason: "Attempt to access Windows system32 detected." }
      ],
      cmd: [
        { re: /(?:;|\|\||&&)\s*(?:cat|ls|whoami|id|wget|curl|nc|bash|sh|powershell|cmd)\b/i, score: 90, signal: "CMD_CHAINING", reason: "Shell command chaining detected (command injection)." },
        { re: /\b(?:rm\s+-rf|del\s+\/f\s+\/q)\b/i, score: 95, signal: "CMD_DESTRUCTIVE", reason: "Destructive shell command detected." }
      ]
    };

    static decode(text) {
      let cur = safeTrim(text);
      const layers = [];
      if (!cur) return { decoded: "", layers };

      // 1) Unicode normalization
      try {
        const n0 = cur.normalize("NFKC");
        if (n0 !== cur) { cur = n0; layers.push("UNICODE_NFKC"); }
      } catch {}

      // 2) URL decode
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
          if (decoded.length && (printable / decoded.length) >= 0.70) {
            cur = decoded;
            layers.push("BASE64_DECODE");
          }
        }
      } catch {}

      // 4) Unicode again post-decode
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
          score += 18; sigs.add("INSECURE_HTTP"); reasons.add("URL uses HTTP (unencrypted).");
        }

        if (/[^\u0000-\u007F]/.test(host) || /xn--/i.test(host)) {
          score += 35; sigs.add("HOMOGRAPH_PUNYCODE"); reasons.add("Non-ASCII/punycode host indicates look-alike domain risk.");
        }

        if (this.RX.ipv4.test(host)) {
          score += 18; sigs.add("IP_HOST"); reasons.add("URL host is an IP address (higher phishing risk).");
        }

        const keys = Array.from(u.searchParams.keys()).map(k => k.toLowerCase());
        if (keys.some(k => CONFIG.redirectKeys.has(k))) {
          score += 12; sigs.add("REDIRECT_PARAM"); reasons.add("Redirect-like query parameter detected (open-redirect pattern).");
        }

        if (/(^|\/)(login|signin|sign-in|auth|oauth|sso)(\/|$)/i.test(path)) {
          score += 10; sigs.add("AUTH_ENDPOINT"); reasons.add("Authentication-related endpoint detected (phishing-sensitive).");
        }
      } catch {
        score = Math.max(score, 20);
        sigs.add("MALFORMED_URL");
        reasons.add("Malformed URL-like input detected.");
      }
      scoreRef.value = score;
    }

    static applyRules(decoded, sigs, reasons, scoreRef) {
      const apply = (prefix, rules) => {
        for (const rule of rules) {
          if (rule.re.test(decoded)) {
            scoreRef.value = Math.max(scoreRef.value, rule.score);
            sigs.add(`${prefix}:${rule.signal}`);
            reasons.add(rule.reason);
          }
        }
      };
      apply("SQLI", this.RX.sqli);
      apply("XSS", this.RX.xss);
      apply("LFI", this.RX.traversal);
      apply("CMD", this.RX.cmd);
    }

    static analyze(line) {
      const raw = safeTrim(line);
      const { decoded, layers } = this.decode(raw);

      const sigs = new Set(layers);
      const reasons = new Set();
      const actions = new Set();
      const scoreRef = { value: 0 };

      this.applyRules(decoded, sigs, reasons, scoreRef);

      // URL intelligence
      const isUrl = this.RX.url.test(decoded);
      if (isUrl) {
        sigs.add("URL");
        this.urlIntel(decoded, sigs, reasons, scoreRef);
      }

      // Entropy / obfuscation
      const ent = entropyNumber(decoded);
      if (decoded.length >= CONFIG.entropy.minLength && ent >= CONFIG.entropy.high) {
        scoreRef.value = Math.max(scoreRef.value, CONFIG.entropy.baseScore);
        sigs.add("HIGH_ENTROPY");
        reasons.add("High entropy content (token/obfuscation signal).");
      }

      const score = Math.min(scoreRef.value, 100);
      const decision = score >= CONFIG.thresholds.block ? "BLOCK" : (score >= CONFIG.thresholds.warn ? "WARN" : "ALLOW");

      const uniqSigs = Array.from(sigs);
      const confRaw =
        CONFIG.confidence.base +
        (score * CONFIG.confidence.scoreWeight) +
        (uniqSigs.length * CONFIG.confidence.signalsWeight);
      const confidence = Math.min(confRaw, CONFIG.confidence.max);

      // Actions
      if (decision === "BLOCK") {
        actions.add("Block or quarantine this input.");
        actions.add("Inspect surrounding context/logs for related activity.");
        actions.add("Enforce strict server-side validation before processing.");
        if (uniqSigs.some(s => s.startsWith("SQLI:"))) actions.add("Use prepared statements / parameterized queries.");
        if (uniqSigs.some(s => s.startsWith("XSS:"))) actions.add("Apply output encoding and Content Security Policy (CSP).");
        if (uniqSigs.some(s => s.startsWith("CMD:"))) actions.add("Remove direct shell execution or strictly whitelist args.");
        if (uniqSigs.some(s => s.startsWith("LFI:"))) actions.add("Normalize/deny traversal patterns; restrict file access.");
      } else if (decision === "WARN") {
        actions.add("Proceed with caution; verify source and context.");
      } else {
        actions.add("No immediate threat detected (continue monitoring).");
      }

      // Type
      let type = "Data";
      if (score >= CONFIG.thresholds.block) type = "Exploit";
      else if (isUrl) type = "URL";

      return {
        input: raw,
        decoded,
        type,
        decision,
        score,
        confidence: Math.round(confidence),
        entropy: ent,
        sigs: Array.from(sigs),
        reasons: Array.from(reasons).slice(0, 10),
        actions: Array.from(actions)
      };
    }
  }

  // -------------------- UI --------------------
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

    const verdict = $("verdict");
    if (verdict) { verdict.textContent = "---"; verdict.style.color = ""; }

    const riskVal = $("riskVal");
    const confVal = $("confVal");
    if (riskVal) riskVal.textContent = "0%";
    if (confVal) confVal.textContent = "0%";

    clearNode($("signals"));
    clearNode($("reasons"));
    clearNode($("actions"));
    clearNode($("tableBody"));
  }

  function renderTag(decision) {
    const cls = decision === "BLOCK" ? "tag-danger" : (decision === "WARN" ? "tag-warn" : "tag-safe");
    return `<span class="tag ${cls}">${decision}</span>`;
  }

  function runScan() {
    const inputEl = $("input");
    if (!inputEl) return;

    let lines = (inputEl.value || "").split("\n").map(s => s.trim()).filter(Boolean);

    clearNode($("tableBody"));
    clearNode($("signals"));
    clearNode($("reasons"));
    clearNode($("actions"));

    if (!lines.length) {
      resetUI();
      return;
    }

    if (lines.length > CONFIG.maxLines) {
      lines = lines.slice(0, CONFIG.maxLines);
      console.warn(`Validoon: truncated to first ${CONFIG.maxLines} lines for UI safety.`);
    }

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
      r.reasons.forEach(x => allReasons.add(x));
      r.actions.forEach(a => allActions.add(a));

      const tr = document.createElement("tr");

      const tdSeg = document.createElement("td");
      tdSeg.className = "mono";
      tdSeg.textContent = line.length > 220 ? (line.slice(0, 220) + "…") : line;

      const tdType = document.createElement("td");
      tdType.textContent = r.type;

      const tdDec = document.createElement("td");
      tdDec.innerHTML = renderTag(r.decision);

      const tdScore = document.createElement("td");
      tdScore.textContent = `${r.score}%`;

      const tdConf = document.createElement("td");
      tdConf.textContent = `${r.confidence}%`;

      const tdEnt = document.createElement("td");
      tdEnt.textContent = String(r.entropy);

      tr.append(tdSeg, tdType, tdDec, tdScore, tdConf, tdEnt);
      $("tableBody").appendChild(tr);
    }

    const riskVal = $("riskVal");
    const confVal = $("confVal");
    if (riskVal) riskVal.textContent = `${peakScore}%`;
    if (confVal) confVal.textContent = `${peakConf}%`;

    setVerdict(peakScore);

    // chips
    allSigs.forEach(s => {
      const ch = document.createElement("span");
      ch.className = "chip";
      ch.textContent = s;
      $("signals").appendChild(ch);
    });

    // reasons (top 6)
    Array.from(allReasons).slice(0, 6).forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      $("reasons").appendChild(li);
    });

    // actions
    if (!allActions.size) allActions.add("No immediate action required.");
    allActions.forEach(a => {
      const li = document.createElement("li");
      li.textContent = a;
      $("actions").appendChild(li);
    });
  }

  function exportJSON() {
    const inputEl = $("input");
    if (!inputEl) return;
    const lines = (inputEl.value || "").split("\n").map(s => s.trim()).filter(Boolean);
    if (!lines.length) return;

    const data = lines.slice(0, CONFIG.maxLines).map(l => ValidoonEngine.analyze(l));
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

  // -------------------- Tests --------------------
  function loadTestA() {
    const inputEl = $("input");
    if (!inputEl) return;
    inputEl.value = [
      "Normal log: user_id=42 action=view_report status=200",
      "hello",
      "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https://mail.google.com/mail/",
      "http://example.com/login?redirect=https://evil.example",
      "https://xn--pple-43d.com/login"
    ].join("\n");
    runScan();
  }

  function loadTestB() {
    const inputEl = $("input");
    if (!inputEl) return;

    // Add a mixed “deep” suite: SQLi + XSS + LFI + CMD + entropy-ish token
    const token = btoa("token_" + rngInt(100000, 999999) + "_" + rngInt(100000, 999999) + "_session");
    inputEl.value = [
      "SELECT * FROM users WHERE id='1' OR 1=1;",
      "<script>alert(1)</script>",
      "../../../etc/passwd",
      "http://host/app?file=../../../../etc/passwd",
      "id; whoami && cat /etc/passwd",
      token,
      "https://example.com/auth/login?return=https://example.com/dashboard"
    ].join("\n");
    runScan();
  }

  // -------------------- Boot --------------------
  function boot() {
    const btnRun = $("btnRun");
    const btnClear = $("btnClear");
    const btnExport = $("btnExport");
    const btnTestA = $("btnTestA");
    const btnTestB = $("btnTestB");

    // Hard guard: if missing core elements, stop silently (prevents console spam)
    if (!btnRun || !$("input") || !$("tableBody") || !$("verdict")) return;

    btnRun.addEventListener("click", runScan);
    if (btnClear) btnClear.addEventListener("click", resetUI);
    if (btnExport) btnExport.addEventListener("click", exportJSON);
    if (btnTestA) btnTestA.addEventListener("click", loadTestA);
    if (btnTestB) btnTestB.addEventListener("click", loadTestB);

    // Initial state
    resetUI();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
