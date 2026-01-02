(() => {
  "use strict";

  // ---------- Safe DOM helper ----------
  const $ = (id) => document.getElementById(id);

  function showResult(html, extraClass = "") {
    const box = $("result");
    box.className = "result" + (extraClass ? ` ${extraClass}` : "");
    box.innerHTML = html;
    box.classList.remove("hidden");
  }

  function hideResult() {
    const box = $("result");
    box.classList.add("hidden");
    box.innerHTML = "";
    box.className = "result";
  }

  function setMeta(lines, peak, conf) {
    $("metaLines").textContent = `Lines: ${lines}`;
    $("metaPeak").textContent = `Peak: ${peak}%`;
    $("metaConf").textContent = `Confidence: ${conf}%`;
  }

  // ---------- Core analysis (defensive triage only) ----------
  const RX = {
    url: /^https?:\/\/\S+$/i,
    b64ish: /^[A-Za-z0-9+/]+={0,2}$/,
    ipv4: /^(?:\d{1,3}\.){3}\d{1,3}$/,
    nonAscii: /[^\u0000-\u007F]/,
    // "Indicators" only (not instructions)
    sqli: /\b(union\s+select|union\s+all\s+select|or\s+1\s*=\s*1|drop\s+table|delete\s+from|truncate\s+table|information_schema|pg_catalog|xp_cmdshell)\b/i,
    xss: /<script\b|javascript:|on(?:error|load|click|mouseover|focus)\s*=|\beval\s*\(|document\.cookie|innerHTML\s*=/i,
    traversal: /(\.\.\/|\.\.%2f|%2e%2e%2f|\/etc\/passwd\b|c:\\\\windows\\\\system32)/i,
    cmd: /(?:;|\|\||&&)\s*(?:cat|ls|whoami|id|wget|curl|bash|sh|powershell|cmd)\b/i,
  };

  function entropy(str) {
    const s = String(str || "");
    if (!s.length) return 0;
    const freq = Object.create(null);
    for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
    let H = 0;
    for (const k in freq) {
      const p = freq[k] / s.length;
      H -= p * Math.log2(p);
    }
    return Number(H.toFixed(2));
  }

  function safeDecode(line) {
    let cur = String(line || "").trim();
    const layers = [];
    if (!cur) return { decoded: "", layers };

    // NFKC
    try {
      const n0 = cur.normalize("NFKC");
      if (n0 !== cur) {
        cur = n0;
        layers.push("UNICODE_NFKC");
      }
    } catch {}

    // URL decode
    try {
      if (/%[0-9a-f]{2}/i.test(cur)) {
        const u = decodeURIComponent(cur);
        if (u && u !== cur) {
          cur = u;
          layers.push("URL_DECODE");
        }
      }
    } catch {}

    // Base64 safe-ish decode
    try {
      const looksB64 = RX.b64ish.test(cur) && cur.length >= 24 && cur.length % 4 === 0;
      if (looksB64) {
        const decoded = atob(cur);
        const printable = decoded.replace(/[^\x20-\x7E]/g, "").length;
        if (decoded.length && printable / decoded.length >= 0.7) {
          cur = decoded;
          layers.push("BASE64_DECODE");
        }
      }
    } catch {}

    // NFKC again
    try {
      const n1 = cur.normalize("NFKC");
      if (n1 !== cur) {
        cur = n1;
        layers.push("UNICODE_NFKC_POST");
      }
    } catch {}

    return { decoded: cur, layers };
  }

  function urlIntel(decoded, sigs, reasons, scoreRef) {
    try {
      const u = new URL(decoded);
      const host = u.hostname || "";
      const path = (u.pathname || "").toLowerCase();

      if (u.protocol !== "https:") {
        scoreRef.value += 18;
        sigs.add("INSECURE_HTTP");
        reasons.add("URL uses HTTP (unencrypted).");
      }

      if (RX.nonAscii.test(host) || /xn--/i.test(host)) {
        scoreRef.value += 35;
        sigs.add("HOMOGRAPH_PUNYCODE");
        reasons.add("Host contains non-ASCII or punycode (possible look-alike domain).");
      }

      if (RX.ipv4.test(host)) {
        scoreRef.value += 18;
        sigs.add("IP_HOST");
        reasons.add("URL host is an IP address (higher phishing risk).");
      }

      const redirectKeys = new Set([
        "redirect","redirect_uri","redirecturl","return","returnto",
        "continue","next","url","dest","destination","target"
      ]);
      const keys = Array.from(u.searchParams.keys()).map(k => k.toLowerCase());
      if (keys.some(k => redirectKeys.has(k))) {
        scoreRef.value += 12;
        sigs.add("REDIRECT_PARAM");
        reasons.add("Redirect-like query parameter detected (possible open-redirect pattern).");
      }

      if (/(^|\/)(login|signin|auth|oauth|sso)(\/|$)/i.test(path)) {
        scoreRef.value += 10;
        sigs.add("AUTH_ENDPOINT");
        reasons.add("Authentication-related path detected (phishing-sensitive).");
      }
    } catch {
      // It's URL-ish but malformed
      scoreRef.value = Math.max(scoreRef.value, 20);
      sigs.add("MALFORMED_URL");
      reasons.add("Malformed URL-like input detected.");
    }
  }

  function analyzeLine(line) {
    const raw = String(line || "").trim();
    const { decoded, layers } = safeDecode(raw);

    const sigs = new Set(layers);
    const reasons = new Set();
    const actions = new Set();
    const scoreRef = { value: 0 };

    // Indicators
    if (RX.sqli.test(decoded)) {
      scoreRef.value = Math.max(scoreRef.value, 88);
      sigs.add("SQLI_INDICATOR");
      reasons.add("SQL injection indicator detected.");
    }
    if (RX.xss.test(decoded)) {
      scoreRef.value = Math.max(scoreRef.value, 90);
      sigs.add("XSS_INDICATOR");
      reasons.add("XSS indicator detected.");
    }
    if (RX.traversal.test(decoded)) {
      scoreRef.value = Math.max(scoreRef.value, 86);
      sigs.add("PATH_TRAVERSAL_INDICATOR");
      reasons.add("Path traversal / LFI indicator detected.");
    }
    if (RX.cmd.test(decoded)) {
      scoreRef.value = Math.max(scoreRef.value, 86);
      sigs.add("CMD_INJECTION_INDICATOR");
      reasons.add("Command injection indicator detected.");
    }

    // URL intel
    if (RX.url.test(decoded)) {
      sigs.add("URL");
      urlIntel(decoded, sigs, reasons, scoreRef);
    }

    // Entropy / token-ish
    const ent = entropy(decoded);
    if (decoded.length >= 24 && ent >= 4.6) {
      scoreRef.value = Math.max(scoreRef.value, 35);
      sigs.add("HIGH_ENTROPY");
      reasons.add("High entropy content (token/obfuscation signal).");
    }

    const score = Math.min(scoreRef.value, 100);
    const decision = score >= 70 ? "BLOCK" : (score >= 40 ? "WARN" : "ALLOW");

    const conf = Math.min(
      55 + (score * 0.35) + (sigs.size * 3.0),
      98
    );

    // Actions (defensive)
    if (decision === "BLOCK") {
      actions.add("Block or quarantine this input.");
      actions.add("Inspect related logs/context for correlated activity.");
      actions.add("Enforce strict server-side validation/sanitization.");
    } else if (decision === "WARN") {
      actions.add("Proceed with caution; verify source/context.");
      actions.add("Prefer opening links in isolated environment.");
    } else {
      actions.add("No immediate risk detected; keep monitoring.");
    }

    return {
      raw,
      decoded,
      decision,
      score,
      confidence: Math.round(conf),
      entropy: ent,
      signals: Array.from(sigs),
      reasons: Array.from(reasons),
      actions: Array.from(actions),
      type: sigs.has("URL") ? "URL" : (score >= 70 ? "Exploit" : "Data")
    };
  }

  // ---------- UI render ----------
  function tagHTML(decision) {
    if (decision === "BLOCK") return `<span class="tag t-bad">BLOCK</span>`;
    if (decision === "WARN") return `<span class="tag t-warn">WARN</span>`;
    return `<span class="tag t-ok">ALLOW</span>`;
  }

  function verdictHTML(peak) {
    if (peak >= 70) return `<div class="verdict v-bad">DANGER</div>`;
    if (peak >= 40) return `<div class="verdict v-warn">SUSPICIOUS</div>`;
    return `<div class="verdict v-ok">SECURE</div>`;
  }

  function runScan() {
    const input = $("input").value || "";
    const lines = input.split("\n").map(s => s.trim()).filter(Boolean);

    if (!lines.length) {
      hideResult();
      setMeta(0, 0, 0);
      return;
    }

    const results = lines.map(analyzeLine);

    let peak = 0;
    let peakConf = 0;
    const topSignals = new Set();
    const topReasons = new Set();
    const topActions = new Set();

    for (const r of results) {
      peak = Math.max(peak, r.score);
      peakConf = Math.max(peakConf, r.confidence);
      r.signals.forEach(s => topSignals.add(s));
      r.reasons.forEach(x => topReasons.add(x));
      r.actions.forEach(x => topActions.add(x));
    }

    setMeta(results.length, peak, peakConf);

    const reasonsList = Array.from(topReasons).slice(0, 6).map(x => `<li>${escapeHTML(x)}</li>`).join("");
    const actionsList = Array.from(topActions).slice(0, 6).map(x => `<li>${escapeHTML(x)}</li>`).join("");

    const rows = results.map(r => `
      <tr>
        <td><div class="tiny">${escapeHTML(r.type)}</div>${escapeHTML(r.raw).slice(0, 160)}</td>
        <td>${tagHTML(r.decision)}</td>
        <td>${r.score}%</td>
        <td>${r.confidence}%</td>
        <td>${r.entropy}</td>
      </tr>
    `).join("");

    const html = `
      ${verdictHTML(peak)}
      <div class="tiny">Signals: ${escapeHTML(Array.from(topSignals).slice(0, 10).join(", "))}${topSignals.size > 10 ? " …" : ""}</div>

      <div style="margin-top:10px; display:grid; gap:10px; grid-template-columns:1fr 1fr;">
        <div class="card" style="padding:12px; box-shadow:none;">
          <div class="tiny" style="font-weight:900; margin-bottom:6px;">Primary reasons</div>
          <ul style="margin:0; padding-left:18px;">${reasonsList || "<li>—</li>"}</ul>
        </div>
        <div class="card" style="padding:12px; box-shadow:none;">
          <div class="tiny" style="font-weight:900; margin-bottom:6px;">Recommended actions</div>
          <ul style="margin:0; padding-left:18px;">${actionsList || "<li>—</li>"}</ul>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th style="width:55%;">Segment</th>
            <th>Decision</th>
            <th>Score</th>
            <th>Conf</th>
            <th>Entropy</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    `;

    showResult(html);
  }

  function clearAll() {
    $("input").value = "";
    hideResult();
    setMeta(0, 0, 0);
  }

  function exportJSON() {
    const input = $("input").value || "";
    const lines = input.split("\n").map(s => s.trim()).filter(Boolean);
    if (!lines.length) {
      showResult(`<div class="verdict v-warn">NO DATA</div><div class="tiny">Paste at least one line before export.</div>`, "err");
      return;
    }

    const data = lines.map(analyzeLine);
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

  // ---------- Tests ----------
  function loadTestA() {
    $("input").value = [
      "Normal log: user_id=42 action=view_report status=200",
      "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https://mail.google.com/mail/",
      "http://example.com/login?redirect=https://evil.example",
      "Ym9sdC5uZXQvc2VjdXJpdHk=",
      "hello world"
    ].join("\n");
    runScan();
  }

  function loadTestB() {
    $("input").value = [
      "SELECT * FROM users WHERE id='1' OR 1=1;",
      "<script>alert(1)</script>",
      "../../../etc/passwd",
      "id; whoami && cat /etc/passwd",
      "https://xn--pple-43d.com/login",
      "http://192.168.0.10/login?redirect=https://evil.example",
      "aHR0cDovL2V4YW1wbGUuY29tL2xvZ2luP3JlZGlyZWN0PWh0dHBzOi8vZXZpbC5leGFtcGxl" // base64-ish
    ].join("\n");
    runScan();
  }

  // ---------- Escaping ----------
  function escapeHTML(str) {
    return String(str)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  // ---------- Boot (guaranteed wiring) ----------
  function boot() {
    const required = ["input","btnScan","btnTestA","btnTestB","btnExport","btnClear","metaLines","metaPeak","metaConf","result"];
    const missing = required.filter(id => !$(id));
    if (missing.length) {
      // Show error in body itself (no console dependency)
      const msg = `
        <div style="max-width:980px;margin:18px auto;padding:16px;border:1px solid rgba(255,92,122,.35);background:rgba(255,92,122,.08);border-radius:12px;color:#fff;">
          <div style="font-weight:1000;font-size:18px;">Validoon wiring error</div>
          <div style="opacity:.9;margin-top:6px;">Missing element IDs: <b>${missing.join(", ")}</b></div>
          <div style="opacity:.85;margin-top:6px;">Fix: replace both index.html and app.js exactly as provided.</div>
        </div>`;
      document.body.innerHTML = msg;
      return;
    }

    $("btnScan").addEventListener("click", runScan);
    $("btnClear").addEventListener("click", clearAll);
    $("btnExport").addEventListener("click", exportJSON);
    $("btnTestA").addEventListener("click", loadTestA);
    $("btnTestB").addEventListener("click", loadTestB);

    // Initial meta
    setMeta(0, 0, 0);
  }

  // Ensure DOM is ready even if defer misbehaves
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
