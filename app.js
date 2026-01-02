(() => {
  "use strict";

  const byId = (id) => document.getElementById(id);

  function esc(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

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

  const RX = {
    url: /^https?:\/\/\S+$/i,
    ipv4: /^(?:\d{1,3}\.){3}\d{1,3}$/,
    b64ish: /^[A-Za-z0-9+/]+={0,2}$/,
    nonAscii: /[^\u0000-\u007F]/,

    sqli: /\b(union\s+(all\s+)?select|or\s+1\s*=\s*1|drop\s+table|delete\s+from|truncate\s+table|information_schema|pg_catalog|xp_cmdshell)\b/i,
    xss: /<script\b|javascript:|on(?:error|load|click|mouseover|focus)\s*=|\beval\s*\(|document\.cookie|innerHTML\s*=/i,
    traversal: /(\.\.\/|\.\.%2f|%2e%2e%2f|\/etc\/passwd\b|c:\\\\windows\\\\system32)/i,
    cmd: /(?:;|\|\||&&)\s*(?:cat|ls|whoami|id|wget|curl|bash|sh|powershell|cmd)\b/i
  };

  function safeDecode(line) {
    let cur = String(line || "").trim();
    const layers = [];
    if (!cur) return { decoded: "", layers };

    try {
      const n0 = cur.normalize("NFKC");
      if (n0 !== cur) {
        cur = n0;
        layers.push("UNICODE_NFKC");
      }
    } catch {}

    try {
      if (/%[0-9a-f]{2}/i.test(cur)) {
        const u = decodeURIComponent(cur);
        if (u && u !== cur) {
          cur = u;
          layers.push("URL_DECODE");
        }
      }
    } catch {}

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
        reasons.add("Host contains non-ASCII or punycode (look-alike domain risk).");
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
        reasons.add("Redirect-like query parameter detected (open-redirect pattern).");
      }

      if (/(^|\/)(login|signin|auth|oauth|sso)(\/|$)/i.test(path)) {
        scoreRef.value += 10;
        sigs.add("AUTH_ENDPOINT");
        reasons.add("Authentication-related path detected (phishing-sensitive).");
      }
    } catch {
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

    if (RX.url.test(decoded)) {
      sigs.add("URL");
      urlIntel(decoded, sigs, reasons, scoreRef);
    }

    const ent = entropy(decoded);
    if (decoded.length >= 24 && ent >= 4.6) {
      scoreRef.value = Math.max(scoreRef.value, 35);
      sigs.add("HIGH_ENTROPY");
      reasons.add("High entropy content (token/obfuscation signal).");
    }

    const score = Math.min(scoreRef.value, 100);
    const decision = score >= 70 ? "BLOCK" : (score >= 40 ? "WARN" : "ALLOW");
    const conf = Math.min(55 + (score * 0.35) + (sigs.size * 3.0), 98);

    if (decision === "BLOCK") {
      actions.add("Block or quarantine this input.");
      actions.add("Inspect related context/logs.");
      actions.add("Enforce strict server-side validation.");
    } else if (decision === "WARN") {
      actions.add("Proceed with caution; verify source/context.");
    } else {
      actions.add("No immediate risk detected.");
    }

    return {
      raw,
      decision,
      score,
      confidence: Math.round(conf),
      entropy: ent,
      signals: Array.from(sigs),
      reasons: Array.from(reasons),
      actions: Array.from(actions)
    };
  }

  function tag(decision) {
    if (decision === "BLOCK") return `<b style="color:#ff5c7a">BLOCK</b>`;
    if (decision === "WARN") return `<b style="color:#fbbf24">WARN</b>`;
    return `<b style="color:#1ec98b">ALLOW</b>`;
  }

  function render(results) {
    let peak = 0;
    for (const r of results) peak = Math.max(peak, r.score);

    const verdict =
      peak >= 70 ? `<div style="font-size:22px;font-weight:900;color:#ff5c7a">DANGER</div>` :
      peak >= 40 ? `<div style="font-size:22px;font-weight:900;color:#fbbf24">SUSPICIOUS</div>` :
                  `<div style="font-size:22px;font-weight:900;color:#1ec98b">SECURE</div>`;

    const rows = results.map(r => `
      <div style="padding:10px 0;border-top:1px solid rgba(42,51,112,.6)">
        <div style="opacity:.9">${tag(r.decision)} — ${r.score}% (conf ${r.confidence}%, ent ${r.entropy})</div>
        <div style="font-family:ui-monospace,Consolas,monospace;opacity:.95;word-break:break-all;margin-top:6px">${esc(r.raw)}</div>
        ${r.reasons.length ? `<div style="margin-top:6px;opacity:.85">• ${esc(r.reasons[0])}</div>` : ``}
      </div>
    `).join("");

    return `${verdict}<div style="opacity:.85;margin-top:6px">Peak severity: <b>${peak}%</b></div>${rows}`;
  }

  function runScan() {
    const input = byId("input");
    const out = byId("result");
    if (!input || !out) return;

    const lines = (input.value || "").split("\n").map(s => s.trim()).filter(Boolean);
    if (!lines.length) {
      out.classList.add("hidden");
      out.innerHTML = "";
      return;
    }

    const results = lines.map(analyzeLine);
    out.innerHTML = render(results);
    out.classList.remove("hidden");

    // Visual class toggle if your CSS supports .block
    const peak = results.reduce((m, r) => Math.max(m, r.score), 0);
    out.classList.toggle("block", peak >= 70);
  }

  function clearAll() {
    const input = byId("input");
    const out = byId("result");
    if (input) input.value = "";
    if (out) {
      out.innerHTML = "";
      out.classList.add("hidden");
      out.classList.remove("block");
    }
  }

  function boot() {
    const scanBtn = byId("scanBtn");     // your current button id
    const clearBtn = byId("btnClear");   // optional if exists
    const testBtn = byId("btnTest");     // optional if exists
    const exportBtn = byId("btnExport"); // optional if exists

    if (!scanBtn || !byId("input") || !byId("result")) return;

    scanBtn.addEventListener("click", runScan);

    if (clearBtn) clearBtn.addEventListener("click", clearAll);

    if (testBtn) {
      testBtn.addEventListener("click", () => {
        byId("input").value = [
          "Normal log: user_id=42 action=view_report status=200",
          "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https://mail.google.com/mail/",
          "http://example.com/login?redirect=https://evil.example",
          "SELECT * FROM users WHERE id='1' OR 1=1;",
          "<script>alert(1)</script>"
        ].join("\n");
        runScan();
      });
    }

    if (exportBtn) {
      exportBtn.addEventListener("click", () => {
        const input = byId("input");
        const lines = (input.value || "").split("\n").map(s => s.trim()).filter(Boolean);
        if (!lines.length) return;
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
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
