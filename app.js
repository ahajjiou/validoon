/* Validoon — client-side triage engine (robust DOM-safe build)
   Works with BOTH:
   - Minimal UI: #input #scanBtn #result
   - Advanced UI: optional #modeSel/#mode, #showReasons, #clearBtn/#btnClear, #pasteBtn/#btnPaste,
     #allowCount/#warnCount/#blockCount, #statusText, #copyJsonBtn
*/

(() => {
  "use strict";

  // ---------- DOM helpers (never throw) ----------
  const $ = (id) => document.getElementById(id);
  const first = (...ids) => ids.map($).find(Boolean) || null;

  const inputEl = first("input", "inputEl", "textInput");
  const scanBtn = first("scanBtn", "executeBtn", "btnScan");
  const resultEl = first("result", "results", "resultBox");
  const clearBtn = first("clearBtn", "btnClear", "clear");
  const pasteBtn = first("pasteBtn", "btnPaste", "paste");
  const modeSel = first("modeSel", "mode", "modesEl");
  const showReasonsEl = first("showReasons", "reasons", "reasonsToggle");

  const allowCountEl = first("allowCount", "cntAllow");
  const warnCountEl  = first("warnCount", "cntWarn");
  const blockCountEl = first("blockCount", "cntBlock");
  const statusTextEl = first("statusText", "status");
  const copyJsonBtn  = first("copyJsonBtn", "btnCopyJson", "copyJson");

  // Minimal UI fallback (your earlier index.html)
  // If inputEl is missing, try to bind to a <textarea> inside the page.
  const inputFallback = inputEl || document.querySelector("textarea");

  // If still missing, show fatal message (but do not crash)
  if (!inputFallback) {
    console.error("Validoon: Missing input element.");
    return;
  }

  // If scan button missing, try any button on page (last resort)
  const scanBtnFallback = scanBtn || document.querySelector("button");

  // If result container missing, create one
  let resultBox = resultEl;
  if (!resultBox) {
    resultBox = document.createElement("div");
    resultBox.id = "result";
    resultBox.style.marginTop = "16px";
    resultBox.style.padding = "12px";
    resultBox.style.borderRadius = "8px";
    resultBox.style.background = "rgba(255,255,255,0.06)";
    resultBox.style.border = "1px solid rgba(255,255,255,0.12)";
    inputFallback.parentElement?.appendChild(resultBox);
  }

  // ---------- Core logic ----------
  const RULES = {
    // BLOCK: clear exploit / sensitive / injection patterns
    block: [
      { re: /<\s*script\b/i, reason: "Script tag detected" },
      { re: /\bjavascript\s*:/i, reason: "javascript: URL detected" },
      { re: /\bdata\s*:\s*text\/html/i, reason: "data:text/html detected" },
      { re: /\b(onerror|onload|onclick|onmouseover)\s*=/i, reason: "Inline event handler detected" },
      { re: /\b(document\.cookie|localStorage|sessionStorage)\b/i, reason: "Browser storage access pattern" },
      { re: /\b(eval|Function)\s*\(/i, reason: "Dynamic code execution pattern" },
      { re: /\b(select|union\s+select|drop\s+table|or\s+1\s*=\s*1)\b/i, reason: "SQLi-like pattern" },
      { re: /\bBearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/i, reason: "JWT-like token detected" },
      { re: /\bAKIA[0-9A-Z]{16}\b/i, reason: "AWS Access Key pattern" },
      { re: /\b(ssh-rsa|BEGIN\s+PRIVATE\s+KEY|BEGIN\s+RSA\s+PRIVATE\s+KEY)\b/i, reason: "Private key material" },
    ],
    // WARN: suspicious but not guaranteed malicious
    warn: [
      { re: /\bhttps?:\/\/\S+/i, reason: "URL detected (review before opening)" },
      { re: /\bpassword\s*[:=]/i, reason: "Password-like field detected" },
      { re: /\b(token|apikey|api_key|secret)\b/i, reason: "Credential keyword detected" },
      { re: /\b(base64,|atob\(|btoa\()\b/i, reason: "Encoding/obfuscation hint" },
      { re: /\bcmd\.exe|powershell|bash\s+-c\b/i, reason: "Command execution hint" },
      { re: /\b(ftp:\/\/|file:\/\/)\b/i, reason: "Risky scheme detected" },
    ],
  };

  const normalize = (s) => (s || "").trim();
  const isEmpty = (s) => !normalize(s);

  function decide(line, mode) {
    const text = normalize(line);
    const reasons = [];

    // STRICT mode: treat warnings more aggressively
    const strict = (mode || "normal").toLowerCase() === "strict";

    for (const r of RULES.block) {
      if (r.re.test(text)) reasons.push({ level: "BLOCK", reason: r.reason });
    }
    if (reasons.length) return { decision: "BLOCK", reasons };

    const warnReasons = [];
    for (const r of RULES.warn) {
      if (r.re.test(text)) warnReasons.push({ level: "WARN", reason: r.reason });
    }
    if (warnReasons.length) {
      // In STRICT, multiple warns => BLOCK
      if (strict && warnReasons.length >= 2) {
        return { decision: "BLOCK", reasons: warnReasons.map(x => ({...x, level:"BLOCK"})) };
      }
      return { decision: "WARN", reasons: warnReasons };
    }

    return { decision: "ALLOW", reasons: [{ level: "ALLOW", reason: "No obvious risk detected" }] };
  }

  function parseLines(raw) {
    return String(raw || "")
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter((x) => x.length > 0);
  }

  function setStatus(text) {
    if (statusTextEl) statusTextEl.textContent = text;
  }

  function setCounts(a, w, b) {
    if (allowCountEl) allowCountEl.textContent = String(a);
    if (warnCountEl) warnCountEl.textContent = String(w);
    if (blockCountEl) blockCountEl.textContent = String(b);
  }

  function renderMinimal(summary) {
    // Minimal UI: dump results as HTML
    const { items, counts } = summary;
    const showReasons = showReasonsEl ? !!showReasonsEl.checked : true;

    const lines = [];
    lines.push(`<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;">`);
    lines.push(`<span>ALLOW: <b>${counts.ALLOW}</b></span>`);
    lines.push(`<span>WARN: <b>${counts.WARN}</b></span>`);
    lines.push(`<span>BLOCK: <b>${counts.BLOCK}</b></span>`);
    lines.push(`</div>`);

    for (const it of items) {
      const color =
        it.decision === "ALLOW" ? "#1ec98b" :
        it.decision === "WARN"  ? "#f6c344" : "#ff5c7a";

      lines.push(`
        <div style="margin:10px 0;padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,.12);border-left:6px solid ${color};">
          <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
            <div style="font-weight:700;">${it.decision}</div>
            <div style="opacity:.8;font-size:12px;">Line ${it.index}</div>
          </div>
          <div style="margin-top:8px;white-space:pre-wrap;word-break:break-word;opacity:.95;">${escapeHtml(it.line)}</div>
          ${
            showReasons
              ? `<ul style="margin:10px 0 0 18px;opacity:.9;">
                   ${it.reasons.map(r => `<li>${escapeHtml(r.reason)}</li>`).join("")}
                 </ul>`
              : ``
          }
        </div>
      `);
    }

    resultBox.innerHTML = lines.join("");
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function scan() {
    const raw = inputFallback.value || "";
    const lines = parseLines(raw);

    const mode = modeSel ? (modeSel.value || "normal") : "normal";
    const items = [];
    const counts = { ALLOW: 0, WARN: 0, BLOCK: 0 };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (isEmpty(line)) continue;

      const out = decide(line, mode);
      counts[out.decision]++;

      items.push({
        index: i + 1,
        line,
        decision: out.decision,
        reasons: out.reasons || [],
      });
    }

    setCounts(counts.ALLOW, counts.WARN, counts.BLOCK);
    setStatus(lines.length ? "Done." : "Idle.");

    // Always render at least minimal
    renderMinimal({ items, counts });

    // Store last JSON for copy
    window.__VALIDOON_LAST__ = { mode, counts, items, ts: new Date().toISOString() };
  }

  function clearAll() {
    inputFallback.value = "";
    setCounts(0, 0, 0);
    setStatus("Idle.");
    resultBox.innerHTML = "";
    window.__VALIDOON_LAST__ = null;
  }

  async function pasteFromClipboard() {
    try {
      const txt = await navigator.clipboard.readText();
      if (txt) inputFallback.value = txt;
    } catch (e) {
      console.warn("Clipboard read failed:", e);
    }
  }

  async function copyJson() {
    try {
      const payload = window.__VALIDOON_LAST__ || { note: "No scan results yet." };
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      setStatus("JSON copied.");
      setTimeout(() => setStatus("Idle."), 1000);
    } catch (e) {
      console.warn("Copy failed:", e);
    }
  }

  // ---------- Wire events ----------
  if (scanBtnFallback) scanBtnFallback.addEventListener("click", scan);
  if (clearBtn) clearBtn.addEventListener("click", clearAll);
  if (pasteBtn) pasteBtn.addEventListener("click", pasteFromClipboard);
  if (copyJsonBtn) copyJsonBtn.addEventListener("click", copyJson);

  // Keyboard shortcut: Ctrl+Enter to scan
  inputFallback.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") scan();
  });

  // Initial state
  setCounts(0, 0, 0);
  setStatus("Idle.");
})();
