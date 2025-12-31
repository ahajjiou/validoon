(() => {
  "use strict";

  // ---------- Helpers ----------
  const $ = (sel) => document.querySelector(sel);
  const byId = (id) => document.getElementById(id);

  function must(el, name) {
    if (!el) throw new Error(`Missing DOM element: ${name}`);
    return el;
  }

  function safeText(s) {
    return String(s ?? "").replace(/\u0000/g, "");
  }

  function nowISO() {
    const d = new Date();
    return d.toISOString();
  }

  // ---------- DOM ----------
  const inputEl     = must(byId("input"), "input");
  const pasteBtn    = must(byId("pasteBtn"), "pasteBtn");
  const clearBtn    = must(byId("clearBtn"), "clearBtn");
  const scanBtn     = must(byId("scanBtn"), "scanBtn");
  const modeSel     = must(byId("modeSel"), "modeSel");
  const reasonsChk  = must(byId("reasonsChk"), "reasonsChk");

  const allowCountEl = must(byId("allowCount"), "allowCount");
  const warnCountEl  = must(byId("warnCount"), "warnCount");
  const blockCountEl = must(byId("blockCount"), "blockCount");

  const copyJsonBtn = must(byId("copyJsonBtn"), "copyJsonBtn");
  const selfTestBtn = must(byId("selfTestBtn"), "selfTestBtn");

  // Optional containers (if you have them)
  const perLineBox = byId("perLineBox");      // container for per-line results
  const statusEl   = byId("statusText");      // small status label

  // ---------- Engine ----------
  const PATTERNS = {
    block: [
      { re: /<\s*script\b/i, reason: "Contains <script> tag" },
      { re: /\bjavascript:\s*/i, reason: "javascript: URL scheme" },
      { re: /\b(onerror|onload|onclick|onmouseover)\s*=/i, reason: "Inline event handler" },
      { re: /\b(eval|Function)\s*\(/i, reason: "Dynamic code execution" },
      { re: /\b(document\.cookie|localStorage|sessionStorage)\b/i, reason: "Sensitive browser storage access" },
      { re: /\b(union\s+select|sleep\(|benchmark\(|or\s+1=1)\b/i, reason: "SQLi-like pattern" },
      { re: /\b(cat\s+\/etc\/passwd|\/etc\/passwd)\b/i, reason: "Obvious sensitive file reference" }
    ],
    warn: [
      { re: /\b(token|apikey|api_key|secret|bearer)\b/i, reason: "Looks like a credential keyword" },
      { re: /\bhttps?:\/\/\S+/i, reason: "Contains URL" },
      { re: /\b(base64|jwt)\b/i, reason: "Encoded/structured token indicator" },
      { re: /\b(select|insert|update|delete)\b/i, reason: "DB keyword (context dependent)" },
      { re: /[A-Za-z0-9+\/]{40,}={0,2}/, reason: "Long base64-ish string" }
    ]
  };

  function triageLine(line, mode) {
    const txt = safeText(line).trim();
    if (!txt) return { decision: "ALLOW", reasons: ["Empty line"] };

    const reasons = [];

    // BLOCK checks
    for (const p of PATTERNS.block) {
      if (p.re.test(txt)) reasons.push(p.reason);
    }
    if (reasons.length) return { decision: "BLOCK", reasons };

    // WARN checks
    for (const p of PATTERNS.warn) {
      if (p.re.test(txt)) reasons.push(p.reason);
    }

    // Strict mode escalates some WARNs to BLOCK if multiple reasons
    if (mode === "strict" && reasons.length >= 2) {
      return { decision: "BLOCK", reasons: [...reasons, "Strict mode: multiple warnings escalated"] };
    }

    if (reasons.length) return { decision: "WARN", reasons };

    return { decision: "ALLOW", reasons: ["No obvious risk signals"] };
  }

  function parseLines(raw) {
    return safeText(raw)
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  function setStatus(msg) {
    if (statusEl) statusEl.textContent = msg;
  }

  function renderSummary(summary) {
    allowCountEl.textContent = String(summary.counts.ALLOW);
    warnCountEl.textContent  = String(summary.counts.WARN);
    blockCountEl.textContent = String(summary.counts.BLOCK);

    if (perLineBox) {
      perLineBox.innerHTML = "";
      for (const row of summary.items) {
        const div = document.createElement("div");
        div.className = "lineRow";
        const left = document.createElement("div");
        left.className = "lineText";
        left.textContent = row.text;

        const right = document.createElement("div");
        right.className = `badge badge-${row.decision.toLowerCase()}`;
        right.textContent = row.decision;

        div.appendChild(left);
        div.appendChild(right);

        if (reasonsChk.checked) {
          const ul = document.createElement("ul");
          ul.className = "reasons";
          for (const r of row.reasons) {
            const li = document.createElement("li");
            li.textContent = r;
            ul.appendChild(li);
          }
          div.appendChild(ul);
        }

        perLineBox.appendChild(div);
      }
    }
  }

  function runScan(customInput) {
    const mode = String(modeSel.value || "normal").toLowerCase();
    const raw = customInput ?? inputEl.value;
    const lines = parseLines(raw);

    const counts = { ALLOW: 0, WARN: 0, BLOCK: 0 };
    const items = [];

    for (const line of lines) {
      const out = triageLine(line, mode);
      counts[out.decision]++;
      items.push({ text: line, decision: out.decision, reasons: out.reasons });
    }

    const summary = {
      meta: { generatedAt: nowISO(), mode, lines: lines.length },
      counts,
      items
    };

    window.__VALIDOON_LAST_JSON__ = summary; // for Copy JSON
    renderSummary(summary);
    setStatus(lines.length ? `Scanned ${lines.length} line(s).` : "No input.");
  }

  // ---------- Actions ----------
  async function doPaste() {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        inputEl.value = text;
        setStatus("Pasted from clipboard.");
      } else {
        setStatus("Clipboard is empty.");
      }
    } catch {
      setStatus("Clipboard paste blocked by browser. Use Ctrl+V inside the box.");
    }
  }

  function doClear() {
    inputEl.value = "";
    allowCountEl.textContent = "0";
    warnCountEl.textContent = "0";
    blockCountEl.textContent = "0";
    if (perLineBox) perLineBox.innerHTML = "";
    window.__VALIDOON_LAST_JSON__ = null;
    setStatus("Cleared.");
    inputEl.focus();
  }

  async function doCopyJSON() {
    const data = window.__VALIDOON_LAST_JSON__;
    if (!data) return setStatus("Nothing to copy yet. Run a scan first.");
    const txt = JSON.stringify(data, null, 2);
    try {
      await navigator.clipboard.writeText(txt);
      setStatus("JSON copied.");
    } catch {
      setStatus("Copy blocked by browser.");
    }
  }

  function doSelfTest() {
    const test = [
      "hello",
      "https://example.com/path?q=1",
      "<script>alert(1)</script>",
      "Bearer sk_test_1234567890abcdef",
      "SELECT * FROM users WHERE id=1 OR 1=1"
    ].join("\n");

    inputEl.value = test;
    runScan(test);
  }

  // ---------- Wire events ----------
  pasteBtn.addEventListener("click", (e) => { e.preventDefault(); doPaste(); });
  clearBtn.addEventListener("click", (e) => { e.preventDefault(); doClear(); });
  scanBtn.addEventListener("click", (e) => { e.preventDefault(); runScan(); });
  copyJsonBtn.addEventListener("click", (e) => { e.preventDefault(); doCopyJSON(); });
  selfTestBtn.addEventListener("click", (e) => { e.preventDefault(); doSelfTest(); });

  // Ctrl+Enter triggers scan
  inputEl.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      runScan();
    }
  });

  // Boot mark
  window.__VALIDOON_APP_OK__ = true;
  setStatus("Ready.");
})();
