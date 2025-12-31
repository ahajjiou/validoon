/* Validoon — client-side triage (ALLOW / WARN / BLOCK)
   No network calls. No storage. No dependencies.
*/

(function () {
  const $ = (id) => document.getElementById(id);

  const inputEl = $("input");
  const scanBtn = $("scanBtn");
  const clearBtn = $("clearBtn");
  const pasteBtn = $("pasteBtn");
  const modeEl = $("mode");
  const showWhyEl = $("showWhy");

  const linesCountEl = $("linesCount");
  const charsCountEl = $("charsCount");

  const allowCountEl = $("allowCount");
  const warnCountEl = $("warnCount");
  const blockCountEl = $("blockCount");

  const resultsEl = $("results");
  const statusEl = $("status");

  const copyJsonBtn = $("copyJsonBtn");
  const selfTestLink = $("selfTestLink");

  // ------- Core rules (simple, explainable, extensible) -------
  function evaluateLine(raw, mode) {
    const s = (raw || "").trim();
    if (!s) return null;

    const reasons = [];
    const lower = s.toLowerCase();
    const strict = mode === "strict";

    // Light heuristics (triage, not a full scanner)
    const hasUrl = /https?:\/\/|www\./i.test(s);
    const hasEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
    const hasLong = s.length >= (strict ? 80 : 120);
    const hasWeird = /[\u0000-\u001f<>]/.test(s); // control chars or angle brackets
    const symbolCount = (s.match(/[^a-z0-9\s]/gi) || []).length;
    const hasManySymbols = symbolCount > (strict ? 18 : 28);

    if (hasWeird) reasons.push("Contains control characters or unsafe symbols.");
    if (hasManySymbols) reasons.push("Unusually high symbol density.");
    if (hasLong) reasons.push("Unusually long input.");

    // Clear red flags (generic patterns)
    const looksLikeScript = /<script\b|javascript:|onerror\s*=|onload\s*=/i.test(s);
    const looksLikeSql =
      /\b(select|union|insert|drop|update|delete)\b/i.test(lower) &&
      /\b(from|into|where|values|set)\b/i.test(lower);
    const looksLikePathTrav = /\.\.\/|\\\.\.\\/.test(s);

    if (looksLikeScript) reasons.push("Looks like script injection.");
    if (looksLikeSql) reasons.push("Looks like SQL-style injection pattern.");
    if (looksLikePathTrav) reasons.push("Looks like path traversal pattern.");

    let decision = "ALLOW";
    if (looksLikeScript || looksLikeSql || looksLikePathTrav) decision = "BLOCK";
    else if (reasons.length) decision = "WARN";

    // Positive reasons for ALLOW (to avoid empty explanation)
    if (decision === "ALLOW") {
      if (hasUrl) reasons.push("Recognized URL-like input.");
      else if (hasEmail) reasons.push("Recognized email-like input.");
      else reasons.push("No risk signals detected.");
    }

    return { input: s, decision, reasons };
  }

  function parseLines(text) {
    return (text || "")
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter(Boolean);
  }

  function setCounts(lines) {
    linesCountEl.textContent = String(lines.length);
    charsCountEl.textContent = String((inputEl.value || "").length);
  }

  function setSummary(items) {
    const allow = items.filter((x) => x.decision === "ALLOW").length;
    const warn = items.filter((x) => x.decision === "WARN").length;
    const block = items.filter((x) => x.decision === "BLOCK").length;

    allowCountEl.textContent = String(allow);
    warnCountEl.textContent = String(warn);
    blockCountEl.textContent = String(block);
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function render(items) {
    resultsEl.innerHTML = "";
    const showWhy = !!showWhyEl.checked;

    if (!items.length) {
      resultsEl.innerHTML =
        `<div style="color:#a8b0ff;font-size:13px;padding:10px 2px">No results. Paste at least one line.</div>`;
      return;
    }

    for (const it of items) {
      const badgeClass = it.decision.toLowerCase();
      const card = document.createElement("div");
      card.className = "card" + (showWhy ? " show-why" : "");

      const left = document.createElement("div");
      left.className = "txt";

      const line = document.createElement("div");
      line.className = "line";
      line.innerHTML = escapeHtml(it.input);

      const why = document.createElement("div");
      why.className = "why";
      why.innerHTML = escapeHtml(it.reasons.join(" "));

      left.appendChild(line);
      left.appendChild(why);

      const badge = document.createElement("div");
      badge.className = `badge ${badgeClass}`;
      badge.textContent = it.decision;

      card.appendChild(left);
      card.appendChild(badge);
      resultsEl.appendChild(card);
    }
  }

  function scan() {
    const mode = modeEl.value;
    const lines = parseLines(inputEl.value);
    setCounts(lines);

    const items = [];
    for (const line of lines) {
      const r = evaluateLine(line, mode);
      if (r) items.push(r);
    }

    setSummary(items);
    render(items);

    statusEl.textContent = items.length
      ? `Scanned ${items.length} line(s) in ${mode.toUpperCase()} mode.`
      : "Idle.";

    window.__VALIDOON_LAST__ = items; // in-memory only
  }

  function clearAll() {
    inputEl.value = "";
    setCounts([]);
    setSummary([]);
    resultsEl.innerHTML = "";
    statusEl.textContent = "Cleared.";
    window.__VALIDOON_LAST__ = [];
  }

  async function pasteFromClipboard() {
    try {
      const txt = await navigator.clipboard.readText();
      if (txt) {
        inputEl.value = txt;
        setCounts(parseLines(txt));
        statusEl.textContent = "Pasted from clipboard.";
      } else {
        statusEl.textContent = "Clipboard is empty.";
      }
    } catch {
      statusEl.textContent = "Clipboard access blocked by browser permissions.";
    }
  }

  async function copyJson() {
    const data = window.__VALIDOON_LAST__ || [];
    try {
      await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
      statusEl.textContent = "Copied JSON to clipboard.";
    } catch {
      statusEl.textContent = "Copy failed (browser permissions).";
    }
  }

  function selfTest() {
    inputEl.value = [
      "hello world",
      "email@example.com",
      "https://example.com/path?q=1",
      "<script>alert(1)</script>",
      "../etc/passwd",
      "SELECT * FROM users WHERE id=1"
    ].join("\n");
    setCounts(parseLines(inputEl.value));
    scan();
  }

  // ------- Events -------
  inputEl.addEventListener("input", () => setCounts(parseLines(inputEl.value)));

  scanBtn.addEventListener("click", scan);
  clearBtn.addEventListener("click", clearAll);
  pasteBtn.addEventListener("click", pasteFromClipboard);

  showWhyEl.addEventListener("change", () => render(window.__VALIDOON_LAST__ || []));
  modeEl.addEventListener("change", () => {
    if ((window.__VALIDOON_LAST__ || []).length) scan();
  });

  copyJsonBtn.addEventListener("click", copyJson);
  selfTestLink.addEventListener("click", (e) => {
    e.preventDefault();
    selfTest();
  });

  // Ctrl+Enter to scan
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") scan();
  });

  // Init
  window.__VALIDOON_LAST__ = [];
  setCounts([]);
  setSummary([]);
})();
```0
