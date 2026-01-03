(function () {
  "use strict";

  // ---- DOM
  const inputStream = document.getElementById("inputStream");

  const btnExecute = document.getElementById("btnExecute");
  const btnExport = document.getElementById("btnExport");
  const btnLoadA = document.getElementById("btnLoadA");
  const btnLoadB = document.getElementById("btnLoadB");
  const btnClear = document.getElementById("btnClear");

  const verdictBox = document.getElementById("verdictBox");
  const peakSeverity = document.getElementById("peakSeverity");
  const confidence = document.getElementById("confidence");
  const signals = document.getElementById("signals");

  const countScans = document.getElementById("countScans");
  const countAllow = document.getElementById("countAllow");
  const countWarn = document.getElementById("countWarn");
  const countBlock = document.getElementById("countBlock");

  const findingsBody = document.getElementById("findingsBody");

  // Info modal
  const btnInfo = document.getElementById("btnInfo");
  const infoModal = document.getElementById("infoModal");
  const closeInfo = document.getElementById("closeInfo");

  // ---- Helpers
  const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

  // Simple entropy estimate
  function entropy(str) {
    if (!str) return 0;
    const map = new Map();
    for (const ch of str) map.set(ch, (map.get(ch) || 0) + 1);
    let e = 0;
    const len = str.length;
    for (const [, c] of map) {
      const p = c / len;
      e -= p * Math.log2(p);
    }
    return Number(e.toFixed(2));
  }

  function addBadge(label) {
    const el = document.createElement("span");
    el.className = "badge";
    el.textContent = label;
    signals.appendChild(el);
  }

  function setVerdict(name) {
    verdictBox.classList.remove("secure", "suspicious", "danger");
    if (name === "SECURE") verdictBox.classList.add("secure");
    if (name === "SUSPICIOUS") verdictBox.classList.add("suspicious");
    if (name === "DANGER") verdictBox.classList.add("danger");
    verdictBox.textContent = name;
  }

  function pill(decision) {
    const span = document.createElement("span");
    span.className = "pill " + (decision === "ALLOW" ? "allow" : decision === "WARN" ? "warn" : "block");
    span.textContent = decision;
    return span;
  }

  function classify(line) {
    const s = line.trim();
    const lower = s.toLowerCase();

    let type = "Data";
    let severity = 0;
    let conf = 0;
    const tags = [];

    // URL
    const isURL = /^https?:\/\//i.test(s);
    if (isURL) type = "URL";

    // XSS
    if (/<script\b|onerror\s*=|onload\s*=/i.test(s)) {
      tags.push("XSS");
      severity = Math.max(severity, 85);
      conf = Math.max(conf, 85);
      type = "Exploit";
    }

    // SQLi
    if (/(\bor\b|\band\b)\s+1\s*=\s*1|union\s+select|sleep\(|benchmark\(/i.test(s)) {
      tags.push("SQLI_TAUTOLOGY");
      severity = Math.max(severity, 80);
      conf = Math.max(conf, 80);
      type = "Exploit";
    }

    // LFI
    if (/\.\.\/\.\.\/|\/etc\/passwd|windows\/system32/i.test(s)) {
      tags.push("LFI_FILE");
      severity = Math.max(severity, 75);
      conf = Math.max(conf, 75);
      type = "Exploit";
    }

    // CMD / PowerShell
    if (/powershell\b|cmd\.exe|bash\s+-c|;\s*rm\s+-rf|\bcurl\b.*\|\s*sh/i.test(lower)) {
      tags.push("CMD_EXEC");
      severity = Math.max(severity, 78);
      conf = Math.max(conf, 78);
      type = "Exploit";
    }

    // Redirect param
    if (/redirect(_uri)?=|returnurl=|continue=|next=/i.test(s)) {
      tags.push("REDIRECT_PARAM");
      severity = Math.max(severity, 55);
      conf = Math.max(conf, 70);
      type = isURL ? "URL" : type;
    }

    // Homograph / suspicious host hints (very light)
    if (isURL && /xn--/i.test(s)) {
      tags.push("HOMOGRAPH_RISK");
      severity = Math.max(severity, 60);
      conf = Math.max(conf, 70);
    }

    // Base64-ish (high entropy)
    const ent = entropy(s);
    if (/^[A-Za-z0-9+/=]{40,}$/.test(s) && ent >= 4.2) {
      tags.push("BASE64_OBFUSCATION");
      severity = Math.max(severity, 50);
      conf = Math.max(conf, 65);
      type = "Data";
    }

    // Decision
    let decision = "ALLOW";
    if (severity >= 80) decision = "BLOCK";
    else if (severity >= 45) decision = "WARN";

    // If empty line
    if (!s) {
      return null;
    }

    return {
      item: s,
      type,
      decision,
      severity: clamp(severity, 0, 100),
      confidence: clamp(conf || (decision === "ALLOW" ? 52 : 70), 0, 100),
      entropy: ent,
      tags
    };
  }

  function render(results) {
    // reset
    signals.innerHTML = "";
    findingsBody.innerHTML = "";

    let allow = 0, warn = 0, block = 0;
    let peak = 0;
    let confPeak = 0;

    const tagSet = new Set();

    for (const r of results) {
      peak = Math.max(peak, r.severity);
      confPeak = Math.max(confPeak, r.confidence);

      if (r.decision === "ALLOW") allow++;
      if (r.decision === "WARN") warn++;
      if (r.decision === "BLOCK") block++;

      for (const t of r.tags) tagSet.add(t);

      const tr = document.createElement("tr");

      const tdItem = document.createElement("td");
      tdItem.textContent = r.item;

      const tdType = document.createElement("td");
      tdType.textContent = r.type;

      const tdDecision = document.createElement("td");
      tdDecision.appendChild(pill(r.decision));

      const tdSeverity = document.createElement("td");
      tdSeverity.textContent = r.severity + "%";

      const tdConf = document.createElement("td");
      tdConf.textContent = r.confidence + "%";

      const tdEnt = document.createElement("td");
      tdEnt.textContent = r.entropy;

      tr.append(tdItem, tdType, tdDecision, tdSeverity, tdConf, tdEnt);
      findingsBody.appendChild(tr);
    }

    // verdict
    let v = "SECURE";
    if (block > 0) v = "DANGER";
    else if (warn > 0) v = "SUSPICIOUS";
    setVerdict(v);

    peakSeverity.textContent = peak + "%";
    confidence.textContent = confPeak + "%";

    // counters
    countScans.textContent = String(results.length);
    countAllow.textContent = String(allow);
    countWarn.textContent = String(warn);
    countBlock.textContent = String(block);

    // badges
    if (tagSet.size === 0) addBadge("No signals");
    else Array.from(tagSet).sort().forEach(addBadge);
  }

  function execute() {
    const lines = (inputStream.value || "").split("\n");
    const results = [];
    for (const line of lines) {
      const r = classify(line);
      if (r) results.push(r);
    }
    render(results);
    window.__VALIDOON_LAST__ = results;
  }

  function exportJSON() {
    const data = window.__VALIDOON_LAST__ || [];
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "validoon_report.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ---- Tests
  const TEST_A = [
    "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://accounts.google.com/signin/oauth/authorize?redirect_uri=https://evil.com",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "' OR 1=1 --",
    "powershell -enc SQBFAFgA",
    "hello world"
  ].join("\n");

  const TEST_B = [
    "https://example.com/",
    "xn--pple-43d.com/login",
    "returnUrl=https://evil.com",
    "union select password from users",
    "onerror=alert(1)",
    "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
  ].join("\n");

  // ---- Bindings
  btnExecute.addEventListener("click", execute);
  btnExport.addEventListener("click", exportJSON);

  btnLoadA.addEventListener("click", () => { inputStream.value = TEST_A; execute(); });
  btnLoadB.addEventListener("click", () => { inputStream.value = TEST_B; execute(); });

  btnClear.addEventListener("click", () => {
    inputStream.value = "";
    window.__VALIDOON_LAST__ = [];
    render([]);
  });

  // Info modal
  btnInfo.addEventListener("click", () => infoModal.classList.add("show"));
  closeInfo.addEventListener("click", () => infoModal.classList.remove("show"));
  infoModal.addEventListener("click", (e) => {
    if (e.target === infoModal) infoModal.classList.remove("show");
  });

  // Initial render empty
  render([]);
})();
