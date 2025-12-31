"use strict";

/* ========= DOM ========= */
const inputEl   = document.getElementById("input");
const scanBtn   = document.getElementById("scanBtn");
const resultEl  = document.getElementById("result");

/* ========= Helpers ========= */
function classifyLine(line) {
  const l = line.toLowerCase();

  if (
    l.includes("<script") ||
    l.includes("javascript:") ||
    l.includes("onerror=") ||
    l.includes("onload=") ||
    l.includes("drop table") ||
    l.includes("select * from") ||
    l.includes("../") ||
    l.includes("etc/passwd")
  ) {
    return { level: "BLOCK", reason: "High-risk pattern detected" };
  }

  if (
    l.includes("http://") ||
    l.includes("https://") ||
    l.includes("token") ||
    l.includes("api_key") ||
    l.includes("password")
  ) {
    return { level: "WARN", reason: "Sensitive or external reference" };
  }

  return { level: "ALLOW", reason: "No obvious risk detected" };
}

/* ========= Scan ========= */
function runScan() {
  const raw = inputEl.value.trim();
  if (!raw) {
    resultEl.classList.remove("hidden");
    resultEl.classList.remove("block");
    resultEl.innerHTML = "No input provided.";
    return;
  }

  const lines = raw.split("\n");
  let html = "";
  let hasBlock = false;

  lines.forEach((line, i) => {
    const r = classifyLine(line);

    if (r.level === "BLOCK") hasBlock = true;

    html += `
      <div>
        <strong>${i + 1}. ${r.level}</strong> — ${r.reason}
      </div>
    `;
  });

  resultEl.innerHTML = html;
  resultEl.classList.remove("hidden");
  resultEl.classList.toggle("block", hasBlock);
}

/* ========= Clear ========= */
function clearAll() {
  inputEl.value = "";
  resultEl.innerHTML = "";
  resultEl.classList.add("hidden");
}

/* ========= Events ========= */
scanBtn.addEventListener("click", runScan);
