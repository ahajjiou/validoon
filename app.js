"use strict";

/*
  Validoon – Local client-side decision engine
  No network calls
  No storage
  No external dependencies
*/

const inputEl = document.getElementById("input");
const buttonEl = document.getElementById("scanBtn");
const resultEl = document.getElementById("result");

buttonEl.addEventListener("click", () => {
  const raw = inputEl.value.trim();

  if (!raw) {
    showResult("No input provided.", false);
    return;
  }

  const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);

  let blocked = 0;

  for (const line of lines) {
    if (isSuspicious(line)) {
      blocked++;
    }
  }

  if (blocked > 0) {
    showResult(
      `BLOCKED\nDetected ${blocked} suspicious item(s).`,
      true
    );
  } else {
    showResult(
      "SECURE\nNo malicious patterns detected.",
      false
    );
  }
});

function isSuspicious(text) {
  const patterns = [
    /<script/i,
    /javascript:/i,
    /onerror=/i,
    /onload=/i,
    /union\s+select/i,
    /drop\s+table/i,
    /--\s*$/i,
    /\$\{.*\}/,
    /base64/i
  ];

  return patterns.some(rx => rx.test(text));
}

function showResult(message, blocked) {
  resultEl.textContent = message;
  resultEl.classList.remove("hidden", "block");

  if (blocked) {
    resultEl.classList.add("block");
  }
}