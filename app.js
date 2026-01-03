(() => {
  "use strict";

  // VERSION MARKER (must appear in console)
  console.log("[VALIDOON_LOADED] v=2026-01-03_14-00");

  const $ = (id) => document.getElementById(id);
  const on = (el, evt, fn) => el && el.addEventListener(evt, fn);

  const TEST_A = ["hello world", "https://example.com/"];
  const TEST_B = ["next=/safe/path", "redirect_uri=https://evil.com"];

  function boot() {
    const input = $("inputStream");
    const loadA = $("loadTestA");
    const loadB = $("loadTestB");
    const exec  = $("executeBtn");
    const exp   = $("exportBtn");
    const info  = $("infoBtn");
    const clr   = $("clearBtn");

    // If any is missing, do not crash
    on(loadA, "click", () => { if (input) input.value = TEST_A.join("\n"); });
    on(loadB, "click", () => { if (input) input.value = TEST_B.join("\n"); });

    on(exec, "click", () => alert("Execute Scan works ✅"));
    on(exp,  "click", () => alert("Export JSON works ✅"));
    on(info, "click", () => alert("Info works ✅"));
    on(clr,  "click", () => { if (input) input.value = ""; });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
