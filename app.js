// app.js
(() => {
  'use strict';

  // ---------------- CONFIG (Step 5: stable knobs) ----------------
  const CONFIG = {
    thresholds: { warn: 40, block: 70 },
    maxLines: 2000,
    entropy: { minLength: 24, high: 4.6, baseScore: 30 },
    confidence: { base: 55, scoreWeight: 0.35, signalsWeight: 3.0, max: 98 },
    redirectKeys: [
      'redirect','redirect_uri','redirecturl','return','returnto','continue','next',
      'url','dest','destination','target'
    ],
    countersKey: 'validoon_counters_v1'
  };

  // ---------------- Utilities ----------------
  const $ = (id) => document.getElementById(id);

  function clearNode(node){
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function safeText(s){
    return (s ?? '').toString();
  }

  function safeTrim(s){
    return safeText(s).trim();
  }

  function uniq(arr){
    return Array.from(new Set(arr));
  }

  function clamp(n, a, b){
    return Math.max(a, Math.min(b, n));
  }

  function tagClass(decision){
    if (decision === 'BLOCK') return 'tag-block';
    if (decision === 'WARN') return 'tag-warn';
    return 'tag-allow';
  }

  // ---------------- Counters (Step 5: measurement) ----------------
  function loadCounters(){
    try {
      const raw = localStorage.getItem(CONFIG.countersKey);
      if (!raw) return { scans:0, lines:0, blocks:0 };
      const obj = JSON.parse(raw);
      return {
        scans: Number(obj.scans || 0),
        lines: Number(obj.lines || 0),
        blocks: Number(obj.blocks || 0)
      };
    } catch {
      return { scans:0, lines:0, blocks:0 };
    }
  }

  function saveCounters(c){
    try { localStorage.setItem(CONFIG.countersKey, JSON.stringify(c)); } catch {}
  }

  function renderCounters(){
    const c = loadCounters();
    const elScans = $('kpiScans');
    const elLines = $('kpiLines');
    const elBlocks = $('kpiBlocks');
    if (elScans) elScans.textContent = String(c.scans);
    if (elLines) elLines.textContent = String(c.lines);
    if (elBlocks) elBlocks.textContent = String(c.blocks);
  }

  // ---------------- Engine (Steps 2+3) ----------------
  const DETECTION_RULES = {
    SQLI: [
      { re:/\bunion\s+all\s+select\b/i, score:95, signal:'UNION_ALL', reason:'UNION ALL SELECT suggests SQL injection.' },
      { re:/\bunion\s+select\b/i, score:90, signal:'UNION', reason:'UNION SELECT suggests SQL injection.' },
      { re:/\bor\s+1\s*=\s*1\b/i, score:92, signal:'TAUTOLOGY', reason:'OR 1=1 tautology pattern detected.' },
      { re:/\b(drop\s+table|truncate\s+table)\b/i, score:95, signal:'DDL_DESTRUCTIVE', reason:'Destructive SQL keyword detected.' },
      { re:/\b(delete\s+from)\b/i, score:90, signal:'DELETE', reason:'DELETE FROM detected (potential destructive SQL).' },
      { re:/\b(information_schema|pg_catalog)\b/i, score:90, signal:'META_ENUM', reason:'Database metadata enumeration indicator.' },
      { re:/\b(load_file|into\s+outfile)\b/i, score:92, signal:'FILE_RW', reason:'SQL file read/write indicator (LOAD_FILE/OUTFILE).' },
      { re:/\bbenchmark\s*\(/i, score:88, signal:'TIME_BASED', reason:'Time-based SQL injection indicator (BENCHMARK).' }
    ],
    XSS: [
      { re:/<script\b/i, score:92, signal:'SCRIPT_TAG', reason:'Script tag found (possible XSS payload).' },
      { re:/on(?:error|load|click|mouseover|focus|submit)\s*=/i, score:90, signal:'EVENT_HANDLER', reason:'Inline event handler detected.' },
      { re:/javascript:/i, score:90, signal:'JS_URL', reason:'javascript: URL detected (XSS vector).' },
      { re:/\beval\s*\(/i, score:88, signal:'EVAL', reason:'eval() detected (dangerous sink).' },
      { re:/\b(document\.cookie|localStorage|sessionStorage|document\.location|location\.href)\b/i, score:85, signal:'SENSITIVE_SINK', reason:'Access to sensitive browser objects detected.' },
      { re:/innerHTML\s*=/i, score:80, signal:'INNERHTML', reason:'innerHTML assignment detected (DOM XSS risk).' }
    ],
    CMD: [
      { re:/(?:;|\|\||&&)\s*(?:cat|ls|whoami|id|wget|curl|nc|bash|sh|powershell|cmd)\b/i, score:90, signal:'CHAINING', reason:'Shell command chaining detected (command injection risk).' },
      { re:/\b(?:rm\s+-rf|del\s+\/f\s+\/q)\b/i, score:95, signal:'DESTRUCTIVE', reason:'Destructive command detected (rm -rf / del /f /q).' }
    ],
    LFI: [
      { re:/\.\.\/|\.\.%2f|%2e%2e%2f/i, score:85, signal:'TRAVERSAL', reason:'Directory traversal pattern detected.' },
      { re:/\/etc\/passwd\b/i, score:92, signal:'ETC_PASSWD', reason:'Attempt to access /etc/passwd detected.' },
      { re:/c:\\\\windows\\\\system32/i, score:90, signal:'SYSTEM32', reason:'Attempt to access Windows system32 detected.' }
    ]
  };

  class ValidoonEngine {
    static RX = {
      url: /^https?:\/\/\S+$/i,
      ipv4: /^(?:\d{1,3}\.){3}\d{1,3}$/,
      b64: /^[A-Za-z0-9+/]+={0,2}$/,
      logLine: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+ip=.+\bmethod=\w+\b.+\broute=/
    };

    static entropyNumber(str){
      const s = safeText(str);
      const len = s.length;
      if (!len) return 0;
      const freq = Object.create(null);
      for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
      let H = 0;
      for (const f of Object.values(freq)){
        const p = f / len;
        H -= p * Math.log2(p);
      }
      return Number(H.toFixed(2));
    }

    static decode(text){
      let cur = safeTrim(text);
      const layers = [];
      if (!cur) return { decoded:'', layers };

      // 1) Unicode NFKC
      try{
        const n0 = cur.normalize('NFKC');
        if (n0 !== cur){
          cur = n0;
          layers.push('UNICODE_NFKC');
        }
      } catch {}

      // 2) URL decode
      try{
        if (/%[0-9a-f]{2}/i.test(cur)){
          const u = decodeURIComponent(cur);
          if (u && u !== cur){
            cur = u;
            layers.push('URL_DECODE');
          }
        }
      } catch {}

      // 3) Base64 decode (safe heuristic)
      try{
        const looksB64 = this.RX.b64.test(cur) && cur.length >= 24 && (cur.length % 4 === 0);
        if (looksB64){
          const decoded = atob(cur);
          const printable = decoded.replace(/[^\x20-\x7E]/g,'').length;
          if (decoded.length && (printable / decoded.length) >= 0.70){
            cur = decoded;
            layers.push('BASE64_DECODE');
          }
        }
      } catch {}

      // 4) Unicode post
      try{
        const n1 = cur.normalize('NFKC');
        if (n1 !== cur){
          cur = n1;
          layers.push('UNICODE_NFKC_POST');
        }
      } catch {}

      return { decoded:cur, layers };
    }

    static urlIntel(urlStr, sigs, reasons, scoreRef){
      let score = scoreRef.value;
      try{
        const u = new URL(urlStr);
        const host = u.hostname || '';
        const path = (u.pathname || '').toLowerCase();

        if (u.protocol !== 'https:'){
          score += 20;
          sigs.push('URL:INSECURE_HTTP');
          reasons.push('URL uses HTTP (unencrypted).');
        }

        if (/[^\u0000-\u007F]/.test(host) || /xn--/i.test(host)){
          score += 40;
          sigs.push('URL:HOMOGRAPH');
          reasons.push('Suspicious host (non-ASCII / punycode) — homograph risk.');
        }

        const keys = Array.from(u.searchParams.keys()).map(k => k.toLowerCase());
        if (keys.some(k => CONFIG.redirectKeys.includes(k))){
          score += 15;
          sigs.push('URL:REDIRECT_PARAM');
          reasons.push('Redirect-style parameter present (open redirect risk).');
        }

        if (/(^|\/)(login|signin|sign-in|auth|oauth|sso)(\/|$)/i.test(path)){
          score += 12;
          sigs.push('URL:AUTH_ENDPOINT');
          reasons.push('Authentication-related endpoint detected.');
        }

        if (this.RX.ipv4.test(host)){
          score += 22;
          sigs.push('URL:IP_HOST');
          reasons.push('URL host is an IP (common phishing characteristic).');
        }
      } catch {
        score = Math.max(score, 25);
        sigs.push('URL:MALFORMED');
        reasons.push('Malformed URL-like input detected.');
      }
      scoreRef.value = score;
    }

    static applyRules(decoded, sigs, reasons, scoreRef){
      const applyCategory = (cat, rules) => {
        for (const rule of rules){
          if (rule.re.test(decoded)){
            scoreRef.value = Math.max(scoreRef.value, rule.score);
            sigs.push(`${cat}:${rule.signal}`);
            reasons.push(rule.reason);
          }
        }
      };
      applyCategory('SQLI', DETECTION_RULES.SQLI);
      applyCategory('XSS',  DETECTION_RULES.XSS);
      applyCategory('CMD',  DETECTION_RULES.CMD);
      applyCategory('LFI',  DETECTION_RULES.LFI);
    }

    static analyze(text){
      const raw = safeTrim(text);
      const { decoded, layers } = this.decode(raw);

      const sigs = [...layers];
      const reasons = [];
      const actions = new Set();
      const scoreRef = { value: 0 };

      // Apply structured rules
      this.applyRules(decoded, sigs, reasons, scoreRef);

      // URL intel
      if (this.RX.url.test(decoded)){
        this.urlIntel(decoded, sigs, reasons, scoreRef);
      }

      // Entropy signal
      const ent = this.entropyNumber(decoded);
      if (ent > CONFIG.entropy.high && decoded.length >= CONFIG.entropy.minLength){
        scoreRef.value = Math.max(scoreRef.value, CONFIG.entropy.baseScore);
        sigs.push('OBF:HIGH_ENTROPY');
        reasons.push('High entropy content (token/obfuscation-like).');
      }

      // Score + decision
      const score = clamp(scoreRef.value, 0, 100);
      const decision = score >= CONFIG.thresholds.block ? 'BLOCK' : (score >= CONFIG.thresholds.warn ? 'WARN' : 'ALLOW');

      // Confidence
      const uniqSigs = uniq(sigs);
      const confRaw =
        CONFIG.confidence.base +
        (score * CONFIG.confidence.scoreWeight) +
        (uniqSigs.length * CONFIG.confidence.signalsWeight);
      const confidence = Math.round(clamp(confRaw, 0, CONFIG.confidence.max));

      // Actions (Step 3: explain + do-next)
      if (decision === 'BLOCK'){
        actions.add('Block this input and investigate related context/source.');
        actions.add('Apply strict validation + server-side sanitization before processing.');
        if (uniqSigs.some(s => s.startsWith('SQLI'))) actions.add('Use prepared statements / parameterized queries.');
        if (uniqSigs.some(s => s.startsWith('XSS')))  actions.add('Encode output + enforce CSP on the target app.');
        if (uniqSigs.some(s => s.startsWith('CMD')))  actions.add('Remove direct shell execution or whitelist arguments.');
        if (uniqSigs.some(s => s.startsWith('LFI')))  actions.add('Normalize paths and block traversal sequences.');
      } else if (decision === 'WARN'){
        actions.add('Proceed carefully: verify context and source before trusting this input.');
      } else {
        actions.add('No immediate threat detected. Keep routine monitoring.');
      }

      // Type classification
      const isUrl = this.RX.url.test(decoded);
      const isLog = this.RX.logLine.test(decoded);
      let type = 'Data';
      if (score >= CONFIG.thresholds.block) type = 'Exploit';
      else if (isUrl) type = 'URL';
      else if (isLog) type = 'Log';

      // Primary reason (keep it crisp)
      const uniqReasons = uniq(reasons);
      const primaryReason = uniqReasons[0] || (decision === 'ALLOW'
        ? 'No strong risk patterns matched.'
        : 'Suspicious indicators matched.');

      return {
        input: raw,
        decoded,
        type,
        decision,
        score,
        confidence,
        entropy: ent,
        sigs: uniqSigs,
        primaryReason,
        reasons: uniqReasons.slice(0, 10),
        actions: Array.from(actions)
      };
    }
  }

  // ---------------- UI (Steps 1+4+5) ----------------
  function resetUI(){
    const inputEl = $('input');
    if (inputEl) inputEl.value = '';

    const verdict = $('verdict');
    if (verdict){
      verdict.textContent = '---';
      verdict.style.color = '';
    }

    if ($('riskVal')) $('riskVal').textContent = '0%';
    if ($('confVal')) $('confVal').textContent = '0%';

    clearNode($('signals'));
    clearNode($('reasons'));
    clearNode($('actions'));
    clearNode($('tableBody'));
  }

  function setVerdict(peakScore){
    const v = $('verdict');
    if (!v) return;

    if (peakScore >= CONFIG.thresholds.block){
      v.textContent = 'DANGER';
      v.style.color = 'var(--bad)';
    } else if (peakScore >= CONFIG.thresholds.warn){
      v.textContent = 'SUSPICIOUS';
      v.style.color = 'var(--warn)';
    } else {
      v.textContent = 'SECURE';
      v.style.color = 'var(--ok)';
    }
  }

  function renderList(id, items, limit){
    const box = $(id);
    if (!box) return;
    clearNode(box);
    (items || []).slice(0, limit ?? items.length).forEach(t => {
      const li = document.createElement('li');
      li.textContent = t;
      box.appendChild(li);
    });
  }

  function renderChips(items){
    const box = $('signals');
    if (!box) return;
    clearNode(box);
    (items || []).forEach(s => {
      const ch = document.createElement('span');
      ch.className = 'chip';
      ch.textContent = s;
      box.appendChild(ch);
    });
  }

  function renderTable(rows){
    const tbody = $('tableBody');
    if (!tbody) return;
    clearNode(tbody);

    rows.forEach(r => {
      const tr = document.createElement('tr');

      const tdSeg = document.createElement('td');
      tdSeg.className = 'mono';
      tdSeg.textContent = r.input;

      const tdType = document.createElement('td');
      tdType.textContent = r.type;

      const tdDec = document.createElement('td');
      const tag = document.createElement('span');
      tag.className = `tag ${tagClass(r.decision)}`;
      tag.textContent = r.decision;
      tdDec.appendChild(tag);

      const tdScore = document.createElement('td');
      tdScore.textContent = `${r.score}%`;

      const tdConf = document.createElement('td');
      tdConf.textContent = `${r.confidence}%`;

      const tdEnt = document.createElement('td');
      tdEnt.textContent = String(r.entropy);

      tr.append(tdSeg, tdType, tdDec, tdScore, tdConf, tdEnt);
      tbody.appendChild(tr);
    });
  }

  function runScan(){
    const inputEl = $('input');
    const raw = inputEl ? inputEl.value : '';
    let lines = raw.split('\n').map(s => s.trim()).filter(Boolean);

    clearNode($('tableBody'));
    clearNode($('signals'));
    clearNode($('reasons'));
    clearNode($('actions'));

    if (!lines.length){
      resetUI();
      return;
    }

    if (lines.length > CONFIG.maxLines){
      lines = lines.slice(0, CONFIG.maxLines);
      // keep silent for UX
    }

    const results = [];
    let peakScore = 0;
    let peakConf = 0;

    const allSigs = new Set();
    const allReasons = new Set();
    const allActions = new Set();

    let blocks = 0;

    for (const line of lines){
      const r = ValidoonEngine.analyze(line);
      results.push(r);

      peakScore = Math.max(peakScore, r.score);
      peakConf = Math.max(peakConf, r.confidence);
      if (r.decision === 'BLOCK') blocks++;

      r.sigs.forEach(x => allSigs.add(x));
      r.reasons.forEach(x => allReasons.add(x));
      r.actions.forEach(x => allActions.add(x));
    }

    // KPIs
    if ($('riskVal')) $('riskVal').textContent = `${peakScore}%`;
    if ($('confVal')) $('confVal').textContent = `${peakConf}%`;
    setVerdict(peakScore);

    renderChips(Array.from(allSigs).slice(0, 18));
    renderList('reasons', Array.from(allReasons).slice(0, 6), 6);
    renderList('actions', Array.from(allActions).slice(0, 4), 4);
    renderTable(results);

    // Counters (Step 5)
    const c = loadCounters();
    c.scans += 1;
    c.lines += lines.length;
    c.blocks += blocks;
    saveCounters(c);
    renderCounters();
  }

  // ---------------- Tests (Step 4) ----------------
  function loadTestA(){
    const inputEl = $('input');
    if (!inputEl) return;
    inputEl.value =
`Normal application log segment: user_id=42 action=view_report
https://accounts.google.com/signin/v2/identifier?service=mail&continue=https://mail.google.com/mail/
http://example.com/login?redirect=https://evil.example
Ym9sdC5uZXQvc2VjdXJpdHk=
SELECT * FROM users WHERE id='1' OR 1=1;
<script>alert(1)</script>
../../../etc/passwd
GET /api/v1/search?q=report status=200`;
  }

  function loadTestB(){
    const inputEl = $('input');
    if (!inputEl) return;
    inputEl.value =
`https://xn--pple-43d.com/login
http://198.51.100.10/auth/login?redirect=https://evil.invalid
..%2f..%2f..%2fetc%2fpasswd
id; whoami && cat /etc/passwd
UNION ALL SELECT username, password FROM users
<img src=x onerror=alert(1)>
TUlNRV9IQVJEX0xJS0VfVE9LRU5fWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFg=`;
  }

  // ---------------- Export (Step 5) ----------------
  function exportJSON(){
    const inputEl = $('input');
    const raw = inputEl ? inputEl.value : '';
    const lines = raw.split('\n').map(s => s.trim()).filter(Boolean).slice(0, CONFIG.maxLines);
    if (!lines.length) return;

    const data = lines.map(l => ValidoonEngine.analyze(l));

    const payload = {
      generatedAt: new Date().toISOString(),
      count: data.length,
      thresholds: CONFIG.thresholds,
      data
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type:'application/json' });
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = 'validoon_report.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ---------------- Wire events ----------------
  function init(){
    const btnRun = $('btnRun');
    const btnClear = $('btnClear');
    const btnTestA = $('btnTestA');
    const btnTestB = $('btnTestB');
    const btnExport = $('btnExport');

    if (btnRun) btnRun.addEventListener('click', runScan);
    if (btnClear) btnClear.addEventListener('click', resetUI);
    if (btnTestA) btnTestA.addEventListener('click', loadTestA);
    if (btnTestB) btnTestB.addEventListener('click', loadTestB);
    if (btnExport) btnExport.addEventListener('click', exportJSON);

    renderCounters();
  }

  if (document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
```0
