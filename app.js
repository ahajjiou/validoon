(() => {
  'use strict';

  // ---------------- CONFIG ----------------
  const CONFIG = Object.freeze({
    thresholds: { warn: 40, block: 70 },
    entropy: { minLen: 24, high: 4.6, baseScore: 30 },
    confidence: { base: 52, scoreW: 0.38, sigW: 3.2, max: 98 },
    maxLines: 3000,
    redirectKeys: [
      'redirect','redirect_uri','redirecturl','return','returnto',
      'continue','next','url','dest','destination','target'
    ],
    authPathRe: /(^|\/)(login|signin|sign-in|auth|oauth|sso)(\/|$)/i
  });

  // ---------------- RULES ----------------
  const RULES = Object.freeze({
    SQLI: [
      { re:/\bunion\s+all\s+select\b/i, score:95, sig:'SQLI_UNION_ALL', why:'UNION ALL SELECT indicates SQL injection attempt.' },
      { re:/\bunion\s+select\b/i,     score:90, sig:'SQLI_UNION',     why:'UNION SELECT indicates SQL injection attempt.' },
      { re:/\bor\s+1\s*=\s*1\b/i,     score:92, sig:'SQLI_TAUTOLOGY', why:'OR 1=1 tautology detected.' },
      { re:/\b(drop\s+table)\b/i,     score:95, sig:'SQLI_DROP',      why:'DROP TABLE detected (destructive SQL).' },
      { re:/\b(delete\s+from|truncate\s+table)\b/i, score:90, sig:'SQLI_DELETE', why:'DELETE/TRUNCATE detected (destructive SQL).' },
      { re:/\b(information_schema|pg_catalog)\b/i, score:90, sig:'SQLI_META', why:'Metadata enumeration patterns detected.' },
      { re:/\b(waitfor\s+delay|sleep\s*\(|benchmark\s*\()\b/i, score:88, sig:'SQLI_TIME', why:'Time-based SQL injection indicator.' }
    ],
    XSS: [
      { re:/<script\b/i, score:92, sig:'XSS_SCRIPT', why:'Script tag found.' },
      { re:/on(?:error|load|click|mouseover|focus|submit)\s*=/i, score:90, sig:'XSS_HANDLER', why:'Inline event-handler attribute detected.' },
      { re:/javascript:/i, score:90, sig:'XSS_JS_URL', why:'javascript: URL detected.' },
      { re:/\beval\s*\(/i, score:88, sig:'XSS_EVAL', why:'eval() usage detected.' },
      { re:/\b(document\.cookie|localStorage|sessionStorage|document\.location|location\.href)\b/i, score:85, sig:'XSS_SINK', why:'Sensitive browser sink access detected.' }
    ],
    CMD: [
      { re:/(?:;|\|\||&&)\s*(?:cat|ls|whoami|id|wget|curl|nc|bash|sh|powershell|cmd)\b/i, score:90, sig:'CMD_CHAIN', why:'Shell command chaining detected.' },
      { re:/\b(?:rm\s+-rf|del\s+\/f\s+\/q)\b/i, score:95, sig:'CMD_DESTRUCT', why:'Destructive command detected.' }
    ],
    LFI: [
      { re:/\.\.\/|\.\.%2f|%2e%2e%2f/i, score:85, sig:'PATH_TRAVERSAL', why:'Directory traversal pattern detected.' },
      { re:/\/etc\/passwd\b/i, score:92, sig:'LFI_ETC_PASSWD', why:'Attempt to access /etc/passwd detected.' },
      { re:/c:\\windows\\system32/i, score:90, sig:'LFI_SYSTEM32', why:'Attempt to access Windows system32 detected.' }
    ]
  });

  // ---------------- ENGINE ----------------
  class Engine {
    static RX = {
      url: /^https?:\/\/\S+$/i,
      ipv4: /^(?:\d{1,3}\.){3}\d{1,3}$/,
      b64: /^[A-Za-z0-9+/]+={0,2}$/,
      // ISO-ish log format used by test generators often
      logLine: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+ip=.+\bmethod=\w+\b.+\broute=/
    };

    static safeTrim(s){ return (s ?? '').toString().trim(); }

    static entropy(str){
      const s = (str ?? '').toString();
      const n = s.length;
      if (!n) return 0;
      const f = Object.create(null);
      for (const ch of s) f[ch] = (f[ch] || 0) + 1;
      let H = 0;
      for (const c of Object.values(f)){
        const p = c / n;
        H -= p * Math.log2(p);
      }
      return Number(H.toFixed(2));
    }

    static decode(text){
      let cur = this.safeTrim(text);
      const layers = [];
      if (!cur) return { decoded:'', layers };

      // Unicode NFKC (reveals confusables in many cases)
      try{
        const n0 = cur.normalize('NFKC');
        if (n0 !== cur){ cur = n0; layers.push('UNICODE_NFKC'); }
      } catch {}

      // URL decode
      try{
        if (/%[0-9a-f]{2}/i.test(cur)){
          const u = decodeURIComponent(cur);
          if (u && u !== cur){ cur = u; layers.push('URL_DECODE'); }
        }
      } catch {}

      // Base64 decode (guarded)
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

      // NFKC again post-decode
      try{
        const n1 = cur.normalize('NFKC');
        if (n1 !== cur){ cur = n1; layers.push('UNICODE_NFKC_POST'); }
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
          score += 20; sigs.push('INSECURE_HTTP'); reasons.push('URL uses HTTP (unencrypted).');
        }

        if (/[^\u0000-\u007F]/.test(host) || /xn--/i.test(host)){
          score += 40; sigs.push('HOMOGRAPH_RISK'); reasons.push('Non-ASCII or punycode host (homograph risk).');
        }

        const keys = Array.from(u.searchParams.keys()).map(k => k.toLowerCase());
        if (keys.some(k => CONFIG.redirectKeys.includes(k))){
          score += 15; sigs.push('REDIRECT_PARAM'); reasons.push('Redirect-like parameter present (open redirect risk).');
        }

        if (CONFIG.authPathRe.test(path)){
          score += 12; sigs.push('AUTH_ENDPOINT'); reasons.push('Auth/login endpoint detected (phishing target).');
        }

        if (this.RX.ipv4.test(host)){
          score += 22; sigs.push('IP_HOST'); reasons.push('Host is an IP address (phishing/SSRF risk).');
        }
      } catch {
        score = Math.max(score, 25);
        sigs.push('MALFORMED_URL');
        reasons.push('Malformed URL-like input detected.');
      }
      scoreRef.value = score;
    }

    static applyRules(decoded, sigs, reasons, scoreRef){
      const applyGroup = (groupName, rules) => {
        for (const r of rules){
          if (r.re.test(decoded)){
            scoreRef.value = Math.max(scoreRef.value, r.score);
            sigs.push(`${groupName}:${r.sig}`);
            reasons.push(r.why);
          }
        }
      };

      applyGroup('SQLI', RULES.SQLI);
      applyGroup('XSS', RULES.XSS);
      applyGroup('CMD', RULES.CMD);
      applyGroup('LFI', RULES.LFI);
    }

    static analyze(text){
      const raw = this.safeTrim(text);
      const { decoded, layers } = this.decode(raw);

      const sigs = [...layers];
      const reasons = [];
      const actions = new Set();
      const scoreRef = { value: 0 };

      this.applyRules(decoded, sigs, reasons, scoreRef);

      // URL intelligence
      if (this.RX.url.test(decoded)) this.urlIntel(decoded, sigs, reasons, scoreRef);

      // Entropy signal
      const ent = this.entropy(decoded);
      if (decoded.length >= CONFIG.entropy.minLen && ent > CONFIG.entropy.high){
        scoreRef.value = Math.max(scoreRef.value, CONFIG.entropy.baseScore);
        sigs.push('HIGH_ENTROPY');
        reasons.push('High entropy content (token/obfuscation likelihood).');
      }

      const score = Math.min(scoreRef.value, 100);
      const decision = score >= CONFIG.thresholds.block ? 'BLOCK' : (score >= CONFIG.thresholds.warn ? 'WARN' : 'ALLOW');

      const uniqSigs = Array.from(new Set(sigs));
      const confRaw = CONFIG.confidence.base + (score * CONFIG.confidence.scoreW) + (uniqSigs.length * CONFIG.confidence.sigW);
      const confidence = Math.round(Math.min(confRaw, CONFIG.confidence.max));

      // Actions
      if (decision === 'BLOCK'){
        actions.add('Block this input in the pipeline.');
        actions.add('Inspect surrounding logs for related activity.');
        actions.add('Sanitize/validate server-side before any processing.');
        if (uniqSigs.some(s => s.startsWith('SQLI:'))) actions.add('Use parameterized queries (prepared statements).');
        if (uniqSigs.some(s => s.startsWith('XSS:'))) actions.add('Apply output encoding + strict CSP.');
        if (uniqSigs.some(s => s.startsWith('CMD:'))) actions.add('Remove/whitelist any shell execution paths.');
        if (uniqSigs.some(s => s.startsWith('LFI:'))) actions.add('Harden file access (deny traversal, allowlist paths).');
      } else if (decision === 'WARN'){
        actions.add('Proceed with caution; verify source and context.');
        actions.add('If external: open in an isolated environment/sandbox.');
      } else {
        actions.add('No immediate threat detected. Keep routine monitoring.');
      }

      // Type
      let type = 'Data';
      const isUrl = this.RX.url.test(decoded);
      const isLog = this.RX.logLine.test(decoded);
      if (score >= CONFIG.thresholds.block) type = 'Exploit';
      else if (isUrl) type = 'URL';
      else if (isLog) type = 'Log';

      return {
        input: raw,
        decoded,
        type,
        decision,
        score,
        confidence,
        entropy: ent,
        sigs: uniqSigs,
        reasons: Array.from(new Set(reasons)).slice(0, 10),
        actions: Array.from(actions)
      };
    }
  }

  // ---------------- UI ----------------
  const $ = (id) => document.getElementById(id);

  function clearNode(node){
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function setVerdict(peak){
    const v = $('verdict');
    if (!v) return;

    if (peak >= CONFIG.thresholds.block){
      v.textContent = 'DANGER';
      v.style.color = 'var(--bad)';
    } else if (peak >= CONFIG.thresholds.warn){
      v.textContent = 'SUSPICIOUS';
      v.style.color = 'var(--warn)';
    } else {
      v.textContent = 'SECURE';
      v.style.color = 'var(--ok)';
    }
  }

  function resetUI(){
    if ($('input')) $('input').value = '';
    if ($('verdict')) { $('verdict').textContent = '---'; $('verdict').style.color = ''; }
    if ($('riskVal')) $('riskVal').textContent = '0%';
    if ($('confVal')) $('confVal').textContent = '0%';
    clearNode($('signals'));
    clearNode($('reasons'));
    clearNode($('actions'));
    clearNode($('tableBody'));
  }

  function renderChips(containerId, items){
    const box = $(containerId);
    if (!box) return;
    for (const s of items){
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = s;
      box.appendChild(chip);
    }
  }

  function renderList(containerId, items, limit){
    const ul = $(containerId);
    if (!ul) return;
    const list = typeof limit === 'number' ? items.slice(0, limit) : items;
    for (const it of list){
      const li = document.createElement('li');
      li.textContent = it;
      ul.appendChild(li);
    }
  }

  function tagHTML(decision){
    const cls = decision === 'BLOCK' ? 'tag-danger' : (decision === 'WARN' ? 'tag-warn' : 'tag-safe');
    return `<span class="tag ${cls}">${decision}</span>`;
  }

  function runScan(){
    const raw = ($('input') && $('input').value) ? $('input').value : '';
    let lines = raw.split('\n').map(s => s.trim()).filter(Boolean);

    clearNode($('signals'));
    clearNode($('reasons'));
    clearNode($('actions'));
    clearNode($('tableBody'));

    if (!lines.length){ resetUI(); return; }
    if (lines.length > CONFIG.maxLines) lines = lines.slice(0, CONFIG.maxLines);

    let peakScore = 0;
    let peakConf = 0;

    const allSigs = new Set();
    const allReasons = new Set();
    const allActions = new Set();

    for (const line of lines){
      const r = Engine.analyze(line);

      peakScore = Math.max(peakScore, r.score);
      peakConf = Math.max(peakConf, r.confidence);

      r.sigs.forEach(x => allSigs.add(x));
      r.reasons.forEach(x => allReasons.add(x));
      r.actions.forEach(x => allActions.add(x));

      const tr = document.createElement('tr');

      const tdSeg = document.createElement('td');
      tdSeg.className = 'mono';
      tdSeg.textContent = line;

      const tdType = document.createElement('td');
      tdType.textContent = r.type;

      const tdDec = document.createElement('td');
      tdDec.innerHTML = tagHTML(r.decision);

      const tdScore = document.createElement('td');
      tdScore.textContent = `${r.score}%`;

      const tdConf = document.createElement('td');
      tdConf.textContent = `${r.confidence}%`;

      const tdEnt = document.createElement('td');
      tdEnt.textContent = String(r.entropy);

      tr.append(tdSeg, tdType, tdDec, tdScore, tdConf, tdEnt);
      $('tableBody').appendChild(tr);
    }

    $('riskVal').textContent = `${peakScore}%`;
    $('confVal').textContent = `${peakConf}%`;
    setVerdict(peakScore);

    renderChips('signals', Array.from(allSigs));
    renderList('reasons', Array.from(allReasons), 8);
    renderList('actions', Array.from(allActions), 10);
  }

  // ---------------- TESTS ----------------
  const TEST_A = [
    "http://example.com/login?redirect=https://evil.example",
    "https://xn--pple-43d.com/login",
    "SELECT * FROM users WHERE id='1' OR 1=1;",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "id; whoami && cat /etc/passwd",
    "Ym9sdC5uZXQvc2VjdXJpdHk=",
    "Normal entry 12345",
    "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https://mail.google.com/mail/"
  ].join('\n');

  const TEST_B = [
    "https://example.com/auth/login?next=https://example.com/dashboard",
    "GET /api/v1/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1",
    "c:\\windows\\system32\\drivers\\etc\\hosts",
    "union all select username,password from users",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.signature",
    "Normal application log segment: user_id=42 action=view_report"
  ].join('\n');

  function exportJSON(){
    const raw = ($('input') && $('input').value) ? $('input').value : '';
    const lines = raw.split('\n').map(s => s.trim()).filter(Boolean);
    if (!lines.length) return;

    const data = lines.slice(0, CONFIG.maxLines).map(l => Engine.analyze(l));
    const blob = new Blob([JSON.stringify(data, null, 2)], { type:'application/json' });

    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = 'validoon_forensic.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function init(){
    const required = ['input','btnScan','btnClear','btnTestA','btnTestB','btnExport','verdict','riskVal','confVal','signals','reasons','actions','tableBody'];
    for (const id of required){
      if (!$(id)){
        // Fail-safe: do nothing if the page is not wired correctly.
        return;
      }
    }

    $('btnScan').addEventListener('click', runScan);
    $('btnClear').addEventListener('click', resetUI);
    $('btnTestA').addEventListener('click', () => { $('input').value = TEST_A; });
    $('btnTestB').addEventListener('click', () => { $('input').value = TEST_B; });
    $('btnExport').addEventListener('click', exportJSON);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
