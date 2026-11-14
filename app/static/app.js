/* PhishLens interactive UI — report rendering, scan progress, toasts, guided tour, checklist. No frameworks. */

/* Interface translations: window.I18N is the current language's catalog (empty
   for English). {0}-style placeholders are filled from `vars`. */
const I18N = window.I18N || {};
function _t(s, vars) {
  const out = I18N[s] || s;
  return vars ? out.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? vars[k] : m)) : out;
}

// Marks a string for the translation catalog where it's looked up later with _t(variable).
const N_ = s => s;

// An API error as text: FastAPI sends a string, or a list of field problems
// for input it rejects outright.
function errorText(d, fallback) {
  const e = d && d.detail;
  if (typeof e === 'string' && e) return e;
  if (Array.isArray(e) && e.length) return e.map(x => (x && x.msg) || '').filter(Boolean).join('; ') || fallback;
  return fallback;
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function gradeClass(score) {
  if (score >= 90) return 'gA';
  if (score >= 80) return 'gB';
  if (score >= 70) return 'gC';
  if (score >= 60) return 'gD';
  return 'gF';
}

// Grade colours come from the theme (style.css --gA … --gF), so they follow light and dark mode.
const GRADE_COLORS = { gA: 'var(--gA)', gB: 'var(--gB)', gC: 'var(--gC)', gD: 'var(--gD)', gF: 'var(--gF)' };

/* Small inline icons (stroke = currentColor). */
const ICONS = {
  spark: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/><path d="M19 17l.7 1.8 1.8.7-1.8.7L19 22l-.7-1.8-1.8-.7 1.8-.7z"/></svg>',
  download: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v11M7 10l5 5 5-5M5 20h14"/></svg>',
  mail: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/></svg>',
  lock: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
  target: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3.5"/></svg>',
  check: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
  gauge: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4-5"/></svg>',
  bell: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/></svg>',
  scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="6"/><path d="M20 20l-4.2-4.2"/></svg>',
};

/* ---------------- toast ---------------- */
let _toastTimer = null;
function toast(msg) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

/* ---------------- clipboard ---------------- */
async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (_) {}
    ta.remove();
  }
  if (btn) {
    const orig = btn.textContent;
    btn.textContent = _t('Copied ✓'); btn.classList.add('ok');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('ok'); }, 1600);
  } else {
    toast(_t('Copied to clipboard ✓'));
  }
}

/* ---------------- scan progress (generic phases — no internals) ---------------- */
function runScanProgress(wrapId, phaseId, fillId) {
  const wrap = document.getElementById(wrapId);
  const phaseEl = document.getElementById(phaseId);
  const fill = document.getElementById(fillId);
  const phases = [
    _t('Resolving domain…'),
    _t('Collecting public records…'),
    _t('Evaluating configuration…'),
    _t('Compiling your report…')
  ];
  wrap.classList.remove('hidden');
  let i = 0, pct = 4, finished = false;
  fill.style.width = pct + '%';
  phaseEl.textContent = phases[0];
  const tick = setInterval(() => {
    if (finished) return;
    pct = Math.min(pct + Math.random() * 14, 92);
    fill.style.width = pct + '%';
    const ni = Math.min(Math.floor(pct / 25), phases.length - 1);
    if (ni !== i) { i = ni; phaseEl.textContent = phases[i]; }
  }, 650);
  return {
    done() {
      finished = true; clearInterval(tick);
      fill.style.width = '100%';
      setTimeout(() => wrap.classList.add('hidden'), 450);
    }
  };
}

/* ---------------- live scan radar ----------------
   Fed by POST /api/scans/public/stream: each check lights up a blip as it
   finishes (red = failing, amber = weak, green = pass). Only names and
   pass/weak/fail are shown here; the report follows. */
const RADAR_SIZE = 320, RADAR_C = 160;
function radarSvg() {
  let ticks = '';
  for (let i = 0; i < 72; i++) {
    const a = i * 5 * Math.PI / 180, long = i % 6 === 0;
    const r1 = 150, r2 = long ? 141 : 146;
    ticks += `<line x1="${(RADAR_C + r1 * Math.cos(a)).toFixed(1)}" y1="${(RADAR_C + r1 * Math.sin(a)).toFixed(1)}" x2="${(RADAR_C + r2 * Math.cos(a)).toFixed(1)}" y2="${(RADAR_C + r2 * Math.sin(a)).toFixed(1)}" class="rd-tick${long ? ' long' : ''}"/>`;
  }
  return `<svg class="rd-svg" viewBox="0 0 ${RADAR_SIZE} ${RADAR_SIZE}" aria-hidden="true">
    <defs>
      <linearGradient id="rd-wedge" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0" stop-color="var(--rd-green)" stop-opacity="0"/>
        <stop offset="1" stop-color="var(--rd-green)" stop-opacity=".38"/>
      </linearGradient>
    </defs>
    <circle cx="${RADAR_C}" cy="${RADAR_C}" r="152" class="rd-outer"/>
    ${ticks}
    <circle cx="${RADAR_C}" cy="${RADAR_C}" r="114" class="rd-ring"/>
    <circle cx="${RADAR_C}" cy="${RADAR_C}" r="76" class="rd-ring"/>
    <circle cx="${RADAR_C}" cy="${RADAR_C}" r="38" class="rd-ring"/>
    <line x1="${RADAR_C}" y1="4" x2="${RADAR_C}" y2="316" class="rd-axis"/>
    <line x1="4" y1="${RADAR_C}" x2="316" y2="${RADAR_C}" class="rd-axis"/>
    <g class="rd-sweep"><path d="M${RADAR_C} ${RADAR_C} L${RADAR_C + 150} ${RADAR_C} A150 150 0 0 0 ${(RADAR_C + 150 * Math.cos(-Math.PI / 4)).toFixed(1)} ${(RADAR_C + 150 * Math.sin(-Math.PI / 4)).toFixed(1)} Z" fill="url(#rd-wedge)"/>
      <line x1="${RADAR_C}" y1="${RADAR_C}" x2="${RADAR_C + 150}" y2="${RADAR_C}" class="rd-beam"/></g>
    <circle cx="${RADAR_C}" cy="${RADAR_C}" r="5" class="rd-hub"/>
  </svg>`;
}
/* Spread blips evenly: golden-angle spiral between the inner and outer ring. */
function radarSlot(i, total) {
  const a = (i * 137.508 - 90) * Math.PI / 180;
  const r = 42 + 96 * Math.sqrt((i + .5) / Math.max(total, 1));
  return {x: (RADAR_C + r * Math.cos(a)) / RADAR_SIZE * 100, y: (RADAR_C + r * Math.sin(a)) / RADAR_SIZE * 100};
}
const RADAR_WORD = {pass: N_('pass'), warn: N_('weak'), fail: N_('failing')};
/* Short names for the blips; the live list shows the full check name. */
const RADAR_SHORT = {'sec-headers': N_('Web headers'), pqc: N_('Post-quantum'), dane: 'DANE', ptr: 'PTR',
  'tls-cert': N_('TLS cert'), parked: N_('Parked'), dangling: N_('Dangling DNS'), dnsbl: N_('Blacklists')};
function runScanRadar(wrapId) {
  const wrap = document.getElementById(wrapId);
  wrap.innerHTML = `<div class="rd-card">
    <div class="rd-scope">${radarSvg()}<div class="rd-blips"></div></div>
    <div class="rd-side">
      <div class="rd-kicker"><span class="rd-live"></span>${_t('Live scan')}</div>
      <div class="rd-domain"></div>
      <div class="rd-count"><b>0</b><span>/ <i>–</i> ${_t('checks')}</span></div>
      <div class="rd-tally"><span class="t-fail"><b>0</b> ${_t('failing')}</span><span class="t-warn"><b>0</b> ${_t('weak')}</span><span class="t-pass"><b>0</b> ${_t('pass')}</span></div>
      <div class="rd-phase">${_t('Resolving domain…')}</div>
      <ol class="rd-feed" aria-live="polite"></ol>
    </div>
  </div>`;
  wrap.classList.remove('hidden');
  const q = el => wrap.querySelector(el);
  const blips = q('.rd-blips'), feed = q('.rd-feed');
  const tally = {fail: 0, warn: 0, pass: 0};
  let total = 0, shown = 0, timer = null, finishWaiters = [];
  const pending = [];
  function placeholders() {
    blips.innerHTML = '';
    for (let i = 0; i < total; i++) {
      const p = radarSlot(i, total);
      blips.insertAdjacentHTML('beforeend',
        `<span class="rd-blip" style="left:${p.x}%;top:${p.y}%;--d:${(i * 0.09).toFixed(2)}s"><i></i><em></em></span>`);
    }
  }
  function reveal(ev) {
    const st = ['pass', 'warn', 'fail'].includes(ev.status) ? ev.status : 'warn';
    const el = blips.children[shown];
    shown++;
    if (el) {
      el.classList.add('on', 'st-' + st);
      el.querySelector('em').textContent = _t(RADAR_SHORT[ev.key] || ev.title || ev.key || '');
    }
    tally[st]++;
    q('.rd-count b').textContent = shown;
    q('.t-' + st + ' b').textContent = tally[st];
    if (shown >= total) q('.rd-phase').textContent = _t('Compiling your report…');
    feed.insertAdjacentHTML('afterbegin',
      `<li class="st-${st}"><span class="rd-dot"></span><span class="rd-name">${escapeHtml(_t(ev.title || ev.key || ''))}</span><span class="rd-word">${_t(RADAR_WORD[st])}</span></li>`);
    while (feed.children.length > 7) feed.lastElementChild.remove();
  }
  function pump() {
    if (!pending.length) { timer = null; if (finishWaiters.length) finishWaiters.splice(0).forEach(f => f()); return; }
    reveal(pending.shift());
    timer = setTimeout(pump, 170);
  }
  return {
    start(domain, n) {
      total = n; q('.rd-domain').textContent = domain;
      q('.rd-count i').textContent = n;
      q('.rd-phase').textContent = _t('Collecting public records…');
      placeholders();
    },
    check(ev) { pending.push(ev); if (!timer) pump(); },
    /* Resolves once every queued blip has been shown, plus a short beat. */
    settle() {
      return new Promise(res => {
        const go = () => setTimeout(res, shown ? 550 : 0);
        if (!timer && !pending.length) go(); else finishWaiters.push(go);
      });
    },
    hide() { clearTimeout(timer); wrap.classList.add('hidden'); wrap.innerHTML = ''; }
  };
}

/* ---------------- report ---------------- */
function statusBadge(status) {
  const map = { pass: _t('✓ pass'), warn: _t('! warning'), fail: _t('✗ fail') };
  return `<span class="badge ${status}">${map[status] || escapeHtml(status)}</span>`;
}

function scoreRing(score) {
  const g = gradeClass(score);
  const color = GRADE_COLORS[g];
  const C = 2 * Math.PI * 52; // r=52
  return `
  <div class="ring-wrap" data-score="${score}">
    <svg width="118" height="118" viewBox="0 0 118 118" aria-hidden="true">
      <circle class="ring-bg" cx="59" cy="59" r="52"></circle>
      <circle class="ring-fg" cx="59" cy="59" r="52"
        style="stroke:${color}"
        stroke-dasharray="${C.toFixed(1)}"
        stroke-dashoffset="${C.toFixed(1)}"
        data-target-offset="${(C * (1 - score / 100)).toFixed(1)}"></circle>
    </svg>
    <div class="ring-num" data-count="${score}">0</div>
  </div>`;
}

/* VirusTotal reputation badge (informational; not part of the score) */
function reputationBadge(rep) {
  if (!rep) return '';
  const link = rep.url ? ` <a href="${escapeHtml(rep.url)}" target="_blank" rel="noopener noreferrer">${_t('View on VirusTotal ↗')}</a>` : '';
  if (!rep.known) return `<div class="rep-badge rep-unknown">${_t('◌ Not yet analysed by VirusTotal{0}', {0: link})}</div>`;
  const flagged = (rep.malicious || 0) + (rep.suspicious || 0);
  const cls = rep.malicious ? 'rep-bad' : rep.suspicious ? 'rep-warn' : 'rep-good';
  const icon = rep.malicious ? '✗' : rep.suspicious ? '!' : '✓';
  return `<div class="rep-badge ${cls}">${_t('{0} Flagged by {1}/{2} security vendors{3}', {0: icon, 1: flagged, 2: rep.total || 0, 3: link})}</div>`;
}

function fmtDate(iso) {
  const d = new Date(iso);
  return isNaN(d) ? '' : d.toLocaleDateString(undefined, {day: 'numeric', month: 'short', year: 'numeric'});
}

/* Tiny inline SVG sparkline of past scores (0-100 scale). */
function sparkline(points, w = 120, h = 28) {
  if (!points || points.length < 2) return '';
  const step = (w - 6) / (points.length - 1);
  // Scale to the observed range (at least 10 points tall) so real movement is visible.
  const scores = points.map(p => p.score);
  let lo = Math.min(...scores), hi = Math.max(...scores);
  if (hi - lo < 10) { const mid = (hi + lo) / 2; lo = mid - 5; hi = mid + 5; }
  const y = s => h - 3 - ((s - lo) / (hi - lo)) * (h - 6);
  const xy = points.map((p, i) => `${(3 + i * step).toFixed(1)},${y(p.score).toFixed(1)}`);
  const last = points[points.length - 1].score;
  const color = GRADE_COLORS[gradeClass(last)];
  return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img"
    aria-label="Score history: ${points.map(p => p.score).join(', ')}">
    <polyline fill="none" style="stroke:${color}" stroke-width="2" stroke-linejoin="round" points="${xy.join(' ')}"/>
    <circle cx="${xy[xy.length - 1].split(',')[0]}" cy="${xy[xy.length - 1].split(',')[1]}" r="2.5" style="fill:${color}"/></svg>`;
}

function trendLine(history) {
  const t = history && history.trend;
  if (!t) return '';
  const cls = t.delta > 0 ? 'up' : t.delta < 0 ? 'down' : 'flat';
  const text = t.delta === 0
    ? _t('Score unchanged at {0} since {1}', {0: t.to_score, 1: fmtDate(t.since)})
    : _t('Your score went from {0} to {1} since {2}', {0: t.from_score, 1: t.to_score, 2: fmtDate(t.since)});
  return `<div class="trend ${cls}">${t.delta > 0 ? '▲' : t.delta < 0 ? '▼' : '■'} ${escapeHtml(text)}
    ${sparkline(history.points)}</div>`;
}

/* "Add TXT at NAME: "VALUE"" fix lines can be published in one click when
   the account has connected its DNS provider (dashboard sets window.applyDnsFix). */
const FIX_RECORD_RE = /Add TXT(?: record)? at ([A-Za-z0-9_.-]+): "([^"]+)"/;
function applyButton(fix, opts) {
  if (!opts.applyFix) return '';
  const m = FIX_RECORD_RE.exec(fix);
  return m ? `<button class="copy-btn" data-apply-name="${escapeHtml(m[1])}" data-apply-value="${escapeHtml(m[2])}">${_t('Apply in {0}', {0: escapeHtml(window.DNS_LABEL || 'DNS')})}</button>` : '';
}

/* ---------------- fix cards ----------------
   Each failing check carries a `guide` from the scanner: plain-language
   problem, the exact record fields, and steps. The card shows the record as
   separate fields with their own copy buttons, and adapts field names and
   steps to the DNS provider picked (detected from the nameservers). */
const DNS_PROVIDERS = {
  cloudflare: {label: 'Cloudflare', name: 'Name', value: 'Content', ttl: 'Auto', apex: '@',
    open: N_('Sign in at <b>dash.cloudflare.com</b> and open <b>{0}</b>.'),
    add: N_('Go to <b>DNS → Records</b> and click <b>Add record</b>.'),
    edit: N_('Go to <b>DNS → Records</b>, find the {0} record named <b>{1}</b> shown under "Replaces", and click <b>Edit</b>.'),
    save: N_('Click <b>Save</b>.')},
  godaddy: {label: 'GoDaddy', name: 'Name', value: 'Value', ttl: '1 Hour', apex: '@',
    open: N_('Sign in at <b>dcc.godaddy.com</b>, open <b>Domains</b> and select <b>{0}</b>.'),
    add: N_('Open the <b>DNS</b> tab and click <b>Add New Record</b>.'),
    edit: N_('Open the <b>DNS</b> tab, find the {0} record named <b>{1}</b> shown under "Replaces", and click the pencil icon.'),
    save: N_('Click <b>Save</b>.')},
  namecheap: {label: 'Namecheap', name: 'Host', value: 'Value', ttl: 'Automatic', apex: '@',
    open: N_('Sign in at <b>namecheap.com</b>, open <b>Domain List</b> and click <b>Manage</b> next to <b>{0}</b>.'),
    add: N_('Open <b>Advanced DNS</b> and click <b>Add New Record</b>.'),
    edit: N_('Open <b>Advanced DNS</b> and find the {0} record with host <b>{1}</b> shown under "Replaces".'),
    save: N_('Click the green tick to save.')},
  route53: {label: 'Amazon Route 53', name: 'Record name', value: 'Value', ttl: '300', apex: '', quoteTxt: true,
    open: N_('Sign in to the AWS console and open <b>Route 53 → Hosted zones → {0}</b>.'),
    add: N_('Click <b>Create record</b>.'),
    edit: N_('Select the {0} record named <b>{1}</b> and click <b>Edit record</b>.'),
    save: N_('Click <b>Create records</b> (or <b>Save</b>).'),
    valueHint: N_('Route 53 needs TXT values inside double quotes. Copy includes them.')},
  m365: {label: 'Microsoft 365', name: 'TXT name', value: 'TXT value', ttl: '1 hour', apex: '@',
    open: N_('Sign in at <b>admin.microsoft.com</b> and go to <b>Settings → Domains → {0}</b>.'),
    add: N_('Open <b>DNS records</b> and click <b>Add record</b>.'),
    edit: N_('Open <b>DNS records</b>, select the {0} record named <b>{1}</b> and click <b>Edit</b>.'),
    save: N_('Click <b>Save</b>.')},
  squarespace: {label: 'Squarespace Domains', name: 'Host', value: 'Data', ttl: 'Default', apex: '@',
    open: N_('Sign in at <b>account.squarespace.com/domains</b> and click <b>{0}</b>.'),
    add: N_('Open <b>DNS → DNS Settings</b> and click <b>Add record</b> under Custom records.'),
    edit: N_('Open <b>DNS → DNS Settings</b> and click the {0} record with host <b>{1}</b> shown under "Replaces".'),
    save: N_('Click <b>Save</b>.')},
  hostinger: {label: 'Hostinger', name: 'Name', value: 'Value', ttl: 'Default', apex: '@',
    open: N_('Sign in to <b>hPanel</b>, open <b>Domains</b> and select <b>{0}</b>.'),
    add: N_('Open <b>DNS / Nameservers</b> and use <b>Manage DNS records</b>.'),
    edit: N_('Open <b>DNS / Nameservers</b>, find the {0} record named <b>{1}</b> shown under "Replaces", and click <b>Edit</b>.'),
    save: N_('Click <b>Add Record</b> (or <b>Update</b>).')},
  digitalocean: {label: 'DigitalOcean', name: 'Hostname', value: 'Value', ttl: '3600', apex: '@',
    open: N_('Sign in at <b>cloud.digitalocean.com</b> and open <b>Networking → Domains → {0}</b>.'),
    add: N_('Choose the <b>{0}</b> tab to create the record.'),
    edit: N_('Find the {0} record named <b>{1}</b> shown under "Replaces", click <b>More → Edit record</b>.'),
    save: N_('Click <b>Create Record</b> (or <b>Update</b>).')},
  other: {label: N_('Other / not sure'), name: 'Name / Host', value: 'Value / Content', ttl: 'Default (1 hour is fine)', apex: '@',
    open: N_('Sign in where you bought <b>{0}</b>, or wherever its DNS is managed.'),
    add: N_('Find <b>DNS</b>, <b>DNS records</b> or <b>Zone editor</b> and choose <b>Add record</b>.'),
    edit: N_('Find <b>DNS</b>, <b>DNS records</b> or <b>Zone editor</b>, and edit the {0} record named <b>{1}</b> shown under "Replaces".'),
    save: N_('Save the record.'),
    hint: N_('If the box already shows ".{0}" after it, type only the part above. If it wants the full name, use "{1}".')},
};
const DIFFICULTY = {easy: N_('Easy'), medium: N_('Medium'), hard: N_('Needs a technical person')};
let FIX_GUIDES = [];
let FIX_OPTS = {};
let fixProvider = null;
try { fixProvider = localStorage.getItem('phishlens_dns_provider'); } catch (_) {}

function providerFor(key) { return DNS_PROVIDERS[key] ? key : 'other'; }

function fixHost(rec, p) {
  return rec.host === '@' ? (p.apex || '@') : rec.host;
}

function fixRecordRows(rec, domain, pk, opts) {
  const p = DNS_PROVIDERS[pk];
  const host = fixHost(rec, p);
  const quote = p.quoteTxt && rec.type === 'TXT';
  const value = rec.value ? (quote ? `"${rec.value}"` : rec.value) : '';
  const copy = (v) => `<button class="copy-btn" data-copy="${escapeHtml(v)}">${_t('Copy')}</button>`;
  const hint = rec.host === '@'
    ? (p.apex ? _t('"{0}" means {1} itself.', {0: p.apex, 1: domain}) : _t('Leave this box empty: the record goes on {0} itself.', {0: domain}))
    : (p.hint && pk === 'other' ? _t(p.hint, {0: domain, 1: rec.fqdn}) : _t('{0} adds ".{1}" for you.', {0: _t(p.label), 1: domain}));
  const caa = rec.type === 'CAA' ? rec.value.match(/^(\d+)\s+(\w+)\s+"?([^"]+)"?$/) : null;
  const rows = [
    `<div class="rec-row"><span class="rec-label">${_t('Type')}</span><span class="rec-val">${escapeHtml(rec.type)}</span>${copy(rec.type)}</div>`,
    `<div class="rec-row"><span class="rec-label">${_t(p.name)}</span><span class="rec-val">${escapeHtml(host || '—')}<span class="rec-hint">${escapeHtml(hint)}</span></span>${host ? copy(host) : '<span></span>'}</div>`,
  ];
  if (rec.value_from_provider) {
    rows.push(`<div class="rec-row"><span class="rec-label">${_t(p.value)}</span><span class="rec-val rec-pending">${_t('Your email provider gives you this value (see the steps below).')}</span><span></span></div>`);
  } else {
    rows.push(`<div class="rec-row"><span class="rec-label">${_t(p.value)}</span><span class="rec-val">${escapeHtml(value)}${quote && p.valueHint ? `<span class="rec-hint">${escapeHtml(_t(p.valueHint))}</span>` : ''}${rec.note ? `<span class="rec-hint">${escapeHtml(rec.note)}</span>` : ''}${caa ? `<span class="rec-hint">${escapeHtml(_t('If your provider asks for separate boxes: Flags {0}, Tag {1}, Value {2}.', {0: caa[1], 1: caa[2], 2: caa[3]}))}</span>` : ''}</span>${copy(value)}</div>`);
  }
  rows.push(`<div class="rec-row"><span class="rec-label">${_t('TTL')}</span><span class="rec-val">${escapeHtml(_t(p.ttl))}</span><span></span></div>`);
  const current = rec.current ? `<div class="rec-current"><span class="rec-label">${_t('Replaces')}</span><code>${escapeHtml(rec.current)}</code></div>` : '';
  const changes = (rec.changes || []).length ? `<p class="small muted">${_t('What changes:')} ${rec.changes.map(escapeHtml).join(' · ')}</p>` : '';
  const apply = opts.applyFix && rec.type === 'TXT' && rec.value && window.applyDnsFix
    ? `<button class="btn tiny" data-apply-name="${escapeHtml(rec.fqdn)}" data-apply-value="${escapeHtml(rec.value)}">${_t('Apply in {0}', {0: escapeHtml(window.DNS_LABEL || 'DNS')})}</button>` : '';
  const action = rec.action === 'replace' ? _t('Change this record') : _t('Add this record');
  return `<div class="rec-block"><span class="fix-label">${action}</span>${current}<div class="rec">${rows.join('')}</div>${changes}${apply ? `<div class="fix-actions">${apply}</div>` : ''}</div>`;
}

function fixSteps(g, domain, pk) {
  const p = DNS_PROVIDERS[pk];
  const steps = [];
  const recs = g.records || [];
  if (recs.length && !recs.every(r => r.value_from_provider)) {
    const r = recs[0];
    steps.push(_t(p.open, {0: escapeHtml(domain)}));
    steps.push(r.action === 'replace'
      ? _t(p.edit, {0: escapeHtml(r.type), 1: escapeHtml(fixHost(r, p) || domain)})
      : _t(p.add, {0: escapeHtml(r.type)}));
    steps.push(r.action === 'replace'
      ? _t('Replace the value with the one above. Keep the type and name as they are.')
      : _t('Choose type <b>{0}</b>, then copy each field above into the matching box.', {0: escapeHtml(r.type)}));
    steps.push(_t(p.save) + ' ' + _t('Changes usually show within 5 minutes, and can take up to an hour.'));
  }
  const extra = (g.steps || []).map(escapeHtml);
  const all = recs.length && recs.every(r => r.value_from_provider) ? [...extra] : [...steps, ...extra];
  return all.length ? `<ol class="fix-steps">${all.map(s => `<li><div>${s}</div></li>`).join('')}</ol>` : '';
}

function fixCardInner(g, domain, pk, opts) {
  const recs = (g.records || []).map(r => fixRecordRows(r, domain, pk, opts)).join('');
  const file = g.file ? `<div class="rec-block"><span class="fix-label">${_t('Publish this file')}</span>
      <p class="small muted">${_t('At this address:')} <code>${escapeHtml(g.file.url)}</code></p>
      <pre class="fix-file">${escapeHtml(g.file.content)}</pre>
      <div class="fix-actions"><button class="copy-btn" data-copy="${escapeHtml(g.file.content)}">${_t('Copy file')}</button></div></div>` : '';
  const steps = fixSteps(g, domain, pk);
  return `${recs}${file}${steps ? `<div class="rec-block"><span class="fix-label">${_t('Steps')}</span>${steps}</div>` : ''}`;
}

function providerPicker(pk, detected) {
  const opts = Object.entries(DNS_PROVIDERS).map(([k, p]) =>
    `<option value="${k}"${k === pk ? ' selected' : ''}>${escapeHtml(_t(p.label))}</option>`).join('');
  const det = detected && detected.label
    ? `<span class="small muted">${_t('Detected from your nameservers: {0}', {0: escapeHtml(detected.label)})}</span>` : '';
  return `<div class="provider-pick"><label for="fix-provider">${_t('Where is your DNS managed?')}</label>
    <select id="fix-provider" class="fix-provider">${opts}</select>${det}</div>`;
}

function fixCard(g, check, points, domain, pk, opts, n) {
  const id = FIX_GUIDES.push({g, domain}) - 1;
  const chips = [
    `<span class="fchip ${escapeHtml(check.status)}">${check.status === 'fail' ? _t('✗ Failing') : _t('! Warning')}</span>`,
    points > 0 ? `<span class="fchip pts">${_t('+{0} points', {0: points})}</span>` : '',
    g.minutes ? `<span class="fchip">${_t('⏱ About {0} min', {0: g.minutes})}</span>` : '',
    g.difficulty ? `<span class="fchip">${_t(DIFFICULTY[g.difficulty] || g.difficulty)}</span>` : '',
  ].join('');
  const why = (g.problem || g.why) ? `<div class="fix-why">
      ${g.problem ? `<div><span class="fix-label">${_t('What\'s wrong')}</span><p>${escapeHtml(g.problem)}</p></div>` : ''}
      ${g.why ? `<div><span class="fix-label">${_t('Why it matters')}</span><p>${escapeHtml(g.why)}</p></div>` : ''}</div>` : '';
  return `<article class="fixcard" id="fix-${escapeHtml(check.key || id)}">
    <header class="fix-head"><div class="fix-chips">${n ? `<span class="fix-num">${n}</span>` : ''}${chips}</div>
      <h4>${escapeHtml(g.headline || check.title)}</h4><span class="small muted">${escapeHtml(check.title)}</span></header>
    <div class="fix-body">
      ${why}
      <div class="fix-dyn" data-gid="${id}">${fixCardInner(g, domain, pk, opts)}</div>
      ${g.warning ? `<p class="fix-warn"><b>${_t('Watch out:')}</b> ${escapeHtml(g.warning)}</p>` : ''}
      <div class="fix-actions">
        ${window.rescanDomain ? `<button class="btn tiny" data-rescan="${escapeHtml(domain)}">${_t('Check again')}</button>` : ''}
        <button class="btn tiny ghost" data-handoff="${id}">${_t('Copy instructions for your IT person')}</button>
      </div>
      ${g.next ? `<p class="small muted"><b>${_t('Next step:')}</b> ${escapeHtml(g.next)}</p>` : ''}
    </div></article>`;
}

/* Plain-text version of one card, to paste into an email or ticket. */
function fixHandoffText(g, domain, pk) {
  const p = DNS_PROVIDERS[pk];
  const lines = [g.headline, '', g.problem || '', g.why ? _t('Why it matters') + ': ' + g.why : ''];
  (g.records || []).forEach(r => {
    lines.push('', (r.action === 'replace' ? _t('Change this record') : _t('Add this record')) + ` (${domain}):`);
    lines.push(`  ${_t('Type')}: ${r.type}`, `  ${_t('Name / Host')}: ${r.host}  (${r.fqdn})`);
    lines.push(`  ${_t('Value')}: ${r.value || _t('Your email provider gives you this value (see the steps below).')}`);
    if (r.current) lines.push(`  ${_t('Replaces')}: ${r.current}`);
  });
  if (g.file) lines.push('', _t('Publish this file') + ': ' + g.file.url, g.file.content);
  const tmp = document.createElement('div');
  tmp.innerHTML = fixSteps(g, domain, pk);
  const steps = [...tmp.querySelectorAll('li')].map((li, i) => `${i + 1}. ${li.textContent.trim()}`);
  if (steps.length) lines.push('', _t('Steps') + ` (${_t(p.label)}):`, ...steps);
  if (g.warning) lines.push('', _t('Watch out:') + ' ' + g.warning);
  return lines.filter((l, i, a) => !(l === '' && a[i - 1] === '')).join('\n').trim();
}

function bindFixCards(container) {
  const sel = container.querySelector('.fix-provider');
  if (sel) sel.addEventListener('change', () => {
    fixProvider = sel.value;
    try { localStorage.setItem('phishlens_dns_provider', fixProvider); } catch (_) {}
    container.querySelectorAll('.fix-dyn').forEach(el => {
      const {g, domain} = FIX_GUIDES[+el.dataset.gid];
      el.innerHTML = fixCardInner(g, domain, fixProvider, FIX_OPTS);
    });
  });
  container.querySelectorAll('[data-handoff]').forEach(b => b.addEventListener('click', (e) => {
    e.preventDefault();
    const {g, domain} = FIX_GUIDES[+b.dataset.handoff];
    copyText(fixHandoffText(g, domain, (sel && sel.value) || 'other'), b);
  }));
  container.querySelectorAll('[data-rescan]').forEach(b => b.addEventListener('click', (e) => {
    e.preventDefault();
    if (window.rescanDomain) window.rescanDomain(b.dataset.rescan);
  }));
}

/* What an attacker or a receiving server can do when a check isn't passing:
   the "Impact" column of the observations table. */
const CHECK_IMPACT = {
  spf: N_('Receivers cannot tell which servers may send your mail, so forged mail is easier to deliver.'),
  dmarc: N_('Mail that fails authentication can still reach inboxes: attackers can send as your domain.'),
  dkim: N_('Your mail is not signed, so receivers cannot prove it came from you or was not changed.'),
  'mta-sts': N_('Mail sent to you can be downgraded to unencrypted SMTP by an attacker in the middle.'),
  'tls-rpt': N_('You will not hear about failed or downgraded TLS deliveries to your mail servers.'),
  bimi: N_('Your logo is not shown next to your mail in supporting inboxes.'),
  caa: N_('Any certificate authority can issue certificates for your domain.'),
  mx: N_('Mail for this domain may not be delivered.'),
  'smtp-tls': N_('Mail to your servers may travel unencrypted.'),
  dnssec: N_('DNS answers for your domain can be spoofed, for example with cache poisoning.'),
  dnsbl: N_('Mail from your domain or servers is likely to be rejected or marked as spam.'),
  'tls-cert': N_('Visitors may see certificate warnings, or the site may stop working when it expires.'),
  'sec-headers': N_('Your website is easier to attack with clickjacking and content injection.'),
  parked: N_('Attackers can send mail that appears to come from this unused domain.'),
  dangling: N_('Someone else could take over one of your subdomains, mail hosts or nameservers and use it for phishing.'),
  pqc: N_('Encrypted traffic recorded today could be decrypted in future by quantum computers.'),
};
const LOW_SEVERITY = ['bimi', 'caa', 'ipv6', 'sec-headers', 'rpki', 'ptr', 'dane', 'tls-rpt', 'pqc'];

function severityFor(c) {
  if (c.status === 'fail') return 'high';
  return LOW_SEVERITY.includes(c.key) ? 'low' : 'medium';
}

/* BIMI logo check result plus an inbox preview. The logo is shown through an
   <img> data: URL, where SVG never runs scripts. */
function bimiCheckHtml(r, svg, sender) {
  const src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg)));
  const name = escapeHtml(sender || r.title || _t('Your brand'));
  const list = (items, cls) => items.map(x => `<li class="${cls}">${escapeHtml(x)}</li>`).join('');
  return `<p>${statusBadge(r.ok ? 'pass' : 'fail')} ${r.ok ? _t('This logo meets SVG Tiny PS.') : _t('Inboxes will not show this logo yet:')}</p>
    <ul class="bimi-issues">${list(r.errors, 'error')}${list(r.warnings, 'muted')}</ul>
    <div class="bimi-preview">
      <div class="bimi-phone"><div class="bimi-row"><img src="${src}" alt=""><div><strong>${name}</strong><div class="muted small">${_t('Your order has shipped')}</div></div></div></div>
      <div class="bimi-desktop"><div class="bimi-row"><img src="${src}" alt=""><strong>${name}</strong><span class="muted small">${_t('Your order has shipped')}</span></div></div>
    </div>`;
}

function risksSection(checks, locked) {
  const d = risksDeck(checks, locked);
  return d ? `<section class="observations rpt-sec"><div class="sec-head"><h3>${_t('Top risks')}</h3><p>${_t('What an attacker could do today, most serious first.')}</p></div>${d}</section>` : '';
}

function dnssecParts(checks) {
  const c = checks.find(x => x.key === 'dnssec');
  if (!c || c.signed_at_nameservers === undefined) return '';
  const yes = `<span class="badge pass">${_t('Enabled')}</span>`;
  const no = `<span class="badge warn">${_t('Disabled')}</span>`;
  return `<p class="details">${_t('Signed at nameservers')}: ${c.signed_at_nameservers ? yes : no}
    · ${_t('DS record at registrar')}: ${c.ds_at_registrar ? yes : no}</p>`;
}

/* The free report has no fixes: the server leaves them out (solutions_locked).
   This card says the plan exists and who can open it, never how fixes work. */
function lockedGuideCard(r, opts) {
  const next = opts.next ? '?next=' + encodeURIComponent(opts.next) : '';
  return `<div class="plan-lock" id="remediation-locked">
    <div class="locked-ico">${ICONS.lock}</div>
    <div class="locked-body">
    <h3>${_t('Your remediation plan is ready')}</h3>
    <p>${_t('{0} issue(s) on this domain have a remediation plan. Sign in or create a free account to view it.', {0: r.locked_fixes})}</p>
    ${window.SIGNUP_ON && opts.scanId ? `<form class="plan-mail" data-scan="${escapeHtml(opts.scanId)}">
      <input name="email" type="email" required placeholder="${_t('Work email')}" aria-label="${_t('Work email')}">
      <input name="company" type="text" required maxlength="200" placeholder="${_t('Company or organization')}" aria-label="${_t('Company or organization')}">
      <button class="btn" type="submit">${_t('Send me the plan')}</button>
      <p class="muted small">${_t('Creates your free account. By continuing you accept the Terms and Privacy notice.')}</p>
    </form>` : ''}
    <p class="locked-actions">
      ${window.SIGNUP_ON && !opts.scanId ? `<a class="btn" href="/signup${next}">${_t('Create a free account')}</a>` : ''}
      <a class="btn ghost" href="/login${next}">${_t('Log in')}</a></p>
    </div>
  </div>`;
}

/* Report sections: every check belongs to one category. */
const CHECK_CATEGORY = {
  spf: 'auth', dkim: 'auth', dmarc: 'auth', bimi: 'auth',
  'smtp-tls': 'transport', 'mta-sts': 'transport', 'tls-rpt': 'transport', dane: 'transport',
  mx: 'dns', dnssec: 'dns', caa: 'dns', ptr: 'dns', ipv6: 'dns', rpki: 'dns', parked: 'dns', dangling: 'dns',
  dnsbl: 'reputation', 'tls-cert': 'web', 'sec-headers': 'web', pqc: 'web',
};
const CATEGORIES = [
  {key: 'auth', label: N_('Email authentication'), blurb: N_('Stops others sending email as you')},
  {key: 'transport', label: N_('Transport encryption'), blurb: N_('Keeps mail private in transit')},
  {key: 'dns', label: N_('Domain and DNS'), blurb: N_('Integrity of your domain records')},
  {key: 'reputation', label: N_('Reputation'), blurb: N_('Blocklists and sender standing')},
  {key: 'web', label: N_('Website'), blurb: N_('HTTPS and browser protections')},
];
const KEY_PROTOCOLS = ['spf', 'dkim', 'dmarc', 'mta-sts', 'tls-rpt', 'bimi', 'dnssec'];

function riskLevel(score) {
  if (score >= 80) return {cls: 'low', label: _t('Low risk')};
  if (score >= 60) return {cls: 'moderate', label: _t('Moderate risk')};
  if (score >= 40) return {cls: 'high', label: _t('High risk')};
  return {cls: 'critical', label: _t('Critical risk')};
}

function verdictFor(r, checks) {
  const dmarc = checks.find(c => c.key === 'dmarc');
  const spoofable = !dmarc || dmarc.status !== 'pass';
  const dom = escapeHtml(r.domain);
  if (r.score >= 90 && !spoofable) return {
    head: _t('{0} is well protected', {0: dom}),
    sub: _t('Email authentication is enforced and the main controls are in place. Keep monitoring for changes.')};
  if (spoofable) return {
    head: _t('Attackers can send email that appears to come from {0}', {0: dom}),
    sub: _t('Receiving mail servers are not told to reject forged mail from this domain, so phishing that uses your name can reach inboxes.')};
  return {
    head: _t('Spoofing is blocked, but gaps remain'),
    sub: _t('Forged mail from this domain is rejected. Other controls below still leave room for interception or abuse.')};
}

function protocolStrip(checks) {
  const icon = {pass: '✓', warn: '!', fail: '✕'};
  return KEY_PROTOCOLS.map(k => checks.find(c => c.key === k)).filter(Boolean).map(c =>
    `<a class="proto ${c.status}" href="#chk-${escapeHtml(c.key)}"><span class="proto-ico">${icon[c.status] || '·'}</span>${escapeHtml(c.title)}</a>`).join('');
}

/* ---------------- threat dashboard report (design C) ---------------- */
function threatRing(score) {
  const g = gradeClass(score);
  const C = 2 * Math.PI * 86;
  return `
  <div class="ring-wrap thr-ring" data-score="${score}">
    <span class="thr-sweep" aria-hidden="true"></span>
    <svg width="200" height="200" viewBox="0 0 200 200" aria-hidden="true">
      <circle class="ring-bg" cx="100" cy="100" r="86"></circle>
      <circle class="ring-fg" cx="100" cy="100" r="86" style="stroke:${GRADE_COLORS[g]}"
        stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${C.toFixed(1)}"
        data-target-offset="${(C * (1 - score / 100)).toFixed(1)}"></circle>
    </svg>
    <div class="ring-num" data-count="${score}">0</div>
  </div>`;
}

/* How an attacker could use the gaps: one row per attack, from the checks. */
const ATTACK_PATHS = [
  {key: 'spoof', icon: '🎭', label: N_('Spoofing your domain'), checks: ['dmarc', 'spf', 'parked'],
   open: N_('Forged mail that uses your domain can still land in inboxes.'), closed: N_('Forged mail using your domain is rejected.')},
  {key: 'intercept', icon: '🕵️', label: N_('Mail interception'), checks: ['mta-sts', 'smtp-tls', 'dane'],
   open: N_('An attacker in the middle can read or change mail sent to you.'), closed: N_('Mail to you is protected in transit.')},
  {key: 'web', icon: '🪟', label: N_('Website attacks'), checks: ['sec-headers', 'tls-cert'],
   open: N_('Your website is easier to clickjack or inject content into.'), closed: N_('Browser protections are in place.')},
  {key: 'takeover', icon: '🧩', label: N_('Domain or subdomain takeover'), checks: ['dangling', 'dnssec', 'caa'],
   open: N_('DNS records could be hijacked or spoofed to host phishing.'), closed: N_('No takeover paths found.')},
  {key: 'blocklist', icon: '🚫', label: N_('Mail blocked as spam'), checks: ['dnsbl', 'mx'],
   open: N_('Your mail is likely to be rejected or sent to spam.'), closed: N_('Not listed on the blocklists checked.')},
];
function attackPaths(checks) {
  return ATTACK_PATHS.map(a => {
    const cs = checks.filter(c => a.checks.includes(c.key) && c.status !== 'pass');
    const hard = cs.filter(c => c.status === 'fail' || (c.status === 'warn' && severityFor(c) !== 'low'));
    if (!checks.some(c => a.checks.includes(c.key))) return null;
    const state = hard.some(c => c.status === 'fail') || (a.key === 'spoof' && hard.length) ? 'likely'
      : hard.length ? 'possible' : cs.length ? 'limited' : 'closed';
    return {...a, state};
  }).filter(Boolean).sort((x, y) => ['likely', 'possible', 'limited', 'closed'].indexOf(x.state) - ['likely', 'possible', 'limited', 'closed'].indexOf(y.state));
}
const PATH_STATE = {likely: N_('likely'), possible: N_('possible'), limited: N_('limited'), closed: N_('blocked')};

const HEAT_LABEL = {auth: N_('Authentication'), transport: N_('Encryption'), dns: N_('DNS'), reputation: N_('Reputation'), web: N_('Website')};
function heatMap(checks) {
  const cols = ['high', 'medium', 'low', 'pass'];
  let i = 0;
  const rows = CATEGORIES.map(cat => {
    const cs = checks.filter(c => (CHECK_CATEGORY[c.key] || 'dns') === cat.key);
    if (!cs.length) return '';
    const n = {high: 0, medium: 0, low: 0, pass: 0};
    cs.forEach(c => { n[c.status === 'pass' ? 'pass' : severityFor(c)]++; });
    return `<div class="hm-label" title="${_t(cat.label)}">${_t(HEAT_LABEL[cat.key])}</div>` + cols.map(k =>
      `<div class="hm-cell hm-${k}${n[k] ? ' on' : ''}" style="--i:${i++};--a:${Math.min(1, .35 + n[k] * .22)}">${n[k]}</div>`).join('');
  }).join('');
  return `<div class="heat"><div></div><div class="hm-h">${_t('High')}</div><div class="hm-h">${_t('Medium')}</div><div class="hm-h">${_t('Low')}</div><div class="hm-h">${_t('Passed')}</div>${rows}</div>`;
}

const PROTO_WORD = {pass: N_('pass'), warn: N_('weak'), fail: N_('failing')};
function protocolTiles(checks) {
  return KEY_PROTOCOLS.map(k => checks.find(c => c.key === k)).filter(Boolean).map((c, i) =>
    `<a class="thr-proto ${c.status}" href="#chk-${escapeHtml(c.key)}" style="--i:${i}"><b>${escapeHtml(c.title)}</b><span>${_t(PROTO_WORD[c.status] || c.status)}</span></a>`).join('');
}

function exposureLevel(score) {
  if (score >= 80) return {cls: 'low', label: _t('Low exposure')};
  if (score >= 60) return {cls: 'moderate', label: _t('Moderate exposure')};
  if (score >= 40) return {cls: 'high', label: _t('High exposure')};
  return {cls: 'critical', label: _t('Critical exposure')};
}

function renderReport(scan, isPublic, opts = {}) {
  const r = scan.result || scan;
  const checks = r.checks || [];
  const plan = r.action_plan || [];
  const recs = r.recommendations || [];
  const issues = checks.filter(c => c.status === 'fail').length;
  const warnings = checks.filter(c => c.status === 'warn').length;
  const passedN = checks.filter(c => c.status === 'pass').length;

  const recHtml = recs.map(rec => `
    <div class="recommend">
      <h3>${escapeHtml(rec.headline)}</h3>
      <p>${escapeHtml(rec.body)}</p>
      <ul>${(rec.products || []).map(p =>
        `<li><strong>${escapeHtml(p.name)}</strong> — ${escapeHtml(p.blurb)}</li>`).join('')}</ul>
      ${rec.cta ? `<p><a class="btn ghost" href="${escapeHtml(rec.cta.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(rec.cta.label)} ↗</a></p>` : ''}
    </div>`).join('');

  FIX_GUIDES = [];
  FIX_OPTS = opts;
  const detected = r.dns_host || null;
  const pk = detected && DNS_PROVIDERS[detected.key] ? detected.key : providerFor(fixProvider || 'other');
  const planned = {};
  plan.forEach((p, i) => { if (p.guide) planned[p.check] = i + 1; });
  const hasGuides = checks.some(c => c.guide);
  const locked = !!r.solutions_locked;
  const lockHtml = locked && r.locked_fixes ? lockedGuideCard(r, opts) : '';
  const goodHtml = `<div class="plan good"><h3>${ICONS.check + ' ' + _t('Nothing urgent — this domain is in great shape.')}</h3></div>`;
  const planHead = `<div class="sec-head"><h3>${_t('Remediation priorities')}</h3><p>${_t('Ranked by how much each item raises your score.')}</p></div>`;
  const planHtml = plan.length || lockHtml
    ? `<section class="rpt-sec">${planHead}<div class="plan${locked ? ' locked-plan' : ''}">
      ${!locked && hasGuides ? providerPicker(pk, detected) : ''}
      ${planDeck(plan, checks, r, pk, opts, locked)}${lockHtml}</div></section>`
    : goodHtml;

  const rank = {fail: 0, warn: 1, pass: 2};
  const checkRow = (c, i, chip) => `
    <details class="check ${c.status}${chip ? ' fc-chip' : ''}" id="chk-${escapeHtml(c.key)}" style="--j:${i}">
      <summary>${chip ? `<span class="fc-tick" aria-hidden="true">✓</span><strong>${escapeHtml(c.title)}</strong><span class="pts">${c.score}/${c.max_score}</span>` : `${statusBadge(c.status)} <strong>${escapeHtml(c.title)}</strong>
        ${c.status !== 'pass' ? `<span class="sev ${severityFor(c)}">${({high: _t('High'), medium: _t('Medium'), low: _t('Low')})[severityFor(c)]}</span>` : ''}
        <span class="pts">${c.score}/${c.max_score}</span>
        ${c.status !== 'pass' && CHECK_IMPACT[c.key] ? `<span class="fc-why">${escapeHtml(_t(CHECK_IMPACT[c.key]))}</span>` : ''}`}
        <span class="chev">▾</span></summary>
      ${c.details ? `<p class="details">${escapeHtml(c.details)}</p>` : ''}
      ${c.key === 'dnssec' ? dnssecParts(checks) : ''}
      ${(c.issues || []).map(x => `<p class="issue">• ${escapeHtml(x)}</p>`).join('')}
      ${c.status !== 'pass' && CHECK_IMPACT[c.key] ? `<p class="impact"><span class="fix-label">${_t('Impact')}</span>${escapeHtml(_t(CHECK_IMPACT[c.key]))}</p>` : ''}
      ${c.solutions_locked ? `<p class="fix-locked">${ICONS.lock}<a href="#remediation-locked">${_t('Remediation available to signed-in users')}</a></p>` : ''}
      ${c.guide && planned[c.title] ? `<p class="fix-see"><a href="#fix-${escapeHtml(c.key)}">${_t('How to fix: see step {0} above ↑', {0: planned[c.title]})}</a></p>`
        : c.guide ? `<div class="fix-in-check">${fixCard(c.guide, c, c.max_score - c.score, r.domain, pk, opts, 0)}</div>`
        : (c.fixes || []).map(f => `<p class="fix"><code>${escapeHtml(f)}</code>
        <button class="copy-btn" data-copy="${escapeHtml(f)}">${_t('Copy')}</button>${applyButton(f, opts)}</p>`).join('')}
    </details>`;
  const groupsHtml = findingsCarousel(checks, rank, checkRow, locked);

  const scanned = r.scanned_at ? new Date(r.scanned_at) : null;
  const scannedText = scanned && !isNaN(scanned)
    ? scanned.toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'}) : _t('just now');
  const verdict = verdictFor(r, checks);
  const reportId = scan.id ? String(scan.id).slice(0, 8).toUpperCase() : '';

  const expo = exposureLevel(r.score);
  const paths = attackPaths(checks);
  return `
  <div class="report rpt rpt-threat">
    <span class="thr-scanline" aria-hidden="true"></span>
    <header class="rpt-head thr-head thr-anim">
      <div>
        <span class="rpt-kicker">${_t('Threat exposure report')}</span>
        <h2>${escapeHtml(r.domain)}</h2>
        <p class="rpt-meta">${_t('Scanned {0}', {0: escapeHtml(scannedText)})} · ${_t('{0} checks', {0: checks.length})}${reportId ? ` · ${_t('Report')} ${escapeHtml(reportId)}` : ''}</p>
      </div>
      <div class="thr-head-side">
        <span class="thr-expo ${expo.cls}"><i></i>${expo.label}</span>
        <div class="report-actions">
          ${opts.pdfUrl ? `<a class="btn tiny ghost pdf-btn" href="${escapeHtml(opts.pdfUrl)}" download>${ICONS.download}${_t('Download PDF')}</a>` : ''}
          ${opts.guideUrl && !locked ? `<a class="btn tiny ghost pdf-btn" href="${escapeHtml(opts.guideUrl)}" download>${ICONS.download}${_t('Fix guide (PDF)')}</a>` : ''}
          ${opts.emailUrl ? `<button class="btn tiny ghost" data-email-report="${escapeHtml(opts.emailUrl)}">${ICONS.mail}${_t('Email me this report')}</button>` : ''}
        </div>
      </div>
    </header>
    <section class="thr-grid">
      <div class="thr-card thr-score thr-anim" style="--i:0">
        ${threatRing(r.score)}
        <div class="thr-grade"><span class="grade big ${gradeClass(r.score)}">${escapeHtml(r.grade)}</span><span>${_t('Grade')}</span></div>
        <div class="thr-counts">
          <div class="stat fail"><b>${issues}</b><span>${_t('Failing')}</span></div>
          <div class="stat warn"><b>${warnings}</b><span>${_t('Warnings')}</span></div>
          <div class="stat pass"><b>${passedN}</b><span>${_t('Passed')}</span></div>
        </div>
      </div>
      <div class="thr-card thr-anim" style="--i:1">
        <h3>${_t('Open attack paths')}</h3>
        <p class="thr-verdict">${verdict.head}</p>
        <div class="thr-paths">${paths.map((a, i) => `<div class="thr-path ${a.state}" style="--i:${i}">
          <span class="thr-ico" aria-hidden="true">${a.icon}</span>
          <div><b>${_t(a.label)}</b> <span class="thr-state ${a.state}">${_t(PATH_STATE[a.state])}</span>
          <div class="thr-sub">${_t(a.state === 'closed' ? a.closed : a.open)}</div></div></div>`).join('')}</div>
      </div>
      <div class="thr-card thr-anim" style="--i:2">
        <h3>${_t('Risk heat map')}</h3>
        <p class="thr-sub">${_t('Findings by area and severity')}</p>
        ${heatMap(checks)}
        ${trendLine(scan.history)}
        ${reputationBadge(r.reputation)}
      </div>
    </section>
    <nav class="thr-protos thr-anim" aria-label="${_t('Key protocols')}">${protocolTiles(checks)}</nav>
    ${opts.summaryUrl ? `<section class="rpt-plain thr-anim" data-summary-url="${escapeHtml(opts.summaryUrl)}">
      <span class="plain-ico">${ICONS.spark}</span>
      <div><span class="rpt-kicker">${_t('In plain words')}</span>
      <p class="plain-text muted">${_t('Writing a summary of this report…')}</p></div></section>` : ''}
    <section class="rpt-sec">
      <div class="sec-head"><h3>${_t('Score by category')}</h3></div>
      ${categoryDeck(checks)}
    </section>
    ${risksSection(checks, locked)}
    ${r.compliance && r.compliance.length ? `<section class="compliance rpt-sec"><div class="sec-head"><h3>${_t('Mailbox provider requirements')}</h3><p>${_t('Rules Gmail, Yahoo and Microsoft apply to senders.')}</p></div>${complianceDeck(r.compliance)}</section>` : ''}
    ${planHtml}
    ${recHtml}
    <section class="rpt-sec">
      <div class="sec-head"><h3>${_t('Detailed findings')}</h3><p>${_t('One area at a time. Point at an area or press Next; open a row for the details.')}</p></div>
      ${hasGuides && !plan.some(p => p.guide) ? providerPicker(pk, detected) : ''}
      ${groupsHtml}
    </section>
    <footer class="rpt-foot">${_t('Read-only scan of public DNS, mail and web records. Results reflect the moment of the scan.')}</footer>
  </div>`;
}

/* Detailed findings: one area card at a time (tabs switch on hover or click,
   Next/Back, arrow keys, swipe). Issues are full rows; passes are chips that
   open in place. Every check keeps its #chk-<key> anchor. */
/* A carousel ("deck"): a tab row (switch on hover, click or focus), Next/Back,
   dots, arrow keys and swipe; one card shows at a time. Used by every
   report section that lists several things. items: {tone, ring|badge,
   label, short, sub, left, right, wide}. */
const DECK_C = (2 * Math.PI * 70).toFixed(1);
function deckRing(pct, small) {
  const off = (DECK_C * (1 - (pct || 0) / 100)).toFixed(1);
  return `<div class="fc-ring"><svg viewBox="0 0 170 170" aria-hidden="true"><circle class="bg" cx="85" cy="85" r="70"/><circle class="fg" cx="85" cy="85" r="70" style="stroke-dasharray:${DECK_C};stroke-dashoffset:${DECK_C};--off:${off}" data-off="${off}"/></svg>
    <div class="fc-num"><b data-to="${pct ?? ''}">${pct === null || pct === undefined ? '—' : pct}</b><small>${small || '/ 100'}</small></div></div>`;
}
function deck(items, o = {}) {
  if (!items.length) return '';
  const many = items.length > 5;
  const tabs = items.map((it, i) => `<button type="button" class="fc-tab tone-${it.tone}" role="tab" data-i="${i}" aria-selected="${i === 0}" style="--s:${it.ring ?? 100}">
      ${it.ring !== undefined ? `<span class="fc-mr"><span>${it.ring === null ? '—' : it.ring}</span></span>` : `<span class="fc-badge">${it.badge}</span>`}
      <span class="fc-tl"><b>${escapeHtml(it.label)}</b><em>${escapeHtml(it.short || it.label)}</em>${it.sub ? `<small>${it.sub}</small>` : ''}</span></button>`).join('');
  const cards = items.map((it, i) => `<article class="fc-card tone-${it.tone}${it.wide ? ' wide' : ''}${i === 0 ? ' on' : ''}" role="tabpanel" data-i="${i}"${i ? ' inert aria-hidden="true"' : ''}>
      ${it.left ? `<div class="fc-left">${it.left}</div>` : ''}
      <div class="fc-right">${it.right}</div>
    </article>`).join('');
  return `<div class="fc${o.cls ? ' ' + o.cls : ''}${many ? ' fc-many' : ''}" data-n="${items.length}">
    <div class="fc-bar"><div class="fc-tabs" role="tablist">${tabs}</div>
      <div class="fc-nav"><button type="button" class="fc-prev" aria-label="${_t('Previous')}">‹</button><span class="fc-pos">1 / ${items.length}</span><button type="button" class="fc-next" aria-label="${_t('Next')}">›</button></div></div>
    <div class="fc-stage">${cards}</div>
    <div class="fc-dots">${items.map((it, i) => `<i data-i="${i}"${i === 0 ? ' class="on"' : ''}></i>`).join('')}</div>
  </div>`;
}

function catStats(checks, rank) {
  return CATEGORIES.map(cat => {
    const cs = checks.filter(c => (CHECK_CATEGORY[c.key] || 'dns') === cat.key)
      .sort((a, b) => (rank[a.status] ?? 3) - (rank[b.status] ?? 3));
    if (!cs.length) return null;
    const earned = cs.reduce((a, c) => a + (c.score || 0), 0);
    const max = cs.reduce((a, c) => a + (c.max_score || 0), 0);
    const pct = max ? Math.round(100 * earned / max) : null;
    const tone = pct === null ? 'na' : pct >= 80 ? 'good' : pct >= 50 ? 'mid' : 'bad';
    const fails = cs.filter(c => c.status === 'fail').length, warns = cs.filter(c => c.status === 'warn').length;
    return {cat, cs, pct, tone, fails, warns, issues: cs.filter(c => c.status !== 'pass'), ok: cs.filter(c => c.status === 'pass')};
  }).filter(Boolean);
}
function catCounts(a) {
  return `<div class="fc-cnt">${a.fails ? `<span class="dotc fail">${_t('{0} failing', {0: a.fails})}</span>` : ''}${a.warns ? `<span class="dotc warn">${_t('{0} warnings', {0: a.warns})}</span>` : ''}${a.ok.length ? `<span class="dotc pass">${_t('{0} passed', {0: a.ok.length})}</span>` : ''}</div>`;
}
const STATUS_WORD = {pass: N_('Passed'), warn: N_('Warning'), fail: N_('Failing')};

/* Score by category: one area per card, every check with its points. */
function categoryDeck(checks) {
  const rank = {fail: 0, warn: 1, pass: 2};
  return deck(catStats(checks, rank).map(a => ({
    tone: a.tone, ring: a.pct, label: _t(a.cat.label), short: _t(FC_SHORT[a.cat.key]),
    sub: a.pct === null ? '' : (a.issues.length ? _t('{0} to review', {0: a.issues.length}) : _t('All passed')),
    left: `${deckRing(a.pct)}<h4>${_t(a.cat.label)}</h4><p>${_t(a.cat.blurb)}</p>${catCounts(a)}`,
    right: `<div class="fc-lbl">${_t('Points by check')}</div><ul class="fc-bars">${a.cs.map((c, j) => {
      const w = c.max_score ? Math.round(100 * c.score / c.max_score) : (c.status === 'pass' ? 100 : 0);
      return `<li class="${c.status}" style="--j:${j}"><span class="fb-name">${escapeHtml(c.title)}</span>
        <span class="fb-st">${_t(STATUS_WORD[c.status] || c.status)}</span>
        <span class="fb-bar"><i style="--w:${w}%"></i></span><span class="fb-pts">${c.max_score ? `${c.score}/${c.max_score}` : '—'}</span></li>`;
    }).join('')}</ul>`,
  })), {cls: 'fc-cats'});
}

/* Top risks: one risk per card, most serious first. */
const SEV_TONE = {high: 'bad', medium: 'mid', low: 'low'};
function risksDeck(checks, locked) {
  const order = {high: 0, medium: 1, low: 2};
  const label = {high: _t('High'), medium: _t('Medium'), low: _t('Low')};
  const rows = checks.filter(c => c.status === 'fail' || c.status === 'warn')
    .map(c => ({c, sev: severityFor(c)})).sort((a, b) => order[a.sev] - order[b.sev]);
  const n = rows.length;
  return deck(rows.map(({c, sev}, i) => ({
    tone: SEV_TONE[sev], badge: i + 1, label: c.title, sub: label[sev],
    left: `<div class="fc-medal"><span>${label[sev]}</span></div><h4>${_t('Risk {0} of {1}', {0: i + 1, 1: n})}</h4><p>${_t('Severity')}: ${label[sev]}</p>`,
    right: `<h3 class="fc-title">${escapeHtml(c.title)}</h3>
      ${(c.issues || [])[0] ? `<p class="fc-issue">${escapeHtml(c.issues[0])}</p>` : ''}
      <div class="fc-lbl">${_t('What an attacker could do')}</div>
      <p class="fc-text">${CHECK_IMPACT[c.key] ? escapeHtml(_t(CHECK_IMPACT[c.key])) : escapeHtml(c.details || '')}</p>
      ${locked ? `<p class="fc-lock">${ICONS.lock}<a href="#remediation-locked">${_t('Remediation available to signed-in users')}</a></p>`
        : (c.fixes || [])[0] ? `<div class="fc-lbl">${_t('Fix')}</div><p class="fc-text"><code>${escapeHtml(c.fixes[0])}</code></p>` : ''}
      <p class="fc-more"><a href="#chk-${escapeHtml(c.key)}">${_t('See the full finding')} →</a></p>`,
  })), {cls: 'fc-risks'});
}

/* Gmail / Yahoo / Microsoft sender requirements, one provider per card. */
function complianceDeck(list) {
  if (!list || !list.length) return '';
  const icon = {pass: '✓', fail: '✗', warn: '!', manual: '?'};
  const label = {pass: _t('Meets'), fail: _t('Fails'), warn: _t('Partly')};
  const tone = {pass: 'good', warn: 'mid', fail: 'bad'};
  return deck(list.map(p => {
    const pct = p.checked ? Math.round(100 * p.passed / p.checked) : null;
    return {
      tone: tone[p.status] || 'na', ring: pct, label: p.name, sub: label[p.status] || '',
      left: `${deckRing(pct, _t('{0}/{1} rules', {0: p.passed, 1: p.checked}))}<h4>${escapeHtml(p.name)}</h4><p><span class="badge ${p.status}">${label[p.status] || ''}</span></p>`,
      right: `${p.note ? `<p class="fc-text">${escapeHtml(p.note)}</p>` : ''}<div class="fc-lbl">${_t('Requirements')}</div>
        <ul class="fc-rules">${p.rules.map((r, j) => `<li class="rule ${r.status}" style="--j:${j}"><span class="ri">${icon[r.status]}</span><span>${escapeHtml(r.label)}${r.status === 'manual' ? ` <span class="muted small">(${_t('not visible in DNS: check it yourself')})</span>` : ''}</span></li>`).join('')}</ul>`,
    };
  }), {cls: 'fc-mail'});
}

/* Remediation priorities, one per card. Signed-in: the fix card. Free: the
   item, its points and that a plan exists (never how fixes work). */
function planDeck(plan, checks, r, pk, opts, locked) {
  const n = plan.length;
  return deck(plan.map((p, i) => {
    const c = checks.find(x => x.title === p.check) || {title: p.check, status: 'fail', key: ''};
    const sev = severityFor(c);
    const body = locked
      ? `<h3 class="fc-title">${escapeHtml(p.check)}</h3>
         ${CHECK_IMPACT[c.key] ? `<div class="fc-lbl">${_t('Why it matters')}</div><p class="fc-text">${escapeHtml(_t(CHECK_IMPACT[c.key]))}</p>` : ''}
         <p class="fc-lock">${ICONS.lock}<a href="#remediation-locked">${_t('Remediation available to signed-in users')}</a></p>`
      : p.guide ? fixCard(p.guide, c, p.points, r.domain, pk, opts, i + 1)
      : `<h3 class="fc-title">${escapeHtml(p.check)}</h3><p class="fixline"><code>${escapeHtml(p.fix)}</code>
         <button class="copy-btn" data-copy="${escapeHtml(p.fix)}">${_t('Copy')}</button>${applyButton(p.fix, opts)}</p>`;
    return {
      tone: SEV_TONE[sev], badge: i + 1, label: p.check, sub: _t('+{0} pts', {0: p.points}),
      left: `<div class="fc-medal step"><b>${i + 1}</b><span>${_t('of {0}', {0: n})}</span></div><h4 class="fc-gain">${_t('+{0} pts', {0: p.points})}</h4><p>${_t('Score gain when fixed')}</p>`,
      right: body,
    };
  }), {cls: 'fc-plan'});
}

/* Detailed findings: one area per card. Issues are full rows; passes are
   chips that open in place. Every check keeps its #chk-<key> anchor. */
const FC_SHORT = {auth: N_('Email'), transport: N_('Transport'), dns: N_('DNS'), reputation: N_('Reputation'), web: N_('Website')};
function findingsCarousel(checks, rank, checkRow, locked) {
  let j = 0;
  return deck(catStats(checks, rank).map(a => ({
    tone: a.tone, ring: a.pct, label: _t(a.cat.label), short: _t(FC_SHORT[a.cat.key]),
    sub: a.issues.length ? _t('{0} to review', {0: a.issues.length}) : _t('All passed'),
    left: `${deckRing(a.pct)}<h4>${_t(a.cat.label)}</h4><p>${_t(a.cat.blurb)}</p>${catCounts(a)}`,
    right: `${a.issues.length ? `<div class="fc-lbl">${_t('Needs attention')}</div><div class="fc-issues">${a.issues.map(c => checkRow(c, j++)).join('')}</div>`
        : `<div class="fc-allgood">${_t('Everything in this area passed.')}</div>`}
      ${a.ok.length ? `<div class="fc-lbl">${_t('Passed')}</div><div class="fc-ok">${a.ok.map(c => checkRow(c, j++, true)).join('')}</div>` : ''}
      ${locked && a.issues.length ? `<p class="fc-lock">${ICONS.lock}<a href="#remediation-locked">${_t('Remediation available to signed-in users')}</a></p>` : ''}`,
  })), {cls: 'fc-findings'});
}

function bindFindingsCarousel(container) {
  container.querySelectorAll('.fc').forEach(fc => {
    if (fc.dataset.bound) return;
    fc.dataset.bound = '1';
    const cards = [...fc.querySelectorAll('.fc-card')], tabs = [...fc.querySelectorAll('.fc-tab')], dots = [...fc.querySelectorAll('.fc-dots i')];
    const N = cards.length;
    let cur = -1;
    const motion = document.documentElement.classList.contains('motion');
    function fill(card) {
      const fg = card.querySelector('.fg'), num = card.querySelector('.fc-num b');
      if (!fg || !num) return;
      fg.style.strokeDashoffset = fg.dataset.off;
      const to = parseInt(num.dataset.to, 10);
      if (motion && !isNaN(to)) countUp(num, to, 900);
    }
    function show(i, dir) {
      i = (i + N) % N;
      if (i === cur) return;
      const back = dir < 0;
      if (cur >= 0) {
        const o = cards[cur];
        o.classList.remove('on', 'from-left'); o.classList.add('out'); o.classList.toggle('to-right', back);
        o.inert = true; o.setAttribute('aria-hidden', 'true');
        const fg = o.querySelector('.fg'); if (fg) fg.style.strokeDashoffset = fg.style.strokeDasharray;
        setTimeout(() => o.classList.remove('out', 'to-right'), 560);
      }
      const n = cards[i];
      n.classList.toggle('from-left', back);
      void n.offsetWidth;
      n.classList.add('on'); n.inert = false; n.removeAttribute('aria-hidden');
      fill(n);
      tabs.forEach((t, k) => { t.classList.toggle('on', k === i); t.setAttribute('aria-selected', k === i); });
      dots.forEach((d, k) => d.classList.toggle('on', k === i));
      fc.querySelector('.fc-pos').textContent = (i + 1) + ' / ' + N;
      cur = i;
    }
    fc.show = show;
    fc.indexOf = el => cards.indexOf(el.closest('.fc-card'));
    tabs.forEach((t, k) => {
      // Hover switches areas, but not while the page scrolls under a still mouse after a jump.
      t.addEventListener('pointerenter', e => { if (e.pointerType === 'mouse' && Date.now() > (fc.hoverLock || 0)) show(k, k > cur ? 1 : -1); });
      t.addEventListener('click', () => show(k, k > cur ? 1 : -1));
      t.addEventListener('focus', () => show(k, k > cur ? 1 : -1));
    });
    dots.forEach((d, k) => d.addEventListener('click', () => show(k, k > cur ? 1 : -1)));
    fc.querySelector('.fc-next').addEventListener('click', () => show(cur + 1, 1));
    fc.querySelector('.fc-prev').addEventListener('click', () => show(cur - 1, -1));
    fc.addEventListener('keydown', e => {
      if (e.target.closest('summary, input, textarea, select')) return;
      if (e.key === 'ArrowRight') { e.preventDefault(); show(cur + 1, 1); }
      if (e.key === 'ArrowLeft') { e.preventDefault(); show(cur - 1, -1); }
    });
    let sx = null, sy = null;
    const stage = fc.querySelector('.fc-stage');
    stage.addEventListener('touchstart', e => { sx = e.touches[0].clientX; sy = e.touches[0].clientY; }, {passive: true});
    stage.addEventListener('touchend', e => {
      if (sx === null) return;
      const dx = e.changedTouches[0].clientX - sx, dy = e.changedTouches[0].clientY - sy;
      if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.5) show(cur + (dx < 0 ? 1 : -1), dx < 0 ? 1 : -1);
      sx = null;
    });
    cards.forEach(c => c.classList.remove('on'));
    cards[0].classList.add('on');
    cur = 0;
    // Fill the first ring when the section scrolls into view.
    const first = () => fill(cards[cur]);
    if ('IntersectionObserver' in window) {
      const io = new IntersectionObserver(es => { if (es.some(x => x.isIntersecting)) { first(); io.disconnect(); } }, {threshold: .25});
      io.observe(fc);
    } else first();
  });
}

/* Jump to one check (protocol pills, links): switch its area card first. */
function openCheck(container, id) {
  const el = container.querySelector('#' + CSS.escape(id));
  if (!el) return false;
  const fc = el.closest('.fc');
  if (fc && fc.show) { fc.hoverLock = Date.now() + 1200; fc.show(fc.indexOf(el), 1); }
  if (el.tagName === 'DETAILS') el.open = true;
  setTimeout(() => el.scrollIntoView({behavior: 'smooth', block: 'center'}), fc ? 120 : 0);
  return true;
}

/* Wire up copy buttons + animate ring + count-up after injecting report HTML. */
function bindReportInteractions(container) {
  // Delegated, so buttons re-rendered by the provider picker keep working.
  if (!container.dataset.bound) {
    container.dataset.bound = '1';
    container.addEventListener('click', (e) => {
      const copy = e.target.closest('[data-copy]');
      if (copy) { e.preventDefault(); copyText(copy.getAttribute('data-copy'), copy); return; }
      const apply = e.target.closest('[data-apply-name]');
      if (apply) {
        e.preventDefault();
        if (window.applyDnsFix) window.applyDnsFix(apply.dataset.applyName, 'TXT', apply.dataset.applyValue, apply);
        return;
      }
      const mail = e.target.closest('[data-email-report]');
      if (mail && window.api) {
        e.preventDefault();
        mail.disabled = true;
        window.api(mail.dataset.emailReport, {method: 'POST'})
          .then(d => toast(_t('Report sent to {0}', {0: d.to})))
          .catch(err => { if (err.message !== 'auth') toast((_t('Could not send —') + ' ') + err.message); })
          .finally(() => { mail.disabled = false; });
        return;
      }
      const jump = e.target.closest('a[href^="#chk-"], a[href^="#fix-"]');
      if (jump && openCheck(container, jump.getAttribute('href').slice(1))) { e.preventDefault(); return; }
      const see = e.target.closest('.fix-see a, .fix-locked a, .fc-lock a');
      if (see) {
        e.preventDefault();
        const el = container.querySelector(see.getAttribute('href'));
        if (el) { if (window.revealSection) revealSection(el); el.scrollIntoView({behavior: 'smooth', block: 'start'}); }
      }
    });
  }
  bindFixCards(container);
  bindFindingsCarousel(container);
  // Threat dashboard: each block plays its entrance when it scrolls into view.
  const anims = container.querySelectorAll('.thr-anim:not(.go)');
  if ('IntersectionObserver' in window && anims.length) {
    const io = new IntersectionObserver(es => es.forEach(e => {
      if (e.isIntersecting) { e.target.classList.add('go'); io.unobserve(e.target); }
    }), {threshold: 0.15});
    anims.forEach(el => io.observe(el));
  } else anims.forEach(el => el.classList.add('go'));
  container.querySelectorAll('[data-summary-url]').forEach(sec => {
    const url = sec.dataset.summaryUrl;
    const tenant = window.api && !/\/api\/scans\/(public|shared)\//.test(url);
    (tenant ? window.api(url) : fetch(url).then(r => r.ok ? r.json() : Promise.reject(new Error(r.status))))
      .then(d => {
        const p = sec.querySelector('.plain-text');
        p.textContent = d.text;
        p.classList.remove('muted');
        if (d.source === 'ai') p.insertAdjacentHTML('afterend', `<span class="muted small">${_t('Written by AI from the findings above.')}</span>`);
      })
      .catch(() => sec.remove());
  });
  container.querySelectorAll('form.plan-mail').forEach(f => f.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = f.querySelector('button');
    btn.disabled = true;
    try {
      const r = await fetch('/api/auth/signup', {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: f.email.value.trim(), company: f.company.value.trim(), accept_terms: true,
                              scan_id: f.dataset.scan})});
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errorText(d, _t('Sign-up failed')));
      f.innerHTML = `<p class="sub">${_t('Check your inbox: your login details are on the way.')}</p>`;
    } catch (err) { toast(err.message); btn.disabled = false; }
  }));
  container.querySelectorAll('.ring-wrap').forEach(ring => {
    const fg = ring.querySelector('.ring-fg');
    const num = ring.querySelector('.ring-num');
    const target = parseInt(ring.dataset.score, 10) || 0;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      fg.style.strokeDashoffset = fg.dataset.targetOffset;
    }));
    // The score climbs from 0, and the ring changes colour as it passes
    // each grade (red, orange, amber, blue, green), then the grade lands.
    const t0 = performance.now(), dur = 1600;
    let shown = '';
    (function countUp(t) {
      const k = Math.min((t - t0) / dur, 1);
      const eased = 1 - Math.pow(1 - k, 3);
      const cur = Math.round(target * eased);
      num.textContent = cur;
      const g = gradeClass(cur);
      if (g !== shown) { shown = g; fg.style.stroke = GRADE_COLORS[g]; }
      if (k < 1) requestAnimationFrame(countUp);
      else {
        ring.classList.add('landed');
      }
    })(t0);
  });
}

/* ---------------- guided tour ---------------- */
function startTour(steps) {
  if (!steps.length) return;
  let idx = 0;
  const overlay = document.createElement('div');
  overlay.className = 'tour-overlay';
  overlay.innerHTML = `
    <div class="tour-hole"></div>
    <div class="tour-card">
      <p class="tour-step"></p>
      <h3 class="tour-title"></h3>
      <p class="tour-text"></p>
      <div class="tour-actions">
        <button class="btn ghost tiny tour-skip">${_t('Skip tour')}</button>
        <span style="flex:1"></span>
        <button class="btn ghost tiny tour-back">${_t('← Back')}</button>
        <button class="btn tiny tour-next">${_t('Next →')}</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  const hole = overlay.querySelector('.tour-hole');
  const card = overlay.querySelector('.tour-card');

  function place() {
    const step = steps[idx];
    const el = document.querySelector(step.el);
    if (el && window.revealSection) revealSection(el);
    if (!el || el.offsetParent === null) { next(); return; }
    el.scrollIntoView({behavior: 'smooth', block: 'center'});
    setTimeout(() => {
      const r = el.getBoundingClientRect();
      const pad = 10;
      hole.style.left = (r.left - pad) + 'px';
      hole.style.top = (r.top - pad) + 'px';
      hole.style.width = (r.width + pad * 2) + 'px';
      hole.style.height = (r.height + pad * 2) + 'px';
      overlay.querySelector('.tour-step').textContent = _t('Step {0} of {1}', {0: idx + 1, 1: steps.length});
      overlay.querySelector('.tour-title').textContent = step.title;
      overlay.querySelector('.tour-text').textContent = step.text;
      overlay.querySelector('.tour-back').style.visibility = idx === 0 ? 'hidden' : 'visible';
      overlay.querySelector('.tour-next').textContent = idx === steps.length - 1 ? _t('Finish ✓') : _t('Next →');
      // position card: below the hole if room, else above
      const cardH = 210;
      let top = r.bottom + pad + 14;
      if (top + cardH > window.innerHeight) top = Math.max(12, r.top - pad - cardH - 14);
      card.style.top = top + 'px';
      card.style.left = Math.max(12, Math.min(r.left - pad, window.innerWidth - 340)) + 'px';
    }, 350);
  }
  function next() {
    if (idx >= steps.length - 1) { end(); return; }
    idx++; place();
  }
  function back() { if (idx > 0) { idx--; place(); } }
  function end() {
    window.removeEventListener('resize', place);
    overlay.remove();
    try { localStorage.setItem('phishlens_tour_done', '1'); } catch (_) {}
  }
  overlay.querySelector('.tour-next').addEventListener('click', next);
  overlay.querySelector('.tour-back').addEventListener('click', back);
  overlay.querySelector('.tour-skip').addEventListener('click', end);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) end(); });
  window.addEventListener('resize', place);
  place();
}

/* ---------------- getting-started checklist ---------------- */
function renderChecklist(container, steps) {
  const done = steps.filter(s => s.done).length;
  const pct = Math.round(done / steps.length * 100);
  container.innerHTML = `
    <div class="checklist-head">
      <h2><span class="dot"></span> ${_t('Getting started')}</h2>
      <span class="muted small">${_t('{0} of {1} complete', {0: done, 1: steps.length})}</span>
    </div>
    <div class="progress-track" style="margin-bottom:14px"><div class="progress-fill" style="width:${pct}%"></div></div>
    <div class="checklist-items">
      ${steps.map(s => `
        <button class="checklist-item ${s.done ? 'done' : ''}" data-target="${s.target || ''}">
          <span class="checklist-box">${s.done ? '✓' : (s.num || '')}</span>
          <span class="checklist-label"><strong>${escapeHtml(s.label)}</strong>
          <small>${escapeHtml(s.hint || '')}</small></span>
          ${s.done ? '' : '<span class="checklist-go">→</span>'}
        </button>`).join('')}
    </div>
    ${done === steps.length ? ('<p class="all-done">' + _t('All set — your domain security is on autopilot.') + '</p>') : ''}`;
  container.querySelectorAll('.checklist-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = btn.getAttribute('data-target');
      if (t) {
        const el = document.querySelector(t);
        if (el) { if (window.revealSection) revealSection(el); el.scrollIntoView({behavior: 'smooth', block: 'center'}); }
      }
    });
  });
}

/* ---------------- colorful KPI tiles ---------------- */
function countUp(el, target, dur = 1000) {
  const t0 = performance.now();
  (function tick(t) {
    const k = Math.min((t - t0) / dur, 1);
    const eased = 1 - Math.pow(1 - k, 3);
    el.textContent = Math.round(target * eased);
    if (k < 1) requestAnimationFrame(tick);
  })(t0);
}

function avgScoreTile(scans, monitors) {
  let vals = (monitors || []).map(m => m.last_score).filter(x => x != null);
  if (!vals.length) vals = (scans || []).map(s => s.score).filter(x => x != null);
  if (!vals.length) return { num: '—', cls: 'kpi-blue', sub: _t('Run a scan to set a baseline') };
  const avg = Math.round(vals.reduce((a, b) => a + b, 0) / vals.length);
  const cls = avg >= 80 ? 'kpi-green' : avg >= 60 ? 'kpi-amber' : 'kpi-red';
  const sub = avg >= 80 ? _t('Strong posture — keep monitoring') : avg >= 60 ? _t('Room to improve — see action plan') : _t('Critical gaps — act on the plan');
  return { num: avg, cls, sub };
}

function renderKpis(container, { monitors = [], alerts = [], scans = [] } = {}) {
  const avg = avgScoreTile(scans, monitors);
  const tiles = [
    { cls: 'kpi-blue', glyph: ICONS.globe, num: monitors.length, label: _t('Domains monitored'), sub: monitors.length ? _t('Under continuous watch') : _t('Add your first below'), animate: true },
    { cls: avg.cls, glyph: ICONS.gauge, num: avg.num, label: _t('Average score'), sub: avg.sub, animate: typeof avg.num === 'number' },
    { cls: alerts.length ? 'kpi-red' : 'kpi-green', glyph: alerts.length ? ICONS.bell : ICONS.check, num: alerts.length, label: _t('Open alerts'), sub: alerts.length ? _t('Needs your attention') : _t('All quiet'), animate: true, pulse: alerts.length > 0 },
    { cls: 'kpi-violet', glyph: ICONS.scan, num: scans.length, label: _t('Scans run'), sub: scans.length === 1 ? _t('1 scan completed') : _t('{0} scans completed', {0: scans.length}), animate: true },
  ];
  container.innerHTML = tiles.map((t, i) => `
    <div class="kpi ${t.cls} ${t.pulse ? 'pulse' : ''}" style="animation-delay:${(i * 0.09).toFixed(2)}s">
      <span class="kpi-glyph">${t.glyph}</span>
      <div class="kpi-num" data-num="${t.animate ? t.num : ''}">${t.animate ? '0' : escapeHtml(t.num)}</div>
      <div><div class="kpi-label">${t.label}</div><div class="kpi-sub">${escapeHtml(t.sub)}</div></div>
    </div>`).join('');
  container.querySelectorAll('.kpi-num[data-num]').forEach(el => {
    const target = parseInt(el.dataset.num, 10);
    if (!isNaN(target)) countUp(el, target);
  });
}

/* ---------------- global ---------------- */
document.addEventListener('click', async (e) => {
  if (e.target && e.target.id === 'logout') {
    e.preventDefault();
    // Logout is a cookie-authenticated POST, so it must carry the CSRF token.
    const m = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
    await fetch('/api/auth/logout', {method: 'POST',
      headers: {'X-CSRF-Token': m ? decodeURIComponent(m[1]) : ''}}).catch(() => {});
    location.href = '/';
  }
});

/* ---------- motion: entrances, scroll reveals and count-ups ----------
   Everything here is decoration. Content is visible without it: the hidden
   start state only applies once this script adds .motion to <html>, and
   nothing animates for people who ask for reduced motion. */
(function motion() {
  if (!('IntersectionObserver' in window)) return;
  if (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const root = document.documentElement;
  root.classList.add('motion');
  const REVEAL = '.panel, .card, .check-tile, .kpi, .help-section, .rpt-sec, .cat-card, .section-head, .cta-band, .stat, .proto, .tool, .findings-group, details.check:not(.fc details.check)';
  const seen = new WeakSet();
  const io = new IntersectionObserver(entries => entries.forEach(e => {
    if (!e.isIntersecting) return;
    io.unobserve(e.target);
    if (e.target.dataset.count) countUp(e.target); else e.target.classList.add('in');
  }), {rootMargin: '0px 0px -6% 0px', threshold: 0.06});

  // Numbers count up from zero: "42", "9/12", "96%", "1,248".
  const NUM = /^\+?(\d[\d,]*)(%|\/\d+|\s?pts)?$/;
  function markCounts(scope) {
    scope.querySelectorAll('.kpi-num, .stat b, .cat-pct, .preview-ring b, .rr-pts, .stat-num').forEach(el => {
      if (el.dataset.count || el.children.length || el.closest('.ring-wrap')) return;
      const m = el.textContent.trim().match(NUM);
      if (m) { el.dataset.count = m[1].replace(/,/g, ''); el.dataset.suffix = m[2] || ''; io.observe(el); }
    });
  }
  function countUp(el) {
    if (el.dataset.counted || el.closest('.ring-wrap')) return;
    el.dataset.counted = '1';
    const end = +el.dataset.count, suffix = el.dataset.suffix || '', t0 = performance.now(), dur = 900;
    if (!end) return;
    let last = el.textContent;
    const step = now => {
      if (el.textContent !== last) return;  // the page updated the number itself: stop
      const p = Math.min(1, (now - t0) / dur), eased = 1 - Math.pow(1 - p, 3);
      last = el.textContent = (el.classList.contains('rr-pts') ? '+' : '') + Math.round(end * eased).toLocaleString() + suffix;
      if (p < 1) requestAnimationFrame(step);
      else last = el.textContent = (el.classList.contains('rr-pts') ? '+' : '') + end.toLocaleString() + suffix;
    };
    requestAnimationFrame(step);
  }
  function scan(scope) {
    markCounts(scope);
    const items = scope.matches && scope.matches(REVEAL) ? [scope] : [];
    items.push(...scope.querySelectorAll(REVEAL));
    let i = 0;
    items.forEach(el => {
      if (seen.has(el)) return;
      seen.add(el);
      el.classList.add('reveal');
      el.style.setProperty('--d', Math.min(i++, 8) * 60 + 'ms');
      io.observe(el);
    });
  }
  const start = () => {
    scan(document.body);
    new MutationObserver(muts => muts.forEach(m => m.addedNodes.forEach(n => { if (n.nodeType === 1) scan(n); })))
      .observe(document.body, {childList: true, subtree: true});
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
