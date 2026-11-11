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
};
const LOW_SEVERITY = ['bimi', 'caa', 'ipv6', 'sec-headers', 'rpki', 'ptr', 'dane', 'tls-rpt'];

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

function observationsTable(checks, locked) {
  const rank = {high: 0, medium: 1, low: 2};
  const rows = checks.filter(c => c.status === 'fail' || c.status === 'warn')
    .map(c => ({c, sev: severityFor(c)}))
    .sort((a, b) => rank[a.sev] - rank[b.sev]);
  if (!rows.length) return '';
  const label = {high: _t('High'), medium: _t('Medium'), low: _t('Low')};
  return `<section class="observations rpt-sec"><div class="sec-head"><h3>${_t('Top risks')}</h3><p>${_t('What an attacker could do today, most serious first.')}</p></div>
    <div class="table-wrap"><table>
    <thead><tr><th>${_t('Risk')}</th><th>${_t('Severity')}</th><th>${_t('Impact')}</th>${locked ? '' : `<th>${_t('Fix')}</th>`}</tr></thead>
    <tbody>${rows.map(({c, sev}) => `<tr>
      <td><strong>${escapeHtml(c.title)}</strong>${(c.issues || [])[0] ? `<br><span class="muted small">${escapeHtml(c.issues[0])}</span>` : ''}</td>
      <td><span class="sev ${sev}">${label[sev]}</span></td>
      <td>${CHECK_IMPACT[c.key] ? escapeHtml(_t(CHECK_IMPACT[c.key])) : '<span class="muted">—</span>'}</td>
      ${locked ? '' : `<td>${escapeHtml((c.fixes || [])[0] || '')}</td>`}</tr>`).join('')}</tbody>
    </table></div></section>`;
}

/* Gmail / Yahoo / Microsoft sender requirements, from compliance.py. */
function complianceCard(list) {
  if (!list || !list.length) return '';
  const icon = {pass: '✓', fail: '✗', warn: '!', manual: '?'};
  const label = {pass: _t('Meets'), fail: _t('Fails'), warn: _t('Partly')};
  return `<section class="compliance rpt-sec"><div class="sec-head"><h3>${_t('Mailbox provider requirements')}</h3><p>${_t('Rules Gmail, Yahoo and Microsoft apply to senders.')}</p></div>
    <div class="compliance-grid">${list.map(p => `
      <details class="compliance-col ${p.status}">
        <summary><strong>${escapeHtml(p.name)}</strong>
          <span class="badge ${p.status}">${label[p.status] || ''}</span>
          <span class="muted small">${_t('{0}/{1} checked rules pass', {0: p.passed, 1: p.checked})}</span></summary>
        <p class="muted small">${escapeHtml(p.note)}</p>
        <ul>${p.rules.map(r => `<li class="rule ${r.status}"><span class="ri">${icon[r.status]}</span> ${escapeHtml(r.label)}${r.status === 'manual' ? ` <span class="muted small">(${_t('not visible in DNS: check it yourself')})</span>` : ''}</li>`).join('')}</ul>
      </details>`).join('')}</div></section>`;
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
  mx: 'dns', dnssec: 'dns', caa: 'dns', ptr: 'dns', ipv6: 'dns', rpki: 'dns', parked: 'dns',
  dnsbl: 'reputation', 'tls-cert': 'web', 'sec-headers': 'web',
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

function categoryCards(checks) {
  return CATEGORIES.map(cat => {
    const cs = checks.filter(c => (CHECK_CATEGORY[c.key] || 'dns') === cat.key);
    if (!cs.length) return '';
    const earned = cs.reduce((a, c) => a + (c.score || 0), 0);
    const max = cs.reduce((a, c) => a + (c.max_score || 0), 0);
    const pct = max ? Math.round(100 * earned / max) : null;
    const fails = cs.filter(c => c.status === 'fail').length, warns = cs.filter(c => c.status === 'warn').length;
    const tone = pct === null ? 'na' : pct >= 80 ? 'good' : pct >= 50 ? 'mid' : 'bad';
    return `<div class="cat-card ${tone}">
      <div class="cat-top"><span class="cat-name">${_t(cat.label)}</span><span class="cat-pct">${pct === null ? '—' : pct + '%'}</span></div>
      <div class="cat-bar"><span style="width:${pct || 0}%"></span></div>
      <div class="cat-meta">${_t(cat.blurb)}</div>
      <div class="cat-counts">${fails ? `<span class="dotc fail">${_t('{0} failing', {0: fails})}</span>` : ''}${warns ? `<span class="dotc warn">${_t('{0} warnings', {0: warns})}</span>` : ''}${!fails && !warns ? `<span class="dotc pass">${_t('All passed')}</span>` : ''}</div>
    </div>`;
  }).join('');
}

function protocolStrip(checks) {
  const icon = {pass: '✓', warn: '!', fail: '✕'};
  return KEY_PROTOCOLS.map(k => checks.find(c => c.key === k)).filter(Boolean).map(c =>
    `<a class="proto ${c.status}" href="#chk-${escapeHtml(c.key)}"><span class="proto-ico">${icon[c.status] || '·'}</span>${escapeHtml(c.title)}</a>`).join('');
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
  const rankList = plan.length ? `<ol class="risk-rank">${plan.map((p, i) => `<li>
      <span class="rr-n">${i + 1}</span><strong>${escapeHtml(p.check)}</strong>
      <span class="rr-pts">${_t('+{0} pts', {0: p.points})}</span>
      ${locked ? `<span class="rr-lock">${ICONS.lock}</span>` : ''}</li>`).join('')}</ol>` : '';
  const planHead = `<div class="sec-head"><h3>${_t('Remediation priorities')}</h3><p>${_t('Ranked by how much each item raises your score.')}</p></div>`;
  const planHtml = locked
    ? (plan.length || lockHtml ? `<section class="rpt-sec">${planHead}<div class="plan locked-plan">${rankList}${lockHtml}</div></section>` : goodHtml)
    : plan.length
    ? `<section class="rpt-sec">${planHead}<div class="plan">
      ${hasGuides ? providerPicker(pk, detected) : ''}` +
      plan.map((p, i) => {
        const c = checks.find(x => x.title === p.check) || {title: p.check, status: 'fail'};
        return p.guide ? fixCard(p.guide, c, p.points, r.domain, pk, opts, i + 1)
          : `<ol start="${i + 1}"><li><strong>${escapeHtml(p.check)}</strong> <span class="pts">${_t('+{0} pts', {0: p.points})}</span>
        <span class="fixline"><code>${escapeHtml(p.fix)}</code>
        <button class="copy-btn" data-copy="${escapeHtml(p.fix)}">${_t('Copy')}</button>${applyButton(p.fix, opts)}</span></li></ol>`;
      }).join('') + `</div></section>`
    : goodHtml;

  const rank = {fail: 0, warn: 1, pass: 2};
  const checkRow = (c, i) => `
    <details class="check ${c.status}" id="chk-${escapeHtml(c.key)}" style="animation-delay:${Math.min(0.15 + i * 0.02, 0.6).toFixed(2)}s">
      <summary>${statusBadge(c.status)} <strong>${escapeHtml(c.title)}</strong>
        ${c.status !== 'pass' ? `<span class="sev ${severityFor(c)}">${({high: _t('High'), medium: _t('Medium'), low: _t('Low')})[severityFor(c)]}</span>` : ''}
        <span class="pts">${c.score}/${c.max_score}</span>
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
  let n = 0;
  const groupsHtml = CATEGORIES.map(cat => {
    const cs = checks.filter(c => (CHECK_CATEGORY[c.key] || 'dns') === cat.key)
      .sort((a, b) => (rank[a.status] ?? 3) - (rank[b.status] ?? 3));
    if (!cs.length) return '';
    return `<p class="findings-group">${_t(cat.label)} · ${cs.length}</p>` + cs.map(c => checkRow(c, n++)).join('');
  }).join('');

  const scanned = r.scanned_at ? new Date(r.scanned_at) : null;
  const scannedText = scanned && !isNaN(scanned)
    ? scanned.toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'}) : _t('just now');
  const risk = riskLevel(r.score);
  const verdict = verdictFor(r, checks);
  const reportId = scan.id ? String(scan.id).slice(0, 8).toUpperCase() : '';

  return `
  <div class="report rpt">
    <header class="rpt-head">
      <div>
        <span class="rpt-kicker">${_t('Email security report')}</span>
        <h2>${escapeHtml(r.domain)}</h2>
        <p class="rpt-meta">${_t('Scanned {0}', {0: escapeHtml(scannedText)})}${reportId ? ` · ${_t('Report')} ${escapeHtml(reportId)}` : ''}</p>
      </div>
      <div class="report-actions">
        ${opts.pdfUrl ? `<a class="btn tiny ghost pdf-btn" href="${escapeHtml(opts.pdfUrl)}" download>${ICONS.download}${_t('Download PDF')}</a>` : ''}
        ${opts.guideUrl && !locked ? `<a class="btn tiny ghost pdf-btn" href="${escapeHtml(opts.guideUrl)}" download>${ICONS.download}${_t('Fix guide (PDF)')}</a>` : ''}
        ${opts.emailUrl ? `<button class="btn tiny ghost" data-email-report="${escapeHtml(opts.emailUrl)}">${ICONS.mail}${_t('Email me this report')}</button>` : ''}
      </div>
    </header>
    <section class="rpt-summary">
      <div class="scorehead">
        ${scoreRing(r.score)}
        <div class="grade-col">
          <span class="grade big ${gradeClass(r.score)}">${escapeHtml(r.grade)}</span>
          <span class="muted small">${_t('Grade')}</span>
        </div>
      </div>
      <div class="verdict">
        <span class="risk-badge ${risk.cls}">${risk.label}</span>
        <h3>${verdict.head}</h3>
        <p>${escapeHtml(verdict.sub)}</p>
        ${trendLine(scan.history)}
        ${reputationBadge(r.reputation)}
      </div>
      <div class="sum-stats">
        <div class="stat fail"><b>${issues}</b><span>${_t('Failing')}</span></div>
        <div class="stat warn"><b>${warnings}</b><span>${_t('Warnings')}</span></div>
        <div class="stat pass"><b>${passedN}</b><span>${_t('Passed')}</span></div>
        <div class="stat"><b>${checks.length}</b><span>${_t('Checks run')}</span></div>
      </div>
    </section>
    <nav class="proto-strip" aria-label="${_t('Key protocols')}">${protocolStrip(checks)}</nav>
    <section class="rpt-sec">
      <div class="sec-head"><h3>${_t('Score by category')}</h3></div>
      <div class="cat-grid">${categoryCards(checks)}</div>
    </section>
    ${observationsTable(checks, locked)}
    ${complianceCard(r.compliance)}
    ${planHtml}
    ${recHtml}
    <section class="rpt-sec">
      <div class="sec-head"><h3>${_t('Detailed findings')}</h3><p>${_t('Every check, grouped by area. Open a row for the details.')}</p></div>
      ${hasGuides && !plan.some(p => p.guide) ? providerPicker(pk, detected) : ''}
      ${groupsHtml}
    </section>
    <footer class="rpt-foot">${_t('Read-only scan of public DNS, mail and web records. Results reflect the moment of the scan.')}</footer>
  </div>`;
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
      const see = e.target.closest('.fix-see a, .fix-locked a');
      if (see) {
        e.preventDefault();
        const el = container.querySelector(see.getAttribute('href'));
        if (el) { if (window.revealSection) revealSection(el); el.scrollIntoView({behavior: 'smooth', block: 'start'}); }
      }
    });
  }
  bindFixCards(container);
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
    const t0 = performance.now(), dur = 1400;
    (function countUp(t) {
      const k = Math.min((t - t0) / dur, 1);
      const eased = 1 - Math.pow(1 - k, 3);
      num.textContent = Math.round(target * eased);
      if (k < 1) requestAnimationFrame(countUp);
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
