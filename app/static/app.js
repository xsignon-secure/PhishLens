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

const GRADE_COLORS = { gA: '#34d399', gB: '#60a5fa', gC: '#fbbf24', gD: '#fb923c', gF: '#f87171' };

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
        stroke="${color}"
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
    <polyline fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" points="${xy.join(' ')}"/>
    <circle cx="${xy[xy.length - 1].split(',')[0]}" cy="${xy[xy.length - 1].split(',')[1]}" r="2.5" fill="${color}"/></svg>`;
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

function observationsTable(checks) {
  const rank = {high: 0, medium: 1, low: 2};
  const rows = checks.filter(c => c.status === 'fail' || c.status === 'warn')
    .map(c => ({c, sev: severityFor(c)}))
    .sort((a, b) => rank[a.sev] - rank[b.sev]);
  if (!rows.length) return '';
  const label = {high: _t('High'), medium: _t('Medium'), low: _t('Low')};
  return `<div class="observations"><h3>${_t('Observations')}</h3>
    <div class="table-wrap"><table>
    <thead><tr><th>${_t('Risk')}</th><th>${_t('Severity')}</th><th>${_t('Impact')}</th><th>${_t('Fix')}</th></tr></thead>
    <tbody>${rows.map(({c, sev}) => `<tr>
      <td><strong>${escapeHtml(c.title)}</strong>${(c.issues || [])[0] ? `<br><span class="muted small">${escapeHtml(c.issues[0])}</span>` : ''}</td>
      <td><span class="sev ${sev}">${label[sev]}</span></td>
      <td>${CHECK_IMPACT[c.key] ? escapeHtml(_t(CHECK_IMPACT[c.key])) : '<span class="muted">—</span>'}</td>
      <td>${escapeHtml((c.fixes || [])[0] || '')}</td></tr>`).join('')}</tbody>
    </table></div></div>`;
}

function dnssecParts(checks) {
  const c = checks.find(x => x.key === 'dnssec');
  if (!c || c.signed_at_nameservers === undefined) return '';
  const yes = `<span class="badge pass">${_t('Enabled')}</span>`;
  const no = `<span class="badge warn">${_t('Disabled')}</span>`;
  return `<p class="details">${_t('Signed at nameservers')}: ${c.signed_at_nameservers ? yes : no}
    · ${_t('DS record at registrar')}: ${c.ds_at_registrar ? yes : no}</p>`;
}

function renderReport(scan, isPublic, opts = {}) {
  const r = scan.result || scan;
  const checks = r.checks || [];
  const plan = r.action_plan || [];
  const recs = r.recommendations || [];
  const issues = checks.filter(c => c.status === 'fail').length;
  const warnings = checks.filter(c => c.status === 'warn').length;

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
  const planHtml = plan.length
    ? `<div class="plan"><h3>${_t('🎯 Fix these first — biggest grade gains')}</h3>
      ${hasGuides ? providerPicker(pk, detected) : ''}` +
      plan.map((p, i) => {
        const c = checks.find(x => x.title === p.check) || {title: p.check, status: 'fail'};
        return p.guide ? fixCard(p.guide, c, p.points, r.domain, pk, opts, i + 1)
          : `<ol start="${i + 1}"><li><strong>${escapeHtml(p.check)}</strong> <span class="pts">${_t('+{0} pts', {0: p.points})}</span>
        <span class="fixline"><code>${escapeHtml(p.fix)}</code>
        <button class="copy-btn" data-copy="${escapeHtml(p.fix)}">${_t('Copy')}</button>${applyButton(p.fix, opts)}</span></li></ol>`;
      }).join('') + `</div>`
    : `<div class="plan good"><h3>${_t('✓ Nothing urgent — this domain is in great shape.')}</h3></div>`;

  const checksHtml = checks.map((c, i) => `
    <details class="check ${c.status}" style="animation-delay:${Math.min(0.35 + i * 0.05, 1.2).toFixed(2)}s">
      <summary>${statusBadge(c.status)} <strong>${escapeHtml(c.title)}</strong>
        <span class="pts">${c.score}/${c.max_score}</span>
        <span class="chev">▾</span></summary>
      ${c.details ? `<p class="details">${escapeHtml(c.details)}</p>` : ''}
      ${c.key === 'dnssec' ? dnssecParts(checks) : ''}
      ${(c.issues || []).map(x => `<p class="issue">• ${escapeHtml(x)}</p>`).join('')}
      ${c.guide && planned[c.title] ? `<p class="fix-see"><a href="#fix-${escapeHtml(c.key)}">${_t('How to fix: see step {0} above ↑', {0: planned[c.title]})}</a></p>`
        : c.guide ? `<div class="fix-in-check">${fixCard(c.guide, c, c.max_score - c.score, r.domain, pk, opts, 0)}</div>`
        : (c.fixes || []).map(f => `<p class="fix"><code>${escapeHtml(f)}</code>
        <button class="copy-btn" data-copy="${escapeHtml(f)}">${_t('Copy')}</button>${applyButton(f, opts)}</p>`).join('')}
    </details>`).join('');

  return `
  <div class="report">
    <div class="scorehead">
      ${scoreRing(r.score)}
      <div>
        <h2>${escapeHtml(r.domain)}</h2>
        <p class="muted">${_t('Scanned {0}', {0: escapeHtml(r.scanned_at || _t('just now'))})}</p>
        <div class="grade-line">
          <span class="grade ${gradeClass(r.score)}">${_t('Grade {0}', {0: escapeHtml(r.grade)})}</span>
          <span class="muted small">${_t('{0} failing · {1} warnings', {0: issues, 1: warnings})}</span>
          ${opts.pdfUrl ? `<a class="btn tiny ghost pdf-btn" href="${escapeHtml(opts.pdfUrl)}" download>${_t('⤓ Download PDF')}</a>` : ''}
          ${opts.emailUrl ? `<button class="btn tiny ghost" data-email-report="${escapeHtml(opts.emailUrl)}">${_t('✉ Email me this report')}</button>` : ''}
        </div>
        ${trendLine(scan.history)}
        ${reputationBadge(r.reputation)}
      </div>
    </div>
    ${observationsTable(checks)}
    ${planHtml}
    ${recHtml}
    <h3 class="findings-title">${_t('Findings')}</h3>
    ${hasGuides && !plan.some(p => p.guide) ? providerPicker(pk, detected) : ''}
    ${checksHtml}
    ${isPublic ? `<p class="upsell">${_t('Want drift alerts and history for your domains?')} <a href="/signup">${_t('Create a free account →')}</a></p>` : ''}
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
      const see = e.target.closest('.fix-see a');
      if (see) {
        e.preventDefault();
        const el = container.querySelector(see.getAttribute('href'));
        if (el) el.scrollIntoView({behavior: 'smooth', block: 'start'});
      }
    });
  }
  bindFixCards(container);
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
    ${done === steps.length ? ('<p class="all-done">' + _t('🎉 All set — your domain security is on autopilot.') + '</p>') : ''}`;
  container.querySelectorAll('.checklist-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = btn.getAttribute('data-target');
      if (t) {
        const el = document.querySelector(t);
        if (el) el.scrollIntoView({behavior: 'smooth', block: 'center'});
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
    { cls: 'kpi-blue', glyph: '◈', num: monitors.length, label: _t('Domains monitored'), sub: monitors.length ? _t('Under continuous watch') : _t('Add your first below'), animate: true },
    { cls: avg.cls, glyph: '✦', num: avg.num, label: _t('Average score'), sub: avg.sub, animate: typeof avg.num === 'number' },
    { cls: alerts.length ? 'kpi-red' : 'kpi-green', glyph: alerts.length ? '⚠' : '✓', num: alerts.length, label: _t('Open alerts'), sub: alerts.length ? _t('Needs your attention') : _t('All quiet'), animate: true, pulse: alerts.length > 0 },
    { cls: 'kpi-violet', glyph: '◐', num: scans.length, label: _t('Scans run'), sub: scans.length === 1 ? _t('1 scan completed') : _t('{0} scans completed', {0: scans.length}), animate: true },
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
