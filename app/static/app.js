/* PhishLens interactive UI — report rendering, scan progress, toasts, guided tour, checklist. No frameworks. */

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
    btn.textContent = 'Copied ✓'; btn.classList.add('ok');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('ok'); }, 1600);
  } else {
    toast('Copied to clipboard ✓');
  }
}

/* ---------------- scan progress (generic phases — no internals) ---------------- */
function runScanProgress(wrapId, phaseId, fillId) {
  const wrap = document.getElementById(wrapId);
  const phaseEl = document.getElementById(phaseId);
  const fill = document.getElementById(fillId);
  const phases = [
    'Resolving domain…',
    'Collecting public records…',
    'Evaluating configuration…',
    'Compiling your report…'
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
  const map = { pass: '✓ pass', warn: '! warning', fail: '✗ fail' };
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
  const link = rep.url ? ` <a href="${escapeHtml(rep.url)}" target="_blank" rel="noopener noreferrer">View on VirusTotal ↗</a>` : '';
  if (!rep.known) return `<div class="rep-badge rep-unknown">◌ Not yet analysed by VirusTotal${link}</div>`;
  const flagged = (rep.malicious || 0) + (rep.suspicious || 0);
  const cls = rep.malicious ? 'rep-bad' : rep.suspicious ? 'rep-warn' : 'rep-good';
  const icon = rep.malicious ? '✗' : rep.suspicious ? '!' : '✓';
  return `<div class="rep-badge ${cls}">${icon} Flagged by ${flagged}/${rep.total || 0} security vendors${link}</div>`;
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
    ? `Score unchanged at ${t.to_score} since ${fmtDate(t.since)}`
    : `Your score went from ${t.from_score} to ${t.to_score} since ${fmtDate(t.since)}`;
  return `<div class="trend ${cls}">${t.delta > 0 ? '▲' : t.delta < 0 ? '▼' : '■'} ${escapeHtml(text)}
    ${sparkline(history.points)}</div>`;
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
      <p><a class="btn" href="${escapeHtml(rec.cta.href)}">${escapeHtml(rec.cta.label)}</a>
      <span class="muted">${escapeHtml(rec.contact || '')}</span></p>
    </div>`).join('');

  const planHtml = plan.length
    ? `<div class="plan"><h3>🎯 Fix these first — biggest grade gains</h3><ol>` +
      plan.map(p => `<li><strong>${escapeHtml(p.check)}</strong> <span class="pts">+${p.points} pts</span>
        <span class="fixline"><code>${escapeHtml(p.fix)}</code>
        <button class="copy-btn" data-copy="${escapeHtml(p.fix)}">Copy</button></span></li>`).join('') +
      `</ol></div>`
    : `<div class="plan good"><h3>✓ Nothing urgent — this domain is in great shape.</h3></div>`;

  const checksHtml = checks.map((c, i) => `
    <details class="check ${c.status}" style="animation-delay:${Math.min(0.35 + i * 0.05, 1.2).toFixed(2)}s">
      <summary>${statusBadge(c.status)} <strong>${escapeHtml(c.title)}</strong>
        <span class="pts">${c.score}/${c.max_score}</span>
        <span class="chev">▾</span></summary>
      ${c.details ? `<p class="details">${escapeHtml(c.details)}</p>` : ''}
      ${(c.issues || []).map(x => `<p class="issue">• ${escapeHtml(x)}</p>`).join('')}
      ${(c.fixes || []).map(f => `<p class="fix"><code>${escapeHtml(f)}</code>
        <button class="copy-btn" data-copy="${escapeHtml(f)}">Copy</button></p>`).join('')}
    </details>`).join('');

  return `
  <div class="report">
    <div class="scorehead">
      ${scoreRing(r.score)}
      <div>
        <h2>${escapeHtml(r.domain)}</h2>
        <p class="muted">Scanned ${escapeHtml(r.scanned_at || 'just now')}</p>
        <div class="grade-line">
          <span class="grade ${gradeClass(r.score)}">Grade ${escapeHtml(r.grade)}</span>
          <span class="muted small">${issues} failing · ${warnings} warnings</span>
          ${opts.pdfUrl ? `<a class="btn tiny ghost pdf-btn" href="${escapeHtml(opts.pdfUrl)}" download>⤓ Download PDF</a>` : ''}
        </div>
        ${trendLine(scan.history)}
        ${reputationBadge(r.reputation)}
      </div>
    </div>
    ${planHtml}
    ${recHtml}
    <h3 class="findings-title">Findings</h3>
    ${checksHtml}
    ${isPublic ? `<p class="upsell">Want drift alerts and history for your domains? <a href="/signup">Create a free account →</a></p>` : ''}
  </div>`;
}

/* Wire up copy buttons + animate ring + count-up after injecting report HTML. */
function bindReportInteractions(container) {
  container.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      copyText(btn.getAttribute('data-copy'), btn);
    });
  });
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
        <button class="btn ghost tiny tour-skip">Skip tour</button>
        <span style="flex:1"></span>
        <button class="btn ghost tiny tour-back">← Back</button>
        <button class="btn tiny tour-next">Next →</button>
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
      overlay.querySelector('.tour-step').textContent = `Step ${idx + 1} of ${steps.length}`;
      overlay.querySelector('.tour-title').textContent = step.title;
      overlay.querySelector('.tour-text').textContent = step.text;
      overlay.querySelector('.tour-back').style.visibility = idx === 0 ? 'hidden' : 'visible';
      overlay.querySelector('.tour-next').textContent = idx === steps.length - 1 ? 'Finish ✓' : 'Next →';
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
      <h2><span class="dot"></span> Getting started</h2>
      <span class="muted small">${done} of ${steps.length} complete</span>
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
    ${done === steps.length ? '<p class="all-done">🎉 All set — your domain security is on autopilot.</p>' : ''}`;
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
  if (!vals.length) return { num: '—', cls: 'kpi-blue', sub: 'Run a scan to set a baseline' };
  const avg = Math.round(vals.reduce((a, b) => a + b, 0) / vals.length);
  const cls = avg >= 80 ? 'kpi-green' : avg >= 60 ? 'kpi-amber' : 'kpi-red';
  const sub = avg >= 80 ? 'Strong posture — keep monitoring' : avg >= 60 ? 'Room to improve — see action plan' : 'Critical gaps — act on the plan';
  return { num: avg, cls, sub };
}

function renderKpis(container, { monitors = [], alerts = [], scans = [] } = {}) {
  const avg = avgScoreTile(scans, monitors);
  const tiles = [
    { cls: 'kpi-blue', glyph: '◈', num: monitors.length, label: 'Domains monitored', sub: monitors.length ? 'Under continuous watch' : 'Add your first below', animate: true },
    { cls: avg.cls, glyph: '✦', num: avg.num, label: 'Average score', sub: avg.sub, animate: typeof avg.num === 'number' },
    { cls: alerts.length ? 'kpi-red' : 'kpi-green', glyph: alerts.length ? '⚠' : '✓', num: alerts.length, label: 'Open alerts', sub: alerts.length ? 'Needs your attention' : 'All quiet', animate: true, pulse: alerts.length > 0 },
    { cls: 'kpi-violet', glyph: '◐', num: scans.length, label: 'Scans run', sub: scans.length === 1 ? '1 scan completed' : `${scans.length} scans completed`, animate: true },
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
