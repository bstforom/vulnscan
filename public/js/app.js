// public/js/app.js — frontend logic

const SEV_LABEL = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info', UNKNOWN: 'Unknown' };
const SEV_COLOR = { CRITICAL: '#7c1d1d', HIGH: '#b91c1c', MEDIUM: '#c2770b', LOW: '#2563eb', INFO: '#475569', UNKNOWN: '#64748b' };

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---- Authentication (page guard) ----
let CSRF = '';
(async function bootstrap() {
  try {
    const res = await fetch('/api/auth/me');
    if (!res.ok) { location.href = '/login.html'; return; }
    const data = await res.json();
    CSRF = data.csrfToken;
    if (data.authDisabled) {
      $('#user-chip').textContent = '🖥️ Local mode';
      $('#btn-logout').style.display = 'none';
    } else {
      $('#user-chip').textContent = '👤 ' + data.user.username + (data.user.role === 'admin' ? ' (admin)' : '');
    }
    $('#topbar-title').textContent = 'Dashboard';
    loadOverview();
  } catch {
    location.href = '/login.html';
  }
})();

// ---- Dashboard ----
async function loadOverview() {
  try {
    const [statsRes, repRes] = await Promise.all([
      fetch('/api/cve/stats'),
      fetch('/api/reports'),
    ]);
    const stats = statsRes.ok ? await statsRes.json() : {};
    const repJson = repRes.ok ? await repRes.json() : {};
    const reps = repJson.reports || [];

    $('#kpi-cve').textContent = Number(stats.total || 0).toLocaleString('en');
    $('#kpi-kev').textContent = Number(stats.kev || 0).toLocaleString('en');
    $('#kpi-reports').textContent = Number(repJson.total ?? reps.length ?? 0).toLocaleString('en');
    const maxRisk = reps.reduce((m, r) => Math.max(m, r.riskScore || 0), 0);
    $('#kpi-risk').textContent = reps.length ? maxRisk : '—';

    const note = $('#ov-dbnote');
    if (note) {
      if ((stats.total || 0) < 5000) {
        note.innerHTML = '💡 To build the full database (100k+) run <code>npm run import</code> once.';
      } else {
        note.innerHTML = `✅ The database holds ${Number(stats.total).toLocaleString('en')} CVEs · ${Number(stats.cpeRows || 0).toLocaleString('en')} CPE match rows.`;
      }
    }

    const mount = $('#ov-reports');
    if (!reps.length) {
      mount.innerHTML = '<div class="muted">No reports yet. Start your first scan.</div>';
    } else {
      mount.innerHTML = reps.slice(0, 5).map((r) => `
        <a class="ov-report" href="${r.html}" target="_blank">
          <span class="ov-risk ${r.riskScore >= 60 ? 'hi' : r.riskScore >= 30 ? 'mid' : 'lo'}">${r.riskScore}</span>
          <span class="ov-subj">${esc(r.subject)}</span>
          <span class="ov-meta">${r.kind === 'target' ? 'Target' : 'File'} · ${r.findingsCount} findings</span>
        </a>`).join('');
    }
  } catch { /* ignore */ }
}

document.querySelectorAll('.quick-btn').forEach((b) => b.addEventListener('click', () => gotoTab(b.dataset.goto)));
document.getElementById('ov-all-reports')?.addEventListener('click', () => gotoTab('reports'));

$('#btn-logout').addEventListener('click', async () => {
  try {
    await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': CSRF } });
  } catch { /* ignore */ }
  location.href = '/login.html';
});

const TAB_TITLES = { overview: 'Dashboard', target: 'Scan Target', file: 'Scan File', cve: 'CVE Database', reports: 'Reports', schedules: 'Schedules' };

function gotoTab(name) {
  const btn = document.querySelector(`.nav-btn[data-tab="${name}"]`);
  if (btn) btn.click();
}

// ---- Tabs ----
document.querySelectorAll('.nav-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    btn.classList.add('active');
    $('#tab-' + btn.dataset.tab).classList.add('active');
    $('#topbar-title').textContent = TAB_TITLES[btn.dataset.tab] || 'Dashboard';
    if (btn.dataset.tab === 'overview') loadOverview();
    if (btn.dataset.tab === 'cve') loadCVEs();
    if (btn.dataset.tab === 'reports') loadReports();
    if (btn.dataset.tab === 'schedules') loadSchedules();
  });
});

// ---- Authorization gates ----
$('#auth-target').addEventListener('change', (e) => { $('#btn-scan-target').disabled = !e.target.checked; });
$('#auth-file').addEventListener('change', updateFileBtn);

// ---- Shared report rendering ----
function renderReport(data, mount) {
  const r = data.report;
  const scoreColor = r.riskScore >= 60 ? '#f87171' : r.riskScore >= 30 ? '#fbbf24' : '#4ade80';
  const pills = Object.entries(r.summary).filter(([, n]) => n > 0)
    .map(([s, n]) => `<span class="pill" style="background:${SEV_COLOR[s]}">${SEV_LABEL[s]}: ${n}</span>`).join('');

  let metaHtml = '';
  if (r.kind === 'target') {
    const techs = (r.meta.technologies || []).map((t) => `<span class="tech">${esc(t.name)}${t.version ? ' ' + esc(t.version) : ''}</span>`).join(' ') || '<span class="muted">No technologies detected</span>';
    metaHtml = `<div class="meta-row">
      <span class="chip">IP: ${esc(r.meta.ip || '—')}</span>
      <span class="chip">Server: ${esc(r.meta.server || '—')}</span>
      ${r.meta.title ? `<span class="chip">Title: ${esc(r.meta.title)}</span>` : ''}
      ${(r.meta.waf && r.meta.waf.length) ? `<span class="chip">🛡️ WAF: ${esc(r.meta.waf.join(', '))}</span>` : ''}
    </div><div class="meta-row" style="margin-top:8px">${techs}</div>`;
  } else {
    metaHtml = `<div class="meta-row">
      <span class="chip">Size: ${(r.meta.size / 1024).toFixed(1)} KB</span>
      <span class="chip">Type: ${esc(r.meta.manifest || r.meta.fileType || '—')}</span>
      ${r.meta.dependencies ? `<span class="chip">Dependencies: ${r.meta.dependencies}</span>` : ''}
      <span class="chip" style="font-family:monospace">SHA256: ${esc((r.meta.sha256 || '').slice(0, 16))}…</span>
    </div>`;
  }

  const findings = r.findings.map((f) => `
    <div class="finding ${f.severity}">
      <div class="finding-head">
        <span class="finding-title">${esc(f.title)}${f.cve ? ` <a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" style="color:#93c5fd">↗</a>` : ''}</span>
        <span class="sev-tag ${f.severity}">${SEV_LABEL[f.severity]}</span>
      </div>
      <div class="finding-detail">${esc(f.detail)}</div>
      ${f.evidence ? `<div class="finding-ev">${esc(f.evidence)}</div>` : ''}
      ${(f.cwe || f.owasp) ? `<div class="finding-tags">${f.owasp ? `<span class="tag-owasp">${esc(f.owasp)}</span>` : ''}${f.cwe ? `<a class="tag-cwe" href="https://cwe.mitre.org/data/definitions/${esc(String(f.cwe).replace('CWE-',''))}.html" target="_blank">${esc(f.cwe)}</a>` : ''}</div>` : ''}
    </div>`).join('');

  const errs = (r.errors && r.errors.length) ? `<div class="auth-box" style="margin-top:14px">⚠️ Notes: ${r.errors.map(esc).join(' · ')}</div>` : '';

  mount.innerHTML = `
    <div class="score-card">
      <div style="text-align:center">
        <div class="score-num" style="color:${scoreColor}">${r.riskScore}</div>
        <div class="muted">Risk score /100</div>
      </div>
      <div style="flex:1">
        <div class="pills">${pills || '<span class="muted">No findings</span>'}</div>
        ${metaHtml}
      </div>
    </div>
    <div style="margin-bottom:12px">
      <a class="report-link" href="${data.saved.html}" target="_blank">📄 Open report (HTML)</a>
      <a class="report-link ghost" href="${data.saved.json}" target="_blank">⬇️ JSON</a>
      ${data.saved.sarif ? `<a class="report-link ghost" href="${data.saved.sarif}" target="_blank">⬇️ SARIF</a>` : ''}
      <span class="muted" style="margin-left:8px">Report ID: ${esc(r.id)}</span>
    </div>
    <h3 style="margin:16px 0 10px">Findings (${r.findingsCount})</h3>
    ${findings || '<div class="muted">No findings detected.</div>'}
    ${errs}`;
}

// ---- Target scan (single / authenticated / bulk) ----
function parseHeaders(text) {
  const h = {};
  for (const line of (text || '').split('\n')) {
    const i = line.indexOf(':');
    if (i > 0) { const k = line.slice(0, i).trim(); const v = line.slice(i + 1).trim(); if (k && v) h[k] = v; }
  }
  return h;
}

const LOG_ICON = { start: '🚀', dns: '🌐', http: '📡', headers: '🧾', waf: '🛡️', tech: '🔧', tls: '🔒', deep: '🔎', check: '✓', cve: '🧬', done: '✅', error: '⚠️', blocked: '⛔' };
function appendLog(box, e) {
  const div = document.createElement('div');
  div.className = 'log-line' + (e.phase === 'error' || e.phase === 'blocked' ? ' err' : e.phase === 'done' ? ' ok' : '');
  const time = new Date(e.t || Date.now()).toLocaleTimeString('en', { hour12: false });
  div.innerHTML = `<span class="log-time">${time}</span> ${LOG_ICON[e.phase] || '•'} ${esc(e.message)}`;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

$('#btn-scan-target').addEventListener('click', async () => {
  const headers = parseHeaders($('#custom-headers').value);
  const bulk = $('#bulk-targets').value.split('\n').map((t) => t.trim()).filter(Boolean);
  const target = $('#target-input').value.trim();
  const status = $('#target-status');
  const result = $('#target-result');
  const allowPrivate = $('#allow-private').checked;
  result.innerHTML = '';
  $('#btn-scan-target').disabled = true;
  try {
    if (bulk.length) {
      // Bulk scan
      status.className = 'status loading';
      status.innerHTML = `Scanning ${bulk.length} targets... <span class="spinner"></span>`;
      const res = await fetch('/api/scan/targets', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
        body: JSON.stringify({ targets: bulk, authorized: true, allowPrivate, headers }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || data.error || 'Bulk scan failed');
      status.className = 'status ok';
      status.textContent = `✓ Scanned ${data.count} targets`;
      result.innerHTML = `<table class="rep"><thead><tr><th>Target</th><th>Risk</th><th>Findings</th><th>WAF</th><th></th></tr></thead><tbody>${
        data.results.map((r) => r.error
          ? `<tr><td style="max-width:240px;overflow:hidden;text-overflow:ellipsis">${esc(r.target)}</td><td colspan="4" class="status error">✗ ${esc(r.error)}</td></tr>`
          : `<tr><td style="max-width:240px;overflow:hidden;text-overflow:ellipsis">${esc(r.target)}</td><td style="color:${r.riskScore >= 60 ? '#f87171' : r.riskScore >= 30 ? '#fbbf24' : '#4ade80'}">${r.riskScore}</td><td>${r.findingsCount}</td><td class="muted">${esc((r.waf || []).join(', ') || '—')}</td><td><a href="${r.html}" target="_blank">Open ↗</a></td></tr>`
        ).join('')}</tbody></table>`;
    } else {
      // Single scan — stream the live log
      if (!target) { $('#btn-scan-target').disabled = false; return; }
      status.className = 'status loading';
      status.innerHTML = 'Scanning... <span class="spinner"></span>';
      const logBox = $('#scan-log');
      logBox.hidden = false;
      logBox.innerHTML = '';
      const res = await fetch('/api/scan/target/stream', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
        body: JSON.stringify({ target, authorized: true, allowPrivate, headers }),
      });
      if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || d.message || 'Scan failed'); }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '', finalData = null, errMsg = null;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
          if (!line) continue;
          let obj; try { obj = JSON.parse(line); } catch { continue; }
          if (obj.type === 'log') appendLog(logBox, obj);
          else if (obj.type === 'result') finalData = obj;
          else if (obj.type === 'error') errMsg = obj.message;
        }
      }
      if (errMsg) throw new Error(errMsg);
      if (!finalData) throw new Error('Scan ended without a result');
      status.className = 'status ok';
      status.textContent = '✓ Scan complete' + (finalData.scan?.authenticated ? ' (authenticated)' : '');
      renderReport(finalData, result);
    }
  } catch (e) {
    status.className = 'status error';
    status.textContent = '✗ ' + e.message;
  } finally {
    $('#btn-scan-target').disabled = false;
  }
});
$('#target-input').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !$('#btn-scan-target').disabled) $('#btn-scan-target').click(); });

// ---- Subdomain discovery ----
$('#btn-discover').addEventListener('click', async () => {
  const domain = $('#subdomain-input').value.trim();
  if (!domain) return;
  const out = $('#subdomain-result');
  out.innerHTML = '<div class="status loading">Searching certificate transparency logs <span class="spinner"></span></div>';
  try {
    const res = await fetch('/api/discover/subdomains?domain=' + encodeURIComponent(domain));
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || data.error || 'Discovery failed');
    if (!data.subdomains.length) { out.innerHTML = '<div class="muted">No subdomains found.</div>'; return; }
    out.innerHTML = `<div class="muted" style="margin:8px 0">Found ${data.count} subdomains (click to load into the target field):</div>` +
      '<div class="sub-list">' + data.subdomains.map((s) => `<button class="sub-chip" data-sub="${esc(s)}">${esc(s)}</button>`).join('') + '</div>';
    out.querySelectorAll('[data-sub]').forEach((b) => b.addEventListener('click', () => {
      $('#target-input').value = b.dataset.sub;
      $('#target-input').scrollIntoView({ behavior: 'smooth', block: 'center' });
    }));
  } catch (e) {
    out.innerHTML = '<div class="status error">✗ ' + e.message + '</div>';
  }
});
$('#subdomain-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#btn-discover').click(); });

// ---- File scan ----
let selectedFile = null;
const drop = $('#drop');
$('#pick-file').addEventListener('click', (e) => { e.stopPropagation(); $('#file-input').click(); });
drop.addEventListener('click', () => $('#file-input').click());
$('#file-input').addEventListener('change', (e) => setFile(e.target.files[0]));
['dragover', 'dragenter'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', (e) => setFile(e.dataTransfer.files[0]));

function setFile(f) {
  selectedFile = f || null;
  $('#file-name').textContent = f ? `${f.name} (${(f.size / 1024).toFixed(1)} KB)` : 'Maximum 15 MB';
  updateFileBtn();
}
function updateFileBtn() {
  $('#btn-scan-file').disabled = !(selectedFile && $('#auth-file').checked);
}

$('#btn-scan-file').addEventListener('click', async () => {
  if (!selectedFile) return;
  const status = $('#file-status');
  const result = $('#file-result');
  result.innerHTML = '';
  status.className = 'status loading';
  status.innerHTML = 'Analyzing the file and matching against the vulnerability database <span class="spinner"></span>';
  $('#btn-scan-file').disabled = true;
  try {
    const fd = new FormData();
    fd.append('file', selectedFile);
    fd.append('authorized', 'true');
    const res = await fetch('/api/scan/file', { method: 'POST', headers: { 'X-CSRF-Token': CSRF }, body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || data.error || 'Scan failed');
    status.className = 'status ok';
    status.textContent = '✓ File scan complete';
    renderReport(data, result);
  } catch (e) {
    status.className = 'status error';
    status.textContent = '✗ ' + e.message;
  } finally {
    updateFileBtn();
  }
});

// ---- CVE database ----
let cveLoaded = false;
async function loadCVEs(force = false) {
  const status = $('#cve-status');
  const list = $('#cve-list');
  if (cveLoaded && !force) return;
  status.className = 'status loading';
  status.innerHTML = 'Fetching from NVD <span class="spinner"></span>';
  try {
    const q = $('#cve-search').value.trim();
    const url = `/api/cve/latest?limit=150${q ? '&q=' + encodeURIComponent(q) : ''}${force ? '&refresh=1' : ''}`;
    const res = await fetch(url);
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || data.error);
    cveLoaded = true;
    const s = data.stats || {};
    const srcLabel = data.source === 'seed' ? 'initial seed (run full import)' : 'local database';
    status.className = 'status ok';
    status.innerHTML = `<strong>${Number(data.total).toLocaleString('en')}</strong> CVEs in database · ` +
      `🔴 <strong>${Number(s.kev || 0).toLocaleString('en')}</strong> actively exploited (KEV) · ` +
      `showing ${data.returned} · ${srcLabel}`;
    list.innerHTML = data.items.map((c) => `
      <div class="cve-item">
        <div class="cve-meta">
          <a class="cve-id" href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank">${esc(c.id)}</a>
          ${c.cvss.score != null ? `<span class="sev-tag ${c.cvss.severity}">CVSS ${c.cvss.score} · ${SEV_LABEL[c.cvss.severity] || c.cvss.severity}</span>` : ''}
          ${c.kev ? '<span class="sev-tag CRITICAL">🔴 KEV</span>' : ''}
          ${c.epss != null ? `<span class="chip">EPSS ${(c.epss * 100).toFixed(1)}%</span>` : ''}
          <span class="muted">${c.published ? new Date(c.published).toLocaleDateString('en') : ''}</span>
        </div>
        <div class="cve-desc">${esc((c.description || '').slice(0, 280))}</div>
        ${(c.cwe || []).length ? `<div class="meta-row">${c.cwe.slice(0, 3).map((w) => `<span class="chip">${esc(w)}</span>`).join('')}</div>` : ''}
      </div>`).join('') || '<div class="muted">No results.</div>';
  } catch (e) {
    status.className = 'status error';
    status.textContent = '✗ ' + e.message;
  }
}
$('#btn-cve-refresh').addEventListener('click', () => loadCVEs(true));
let cveTimer;
$('#cve-search').addEventListener('input', () => { clearTimeout(cveTimer); cveTimer = setTimeout(() => loadCVEs(true), 400); });

// ---- Reports (paginated + history diff) ----
const REP_PAGE = 20;
let repOffset = 0;

async function loadReports(offset = 0) {
  repOffset = offset;
  const mount = $('#reports-list');
  mount.innerHTML = '<div class="muted">Loading...</div>';
  try {
    const res = await fetch(`/api/reports?limit=${REP_PAGE}&offset=${offset}`);
    const data = await res.json();
    const total = data.total || 0;
    if (!data.reports.length) { mount.innerHTML = '<div class="muted">No reports yet.</div>'; return; }
    const from = offset + 1, to = offset + data.reports.length;
    mount.innerHTML = `<table class="rep">
      <thead><tr><th>Report</th><th>Type</th><th>Target</th><th>Risk</th><th>Findings</th><th>Date</th><th></th></tr></thead>
      <tbody>${data.reports.map((r) => `
        <tr>
          <td>${esc(r.id)}</td>
          <td>${r.kind === 'target' ? 'Target' : 'File'}</td>
          <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(r.subject)}</td>
          <td style="color:${r.riskScore >= 60 ? '#f87171' : r.riskScore >= 30 ? '#fbbf24' : '#4ade80'}">${r.riskScore}</td>
          <td>${r.findingsCount}</td>
          <td class="muted">${new Date(r.generatedAt).toLocaleString('en')}</td>
          <td><a href="${r.html}" target="_blank">Open ↗</a> ${r.kind === 'target' ? `· <button class="link" data-diff="${esc(r.subject)}">Compare</button>` : ''}</td>
        </tr>`).join('')}</tbody></table>
      <div class="pager">
        <button class="btn-ghost" ${offset <= 0 ? 'disabled' : ''} id="rep-prev">← Prev</button>
        <span class="muted">Showing ${from}–${to} of ${total}</span>
        <button class="btn-ghost" ${to >= total ? 'disabled' : ''} id="rep-next">Next →</button>
      </div>`;
    const prev = $('#rep-prev'); if (prev) prev.onclick = () => loadReports(Math.max(0, offset - REP_PAGE));
    const next = $('#rep-next'); if (next) next.onclick = () => loadReports(offset + REP_PAGE);
    mount.querySelectorAll('[data-diff]').forEach((b) => b.addEventListener('click', () => showDiff(b.dataset.diff)));
  } catch (e) {
    mount.innerHTML = '<div class="status error">✗ ' + e.message + '</div>';
  }
}

async function showDiff(subject) {
  const mount = $('#reports-list');
  mount.innerHTML = '<div class="muted">Comparing last two scans...</div>';
  try {
    const res = await fetch('/api/reports/diff?subject=' + encodeURIComponent(subject));
    const d = await res.json();
    if (!res.ok) { mount.innerHTML = `<div class="status error">✗ ${esc(d.error || 'Diff failed')}</div><button class="btn-ghost" id="diff-back">← Back</button>`; $('#diff-back').onclick = () => loadReports(repOffset); return; }
    const deltaColor = d.riskDelta > 0 ? '#f87171' : d.riskDelta < 0 ? '#4ade80' : 'var(--muted)';
    const fList = (arr, cls) => arr.length ? arr.map((f) => `<div class="finding ${f.severity}"><div class="finding-head"><span class="finding-title">${esc(f.title)}</span><span class="sev-tag ${f.severity}">${SEV_LABEL[f.severity] || f.severity}</span></div>${f.evidence ? `<div class="finding-ev">${esc(f.evidence)}</div>` : ''}</div>`).join('') : `<div class="muted">None.</div>`;
    mount.innerHTML = `
      <button class="btn-ghost" id="diff-back">← Back to reports</button>
      <h3 style="margin:14px 0 6px">Comparison — ${esc(subject)}</h3>
      <div class="meta-row">
        <span class="chip">Newer: ${esc(d.newer.id)} (${new Date(d.newer.generatedAt).toLocaleDateString('en')})</span>
        <span class="chip">Older: ${esc(d.older.id)} (${new Date(d.older.generatedAt).toLocaleDateString('en')})</span>
        <span class="chip" style="color:${deltaColor}">Risk change: ${d.riskDelta > 0 ? '+' : ''}${d.riskDelta}</span>
      </div>
      <h3 style="margin:16px 0 8px;color:#f87171">🔺 New findings (${d.addedCount})</h3>${fList(d.added)}
      <h3 style="margin:16px 0 8px;color:#4ade80">✅ Resolved findings (${d.resolvedCount})</h3>${fList(d.resolved)}`;
    $('#diff-back').onclick = () => loadReports(repOffset);
  } catch (e) {
    mount.innerHTML = '<div class="status error">✗ ' + e.message + '</div>';
  }
}

// ---- Scheduled scans ----
$('#sched-auth').addEventListener('change', (e) => { $('#btn-sched-add').disabled = !e.target.checked; });
$('#sched-interval').addEventListener('change', (e) => {
  $('#sched-custom').hidden = e.target.value !== 'custom';
});
$('#sched-refresh').addEventListener('click', () => loadSchedules());
$('#btn-sched-add').addEventListener('click', createSchedule);

function intervalLabel(min) {
  if (min % 10080 === 0) return (min / 10080) + 'w';
  if (min % 1440 === 0) return (min / 1440) + 'd';
  if (min % 60 === 0) return (min / 60) + 'h';
  return min + 'm';
}

async function createSchedule() {
  const status = $('#sched-status');
  const target = $('#sched-target').value.trim();
  if (!target) { status.className = 'status error'; status.textContent = '✗ Enter a target.'; return; }
  let intervalMin = $('#sched-interval').value;
  if (intervalMin === 'custom') intervalMin = Number($('#sched-custom').value);
  else intervalMin = Number(intervalMin);
  if (!intervalMin || intervalMin < 5 || intervalMin > 40320) {
    status.className = 'status error'; status.textContent = '✗ Interval must be between 5 minutes and 4 weeks.'; return;
  }
  status.className = 'status'; status.textContent = 'Adding...';
  const body = {
    target, intervalMin, authorized: true,
    allowPrivate: $('#sched-private').checked,
    headers: parseHeaders($('#sched-headers').value),
  };
  try {
    const res = await fetch('/api/schedules', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
      body: JSON.stringify(body),
    });
    const d = await res.json();
    if (!res.ok) { status.className = 'status error'; status.textContent = '✗ ' + esc(d.error || 'Failed'); return; }
    status.className = 'status ok'; status.textContent = '✓ Schedule added.';
    $('#sched-target').value = '';
    $('#sched-headers').value = '';
    loadSchedules();
  } catch (e) {
    status.className = 'status error'; status.textContent = '✗ ' + e.message;
  }
}

async function loadSchedules() {
  const mount = $('#schedules-list');
  mount.innerHTML = '<div class="muted">Loading...</div>';
  try {
    const res = await fetch('/api/schedules');
    const d = await res.json();
    const list = d.schedules || [];
    if (!list.length) { mount.innerHTML = '<div class="muted">No schedules yet.</div>'; return; }
    mount.innerHTML = `<table class="rep">
      <thead><tr><th>Target</th><th>Every</th><th>Next run</th><th>Last run</th><th>Last report</th><th>Status</th><th></th></tr></thead>
      <tbody>${list.map((s) => `
        <tr>
          <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis">${esc(s.target)}${s.allowPrivate ? ' <span class="muted">(private)</span>' : ''}${Object.keys(s.headers || {}).length ? ' 🔑' : ''}</td>
          <td>${intervalLabel(s.intervalMin)}</td>
          <td class="muted">${s.nextRun ? new Date(s.nextRun).toLocaleString('en') : '—'}</td>
          <td class="muted">${s.lastRun ? new Date(s.lastRun).toLocaleString('en') : 'never'}</td>
          <td>${s.lastReportId ? `<a href="/reports/${esc(s.lastReportId)}.html" target="_blank">${esc(s.lastReportId)} ↗</a>` : '—'}</td>
          <td style="color:${s.enabled ? '#4ade80' : '#9ca3af'}">${s.enabled ? 'Active' : 'Paused'}</td>
          <td>
            <button class="link" data-toggle="${esc(s.id)}" data-enabled="${s.enabled ? '1' : '0'}">${s.enabled ? 'Pause' : 'Resume'}</button>
            · <button class="link danger" data-del="${esc(s.id)}">Delete</button>
          </td>
        </tr>`).join('')}</tbody></table>`;
    mount.querySelectorAll('[data-toggle]').forEach((b) =>
      b.addEventListener('click', () => toggleSchedule(b.dataset.toggle, b.dataset.enabled !== '1')));
    mount.querySelectorAll('[data-del]').forEach((b) =>
      b.addEventListener('click', () => deleteSchedule(b.dataset.del)));
  } catch (e) {
    mount.innerHTML = '<div class="status error">✗ ' + e.message + '</div>';
  }
}

async function toggleSchedule(id, enabled) {
  try {
    await fetch(`/api/schedules/${encodeURIComponent(id)}/toggle`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
      body: JSON.stringify({ enabled }),
    });
    loadSchedules();
  } catch (e) { /* ignore */ }
}

async function deleteSchedule(id) {
  if (!confirm('Delete this schedule?')) return;
  try {
    await fetch(`/api/schedules/${encodeURIComponent(id)}`, {
      method: 'DELETE', headers: { 'X-CSRF-Token': CSRF },
    });
    loadSchedules();
  } catch (e) { /* ignore */ }
}
