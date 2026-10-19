// src/report.js
// Generates a professional JSON + HTML report from scan results.

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { buildSARIF } from './sarif.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.join(__dirname, '..', 'reports');

const SEV_ORDER = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, UNKNOWN: 0 };
const SEV_COLOR = {
  CRITICAL: '#7c1d1d', HIGH: '#b91c1c', MEDIUM: '#c2770b', LOW: '#2563eb', INFO: '#475569', UNKNOWN: '#64748b',
};
const SEV_LABEL = {
  CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info', UNKNOWN: 'Unknown',
};

function normalizeSeverity(s) {
  const up = String(s || 'UNKNOWN').toUpperCase();
  return SEV_ORDER[up] !== undefined ? up : 'UNKNOWN';
}

// Build a unified report object from a target or file scan
export function buildReport({ kind, scan, correlation = [] }) {
  const findings = [];

  if (kind === 'target') {
    for (const f of scan.findings || []) {
      findings.push({ ...f, severity: normalizeSeverity(f.severity), source: 'target-scan' });
    }
    const confLabel = { exact: 'exact version match', range: 'version within affected range', product: 'product match (needs verification)' };
    for (const c of correlation) {
      for (const m of c.topMatches || []) {
        let sev = normalizeSeverity(m.severity);
        // Escalate severity for actively exploited vulnerabilities (KEV)
        if (m.kev && SEV_ORDER[sev] < SEV_ORDER.CRITICAL) sev = sev === 'HIGH' ? 'CRITICAL' : sev;
        const tv = `${c.technology.name}${c.technology.version ? ' ' + c.technology.version : ''}`;
        const tags = [];
        if (m.kev) tags.push('🔴 actively exploited (KEV)');
        tags.push(confLabel[m.confidence] || 'correlation');
        if (m.epss != null) tags.push(`EPSS ${(m.epss * 100).toFixed(1)}%`);
        findings.push({
          type: 'cve-correlation',
          title: `${m.kev ? '🔴 ' : ''}Vulnerability in ${tv}: ${m.id}`,
          severity: sev,
          detail: m.description,
          evidence: `CVSS ${m.score ?? 'N/A'} · ${tags.join(' · ')}`,
          source: 'cve-correlation',
          cve: m.id,
          kev: !!m.kev,
          confidence: m.confidence,
        });
      }
    }
  } else if (kind === 'file') {
    for (const f of scan.findings || []) {
      findings.push({ ...f, severity: normalizeSeverity(f.severity), source: 'file-scan' });
    }
  }

  findings.sort((a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity]);

  const summary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
  for (const f of findings) summary[f.severity]++;

  // OWASP Top 10 summary
  const owaspSummary = {};
  for (const f of findings) if (f.owasp) owaspSummary[f.owasp] = (owaspSummary[f.owasp] || 0) + 1;

  // Overall risk score 0-100
  const riskScore = Math.min(
    100,
    summary.CRITICAL * 25 + summary.HIGH * 15 + summary.MEDIUM * 7 + summary.LOW * 3 + summary.INFO * 0
  );

  return {
    id: 'RPT-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
    kind,
    generatedAt: new Date().toISOString(),
    subject: kind === 'target' ? scan.target : scan.filename,
    meta: kind === 'target'
      ? { hostname: scan.hostname, ip: scan.dns?.addresses?.[0], server: scan.http?.headers?.server, title: scan.http?.title, technologies: scan.technologies, waf: scan.waf || [] }
      : { size: scan.size, sha256: scan.sha256, fileType: scan.fileType, manifest: scan.manifest, dependencies: scan.dependencies },
    summary,
    owaspSummary,
    riskScore,
    findingsCount: findings.length,
    findings,
    errors: scan.errors || [],
  };
}

const OWASP_LABEL = {
  A01: 'A01 Broken Access Control', A02: 'A02 Cryptographic Failures', A03: 'A03 Injection', A04: 'A04 Insecure Design',
  A05: 'A05 Security Misconfiguration', A06: 'A06 Vulnerable Components', A07: 'A07 Auth Failures', A08: 'A08 Integrity Failures',
  A09: 'A09 Logging Failures', A10: 'A10 SSRF',
};
export { OWASP_LABEL };

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

export function renderHTML(report) {
  const rows = report.findings
    .map(
      (f, i) => `
      <tr>
        <td>${i + 1}</td>
        <td><span class="sev" style="background:${SEV_COLOR[f.severity]}">${SEV_LABEL[f.severity]}</span></td>
        <td>${esc(f.title)}${f.cve ? ` <a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" rel="noopener">${esc(f.cve)}</a>` : ''}
          ${f.cwe ? `<a href="https://cwe.mitre.org/data/definitions/${esc(String(f.cwe).replace('CWE-',''))}.html" target="_blank" rel="noopener" style="font-size:11px;color:#64748b">${esc(f.cwe)}</a>` : ''}
          ${f.owasp ? `<span style="font-size:11px;color:#7c3aed">${esc(f.owasp)}</span>` : ''}</td>
        <td>${esc(f.detail)}</td>
        <td><code>${esc(f.evidence)}</code></td>
      </tr>`
    )
    .join('');

  const sevBadges = Object.entries(report.summary)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `<span class="pill" style="background:${SEV_COLOR[s]}">${SEV_LABEL[s]}: ${n}</span>`)
    .join(' ');

  const techList = (report.meta.technologies || [])
    .map((t) => `<span class="tech">${esc(t.name)}${t.version ? ' ' + esc(t.version) : ''}</span>`)
    .join(' ') || '—';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scan Report ${esc(report.id)}</title>
<style>
  :root { --bg:#0f172a; --card:#1e293b; --text:#e2e8f0; --muted:#94a3b8; --line:#334155; }
  * { box-sizing:border-box; }
  body { font-family:'Segoe UI',Tahoma,sans-serif; background:#f1f5f9; color:#0f172a; margin:0; padding:24px; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .wrap { max-width:1000px; margin:0 auto; }
  header { background:var(--bg); color:var(--text); border-radius:16px; padding:28px; position:relative; }
  .print-btn { position:absolute; top:20px; right:24px; background:#2563eb; color:#fff; border:none; padding:9px 16px; border-radius:8px; font-size:13px; cursor:pointer; }
  .print-btn:hover { background:#1d4ed8; }
  header h1 { margin:0 0 6px; font-size:22px; }
  header .sub { color:var(--muted); font-size:14px; }
  .score { font-size:46px; font-weight:800; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin:18px 0; }
  .box { background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:16px; }
  .box h3 { margin:0 0 8px; font-size:13px; color:#64748b; font-weight:600; }
  .pill, .sev { color:#fff; padding:3px 10px; border-radius:20px; font-size:12px; display:inline-block; margin:2px; }
  .sev { padding:3px 8px; border-radius:6px; white-space:nowrap; }
  .tech { background:#e0e7ff; color:#3730a3; padding:3px 10px; border-radius:20px; font-size:12px; display:inline-block; margin:2px; }
  table { width:100%; border-collapse:collapse; background:#fff; border-radius:12px; overflow:hidden; margin-top:10px; }
  th,td { text-align:left; padding:10px 12px; border-bottom:1px solid #e2e8f0; font-size:13px; vertical-align:top; }
  th { background:#f8fafc; color:#475569; }
  code { background:#f1f5f9; padding:2px 6px; border-radius:4px; font-size:12px; word-break:break-all; }
  a { color:#2563eb; }
  .foot { color:#64748b; font-size:12px; margin-top:20px; text-align:center; }
  .warn { background:#fef3c7; border:1px solid #fde68a; color:#92400e; padding:12px 16px; border-radius:10px; margin-top:16px; font-size:13px; }
  @media print {
    body { padding:0; background:#fff; }
    .no-print { display:none !important; }
    header, .box, table, tr, .warn { break-inside:avoid; }
    a { text-decoration:none; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <button class="print-btn no-print" onclick="window.print()">🖨️ Print / Save as PDF</button>
    <h1>🛡️ Security Scan Report — ${esc(report.id)}</h1>
    <div class="sub">Target: <strong>${esc(report.subject)}</strong> · ${esc(report.generatedAt)}</div>
    <div style="margin-top:16px; display:flex; align-items:center; gap:24px; flex-wrap:wrap;">
      <div><div class="score" style="color:${report.riskScore >= 60 ? '#f87171' : report.riskScore >= 30 ? '#fbbf24' : '#4ade80'}">${report.riskScore}</div><div class="sub">Risk score /100</div></div>
      <div>${sevBadges || '<span class="sub">No findings</span>'}</div>
    </div>
  </header>

  <div class="grid">
    <div class="box"><h3>Findings</h3><strong style="font-size:22px">${report.findingsCount}</strong></div>
    <div class="box"><h3>Type</h3><strong>${report.kind === 'target' ? 'Target (website/IP)' : 'File'}</strong></div>
    ${report.kind === 'target'
      ? `<div class="box"><h3>IP / Server</h3><strong>${esc(report.meta.ip || '—')}</strong><br><span class="sub">${esc(report.meta.server || '')}</span></div>
         <div class="box"><h3>Technologies</h3>${techList}</div>`
      : `<div class="box"><h3>SHA-256</h3><code>${esc((report.meta.sha256 || '').slice(0, 32))}…</code></div>
         <div class="box"><h3>Type / Manifest</h3><strong>${esc(report.meta.manifest || report.meta.fileType || '—')}</strong></div>`}
  </div>

  <h2 style="font-size:16px">Detailed findings</h2>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Details / Remediation</th><th>Evidence</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="5" style="text-align:center;color:#64748b">No findings recorded.</td></tr>'}</tbody>
  </table>

  ${report.errors && report.errors.length ? `<div class="warn"><strong>Notes during the scan:</strong><br>${report.errors.map(esc).join('<br>')}</div>` : ''}

  <div class="warn">⚠️ This report is for authorized security assessment only. CVE correlations are approximate and require manual verification before relying on them. Do not use these results against systems you do not have explicit permission to test.</div>
  <div class="foot">Generated by VulnScan Platform · Data sources: NVD (nvd.nist.gov) and OSV (osv.dev)</div>
</div>
</body>
</html>`;
}

export async function saveReport(report) {
  await fs.mkdir(REPORTS_DIR, { recursive: true });
  const base = `${report.id}`;
  const jsonPath = path.join(REPORTS_DIR, base + '.json');
  const htmlPath = path.join(REPORTS_DIR, base + '.html');
  const sarifPath = path.join(REPORTS_DIR, base + '.sarif');
  await fs.writeFile(jsonPath, JSON.stringify(report, null, 2), 'utf8');
  await fs.writeFile(htmlPath, renderHTML(report), 'utf8');
  await fs.writeFile(sarifPath, JSON.stringify(buildSARIF(report), null, 2), 'utf8');
  return { id: report.id, json: `/reports/${base}.json`, html: `/reports/${base}.html`, sarif: `/reports/${base}.sarif`, owner: report.owner };
}
