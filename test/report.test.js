import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildReport, renderHTML } from '../src/report.js';

const fakeTargetScan = {
  target: 'https://example.com',
  hostname: 'example.com',
  dns: { addresses: ['93.184.216.34'] },
  http: { headers: { server: 'nginx' }, title: 'Example' },
  technologies: [{ name: 'nginx', version: '1.18.0' }],
  waf: ['Cloudflare'],
  findings: [
    { type: 'tls', title: 'Expired TLS certificate', severity: 'HIGH', detail: 'x', evidence: 'y', cwe: 'CWE-298', owasp: 'A02' },
    { type: 'missing-security-header', title: 'Missing security header: HSTS', severity: 'MEDIUM', detail: 'x', evidence: 'y', cwe: 'CWE-319', owasp: 'A02' },
  ],
  errors: [],
};

test('buildReport computes summary, risk score, and sorts by severity', () => {
  const r = buildReport({ kind: 'target', scan: fakeTargetScan });
  assert.equal(r.findingsCount, 2);
  assert.equal(r.summary.HIGH, 1);
  assert.equal(r.summary.MEDIUM, 1);
  assert.equal(r.findings[0].severity, 'HIGH'); // highest first
  assert.ok(r.riskScore > 0);
  assert.equal(r.meta.waf[0], 'Cloudflare');
  assert.ok(r.id.startsWith('RPT-'));
});

test('buildReport builds OWASP summary', () => {
  const r = buildReport({ kind: 'target', scan: fakeTargetScan });
  assert.equal(r.owaspSummary.A02, 2);
});

test('renderHTML produces a printable HTML document', () => {
  const r = buildReport({ kind: 'target', scan: fakeTargetScan });
  const html = renderHTML(r);
  assert.ok(html.includes('<!doctype html>'));
  assert.ok(html.includes('Save as PDF'));
  assert.ok(html.includes('Expired TLS certificate'));
});

test('KEV correlation escalates HIGH to CRITICAL', () => {
  const correlation = [{
    technology: { name: 'nginx', version: '1.18.0' },
    topMatches: [{ id: 'CVE-2021-0001', score: 8.1, severity: 'HIGH', description: 'x', kev: true, confidence: 'range' }],
  }];
  const r = buildReport({ kind: 'target', scan: { ...fakeTargetScan, findings: [] }, correlation });
  const cve = r.findings.find((f) => f.cve === 'CVE-2021-0001');
  assert.equal(cve.severity, 'CRITICAL');
});
