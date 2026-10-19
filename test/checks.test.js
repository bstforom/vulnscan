import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSecurityHeaders, analyzeCookies, detectWAF, analyzeHTML } from '../src/checks.js';

test('flags missing security headers', () => {
  const f = analyzeSecurityHeaders({}, []);
  const titles = f.map((x) => x.title);
  assert.ok(titles.some((t) => t.includes('HSTS')));
  assert.ok(titles.some((t) => t.includes('Content-Security-Policy')));
});

test('flags weak CSP (unsafe-inline) and server header disclosure', () => {
  const f = analyzeSecurityHeaders({ 'content-security-policy': "script-src 'unsafe-inline'", server: 'nginx/1.18.0' }, []);
  assert.ok(f.some((x) => x.type === 'weak-csp'));
  assert.ok(f.some((x) => x.type === 'info-disclosure'));
});

test('flags cookie missing flags', () => {
  const f = analyzeCookies(['session=abc; Path=/']);
  assert.ok(f.some((x) => x.type === 'cookie-flags'));
});

test('detects Cloudflare WAF', () => {
  assert.deepEqual(detectWAF({ 'cf-ray': '123abc' }), ['Cloudflare']);
  assert.deepEqual(detectWAF({}), []);
});

test('analyzeHTML detects mixed content and extracts jquery version', () => {
  const html = '<script src="https://cdn.example.com/jquery-3.4.1.min.js"></script><img src="http://x/y.png">';
  const { findings, detectedLibs } = analyzeHTML(html, 'https://site.example');
  assert.ok(detectedLibs.some((l) => l.name === 'jquery' && l.version === '3.4.1'));
  assert.ok(findings.some((x) => x.type === 'mixed-content' || x.type === 'missing-sri'));
});
