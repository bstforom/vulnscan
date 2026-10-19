// src/checks.js
// Extended passive/light security checks (GET/OPTIONS/introspection only — no exploitation).
// Each function returns a findings array: { type, title, severity, detail, evidence, cwe, owasp }

import dns from 'dns/promises';
import { WAF_SIGNATURES, JS_LIB_PATTERNS } from './wordlists.js';

const UA = 'VulnScan-Platform/1.0 (authorized security assessment)';
const T = 6000;

// ===== 1) Security headers (extended) =====
const SEC_HEADERS = [
  { key: 'strict-transport-security', name: 'HSTS', severity: 'MEDIUM', cwe: 'CWE-319', owasp: 'A02', advice: 'Enable HSTS to force HTTPS.' },
  { key: 'content-security-policy', name: 'Content-Security-Policy', severity: 'MEDIUM', cwe: 'CWE-1021', owasp: 'A05', advice: 'Add a CSP to limit XSS and content injection.' },
  { key: 'x-frame-options', name: 'X-Frame-Options', severity: 'LOW', cwe: 'CWE-1021', owasp: 'A05', advice: 'Prevent framing (clickjacking).' },
  { key: 'x-content-type-options', name: 'X-Content-Type-Options', severity: 'LOW', cwe: 'CWE-16', owasp: 'A05', advice: 'Set nosniff.' },
  { key: 'referrer-policy', name: 'Referrer-Policy', severity: 'LOW', cwe: 'CWE-200', owasp: 'A05', advice: 'Restrict Referrer leakage.' },
  { key: 'permissions-policy', name: 'Permissions-Policy', severity: 'LOW', cwe: 'CWE-16', owasp: 'A05', advice: 'Restrict browser capabilities.' },
  { key: 'cross-origin-opener-policy', name: 'Cross-Origin-Opener-Policy', severity: 'LOW', cwe: 'CWE-16', owasp: 'A05', advice: 'Add COOP for cross-origin isolation.' },
  { key: 'cross-origin-resource-policy', name: 'Cross-Origin-Resource-Policy', severity: 'LOW', cwe: 'CWE-16', owasp: 'A05', advice: 'Add CORP.' },
];

export function analyzeSecurityHeaders(headers, setCookie = []) {
  const findings = [];
  for (const h of SEC_HEADERS) {
    if (!headers[h.key]) {
      findings.push({ type: 'missing-security-header', title: `Missing security header: ${h.name}`, severity: h.severity, detail: h.advice, evidence: `No ${h.key}`, cwe: h.cwe, owasp: h.owasp });
    }
  }
  // CSP strength: unsafe-inline / unsafe-eval
  const csp = headers['content-security-policy'];
  if (csp) {
    if (/unsafe-inline/i.test(csp)) findings.push({ type: 'weak-csp', title: 'CSP allows unsafe-inline', severity: 'LOW', detail: 'Weakens XSS protection.', evidence: "script-src 'unsafe-inline'", cwe: 'CWE-79', owasp: 'A03' });
    if (/unsafe-eval/i.test(csp)) findings.push({ type: 'weak-csp', title: 'CSP allows unsafe-eval', severity: 'LOW', detail: 'Allows dynamic code execution.', evidence: "script-src 'unsafe-eval'", cwe: 'CWE-95', owasp: 'A03' });
  }
  // Version disclosure via headers
  for (const leak of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache']) {
    if (headers[leak]) findings.push({ type: 'info-disclosure', title: `Information disclosure via header: ${leak}`, severity: 'LOW', detail: 'Hiding server/framework version reduces the attack surface.', evidence: `${leak}: ${headers[leak]}`, cwe: 'CWE-200', owasp: 'A05' });
  }
  return findings;
}

// ===== 2) Cookies (extended) =====
export function analyzeCookies(setCookie = []) {
  const findings = [];
  const arr = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  for (const c of arr) {
    const lc = c.toLowerCase();
    const name = c.split('=')[0].trim();
    const missing = [];
    if (!lc.includes('secure')) missing.push('Secure');
    if (!lc.includes('httponly')) missing.push('HttpOnly');
    if (!lc.includes('samesite')) missing.push('SameSite');
    if (missing.length) findings.push({ type: 'cookie-flags', title: `Cookie missing protection flags: ${missing.join(', ')} (${name})`, severity: 'LOW', detail: 'Add Secure, HttpOnly and SameSite.', evidence: c.split(';')[0], cwe: 'CWE-614', owasp: 'A05' });
    if (/samesite=none/i.test(lc) && !lc.includes('secure')) findings.push({ type: 'cookie-flags', title: `SameSite=None without Secure (${name})`, severity: 'MEDIUM', detail: 'SameSite=None requires Secure.', evidence: c.split(';')[0], cwe: 'CWE-614', owasp: 'A05' });
    if (/^__host-/i.test(name) && (!lc.includes('secure') || !lc.includes('path=/'))) findings.push({ type: 'cookie-flags', title: `__Host- cookie does not meet its requirements (${name})`, severity: 'LOW', detail: 'The __Host- prefix requires Secure, Path=/ and no Domain.', evidence: name, cwe: 'CWE-614', owasp: 'A05' });
  }
  return findings;
}

// ===== 3) WAF/CDN detection =====
export function detectWAF(headers) {
  const detected = new Set();
  for (const sig of WAF_SIGNATURES) {
    const val = headers[sig.header];
    if (val && sig.re.test(Array.isArray(val) ? val.join(';') : val)) detected.add(sig.name);
  }
  return [...detected];
}

// ===== 4) HTML content analysis =====
export function analyzeHTML(body, baseUrl) {
  const findings = [];
  const detectedLibs = [];
  if (!body) return { findings, detectedLibs };
  let baseHost = '';
  let isHttps = false;
  try { const u = new URL(baseUrl); baseHost = u.host; isHttps = u.protocol === 'https:'; } catch { /* */ }

  // External scripts: SRI and version extraction
  const scriptRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  const seenLib = new Set();
  while ((m = scriptRe.exec(body))) {
    const tag = m[0];
    const src = m[1];
    // Extract library version
    for (const lib of JS_LIB_PATTERNS) {
      const lm = lib.re.exec(src);
      if (lm && !seenLib.has(lib.name)) { seenLib.add(lib.name); detectedLibs.push({ name: lib.name, version: lm[1] || null, evidence: 'script-src' }); }
    }
    // SRI for external sources
    try {
      const su = new URL(src, baseUrl);
      if (su.host && su.host !== baseHost && !/integrity\s*=/.test(tag)) {
        findings.push({ type: 'missing-sri', title: 'External script without Subresource Integrity (SRI)', severity: 'LOW', detail: 'Add an integrity attribute to prevent tampering of CDN content.', evidence: src.slice(0, 120), cwe: 'CWE-353', owasp: 'A08' });
      }
    } catch { /* relative */ }
  }

  // Mixed content
  if (isHttps) {
    const mixed = body.match(/\b(?:src|href)\s*=\s*["']http:\/\/[^"']+/i);
    if (mixed) findings.push({ type: 'mixed-content', title: 'Mixed content (HTTP resources inside an HTTPS page)', severity: 'MEDIUM', detail: 'Load all resources over HTTPS.', evidence: mixed[0].slice(0, 120), cwe: 'CWE-319', owasp: 'A02' });
  }

  // Forms submitting over HTTP
  const formActionHttp = /<form\b[^>]*\baction\s*=\s*["']http:\/\/[^"']+/i.exec(body);
  if (formActionHttp) findings.push({ type: 'insecure-form', title: 'Form submits its data over HTTP', severity: 'MEDIUM', detail: 'Use HTTPS for form actions.', evidence: formActionHttp[0].slice(0, 120), cwe: 'CWE-319', owasp: 'A02' });

  // Password field on an HTTP page
  if (!isHttps && /<input[^>]*type\s*=\s*["']password["']/i.test(body)) {
    findings.push({ type: 'password-over-http', title: 'Password field on an unencrypted page (HTTP)', severity: 'HIGH', detail: 'Credentials are sent in clear text.', evidence: 'input[type=password] over HTTP', cwe: 'CWE-319', owasp: 'A02' });
  }

  // POST forms without an anti-CSRF token (heuristic)
  const forms = body.match(/<form\b[\s\S]{0,1500}?<\/form>/gi) || [];
  for (const f of forms.slice(0, 10)) {
    if (/method\s*=\s*["']post["']/i.test(f) && !/name\s*=\s*["'][^"']*(csrf|token|_token|authenticity|nonce)[^"']*["']/i.test(f)) {
      findings.push({ type: 'missing-csrf-token', title: 'POST form without a visible CSRF token', severity: 'LOW', detail: 'May lack CSRF protection — needs verification.', evidence: (f.match(/<form[^>]*>/i) || [''])[0].slice(0, 120), cwe: 'CWE-352', owasp: 'A01' });
      break;
    }
  }

  // Internal IP address leakage
  const internalIP = body.match(/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/);
  if (internalIP) findings.push({ type: 'internal-ip', title: 'Internal IP address leaked in the page', severity: 'LOW', detail: 'May reveal internal network structure.', evidence: internalIP[0], cwe: 'CWE-200', owasp: 'A05' });

  // HTML comments containing sensitive keywords
  const comments = body.match(/<!--[\s\S]{0,400}?-->/g) || [];
  for (const c of comments) {
    if (/\b(password|passwd|secret|api[_-]?key|todo|fixme|hack|backdoor|debug|username)\b/i.test(c)) {
      findings.push({ type: 'html-comment-leak', title: 'HTML comment contains a sensitive keyword', severity: 'LOW', detail: 'Remove sensitive comments from production.', evidence: c.replace(/\s+/g, ' ').slice(0, 120), cwe: 'CWE-615', owasp: 'A05' });
      break;
    }
  }

  // Exposed email addresses
  const emails = [...new Set((body.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || []))].slice(0, 3);
  if (emails.length) findings.push({ type: 'email-exposure', title: `Exposed email addresses (${emails.length})`, severity: 'INFO', detail: 'May be targeted by phishing.', evidence: emails.join(', ').slice(0, 160), cwe: 'CWE-200', owasp: 'A05' });

  return { findings, detectedLibs };
}

// ===== 5) DNS security (SPF/DMARC/CAA) =====
export async function analyzeDNSSecurity(hostname) {
  const findings = [];
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return findings;
  const root = hostname.split('.').slice(-2).join('.');
  try {
    const txt = (await dns.resolveTxt(hostname).catch(() => [])).map((r) => r.join(''));
    const txtRoot = (await dns.resolveTxt(root).catch(() => [])).map((r) => r.join(''));
    const allTxt = [...txt, ...txtRoot];
    if (!allTxt.some((t) => /v=spf1/i.test(t))) findings.push({ type: 'dns-spf', title: 'Missing SPF record', severity: 'MEDIUM', detail: 'Without SPF, email from your domain can be spoofed.', evidence: 'No v=spf1', cwe: 'CWE-290', owasp: 'A07' });
    else if (allTxt.some((t) => /v=spf1[^\n]*\+all/i.test(t))) findings.push({ type: 'dns-spf', title: 'Weak SPF (+all)', severity: 'MEDIUM', detail: '+all allows any sender.', evidence: '+all', cwe: 'CWE-290', owasp: 'A07' });
  } catch { /* */ }
  try {
    const dmarc = (await dns.resolveTxt('_dmarc.' + root).catch(() => [])).map((r) => r.join(''));
    if (!dmarc.some((t) => /v=DMARC1/i.test(t))) findings.push({ type: 'dns-dmarc', title: 'Missing DMARC record', severity: 'MEDIUM', detail: 'Without DMARC it is hard to prevent email spoofing.', evidence: 'No _dmarc', cwe: 'CWE-290', owasp: 'A07' });
    else if (dmarc.some((t) => /p=none/i.test(t))) findings.push({ type: 'dns-dmarc', title: 'DMARC policy = none (no enforcement)', severity: 'LOW', detail: 'Raise it to quarantine/reject.', evidence: 'p=none', cwe: 'CWE-290', owasp: 'A07' });
  } catch { /* */ }
  try {
    const caa = await dns.resolveCaa(root).catch(() => []);
    if (!caa || !caa.length) findings.push({ type: 'dns-caa', title: 'Missing CAA record', severity: 'LOW', detail: 'CAA restricts which certificate authorities may issue.', evidence: 'No CAA', cwe: 'CWE-295', owasp: 'A02' });
  } catch { /* */ }
  return findings;
}

// ===== 6) GraphQL introspection =====
export async function checkGraphQL(baseUrl, extraHeaders = {}) {
  const findings = [];
  const endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query'];
  const q = JSON.stringify({ query: '{__schema{queryType{name}}}' });
  for (const ep of endpoints) {
    try {
      const url = new URL(ep, baseUrl).toString();
      const res = await fetch(url, { method: 'POST', headers: { 'User-Agent': UA, 'Content-Type': 'application/json', ...extraHeaders }, body: q, signal: AbortSignal.timeout(T) });
      if (!res.ok) continue;
      const text = (await res.text().catch(() => '')).slice(0, 2000);
      if (/__schema|queryType/.test(text)) {
        findings.push({ type: 'graphql-introspection', title: 'GraphQL introspection enabled', severity: 'MEDIUM', detail: `Full API schema exposed via ${ep}. Disable introspection in production.`, evidence: `${ep} → __schema`, cwe: 'CWE-200', owasp: 'A05' });
        break;
      }
    } catch { /* */ }
  }
  return findings;
}

// ===== 7) Source map detection (.map) =====
export async function checkSourceMaps(scriptUrls, baseUrl, extraHeaders = {}) {
  const findings = [];
  const seen = new Set();
  for (const src of scriptUrls.slice(0, 6)) {
    try {
      const su = new URL(src, baseUrl);
      if (!su.pathname.endsWith('.js')) continue;
      const mapUrl = su.toString() + '.map';
      if (seen.has(mapUrl)) continue;
      seen.add(mapUrl);
      const res = await fetch(mapUrl, { headers: { 'User-Agent': UA, ...extraHeaders }, signal: AbortSignal.timeout(T) });
      if (res.ok) {
        const t = (await res.text().catch(() => '')).slice(0, 300);
        if (/"version"\s*:\s*3|"sources"/.test(t)) {
          findings.push({ type: 'source-map', title: 'Exposed JavaScript source map (.map)', severity: 'LOW', detail: 'Reveals the original source code.', evidence: mapUrl.slice(0, 120), cwe: 'CWE-540', owasp: 'A05' });
        }
      }
    } catch { /* */ }
  }
  return findings;
}

// ===== 8) Lightweight WordPress checks =====
export async function checkWordPress(baseUrl, extraHeaders = {}) {
  const findings = [];
  try {
    const usersUrl = new URL('/wp-json/wp/v2/users', baseUrl).toString();
    const res = await fetch(usersUrl, { headers: { 'User-Agent': UA, ...extraHeaders }, signal: AbortSignal.timeout(T) });
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (Array.isArray(data) && data.length && data[0].slug) {
        const names = data.map((u) => u.slug).slice(0, 5).join(', ');
        findings.push({ type: 'wp-user-enum', title: 'WordPress user enumeration via REST API', severity: 'MEDIUM', detail: 'Usernames are exposed — eases guessing attacks.', evidence: `Users: ${names}`, cwe: 'CWE-200', owasp: 'A01' });
      }
    }
  } catch { /* */ }
  try {
    const xmlrpc = new URL('/xmlrpc.php', baseUrl).toString();
    const res = await fetch(xmlrpc, { headers: { 'User-Agent': UA, ...extraHeaders }, signal: AbortSignal.timeout(T) });
    const t = (await res.text().catch(() => '')).toLowerCase();
    if (res.status === 405 || /xml-rpc server accepts post/i.test(t)) {
      findings.push({ type: 'wp-xmlrpc', title: 'XML-RPC enabled in WordPress', severity: 'LOW', detail: 'Can be abused for attack amplification/brute force. Disable it if unused.', evidence: '/xmlrpc.php available', cwe: 'CWE-307', owasp: 'A07' });
    }
  } catch { /* */ }
  return findings;
}

// ===== 9) Caching of sensitive content =====
export function analyzeCaching(headers, setCookie = []) {
  const findings = [];
  const cc = (headers['cache-control'] || '').toLowerCase();
  const hasCookie = (Array.isArray(setCookie) ? setCookie.length : !!setCookie);
  if (hasCookie && (cc.includes('public') || (!cc.includes('no-store') && !cc.includes('private') && !cc.includes('no-cache')))) {
    findings.push({ type: 'cache-sensitive', title: 'Response sets a cookie without disabling caching', severity: 'LOW', detail: 'Add Cache-Control: no-store for sensitive pages.', evidence: `Cache-Control: ${headers['cache-control'] || '(not set)'}`, cwe: 'CWE-525', owasp: 'A05' });
  }
  return findings;
}

// Extract script URLs from HTML (helper for source maps)
export function extractScriptSrcs(body) {
  const srcs = [];
  const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(body))) srcs.push(m[1]);
  return srcs;
}
