// src/scanner.js
// Safe passive/light target scan: GET/OPTIONS/introspection only — no exploitation or attacks.
// Runs dozens of checks: headers, cookies, TLS, exposed paths, CORS, methods,
// WAF, HTML analysis, DNS security, GraphQL, source maps, WordPress, and CVE correlation.

import tls from 'tls';
import dns from 'dns/promises';
import net from 'net';
import { fingerprint } from './fingerprint.js';
import { SENSITIVE_PATHS } from './wordlists.js';
import {
  analyzeSecurityHeaders, analyzeCookies, analyzeCaching, detectWAF, analyzeHTML,
  analyzeDNSSecurity, checkGraphQL, checkSourceMaps, checkWordPress, extractScriptSrcs,
} from './checks.js';

const UA = 'VulnScan-Platform/1.0 (authorized security assessment)';
const REQ_TIMEOUT = 12000;

export function parseTarget(input) {
  let raw = String(input || '').trim();
  if (!raw) throw new Error('Target is empty');
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  let u;
  try { u = new URL(raw); } catch { throw new Error('Invalid target format'); }
  return { url: u, hostname: u.hostname, protocol: u.protocol, port: u.port || (u.protocol === 'https:' ? 443 : 80) };
}

function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
  }
  if (net.isIPv6(ip)) {
    const low = ip.toLowerCase();
    return low === '::1' || low.startsWith('fe80') || low.startsWith('fc') || low.startsWith('fd');
  }
  return false;
}

async function resolveHost(hostname) {
  if (net.isIP(hostname)) return { addresses: [hostname], isIP: true };
  const res = { addresses: [], isIP: false };
  try { res.addresses.push(...(await dns.resolve4(hostname))); } catch { /* */ }
  try { res.addresses.push(...(await dns.resolve6(hostname))); } catch { /* */ }
  if (!res.addresses.length) {
    const lookup = await dns.lookup(hostname, { all: true });
    res.addresses.push(...lookup.map((l) => l.address));
  }
  return res;
}

// Fetch HTTP following redirects manually
async function fetchHttp(url, redirects = 4, extraHeaders = {}) {
  const chain = [];
  let current = url;
  let last = null;
  for (let i = 0; i <= redirects; i++) {
    const res = await fetch(current, { method: 'GET', headers: { 'User-Agent': UA, Accept: '*/*', ...extraHeaders }, redirect: 'manual', signal: AbortSignal.timeout(REQ_TIMEOUT) });
    const headers = {};
    for (const [k, v] of res.headers.entries()) headers[k.toLowerCase()] = v;
    const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    chain.push({ url: current, status: res.status, location: headers.location || null });
    last = { res, headers, setCookie, url: current };
    if (res.status >= 300 && res.status < 400 && headers.location) { current = new URL(headers.location, current).toString(); continue; }
    break;
  }
  return { ...last, chain };
}

// Inspect TLS certificate (extended: expiry, protocol, key size, self-signed, hostname match)
function inspectTLS(hostname, port) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: REQ_TIMEOUT }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const now = Date.now();
      const validTo = cert.valid_to ? new Date(cert.valid_to).getTime() : null;
      const daysLeft = validTo ? Math.round((validTo - now) / 864e5) : null;
      const findings = [];

      if (daysLeft !== null && daysLeft < 0) findings.push({ type: 'tls', title: 'Expired TLS certificate', severity: 'HIGH', detail: 'Renew the certificate immediately.', evidence: `Expired: ${cert.valid_to}`, cwe: 'CWE-298', owasp: 'A02' });
      else if (daysLeft !== null && daysLeft < 15) findings.push({ type: 'tls', title: 'TLS certificate nearing expiry', severity: 'MEDIUM', detail: `${daysLeft} days remaining.`, evidence: `Expires: ${cert.valid_to}`, cwe: 'CWE-298', owasp: 'A02' });

      if (protocol && /TLSv1(\.[01])?$|SSLv/.test(protocol)) findings.push({ type: 'tls', title: `Outdated TLS/SSL protocol: ${protocol}`, severity: 'MEDIUM', detail: 'Use only TLS 1.2 or 1.3.', evidence: protocol, cwe: 'CWE-327', owasp: 'A02' });

      // Weak RSA key only (256-bit ECDSA is strong and not considered weak)
      const isEC = !!(cert.asn1Curve || cert.nistCurve);
      if (cert.bits && !isEC && cert.bits < 2048) findings.push({ type: 'tls', title: `Weak RSA key (${cert.bits}-bit)`, severity: 'MEDIUM', detail: 'Use RSA 2048+ or ECDSA.', evidence: `${cert.bits}-bit RSA`, cwe: 'CWE-326', owasp: 'A02' });

      // Self-signed
      const issCN = cert.issuer?.CN; const subCN = cert.subject?.CN;
      if (issCN && subCN && issCN === subCN && (cert.issuer?.O || '') === (cert.subject?.O || '')) findings.push({ type: 'tls', title: 'Self-signed certificate', severity: 'MEDIUM', detail: 'Not trusted by a recognized certificate authority.', evidence: `CN=${subCN}`, cwe: 'CWE-295', owasp: 'A02' });

      // Hostname match against SAN
      const san = cert.subjectaltname || '';
      if (san) {
        const names = san.split(',').map((s) => s.replace(/^\s*DNS:/, '').trim().toLowerCase());
        const matches = names.some((n) => n === hostname.toLowerCase() || (n.startsWith('*.') && hostname.toLowerCase().endsWith(n.slice(1))));
        if (!matches && !net.isIP(hostname)) findings.push({ type: 'tls', title: 'Hostname does not match TLS certificate', severity: 'HIGH', detail: 'The certificate was not issued for this domain.', evidence: `SAN: ${san.slice(0, 100)}`, cwe: 'CWE-297', owasp: 'A02' });
      }

      resolve({ ok: true, protocol, cipher: cipher ? `${cipher.name} (${cipher.version})` : null, keyBits: cert.bits || null, issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN : null, subject: subCN || null, validFrom: cert.valid_from || null, validTo: cert.valid_to || null, daysLeft, san: san || null, findings });
      socket.end();
    });
    socket.on('error', (e) => resolve({ ok: false, error: String(e.message || e), findings: [] }));
    socket.on('timeout', () => { socket.destroy(); resolve({ ok: false, error: 'timeout', findings: [] }); });
  });
}

// Baseline to avoid false positives
async function getBaseline(base, extraHeaders = {}) {
  try {
    const rand = '/vulnscan-' + Math.random().toString(36).slice(2, 12) + '-404check';
    const res = await fetch(new URL(rand, base).toString(), { method: 'GET', headers: { 'User-Agent': UA, ...extraHeaders }, redirect: 'manual', signal: AbortSignal.timeout(5000) });
    const text = (await res.text().catch(() => '')).slice(0, 2000);
    return { status: res.status, length: text.length, alwaysOk: res.status === 200 };
  } catch { return { status: null, length: 0, alwaysOk: false }; }
}

// Sensitive-path checks (extended categorized list)
async function checkSensitivePaths(baseUrl, extraHeaders = {}) {
  const findings = [];
  const base = new URL(baseUrl);
  const baseline = await getBaseline(base, extraHeaders);
  const queue = [...SENSITIVE_PATHS];
  const workers = Array.from({ length: 12 }, async () => {
    while (queue.length) {
      const item = queue.shift();
      const target = new URL(item.path, base).toString();
      try {
        const res = await fetch(target, { method: 'GET', headers: { 'User-Agent': UA, ...extraHeaders }, redirect: 'manual', signal: AbortSignal.timeout(5000) });
        if (res.status === 200) {
          const text = (await res.text().catch(() => '')).slice(0, 4000);
          const ctype = (res.headers.get('content-type') || '').toLowerCase();
          const sameAsBaseline = baseline.alwaysOk && Math.abs(text.length - baseline.length) < 64;
          const looksError = /(404|not found|page not found)/i.test(text.slice(0, 200));
          const looksHtml = /<html|<!doctype/i.test(text.slice(0, 500));

          let confirmed = false;
          if (item.sig) {
            // Confirm by content signature (high precision — removes false positives from catch-all routing)
            confirmed = item.sig.test(text);
          } else if (item.binary) {
            // Binary/downloadable file: not an HTML page and not like the baseline
            confirmed = !looksHtml && !sameAsBaseline && !looksError && !ctype.includes('text/html');
          } else {
            // Generic existence check (lower confidence)
            confirmed = !sameAsBaseline && !looksError;
          }

          if (confirmed) {
            findings.push({ type: 'exposed-path', title: item.title, severity: item.severity, detail: `Path ${item.path} returned 200 with matching content.`, evidence: `${item.path} → 200`, cwe: item.cwe, owasp: 'A05', category: item.category });
          }
        }
      } catch { /* */ }
    }
  });
  await Promise.all(workers);
  return findings;
}

// CORS checks (with origin reflection and null tests)
async function checkCORS(url, extraHeaders = {}) {
  const findings = [];
  try {
    const probe = 'https://vulnscan-probe.example';
    const res = await fetch(url, { method: 'GET', headers: { 'User-Agent': UA, Origin: probe, ...extraHeaders }, redirect: 'manual', signal: AbortSignal.timeout(6000) });
    const acao = res.headers.get('access-control-allow-origin');
    const acac = res.headers.get('access-control-allow-credentials');
    if (acao === '*' && acac === 'true') findings.push({ type: 'cors', title: 'Dangerous CORS: any origin + credentials', severity: 'HIGH', detail: 'ACAO=* with credentials=true allows cross-origin data theft.', evidence: 'ACAO:* ACAC:true', cwe: 'CWE-942', owasp: 'A05' });
    else if (acao === probe) findings.push({ type: 'cors', title: 'CORS reflects any origin (origin reflection)', severity: acac === 'true' ? 'HIGH' : 'MEDIUM', detail: 'The server reflects the Origin that was sent.', evidence: `ACAO reflects origin${acac === 'true' ? ' + credentials' : ''}`, cwe: 'CWE-942', owasp: 'A05' });
    else if (acao === '*') findings.push({ type: 'cors', title: 'Open CORS (*)', severity: 'LOW', detail: 'Acceptable for public resources only.', evidence: 'ACAO:*', cwe: 'CWE-942', owasp: 'A05' });
    // null origin test
    const res2 = await fetch(url, { method: 'GET', headers: { 'User-Agent': UA, Origin: 'null', ...extraHeaders }, redirect: 'manual', signal: AbortSignal.timeout(6000) });
    if (res2.headers.get('access-control-allow-origin') === 'null') findings.push({ type: 'cors', title: 'CORS allows the null origin', severity: 'MEDIUM', detail: 'Can be exploited from sandboxed iframes.', evidence: 'ACAO: null', cwe: 'CWE-942', owasp: 'A05' });
  } catch { /* */ }
  return findings;
}

async function checkHttpMethods(url, extraHeaders = {}) {
  const findings = [];
  try {
    const res = await fetch(url, { method: 'OPTIONS', headers: { 'User-Agent': UA, ...extraHeaders }, redirect: 'manual', signal: AbortSignal.timeout(6000) });
    const allow = res.headers.get('allow') || res.headers.get('access-control-allow-methods');
    if (allow) {
      const methods = allow.toUpperCase();
      const dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'].filter((m) => methods.includes(m));
      if (methods.includes('TRACE')) findings.push({ type: 'http-methods', title: 'TRACE method enabled (XST)', severity: 'MEDIUM', detail: 'Disable TRACE.', evidence: `Allow: ${allow}`, cwe: 'CWE-16', owasp: 'A05' });
      if (dangerous.length) findings.push({ type: 'http-methods', title: `Writable methods allowed: ${dangerous.join(', ')}`, severity: 'LOW', detail: 'Ensure they are protected by authorization.', evidence: `Allow: ${allow}`, cwe: 'CWE-650', owasp: 'A05' });
    }
  } catch { /* */ }
  return findings;
}

async function gatherDNS(hostname) {
  if (net.isIP(hostname)) return {};
  const out = {};
  await Promise.all([
    dns.resolveMx(hostname).then((r) => { out.mx = r.map((x) => x.exchange); }).catch(() => {}),
    dns.resolveNs(hostname).then((r) => { out.ns = r; }).catch(() => {}),
    dns.resolveTxt(hostname).then((r) => { out.txt = r.flat().slice(0, 8); }).catch(() => {}),
    dns.resolveCname(hostname).then((r) => { out.cname = r; }).catch(() => {}),
  ]);
  return out;
}

// Full scan. opts.headers lets you scan behind authentication (e.g. { Cookie: '...', Authorization: '...' }).
export async function scanTarget(input, { allowPrivate = false, headers = {}, onLog = () => {} } = {}) {
  const log = (phase, message) => { try { onLog({ phase, message, t: Date.now() }); } catch { /* */ } };
  const parsed = parseTarget(input);
  const result = {
    target: parsed.url.toString(), hostname: parsed.hostname, startedAt: new Date().toISOString(),
    authenticated: Object.keys(headers || {}).length > 0,
    dns: null, http: null, tls: null, waf: [], technologies: [], findings: [], errors: [],
  };
  log('start', `Starting scan of ${result.target}${result.authenticated ? ' (authenticated)' : ''}`);

  // DNS + private-address protection
  log('dns', `Resolving DNS for ${parsed.hostname}...`);
  try {
    const resolved = await resolveHost(parsed.hostname);
    result.dns = resolved;
    log('dns', `Resolved to ${resolved.addresses[0] || '?'} (${resolved.addresses.length} address(es))`);
    const privateHit = resolved.addresses.find((ip) => isPrivateIP(ip));
    if (privateHit && !allowPrivate) {
      result.errors.push(`Target resolves to an internal/private address (${privateHit}). Scan halted unless explicitly allowed.`);
      result.blocked = true;
      log('blocked', `Halted: internal/private address (${privateHit})`);
      return result;
    }
  } catch (e) { result.errors.push(`DNS resolution failed: ${e.message}`); log('error', `DNS resolution failed: ${e.message}`); return result; }

  // HTTP + content analysis
  let body = '';
  let scriptSrcs = [];
  try {
    log('http', `Fetching ${parsed.url.toString()}...`);
    const http = await fetchHttp(parsed.url.toString(), 4, headers);
    body = await http.res.text().catch(() => '');
    result.http = {
      finalUrl: http.url, status: http.res.status, headers: http.headers, redirectChain: http.chain,
      title: (/(<title[^>]*>)([\s\S]*?)<\/title>/i.exec(body) || [])[2]?.trim()?.slice(0, 160) || null,
      bodyLength: body.length,
    };
    log('http', `HTTP ${http.res.status} · server: ${http.headers.server || '?'} · ${body.length} bytes`);
    const setCookie = http.setCookie;
    const hdrFindings = [...analyzeSecurityHeaders(http.headers, setCookie), ...analyzeCookies(setCookie), ...analyzeCaching(http.headers, setCookie)];
    result.findings.push(...hdrFindings);
    log('headers', `Analyzed security headers & cookies (${hdrFindings.length} finding(s))`);
    result.waf = detectWAF(http.headers);
    if (result.waf.length) log('waf', `WAF/CDN detected: ${result.waf.join(', ')}`);

    if (parsed.protocol === 'http:' && !http.chain.some((c) => c.location && c.location.startsWith('https'))) {
      result.findings.push({ type: 'transport', title: 'Site served over HTTP without redirect to HTTPS', severity: 'MEDIUM', detail: 'Enable a permanent redirect to HTTPS.', evidence: parsed.url.toString(), cwe: 'CWE-319', owasp: 'A02' });
    }

    const htmlAnalysis = analyzeHTML(body, http.url);
    result.findings.push(...htmlAnalysis.findings);
    scriptSrcs = extractScriptSrcs(body);

    // Technologies = header/content fingerprint + detected JS libraries
    const techs = fingerprint({ headers: http.headers, body, cookies: setCookie });
    const techMap = new Map(techs.map((t) => [t.name, t]));
    for (const lib of htmlAnalysis.detectedLibs) { if (!techMap.has(lib.name)) techMap.set(lib.name, lib); else if (!techMap.get(lib.name).version && lib.version) techMap.get(lib.name).version = lib.version; }
    result.technologies = [...techMap.values()];
    log('tech', `Technologies: ${result.technologies.map((t) => t.name + (t.version ? ' ' + t.version : '')).join(', ') || 'none detected'}`);
  } catch (e) { result.errors.push(`HTTP request failed: ${e.message}`); log('error', `HTTP request failed: ${e.message}`); }

  // TLS
  if (parsed.protocol === 'https:' || String(parsed.port) === '443') {
    log('tls', 'Inspecting TLS certificate...');
    try {
      const tlsInfo = await inspectTLS(parsed.hostname, Number(parsed.port) || 443);
      result.tls = tlsInfo;
      if (tlsInfo.findings) result.findings.push(...tlsInfo.findings);
      if (tlsInfo.ok) log('tls', `TLS ${tlsInfo.protocol || '?'} · cert valid for ${tlsInfo.daysLeft ?? '?'} more day(s)`);
      else log('tls', `TLS check: ${tlsInfo.error}`);
    } catch (e) { result.errors.push(`TLS check failed: ${e.message}`); log('error', `TLS check failed: ${e.message}`); }
  }

  // Deep checks (in parallel), logging each as it completes
  const base = result.http?.finalUrl || parsed.url.toString();
  const isWP = result.technologies.some((t) => t.name === 'wordpress');
  log('deep', 'Running deep checks: exposed paths, CORS, methods, GraphQL, source maps, DNS security' + (isWP ? ', WordPress' : '') + '...');
  try {
    const named = [
      ['Exposed paths', checkSensitivePaths(base, headers)],
      ['CORS', checkCORS(base, headers)],
      ['HTTP methods', checkHttpMethods(base, headers)],
      ['GraphQL', checkGraphQL(base, headers)],
      ['Source maps', checkSourceMaps(scriptSrcs, base, headers)],
      ['DNS security', analyzeDNSSecurity(parsed.hostname)],
      ['WordPress', isWP ? checkWordPress(base, headers) : Promise.resolve([])],
    ];
    const results = await Promise.all(named.map(async ([name, p]) => {
      const r = await p;
      log('check', `${name}: ${r.length} finding(s)`);
      return r;
    }));
    for (const r of results) result.findings.push(...r);
  } catch (e) { result.errors.push(`Deep scan failed: ${e.message}`); log('error', `Deep scan failed: ${e.message}`); }

  // Additional DNS records
  try { const extra = await gatherDNS(parsed.hostname); if (result.dns) Object.assign(result.dns, extra); } catch { /* */ }

  result.finishedAt = new Date().toISOString();
  log('done', `Scan complete · ${result.findings.length} findings`);
  return result;
}
