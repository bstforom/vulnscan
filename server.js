// server.js — VulnScan Platform — hardened build with optional login
// Authorized use only: scan only targets you own or have explicit permission to test.

import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';

import { getLatestCVEs, searchCVEs, correlate, getStats } from './src/cve.js';
import { saveReportRow, listReports, reportsBySubject, getReportRow, countReports,
  addSchedule, listSchedules, getDueSchedules, updateScheduleRun, setScheduleEnabled, deleteSchedule } from './src/db.js';
import crypto from 'crypto';
import { scanTarget } from './src/scanner.js';
import { scanFile } from './src/fileScan.js';
import { discoverSubdomains } from './src/discover.js';
import { buildReport, saveReport } from './src/report.js';
import {
  createUser, authenticate, createSession, destroySession, userCount, checkBreached, validatePasswordPolicy,
} from './src/auth.js';
import {
  securityHeaders, cookieParser, setSessionCookie, clearSessionCookie,
  makeRateLimiter, requireAuth, requireAuthPage, requireCsrf, REQUIRE_AUTH,
  isLoopbackHost, localModeGuard,
} from './src/security.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const ALLOW_REGISTRATION = process.env.ALLOW_REGISTRATION !== '0';

// Without login, the platform must never be reachable from the network.
if (!REQUIRE_AUTH && !isLoopbackHost(HOST)) {
  console.error(`\n[VulnScan] Refusing to listen on ${HOST} without authentication.`);
  console.error('[VulnScan] Local mode has no login. To expose VulnScan on a network, set REQUIRE_AUTH=1 (and SECURE_COOKIES=1 behind HTTPS).\n');
  process.exit(1);
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(securityHeaders);
app.use(localModeGuard);
app.use(cookieParser);
app.use(express.json({ limit: '2mb' }));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

// Rate limiters
const loginLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, message: 'Too many login attempts. Try again later.' });
const registerLimiter = makeRateLimiter({ windowMs: 60 * 60 * 1000, max: 5, message: 'Too many registration attempts. Try again later.' });
const scanLimiter = makeRateLimiter({ windowMs: 60 * 1000, max: 20, message: 'Too many scan requests. Please slow down.' });

// ========== Authentication ==========

app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('/api/auth/config', async (req, res) => {
  res.json({ allowRegistration: ALLOW_REGISTRATION, hasUsers: (await userCount()) > 0 });
});

// Live password-strength check (for the UI)
app.post('/api/auth/check-password', registerLimiter, async (req, res) => {
  const { password, username } = req.body || {};
  const policy = validatePasswordPolicy(password || '', username || '');
  let breach = { checked: false, breached: false, count: 0 };
  if (policy.length === 0 && password) breach = await checkBreached(password);
  res.json({ policyErrors: policy, breach });
});

app.post('/api/auth/register', registerLimiter, async (req, res) => {
  if (!ALLOW_REGISTRATION) return res.status(403).json({ error: 'Registration is closed' });
  const { username, password } = req.body || {};
  const result = await createUser(username, password);
  if (!result.ok) return res.status(400).json({ error: result.error });
  // Auto sign-in after creation (with a fresh session)
  const { sid, csrfToken } = createSession(result.user, { ip: req.ip, ua: req.headers['user-agent'] });
  setSessionCookie(res, sid);
  res.json({ ok: true, user: result.user, csrfToken });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const result = await authenticate(username, password);
  if (!result.ok) return res.status(401).json({ error: result.error });
  // Regenerate the session on login (prevents session fixation)
  const { sid, csrfToken } = createSession(result.user, { ip: req.ip, ua: req.headers['user-agent'] });
  setSessionCookie(res, sid);
  res.json({ ok: true, user: result.user, csrfToken });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  destroySession(req.sid);
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({
    user: { username: req.session.username, role: req.session.role },
    csrfToken: req.session.csrfToken,
    authDisabled: !REQUIRE_AUTH,
  });
});

// ========== Scan endpoints (protected) ==========

app.get('/api/cve/latest', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 100, 1000);
    if (req.query.q) {
      const items = searchCVEs(String(req.query.q), limit);
      const stats = getStats();
      return res.json({ source: 'db', total: stats.total, returned: items.length, items, stats });
    }
    const data = await getLatestCVEs({ limit });
    res.json({
      source: data.source, fetchedAt: data.fetchedAt, total: data.count,
      returned: data.items.length, items: data.items, stats: data.stats,
    });
  } catch (e) {
    res.status(502).json({ error: 'Failed to fetch CVEs', message: String(e.message || e) });
  }
});

app.get('/api/cve/stats', requireAuth, (req, res) => {
  try {
    res.json(getStats());
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// Sanitize user-supplied scan headers (for authenticated scanning behind a login)
function sanitizeHeaders(h) {
  const out = {};
  if (!h || typeof h !== 'object') return out;
  let n = 0;
  for (const [k, v] of Object.entries(h)) {
    if (n >= 20) break;
    if (typeof k !== 'string' || typeof v !== 'string') continue;
    if (!/^[A-Za-z0-9-]{1,64}$/.test(k)) continue;           // valid header name only
    if (/^(host|content-length)$/i.test(k)) continue;         // never override these
    out[k] = v.slice(0, 4096);
    n++;
  }
  return out;
}

// Run one target scan and persist the report. Returns { ok, ...result } or { ok:false, error }.
async function runTargetScan(target, { allowPrivate, headers, owner }) {
  const scan = await scanTarget(target, { allowPrivate: !!allowPrivate, headers });
  if (scan.blocked) return { ok: false, error: 'Scan halted (internal/private address)', scan };
  let correlation = [];
  try {
    await getLatestCVEs({ limit: 1 }); // ensures the database is seeded if empty
    correlation = correlate(scan.technologies || []);
  } catch { /* non-fatal */ }
  const report = { ...buildReport({ kind: 'target', scan, correlation }), owner };
  const saved = await saveReport(report);
  saveReportRow(report);
  return { ok: true, scan, report, correlation, saved };
}

app.post('/api/scan/target', requireAuth, requireCsrf, scanLimiter, async (req, res) => {
  const { target, allowPrivate } = req.body || {};
  if (req.body?.authorized !== true) return res.status(403).json({ error: 'Authorization acknowledgment required (authorized: true).' });
  if (!target || typeof target !== 'string') return res.status(400).json({ error: 'Target is required' });
  if (target.length > 2048) return res.status(400).json({ error: 'Target is too long' });
  try {
    const headers = sanitizeHeaders(req.body.headers);
    const r = await runTargetScan(target, { allowPrivate, headers, owner: req.session.username });
    if (!r.ok) return res.status(400).json({ error: r.error, scan: r.scan });
    res.json({ scan: r.scan, report: r.report, correlation: r.correlation, saved: r.saved });
  } catch (e) {
    res.status(500).json({ error: 'Scan failed', message: String(e.message || e) });
  }
});

// Streaming target scan — emits live log events (NDJSON) then a final result.
app.post('/api/scan/target/stream', requireAuth, requireCsrf, scanLimiter, async (req, res) => {
  const { target, allowPrivate } = req.body || {};
  if (req.body?.authorized !== true) return res.status(403).json({ error: 'Authorization acknowledgment required (authorized: true).' });
  if (!target || typeof target !== 'string' || target.length > 2048) return res.status(400).json({ error: 'Invalid target' });
  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no'); // disable proxy buffering so events stream live
  const send = (obj) => { try { res.write(JSON.stringify(obj) + '\n'); } catch { /* client gone */ } };
  try {
    const headers = sanitizeHeaders(req.body.headers);
    // The scanner's own 'done' is held back; the stream emits its final 'done' once the report is saved.
    const scan = await scanTarget(target, { allowPrivate: !!allowPrivate, headers, onLog: (e) => { if (e.phase !== 'done') send({ type: 'log', ...e }); } });
    if (scan.blocked) { send({ type: 'error', message: 'Scan halted: internal/private address' }); return res.end(); }
    let correlation = [];
    try {
      await getLatestCVEs({ limit: 1 });
      correlation = correlate(scan.technologies || []);
      send({ type: 'log', phase: 'cve', message: `CVE correlation: ${correlation.reduce((n, c) => n + c.topMatches.length, 0)} potential match(es)`, t: Date.now() });
    } catch { /* non-fatal */ }
    const report = { ...buildReport({ kind: 'target', scan, correlation }), owner: req.session.username };
    const saved = await saveReport(report);
    saveReportRow(report);
    send({ type: 'log', phase: 'done', message: `Scan complete · ${scan.findings.length} findings · report ${saved.id} saved`, t: Date.now() });
    send({ type: 'result', scan, report, correlation, saved });
  } catch (e) {
    send({ type: 'error', message: String(e.message || e) });
  }
  res.end();
});

// Scan multiple targets (list you own/are authorized to test). Sequential + capped.
app.post('/api/scan/targets', requireAuth, requireCsrf, scanLimiter, async (req, res) => {
  if (req.body?.authorized !== true) return res.status(403).json({ error: 'Authorization acknowledgment required (authorized: true).' });
  let targets = req.body?.targets;
  if (!Array.isArray(targets)) return res.status(400).json({ error: 'targets must be an array' });
  targets = [...new Set(targets.map((t) => String(t).trim()).filter(Boolean))].slice(0, 20);
  if (!targets.length) return res.status(400).json({ error: 'No valid targets' });
  const headers = sanitizeHeaders(req.body.headers);
  const allowPrivate = !!req.body.allowPrivate;
  const results = [];
  for (const target of targets) {
    try {
      const r = await runTargetScan(target, { allowPrivate, headers, owner: req.session.username });
      if (!r.ok) results.push({ target, error: r.error });
      else results.push({ target, id: r.report.id, riskScore: r.report.riskScore, findingsCount: r.report.findingsCount, html: r.saved.html, waf: r.scan.waf });
    } catch (e) {
      results.push({ target, error: String(e.message || e) });
    }
  }
  res.json({ count: results.length, results });
});

// Passive subdomain discovery (certificate transparency via crt.sh)
app.get('/api/discover/subdomains', requireAuth, async (req, res) => {
  const domain = String(req.query.domain || '');
  if (!domain) return res.status(400).json({ error: 'domain is required' });
  try {
    res.json(await discoverSubdomains(domain));
  } catch (e) {
    res.status(502).json({ error: 'Discovery failed', message: String(e.message || e) });
  }
});

// ---- Scheduled scans (run while the server is up) ----
app.get('/api/schedules', requireAuth, (req, res) => {
  try { res.json({ schedules: listSchedules() }); } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.post('/api/schedules', requireAuth, requireCsrf, (req, res) => {
  const { target, intervalMin, allowPrivate } = req.body || {};
  if (req.body?.authorized !== true) return res.status(403).json({ error: 'Authorization acknowledgment required (authorized: true).' });
  if (!target || typeof target !== 'string' || target.length > 2048) return res.status(400).json({ error: 'Invalid target' });
  const iv = Math.max(5, Math.min(Number(intervalMin) || 0, 40320)); // 5 minutes .. 4 weeks
  if (!Number(intervalMin)) return res.status(400).json({ error: 'Invalid interval' });
  try {
    const headers = sanitizeHeaders(req.body.headers);
    const s = addSchedule({
      id: 'SCH-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
      target, headers, allowPrivate: !!allowPrivate, intervalMin: iv,
      nextRun: Date.now() + iv * 60000, owner: req.session.username,
    });
    res.json({ ok: true, schedule: s });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.post('/api/schedules/:id/toggle', requireAuth, requireCsrf, (req, res) => {
  const enabled = req.body?.enabled !== false;
  const n = setScheduleEnabled(req.params.id, enabled);
  if (!n) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true, enabled });
});

app.delete('/api/schedules/:id', requireAuth, requireCsrf, (req, res) => {
  const n = deleteSchedule(req.params.id);
  if (!n) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

app.post('/api/scan/file', requireAuth, requireCsrf, scanLimiter, upload.single('file'), async (req, res) => {
  if (req.body?.authorized !== 'true' && req.body?.authorized !== true) {
    return res.status(403).json({ error: 'Authorization acknowledgment required (authorized=true).' });
  }
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const scan = await scanFile({ filename: req.file.originalname, buffer: req.file.buffer });
    const report = { ...buildReport({ kind: 'file', scan }), owner: req.session.username };
    const saved = await saveReport(report);
    saveReportRow(report);
    res.json({ scan, report, saved });
  } catch (e) {
    res.status(500).json({ error: 'File scan failed', message: String(e.message || e) });
  }
});

// Reports list (DB-backed, paginated). Query: ?limit=&offset=&subject=
app.get('/api/reports', requireAuth, (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 20, 100);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const subject = req.query.subject ? String(req.query.subject) : null;
    res.json(listReports({ limit, offset, subject }));
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// History diff: compare the two most recent reports for the same target.
// Query: ?subject=<target>  (or ?a=<reportId>&b=<reportId>)
app.get('/api/reports/diff', requireAuth, (req, res) => {
  try {
    let a, b;
    if (req.query.a && req.query.b) {
      a = getReportRow(String(req.query.a));
      b = getReportRow(String(req.query.b));
    } else if (req.query.subject) {
      const hist = reportsBySubject(String(req.query.subject), 2); // newest first
      b = hist[1]; // older
      a = hist[0]; // newer
    }
    if (!a || !b) return res.status(404).json({ error: 'Need two reports to diff (same target, or a & b ids).' });

    const key = (f) => `${f.type}|${f.title}|${f.evidence}`;
    const aKeys = new Set((a.findings || []).map(key));
    const bKeys = new Set((b.findings || []).map(key));
    const added = (a.findings || []).filter((f) => !bKeys.has(key(f)));   // new in the newer report
    const resolved = (b.findings || []).filter((f) => !aKeys.has(key(f))); // present before, gone now

    res.json({
      newer: { id: a.id, generatedAt: a.generatedAt, riskScore: a.riskScore, findingsCount: a.findingsCount },
      older: { id: b.id, generatedAt: b.generatedAt, riskScore: b.riskScore, findingsCount: b.findingsCount },
      riskDelta: (a.riskScore || 0) - (b.riskScore || 0),
      added, resolved,
      addedCount: added.length, resolvedCount: resolved.length,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// ========== Pages and static files ==========

// Reports are auth-protected (may contain scan data)
app.use('/reports', requireAuthPage, express.static(path.join(__dirname, 'reports')));

// The home page is protected — redirects to login when not authenticated
app.get(['/', '/index.html'], requireAuthPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Remaining public assets (CSS/JS/login page)
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// One-time migration: import any existing report files into the DB (history continuity)
(async function migrateReportsToDb() {
  try {
    if (countReports() > 0) return;
    const dir = path.join(__dirname, 'reports');
    const files = (await fs.readdir(dir).catch(() => [])).filter((f) => f.endsWith('.json'));
    for (const f of files) {
      try { const r = JSON.parse(await fs.readFile(path.join(dir, f), 'utf8')); if (r.id) saveReportRow(r); } catch { /* */ }
    }
  } catch { /* */ }
})();

// Scheduler: every minute, run any due scheduled scans (sequentially). Only while the server runs.
let schedulerBusy = false;
async function tickScheduler() {
  if (schedulerBusy) return;
  schedulerBusy = true;
  try {
    for (const s of getDueSchedules(Date.now())) {
      const next = Date.now() + s.intervalMin * 60000;
      try {
        const r = await runTargetScan(s.target, { allowPrivate: s.allowPrivate, headers: s.headers, owner: s.owner || 'scheduler' });
        updateScheduleRun(s.id, { lastRun: Date.now(), nextRun: next, lastReportId: r.ok ? r.report.id : s.lastReportId });
        console.log(`[VulnScan] Scheduled scan: ${s.target} -> ${r.ok ? r.report.id : 'failed'}`);
      } catch (e) {
        updateScheduleRun(s.id, { lastRun: Date.now(), nextRun: next, lastReportId: s.lastReportId });
        console.error('[VulnScan] Scheduled scan error:', e.message);
      }
    }
  } finally { schedulerBusy = false; }
}
setInterval(tickScheduler, 60000).unref();

// JSON 404 for unknown API routes
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

// Global error handler — never leak stack traces to clients
app.use((err, req, res, next) => {
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  console.error('[VulnScan] Unhandled error:', err?.message || err);
  if (res.headersSent) return next(err);
  res.status(err?.status || 500).json({ error: 'Internal server error' });
});

// Keep the process alive on unexpected errors (log, do not crash)
process.on('unhandledRejection', (r) => console.error('[VulnScan] Unhandled rejection:', r?.message || r));
process.on('uncaughtException', (e) => console.error('[VulnScan] Uncaught exception:', e?.message || e));

const server = app.listen(PORT, HOST, () => {
  console.log(`\n[VulnScan] Server running at: http://localhost:${PORT}`);
  console.log('[VulnScan] Authorized use only - scan only what you own or are permitted to test.\n');
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n[VulnScan] Port ${PORT} is already in use - the app is probably already running.`);
    console.error(`[VulnScan] Just open your browser at: http://localhost:${PORT}\n`);
  } else {
    console.error('[VulnScan] Server error:', err.message);
  }
  process.exit(1);
});
