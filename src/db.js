// src/db.js
// SQLite database layer (node:sqlite) with FTS5 indexing — handles 100k+ CVEs quickly.
// Running the program requires the flag: node --experimental-sqlite

import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { parseCPE } from './cpe.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.VULNSCAN_DB || path.join(__dirname, '..', 'data', 'vulnscan.db');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA synchronous = NORMAL');
db.exec('PRAGMA foreign_keys = ON');

// ---- Schema ----
db.exec(`
CREATE TABLE IF NOT EXISTS cve (
  rid           INTEGER PRIMARY KEY,
  id            TEXT UNIQUE NOT NULL,
  published     TEXT,
  lastModified  TEXT,
  cvss_score    REAL,
  cvss_severity TEXT,
  cvss_vector   TEXT,
  cwe           TEXT,
  description   TEXT,
  refs          TEXT,
  products      TEXT,
  kev           INTEGER DEFAULT 0,
  epss          REAL,
  data          TEXT
);
CREATE INDEX IF NOT EXISTS idx_cve_published ON cve(published DESC);
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve(kev);

CREATE TABLE IF NOT EXISTS cpe (
  cve_id             TEXT NOT NULL,
  part               TEXT,
  vendor             TEXT,
  product            TEXT,
  exact_version      TEXT,
  version_start_incl TEXT,
  version_start_excl TEXT,
  version_end_incl   TEXT,
  version_end_excl   TEXT,
  vulnerable         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe(product);
CREATE INDEX IF NOT EXISTS idx_cpe_cveid ON cpe(cve_id);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS report (
  id             TEXT PRIMARY KEY,
  kind           TEXT,
  subject        TEXT,
  risk_score     INTEGER,
  findings_count INTEGER,
  generated_at   TEXT,
  owner          TEXT,
  summary        TEXT,
  data           TEXT
);
CREATE INDEX IF NOT EXISTS idx_report_subject ON report(subject);
CREATE INDEX IF NOT EXISTS idx_report_generated ON report(generated_at DESC);

CREATE TABLE IF NOT EXISTS schedule (
  id             TEXT PRIMARY KEY,
  target         TEXT NOT NULL,
  headers        TEXT,
  allow_private  INTEGER DEFAULT 0,
  interval_min   INTEGER NOT NULL,
  next_run       INTEGER,
  last_run       INTEGER,
  last_report_id TEXT,
  enabled        INTEGER DEFAULT 1,
  owner          TEXT,
  created_at     TEXT
);
`);

// FTS5 with external content linked to the cve table (synced via triggers)
db.exec(`
CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
  description, products, content='cve', content_rowid='rid'
);
CREATE TRIGGER IF NOT EXISTS cve_ai AFTER INSERT ON cve BEGIN
  INSERT INTO cve_fts(rowid, description, products) VALUES (new.rid, new.description, new.products);
END;
CREATE TRIGGER IF NOT EXISTS cve_ad AFTER DELETE ON cve BEGIN
  INSERT INTO cve_fts(cve_fts, rowid, description, products) VALUES('delete', old.rid, old.description, old.products);
END;
CREATE TRIGGER IF NOT EXISTS cve_au AFTER UPDATE ON cve BEGIN
  INSERT INTO cve_fts(cve_fts, rowid, description, products) VALUES('delete', old.rid, old.description, old.products);
  INSERT INTO cve_fts(rowid, description, products) VALUES (new.rid, new.description, new.products);
END;
`);

// ---- Prepared statements ----
const stmtUpsert = db.prepare(`
INSERT INTO cve (id, published, lastModified, cvss_score, cvss_severity, cvss_vector, cwe, description, refs, products, data)
VALUES (@id, @published, @lastModified, @cvss_score, @cvss_severity, @cvss_vector, @cwe, @description, @refs, @products, @data)
ON CONFLICT(id) DO UPDATE SET
  published=@published, lastModified=@lastModified, cvss_score=@cvss_score, cvss_severity=@cvss_severity,
  cvss_vector=@cvss_vector, cwe=@cwe, description=@description, refs=@refs, products=@products, data=@data
`);
const stmtDelCpe = db.prepare('DELETE FROM cpe WHERE cve_id = ?');
const stmtInsCpe = db.prepare(`
INSERT INTO cpe (cve_id, part, vendor, product, exact_version, version_start_incl, version_start_excl, version_end_incl, version_end_excl, vulnerable)
VALUES (@cve_id, @part, @vendor, @product, @exact_version, @version_start_incl, @version_start_excl, @version_end_incl, @version_end_excl, @vulnerable)
`);

function upsertOne(item) {
  stmtUpsert.run({
    id: item.id,
    published: item.published || null,
    lastModified: item.lastModified || null,
    cvss_score: item.cvss?.score ?? null,
    cvss_severity: item.cvss?.severity || 'UNKNOWN',
    cvss_vector: item.cvss?.vector || null,
    cwe: JSON.stringify(item.cwe || []),
    description: item.description || '',
    refs: JSON.stringify(item.references || []),
    products: (item.products || []).join(' '),
    data: JSON.stringify(item),
  });
  stmtDelCpe.run(item.id);
  for (const cm of item.cpes || []) {
    const parsed = parseCPE(cm.criteria) || {};
    stmtInsCpe.run({
      cve_id: item.id,
      part: parsed.part || null,
      vendor: parsed.vendor || null,
      product: parsed.product || null,
      exact_version: parsed.version || null,
      version_start_incl: cm.versionStartIncluding || null,
      version_start_excl: cm.versionStartExcluding || null,
      version_end_incl: cm.versionEndIncluding || null,
      version_end_excl: cm.versionEndExcluding || null,
      vulnerable: cm.vulnerable ? 1 : 0,
    });
  }
}

// Insert a batch in a single transaction (high performance for large volumes)
export function upsertMany(items) {
  db.exec('BEGIN');
  try {
    for (const it of items) if (it && it.id) upsertOne(it);
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
  return items.length;
}

export function getStats() {
  const total = db.prepare('SELECT COUNT(*) n FROM cve').get().n;
  const kev = db.prepare('SELECT COUNT(*) n FROM cve WHERE kev=1').get().n;
  const latest = db.prepare('SELECT published FROM cve ORDER BY published DESC LIMIT 1').get();
  const sev = {};
  for (const r of db.prepare('SELECT cvss_severity s, COUNT(*) n FROM cve GROUP BY cvss_severity').all()) sev[r.s] = r.n;
  return {
    total,
    kev,
    latestPublished: latest?.published || null,
    severities: sev,
    lastImport: getMeta('lastImport'),
    cpeRows: db.prepare('SELECT COUNT(*) n FROM cpe').get().n,
  };
}

function rowToCVE(row) {
  try {
    return JSON.parse(row.data);
  } catch {
    return {
      id: row.id, published: row.published, description: row.description,
      cvss: { score: row.cvss_score, severity: row.cvss_severity, vector: row.cvss_vector },
      cwe: JSON.parse(row.cwe || '[]'), products: (row.products || '').split(' '), references: JSON.parse(row.refs || '[]'),
    };
  }
}

export function getLatest(limit = 100) {
  const rows = db.prepare('SELECT * FROM cve ORDER BY published DESC LIMIT ?').all(limit);
  return rows.map((r) => ({ ...rowToCVE(r), kev: !!r.kev, epss: r.epss }));
}

// Sanitize the FTS query of characters that could break the syntax
function sanitizeFTS(q) {
  const cleaned = String(q).replace(/["']/g, ' ').replace(/[^\p{L}\p{N}\s.\-_]/gu, ' ').trim();
  if (!cleaned) return null;
  // each word as a prefix for flexible search
  return cleaned.split(/\s+/).map((t) => `"${t}"*`).join(' ');
}

export function search(query, limit = 150) {
  const m = sanitizeFTS(query);
  if (!m) return getLatest(limit);
  try {
    const rows = db.prepare(`
      SELECT cve.* FROM cve_fts
      JOIN cve ON cve.rid = cve_fts.rowid
      WHERE cve_fts MATCH ?
      ORDER BY cve.published DESC LIMIT ?
    `).all(m, limit);
    return rows.map((r) => ({ ...rowToCVE(r), kev: !!r.kev, epss: r.epss }));
  } catch {
    // on syntax failure, fall back to a simple LIKE search
    const like = `%${String(query).toLowerCase()}%`;
    const rows = db.prepare('SELECT * FROM cve WHERE lower(description) LIKE ? OR lower(id) LIKE ? ORDER BY published DESC LIMIT ?').all(like, like, limit);
    return rows.map((r) => ({ ...rowToCVE(r), kev: !!r.kev, epss: r.epss }));
  }
}

// Fetch CPE rows for a given product (for precise version matching)
export function getCpeByProduct(product) {
  return db.prepare(`
    SELECT c.*, v.cvss_score, v.cvss_severity, v.description, v.published, v.kev, v.epss
    FROM cpe c JOIN cve v ON v.id = c.cve_id
    WHERE c.product = ? AND c.vulnerable = 1
  `).all(String(product).toLowerCase());
}

// Search for partially matching products (fallback when the name does not match exactly)
export function getCpeByProductLike(product) {
  const like = `%${String(product).toLowerCase()}%`;
  return db.prepare(`
    SELECT c.*, v.cvss_score, v.cvss_severity, v.description, v.published, v.kev, v.epss
    FROM cpe c JOIN cve v ON v.id = c.cve_id
    WHERE c.product LIKE ? AND c.vulnerable = 1 LIMIT 4000
  `).all(like);
}

export function markKev(ids) {
  if (!ids || !ids.length) return 0;
  const stmt = db.prepare('UPDATE cve SET kev=1 WHERE id = ?');
  db.exec('BEGIN');
  let n = 0;
  try {
    for (const id of ids) n += stmt.run(id).changes;
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
  return n;
}

export function setEpss(map) {
  const stmt = db.prepare('UPDATE cve SET epss=? WHERE id=?');
  db.exec('BEGIN');
  let n = 0;
  try {
    for (const [id, score] of map) n += stmt.run(score, id).changes;
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
  return n;
}

export function getMeta(key) {
  const r = db.prepare('SELECT value FROM meta WHERE key=?').get(key);
  return r ? r.value : null;
}
export function setMeta(key, value) {
  db.prepare('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=?').run(key, String(value), String(value));
}

export function count() {
  return db.prepare('SELECT COUNT(*) n FROM cve').get().n;
}

// ---- Reports ----
const stmtSaveReport = db.prepare(`
INSERT INTO report (id, kind, subject, risk_score, findings_count, generated_at, owner, summary, data)
VALUES (@id, @kind, @subject, @risk_score, @findings_count, @generated_at, @owner, @summary, @data)
ON CONFLICT(id) DO UPDATE SET
  kind=@kind, subject=@subject, risk_score=@risk_score, findings_count=@findings_count,
  generated_at=@generated_at, owner=@owner, summary=@summary, data=@data
`);

export function saveReportRow(report) {
  stmtSaveReport.run({
    id: report.id,
    kind: report.kind,
    subject: report.subject,
    risk_score: report.riskScore,
    findings_count: report.findingsCount,
    generated_at: report.generatedAt,
    owner: report.owner || null,
    summary: JSON.stringify(report.summary || {}),
    data: JSON.stringify(report),
  });
}

function reportRowToMeta(r) {
  return { id: r.id, kind: r.kind, subject: r.subject, riskScore: r.risk_score, findingsCount: r.findings_count, generatedAt: r.generated_at, owner: r.owner, html: `/reports/${r.id}.html` };
}

export function listReports({ limit = 20, offset = 0, subject = null } = {}) {
  let total, rows;
  if (subject) {
    total = db.prepare('SELECT COUNT(*) n FROM report WHERE subject = ?').get(subject).n;
    rows = db.prepare('SELECT id, kind, subject, risk_score, findings_count, generated_at, owner FROM report WHERE subject = ? ORDER BY generated_at DESC LIMIT ? OFFSET ?').all(subject, limit, offset);
  } else {
    total = db.prepare('SELECT COUNT(*) n FROM report').get().n;
    rows = db.prepare('SELECT id, kind, subject, risk_score, findings_count, generated_at, owner FROM report ORDER BY generated_at DESC LIMIT ? OFFSET ?').all(limit, offset);
  }
  return { total, reports: rows.map(reportRowToMeta) };
}

export function getReportRow(id) {
  const r = db.prepare('SELECT data FROM report WHERE id = ?').get(id);
  if (!r) return null;
  try { return JSON.parse(r.data); } catch { return null; }
}

export function reportsBySubject(subject, limit = 10) {
  const rows = db.prepare('SELECT data FROM report WHERE subject = ? ORDER BY generated_at DESC LIMIT ?').all(subject, limit);
  return rows.map((r) => { try { return JSON.parse(r.data); } catch { return null; } }).filter(Boolean);
}

export function countReports() {
  return db.prepare('SELECT COUNT(*) n FROM report').get().n;
}

// ---- Scheduled scans ----
function safeParse(s) { try { return JSON.parse(s); } catch { return {}; } }
function rowToSchedule(r) {
  return { id: r.id, target: r.target, headers: safeParse(r.headers), allowPrivate: !!r.allow_private, intervalMin: r.interval_min, nextRun: r.next_run, lastRun: r.last_run, lastReportId: r.last_report_id, enabled: !!r.enabled, owner: r.owner, createdAt: r.created_at };
}

export function addSchedule(s) {
  db.prepare(`INSERT INTO schedule (id, target, headers, allow_private, interval_min, next_run, last_run, last_report_id, enabled, owner, created_at)
    VALUES (@id, @target, @headers, @allow_private, @interval_min, @next_run, NULL, NULL, 1, @owner, @created_at)`).run({
    id: s.id, target: s.target, headers: JSON.stringify(s.headers || {}), allow_private: s.allowPrivate ? 1 : 0,
    interval_min: s.intervalMin, next_run: s.nextRun, owner: s.owner || null, created_at: new Date().toISOString(),
  });
  return getSchedule(s.id);
}
export function getSchedule(id) {
  const r = db.prepare('SELECT * FROM schedule WHERE id=?').get(id);
  return r ? rowToSchedule(r) : null;
}
export function listSchedules() {
  return db.prepare('SELECT * FROM schedule ORDER BY created_at DESC').all().map(rowToSchedule);
}
export function getDueSchedules(now) {
  return db.prepare('SELECT * FROM schedule WHERE enabled=1 AND next_run<=?').all(now).map(rowToSchedule);
}
export function updateScheduleRun(id, { lastRun, nextRun, lastReportId }) {
  db.prepare('UPDATE schedule SET last_run=?, next_run=?, last_report_id=? WHERE id=?').run(lastRun, nextRun, lastReportId, id);
}
export function setScheduleEnabled(id, enabled) {
  return db.prepare('UPDATE schedule SET enabled=? WHERE id=?').run(enabled ? 1 : 0, id).changes;
}
export function deleteSchedule(id) {
  return db.prepare('DELETE FROM schedule WHERE id=?').run(id).changes;
}

export default db;
