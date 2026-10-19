// src/cve.js
// CVE interface over the SQLite database: fetch latest, FTS search, and precise CPE version matching.

import * as store from './db.js';
import { nvdDate, normalize, fetchPage } from './nvd.js';
import { versionInRange } from './cpe.js';

const FRESH_DAYS = 4;              // window for the light top-up of the latest CVEs
const TOPUP_THROTTLE_MS = 30 * 60 * 1000; // do not repeat the light top-up more than once every 30 minutes

let topping = null;
let lastTopUp = 0;

// Light top-up: ensures the latest CVEs exist (empty DB, or newest older than ~36 hours).
// The full import remains via: npm run import
async function ensureFreshTop() {
  const empty = store.count() === 0;
  const latest = store.getStats().latestPublished;
  const stale = !latest || Date.now() - new Date(latest).getTime() > 36 * 3600 * 1000;
  if (!empty && !stale) return;
  if (Date.now() - lastTopUp < TOPUP_THROTTLE_MS && !empty) return;
  if (topping) return topping;

  topping = (async () => {
    try {
      const end = new Date();
      const start = new Date(end.getTime() - FRESH_DAYS * 864e5);
      const collected = [];
      let startIndex = 0;
      for (let i = 0; i < 3; i++) {
        const params = new URLSearchParams({
          pubStartDate: nvdDate(start), pubEndDate: nvdDate(end),
          resultsPerPage: '2000', startIndex: String(startIndex),
        });
        const data = await fetchPage(params, process.env.NVD_API_KEY);
        const vulns = (data.vulnerabilities || []).map(normalize).filter((c) => c.id);
        collected.push(...vulns);
        startIndex += 2000;
        if (startIndex >= (data.totalResults || 0)) break;
        await new Promise((r) => setTimeout(r, process.env.NVD_API_KEY ? 700 : 6500));
      }
      if (collected.length) {
        store.upsertMany(collected);
        store.setMeta('lastImport', new Date().toISOString());
        if (empty) store.setMeta('seed', 'true');
      }
      lastTopUp = Date.now();
    } finally {
      topping = null;
    }
  })();
  return topping;
}

// Latest CVEs (compatible with the previous interface)
export async function getLatestCVEs({ force = false, limit = 1000 } = {}) {
  await ensureFreshTop();
  const stats = store.getStats();
  const items = store.getLatest(limit);
  return {
    source: store.getMeta('seed') === 'true' && stats.total < 5000 ? 'seed' : 'db',
    fetchedAt: stats.lastImport ? new Date(stats.lastImport).getTime() : Date.now(),
    count: stats.total,
    items,
    stats,
  };
}

export function searchCVEs(query, limit = 150) {
  return store.search(query, limit);
}

export function getStats() {
  return store.getStats();
}

// Precise matching: for each technology (product + version) search the CPE table and verify the version is in range
export function correlate(technologies) {
  const results = [];
  for (const tech of technologies) {
    const name = (tech.name || '').toLowerCase().replace(/\s+/g, '_');
    if (!name) continue;
    const version = tech.version || null;

    // Primary match by exact product name, then partial as a fallback
    let rows = store.getCpeByProduct(name);
    if (!rows.length) rows = store.getCpeByProductLike(name).filter((r) => (r.product || '').includes(name) || name.includes(r.product || ''));

    const matched = new Map(); // cve_id -> { ...cve, confidence }
    for (const r of rows) {
      const verdict = versionInRange(version, {
        exact: r.exact_version,
        versionStartIncluding: r.version_start_incl,
        versionStartExcluding: r.version_start_excl,
        versionEndIncluding: r.version_end_incl,
        versionEndExcluding: r.version_end_excl,
      });
      if (!verdict.match) continue;
      const existing = matched.get(r.cve_id);
      const rank = { exact: 3, range: 2, product: 1 }[verdict.confidence] || 0;
      if (!existing || rank > existing._rank) {
        matched.set(r.cve_id, {
          id: r.cve_id,
          score: r.cvss_score,
          severity: r.cvss_severity,
          description: (r.description || '').slice(0, 240),
          published: r.published,
          kev: !!r.kev,
          epss: r.epss,
          confidence: verdict.confidence,
          _rank: rank,
        });
      }
    }

    if (matched.size) {
      const list = [...matched.values()].sort((a, b) => {
        // Priority: KEV, then confidence, then CVSS
        if (a.kev !== b.kev) return a.kev ? -1 : 1;
        if (a._rank !== b._rank) return b._rank - a._rank;
        return (b.score || 0) - (a.score || 0);
      });
      results.push({
        technology: tech,
        matchCount: list.length,
        // With a version: keep only exact/range matches (avoid weak product-wide matches)
        topMatches: (version ? list.filter((m) => m.confidence !== 'product') : list).slice(0, 12),
      });
    }
  }
  return results;
}
