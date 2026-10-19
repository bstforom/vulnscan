// scripts/import-cve.js
// Bulk CVE importer from NVD into the SQLite database (supports 100k+).
// Run:  node --experimental-sqlite scripts/import-cve.js
// Env:  TARGET=100000  NVD_API_KEY=xxxx  EPSS=1
//
// Pulls in 120-day windows (NVD limit) from newest to oldest, respecting the rate limit
// and supporting resume, then merges the CISA KEV list (actively exploited vulnerabilities)
// and optionally EPSS scores.

import zlib from 'zlib';
import * as store from '../src/db.js';
import { nvdDate, normalize, fetchPage } from '../src/nvd.js';

const TARGET = parseInt(process.env.TARGET || '100000', 10);
const API_KEY = process.env.NVD_API_KEY || null;
const WINDOW_DAYS = 120;
const PER_PAGE = 2000;
const DELAY_MS = API_KEY ? 650 : 6200;         // NVD limit: 50/30s with a key, 5/30s without
const EARLIEST = new Date('1999-01-01T00:00:00.000');
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchWithRetry(params, tries = 5) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      return await fetchPage(params, API_KEY);
    } catch (e) {
      lastErr = e;
      const wait = Math.min(60000, DELAY_MS * Math.pow(2, i));
      process.stdout.write(`\n  !  ${e.message} — retrying in ${Math.round(wait / 1000)}s (${i + 1}/${tries})`);
      await sleep(wait);
    }
  }
  throw lastErr;
}

async function importCVEs() {
  console.log(`\n[DB] Importing CVEs from NVD — target: ${TARGET.toLocaleString('en')} | API key: ${API_KEY ? 'yes' : 'no (slower)'}`);
  console.log(`   Starting from a database with ${store.count().toLocaleString('en')} CVEs.\n`);

  // Resume: start from the saved cursor if present (the oldest point reached)
  const cursor = store.getMeta('importCursor');
  let end = cursor ? new Date(cursor) : new Date();
  let windows = 0;

  while (store.count() < TARGET && end > EARLIEST) {
    const start = new Date(Math.max(end.getTime() - WINDOW_DAYS * 864e5, EARLIEST.getTime()));
    windows++;
    let startIndex = 0;
    let total = 0;
    let fetchedInWindow = 0;

    do {
      const params = new URLSearchParams({
        pubStartDate: nvdDate(start),
        pubEndDate: nvdDate(end),
        resultsPerPage: String(PER_PAGE),
        startIndex: String(startIndex),
      });
      const data = await fetchWithRetry(params);
      total = data.totalResults || 0;
      const batch = (data.vulnerabilities || []).map(normalize).filter((c) => c.id);
      if (batch.length) store.upsertMany(batch);
      fetchedInWindow += batch.length;
      startIndex += PER_PAGE;

      const nowCount = store.count();
      process.stdout.write(
        `\r  Window ${windows} [${start.toISOString().slice(0, 10)} -> ${end.toISOString().slice(0, 10)}] ` +
        `page ${Math.ceil(startIndex / PER_PAGE)} | total in DB: ${nowCount.toLocaleString('en')}   `
      );

      if (nowCount >= TARGET) break;
      if (startIndex < total) await sleep(DELAY_MS);
    } while (startIndex < total);

    // Advance the cursor to the older window
    end = start;
    store.setMeta('importCursor', end.toISOString());
    store.setMeta('lastImport', new Date().toISOString());
    store.setMeta('seed', 'false');
    console.log(`\n  OK Window ${windows}: +${fetchedInWindow.toLocaleString('en')} (of ${total.toLocaleString('en')})`);
    if (store.count() >= TARGET) break;
    await sleep(DELAY_MS);
  }

  console.log(`\n[OK] CVE import finished. Total: ${store.count().toLocaleString('en')}\n`);
}

async function importKEV() {
  try {
    console.log('[KEV] Downloading the CISA KEV list (actively exploited vulnerabilities)...');
    const res = await fetch(KEV_URL, { signal: AbortSignal.timeout(30000), headers: { 'User-Agent': 'VulnScan-Platform/1.0' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const ids = (data.vulnerabilities || []).map((v) => v.cveID).filter(Boolean);
    const n = store.markKev(ids);
    console.log(`   OK KEV: ${ids.length.toLocaleString('en')} in the list, ${n.toLocaleString('en')} matched in our database.\n`);
  } catch (e) {
    console.log(`   ! Could not download KEV: ${e.message}\n`);
  }
}

async function importEPSS() {
  if (process.env.EPSS !== '1') return;
  try {
    console.log('[EPSS] Downloading EPSS scores (exploitation probability)...');
    const res = await fetch(EPSS_URL, { signal: AbortSignal.timeout(60000), headers: { 'User-Agent': 'VulnScan-Platform/1.0' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    const csv = zlib.gunzipSync(buf).toString('utf8');
    const map = [];
    for (const line of csv.split('\n')) {
      if (!line || line.startsWith('#') || line.startsWith('cve')) continue;
      const [cve, epss] = line.split(',');
      if (cve && epss) map.push([cve.trim(), parseFloat(epss)]);
    }
    const n = store.setEpss(map);
    console.log(`   OK EPSS: ${map.length.toLocaleString('en')} scores, ${n.toLocaleString('en')} updated in our database.\n`);
  } catch (e) {
    console.log(`   ! Could not download EPSS: ${e.message}\n`);
  }
}

(async () => {
  const t0 = Date.now();
  await importCVEs();
  await importKEV();
  await importEPSS();
  const stats = store.getStats();
  console.log('[STATS] Final statistics:');
  console.log(`   Total CVEs: ${stats.total.toLocaleString('en')}`);
  console.log(`   Actively exploited (KEV): ${stats.kev.toLocaleString('en')}`);
  console.log(`   CPE match rows: ${stats.cpeRows.toLocaleString('en')}`);
  console.log(`   Severity:`, stats.severities);
  console.log(`   Time: ${Math.round((Date.now() - t0) / 1000)}s\n`);
  process.exit(0);
})();
