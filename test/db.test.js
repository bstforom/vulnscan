import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

// Use an isolated temp database — must be set BEFORE importing db.js
process.env.VULNSCAN_DB = path.join(os.tmpdir(), `vulnscan-test-${crypto.randomBytes(4).toString('hex')}.db`);

const store = await import('../src/db.js');
const { correlate } = await import('../src/cve.js');

const fakeCVE = {
  id: 'CVE-2099-0001',
  published: '2099-01-01T00:00:00.000',
  lastModified: '2099-01-01T00:00:00.000',
  description: 'Remote code execution in testprod before 2.0',
  cvss: { score: 9.8, severity: 'CRITICAL', vector: null },
  products: ['testvendor:testprod'],
  cpes: [{ criteria: 'cpe:2.3:a:testvendor:testprod:*:*:*:*:*:*:*:*', vulnerable: true, versionEndExcluding: '2.0' }],
  references: [],
  cwe: ['CWE-94'],
};

test('upsertMany + getStats + getLatest', () => {
  store.upsertMany([fakeCVE]);
  const stats = store.getStats();
  assert.ok(stats.total >= 1);
  const latest = store.getLatest(10);
  assert.ok(latest.some((c) => c.id === 'CVE-2099-0001'));
});

test('FTS search finds the CVE by product name', () => {
  const results = store.search('testprod', 10);
  assert.ok(results.some((c) => c.id === 'CVE-2099-0001'));
});

test('getCpeByProduct returns the vulnerable CPE row', () => {
  const rows = store.getCpeByProduct('testprod');
  assert.ok(rows.length >= 1);
  assert.equal(rows[0].version_end_excl, '2.0');
});

test('correlate matches version inside range, not outside', () => {
  const inside = correlate([{ name: 'testprod', version: '1.5' }]);
  assert.ok(inside.some((g) => g.topMatches.some((m) => m.id === 'CVE-2099-0001')));

  const outside = correlate([{ name: 'testprod', version: '3.0' }]);
  assert.ok(!outside.some((g) => g.topMatches.some((m) => m.id === 'CVE-2099-0001')));
});
