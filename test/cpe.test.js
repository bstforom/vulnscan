import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCPE, compareVersions, versionInRange } from '../src/cpe.js';

test('parseCPE extracts vendor/product/version', () => {
  const p = parseCPE('cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*');
  assert.equal(p.part, 'a');
  assert.equal(p.vendor, 'nginx');
  assert.equal(p.product, 'nginx');
  assert.equal(p.version, '1.18.0');
});

test('parseCPE returns null for invalid input', () => {
  assert.equal(parseCPE('not-a-cpe'), null);
  assert.equal(parseCPE(''), null);
  assert.equal(parseCPE(null), null);
});

test('compareVersions orders versions correctly', () => {
  assert.equal(compareVersions('1.0.0', '1.0.1'), -1);
  assert.equal(compareVersions('2.0', '1.9.9'), 1);
  assert.equal(compareVersions('1.2.3', '1.2.3'), 0);
  assert.equal(compareVersions('1.0', '1.0.0'), -1); // shorter is smaller
  assert.equal(compareVersions('1.0.0', '1.0.0-rc'), 1); // release > pre-release
});

test('versionInRange: version inside end-exclusive range matches', () => {
  const r = versionInRange('22.0', { versionEndExcluding: '22.23.0' });
  assert.equal(r.match, true);
  assert.equal(r.confidence, 'range');
});

test('versionInRange: version outside range does not match', () => {
  const r = versionInRange('99999', { versionEndExcluding: '22.23.0' });
  assert.equal(r.match, false);
});

test('versionInRange: exact version match', () => {
  assert.equal(versionInRange('1.18.0', { exact: '1.18.0' }).match, true);
  assert.equal(versionInRange('1.18.1', { exact: '1.18.0' }).match, false);
});

test('versionInRange: no detected version + ranged CVE = no false positive', () => {
  const r = versionInRange(null, { versionEndExcluding: '2.0' });
  assert.equal(r.match, false);
});
