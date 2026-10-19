import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectManifest, scanFile } from '../src/fileScan.js';

test('detectManifest recognizes known manifests', () => {
  assert.equal(detectManifest('package.json'), 'package.json');
  assert.equal(detectManifest('/a/b/yarn.lock'), 'yarn.lock');
  assert.equal(detectManifest('MyApp.csproj'), '.csproj');
  assert.equal(detectManifest('random.txt'), null);
});

test('scanFile on a source file finds secrets and SAST issues (no network)', async () => {
  const content = [
    'const KEY = "AKIAIOSFODNN7EXAMPLE";',
    'db.query("SELECT * FROM u WHERE id=" + id);',
    'eval(userInput);',
  ].join('\n');
  const result = await scanFile({ filename: 'app.js', buffer: Buffer.from(content) });
  const types = new Set(result.findings.map((f) => f.type));
  assert.ok(types.has('secret'));
  assert.ok(types.has('sast'));
  assert.ok(result.sha256.length === 64);
});

test('scanFile computes hash and type for a plain text file', async () => {
  const result = await scanFile({ filename: 'notes.txt', buffer: Buffer.from('hello world') });
  assert.ok(result.sha256);
  assert.ok(/Text|Source/.test(result.fileType));
});
