import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fingerprint } from '../src/fingerprint.js';

test('detects nginx with version from server header', () => {
  const t = fingerprint({ headers: { server: 'nginx/1.18.0' }, body: '', cookies: [] });
  const nginx = t.find((x) => x.name === 'nginx');
  assert.ok(nginx);
  assert.equal(nginx.version, '1.18.0');
});

test('detects WordPress from body', () => {
  const t = fingerprint({ headers: {}, body: '<link href="/wp-content/themes/x/style.css">', cookies: [] });
  assert.ok(t.some((x) => x.name === 'wordpress'));
});

test('detects framework from cookie', () => {
  const t = fingerprint({ headers: {}, body: '', cookies: ['PHPSESSID=abc'] });
  assert.ok(t.some((x) => x.name === 'php'));
});

test('returns empty array when nothing matches', () => {
  assert.deepEqual(fingerprint({ headers: {}, body: '', cookies: [] }), []);
});
