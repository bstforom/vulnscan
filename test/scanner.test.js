import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseTarget } from '../src/scanner.js';

test('parseTarget adds https and parses host/port', () => {
  const p = parseTarget('example.com');
  assert.equal(p.hostname, 'example.com');
  assert.equal(p.protocol, 'https:');
  assert.equal(String(p.port), '443');
});

test('parseTarget keeps explicit http scheme and port', () => {
  const p = parseTarget('http://example.com:8080/path');
  assert.equal(p.protocol, 'http:');
  assert.equal(String(p.port), '8080');
});

test('parseTarget rejects empty input', () => {
  assert.throws(() => parseTarget(''), /empty/i);
});
