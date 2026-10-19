import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isLoopbackHost, localModeGuard } from '../src/security.js';

// Runs the guard against a fake request; returns the HTTP status (200 = passed through).
function guard({ method = 'GET', host = 'localhost:3000', origin } = {}) {
  const headers = { host };
  if (origin !== undefined) headers.origin = origin;
  let status = 200;
  const res = { status(code) { status = code; return this; }, json() { return this; } };
  localModeGuard({ method, headers }, res, () => {});
  return status;
}

test('isLoopbackHost accepts only loopback names', () => {
  for (const h of ['localhost', '127.0.0.1', '::1', '[::1]', 'app.localhost', 'LOCALHOST']) assert.ok(isLoopbackHost(h), h);
  for (const h of ['0.0.0.0', '192.168.1.5', 'example.com', 'localhost.evil.com', '']) assert.ok(!isLoopbackHost(h), h);
});

test('local mode allows same-machine requests', () => {
  assert.equal(guard({ host: 'localhost:3000' }), 200);
  assert.equal(guard({ host: '127.0.0.1:3000' }), 200);
  assert.equal(guard({ host: '[::1]:3000' }), 200);
  assert.equal(guard({ method: 'POST', host: 'localhost:3000', origin: 'http://localhost:3000' }), 200);
  assert.equal(guard({ method: 'POST', host: 'localhost:3000' }), 200); // non-browser client (curl, CLI)
});

test('local mode blocks DNS rebinding via a foreign Host header', () => {
  assert.equal(guard({ host: 'attacker.example:3000' }), 403);
  assert.equal(guard({ host: '192.168.1.20:3000' }), 403);
});

test('local mode blocks cross-origin state-changing requests (CSRF)', () => {
  assert.equal(guard({ method: 'POST', origin: 'https://evil.example' }), 403);
  assert.equal(guard({ method: 'DELETE', origin: 'http://localhost.evil.com' }), 403);
  assert.equal(guard({ method: 'POST', origin: 'null' }), 403);
  assert.equal(guard({ method: 'GET', origin: 'https://evil.example' }), 200); // reads are protected by same-origin policy
});
