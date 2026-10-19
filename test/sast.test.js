import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCode } from '../src/sast.js';

test('detects SQL injection via string concatenation', () => {
  const f = scanCode('db.query("SELECT * FROM users WHERE id=" + id)', 'a.js');
  assert.ok(f.some((x) => x.cwe === 'CWE-89'));
});

test('detects eval and disabled TLS verification', () => {
  const f = scanCode('eval(x);\nhttps.get(u, { rejectUnauthorized: false });', 'a.js');
  assert.ok(f.some((x) => x.title.includes('eval')));
  assert.ok(f.some((x) => x.cwe === 'CWE-295'));
});

test('detects weak MD5 (Node createHash)', () => {
  const f = scanCode("crypto.createHash('md5').update(x)", 'a.js');
  assert.ok(f.some((x) => x.cwe === 'CWE-327'));
});

test('detects PHP backdoor from user input', () => {
  const f = scanCode('<?php system($_GET["cmd"]); ?>', 'shell.php');
  assert.ok(f.some((x) => x.severity === 'CRITICAL' && x.cwe === 'CWE-94'));
});

test('findings include line numbers', () => {
  const f = scanCode('x\neval(y)', 'a.js');
  const evalF = f.find((x) => x.title.includes('eval'));
  assert.ok(evalF.evidence.startsWith('Line 2'));
});
