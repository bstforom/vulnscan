import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, validatePasswordPolicy, validateUsername } from '../src/auth.js';

test('hashPassword + verifyPassword round-trip', async () => {
  const hash = await hashPassword('Correct Horse 9!');
  assert.ok(hash.startsWith('scrypt$'));
  assert.equal(await verifyPassword('Correct Horse 9!', hash), true);
  assert.equal(await verifyPassword('wrong password', hash), false);
});

test('validatePasswordPolicy rejects weak passwords', () => {
  assert.ok(validatePasswordPolicy('weak', 'bob').length > 0);
  assert.ok(validatePasswordPolicy('alllowercase123', 'bob').some((e) => /uppercase/i.test(e)));
});

test('validatePasswordPolicy accepts a strong password', () => {
  assert.equal(validatePasswordPolicy('Str0ng_P@ssw0rd!', 'bob').length, 0);
});

test('validatePasswordPolicy rejects username embedded in password', () => {
  assert.ok(validatePasswordPolicy('Alice12345!@#', 'alice').some((e) => /username/i.test(e)));
});

test('validateUsername enforces format', () => {
  assert.equal(validateUsername('good_user'), null);
  assert.ok(validateUsername('x'));        // too short
  assert.ok(validateUsername('bad user')); // space not allowed
});
