import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSecrets } from '../src/secrets.js';

test('detects AWS access key and GitHub token', () => {
  // Fake token assembled at runtime so the literal never appears in source (avoids push-protection false alarms).
  const fakeGh = 'ghp' + '_' + 'abcdefghijklmnopqrstuvwxyz0123456789';
  const text = 'const a = "AKIAIOSFODNN7EXAMPLE";\nconst b = "' + fakeGh + '";';
  const f = scanSecrets(text);
  const titles = f.map((x) => x.title);
  assert.ok(titles.some((t) => t.includes('AWS Access Key ID')));
  assert.ok(titles.some((t) => t.includes('GitHub Token')));
});

test('masks the secret value in evidence', () => {
  const f = scanSecrets('key = "AKIAIOSFODNN7EXAMPLE";');
  assert.ok(f.length > 0);
  assert.ok(!f[0].evidence.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(f[0].evidence.includes('***'));
});

test('detects DB connection string', () => {
  const f = scanSecrets('DB="postgres://admin:SuperSecret123@db.example.com:5432/app"');
  assert.ok(f.some((x) => x.title.includes('DB Connection String')));
});

test('ignores placeholder values', () => {
  const f = scanSecrets('api_key = "your-api-key-here"');
  assert.equal(f.length, 0);
});

test('returns empty for empty input', () => {
  assert.deepEqual(scanSecrets(''), []);
});
