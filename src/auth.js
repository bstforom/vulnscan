// src/auth.js
// Hardened authentication system:
//  - Password hashing with scrypt + random salt + constant-time comparison
//  - Password checked against the HIBP breach database (k-anonymity; the password is never sent)
//  - Strong password policy + prevents embedding the username
//  - Account lockout after repeated failed attempts
//  - Random in-memory sessions with sliding expiry + a CSRF token per session

import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { promisify } from 'util';

const scrypt = promisify(crypto.scrypt);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');

// scrypt parameters (high compute cost to slow guessing without blocking login)
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64, maxmem: 64 * 1024 * 1024 };

const MAX_FAILED = 5;                       // failed attempts before lockout
const LOCK_MS = 15 * 60 * 1000;             // lockout duration: 15 minutes
const SESSION_TTL_MS = 2 * 60 * 60 * 1000;  // session lifetime: 2 hours (sliding)

// ---- User storage (JSON file with atomic writes) ----
let usersCache = null;

async function loadUsers() {
  if (usersCache) return usersCache;
  try {
    usersCache = JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
  } catch {
    usersCache = [];
  }
  return usersCache;
}

async function saveUsers(users) {
  usersCache = users;
  await fs.mkdir(path.dirname(USERS_FILE), { recursive: true });
  const tmp = USERS_FILE + '.tmp';
  await fs.writeFile(tmp, JSON.stringify(users, null, 2), 'utf8');
  await fs.rename(tmp, USERS_FILE); // atomic: prevents file corruption on crash
}

// ---- Hashing and verification ----
export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const dk = await scrypt(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('hex')}$${dk.toString('hex')}`;
}

export async function verifyPassword(password, stored) {
  try {
    const [alg, N, r, p, saltHex, hashHex] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = await scrypt(password, salt, expected.length, { N: +N, r: +r, p: +p, maxmem: SCRYPT.maxmem });
    // constant-time comparison to prevent timing attacks
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// ---- Password check against HIBP breaches (k-anonymity) ----
// Only the first 5 characters of the SHA-1 hash are sent — the password and full hash are never sent.
export async function checkBreached(password) {
  try {
    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true', 'User-Agent': 'VulnScan-Platform/1.0' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return { checked: false, breached: false, count: 0 };
    const text = await res.text();
    for (const line of text.split('\n')) {
      const [suf, count] = line.trim().split(':');
      if (suf === suffix) return { checked: true, breached: true, count: parseInt(count, 10) || 0 };
    }
    return { checked: true, breached: false, count: 0 };
  } catch {
    return { checked: false, breached: false, count: 0 };
  }
}

// ---- Password policy ----
export function validatePasswordPolicy(password, username) {
  const errors = [];
  if (!password || password.length < 12) errors.push('Password must be at least 12 characters');
  if (password && password.length > 128) errors.push('Password is too long (max 128)');
  if (!/[a-z]/.test(password)) errors.push('Add a lowercase letter');
  if (!/[A-Z]/.test(password)) errors.push('Add an uppercase letter');
  if (!/[0-9]/.test(password)) errors.push('Add a digit');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('Add a special character (!@#$...)');
  if (username && password && password.toLowerCase().includes(username.toLowerCase())) errors.push('Do not include the username in the password');
  // common weak patterns
  if (/^(.)\1+$/.test(password)) errors.push('Password is clearly repetitive');
  if (/123456|password|qwerty|admin/i.test(password)) errors.push('Password contains a very common pattern');
  return errors;
}

export function validateUsername(username) {
  if (!username || typeof username !== 'string') return 'Username is required';
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) return 'Username: 3-32 characters (letters/digits/_.-)';
  return null;
}

// ---- User management ----
export async function userCount() {
  return (await loadUsers()).length;
}

export async function createUser(username, password) {
  const uErr = validateUsername(username);
  if (uErr) return { ok: false, error: uErr };

  const pErrs = validatePasswordPolicy(password, username);
  if (pErrs.length) return { ok: false, error: pErrs.join(' · ') };

  const breach = await checkBreached(password);
  if (breach.breached) {
    return { ok: false, error: `This password has appeared in ${breach.count.toLocaleString('en')} known breaches — choose another.` };
  }

  const users = await loadUsers();
  if (users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
    return { ok: false, error: 'Username is already taken' };
  }

  const passwordHash = await hashPassword(password);
  const user = {
    id: crypto.randomUUID(),
    username,
    passwordHash,
    role: users.length === 0 ? 'admin' : 'user', // first user = admin
    createdAt: new Date().toISOString(),
    failedAttempts: 0,
    lockedUntil: null,
    lastLogin: null,
    breachChecked: breach.checked,
  };
  users.push(user);
  await saveUsers(users);
  return { ok: true, user: publicUser(user) };
}

function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role, createdAt: u.createdAt, lastLogin: u.lastLogin };
}

export async function authenticate(username, password) {
  const users = await loadUsers();
  const user = users.find((u) => u.username.toLowerCase() === String(username || '').toLowerCase());

  // To keep response time uniform and resist username enumeration, always hash even if the user does not exist
  if (!user) {
    await hashPassword(String(password || 'x')); // consume similar time
    return { ok: false, error: 'Invalid username or password' };
  }

  if (user.lockedUntil && Date.now() < user.lockedUntil) {
    const mins = Math.ceil((user.lockedUntil - Date.now()) / 60000);
    return { ok: false, error: `Account temporarily locked due to failed attempts. Try again in ${mins} minute(s).` };
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    user.failedAttempts = (user.failedAttempts || 0) + 1;
    if (user.failedAttempts >= MAX_FAILED) {
      user.lockedUntil = Date.now() + LOCK_MS;
      user.failedAttempts = 0;
    }
    await saveUsers(users);
    return { ok: false, error: 'Invalid username or password' };
  }

  // success: reset counters
  user.failedAttempts = 0;
  user.lockedUntil = null;
  user.lastLogin = new Date().toISOString();
  await saveUsers(users);
  return { ok: true, user: publicUser(user) };
}

// ---- Session management (in-memory, sliding expiry) ----
const sessions = new Map(); // sid -> { userId, username, role, csrfToken, expiresAt, ip, ua }

function newToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function createSession(user, { ip, ua } = {}) {
  const sid = newToken(32);
  const csrfToken = newToken(24);
  sessions.set(sid, {
    userId: user.id,
    username: user.username,
    role: user.role,
    csrfToken,
    expiresAt: Date.now() + SESSION_TTL_MS,
    ip,
    ua,
  });
  return { sid, csrfToken };
}

export function getSession(sid) {
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() > s.expiresAt) {
    sessions.delete(sid);
    return null;
  }
  // sliding expiry: extend on every use
  s.expiresAt = Date.now() + SESSION_TTL_MS;
  return s;
}

export function destroySession(sid) {
  if (sid) sessions.delete(sid);
}

// Periodic cleanup of expired sessions
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) if (now > s.expiresAt) sessions.delete(sid);
}, 10 * 60 * 1000).unref();
