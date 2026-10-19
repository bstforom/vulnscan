// src/security.js
// Security layer for the platform itself: security headers, cookie parsing, rate limiting, and CSRF protection.

import { getSession, destroySession } from './auth.js';

const SECURE_COOKIES = process.env.SECURE_COOKIES === '1';
const COOKIE_NAME = 'vs_sid';

// The server runs locally without login by default. To enable authentication (for commercial deployment): REQUIRE_AUTH=1
export const REQUIRE_AUTH = process.env.REQUIRE_AUTH === '1';
const LOCAL_SESSION = { username: 'local', role: 'admin', csrfToken: 'local' };

// ---- Local-mode guard ----
// Local mode has no login and no real CSRF token, so it must only ever be reachable from this machine.
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);
export function isLoopbackHost(h) {
  h = String(h || '').toLowerCase().replace(/^\[|\]$/g, '');
  return LOOPBACK_HOSTS.has(h) || h.endsWith('.localhost');
}

// Rejects a non-loopback Host header (DNS rebinding) and state-changing requests from a
// foreign Origin (CSRF — e.g. a cross-site multipart form posting to /api/scan/file).
export function localModeGuard(req, res, next) {
  if (REQUIRE_AUTH) return next();
  const host = String(req.headers.host || '').replace(/:\d+$/, '');
  if (!isLoopbackHost(host)) return res.status(403).json({ error: 'Local mode only accepts requests to localhost.' });
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.headers.origin) {
    let origin = '';
    try { origin = new URL(req.headers.origin).hostname; } catch { /* "null" or malformed */ }
    if (!isLoopbackHost(origin)) return res.status(403).json({ error: 'Cross-origin request blocked.' });
  }
  next();
}

// ---- Security headers on every response (we practice what we check for) ----
export function securityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'", // inline style attributes in dynamic results
      "img-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
    ].join('; ')
  );
  if (SECURE_COOKIES) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.removeHeader('X-Powered-By');
  next();
}

// ---- Manual cookie parsing (no extra dependencies) ----
export function cookieParser(req, res, next) {
  req.cookies = {};
  const header = req.headers.cookie;
  if (header) {
    for (const part of header.split(';')) {
      const idx = part.indexOf('=');
      if (idx > -1) {
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        req.cookies[k] = decodeURIComponent(v);
      }
    }
  }
  next();
}

export function setSessionCookie(res, sid) {
  const attrs = [
    `${COOKIE_NAME}=${sid}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${2 * 60 * 60}`,
  ];
  if (SECURE_COOKIES) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

export function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}

export { COOKIE_NAME };

// ---- Rate limiting (in-memory, simple sliding window) ----
export function makeRateLimiter({ windowMs, max, message }) {
  const hits = new Map(); // key -> [timestamps]
  setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [k, arr] of hits) {
      const filtered = arr.filter((t) => t > cutoff);
      if (filtered.length) hits.set(k, filtered);
      else hits.delete(k);
    }
  }, windowMs).unref();

  return (req, res, next) => {
    const key = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
    const now = Date.now();
    const cutoff = now - windowMs;
    const arr = (hits.get(key) || []).filter((t) => t > cutoff);
    arr.push(now);
    hits.set(key, arr);
    if (arr.length > max) {
      const retry = Math.ceil((arr[0] + windowMs - now) / 1000);
      res.setHeader('Retry-After', String(retry));
      return res.status(429).json({ error: message || 'Too many requests', retryAfter: retry });
    }
    next();
  };
}

// ---- Auth middleware for API endpoints (returns 401) ----
export function requireAuth(req, res, next) {
  if (!REQUIRE_AUTH) { req.session = LOCAL_SESSION; return next(); } // local: no login
  const sid = req.cookies?.[COOKIE_NAME];
  const session = getSession(sid);
  if (!session) {
    if (sid) destroySession(sid);
    return res.status(401).json({ error: 'Unauthorized', message: 'Session expired or invalid. Please sign in.' });
  }
  req.session = session;
  req.sid = sid;
  next();
}

// ---- Auth middleware for pages (redirects to the login page) ----
export function requireAuthPage(req, res, next) {
  if (!REQUIRE_AUTH) { req.session = LOCAL_SESSION; return next(); }
  const session = getSession(req.cookies?.[COOKIE_NAME]);
  if (!session) return res.redirect('/login.html');
  req.session = session;
  next();
}

// ---- CSRF protection: double-submit token via a header matching the session token ----
export function requireCsrf(req, res, next) {
  if (!REQUIRE_AUTH) return next(); // local: no CSRF needed
  const token = req.headers['x-csrf-token'];
  if (!req.session || !token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: 'Invalid CSRF token', message: 'Reload the page and try again.' });
  }
  next();
}
