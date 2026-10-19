// src/discover.js
// Passive subdomain discovery via certificate transparency logs (crt.sh). Read-only, non-intrusive.

export async function discoverSubdomains(domain, { max = 300 } = {}) {
  const clean = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(clean)) throw new Error('Invalid domain');

  const url = `https://crt.sh/?q=${encodeURIComponent('%.' + clean)}&output=json`;
  // crt.sh is frequently overloaded (502/504) — retry a few times with backoff
  let data = null;
  let lastErr = '';
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url, { headers: { 'User-Agent': 'VulnScan-Platform/1.0 (authorized assessment)' }, signal: AbortSignal.timeout(25000) });
      if (res.ok) { data = await res.json().catch(() => []); break; }
      lastErr = `crt.sh returned ${res.status}`;
    } catch (e) { lastErr = String(e.message || e); }
    if (attempt < 2) await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
  }
  if (!data) throw new Error(`${lastErr} (crt.sh is often overloaded — try again shortly)`);

  const set = new Set();
  for (const row of data) {
    for (const n of String(row.name_value || '').split('\n')) {
      const name = n.trim().toLowerCase().replace(/^\*\./, '');
      if (name && (name === clean || name.endsWith('.' + clean))) set.add(name);
    }
  }
  const subdomains = [...set].sort();
  return { domain: clean, count: subdomains.length, subdomains: subdomains.slice(0, max), source: 'crt.sh' };
}
