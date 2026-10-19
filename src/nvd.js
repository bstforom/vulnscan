// src/nvd.js
// NVD API connection helpers and CVE normalization (used by the importer and the server).

export const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// NVD requires ISO-8601 in UTC with millisecond precision (without Z)
export function nvdDate(d) {
  return d.toISOString().replace('Z', '');
}

function cvssFrom(metrics) {
  if (!metrics) return { score: null, severity: 'UNKNOWN', vector: null, version: null };
  const order = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];
  for (const key of order) {
    const arr = metrics[key];
    if (Array.isArray(arr) && arr.length) {
      const m = arr[0];
      const data = m.cvssData || {};
      return {
        score: data.baseScore ?? null,
        severity: (data.baseSeverity || m.baseSeverity || 'UNKNOWN').toUpperCase(),
        vector: data.vectorString || null,
        version: data.version || null,
      };
    }
  }
  return { score: null, severity: 'UNKNOWN', vector: null, version: null };
}

function productsFrom(configurations) {
  const products = new Set();
  const cpes = [];
  if (!Array.isArray(configurations)) return { products: [], cpes: [] };
  for (const cfg of configurations) {
    for (const node of cfg.nodes || []) {
      for (const cm of node.cpeMatch || []) {
        if (!cm.criteria) continue;
        cpes.push({
          criteria: cm.criteria,
          vulnerable: !!cm.vulnerable,
          versionStartIncluding: cm.versionStartIncluding || null,
          versionStartExcluding: cm.versionStartExcluding || null,
          versionEndIncluding: cm.versionEndIncluding || null,
          versionEndExcluding: cm.versionEndExcluding || null,
        });
        const parts = cm.criteria.split(':');
        if (parts.length > 5) {
          const vendor = parts[3];
          const product = parts[4];
          if (product && product !== '*') products.add(`${vendor}:${product}`.toLowerCase());
        }
      }
    }
  }
  return { products: [...products], cpes };
}

export function normalize(vuln) {
  const cve = vuln.cve || {};
  const descEn = (cve.descriptions || []).find((d) => d.lang === 'en');
  const metrics = cvssFrom(cve.metrics);
  const { products, cpes } = productsFrom(cve.configurations);
  const refs = (cve.references || []).slice(0, 8).map((r) => r.url);
  return {
    id: cve.id,
    published: cve.published,
    lastModified: cve.lastModified,
    status: cve.vulnStatus,
    description: descEn ? descEn.value : (cve.descriptions?.[0]?.value || ''),
    cvss: metrics,
    products,
    cpes,
    references: refs,
    cwe: (cve.weaknesses || [])
      .flatMap((w) => (w.description || []).map((d) => d.value))
      .filter((v) => v && v !== 'NVD-CWE-noinfo' && v !== 'NVD-CWE-Other'),
  };
}

// Fetch a single page from NVD, respecting the timeout and API key
export async function fetchPage(params, apiKey) {
  const url = `${NVD_BASE}?${params.toString()}`;
  const headers = { 'User-Agent': 'VulnScan-Platform/1.0 (authorized assessment)' };
  if (apiKey) headers.apiKey = apiKey;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(60000) });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`NVD API ${res.status}: ${body.slice(0, 160)}`);
  }
  return res.json();
}
