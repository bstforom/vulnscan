// src/cpe.js
// Parse CPE 2.3 strings and compare versions precisely — the basis for removing false positives.
// cpe:2.3:a:vendor:product:version:update:edition:lang:sw_edition:...

export function parseCPE(criteria) {
  if (!criteria || typeof criteria !== 'string') return null;
  const parts = criteria.split(':');
  if (parts.length < 6 || parts[0] !== 'cpe') return null;
  return {
    part: parts[2],       // a=application, o=operating system, h=hardware
    vendor: parts[3],
    product: parts[4],
    version: parts[5],
    update: parts[6] || '*',
  };
}

// Split a version into numeric/alpha tokens for comparison
function tokenize(v) {
  return String(v)
    .toLowerCase()
    .replace(/^v/, '')
    .split(/[^0-9a-z]+/i)
    .filter(Boolean);
}

// Compare two versions: -1 if a<b, 0 if equal, 1 if a>b
export function compareVersions(a, b) {
  const ta = tokenize(a);
  const tb = tokenize(b);
  const n = Math.max(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const x = ta[i];
    const y = tb[i];
    // One version ran out of tokens: a trailing numeric token means "newer" (1.0 < 1.0.1),
    // but a trailing alphabetic token is a pre-release, so the shorter one is "newer" (1.0.0 > 1.0.0-rc).
    if (x === undefined) return /^\d+$/.test(y) ? -1 : 1;
    if (y === undefined) return /^\d+$/.test(x) ? 1 : -1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      const dx = parseInt(x, 10);
      const dy = parseInt(y, 10);
      if (dx !== dy) return dx < dy ? -1 : 1;
    } else if (nx && !ny) {
      return 1; // a final release is newer than a pre-release (1.0 > 1.0.rc)
    } else if (!nx && ny) {
      return -1;
    } else {
      if (x !== y) return x < y ? -1 : 1;
    }
  }
  return 0;
}

const WILDCARD = new Set(['*', '-', '', undefined, null]);

// Does the detected version fall within a CPE vulnerability range?
// range: { exact, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding }
// Returns: { match: boolean, confidence: 'exact'|'range'|'product'|'none' }
export function versionInRange(detectedVersion, range) {
  const hasBounds =
    !WILDCARD.has(range.versionStartIncluding) ||
    !WILDCARD.has(range.versionStartExcluding) ||
    !WILDCARD.has(range.versionEndIncluding) ||
    !WILDCARD.has(range.versionEndExcluding);

  const exact = range.exact;
  const exactSpecified = !WILDCARD.has(exact);

  // No detected version -> cannot confirm precisely
  if (WILDCARD.has(detectedVersion)) {
    // If the vuln covers all product versions (no bounds, no specific version) it is possible at low confidence
    if (!hasBounds && !exactSpecified) return { match: true, confidence: 'product' };
    return { match: false, confidence: 'none' };
  }

  // Exact version specified in the CPE
  if (exactSpecified) {
    return { match: compareVersions(detectedVersion, exact) === 0, confidence: 'exact' };
  }

  // Version range
  if (hasBounds) {
    if (!WILDCARD.has(range.versionStartIncluding) && compareVersions(detectedVersion, range.versionStartIncluding) < 0) return { match: false, confidence: 'none' };
    if (!WILDCARD.has(range.versionStartExcluding) && compareVersions(detectedVersion, range.versionStartExcluding) <= 0) return { match: false, confidence: 'none' };
    if (!WILDCARD.has(range.versionEndIncluding) && compareVersions(detectedVersion, range.versionEndIncluding) > 0) return { match: false, confidence: 'none' };
    if (!WILDCARD.has(range.versionEndExcluding) && compareVersions(detectedVersion, range.versionEndExcluding) >= 0) return { match: false, confidence: 'none' };
    return { match: true, confidence: 'range' };
  }

  // Whole product with no bounds -> low confidence
  return { match: true, confidence: 'product' };
}
