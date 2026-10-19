// src/fileScan.js
// Scan uploaded files:
//  (1) Dependency manifests (package.json, requirements.txt, ...) -> matched against the official OSV.dev database
//  (2) Any other file -> hash, type, secrets, code patterns, suspicious indicators

import crypto from 'crypto';
import path from 'path';
import { scanSecrets } from './secrets.js';
import { scanCode } from './sast.js';

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';

// ---- Dependency manifest parsers ----

function parsePackageJson(content) {
  const deps = [];
  try {
    const json = JSON.parse(content);
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const [name, range] of Object.entries(json[field] || {})) {
        const version = String(range).replace(/^[\^~>=<\s]+/, '').split(/\s|\|\|/)[0];
        if (version && /^\d/.test(version)) deps.push({ ecosystem: 'npm', name, version });
      }
    }
  } catch { /* ignore */ }
  return deps;
}

function parsePackageLock(content) {
  const deps = [];
  try {
    const json = JSON.parse(content);
    const pkgs = json.packages || json.dependencies || {};
    for (const [key, val] of Object.entries(pkgs)) {
      const name = key.startsWith('node_modules/') ? key.slice('node_modules/'.length) : key;
      if (name && val.version) deps.push({ ecosystem: 'npm', name, version: val.version });
    }
  } catch { /* ignore */ }
  return deps;
}

function parseRequirementsTxt(content) {
  const deps = [];
  for (const line of content.split(/\r?\n/)) {
    const l = line.trim();
    if (!l || l.startsWith('#') || l.startsWith('-')) continue;
    const m = /^([A-Za-z0-9._-]+)\s*==\s*([0-9][\w.+!-]*)/.exec(l);
    if (m) deps.push({ ecosystem: 'PyPI', name: m[1], version: m[2] });
  }
  return deps;
}

function parsePipfileLock(content) {
  const deps = [];
  try {
    const json = JSON.parse(content);
    for (const group of ['default', 'develop']) {
      for (const [name, info] of Object.entries(json[group] || {})) {
        const version = String(info.version || '').replace(/^==/, '');
        if (version) deps.push({ ecosystem: 'PyPI', name, version });
      }
    }
  } catch { /* ignore */ }
  return deps;
}

function parseComposerLock(content) {
  const deps = [];
  try {
    const json = JSON.parse(content);
    for (const p of [...(json.packages || []), ...(json['packages-dev'] || [])]) {
      if (p.name && p.version) deps.push({ ecosystem: 'Packagist', name: p.name, version: String(p.version).replace(/^v/, '') });
    }
  } catch { /* ignore */ }
  return deps;
}

function parseGoMod(content) {
  const deps = [];
  const re = /^\s*([\w.\-/]+)\s+v([\w.\-+]+)/gm;
  let m;
  while ((m = re.exec(content))) deps.push({ ecosystem: 'Go', name: m[1], version: m[2] });
  return deps;
}

function parseGemfileLock(content) {
  const deps = [];
  const re = /^\s{4}([a-zA-Z0-9_.\-]+)\s+\(([\d][\w.]*)\)/gm;
  let m;
  while ((m = re.exec(content))) deps.push({ ecosystem: 'RubyGems', name: m[1], version: m[2] });
  return deps;
}

function parseYarnLock(content) {
  const deps = [];
  const blocks = content.split(/\n(?=\S)/);
  for (const b of blocks) {
    const keyLine = b.split('\n')[0];
    const nameM = /^"?(@?[^@"\s,]+)@/.exec(keyLine);
    const verM = /\n\s+version:?\s+"?([0-9][\w.\-]*)"?/.exec(b);
    if (nameM && verM) deps.push({ ecosystem: 'npm', name: nameM[1], version: verM[1] });
  }
  return deps;
}

function parsePnpmLock(content) {
  const deps = [];
  const seen = new Set();
  // pnpm v6: /pkg/1.2.3:  |  v9: pkg@1.2.3:  |  @scope/pkg@1.2.3
  const re = /^\s+\/?((?:@[\w.-]+\/)?[\w.-]+)[@/](\d[\w.\-]*)(?:[(_:]|$)/gm;
  let m;
  while ((m = re.exec(content))) {
    const key = m[1] + '@' + m[2];
    if (seen.has(key)) continue; seen.add(key);
    deps.push({ ecosystem: 'npm', name: m[1], version: m[2] });
  }
  return deps;
}

function parseCargoLock(content) {
  const deps = [];
  const re = /\[\[package\]\]\s*[\s\S]*?name\s*=\s*"([^"]+)"\s*[\s\S]*?version\s*=\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(content))) deps.push({ ecosystem: 'crates.io', name: m[1], version: m[2] });
  return deps;
}

function parsePoetryLock(content) {
  const deps = [];
  const re = /\[\[package\]\]\s*[\s\S]*?name\s*=\s*"([^"]+)"\s*[\s\S]*?version\s*=\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(content))) deps.push({ ecosystem: 'PyPI', name: m[1], version: m[2] });
  return deps;
}

function parseGoSum(content) {
  const deps = [];
  const seen = new Set();
  for (const line of content.split(/\r?\n/)) {
    const m = /^([\w.\-/]+)\s+v([\w.\-+]+?)(?:\/go\.mod)?\s+h1:/.exec(line);
    if (m) {
      const key = m[1] + '@' + m[2];
      if (seen.has(key)) continue; seen.add(key);
      deps.push({ ecosystem: 'Go', name: m[1], version: m[2] });
    }
  }
  return deps;
}

function parsePubspecLock(content) {
  const deps = [];
  const re = /^\s{2}([\w.\-]+):\s*[\s\S]*?version:\s*"?([0-9][\w.\-+]*)"?/gm;
  let m;
  while ((m = re.exec(content))) deps.push({ ecosystem: 'Pub', name: m[1], version: m[2] });
  return deps;
}

function parseMixLock(content) {
  const deps = [];
  const re = /"([\w.\-]+)":\s*\{:hex,\s*:[\w.\-]+,\s*"([0-9][\w.\-]*)"/g;
  let m;
  while ((m = re.exec(content))) deps.push({ ecosystem: 'Hex', name: m[1], version: m[2] });
  return deps;
}

function parsePomXml(content) {
  const deps = [];
  const re = /<dependency>\s*[\s\S]*?<groupId>([^<]+)<\/groupId>\s*[\s\S]*?<artifactId>([^<]+)<\/artifactId>\s*[\s\S]*?<version>([^<${]+)<\/version>/g;
  let m;
  while ((m = re.exec(content))) deps.push({ ecosystem: 'Maven', name: `${m[1].trim()}:${m[2].trim()}`, version: m[3].trim() });
  return deps;
}

function parseCsproj(content) {
  const deps = [];
  const re = /<PackageReference\s+Include\s*=\s*"([^"]+)"\s+Version\s*=\s*"([^"]+)"/gi;
  let m;
  while ((m = re.exec(content))) deps.push({ ecosystem: 'NuGet', name: m[1], version: m[2] });
  return deps;
}

function parsePackagesConfig(content) {
  const deps = [];
  const re = /<package\s+id\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"/gi;
  let m;
  while ((m = re.exec(content))) deps.push({ ecosystem: 'NuGet', name: m[1], version: m[2] });
  return deps;
}

const PARSERS = {
  'package.json': parsePackageJson,
  'package-lock.json': parsePackageLock,
  'requirements.txt': parseRequirementsTxt,
  'pipfile.lock': parsePipfileLock,
  'composer.lock': parseComposerLock,
  'go.mod': parseGoMod,
  'go.sum': parseGoSum,
  'gemfile.lock': parseGemfileLock,
  'yarn.lock': parseYarnLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'cargo.lock': parseCargoLock,
  'poetry.lock': parsePoetryLock,
  'pubspec.lock': parsePubspecLock,
  'mix.lock': parseMixLock,
  'pom.xml': parsePomXml,
  'packages.config': parsePackagesConfig,
};

export function detectManifest(filename) {
  const base = path.basename(filename).toLowerCase();
  if (PARSERS[base]) return base;
  if (base.endsWith('.csproj')) return '.csproj';
  return null;
}
PARSERS['.csproj'] = parseCsproj;

// ---- OSV query ----

async function queryOSV(deps) {
  if (!deps.length) return [];
  // Split into batches of 100
  const batches = [];
  for (let i = 0; i < deps.length; i += 100) batches.push(deps.slice(i, i + 100));

  const vulnerable = [];
  for (const batch of batches) {
    const queries = batch.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version }));
    let data;
    try {
      const res = await fetch(OSV_BATCH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'VulnScan-Platform/1.0' },
        body: JSON.stringify({ queries }),
        signal: AbortSignal.timeout(30000),
      });
      if (!res.ok) throw new Error(`OSV ${res.status}`);
      data = await res.json();
    } catch (e) {
      vulnerable.push({ _error: `OSV query failed: ${e.message}` });
      continue;
    }
    const results = data.results || [];
    results.forEach((r, idx) => {
      const dep = batch[idx];
      if (r.vulns && r.vulns.length) {
        vulnerable.push({
          package: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          vulns: r.vulns.map((v) => ({ id: v.id, modified: v.modified })),
        });
      }
    });
    await new Promise((r) => setTimeout(r, 200));
  }

  // Fetch severity details for the top vulnerabilities (max 40 to keep it fast)
  const toDetail = [];
  for (const v of vulnerable) {
    if (v._error) continue;
    for (const vv of v.vulns) toDetail.push({ owner: v, id: vv.id });
  }
  for (const item of toDetail.slice(0, 40)) {
    try {
      const res = await fetch(OSV_VULN + item.id, { signal: AbortSignal.timeout(15000) });
      if (res.ok) {
        const detail = await res.json();
        const sev = (detail.severity || [])[0];
        const found = item.owner.vulns.find((x) => x.id === item.id);
        if (found) {
          found.summary = detail.summary || (detail.details || '').slice(0, 200);
          found.severity = sev ? sev.score : null;
          found.aliases = detail.aliases || [];
        }
      }
    } catch { /* ignore */ }
    await new Promise((r) => setTimeout(r, 120));
  }

  return vulnerable;
}

// ---- Generic file analysis (non-manifest) ----

const MAGIC = [
  { type: 'PE/EXE (Windows executable)', sig: [0x4d, 0x5a] },
  { type: 'ELF (Linux executable)', sig: [0x7f, 0x45, 0x4c, 0x46] },
  { type: 'ZIP/JAR/DOCX', sig: [0x50, 0x4b, 0x03, 0x04] },
  { type: 'PDF', sig: [0x25, 0x50, 0x44, 0x46] },
  { type: 'GZIP', sig: [0x1f, 0x8b] },
  { type: 'PNG', sig: [0x89, 0x50, 0x4e, 0x47] },
  { type: 'GIF', sig: [0x47, 0x49, 0x46] },
  { type: 'RAR', sig: [0x52, 0x61, 0x72, 0x21] },
  { type: 'Class (Java)', sig: [0xca, 0xfe, 0xba, 0xbe] },
];

function detectType(buffer) {
  for (const m of MAGIC) {
    if (m.sig.every((b, i) => buffer[i] === b)) return m.type;
  }
  // Text?
  const sample = buffer.slice(0, 512);
  const nonPrintable = [...sample].filter((b) => b < 9 || (b > 13 && b < 32)).length;
  if (nonPrintable / Math.max(sample.length, 1) < 0.1) return 'Text/Source';
  return 'Binary/Unknown';
}

function shannonEntropy(buffer) {
  if (!buffer.length) return 0;
  const freq = new Array(256).fill(0);
  for (const b of buffer) freq[b]++;
  let ent = 0;
  for (const f of freq) {
    if (!f) continue;
    const p = f / buffer.length;
    ent -= p * Math.log2(p);
  }
  return Number(ent.toFixed(3));
}

const SUSPICIOUS_PATTERNS = [
  { name: 'eval()', re: /\beval\s*\(/g },
  { name: 'exec/system call', re: /\b(exec|system|popen|shell_exec|passthru|proc_open)\s*\(/g },
  { name: 'base64 decode', re: /base64_decode|atob\s*\(|Buffer\.from\([^)]*base64/g },
  { name: 'PowerShell encoded', re: /-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}/gi },
  { name: 'reverse shell hint', re: /\/dev\/tcp\/|nc\s+-e|socket\.(connect|SOCK_STREAM)/g },
  { name: 'obfuscation (fromCharCode)', re: /String\.fromCharCode|chr\(\d+\)\.chr/g },
];

function scanGenericContent(buffer, { skipTextPatterns = false } = {}) {
  const findings = [];
  const type = detectType(buffer);
  const entropy = shannonEntropy(buffer.slice(0, 65536));
  if (entropy > 7.2 && buffer.length > 1024) {
    findings.push({
      type: 'entropy',
      title: 'High entropy (may be compressed/encrypted/packed)',
      severity: 'INFO',
      detail: `Entropy ${entropy} — common in packed or encrypted files.`,
      evidence: `entropy=${entropy}`,
    });
  }
  // Only run pattern checks on text files (skipped if SAST already ran, to avoid duplicates)
  if (!skipTextPatterns && /Text|Source/.test(type)) {
    const text = buffer.toString('utf8', 0, Math.min(buffer.length, 200000));
    for (const p of SUSPICIOUS_PATTERNS) {
      const count = (text.match(p.re) || []).length;
      if (count) {
        findings.push({
          type: 'suspicious-pattern',
          title: `Suspicious pattern: ${p.name}`,
          severity: count > 3 ? 'MEDIUM' : 'LOW',
          detail: `Seen ${count} time(s). Worth manual review.`,
          evidence: p.name,
        });
      }
    }
  }
  return { type, entropy, findings };
}

// Main entry point for scanning an uploaded file
export async function scanFile({ filename, buffer }) {
  const result = {
    filename,
    size: buffer.length,
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
    md5: crypto.createHash('md5').update(buffer).digest('hex'),
    scannedAt: new Date().toISOString(),
    manifest: null,
    dependencies: 0,
    vulnerable: [],
    fileType: null,
    entropy: null,
    findings: [],
  };

  const type = detectType(buffer);
  const isText = /Text|Source/.test(type);
  const text = isText ? buffer.toString('utf8', 0, Math.min(buffer.length, 1_000_000)) : '';

  const manifestType = detectManifest(filename);
  if (manifestType) {
    const content = buffer.toString('utf8');
    const deps = PARSERS[manifestType](content);
    result.manifest = manifestType;
    result.dependencies = deps.length;
    const vulnerable = await queryOSV(deps);
    result.vulnerable = vulnerable.filter((v) => !v._error);
    const errs = vulnerable.filter((v) => v._error).map((v) => v._error);
    if (errs.length) result.findings.push({ type: 'error', title: 'Query warning', severity: 'INFO', detail: errs.join('; '), evidence: '' });
    for (const v of result.vulnerable) {
      const worst = v.vulns.map((x) => x.id).join(', ');
      result.findings.push({
        type: 'vulnerable-dependency',
        title: `Vulnerable dependency: ${v.package}@${v.version}`,
        severity: 'HIGH',
        detail: `Known vulnerabilities: ${worst}. Update to a safe version.`,
        evidence: `${v.ecosystem}:${v.package}@${v.version}`,
        cwe: 'CWE-1104', owasp: 'A06',
      });
    }
  }

  // Secret scanning (for every text file, including config and manifest files)
  if (isText) {
    result.findings.push(...scanSecrets(text));
  }

  // Static analysis of source code (not manifests)
  if (isText && !manifestType) {
    result.findings.push(...scanCode(text, filename));
  }

  // Generic analysis (type/entropy/suspicious patterns) for non-manifest files
  if (!manifestType) {
    const generic = scanGenericContent(buffer, { skipTextPatterns: isText });
    result.fileType = generic.type;
    result.entropy = generic.entropy;
    result.findings.push(...generic.findings);
  } else {
    result.fileType = type;
  }

  return result;
}
