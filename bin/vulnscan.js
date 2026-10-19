#!/usr/bin/env node
// VulnScan CLI — authorized vulnerability assessment from the command line.
//   vulnscan example.com                 scan a website/IP
//   vulnscan --file package.json         scan a file / dependency manifest
//   vulnscan example.com --sarif --html  also write SARIF and HTML reports
//
// Authorized use only: scan only targets you own or are permitted to test.

import fs from 'fs/promises';
import path from 'path';
import { scanTarget } from '../src/scanner.js';
import { scanFile } from '../src/fileScan.js';
import { buildReport, renderHTML } from '../src/report.js';
import { buildSARIF } from '../src/sarif.js';

const C = { reset: '\x1b[0m', red: '\x1b[31m', yellow: '\x1b[33m', blue: '\x1b[34m', gray: '\x1b[90m', bold: '\x1b[1m', green: '\x1b[32m' };
const SEV_COLOR = { CRITICAL: C.red, HIGH: C.red, MEDIUM: C.yellow, LOW: C.blue, INFO: C.gray, UNKNOWN: C.gray };

function parseArgs(argv) {
  const opts = { out: process.cwd(), formats: [], headers: {}, exitZero: false, allowPrivate: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--file' || a === '-f') opts.file = argv[++i];
    else if (a === '--out' || a === '-o') opts.out = argv[++i];
    else if (a === '--json') opts.formats.push('json');
    else if (a === '--sarif') opts.formats.push('sarif');
    else if (a === '--html') opts.formats.push('html');
    else if (a === '--allow-private') opts.allowPrivate = true;
    else if (a === '--exit-zero') opts.exitZero = true;
    else if (a === '--header' || a === '-H') { const [k, ...v] = (argv[++i] || '').split(':'); if (k && v.length) opts.headers[k.trim()] = v.join(':').trim(); }
    else if (a === '--help' || a === '-h') opts.help = true;
    else rest.push(a);
  }
  opts.target = rest[0];
  return opts;
}

function help() {
  console.log(`VulnScan CLI — authorized vulnerability assessment

Usage:
  vulnscan <target> [options]        Scan a website or IP
  vulnscan --file <path> [options]   Scan a file / dependency manifest

Options:
  -f, --file <path>     Scan a file instead of a URL
  -H, --header "K: V"   Add a request header (repeatable) — for authenticated scans
      --allow-private   Allow scanning internal/private addresses
      --json            Write a JSON report
      --sarif           Write a SARIF 2.1.0 report (GitHub Code Scanning)
      --html            Write an HTML report
  -o, --out <dir>       Output directory for reports (default: cwd)
      --exit-zero       Always exit 0 (default: exit 1 if HIGH/CRITICAL found)
  -h, --help            Show this help

Only scan systems you own or have explicit permission to test.`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || (!opts.target && !opts.file)) { help(); process.exit(opts.help ? 0 : 1); }

  let report;
  if (opts.file) {
    const buffer = await fs.readFile(opts.file);
    const scan = await scanFile({ filename: path.basename(opts.file), buffer });
    report = buildReport({ kind: 'file', scan });
  } else {
    console.error(`${C.gray}Scanning ${opts.target} ...${C.reset}`);
    const scan = await scanTarget(opts.target, { allowPrivate: opts.allowPrivate, headers: opts.headers });
    if (scan.blocked) { console.error(`${C.red}Scan halted: ${scan.errors.join('; ')}${C.reset}`); process.exit(2); }
    report = buildReport({ kind: 'target', scan });
  }

  // Print summary + findings
  const riskColor = report.riskScore >= 60 ? C.red : report.riskScore >= 30 ? C.yellow : C.green;
  console.log(`\n${C.bold}VulnScan report ${report.id}${C.reset}  —  ${report.subject}`);
  console.log(`Risk score: ${riskColor}${report.riskScore}/100${C.reset}   Findings: ${report.findingsCount}`);
  const sev = Object.entries(report.summary).filter(([, n]) => n > 0).map(([s, n]) => `${SEV_COLOR[s]}${s} ${n}${C.reset}`).join('  ');
  if (sev) console.log(sev);
  console.log('');
  for (const f of report.findings) {
    const col = SEV_COLOR[f.severity] || C.gray;
    console.log(`${col}● ${f.severity.padEnd(8)}${C.reset} ${f.title}${f.cwe ? C.gray + ' [' + f.cwe + ']' + C.reset : ''}`);
    if (f.evidence) console.log(`${C.gray}    ${f.evidence}${C.reset}`);
  }

  // Write requested report files
  await fs.mkdir(opts.out, { recursive: true });
  for (const fmt of opts.formats) {
    const file = path.join(opts.out, `${report.id}.${fmt}`);
    const content = fmt === 'html' ? renderHTML(report) : JSON.stringify(fmt === 'sarif' ? buildSARIF(report) : report, null, 2);
    await fs.writeFile(file, content, 'utf8');
    console.log(`\n${C.green}Wrote ${file}${C.reset}`);
  }

  const hasHigh = (report.summary.CRITICAL || 0) + (report.summary.HIGH || 0) > 0;
  process.exit(!opts.exitZero && hasHigh ? 1 : 0);
}

main().catch((e) => { console.error(`${C.red}Error: ${e.message}${C.reset}`); process.exit(2); });
