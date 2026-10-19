# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — 2026-10-18

### Added
- **Target scanning**: security headers, cookies, TLS, technology/version fingerprinting,
  categorized sensitive-path exposure (with content-signature confirmation), CORS, HTTP methods,
  WAF/CDN detection, HTML analysis, DNS security (SPF/DMARC/CAA), GraphQL introspection,
  source maps, and WordPress checks — all mapped to OWASP Top 10 and CWE.
- **File scanning**: dependency analysis via OSV (npm, PyPI, Maven, Go, crates.io, Packagist,
  RubyGems, NuGet, Pub, Hex), hardcoded-secret detection (30+ patterns), and SAST-lite static
  analysis (35+ rules).
- **CVE intelligence**: local SQLite + FTS5 database (scales to 100k+), CISA KEV flagging,
  optional EPSS scores, and precise CPE version matching.
- **Reporting**: HTML + JSON reports with risk scoring, severity breakdown, and OWASP/CWE references.
- **Print / Save as PDF** button on reports.
- **SARIF 2.1.0 export** for every report (GitHub Code Scanning compatible).
- **CLI** (`bin/vulnscan.js`) with CI-friendly exit codes, and a **library API** (`index.js`).
- **Authenticated scanning** (custom request headers), **bulk scanning** (up to 20 targets),
  and **subdomain discovery** via Certificate Transparency.
- **Live scan log** streamed as NDJSON (`/api/scan/target/stream`).
- **Scheduled scans** (5 minutes – 4 weeks) with pause/resume/delete.
- **History diff**: new vs. resolved findings between the last two scans of a target.
- Reports stored in the database with pagination.
- Optional hardened authentication (scrypt, HIBP, lockout, CSRF) behind `REQUIRE_AUTH=1`.
- Bulk CVE importer (`npm run import`) with resume and KEV/EPSS merge.
- Automated test suite (`npm test`).

### Security
- Local mode runs without login by default; authentication and CSRF enforce when `REQUIRE_AUTH=1`.
- Authorization acknowledgment required for every active scan.
- Passive/light-active checks only — no exploitation, DoS, brute-force, or evasion.
