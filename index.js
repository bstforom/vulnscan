// index.js — public library API for VulnScan.
// Import these in your own project:  import { scanTarget, scanFile, buildReport } from 'vulnscan';
//
// Note: these entry points do NOT require the SQLite CVE database or the
// --experimental-sqlite flag. CVE correlation (src/cve.js) is optional and
// needs the database; import it directly if you want it.

export { scanTarget, parseTarget } from './src/scanner.js';
export { scanFile, detectManifest } from './src/fileScan.js';
export { buildReport, renderHTML } from './src/report.js';
export { buildSARIF } from './src/sarif.js';
export { scanSecrets } from './src/secrets.js';
export { scanCode } from './src/sast.js';
export { fingerprint } from './src/fingerprint.js';
export { discoverSubdomains } from './src/discover.js';
export { compareVersions, versionInRange } from './src/cpe.js';
