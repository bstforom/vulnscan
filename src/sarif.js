// src/sarif.js
// Convert a VulnScan report to SARIF 2.1.0 (integrates with GitHub Code Scanning and other tools).

const LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note', UNKNOWN: 'none' };

function cweTaxa(cwe) {
  if (!cwe) return undefined;
  const id = String(cwe).replace('CWE-', '');
  return [{ toolComponent: { name: 'CWE' }, id }];
}

export function buildSARIF(report) {
  const rulesMap = new Map();
  const results = [];

  for (const f of report.findings || []) {
    const ruleId = f.type || 'finding';
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: ruleId.replace(/[-_]/g, ' '),
        shortDescription: { text: f.title },
        helpUri: f.cwe ? `https://cwe.mitre.org/data/definitions/${String(f.cwe).replace('CWE-', '')}.html` : undefined,
        properties: {
          tags: [f.owasp, f.cwe].filter(Boolean),
          'security-severity': ({ CRITICAL: '9.5', HIGH: '8.0', MEDIUM: '5.5', LOW: '3.0', INFO: '0.0', UNKNOWN: '0.0' }[f.severity] || '0.0'),
        },
      });
    }

    // Location: file scans embed a line number in the evidence ("Line N: ...")
    const lineMatch = /Line (\d+):/.exec(f.evidence || '');
    const uri = report.kind === 'file' ? (report.subject || 'uploaded-file') : (report.subject || 'target');
    const location = {
      physicalLocation: {
        artifactLocation: { uri },
        ...(lineMatch ? { region: { startLine: parseInt(lineMatch[1], 10) } } : {}),
      },
    };

    results.push({
      ruleId,
      level: LEVEL[f.severity] || 'note',
      message: { text: `${f.title}${f.detail ? ' — ' + f.detail : ''}${f.evidence ? ` (${f.evidence})` : ''}` },
      locations: [location],
      taxa: cweTaxa(f.cwe),
      properties: { severity: f.severity, cwe: f.cwe || null, owasp: f.owasp || null, cve: f.cve || null },
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'VulnScan',
          version: '1.0.0',
          informationUri: 'https://github.com/',
          rules: [...rulesMap.values()],
        },
      },
      results,
      properties: { subject: report.subject, kind: report.kind, riskScore: report.riskScore, generatedAt: report.generatedAt },
    }],
  };
}
