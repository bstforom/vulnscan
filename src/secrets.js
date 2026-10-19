// src/secrets.js
// Detect hardcoded secrets (API keys, tokens, private keys...) in files and text.
// Sensitive values are masked in the output (prefix only).

const PATTERNS = [
  { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'AWS Secret Access Key', re: /\b(?:aws_secret_access_key|aws_secret)\b["'\s:=]+([A-Za-z0-9/+]{40})/gi, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Google API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Google OAuth Client', re: /\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b/g, severity: 'MEDIUM', cwe: 'CWE-798' },
  { name: 'GitHub Token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'GitHub Fine-grained PAT', re: /\bgithub_pat_[0-9A-Za-z_]{22,}\b/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'GitLab PAT', re: /\bglpat-[0-9A-Za-z\-_]{20}\b/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Slack Token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Slack Webhook', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g, severity: 'MEDIUM', cwe: 'CWE-798' },
  { name: 'Stripe Secret Key', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Twilio API Key', re: /\bSK[0-9a-fA-F]{32}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'SendGrid API Key', re: /\bSG\.[\w-]{22}\.[\w-]{43}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Mailgun API Key', re: /\bkey-[0-9a-zA-Z]{32}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'NPM Token', re: /\bnpm_[0-9A-Za-z]{36}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Private Key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, severity: 'CRITICAL', cwe: 'CWE-321' },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: 'MEDIUM', cwe: 'CWE-522' },
  { name: 'DB Connection String', re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s:'"]+:[^\s@'"]+@[^\s'"]+/gi, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Basic Auth in URL', re: /\bhttps?:\/\/[A-Za-z0-9._%+-]+:[^@\s'"]{3,}@[A-Za-z0-9.-]+/g, severity: 'HIGH', cwe: 'CWE-522' },
  { name: 'Azure Storage Key', re: /\bAccountKey=[A-Za-z0-9+/]{80,}==/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Firebase Cloud Messaging Key', re: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Discord Token', re: /\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Discord Webhook', re: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[\w-]+/g, severity: 'MEDIUM', cwe: 'CWE-798' },
  { name: 'OpenAI API Key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{48}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Anthropic API Key', re: /\bsk-ant-[A-Za-z0-9_-]{90,}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Stripe Webhook Secret', re: /\bwhsec_[A-Za-z0-9]{32,}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Telegram Bot Token', re: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g, severity: 'MEDIUM', cwe: 'CWE-798' },
  { name: 'Shopify Access Token', re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Square Access Token', re: /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}\b/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Google Service Account', re: /"type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[a-f0-9]{40}"/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Generic Secret Assignment', re: /\b(?:api[_-]?key|apikey|secret|passwd|password|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*["']([0-9a-zA-Z\-_./+]{12,})["']/gi, severity: 'MEDIUM', cwe: 'CWE-798' },
];

// Mask the sensitive value
function mask(s) {
  const str = String(s);
  if (str.length <= 8) return str.slice(0, 2) + '***';
  return str.slice(0, 4) + '***' + str.slice(-2) + ` (${str.length} chars)`;
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

// Common example/placeholder values — ignored to reduce false positives
function looksPlaceholder(val) {
  return /^(x{4,}|0{4,}|your[_-]?|example|placeholder|changeme|test|dummy|sample|<.*>|\$\{)/i.test(String(val));
}

export function scanSecrets(text, { maxPerPattern = 5, maxTotal = 60 } = {}) {
  const findings = [];
  if (!text) return findings;
  const seen = new Set();
  for (const p of PATTERNS) {
    let count = 0;
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(text)) && count < maxPerPattern && findings.length < maxTotal) {
      const full = m[1] || m[0];
      if (looksPlaceholder(full)) continue;
      const key = p.name + ':' + full.slice(0, 12);
      if (seen.has(key)) continue;
      seen.add(key);
      count++;
      findings.push({
        type: 'secret',
        title: `Hardcoded secret: ${p.name}`,
        severity: p.severity,
        detail: 'Remove the secret from code, rotate it immediately, and use environment variables / a secrets vault.',
        evidence: `Line ${lineOf(text, m.index)}: ${mask(full)}`,
        cwe: p.cwe,
        owasp: 'A07',
      });
    }
    if (findings.length >= maxTotal) break;
  }
  return findings;
}
