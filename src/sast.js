// src/sast.js
// Lightweight static analysis (SAST-lite): detects common vulnerability patterns in source code.
// Heuristic — needs manual review. Does not execute the code.

import path from 'path';

const EXT_LANG = {
  '.js': 'js', '.ts': 'js', '.jsx': 'js', '.tsx': 'js', '.mjs': 'js', '.cjs': 'js',
  '.py': 'py', '.php': 'php', '.java': 'java', '.rb': 'rb', '.go': 'go',
  '.cs': 'cs', '.c': 'c', '.cpp': 'c', '.cc': 'c', '.h': 'c',
};

// Each rule: { name, re, severity, cwe, owasp, langs? (all languages if omitted) }
const RULES = [
  // ===== Injection: SQL =====
  { name: 'Possible SQL injection (string concatenation into query)', re: /(?:execute|query|exec|prepare)\s*\(\s*[`"'][^`"')]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^`"')]*[`"']\s*\+/gi, severity: 'HIGH', cwe: 'CWE-89', owasp: 'A03' },
  { name: 'Possible SQL injection (f-string/template in query)', re: /(?:execute|cursor\.execute|query)\s*\(\s*f?[`"'][^`"')]*\{[^}]+\}[^`"')]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)/gi, severity: 'HIGH', cwe: 'CWE-89', owasp: 'A03' },
  { name: 'Possible SQL injection (string formatting)', re: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^;'"]{0,80}%s[^;'"]{0,40}["']\s*%\s*\(/gi, severity: 'MEDIUM', cwe: 'CWE-89', owasp: 'A03' },

  // ===== Command injection =====
  { name: 'Possible command injection (exec/system with variable)', re: /\b(?:os\.system|subprocess\.(?:call|run|Popen)|exec|execSync|child_process\.exec|shell_exec|passthru|popen|Runtime\.getRuntime\(\)\.exec)\s*\(\s*[^)'"]*(?:\+|\$\{|%s|f["'])/g, severity: 'HIGH', cwe: 'CWE-78', owasp: 'A03' },
  { name: 'Shell command execution with input (shell=True)', re: /\bsubprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True/g, severity: 'MEDIUM', cwe: 'CWE-78', owasp: 'A03', langs: ['py'] },

  // ===== Dynamic code execution =====
  { name: 'Dynamic eval()/Function usage', re: /\b(?:eval|Function|execScript)\s*\(/g, severity: 'MEDIUM', cwe: 'CWE-95', owasp: 'A03' },
  { name: 'String passed to setTimeout/setInterval', re: /\b(?:setTimeout|setInterval)\s*\(\s*["'`]/g, severity: 'LOW', cwe: 'CWE-95', owasp: 'A03', langs: ['js'] },

  // ===== Insecure deserialization =====
  { name: 'Insecure deserialization (pickle)', re: /\bpickle\.loads?\s*\(/g, severity: 'HIGH', cwe: 'CWE-502', owasp: 'A08', langs: ['py'] },
  { name: 'Unsafe YAML (yaml.load without SafeLoader)', re: /\byaml\.load\s*\((?![^)]*Safe)/g, severity: 'HIGH', cwe: 'CWE-502', owasp: 'A08', langs: ['py'] },
  { name: 'Insecure deserialization (PHP unserialize)', re: /\bunserialize\s*\(/g, severity: 'MEDIUM', cwe: 'CWE-502', owasp: 'A08', langs: ['php'] },
  { name: 'Insecure deserialization (Java ObjectInputStream)', re: /\bObjectInputStream\b/g, severity: 'MEDIUM', cwe: 'CWE-502', owasp: 'A08', langs: ['java'] },

  // ===== Weak cryptography =====
  { name: 'Weak hash algorithm (MD5)', re: /\bmd5\s*\(|hashlib\.md5|CryptoJS\.MD5|createHash\(\s*["']md5["']|MessageDigest\.getInstance\(\s*["']MD5/gi, severity: 'MEDIUM', cwe: 'CWE-327', owasp: 'A02' },
  { name: 'Weak hash algorithm (SHA-1)', re: /\bsha1\s*\(|hashlib\.sha1|CryptoJS\.SHA1|createHash\(\s*["']sha1["']|MessageDigest\.getInstance\(\s*["']SHA-?1/gi, severity: 'LOW', cwe: 'CWE-327', owasp: 'A02' },
  { name: 'Weak cipher (DES)', re: /\bDES\/|["']DES["']|Cipher\.getInstance\(\s*["']DES/g, severity: 'MEDIUM', cwe: 'CWE-327', owasp: 'A02' },
  { name: 'Insecure ECB cipher mode', re: /\b(?:AES|DES)\/ECB|["']ecb["']|MODE_ECB/gi, severity: 'MEDIUM', cwe: 'CWE-327', owasp: 'A02' },
  { name: 'Insecure randomness for security', re: /\bMath\.random\s*\(\)|new Random\(\)|random\.random\(\)/g, severity: 'LOW', cwe: 'CWE-338', owasp: 'A02' },

  // ===== Disabled certificate verification =====
  { name: 'TLS certificate verification disabled', re: /verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/gi, severity: 'HIGH', cwe: 'CWE-295', owasp: 'A07' },

  // ===== SSRF =====
  { name: 'External request with likely user input (SSRF)', re: /\b(?:requests\.(?:get|post)|urllib\.request\.urlopen|axios\.(?:get|post)|fetch|http\.get)\s*\(\s*(?:req\.|request\.|params\.|input|user|url\s*\+)/g, severity: 'MEDIUM', cwe: 'CWE-918', owasp: 'A10' },

  // ===== Path traversal =====
  { name: 'Possible path traversal (file read with input)', re: /\b(?:open|readFile|readFileSync|file_get_contents|fopen|include|require)\s*\(\s*(?:req\.|request\.|params\.|\$_(?:GET|POST|REQUEST))/g, severity: 'MEDIUM', cwe: 'CWE-22', owasp: 'A01' },

  // ===== XXE =====
  { name: 'Possible XXE (entity protection disabled)', re: /libxml_disable_entity_loader\s*\(\s*false|setFeature\([^)]*external-general-entities[^)]*true|XMLConstants\.FEATURE_SECURE_PROCESSING[^;]*false/gi, severity: 'MEDIUM', cwe: 'CWE-611', owasp: 'A05' },

  // ===== Dangerous configuration =====
  { name: 'Debug mode enabled', re: /\b(?:DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*true|RAILS_ENV.*development)/g, severity: 'LOW', cwe: 'CWE-489', owasp: 'A05' },
  { name: 'Wildcard CORS in code (*)', re: /Access-Control-Allow-Origin["'\s:,]+\*/g, severity: 'LOW', cwe: 'CWE-942', owasp: 'A05' },

  // ===== XSS (DOM) =====
  { name: 'Possible XSS (innerHTML/document.write with input)', re: /\.innerHTML\s*=\s*(?!["'`]\s*["'`])[^;]*(?:\+|\$\{|req\.|location|input)|document\.write\s*\(/g, severity: 'MEDIUM', cwe: 'CWE-79', owasp: 'A03', langs: ['js'] },
  { name: 'Possible XSS (dangerouslySetInnerHTML)', re: /dangerouslySetInnerHTML/g, severity: 'LOW', cwe: 'CWE-79', owasp: 'A03', langs: ['js'] },

  // ===== Log4Shell / JNDI injection =====
  { name: 'Possible JNDI injection (Log4Shell pattern)', re: /\$\{jndi:(?:ldap|ldaps|rmi|dns|iiop):/gi, severity: 'CRITICAL', cwe: 'CWE-917', owasp: 'A03' },

  // ===== Server-side template injection (SSTI) =====
  { name: 'Possible SSTI (render_template_string with input)', re: /render_template_string\s*\(\s*(?:[^)]*(?:\+|%|\.format|f["']|request\.))/g, severity: 'HIGH', cwe: 'CWE-1336', owasp: 'A03', langs: ['py'] },

  // ===== Weak JWT =====
  { name: 'JWT with alg none', re: /alg["'\s:]+none|algorithm[s]?["'\s:=\[]+["']?none/gi, severity: 'HIGH', cwe: 'CWE-347', owasp: 'A02' },
  { name: 'Hardcoded JWT secret in code', re: /jwt\.sign\s*\([^)]*,\s*["'][^"']{4,}["']/g, severity: 'MEDIUM', cwe: 'CWE-798', owasp: 'A02', langs: ['js'] },

  // ===== Open redirect =====
  { name: 'Possible open redirect', re: /(?:redirect|location\.href|sendRedirect)\s*[=(]\s*(?:req\.|request\.|params\.|\$_(?:GET|REQUEST)|query\.)/g, severity: 'MEDIUM', cwe: 'CWE-601', owasp: 'A01' },

  // ===== Insecure cookie in code =====
  { name: 'Cookie without HttpOnly/Secure in code', re: /httpOnly\s*:\s*false|secure\s*:\s*false(?![\w])/gi, severity: 'LOW', cwe: 'CWE-614', owasp: 'A05', langs: ['js'] },

  // ===== LDAP / XPath injection =====
  { name: 'Possible XPath injection', re: /(?:evaluate|selectNodes|xpath)\s*\([^)]*(?:\+|\$\{|f["'])/gi, severity: 'MEDIUM', cwe: 'CWE-643', owasp: 'A03' },

  // ===== Backdoor / reverse-shell indicators =====
  { name: 'Reverse shell indicator', re: /\/dev\/tcp\/|nc\s+-e\s|bash\s+-i\s*>&|socket\.(?:connect|SOCK_STREAM)|\/bin\/(?:sh|bash)['"]?\s*,?\s*['"]?-i/g, severity: 'HIGH', cwe: 'CWE-506', owasp: 'A03' },
  { name: 'PHP backdoor (execution from user input)', re: /\b(?:eval|assert|system|passthru|shell_exec|exec|popen)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/g, severity: 'CRITICAL', cwe: 'CWE-94', owasp: 'A03', langs: ['php'] },
  { name: 'Suspicious obfuscation (fromCharCode/long hex)', re: /String\.fromCharCode\([^)]{30,}\)|(?:\\x[0-9a-fA-F]{2}){12,}/g, severity: 'LOW', cwe: 'CWE-506', owasp: 'A03' },
];

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

export function scanCode(text, filename, { maxPerRule = 4, maxTotal = 80 } = {}) {
  const findings = [];
  if (!text) return findings;
  const ext = path.extname(filename || '').toLowerCase();
  const lang = EXT_LANG[ext] || null;

  for (const rule of RULES) {
    if (rule.langs && lang && !rule.langs.includes(lang)) continue;
    let count = 0;
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text)) && count < maxPerRule && findings.length < maxTotal) {
      count++;
      const ln = lineOf(text, m.index);
      const snippet = (text.split('\n')[ln - 1] || '').trim().slice(0, 120);
      findings.push({
        type: 'sast',
        title: rule.name,
        severity: rule.severity,
        detail: 'Static pattern — needs manual review to confirm.',
        evidence: `Line ${ln}: ${snippet}`,
        cwe: rule.cwe,
        owasp: rule.owasp,
      });
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
    }
    if (findings.length >= maxTotal) break;
  }
  return findings;
}
