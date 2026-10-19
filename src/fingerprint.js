// src/fingerprint.js
// Detect technologies used by the target from headers and page content (passive, no exploitation)

// Detection rules: technology name + search patterns in headers and content
const RULES = [
  { name: 'nginx', header: 'server', re: /nginx(?:\/([\d.]+))?/i },
  { name: 'apache', header: 'server', re: /apache(?:\/([\d.]+))?/i },
  { name: 'iis', header: 'server', re: /microsoft-iis(?:\/([\d.]+))?/i },
  { name: 'litespeed', header: 'server', re: /litespeed/i },
  { name: 'openresty', header: 'server', re: /openresty(?:\/([\d.]+))?/i },
  { name: 'cloudflare', header: 'server', re: /cloudflare/i },
  { name: 'php', header: 'x-powered-by', re: /php(?:\/([\d.]+))?/i },
  { name: 'express', header: 'x-powered-by', re: /express/i },
  { name: 'asp.net', header: 'x-powered-by', re: /asp\.net/i },
  { name: 'asp.net', header: 'x-aspnet-version', re: /([\d.]+)/i },
  { name: 'tomcat', header: 'server', re: /tomcat(?:\/([\d.]+))?/i },
  { name: 'jetty', header: 'server', re: /jetty(?:\/([\d.]+))?/i },
  { name: 'gunicorn', header: 'server', re: /gunicorn(?:\/([\d.]+))?/i },
  { name: 'kestrel', header: 'server', re: /kestrel/i },
];

// Content (HTML) patterns — especially content management systems
const BODY_RULES = [
  { name: 'wordpress', re: /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([\d.]+)?/i },
  { name: 'wordpress', re: /\/wp-(content|includes)\//i },
  { name: 'joomla', re: /<meta[^>]+name=["']generator["'][^>]+content=["']Joomla!?\s*([\d.]+)?/i },
  { name: 'drupal', re: /(Drupal\.settings|\/sites\/(all|default)\/)/i },
  { name: 'drupal', re: /<meta[^>]+name=["']Generator["'][^>]+content=["']Drupal\s*([\d]+)?/i },
  { name: 'magento', re: /(Mage\.|\/skin\/frontend\/|mage\/cookies)/i },
  { name: 'shopify', re: /cdn\.shopify\.com/i },
  { name: 'react', re: /(data-reactroot|__REACT_DEVTOOLS)/i },
  { name: 'vue', re: /(data-v-[0-9a-f]{8}|__VUE__)/i },
  { name: 'angular', re: /(ng-version=["']([\d.]+)|ng-app)/i },
  { name: 'laravel', re: /(laravel_session|XSRF-TOKEN)/i },
  { name: 'django', re: /(csrftoken|__admin_media_prefix__)/i },
  { name: 'jquery', re: /jquery[.-]([\d.]+)(?:\.min)?\.js/i },
  { name: 'bootstrap', re: /bootstrap[.-]([\d.]+)(?:\.min)?\.(css|js)/i },
];

// Cookie patterns to detect the framework
const COOKIE_RULES = [
  { name: 'php', re: /PHPSESSID/i },
  { name: 'asp.net', re: /ASP\.NET_SessionId/i },
  { name: 'java', re: /JSESSIONID/i },
  { name: 'laravel', re: /laravel_session/i },
  { name: 'express', re: /connect\.sid/i },
];

export function fingerprint({ headers = {}, body = '', cookies = [] }) {
  const found = new Map(); // name -> {name, version, evidence}

  const add = (name, version, evidence) => {
    const existing = found.get(name);
    if (existing) {
      if (!existing.version && version) existing.version = version;
      if (!existing.evidence.includes(evidence)) existing.evidence.push(evidence);
    } else {
      found.set(name, { name, version: version || null, evidence: [evidence] });
    }
  };

  // headers
  for (const rule of RULES) {
    const val = headers[rule.header];
    if (!val) continue;
    const m = rule.re.exec(val);
    if (m) add(rule.name, m[1] || null, `header:${rule.header}`);
  }

  // content
  for (const rule of BODY_RULES) {
    const m = rule.re.exec(body);
    if (m) add(rule.name, m[1] || null, 'body');
  }

  // cookies
  const cookieStr = Array.isArray(cookies) ? cookies.join('; ') : String(cookies || '');
  for (const rule of COOKIE_RULES) {
    if (rule.re.test(cookieStr)) add(rule.name, null, 'cookie');
  }

  return [...found.values()];
}
