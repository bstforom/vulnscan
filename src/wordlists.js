// src/wordlists.js
// Categorized sensitive-path lists for exposure checks (one GET per path, non-destructive).
// Each item: { path, severity, title, category, cwe, sig?, binary? }
//  - sig:    regex the response body must match to confirm the finding (removes false positives).
//  - binary: file is binary/downloadable; confirmed if it is not an HTML page.
//  - no sig/binary: generic existence check (lower confidence).

export const SENSITIVE_PATHS = [
  // ===== Version control systems =====
  { path: '/.git/config', severity: 'HIGH', title: 'Exposed Git repository (.git/config)', category: 'vcs', cwe: 'CWE-527', sig: /\[core\]|repositoryformatversion|\[remote/i },
  { path: '/.git/HEAD', severity: 'HIGH', title: 'Exposed Git repository (.git/HEAD)', category: 'vcs', cwe: 'CWE-527', sig: /ref:\s*refs\/|^[0-9a-f]{40}/i },
  { path: '/.svn/entries', severity: 'HIGH', title: 'Exposed SVN repository', category: 'vcs', cwe: 'CWE-527', sig: /svn|dir\n|\d+\n/i },
  { path: '/.hg/requires', severity: 'MEDIUM', title: 'Exposed Mercurial repository', category: 'vcs', cwe: 'CWE-527', sig: /revlogv1|dotencode|store/i },

  // ===== Environment & config files =====
  { path: '/.env', severity: 'CRITICAL', title: 'Exposed environment file (.env)', category: 'config', cwe: 'CWE-215', sig: /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=|\b(?:APP_KEY|DB_|SECRET|API_?KEY|TOKEN|PASSWORD)\b/ },
  { path: '/.env.local', severity: 'CRITICAL', title: 'Exposed environment file (.env.local)', category: 'config', cwe: 'CWE-215', sig: /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=|\b(?:APP_KEY|DB_|SECRET)\b/ },
  { path: '/.env.production', severity: 'CRITICAL', title: 'Exposed production environment file', category: 'config', cwe: 'CWE-215', sig: /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=|\b(?:APP_KEY|DB_|SECRET)\b/ },
  { path: '/appsettings.json', severity: 'HIGH', title: 'Exposed .NET settings (appsettings.json)', category: 'config', cwe: 'CWE-538', sig: /"ConnectionStrings"|"Logging"|"AllowedHosts"/ },
  { path: '/web.config', severity: 'HIGH', title: 'Exposed web.config', category: 'config', cwe: 'CWE-538', sig: /<configuration>|<system\.web/i },
  { path: '/application.properties', severity: 'HIGH', title: 'Exposed Spring configuration', category: 'config', cwe: 'CWE-538', sig: /spring\.|server\.port|datasource/i },
  { path: '/application.yml', severity: 'HIGH', title: 'Exposed Spring configuration (yml)', category: 'config', cwe: 'CWE-538', sig: /spring:|datasource:|server:/i },
  { path: '/wp-config.php.bak', severity: 'CRITICAL', title: 'Exposed wp-config.php.bak backup', category: 'config', cwe: 'CWE-530', sig: /DB_PASSWORD|DB_NAME|wpdb|AUTH_KEY/i },
  { path: '/.htaccess', severity: 'MEDIUM', title: 'Readable .htaccess file', category: 'config', cwe: 'CWE-538', sig: /RewriteEngine|RewriteRule|<Directory|Options\s/i },
  { path: '/.htpasswd', severity: 'HIGH', title: 'Exposed .htpasswd file', category: 'config', cwe: 'CWE-522', sig: /^[^:\s]+:\$?(?:apr1|1|2[aby]|6)?\$/m },
  { path: '/.npmrc', severity: 'HIGH', title: 'Exposed .npmrc file', category: 'config', cwe: 'CWE-522', sig: /_authToken|registry=|\/\/.*:_/i },

  // ===== Backups & database dumps =====
  { path: '/backup.zip', severity: 'HIGH', title: 'Exposed backup archive (zip)', category: 'backup', cwe: 'CWE-530', binary: true },
  { path: '/backup.tar.gz', severity: 'HIGH', title: 'Exposed backup archive (tar.gz)', category: 'backup', cwe: 'CWE-530', binary: true },
  { path: '/backup.sql', severity: 'CRITICAL', title: 'Exposed database dump (backup.sql)', category: 'backup', cwe: 'CWE-530', sig: /CREATE TABLE|INSERT INTO|DROP TABLE|MySQL dump|PostgreSQL database dump/i },
  { path: '/database.sql', severity: 'CRITICAL', title: 'Exposed database dump (database.sql)', category: 'backup', cwe: 'CWE-530', sig: /CREATE TABLE|INSERT INTO|DROP TABLE|dump/i },
  { path: '/dump.sql', severity: 'CRITICAL', title: 'Exposed database dump (dump.sql)', category: 'backup', cwe: 'CWE-530', sig: /CREATE TABLE|INSERT INTO|DROP TABLE|dump/i },
  { path: '/db.sql', severity: 'CRITICAL', title: 'Exposed database dump (db.sql)', category: 'backup', cwe: 'CWE-530', sig: /CREATE TABLE|INSERT INTO|DROP TABLE|dump/i },
  { path: '/site.zip', severity: 'HIGH', title: 'Exposed site archive (site.zip)', category: 'backup', cwe: 'CWE-530', binary: true },
  { path: '/config.php.bak', severity: 'HIGH', title: 'Exposed config file backup', category: 'backup', cwe: 'CWE-530', sig: /<\?php|define\(|\$config|password/i },

  // ===== Admin panels =====
  { path: '/administrator/', severity: 'INFO', title: 'Joomla admin panel', category: 'admin', cwe: 'CWE-284', sig: /Joomla|com_login|administrator/i },
  { path: '/wp-admin/', severity: 'INFO', title: 'WordPress admin panel', category: 'admin', cwe: 'CWE-284', sig: /wp-login|wp-admin|WordPress/i },
  { path: '/phpmyadmin/', severity: 'MEDIUM', title: 'Exposed phpMyAdmin', category: 'admin', cwe: 'CWE-284', sig: /phpMyAdmin|pma_|pmahomme/i },
  { path: '/adminer.php', severity: 'MEDIUM', title: 'Exposed Adminer', category: 'admin', cwe: 'CWE-284', sig: /Adminer|adminer\.org/i },
  { path: '/manager/html', severity: 'MEDIUM', title: 'Exposed Tomcat Manager', category: 'admin', cwe: 'CWE-284', sig: /Tomcat|Manager Application/i },

  // ===== Information disclosure =====
  { path: '/phpinfo.php', severity: 'HIGH', title: 'Exposed phpinfo()', category: 'info', cwe: 'CWE-200', sig: /phpinfo\(\)|PHP Version|php_?info/i },
  { path: '/info.php', severity: 'HIGH', title: 'Exposed info.php (phpinfo)', category: 'info', cwe: 'CWE-200', sig: /phpinfo\(\)|PHP Version/i },
  { path: '/server-status', severity: 'MEDIUM', title: 'Exposed Apache server-status', category: 'info', cwe: 'CWE-200', sig: /Apache Server Status|Server uptime|requests currently being processed/i },
  { path: '/server-info', severity: 'MEDIUM', title: 'Exposed Apache server-info', category: 'info', cwe: 'CWE-200', sig: /Apache Server Information|Server Settings|Module Name/i },
  { path: '/nginx_status', severity: 'MEDIUM', title: 'Exposed nginx status', category: 'info', cwe: 'CWE-200', sig: /Active connections|server accepts handled/i },
  { path: '/.well-known/security.txt', severity: 'INFO', title: 'security.txt present', category: 'info', cwe: null, sig: /Contact:|Policy:|Expires:/i },
  { path: '/robots.txt', severity: 'INFO', title: 'robots.txt present', category: 'info', cwe: null, sig: /User-?agent:|Disallow:|Allow:|Sitemap:/i },
  { path: '/crossdomain.xml', severity: 'LOW', title: 'crossdomain.xml present', category: 'info', cwe: 'CWE-942', sig: /cross-domain-policy|allow-access-from/i },

  // ===== Cloud secrets & keys =====
  { path: '/.aws/credentials', severity: 'CRITICAL', title: 'Exposed AWS credentials', category: 'cloud', cwe: 'CWE-522', sig: /aws_access_key_id|aws_secret_access_key|\[default\]/i },
  { path: '/.ssh/id_rsa', severity: 'CRITICAL', title: 'Exposed SSH private key', category: 'cloud', cwe: 'CWE-522', sig: /BEGIN (?:RSA |OPENSSH )?PRIVATE KEY/ },
  { path: '/id_rsa', severity: 'CRITICAL', title: 'Exposed SSH private key (id_rsa)', category: 'cloud', cwe: 'CWE-522', sig: /BEGIN (?:RSA |OPENSSH )?PRIVATE KEY/ },
  { path: '/Dockerfile', severity: 'LOW', title: 'Exposed Dockerfile', category: 'cloud', cwe: 'CWE-527', sig: /^FROM\s|RUN\s|COPY\s|ENTRYPOINT/im },
  { path: '/docker-compose.yml', severity: 'MEDIUM', title: 'Exposed docker-compose.yml', category: 'cloud', cwe: 'CWE-538', sig: /services:|image:|version:\s*["']?\d/i },
  { path: '/.gitlab-ci.yml', severity: 'LOW', title: 'Exposed GitLab CI config', category: 'cloud', cwe: 'CWE-527', sig: /stages:|script:|image:/i },

  // ===== API & documentation =====
  { path: '/swagger-ui.html', severity: 'LOW', title: 'Exposed Swagger UI', category: 'api', cwe: 'CWE-200', sig: /swagger-ui|Swagger UI/i },
  { path: '/swagger.json', severity: 'LOW', title: 'Exposed Swagger spec', category: 'api', cwe: 'CWE-200', sig: /"swagger"\s*:|"paths"\s*:/i },
  { path: '/openapi.json', severity: 'LOW', title: 'Exposed OpenAPI spec', category: 'api', cwe: 'CWE-200', sig: /"openapi"\s*:|"paths"\s*:/i },
  { path: '/v2/api-docs', severity: 'LOW', title: 'Exposed Springfox API docs', category: 'api', cwe: 'CWE-200', sig: /"swagger"|"paths"|"definitions"/i },
  { path: '/graphiql', severity: 'MEDIUM', title: 'Exposed GraphiQL IDE', category: 'api', cwe: 'CWE-200', sig: /GraphiQL|graphiql/i },

  // ===== Spring Boot Actuator =====
  { path: '/actuator', severity: 'MEDIUM', title: 'Exposed Spring Actuator', category: 'actuator', cwe: 'CWE-200', sig: /"_links"|"self"|actuator/i },
  { path: '/actuator/health', severity: 'INFO', title: 'Exposed Actuator health', category: 'actuator', cwe: 'CWE-200', sig: /"status"\s*:\s*"(?:UP|DOWN)"/i },
  { path: '/actuator/env', severity: 'HIGH', title: 'Exposed Actuator env (environment variables)', category: 'actuator', cwe: 'CWE-200', sig: /"propertySources"|"activeProfiles"|"systemProperties"/i },
  { path: '/actuator/heapdump', severity: 'CRITICAL', title: 'Exposed Actuator heapdump', category: 'actuator', cwe: 'CWE-200', binary: true },
  { path: '/env', severity: 'MEDIUM', title: 'Exposed /env endpoint', category: 'actuator', cwe: 'CWE-200', sig: /"propertySources"|"activeProfiles"/i },

  // ===== Miscellaneous =====
  { path: '/.DS_Store', severity: 'LOW', title: 'Exposed .DS_Store file', category: 'misc', cwe: 'CWE-527', sig: /Bud1|\x00\x00\x00\x01Bud1/ },
  { path: '/.vscode/settings.json', severity: 'LOW', title: 'Exposed VS Code settings', category: 'misc', cwe: 'CWE-527', sig: /"editor\.|"files\.|"\w+\.\w+"\s*:/i },
  { path: '/.idea/workspace.xml', severity: 'LOW', title: 'Exposed IntelliJ settings', category: 'misc', cwe: 'CWE-527', sig: /<project|<component name/i },
  { path: '/package.json', severity: 'LOW', title: 'Exposed package.json', category: 'misc', cwe: 'CWE-527', sig: /"dependencies"|"devDependencies"|"scripts"/i },
  { path: '/composer.json', severity: 'LOW', title: 'Exposed composer.json', category: 'misc', cwe: 'CWE-527', sig: /"require"|"autoload"|"psr-4"/i },
];

// Web Application Firewall (WAF) signatures
export const WAF_SIGNATURES = [
  { name: 'Cloudflare', header: 'cf-ray', re: /.+/ },
  { name: 'Cloudflare', header: 'server', re: /cloudflare/i },
  { name: 'Sucuri', header: 'x-sucuri-id', re: /.+/ },
  { name: 'Sucuri', header: 'server', re: /sucuri/i },
  { name: 'Incapsula/Imperva', header: 'x-iinfo', re: /.+/ },
  { name: 'Incapsula/Imperva', header: 'set-cookie', re: /incap_ses|visid_incap/i },
  { name: 'Akamai', header: 'server', re: /akamaighost/i },
  { name: 'AWS CloudFront', header: 'server', re: /cloudfront/i },
  { name: 'AWS WAF', header: 'x-amzn-requestid', re: /.+/ },
  { name: 'F5 BIG-IP', header: 'set-cookie', re: /BIGipServer/ },
  { name: 'Barracuda', header: 'set-cookie', re: /barra_counter_session/i },
  { name: 'Fastly', header: 'x-fastly-request-id', re: /.+/ },
  { name: 'ModSecurity', header: 'server', re: /mod_security|modsecurity/i },
  { name: 'Wordfence', header: 'server', re: /wordfence/i },
];

// Extract common JS library versions from script URLs (for CVE correlation)
export const JS_LIB_PATTERNS = [
  { name: 'jquery', re: /jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i },
  { name: 'angularjs', re: /angular[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i },
  { name: 'bootstrap', re: /bootstrap[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)/i },
  { name: 'vue', re: /vue[@-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i },
  { name: 'react', re: /react[@-]?(\d+\.\d+(?:\.\d+)?)(?:\.min|\.production)?\.js/i },
  { name: 'lodash', re: /lodash[@-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i },
  { name: 'moment', re: /moment[@-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i },
  { name: 'ckeditor', re: /ckeditor[-.]?(\d+\.\d+(?:\.\d+)?)/i },
  { name: 'tinymce', re: /tinymce[-.]?(\d+\.\d+(?:\.\d+)?)/i },
  { name: 'handlebars', re: /handlebars[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i },
];
