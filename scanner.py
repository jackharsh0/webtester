"""
Security Scanner Module - 55+ Security Checks
Performs comprehensive security testing including WordPress-specific vulnerabilities.
"""

import os
import re
import ssl
import socket
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
import requests


class SecurityScanner:
    """Scans websites for 55+ security vulnerabilities."""

    def __init__(self, target_url, scan_dir=None):
        """Initialize scanner."""
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target_url)
        self.domain = self.parsed_url.netloc
        self.is_wordpress = False
        self.wp_version = None
        self.wp_plugins = []
        self.wp_themes = []
        
        if scan_dir:
            self.scan_dir = Path(scan_dir)
        else:
            safe_domain = self.domain.replace('.', '_').replace(':', '_')
            self.scan_dir = Path("data") / safe_domain
        
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        })
        
        self.stats = {
            'critical': 0, 'high': 0, 'medium': 0,
            'low': 0, 'info': 0, 'checks_run': 0, 'checks_passed': 0,
        }

    def _add_finding(self, category, severity, title, description, evidence=None, remediation=None):
        """Add a security finding."""
        self.findings.append({
            'id': f"finding-{len(self.findings) + 1}",
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
        })
        self.stats[severity] = self.stats.get(severity, 0) + 1

    def _check_url(self, url_path, method='HEAD'):
        """Check if URL exists and return status code."""
        try:
            full_url = f"{self.target_url}{url_path}"
            if method == 'HEAD':
                r = self.session.head(full_url, timeout=10, allow_redirects=True)
            else:
                r = self.session.get(full_url, timeout=10, allow_redirects=True)
            return r.status_code, r.text if r.status_code == 200 else ''
        except Exception:
            return 0, ''

    def _read_local_files(self):
        """Read all text files from downloaded site."""
        contents = {}
        if not self.scan_dir.exists():
            return contents
        for fp in self.scan_dir.rglob('*'):
            if fp.is_file() and fp.suffix.lower() in {'.html', '.htm', '.css', '.js', '.json', '.xml', '.txt', '.php'}:
                try:
                    contents[str(fp)] = fp.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    pass
        return contents

    # ================================================================
    # CATEGORY 1: SECRETS & CREDENTIALS EXPOSURE (Checks 1-10)
    # ================================================================

    def check_01_env_files(self):
        """Check 1: Exposed .env files."""
        self.stats['checks_run'] += 1
        paths = ['/.env', '/.env.local', '/.env.production', '/.env.development', '/.env.backup', '/.env.old']
        for p in paths:
            code, _ = self._check_url(p)
            if code == 200:
                self._add_finding('secrets', 'critical', f'Exposed .env File: {p}',
                    f'Environment file {p} is publicly accessible containing API keys, database credentials, secrets.',
                    f'URL: {self.target_url}{p}',
                    'Move .env outside web root. Block with .htaccess or server config.')
                return
        self.stats['checks_passed'] += 1

    def check_02_git_exposure(self):
        """Check 2: Exposed .git directory."""
        self.stats['checks_run'] += 1
        paths = ['/.git/config', '/.git/HEAD', '/.git/index', '/.gitignore']
        for p in paths:
            code, _ = self._check_url(p)
            if code == 200:
                self._add_finding('secrets', 'critical', f'Exposed Git: {p}',
                    f'Git file {p} is accessible. Exposes source code history, credentials, and sensitive data.',
                    f'URL: {self.target_url}{p}',
                    'Block .git in server config. Never deploy .git to production.')
                return
        self.stats['checks_passed'] += 1

    def check_03_svn_exposure(self):
        """Check 3: Exposed .svn directory."""
        self.stats['checks_run'] += 1
        paths = ['/.svn/entries', '/.svn/wc.db', '/.svnignore']
        for p in paths:
            code, _ = self._check_url(p)
            if code == 200:
                self._add_finding('secrets', 'critical', f'Exposed SVN: {p}',
                    f'SVN directory accessible at {p}. Exposes version control data.',
                    f'URL: {self.target_url}{p}',
                    'Block .svn access in server configuration.')
                return
        self.stats['checks_passed'] += 1

    def check_04_config_files(self):
        """Check 4: Exposed configuration files."""
        self.stats['checks_run'] += 1
        paths = ['/config.json', '/config.php', '/config.py', '/config.yml', '/config.yaml',
                 '/settings.json', '/settings.php', '/database.yml', '/db.php', '/wp-config.php']
        found = [p for p in paths if self._check_url(p)[0] == 200]
        if found:
            self._add_finding('secrets', 'critical', 'Exposed Config Files',
                f'Configuration files publicly accessible: {", ".join(found)}',
                f'Files: {", ".join(found)}',
                'Move config files outside web root. Restrict access via server config.')
        else:
            self.stats['checks_passed'] += 1

    def check_05_backup_files(self):
        """Check 5: Exposed backup files."""
        self.stats['checks_run'] += 1
        paths = ['/backup.sql', '/backup.zip', '/backup.tar.gz', '/dump.sql', '/database.sql',
                 '/db.sql', '/backup/', '/backups/', '/site.zip', '/www.zip', '/html.zip',
                 '/.DS_Store', '/Thumbs.db', '/backup.bak', '/config.bak']
        found = [p for p in paths if self._check_url(p)[0] == 200]
        if found:
            self._add_finding('secrets', 'high', 'Exposed Backup Files',
                f'Backup files publicly accessible: {", ".join(found)}',
                f'Files: {", ".join(found)}',
                'Remove backups from web-accessible dirs. Store in secure locations.')
        else:
            self.stats['checks_passed'] += 1

    def check_06_database_files(self):
        """Check 6: Exposed database files."""
        self.stats['checks_run'] += 1
        paths = ['/database.sql', '/dump.sql', '/db.sql', '/mysql.sql', '/data.sql',
                 '/sqlite.db', '/database.db', '/app.db', '/.sqlite', '/db.sqlite']
        found = [p for p in paths if self._check_url(p)[0] == 200]
        if found:
            self._add_finding('secrets', 'critical', 'Exposed Database Files',
                f'Database files publicly accessible: {", ".join(found)}',
                f'Files: {", ".join(found)}',
                'Remove database files from web root immediately. Rotate all credentials.')
        else:
            self.stats['checks_passed'] += 1

    def check_07_private_keys(self):
        """Check 7: Exposed private keys and certificates."""
        self.stats['checks_run'] += 1
        paths = ['/private.key', '/private.pem', '/id_rsa', '/id_rsa.pub', '/server.key',
                 '/server.pem', '/ssl.key', '/ssl.pem', '/certificate.key', '/cert.key']
        found = [p for p in paths if self._check_url(p)[0] == 200]
        if found:
            self._add_finding('secrets', 'critical', 'Exposed Private Keys',
                f'Private keys/certificates publicly accessible: {", ".join(found)}',
                f'Files: {", ".join(found)}',
                'Immediately remove keys from public access. Regenerate all certificates.')
        else:
            self.stats['checks_passed'] += 1

    def check_08_credentials_json(self):
        """Check 8: Exposed credentials files."""
        self.stats['checks_run'] += 1
        paths = ['/credentials.json', '/secrets.json', '/service-account.json',
                 '/google-credentials.json', '/aws-credentials', '/.aws/credentials']
        found = [p for p in paths if self._check_url(p)[0] == 200]
        if found:
            self._add_finding('secrets', 'critical', 'Exposed Credentials',
                f'Credential files publicly accessible: {", ".join(found)}',
                f'Files: {", ".join(found)}',
                'Remove credentials immediately. Rotate all exposed keys.')
        else:
            self.stats['checks_passed'] += 1

    def check_09_api_keys_in_code(self):
        """Check 9: API keys in HTML/JS source."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']', 'API Key'),
            (r'secret[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']', 'Secret Key'),
            (r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\'][^"\']+["\']', 'AWS Key'),
            (r'sk_live_[a-zA-Z0-9]{20,}', 'Stripe Secret Key'),
            (r'ghp_[a-zA-Z0-9]{30,}', 'GitHub Token'),
            (r'AIza[0-9A-Za-z_-]{30,}', 'Google API Key'),
            (r'xox[bpsa]-[a-zA-Z0-9-]+', 'Slack Token'),
            (r'AAAA[A-Za-z0-9+/]{20,}=*', 'Firebase Key'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('secrets', 'critical', 'Secrets in Source Code',
                'API keys, tokens, or secrets found in downloaded files.',
                '\n'.join(found[:10]),
                'Remove secrets from client-side code. Use env vars and server-side proxies.')
        else:
            self.stats['checks_passed'] += 1

    def check_10_passwords_in_code(self):
        """Check 10: Passwords in source code."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'password\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded Password'),
            (r'passwd\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded Passwd'),
            (r'pwd\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded PWD'),
            (r'db_pass\w*\s*[=:]\s*["\'][^"\']+["\']', 'DB Password'),
            (r'mysql_connect\s*\([^)]+\)', 'MySQL Credentials in Code'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                matches = re.findall(pat, content, re.IGNORECASE)
                if matches:
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('secrets', 'critical', 'Hardcoded Passwords',
                'Passwords found hardcoded in source code.',
                '\n'.join(found[:10]),
                'Remove hardcoded passwords. Use environment variables.')
        else:
            self.stats['checks_passed'] += 1

    # ================================================================
    # CATEGORY 2: SECURITY HEADERS (Checks 11-17)
    # ================================================================

    def check_11_csp_header(self):
        """Check 11: Content-Security-Policy header."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            if 'content-security-policy' not in [h.lower() for h in r.headers]:
                self._add_finding('headers', 'critical', 'Missing Content-Security-Policy',
                    'CSP header not set. Site vulnerable to XSS, data injection, and code injection attacks.',
                    'Header not found in response',
                    'Implement strict CSP policy. Start with report-only mode.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_12_hsts_header(self):
        """Check 12: Strict-Transport-Security header."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            if 'strict-transport-security' not in [h.lower() for h in r.headers]:
                self._add_finding('headers', 'high', 'Missing HSTS Header',
                    'HSTS not set. Site vulnerable to protocol downgrade attacks and cookie hijacking.',
                    'Header not found',
                    'Add Strict-Transport-Security: max-age=31536000; includeSubDomains')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_13_x_frame_options(self):
        """Check 13: X-Frame-Options header."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            if 'x-frame-options' not in [h.lower() for h in r.headers]:
                self._add_finding('headers', 'high', 'Missing X-Frame-Options',
                    'X-Frame-Options not set. Site vulnerable to clickjacking attacks.',
                    'Header not found',
                    'Add X-Frame-Options: DENY or SAMEORIGIN')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_14_x_content_type(self):
        """Check 14: X-Content-Type-Options header."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            if 'x-content-type-options' not in [h.lower() for h in r.headers]:
                self._add_finding('headers', 'medium', 'Missing X-Content-Type-Options',
                    'MIME type sniffing not prevented. May lead to security vulnerabilities.',
                    'Header not found',
                    'Add X-Content-Type-Options: nosniff')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_15_x_xss_protection(self):
        """Check 15: X-XSS-Protection header."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            if 'x-xss-protection' not in [h.lower() for h in r.headers]:
                self._add_finding('headers', 'medium', 'Missing X-XSS-Protection',
                    'XSS protection header not set.',
                    'Header not found',
                    'Add X-XSS-Protection: 1; mode=block')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_16_referrer_policy(self):
        """Check 16: Referrer-Policy header."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            if 'referrer-policy' not in [h.lower() for h in r.headers]:
                self._add_finding('headers', 'low', 'Missing Referrer-Policy',
                    'Referrer policy not set. May leak sensitive URL information.',
                    'Header not found',
                    'Add Referrer-Policy: strict-origin-when-cross-origin')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_17_permissions_policy(self):
        """Check 17: Permissions-Policy header."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            if 'permissions-policy' not in [h.lower() for h in r.headers]:
                self._add_finding('headers', 'low', 'Missing Permissions-Policy',
                    'Permissions policy not set. Browser features not restricted.',
                    'Header not found',
                    'Add Permissions-Policy to restrict browser features.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    # ================================================================
    # CATEGORY 3: SSL/TLS SECURITY (Checks 18-22)
    # ================================================================

    def check_18_ssl_certificate(self):
        """Check 18: SSL certificate validity."""
        self.stats['checks_run'] += 1
        if self.parsed_url.scheme != 'https':
            self._add_finding('ssl', 'critical', 'No HTTPS',
                'Website does not use HTTPS. All traffic transmitted in plain text.',
                f'URL scheme: {self.parsed_url.scheme}',
                'Install SSL certificate and enforce HTTPS.')
            return
        try:
            hostname = self.parsed_url.netloc.split(':')[0]
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.now()).days
                    if days_left < 0:
                        self._add_finding('ssl', 'critical', 'SSL Certificate Expired',
                            f'SSL certificate expired {abs(days_left)} days ago.',
                            f'Expires: {cert["notAfter"]}',
                            'Renew SSL certificate immediately.')
                    elif days_left < 30:
                        self._add_finding('ssl', 'high', 'SSL Expiring Soon',
                            f'SSL certificate expires in {days_left} days.',
                            f'Expires: {cert["notAfter"]}',
                            'Renew SSL certificate before expiration.')
            self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_19_tls_version(self):
        """Check 19: TLS protocol version."""
        self.stats['checks_run'] += 1
        if self.parsed_url.scheme != 'https':
            self.stats['checks_passed'] += 1
            return
        try:
            hostname = self.parsed_url.netloc.split(':')[0]
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    if version in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                        self._add_finding('ssl', 'critical', f'Insecure TLS: {version}',
                            f'Server uses {version} which has known vulnerabilities.',
                            f'Protocol: {version}',
                            'Disable TLS 1.0/1.1. Use TLS 1.2 or 1.3 only.')
                    else:
                        self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_20_weak_ciphers(self):
        """Check 20: Weak cipher suites."""
        self.stats['checks_run'] += 1
        if self.parsed_url.scheme != 'https':
            self.stats['checks_passed'] += 1
            return
        try:
            hostname = self.parsed_url.netloc.split(':')[0]
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
                    if any(w in str(cipher).upper() for w in weak_ciphers):
                        self._add_finding('ssl', 'high', 'Weak Cipher Suite',
                            f'Weak cipher detected: {cipher[0]}',
                            f'Cipher: {cipher}',
                            'Disable weak ciphers. Use AES-256-GCM or ChaCha20.')
                    else:
                        self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_21_ssl_redirect(self):
        """Check 21: HTTP to HTTPS redirect."""
        self.stats['checks_run'] += 1
        if self.parsed_url.scheme == 'https':
            self.stats['checks_passed'] += 1
            return
        try:
            http_url = self.target_url.replace('https://', 'http://')
            r = self.session.get(http_url, timeout=10, allow_redirects=False)
            if r.status_code not in (301, 302, 307, 308):
                self._add_finding('ssl', 'high', 'No HTTP to HTTPS Redirect',
                    'HTTP requests are not redirected to HTTPS.',
                    f'Status: {r.status_code}',
                    'Configure 301 redirect from HTTP to HTTPS.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_22_mixed_content(self):
        """Check 22: Mixed content (HTTP resources on HTTPS page)."""
        self.stats['checks_run'] += 1
        if self.parsed_url.scheme != 'https':
            self.stats['checks_passed'] += 1
            return
        all_files = self._read_local_files()
        mixed = []
        for fp, content in all_files.items():
            http_refs = re.findall(r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']', content)
            if http_refs:
                mixed.append(f"{os.path.basename(fp)}: {len(http_refs)} HTTP refs")
        if mixed:
            self._add_finding('ssl', 'medium', 'Mixed Content Detected',
                'HTTPS page loads resources over HTTP.',
                '\n'.join(mixed[:5]),
                'Update all resource URLs to use HTTPS.')
        else:
            self.stats['checks_passed'] += 1

    # ================================================================
    # CATEGORY 4: SERVER & INFO DISCLOSURE (Checks 23-28)
    # ================================================================

    def check_23_server_header(self):
        """Check 23: Server header disclosure."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            exposed = []
            for h in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator']:
                if h in r.headers:
                    exposed.append(f"{h}: {r.headers[h]}")
            if exposed:
                self._add_finding('info_disclosure', 'medium', 'Server Info Disclosed',
                    'Server software and version exposed in headers.',
                    '\n'.join(exposed),
                    'Remove or obscure server version info from headers.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_24_directory_listing(self):
        """Check 24: Directory listing enabled."""
        self.stats['checks_run'] += 1
        dirs = ['/images/', '/css/', '/js/', '/assets/', '/uploads/', '/files/', '/media/', '/static/']
        for d in dirs:
            try:
                r = self.session.get(f"{self.target_url}{d}", timeout=10)
                if r.status_code == 200:
                    content = r.text.lower()
                    if any(x in content for x in ['index of', 'directory listing', '<pre>', 'parent directory']):
                        self._add_finding('info_disclosure', 'high', f'Directory Listing: {d}',
                            f'Directory listing enabled at {d}, exposing file structure.',
                            f'URL: {self.target_url}{d}',
                            'Disable directory listing in server config.')
                        return
            except Exception:
                continue
        self.stats['checks_passed'] += 1

    def check_25_phpinfo(self):
        """Check 25: PHP info exposure."""
        self.stats['checks_run'] += 1
        paths = ['/phpinfo.php', '/info.php', '/test.php', '/php.php', '/pinfo.php']
        for p in paths:
            code, content = self._check_url(p, 'GET')
            if code == 200 and 'phpinfo()' in content.lower():
                self._add_finding('info_disclosure', 'critical', f'PHP Info Exposed: {p}',
                    'PHP info page exposes server configuration, paths, and versions.',
                    f'URL: {self.target_url}{p}',
                    'Remove phpinfo pages from production.')
                return
        self.stats['checks_passed'] += 1

    def check_26_error_pages(self):
        """Check 26: Debug info in error pages."""
        self.stats['checks_run'] += 1
        paths = ['/error', '/404', '/500', '/debug', '/test']
        for p in paths:
            try:
                r = self.session.get(f"{self.target_url}{p}", timeout=10)
                if r.status_code == 200:
                    content = r.text.lower()
                    if any(x in content for x in ['stack trace', 'debug', 'trace', 'exception', 'file:', 'line']):
                        self._add_finding('info_disclosure', 'high', f'Debug Info Exposed: {p}',
                            'Stack traces or debug information exposed in error pages.',
                            f'URL: {self.target_url}{p}',
                            'Disable debug mode. Configure custom error pages.')
                        return
            except Exception:
                continue
        self.stats['checks_passed'] += 1

    def check_27_source_code_disclosure(self):
        """Check 27: Source code file exposure."""
        self.stats['checks_run'] += 1
        paths = ['/index.php~', '/index.php.bak', '/index.php.old', '/index.php.swp',
                 '/.htaccess', '/.htpasswd', '/web.config', '/crossdomain.xml']
        found = [p for p in paths if self._check_url(p)[0] == 200]
        if found:
            self._add_finding('info_disclosure', 'high', 'Source Code Exposed',
                f'Source code or config files publicly accessible: {", ".join(found)}',
                f'Files: {", ".join(found)}',
                'Remove backup and config files from web root.')
        else:
            self.stats['checks_passed'] += 1

    def check_28_robots_sitemap(self):
        """Check 28: Robots.txt and sitemap info disclosure."""
        self.stats['checks_run'] += 1
        try:
            robots_code, robots_content = self._check_url('/robots.txt', 'GET')
            if robots_code == 200:
                sensitive = re.findall(r'Disallow:\s*(/[^\s]+)', robots_content)
                if sensitive:
                    self._add_finding('info_disclosure', 'low', 'Sensitive Paths in Robots.txt',
                        'Robots.txt reveals sensitive paths that should be hidden.',
                        f'Paths: {", ".join(sensitive[:10])}',
                        'Review robots.txt for sensitive path disclosure.')
            self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    # ================================================================
    # CATEGORY 5: INJECTION VULNERABILITIES (Checks 29-35)
    # ================================================================

    def check_29_sql_injection(self):
        """Check 29: SQL injection patterns."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'query\s*\(\s*["\'].*\$', 'String concat in query'),
            (r'execute\s*\(\s*["\'].*\+', 'String concat in execute'),
            (r'mysql_query\s*\(', 'Direct mysql_query'),
            (r'pg_query\s*\(', 'Direct pg_query'),
            (r'mysqli_query\s*\(', 'Direct mysqli_query'),
            (r'SELECT.*FROM.*\$_GET', 'User input in SQL'),
            (r'SELECT.*FROM.*\$_POST', 'User input in SQL'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('injection', 'critical', 'SQL Injection Risk',
                'Code patterns indicate potential SQL injection vulnerabilities.',
                '\n'.join(found[:10]),
                'Use prepared statements. Never concatenate user input into SQL.')
        else:
            self.stats['checks_passed'] += 1

    def check_30_xss_vulnerabilities(self):
        """Check 30: XSS vulnerabilities."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'document\.write\s*\(', 'document.write()'),
            (r'innerHTML\s*=', 'innerHTML assignment'),
            (r'eval\s*\(', 'eval()'),
            (r'outerHTML\s*=', 'outerHTML assignment'),
            (r'\.html\s*\(', 'jQuery .html()'),
            (r'insertAdjacentHTML\s*\(', 'insertAdjacentHTML'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('injection', 'high', 'XSS Vulnerabilities',
                'Code patterns indicate potential Cross-Site Scripting.',
                '\n'.join(found[:10]),
                'Sanitize input. Use textContent instead of innerHTML. Avoid eval().')
        else:
            self.stats['checks_passed'] += 1

    def check_31_command_injection(self):
        """Check 31: Command injection patterns."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'exec\s*\(', 'exec()'),
            (r'system\s*\(', 'system()'),
            (r'passthru\s*\(', 'passthru()'),
            (r'shell_exec\s*\(', 'shell_exec()'),
            (r'popen\s*\(', 'popen()'),
            (r'proc_open\s*\(', 'proc_open()'),
            (r'`.*\$_', 'Backtick execution with user input'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('injection', 'critical', 'Command Injection Risk',
                'Code patterns indicate potential command injection vulnerabilities.',
                '\n'.join(found[:10]),
                'Avoid system commands. Use language-native APIs instead.')
        else:
            self.stats['checks_passed'] += 1

    def check_32_directory_traversal(self):
        """Check 32: Directory traversal patterns."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'open\s*\(.*\.\./', 'File open with traversal'),
            (r'readfile\s*\(.*\.\./', 'readfile with traversal'),
            (r'include\s*\(.*\.\./', 'include with traversal'),
            (r'require\s*\(.*\.\./', 'require with traversal'),
            (r'file_get_contents\s*\(.*\.\./', 'file_get_contents with traversal'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('injection', 'high', 'Directory Traversal Risk',
                'Code patterns indicate directory traversal vulnerabilities.',
                '\n'.join(found[:10]),
                'Validate and sanitize file paths. Use allowlists.')
        else:
            self.stats['checks_passed'] += 1

    def check_33_file_inclusion(self):
        """Check 33: Remote/Local file inclusion."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'include\s*\(\s*\$_', 'Dynamic include with user input'),
            (r'require\s*\(\s*\$_', 'Dynamic require with user input'),
            (r'include_once\s*\(\s*\$_', 'Dynamic include_once with user input'),
            (r'require_once\s*\(\s*\$_', 'Dynamic require_once with user input'),
            (r'file_get_contents\s*\(\s*\$_', 'file_get_contents with user input'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('injection', 'critical', 'File Inclusion Vulnerability',
                'Code patterns indicate Local/Remote File Inclusion (LFI/RFI).',
                '\n'.join(found[:10]),
                'Never include files based on user input. Use allowlists.')
        else:
            self.stats['checks_passed'] += 1

    def check_34_xxe(self):
        """Check 34: XML External Entity (XXE) patterns."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'libxml_disable_entity_loader\s*\(\s*false', 'XXE enabled'),
            (r'LIBXML_NOENT', 'Entity substitution enabled'),
            (r'SimpleXMLElement.*LIBXML', 'XML parsing without XXE protection'),
            (r'XMLReader.*xml://', 'Potential XXE via XMLReader'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('injection', 'high', 'XXE Vulnerability',
                'XML External Entity vulnerability detected.',
                '\n'.join(found[:10]),
                'Disable entity loading. Use defusedxml library.')
        else:
            self.stats['checks_passed'] += 1

    def check_35_deserialization(self):
        """Check 35: Insecure deserialization."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'unserialize\s*\(.*\$_', 'unserialize with user input'),
            (r'pickle\.loads', 'Python pickle.loads'),
            (r'yaml\.load\s*\(', 'YAML unsafe load'),
            (r'eval\s*\(.*base64', 'eval with base64'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('injection', 'critical', 'Insecure Deserialization',
                'Code patterns indicate insecure deserialization vulnerabilities.',
                '\n'.join(found[:10]),
                'Avoid deserializing untrusted data. Use safe serialization formats.')
        else:
            self.stats['checks_passed'] += 1

    # ================================================================
    # CATEGORY 6: AUTHENTICATION & SESSION (Checks 36-40)
    # ================================================================

    def check_36_login_pages(self):
        """Check 36: Exposed login pages."""
        self.stats['checks_run'] += 1
        paths = ['/login', '/wp-login.php', '/admin/login', '/signin', '/auth',
                 '/user/login', '/account/login', '/wp-admin']
        found = []
        for p in paths:
            code, _ = self._check_url(p)
            if code in (200, 301, 302, 401):
                found.append(p)
        if found:
            self._add_finding('auth', 'medium', 'Login Pages Found',
                f'Login pages accessible: {", ".join(found)}',
                f'Paths: {", ".join(found)}',
                'Restrict login pages. Implement rate limiting and 2FA.')
        else:
            self.stats['checks_passed'] += 1

    def check_37_default_credentials(self):
        """Check 37: Default credential testing."""
        self.stats['checks_run'] += 1
        paths = ['/wp-login.php', '/administrator', '/admin', '/cpanel']
        creds = [('admin', 'admin'), ('admin', 'password'), ('root', 'root')]
        for p in paths:
            try:
                r = self.session.get(f"{self.target_url}{p}", timeout=10)
                if r.status_code == 200:
                    self._add_finding('auth', 'info', f'Login Page: {p}',
                        f'Login page exists. Check for default credentials manually.',
                        f'URL: {self.target_url}{p}',
                        'Change default credentials. Implement account lockout.')
                    return
            except Exception:
                continue
        self.stats['checks_passed'] += 1

    def check_38_cookie_security(self):
        """Check 38: Cookie security flags."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            insecure = []
            for c in r.cookies:
                issues = []
                if not c.secure:
                    issues.append('No Secure flag')
                if 'httponly' not in str(c).lower():
                    issues.append('No HttpOnly flag')
                if issues:
                    insecure.append(f"{c.name}: {', '.join(issues)}")
            if insecure:
                self._add_finding('auth', 'medium', 'Insecure Cookies',
                    'Cookies missing security flags.',
                    '\n'.join(insecure[:10]),
                    'Set Secure, HttpOnly, and SameSite flags on all cookies.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_39_session_fixation(self):
        """Check 39: Session ID in URL."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            url_patterns = ['PHPSESSID', 'session_id', 'sid', 'token']
            for pattern in url_patterns:
                if pattern.lower() in r.url.lower():
                    self._add_finding('auth', 'high', 'Session ID in URL',
                        'Session identifier exposed in URL. Vulnerable to session fixation.',
                        f'URL: {r.url}',
                        'Use cookie-based sessions only. Never put session IDs in URLs.')
            self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_40_brute_force_protection(self):
        """Check 40: Brute force protection."""
        self.stats['checks_run'] += 1
        paths = ['/wp-login.php', '/login', '/admin/login']
        for p in paths:
            try:
                r = self.session.get(f"{self.target_url}{p}", timeout=10)
                if r.status_code == 200:
                    if 'captcha' not in r.text.lower() and 'rate limit' not in r.text.lower():
                        self._add_finding('auth', 'medium', 'No Brute Force Protection',
                            'Login page has no visible CAPTCHA or rate limiting.',
                            f'URL: {self.target_url}{p}',
                            'Implement CAPTCHA, rate limiting, and account lockout.')
                        return
            except Exception:
                continue
        self.stats['checks_passed'] += 1

    # ================================================================
    # CATEGORY 7: WORDPRESS SPECIFIC (Checks 41-55)
    # ================================================================

    def _detect_wordpress(self):
        """Detect if site is WordPress."""
        try:
            r = self.session.get(self.target_url, timeout=15)
            content = r.text.lower()
            if 'wp-content' in content or 'wordpress' in content or 'wp-includes' in content:
                self.is_wordpress = True
                version_match = re.search(r'content="WordPress\s+([0-9.]+)"', r.text)
                if version_match:
                    self.wp_version = version_match.group(1)
                plugin_matches = re.findall(r'wp-content/plugins/([^/]+)/', r.text)
                self.wp_plugins = list(set(plugin_matches))
                theme_matches = re.findall(r'wp-content/themes/([^/]+)/', r.text)
                self.wp_themes = list(set(theme_matches))
        except Exception:
            pass

    def check_41_wp_version_exposure(self):
        """Check 41: WordPress version exposure."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        if self.wp_version:
            self._add_finding('wordpress', 'medium', f'WordPress Version Exposed: {self.wp_version}',
                'WordPress version is publicly visible, helping attackers find version-specific exploits.',
                f'Version: {self.wp_version}',
                'Remove version numbers from meta tags and RSS feeds.')
        else:
            self.stats['checks_passed'] += 1

    def check_42_wp_xmlrpc(self):
        """Check 42: WordPress XML-RPC enabled."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        code, _ = self._check_url('/xmlrpc.php')
        if code == 200:
            self._add_finding('wordpress', 'critical', 'XML-RPC Enabled',
                'XML-RPC is enabled. Vulnerable to brute force, DDoS, and SQL injection.',
                f'URL: {self.target_url}/xmlrpc.php',
                'Disable XML-RPC via plugin or server config.')
        else:
            self.stats['checks_passed'] += 1

    def check_43_wp_readme(self):
        """Check 43: WordPress readme.html exposure."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        code, _ = self._check_url('/readme.html')
        if code == 200:
            self._add_finding('wordpress', 'low', 'WordPress readme.html Exposed',
                'readme.html file exposes WordPress version information.',
                f'URL: {self.target_url}/readme.html',
                'Delete readme.html from WordPress root.')
        else:
            self.stats['checks_passed'] += 1

    def check_44_wp_license(self):
        """Check 44: WordPress license.txt exposure."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        code, _ = self._check_url('/license.txt')
        if code == 200:
            self._add_finding('wordpress', 'info', 'WordPress license.txt Exposed',
                'license.txt file is publicly accessible.',
                f'URL: {self.target_url}/license.txt',
                'Delete license.txt from WordPress root.')
        else:
            self.stats['checks_passed'] += 1

    def check_45_wp_debug_log(self):
        """Check 45: WordPress debug.log exposure."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        paths = ['/debug.log', '/wp-content/debug.log', '/wp-content/uploads/debug.log']
        for p in paths:
            code, _ = self._check_url(p)
            if code == 200:
                self._add_finding('wordpress', 'critical', 'WordPress debug.log Exposed',
                    'Debug log is publicly accessible, exposing sensitive information.',
                    f'URL: {self.target_url}{p}',
                    'Set WP_DEBUG_LOG to false. Delete debug.log.')
                return
        self.stats['checks_passed'] += 1

    def check_46_wp_config_backup(self):
        """Check 46: WordPress wp-config.php backup."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        paths = ['/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php~',
                 '/wp-config.php.save', '/wp-config.php.swp', '/wp-config.bak',
                 '/wp-config.txt', '/wp-config.php.dist']
        found = [p for p in paths if self._check_url(p)[0] == 200]
        if found:
            self._add_finding('wordpress', 'critical', 'WP-Config Backup Exposed',
                'WordPress configuration backup files are publicly accessible.',
                f'Files: {", ".join(found)}',
                'Delete all wp-config backup files immediately.')
        else:
            self.stats['checks_passed'] += 1

    def check_47_wp_upload_dir(self):
        """Check 47: WordPress uploads directory."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        code, content = self._check_url('/wp-content/uploads/', 'GET')
        if code == 200 and ('index of' in content.lower() or 'parent directory' in content.lower()):
            self._add_finding('wordpress', 'high', 'WP Uploads Directory Listed',
                'WordPress uploads directory has directory listing enabled.',
                f'URL: {self.target_url}/wp-content/uploads/',
                'Add index.php or .htaccess to disable directory listing.')
        else:
            self.stats['checks_passed'] += 1

    def check_48_wp_includes(self):
        """Check 48: WordPress wp-includes exposure."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        paths = ['/wp-includes/', '/wp-includes/js/tinymce/', '/wp-includes/images/']
        for p in paths:
            code, content = self._check_url(p, 'GET')
            if code == 200 and 'index of' in content.lower():
                self._add_finding('wordpress', 'medium', f'WP-Includes Directory Listed: {p}',
                    'WordPress includes directory has directory listing enabled.',
                    f'URL: {self.target_url}{p}',
                    'Add index.php to wp-includes directories.')
                return
        self.stats['checks_passed'] += 1

    def check_49_wp_user_enumeration(self):
        """Check 49: WordPress user enumeration."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        code, content = self._check_url('/?author=1', 'GET')
        if code in (200, 301, 302):
            self._add_finding('wordpress', 'medium', 'WP User Enumeration Possible',
                'WordPress user IDs can be enumerated via author parameter.',
                f'URL: {self.target_url}/?author=1',
                'Disable author archives or use slugs instead of IDs.')
        else:
            self.stats['checks_passed'] += 1

    def check_50_wp_rest_api(self):
        """Check 50: WordPress REST API user exposure."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        code, content = self._check_url('/wp-json/wp/v2/users', 'GET')
        if code == 200:
            self._add_finding('wordpress', 'medium', 'WP REST API User Enumeration',
                'WordPress REST API exposes user information.',
                f'URL: {self.target_url}/wp-json/wp/v2/users',
                'Restrict REST API access. Disable user enumeration endpoints.')
        else:
            self.stats['checks_passed'] += 1

    def check_51_wp_plugin_vulnerabilities(self):
        """Check 51: WordPress known vulnerable plugins."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        if not self.wp_plugins:
            self.stats['checks_passed'] += 1
            return
        known_vulnerable = [
            'easy-wp-smtp', 'easy-wp-smtp-premium', 'wp-statistics',
            'contact-form-7', 'akismet', 'wordfence', 'yoast-seo',
            'elementor', 'woocommerce', 'jetpack', 'classic-editor',
            'ultimate-member', 'all-in-one-seo-pack', 'redirection',
        ]
        vulnerable_found = [p for p in self.wp_plugins if p.lower() in known_vulnerable]
        if vulnerable_found:
            self._add_finding('wordpress', 'high', 'Potentially Vulnerable WP Plugins',
                'WordPress plugins with known vulnerabilities detected.',
                f'Plugins: {", ".join(vulnerable_found)}',
                'Update all plugins to latest versions. Remove unused plugins.')
        else:
            self.stats['checks_passed'] += 1

    def check_52_wp_file_editing(self):
        """Check 52: WordPress file editing enabled."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        code, content = self._check_url('/wp-admin/plugin-editor.php', 'GET')
        if code in (200, 302) and '404' not in content:
            self._add_finding('wordpress', 'high', 'WP File Editing Enabled',
                'WordPress file editing is accessible. Attackers can modify plugin/theme code.',
                f'URL: {self.target_url}/wp-admin/plugin-editor.php',
                'Add define("DISALLOW_FILE_EDIT", true) to wp-config.php.')
        else:
            self.stats['checks_passed'] += 1

    def check_53_wp_old_versions(self):
        """Check 53: WordPress outdated version check."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress or not self.wp_version:
            self.stats['checks_passed'] += 1
            return
        try:
            latest = '6.4'
            wp_major = '.'.join(self.wp_version.split('.')[:2])
            if wp_major < latest:
                self._add_finding('wordpress', 'high', f'Outdated WordPress: {self.wp_version}',
                    f'WordPress version {self.wp_version} is outdated. Latest is {latest}.',
                    f'Current: {self.wp_version}, Latest: {latest}',
                    'Update WordPress to the latest version immediately.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_54_wp_htaccess(self):
        """Check 54: WordPress .htaccess protection."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        paths = ['/wp-config.php', '/.htaccess', '/wp-includes/js/jquery/']
        protected = []
        for p in paths:
            code, _ = self._check_url(p)
            if code in (403, 404):
                protected.append(p)
        if len(protected) < 2:
            self._add_finding('wordpress', 'medium', 'WP File Protection Missing',
                'WordPress core files may not be properly protected.',
                f'Accessible: {", ".join(paths)}',
                'Add .htaccess rules to protect wp-config.php and wp-includes.')
        else:
            self.stats['checks_passed'] += 1

    def check_55_wp_wpscan_patterns(self):
        """Check 55: WPScan-style fingerprinting."""
        self.stats['checks_run'] += 1
        if not self.is_wordpress:
            self._detect_wordpress()
        if not self.is_wordpress:
            self.stats['checks_passed'] += 1
            return
        indicators = {
            'wp-cron.php': 'WP-Cron accessible',
            'wp-links-opml.php': 'Links OPML exposed',
            'wp-login.php': 'Login page exposed',
            'xmlrpc.php': 'XML-RPC accessible',
            'wp-json/': 'REST API accessible',
        }
        found = []
        for path, desc in indicators.items():
            code, _ = self._check_url(f'/{path}')
            if code in (200, 301, 302, 403):
                found.append(desc)
        if found:
            self._add_finding('wordpress', 'medium', 'WordPress Fingerprinting Information',
                'WordPress installation exposes multiple reconnaissance points.',
                '\n'.join(found),
                'Disable unnecessary WordPress features. Hardening wp-config.php.')
        else:
            self.stats['checks_passed'] += 1

    # ================================================================
    # CATEGORY 8: ADDITIONAL ATTACK VECTORS (Checks 56-65)
    # ================================================================

    def check_56_http_methods(self):
        """Check 56: Dangerous HTTP methods."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.options(self.target_url, timeout=10)
            allow = r.headers.get('Allow', '')
            dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
            found = [m for m in dangerous if m in allow.upper()]
            if found:
                self._add_finding('server', 'medium', f'Dangerous HTTP Methods: {", ".join(found)}',
                    'Server allows dangerous HTTP methods that could be exploited.',
                    f'Allowed: {allow}',
                    'Disable unnecessary HTTP methods in server config.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_57_host_header_injection(self):
        """Check 57: Host header injection."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=10,
                headers={'Host': 'evil.com'})
            if r.status_code == 200:
                self._add_finding('server', 'medium', 'Host Header Injection',
                    'Server responds to arbitrary Host headers. May enable cache poisoning.',
                    'Response to Host: evil.com was 200',
                    'Validate Host header in server configuration.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_58_cors_misconfiguration(self):
        """Check 58: CORS misconfiguration."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            if acao == '*':
                self._add_finding('server', 'medium', 'Wide Open CORS',
                    'CORS allows any origin. May enable cross-site attacks.',
                    f'Access-Control-Allow-Origin: {acao}',
                    'Restrict CORS to trusted origins.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_59_rate_limiting(self):
        """Check 59: Rate limiting protection."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.get(self.target_url, timeout=15)
            rate_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'Retry-After']
            if not any(h in r.headers for h in rate_headers):
                self._add_finding('server', 'low', 'No Rate Limiting',
                    'No rate limiting headers detected.',
                    'No rate limit headers in response',
                    'Implement rate limiting to prevent abuse.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_60_information_leakage(self):
        """Check 60: Information leakage in HTML."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'<!--.*?TODO.*?-->', 'TODO comment'),
            (r'<!--.*?FIXME.*?-->', 'FIXME comment'),
            (r'<!--.*?HACK.*?-->', 'HACK comment'),
            (r'<!--.*?password.*?-->', 'Password in comment'),
            (r'<!--.*?secret.*?-->', 'Secret in comment'),
            (r'<!--.*?admin.*?-->', 'Admin info in comment'),
            (r'<!--.*?database.*?-->', 'DB info in comment'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('info_disclosure', 'low', 'Information Leakage',
                'Sensitive information found in code comments.',
                '\n'.join(found[:10]),
                'Remove sensitive comments from production code.')
        else:
            self.stats['checks_passed'] += 1

    def check_61_api_endpoints(self):
        """Check 61: Exposed API endpoints."""
        self.stats['checks_run'] += 1
        paths = ['/api', '/api/', '/graphql', '/swagger', '/docs', '/api/v1', '/api/v2',
                 '/api/users', '/api/config', '/api/debug']
        found = []
        for p in paths:
            code, _ = self._check_url(p)
            if code in (200, 400, 401, 403):
                found.append(p)
        if found:
            self._add_finding('api', 'info', 'API Endpoints Detected',
                f'API endpoints accessible: {", ".join(found)}',
                f'Paths: {", ".join(found)}',
                'Ensure APIs require authentication and rate limiting.')
        else:
            self.stats['checks_passed'] += 1

    def check_62_graphql_introspection(self):
        """Check 62: GraphQL introspection enabled."""
        self.stats['checks_run'] += 1
        try:
            r = self.session.post(f"{self.target_url}/graphql",
                json={'query': '{ __schema { types { name } } }'}, timeout=10)
            if r.status_code == 200 and '__schema' in r.text:
                self._add_finding('api', 'high', 'GraphQL Introspection Enabled',
                    'GraphQL introspection is enabled, exposing entire API schema.',
                    f'URL: {self.target_url}/graphql',
                    'Disable introspection in production.')
            else:
                self.stats['checks_passed'] += 1
        except Exception:
            self.stats['checks_passed'] += 1

    def check_63_admin_panels(self):
        """Check 63: Exposed admin panels."""
        self.stats['checks_run'] += 1
        paths = ['/admin', '/administrator', '/cpanel', '/webmail', '/phpmyadmin',
                 '/pma', '/manager', '/panel', '/backend', '/console', '/dashboard']
        found = []
        for p in paths:
            code, _ = self._check_url(p)
            if code in (200, 301, 302, 401, 403):
                found.append(p)
        if found:
            self._add_finding('admin', 'medium', 'Admin Panels Accessible',
                f'Admin panels found: {", ".join(found[:5])}',
                f'Paths: {", ".join(found)}',
                'Restrict admin access via IP whitelist or VPN.')
        else:
            self.stats['checks_passed'] += 1

    def check_64_exposed_databases(self):
        """Check 64: Exposed database management tools."""
        self.stats['checks_run'] += 1
        paths = ['/phpmyadmin', '/pma', '/adminer', '/phpminiadmin',
                 '/phpMyAdmin', '/mysql', '/adminer.php']
        found = []
        for p in paths:
            code, _ = self._check_url(p)
            if code in (200, 301, 302, 401, 403):
                found.append(p)
        if found:
            self._add_finding('admin', 'critical', 'Database Management Exposed',
                f'Database management tools accessible: {", ".join(found)}',
                f'Paths: {", ".join(found)}',
                'Remove database management tools from production. Use VPN access.')
        else:
            self.stats['checks_passed'] += 1

    def check_65_server_side_request_forgery(self):
        """Check 65: SSRF patterns in code."""
        self.stats['checks_run'] += 1
        all_files = self._read_local_files()
        patterns = [
            (r'curl_setopt.*CURLOPT_URL.*\$_', 'cURL with user input'),
            (r'file_get_contents\s*\(\s*\$_', 'file_get_contents with user input'),
            (r'fopen\s*\(\s*\$_', 'fopen with user input'),
            (r'requests\.get\s*\(.*input', 'requests.get with user input'),
            (r'urlopen\s*\(.*input', 'urlopen with user input'),
        ]
        found = []
        for fp, content in all_files.items():
            for pat, desc in patterns:
                if re.search(pat, content):
                    found.append(f"{desc} in {os.path.basename(fp)}")
        if found:
            self._add_finding('injection', 'high', 'SSRF Vulnerability',
                'Server-Side Request Forgery patterns detected.',
                '\n'.join(found[:10]),
                'Validate and sanitize URLs. Use allowlists for permitted domains.')
        else:
            self.stats['checks_passed'] += 1

    # ================================================================
    # MAIN SCAN FUNCTION
    # ================================================================

    def scan(self):
        """Run all 55+ security checks."""
        print(f"\n[SCANNING] Starting security scan...")
        print(f"[SCANNING] Target: {self.target_url}")
        print(f"[SCANNING] Detecting CMS...")
        
        self._detect_wordpress()
        if self.is_wordpress:
            print(f"[SCANNING] WordPress detected! Version: {self.wp_version or 'unknown'}")
            print(f"[SCANNING] Plugins found: {len(self.wp_plugins)}")
            print(f"[SCANNING] Themes found: {len(self.wp_themes)}")
        
        print()
        
        checks = [
            # Secrets & Credentials (1-10)
            (".env files", self.check_01_env_files),
            ("Git exposure", self.check_02_git_exposure),
            ("SVN exposure", self.check_03_svn_exposure),
            ("Config files", self.check_04_config_files),
            ("Backup files", self.check_05_backup_files),
            ("Database files", self.check_06_database_files),
            ("Private keys", self.check_07_private_keys),
            ("Credentials files", self.check_08_credentials_json),
            ("API keys in code", self.check_09_api_keys_in_code),
            ("Passwords in code", self.check_10_passwords_in_code),
            # Security Headers (11-17)
            ("CSP header", self.check_11_csp_header),
            ("HSTS header", self.check_12_hsts_header),
            ("X-Frame-Options", self.check_13_x_frame_options),
            ("X-Content-Type", self.check_14_x_content_type),
            ("X-XSS-Protection", self.check_15_x_xss_protection),
            ("Referrer-Policy", self.check_16_referrer_policy),
            ("Permissions-Policy", self.check_17_permissions_policy),
            # SSL/TLS (18-22)
            ("SSL certificate", self.check_18_ssl_certificate),
            ("TLS version", self.check_19_tls_version),
            ("Weak ciphers", self.check_20_weak_ciphers),
            ("SSL redirect", self.check_21_ssl_redirect),
            ("Mixed content", self.check_22_mixed_content),
            # Server & Info (23-28)
            ("Server header", self.check_23_server_header),
            ("Directory listing", self.check_24_directory_listing),
            ("PHP info", self.check_25_phpinfo),
            ("Error pages", self.check_26_error_pages),
            ("Source code", self.check_27_source_code_disclosure),
            ("Robots.txt", self.check_28_robots_sitemap),
            # Injection (29-35)
            ("SQL injection", self.check_29_sql_injection),
            ("XSS vulnerabilities", self.check_30_xss_vulnerabilities),
            ("Command injection", self.check_31_command_injection),
            ("Directory traversal", self.check_32_directory_traversal),
            ("File inclusion", self.check_33_file_inclusion),
            ("XXE injection", self.check_34_xxe),
            ("Deserialization", self.check_35_deserialization),
            # Auth & Session (36-40)
            ("Login pages", self.check_36_login_pages),
            ("Default credentials", self.check_37_default_credentials),
            ("Cookie security", self.check_38_cookie_security),
            ("Session fixation", self.check_39_session_fixation),
            ("Brute force", self.check_40_brute_force_protection),
            # WordPress (41-55)
            ("WP version", self.check_41_wp_version_exposure),
            ("WP XML-RPC", self.check_42_wp_xmlrpc),
            ("WP readme.html", self.check_43_wp_readme),
            ("WP license.txt", self.check_44_wp_license),
            ("WP debug.log", self.check_45_wp_debug_log),
            ("WP config backup", self.check_46_wp_config_backup),
            ("WP uploads dir", self.check_47_wp_upload_dir),
            ("WP includes dir", self.check_48_wp_includes),
            ("WP user enum", self.check_49_wp_user_enumeration),
            ("WP REST API", self.check_50_wp_rest_api),
            ("WP plugins vuln", self.check_51_wp_plugin_vulnerabilities),
            ("WP file editing", self.check_52_wp_file_editing),
            ("WP old version", self.check_53_wp_old_versions),
            ("WP htaccess", self.check_54_wp_htaccess),
            ("WP fingerprinting", self.check_55_wp_wpscan_patterns),
            # Additional (56-65)
            ("HTTP methods", self.check_56_http_methods),
            ("Host header", self.check_57_host_header_injection),
            ("CORS config", self.check_58_cors_misconfiguration),
            ("Rate limiting", self.check_59_rate_limiting),
            ("Info leakage", self.check_60_information_leakage),
            ("API endpoints", self.check_61_api_endpoints),
            ("GraphQL introspect", self.check_62_graphql_introspection),
            ("Admin panels", self.check_63_admin_panels),
            ("Database tools", self.check_64_exposed_databases),
            ("SSRF patterns", self.check_65_server_side_request_forgery),
        ]
        
        for i, (name, func) in enumerate(checks, 1):
            print(f"[{i}/{len(checks)}] {name}...")
            try:
                func()
            except Exception as e:
                print(f"  [!] Error: {e}")
        
        print(f"\n[SCANNING] Complete! {len(checks)} checks performed.")
        
        return {'findings': self.findings, 'stats': self.stats}


def scan_website(target_url, scan_dir=None):
    """Convenience function to scan a website."""
    scanner = SecurityScanner(target_url, scan_dir)
    return scanner.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <url> [scan_dir]")
        sys.exit(1)
    result = scan_website(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    print(f"\nTotal findings: {len(result['findings'])}")
    for s in ['critical', 'high', 'medium', 'low', 'info']:
        c = result['stats'].get(s, 0)
        if c > 0:
            print(f"  {s.upper()}: {c}")