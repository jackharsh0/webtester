"""
Reconnaissance Module
Subdomain scanner, port scanner, directory bruteforce, WAF detection.
"""

import socket
import requests
import urllib.parse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


class ReconScanner:
    """Reconnaissance and enumeration scanner."""

    def __init__(self, target_url, scan_dir=None):
        """Initialize recon scanner."""
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urllib.parse.urlparse(self.target_url)
        self.domain = self.parsed_url.netloc.split(':')[0]
        self.scan_dir = Path(scan_dir) if scan_dir else None
        self.findings = []
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.stats = {
            'subdomains_found': 0,
            'open_ports': 0,
            'directories_found': 0,
            'waf_detected': False,
        }

    def _add_finding(self, severity, title, description, evidence=None, remediation=None, category='recon'):
        """Add a finding."""
        self.findings.append({
            'id': f"recon-{len(self.findings) + 1}",
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat(),
        })

    # ================================================================
    # SUBDOMAIN SCANNER
    # ================================================================

    def scan_subdomains(self):
        """Scan for subdomains."""
        print("  [SUBDOMAIN] Scanning subdomains...")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'dev', 'staging', 'test',
            'api', 'blog', 'shop', 'store', 'app', 'portal', 'dashboard',
            'cdn', 'media', 'static', 'assets', 'images', 'img',
            'vpn', 'remote', 'gateway', 'proxy', 'lb',
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
            'git', 'gitlab', 'jenkins', 'ci', 'cd',
            'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap',
            'webmail', 'owa', 'exchange', 'lync',
            'backup', 'bak', 'old', 'archive',
            'monitor', 'grafana', 'kibana', 'prometheus',
            'k8s', 'docker', 'registry', 'harbor',
        ]
        
        found_subdomains = []
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found_subdomains.append({
                    'subdomain': subdomain,
                    'ip': ip,
                })
                
                # Try to access the subdomain
                try:
                    r = self.session.get(f"https://{subdomain}", timeout=5, verify=False)
                    self._add_finding(
                        severity='info',
                        title=f'Subdomain Found: {subdomain}',
                        description=f'Subdomain {subdomain} resolves to {ip}.',
                        evidence=f'IP: {ip}, Status: {r.status_code}',
                        remediation='Review all subdomains for security issues.',
                        category='recon'
                    )
                except Exception:
                    self._add_finding(
                        severity='info',
                        title=f'Subdomain Found: {subdomain}',
                        description=f'Subdomain {subdomain} resolves to {ip}.',
                        evidence=f'IP: {ip}',
                        remediation='Review all subdomains for security issues.',
                        category='recon'
                    )
                
                self.stats['subdomains_found'] += 1
                
            except socket.gaierror:
                pass
        
        print(f"  [SUBDOMAIN] Found {len(found_subdomains)} subdomains")
        return found_subdomains

    # ================================================================
    # PORT SCANNER
    # ================================================================

    def scan_ports(self):
        """Scan common ports."""
        print("  [PORT] Scanning ports...")
        
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
            50000: 'SAP',
        }
        
        open_ports = []
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.domain, port))
                
                if result == 0:
                    open_ports.append({'port': port, 'service': service})
                    
                    severity = 'high' if port in [21, 23, 3306, 6379, 27017] else 'medium'
                    
                    self._add_finding(
                        severity=severity,
                        title=f'Open Port: {port} ({service})',
                        description=f'Port {port} ({service}) is open and accessible.',
                        evidence=f'Port {port} is open',
                        remediation=f'Close {service} port if not needed, or restrict access.',
                        category='recon'
                    )
                    
                    self.stats['open_ports'] += 1
                
                sock.close()
                
            except Exception:
                pass
        
        print(f"  [PORT] Found {len(open_ports)} open ports")
        return open_ports

    # ================================================================
    # DIRECTORY BRUTEFORCE
    # ================================================================

    def scan_directories(self):
        """Scan for hidden directories."""
        print("  [DIRECTORY] Bruteforcing directories...")
        
        common_dirs = [
            'admin', 'administrator', 'wp-admin', 'cpanel', 'webmail',
            'phpmyadmin', 'pma', 'adminer', 'dbadmin',
            'backup', 'backups', 'bak', 'old', 'archive',
            'test', 'testing', 'staging', 'dev', 'development',
            'api', 'api/v1', 'api/v2', 'rest', 'graphql',
            'config', 'configuration', 'settings',
            'tmp', 'temp', 'cache', 'logs', 'log',
            'upload', 'uploads', 'files', 'media', 'images',
            'assets', 'static', 'public', 'private',
            'cgi-bin', 'scripts', 'includes',
            'vendor', 'node_modules', 'bower_components',
            '.git', '.svn', '.env', '.htaccess',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'server-status', 'server-info',
            'wp-content', 'wp-includes', 'wp-json',
            'xmlrpc.php', 'readme.html', 'license.txt',
            'debug', 'info', 'phpinfo',
            'console', 'dashboard', 'panel',
            'auth', 'login', 'signin', 'register',
        ]
        
        found_dirs = []
        
        for directory in common_dirs:
            try:
                url = f"{self.target_url}/{directory}"
                r = self.session.get(url, timeout=5, allow_redirects=False)
                
                if r.status_code in (200, 301, 302, 401, 403):
                    found_dirs.append({
                        'path': directory,
                        'status': r.status_code,
                    })
                    
                    severity = 'high' if directory in ['admin', '.env', '.git', 'backup', 'phpmyadmin'] else 'medium'
                    
                    self._add_finding(
                        severity=severity,
                        title=f'Directory Found: /{directory}',
                        description=f'Directory /{directory} exists (Status: {r.status_code}).',
                        evidence=f'URL: {url}, Status: {r.status_code}',
                        remediation='Restrict access to sensitive directories.',
                        category='recon'
                    )
                    
                    self.stats['directories_found'] += 1
                    
            except Exception:
                pass
        
        print(f"  [DIRECTORY] Found {len(found_dirs)} directories")
        return found_dirs

    # ================================================================
    # WAF DETECTION
    # ================================================================

    def detect_waf(self):
        """Detect Web Application Firewall."""
        print("  [WAF] Detecting WAF...")
        
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', 'cf-cache-status'],
            'Akamai': ['akamai', 'x-akamai', 'akamai-transform'],
            'Incapsula': ['incap-ses', 'x-iinfo', 'incapsula'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Barracuda': ['barra_counter_session', 'barracuda'],
            'F5 BIG-IP': ['bigip', 'tsessionid', 'f5-bigip'],
            'FortiWeb': ['fortiweb', 'fwb'],
            'DenyAll': ['denyall', 'rayid'],
        }
        
        detected_wafs = []
        
        try:
            r = self.session.get(self.target_url, timeout=10)
            headers = str(r.headers).lower()
            content = r.text.lower()
            
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in headers or sig.lower() in content:
                        detected_wafs.append(waf_name)
                        self.stats['waf_detected'] = True
                        
                        self._add_finding(
                            severity='info',
                            title=f'WAF Detected: {waf_name}',
                            description=f'Web Application Firewall detected: {waf_name}',
                            evidence=f'Signature: {sig}',
                            remediation='WAF provides protection. Ensure it is properly configured.',
                            category='recon'
                        )
                        break
            
            # Test for WAF with malicious payload
            test_payloads = ["<script>alert(1)</script>", "' OR 1=1--", "../../../etc/passwd"]
            
            for payload in test_payloads:
                r = self.session.get(f"{self.target_url}/?test={urllib.parse.quote(payload)}", timeout=10)
                
                if r.status_code in (403, 406, 429) or 'blocked' in r.text.lower():
                    if not detected_wafs:
                        self._add_finding(
                            severity='info',
                            title='WAF Detected (Behavior)',
                            description='WAF detected based on blocking behavior.',
                            evidence=f'Blocked payload: {payload}',
                            remediation='WAF provides protection.',
                            category='recon'
                        )
                    break
            
            if not detected_wafs:
                self._add_finding(
                    severity='medium',
                    title='No WAF Detected',
                    description='No Web Application Firewall detected.',
                    evidence='No WAF signatures found',
                    remediation='Consider deploying a WAF for protection.',
                    category='recon'
                )
            
        except Exception:
            pass
        
        print(f"  [WAF] Detected: {', '.join(detected_wafs) if detected_wafs else 'None'}")
        return detected_wafs

    # ================================================================
    # MAIN SCAN
    # ================================================================

    def scan(self):
        """Run all recon scans."""
        print(f"\n{'='*60}")
        print(f"RECONNAISSANCE SCANNER")
        print(f"{'='*60}")
        print(f"Target: {self.domain}")
        print(f"{'='*60}\n")
        
        # Run all scans
        subdomains = self.scan_subdomains()
        open_ports = self.scan_ports()
        directories = self.scan_directories()
        wafs = self.detect_waf()
        
        print(f"\n{'='*60}")
        print(f"RECON COMPLETE")
        print(f"{'='*60}")
        
        return {
            'findings': self.findings,
            'stats': self.stats,
            'subdomains': subdomains,
            'open_ports': open_ports,
            'directories': directories,
            'wafs': wafs,
        }


def scan_recon(target_url, scan_dir=None):
    """Convenience function for recon scanning."""
    scanner = ReconScanner(target_url, scan_dir)
    return scanner.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python recon.py <url>")
        sys.exit(1)
    result = scan_recon(sys.argv[1])
    print(f"\nSubdomains: {result['stats']['subdomains_found']}")
    print(f"Open Ports: {result['stats']['open_ports']}")
    print(f"Directories: {result['stats']['directories_found']}")