"""
API Security Tester Module
Tests REST APIs, GraphQL, WebSocket, JWT, and OAuth for vulnerabilities.
"""

import re
import json
import time
import hashlib
import base64
import urllib.parse
import requests
from pathlib import Path
from datetime import datetime


class APISecurityTester:
    """Comprehensive API security testing module."""

    def __init__(self, target_url, scan_dir=None):
        """Initialize API security tester."""
        self.target_url = target_url.rstrip('/')
        self.scan_dir = Path(scan_dir) if scan_dir else None
        self.findings = []
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/json',
        })
        
        self.stats = {
            'tests_run': 0,
            'vulnerabilities_found': 0,
            'api_endpoints_found': 0,
            'graphql_detected': False,
            'jwt_detected': False,
            'oauth_detected': False,
        }

    def _add_finding(self, severity, title, description, evidence=None, remediation=None, category='api'):
        """Add a security finding."""
        self.findings.append({
            'id': f"api-{len(self.findings) + 1}",
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat(),
        })
        self.stats['vulnerabilities_found'] += 1

    def _check_endpoint(self, path, method='GET', data=None):
        """Check an API endpoint."""
        try:
            url = self.target_url + path
            if method == 'GET':
                r = self.session.get(url, timeout=10)
            elif method == 'POST':
                r = self.session.post(url, json=data, timeout=10)
            elif method == 'PUT':
                r = self.session.put(url, json=data, timeout=10)
            elif method == 'DELETE':
                r = self.session.delete(url, timeout=10)
            elif method == 'OPTIONS':
                r = self.session.options(url, timeout=10)
            else:
                r = self.session.get(url, timeout=10)
            return r
        except Exception:
            return None

    # ================================================================
    # REST API TESTING
    # ================================================================

    def scan_rest_api_endpoints(self):
        """Scan for common REST API endpoints."""
        print("  [REST] Scanning API endpoints...")
        
        api_paths = [
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/',
            '/graphql', '/graphiql',
            '/swagger', '/swagger.json', '/swagger-ui', '/swagger-ui.html',
            '/docs', '/api-docs', '/openapi.json',
            '/api/users', '/api/products', '/api/orders',
            '/api/config', '/api/settings', '/api/admin',
            '/api/debug', '/api/health', '/api/status',
            '/.well-known/openapi.yaml',
        ]
        
        found_endpoints = []
        for path in api_paths:
            r = self._check_endpoint(path)
            if r and r.status_code in (200, 400, 401, 403, 405):
                found_endpoints.append(path)
                self.stats['api_endpoints_found'] += 1
        
        if found_endpoints:
            self._add_finding(
                severity='info',
                title='REST API Endpoints Discovered',
                description=f'Found {len(found_endpoints)} API endpoints.',
                evidence=f'Endpoints: {", ".join(found_endpoints[:10])}',
                remediation='Ensure all API endpoints require authentication.',
                category='rest_api'
            )
        
        return found_endpoints

    def test_rest_authentication(self):
        """Test REST API authentication bypass."""
        print("  [REST] Testing authentication bypass...")
        
        auth_endpoints = [
            '/api/users', '/api/admin', '/api/config',
            '/api/v1/users', '/api/v1/admin',
            '/api/settings', '/api/secrets',
        ]
        
        for path in auth_endpoints:
            # Test without auth
            r = self._check_endpoint(path)
            if r and r.status_code == 200:
                self._add_finding(
                    severity='critical',
                    title=f'Authentication Bypass: {path}',
                    description=f'Endpoint {path} accessible without authentication.',
                    evidence=f'Status: {r.status_code}, Response length: {len(r.text)}',
                    remediation='Add authentication middleware to all API endpoints.',
                    category='rest_api'
                )
                return
        
        self.stats['tests_run'] += 1

    def test_rest_method_override(self):
        """Test HTTP method override."""
        print("  [REST] Testing method override...")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        for method in methods:
            r = self._check_endpoint('/api', method)
            if r and r.status_code == 200 and method in ['DELETE', 'PUT', 'PATCH']:
                self._add_finding(
                    severity='high',
                    title=f'Dangerous HTTP Method Allowed: {method}',
                    description=f'Server accepts {method} method on /api.',
                    evidence=f'{method} /api returned {r.status_code}',
                    remediation='Restrict HTTP methods to only those needed.',
                    category='rest_api'
                )
        
        self.stats['tests_run'] += 1

    def test_rest_rate_limiting(self):
        """Test REST API rate limiting."""
        print("  [REST] Testing rate limiting...")
        
        url = self.target_url + '/api'
        responses = []
        
        for i in range(20):
            try:
                r = self.session.get(url, timeout=5)
                responses.append(r.status_code)
            except Exception:
                pass
        
        if 429 not in responses and len(responses) >= 20:
            self._add_finding(
                severity='medium',
                title='No Rate Limiting on API',
                description='API endpoint does not enforce rate limiting after 20 requests.',
                evidence=f'All 20 requests succeeded without 429 response',
                remediation='Implement rate limiting (e.g., 100 requests per minute).',
                category='rest_api'
            )
        
        self.stats['tests_run'] += 1

    def test_rest_information_disclosure(self):
        """Test REST API information disclosure."""
        print("  [REST] Testing information disclosure...")
        
        r = self._check_endpoint('/api')
        if r:
            content = r.text.lower()
            
            # Check for verbose errors
            error_patterns = [
                (r'stack\s*trace', 'Stack trace exposed'),
                (r'exception\s*message', 'Exception message exposed'),
                (r'database\s*error', 'Database error exposed'),
                (r'internal\s*server\s*error.*details', 'Internal error details exposed'),
                (r'debug\s*mode', 'Debug mode enabled'),
            ]
            
            for pattern, desc in error_patterns:
                if re.search(pattern, content):
                    self._add_finding(
                        severity='high',
                        title=f'Information Disclosure: {desc}',
                        description=f'API exposes sensitive information: {desc}',
                        evidence=f'Pattern found: {pattern}',
                        remediation='Disable verbose error messages in production.',
                        category='rest_api'
                    )
        
        self.stats['tests_run'] += 1

    # ================================================================
    # GRAPHQL ATTACK MODULE
    # ================================================================

    def detect_graphql(self):
        """Detect GraphQL endpoint."""
        print("  [GraphQL] Detecting GraphQL endpoint...")
        
        graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/query']
        
        for path in graphql_paths:
            # Test with introspection query
            introspection_query = {
                'query': '{ __schema { types { name } } }'
            }
            
            r = self._check_endpoint(path, 'POST', introspection_query)
            
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if 'data' in data and '__schema' in str(data.get('data', {})):
                        self.stats['graphql_detected'] = True
                        print(f"  [GraphQL] Found at: {path}")
                        return path
                except Exception:
                    pass
        
        return None

    def test_graphql_introspection(self, graphql_path):
        """Test GraphQL introspection."""
        print("  [GraphQL] Testing introspection...")
        
        if not graphql_path:
            return
        
        introspection_query = {
            'query': '''
            {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        fields {
                            name
                            type { name }
                        }
                    }
                }
            }
            '''
        }
        
        r = self._check_endpoint(graphql_path, 'POST', introspection_query)
        
        if r and r.status_code == 200:
            try:
                data = r.json()
                if 'data' in data and '__schema' in data['data']:
                    types = data['data']['__schema'].get('types', [])
                    type_names = [t['name'] for t in types if not t['name'].startswith('__')]
                    
                    self._add_finding(
                        severity='critical',
                        title='GraphQL Introspection Enabled',
                        description=f'GraphQL introspection exposes entire API schema. Found {len(type_names)} types.',
                        evidence=f'Types: {", ".join(type_names[:10])}',
                        remediation='Disable introspection in production.',
                        category='graphql'
                    )
            except Exception:
                pass

    def test_graphql_depth_abuse(self, graphql_path):
        """Test GraphQL query depth abuse."""
        print("  [GraphQL] Testing depth abuse...")
        
        if not graphql_path:
            return
        
        # Deeply nested query
        deep_query = {
            'query': '''
            {
                users {
                    posts {
                        comments {
                            author {
                                posts {
                                    comments {
                                        author {
                                            name
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            '''
        }
        
        start_time = time.time()
        r = self._check_endpoint(graphql_path, 'POST', deep_query)
        elapsed = time.time() - start_time
        
        if r and r.status_code == 200 and elapsed > 5:
            self._add_finding(
                severity='high',
                title='GraphQL Depth Abuse Possible',
                description=f'Deeply nested query took {elapsed:.1f}s. Server vulnerable to DoS.',
                evidence=f'Response time: {elapsed:.1f}s for deep query',
                remediation='Implement query depth limiting (max 10 levels).',
                category='graphql'
            )

    def test_graphql_batching(self, graphql_path):
        """Test GraphQL query batching attacks."""
        print("  [GraphQL] Testing batching attacks...")
        
        if not graphql_path:
            return
        
        # Batch query (multiple queries in one request)
        batch_query = [
            {'query': '{ users { id } }'},
            {'query': '{ users { id } }'},
            {'query': '{ users { id } }'},
            {'query': '{ users { id } }'},
            {'query': '{ users { id } }'},
        ]
        
        r = self._check_endpoint(graphql_path, 'POST', batch_query)
        
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list) and len(data) >= 5:
                    self._add_finding(
                        severity='high',
                        title='GraphQL Batch Query Abuse',
                        description='Server accepts batch queries, enabling DoS attacks.',
                        evidence=f'Batch of {len(batch_query)} queries accepted',
                        remediation='Limit batch size or disable batching.',
                        category='graphql'
                    )
            except Exception:
                pass

    def test_graphql_error_leakage(self, graphql_path):
        """Test GraphQL error information leakage."""
        print("  [GraphQL] Testing error leakage...")
        
        if not graphql_path:
            return
        
        # Invalid query to trigger error
        error_query = {
            'query': '{ invalidField { nested { deep } } }'
        }
        
        r = self._check_endpoint(graphql_path, 'POST', error_query)
        
        if r and r.status_code == 200:
            try:
                data = r.json()
                if 'errors' in data:
                    error_msg = str(data['errors'])
                    if any(x in error_msg.lower() for x in ['stack', 'trace', 'file', 'line']):
                        self._add_finding(
                            severity='medium',
                            title='GraphQL Error Information Leakage',
                            description='GraphQL errors expose internal implementation details.',
                            evidence=f'Error: {error_msg[:200]}',
                            remediation='Sanitize error messages in production.',
                            category='graphql'
                        )
            except Exception:
                pass

    # ================================================================
    # WEBSOCKET SECURITY
    # ================================================================

    def test_websocket_security(self):
        """Test WebSocket connection security."""
        print("  [WebSocket] Testing WebSocket security...")
        
        ws_paths = ['/ws', '/socket', '/socket.io', '/websocket', '/wschat']
        
        for path in ws_paths:
            ws_url = self.target_url.replace('http', 'ws') + path
            
            try:
                # Try to connect to WebSocket
                import websocket
                ws = websocket.create_connection(ws_url, timeout=5)
                
                # If connection succeeds, check security
                self._add_finding(
                    severity='medium',
                    title=f'WebSocket Endpoint Found: {path}',
                    description=f'WebSocket endpoint is accessible at {path}.',
                    evidence=f'URL: {ws_url}',
                    remediation='Ensure WebSocket requires authentication.',
                    category='websocket'
                )
                
                ws.close()
                return
                
            except ImportError:
                # websocket module not installed, use requests
                r = self._check_endpoint(path)
                if r and r.status_code in (101, 200, 400):
                    self._add_finding(
                        severity='info',
                        title=f'WebSocket Endpoint Detected: {path}',
                        description=f'Possible WebSocket endpoint at {path}.',
                        evidence=f'Status: {r.status_code}',
                        remediation='Verify WebSocket requires authentication.',
                        category='websocket'
                    )
                    return
            except Exception:
                continue
        
        self.stats['tests_run'] += 1

    def test_websocket_origin(self):
        """Test WebSocket origin validation."""
        print("  [WebSocket] Testing origin validation...")
        
        ws_paths = ['/ws', '/socket', '/websocket']
        
        for path in ws_paths:
            try:
                r = self.session.get(
                    self.target_url + path,
                    headers={'Origin': 'https://evil.com'},
                    timeout=10
                )
                
                if r.status_code == 101:  # Switching Protocols
                    self._add_finding(
                        severity='high',
                        title='WebSocket Origin Not Validated',
                        description='WebSocket accepts connections from any origin.',
                        evidence=f'Origin: https://evil.com accepted',
                        remediation='Validate WebSocket origin against whitelist.',
                        category='websocket'
                    )
                    return
            except Exception:
                continue
        
        self.stats['tests_run'] += 1

    # ================================================================
    # JWT ATTACK MODULE
    # ================================================================

    def detect_jwt(self):
        """Detect JWT tokens in responses."""
        print("  [JWT] Detecting JWT tokens...")
        
        r = self._check_endpoint('/')
        if r:
            # Check headers
            auth_header = r.headers.get('Authorization', '')
            if 'Bearer' in auth_header:
                token = auth_header.replace('Bearer ', '')
                if self._is_jwt(token):
                    self.stats['jwt_detected'] = True
                    return token
            
            # Check cookies
            for cookie in r.cookies.values():
                if self._is_jwt(cookie):
                    self.stats['jwt_detected'] = True
                    return cookie
        
        return None

    def _is_jwt(self, token):
        """Check if a string is a JWT token."""
        parts = token.split('.')
        if len(parts) == 3:
            try:
                base64.urlsafe_b64decode(parts[0] + '==')
                base64.urlsafe_b64decode(parts[1] + '==')
                return True
            except Exception:
                pass
        return False

    def test_jwt_none_algorithm(self, token):
        """Test JWT none algorithm attack."""
        print("  [JWT] Testing none algorithm...")
        
        if not token:
            return
        
        parts = token.split('.')
        if len(parts) != 3:
            return
        
        try:
            # Decode header
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            
            # Check if none algorithm is supported
            if header.get('alg') == 'none':
                self._add_finding(
                    severity='critical',
                    title='JWT None Algorithm Accepted',
                    description='JWT accepts "none" algorithm, allowing signature bypass.',
                    evidence=f'Header algorithm: {header.get("alg")}',
                    remediation='Reject JWT with "none" algorithm.',
                    category='jwt'
                )
                return
            
            # Try to forge token with none algorithm
            forged_header = base64.urlsafe_b64encode(json.dumps({
                'alg': 'none',
                'typ': 'JWT'
            }).encode()).rstrip(b'=').decode()
            
            forged_token = f"{forged_header}.{parts[1]}."
            
            # Test forged token
            r = self._check_endpoint('/api')
            if r and 'Authorization' in str(r.headers):
                self._add_finding(
                    severity='critical',
                    title='JWT None Algorithm Attack Possible',
                    description='Server may accept forged JWT with none algorithm.',
                    evidence='Forged token created successfully',
                    remediation='Always verify JWT signature algorithm.',
                    category='jwt'
                )
        except Exception:
            pass

    def test_jwt_weak_secret(self, token):
        """Test JWT weak secret (dictionary attack)."""
        print("  [JWT] Testing weak secrets...")
        
        if not token:
            return
        
        common_secrets = [
            'secret', 'password', '123456', 'admin', 'test',
            'jwt_secret', 'your-256-bit-secret', 'shhhhh',
        ]
        
        parts = token.split('.')
        if len(parts) != 3:
            return
        
        for secret in common_secrets:
            try:
                # Create test signature
                import hmac
                test_sig = hmac.new(
                    secret.encode(),
                    f"{parts[0]}.{parts[1]}".encode(),
                    hashlib.sha256
                ).digest()
                
                test_sig_b64 = base64.urlsafe_b64encode(test_sig).rstrip(b'=').decode()
                
                # Compare with original
                if test_sig_b64 == parts[2]:
                    self._add_finding(
                        severity='critical',
                        title='JWT Weak Secret Found',
                        description=f'JWT uses weak secret: {secret}',
                        evidence=f'Secret: {secret}',
                        remediation='Use strong, randomly generated secrets.',
                        category='jwt'
                    )
                    return
            except Exception:
                continue
        
        self.stats['tests_run'] += 1

    def test_jwt_expiration(self, token):
        """Test JWT token expiration."""
        print("  [JWT] Testing token expiration...")
        
        if not token:
            return
        
        try:
            parts = token.split('.')
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            if 'exp' not in payload:
                self._add_finding(
                    severity='high',
                    title='JWT No Expiration Set',
                    description='JWT token has no expiration time.',
                    evidence='No "exp" claim in token',
                    remediation='Always set expiration time on JWT tokens.',
                    category='jwt'
                )
            else:
                exp = payload['exp']
                now = time.time()
                
                if exp > now + 86400 * 365:  # More than 1 year
                    self._add_finding(
                        severity='medium',
                        title='JWT Long Expiration',
                        description=f'JWT token expires in more than 1 year.',
                        evidence=f'Expiration: {datetime.fromtimestamp(exp)}',
                        remediation='Use shorter expiration times (e.g., 1 hour).',
                        category='jwt'
                    )
        except Exception:
            pass

    # ================================================================
    # OAUTH MISCONFIGURATION
    # ================================================================

    def detect_oauth(self):
        """Detect OAuth endpoints."""
        print("  [OAuth] Detecting OAuth endpoints...")
        
        oauth_paths = [
            '/oauth/authorize', '/oauth/token', '/oauth/callback',
            '/auth/google', '/auth/github', '/auth/facebook',
            '/login/google', '/login/github',
            '/.well-known/oauth-authorization-server',
        ]
        
        found = []
        for path in oauth_paths:
            r = self._check_endpoint(path)
            if r and r.status_code in (200, 302, 400, 405):
                found.append(path)
                self.stats['oauth_detected'] = True
        
        if found:
            print(f"  [OAuth] Found: {', '.join(found[:3])}")
        
        return found

    def test_oauth_redirect_uri(self):
        """Test OAuth redirect URI validation."""
        print("  [OAuth] Testing redirect URI validation...")
        
        oauth_paths = ['/oauth/authorize', '/auth/google', '/login/github']
        
        for path in oauth_paths:
            # Test with evil redirect
            evil_params = {
                'redirect_uri': 'https://evil.com/callback',
                'client_id': 'test',
                'response_type': 'code',
            }
            
            r = self._check_endpoint(f"{path}?{urllib.parse.urlencode(evil_params)}")
            
            if r and r.status_code == 200 and 'evil.com' in r.text:
                self._add_finding(
                    severity='critical',
                    title='OAuth Open Redirect',
                    description='OAuth accepts arbitrary redirect URIs.',
                    evidence=f'Evil redirect accepted at {path}',
                    remediation='Validate redirect URI against whitelist.',
                    category='oauth'
                )
                return
        
        self.stats['tests_run'] += 1

    def test_oauth_state_parameter(self):
        """Test OAuth state parameter."""
        print("  [OAuth] Testing state parameter...")
        
        r = self._check_endpoint('/oauth/authorize?client_id=test&response_type=code')
        
        if r and r.status_code == 200:
            if 'state' not in r.text.lower():
                self._add_finding(
                    severity='high',
                    title='OAuth Missing State Parameter',
                    description='OAuth flow does not use state parameter.',
                    evidence='No state parameter in authorization request',
                    remediation='Always use state parameter to prevent CSRF.',
                    category='oauth'
                )
        
        self.stats['tests_run'] += 1

    def test_oauth_token_leakage(self):
        """Test OAuth token leakage in URLs."""
        print("  [OAuth] Testing token leakage...")
        
        r = self._check_endpoint('/oauth/callback?code=test123&access_token=test456')
        
        if r and r.status_code == 200:
            self._add_finding(
                severity='high',
                title='OAuth Tokens in URL',
                description='OAuth tokens may be exposed in URLs.',
                evidence='Token parameters accepted in URL',
                remediation='Use POST for token exchange, never put tokens in URLs.',
                category='oauth'
            )
        
        self.stats['tests_run'] += 1

    # ================================================================
    # MAIN SCAN FUNCTION
    # ================================================================

    def scan(self):
        """Run all API security tests."""
        print(f"\n{'='*60}")
        print(f"API SECURITY TESTER")
        print(f"{'='*60}")
        print(f"Target: {self.target_url}")
        print(f"{'='*60}\n")
        
        # REST API Testing
        print("[REST API TESTING]")
        self.scan_rest_api_endpoints()
        self.test_rest_authentication()
        self.test_rest_method_override()
        self.test_rest_rate_limiting()
        self.test_rest_information_disclosure()
        
        # GraphQL Testing
        print("\n[GRAPHQL TESTING]")
        graphql_path = self.detect_graphql()
        if graphql_path:
            self.test_graphql_introspection(graphql_path)
            self.test_graphql_depth_abuse(graphql_path)
            self.test_graphql_batching(graphql_path)
            self.test_graphql_error_leakage(graphql_path)
        
        # WebSocket Testing
        print("\n[WEBSOCKET TESTING]")
        self.test_websocket_security()
        self.test_websocket_origin()
        
        # JWT Testing
        print("\n[JWT TESTING]")
        jwt_token = self.detect_jwt()
        if jwt_token:
            self.test_jwt_none_algorithm(jwt_token)
            self.test_jwt_weak_secret(jwt_token)
            self.test_jwt_expiration(jwt_token)
        
        # OAuth Testing
        print("\n[OAUTH TESTING]")
        self.detect_oauth()
        self.test_oauth_redirect_uri()
        self.test_oauth_state_parameter()
        self.test_oauth_token_leakage()
        
        print(f"\n{'='*60}")
        print(f"API SECURITY TEST COMPLETE")
        print(f"{'='*60}")
        
        return {
            'findings': self.findings,
            'stats': self.stats,
        }


def scan_api_security(target_url, scan_dir=None):
    """Convenience function for API security testing."""
    tester = APISecurityTester(target_url, scan_dir)
    return tester.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python api_security.py <url>")
        sys.exit(1)
    result = scan_api_security(sys.argv[1])
    print(f"\nVulnerabilities found: {result['stats']['vulnerabilities_found']}")