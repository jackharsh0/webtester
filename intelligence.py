"""
Intelligence Module
Risk score calculator, vulnerability chaining, CVE matching.
"""

import re
import json
import urllib.parse
import requests
from pathlib import Path
from datetime import datetime


class IntelligenceAnalyzer:
    """Intelligence and risk analysis module."""

    def __init__(self, target_url, scan_dir=None):
        """Initialize intelligence analyzer."""
        self.target_url = target_url.rstrip('/')
        self.scan_dir = Path(scan_dir) if scan_dir else None
        self.findings = []
        self.risk_score = 100  # Start with 100, deduct points
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })

    # ================================================================
    # RISK SCORE CALCULATOR
    # ================================================================

    def calculate_risk_score(self, all_findings):
        """Calculate overall risk score (0-100)."""
        print("  [RISK] Calculating risk score...")
        
        score = 100
        deductions = []
        
        for finding in all_findings:
            severity = finding.get('severity', 'info')
            
            if severity == 'critical':
                score -= 15
                deductions.append(f"Critical: {finding['title']} (-15)")
            elif severity == 'high':
                score -= 10
                deductions.append(f"High: {finding['title']} (-10)")
            elif severity == 'medium':
                score -= 5
                deductions.append(f"Medium: {finding['title']} (-5)")
            elif severity == 'low':
                score -= 2
                deductions.append(f"Low: {finding['title']} (-2)")
        
        score = max(0, score)
        
        # Calculate grade
        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        # Count by severity
        severity_counts = {
            'critical': len([f for f in all_findings if f.get('severity') == 'critical']),
            'high': len([f for f in all_findings if f.get('severity') == 'high']),
            'medium': len([f for f in all_findings if f.get('severity') == 'medium']),
            'low': len([f for f in all_findings if f.get('severity') == 'low']),
            'info': len([f for f in all_findings if f.get('severity') == 'info']),
        }
        
        self.findings.append({
            'category': 'risk_score',
            'title': 'Security Risk Score',
            'score': score,
            'grade': grade,
            'deductions': deductions[:20],  # Top 20
            'severity_counts': severity_counts,
            'total_issues': len(all_findings),
        })
        
        return {
            'score': score,
            'grade': grade,
            'deductions': deductions,
            'severity_counts': severity_counts,
        }

    # ================================================================
    # VULNERABILITY CHAINING
    # ================================================================

    def analyze_vulnerability_chains(self, all_findings):
        """Analyze how vulnerabilities can be chained together."""
        print("  [CHAIN] Analyzing attack chains...")
        
        chains = []
        
        # Define chaining patterns
        chain_patterns = [
            {
                'name': 'Full Server Takeover',
                'description': 'Chain leading to complete server compromise',
                'steps': ['exposed_secrets', 'database_access', 'code_execution'],
                'severity': 'critical',
            },
            {
                'name': 'Data Breach',
                'description': 'Chain leading to data exfiltration',
                'steps': ['authentication_bypass', 'data_access', 'exfiltration'],
                'severity': 'critical',
            },
            {
                'name': 'Privilege Escalation',
                'description': 'Chain leading to admin access',
                'steps': ['low_privilege', 'vulnerability_exploit', 'admin_access'],
                'severity': 'high',
            },
        ]
        
        # Check for actual chains based on findings
        finding_categories = [f.get('category', '') for f in all_findings]
        finding_titles = [f.get('title', '').lower() for f in all_findings]
        
        # Chain 1: Exposed secrets -> Database access
        if any('secret' in c or 'credential' in c for c in finding_categories):
            if any('sql injection' in t or 'database' in t for t in finding_titles):
                chains.append({
                    'name': 'Database Compromise Chain',
                    'description': 'Exposed credentials + SQL injection = Full database access',
                    'steps': [
                        'Exposed .env/credentials',
                        'Database connection details obtained',
                        'SQL injection exploitation',
                        'Full database dump possible'
                    ],
                    'risk': 'CRITICAL',
                    'remediation': 'Secure credentials AND fix SQL injection'
                })
        
        # Chain 2: Missing headers -> XSS -> Session hijack
        if any('csp' in t or 'x-frame' in t for t in finding_titles):
            if any('xss' in t for t in finding_titles):
                chains.append({
                    'name': 'Session Hijacking Chain',
                    'description': 'Missing CSP + XSS = Session cookie theft',
                    'steps': [
                        'Missing Content-Security-Policy',
                        'XSS vulnerability exists',
                        'Attacker injects malicious script',
                        'User session cookies stolen'
                    ],
                    'risk': 'HIGH',
                    'remediation': 'Add CSP header AND fix XSS vulnerabilities'
                })
        
        # Chain 3: Directory listing -> Backup files -> Database dump
        if any('directory listing' in t for t in finding_titles):
            if any('backup' in t or 'database' in t for t in finding_titles):
                chains.append({
                    'name': 'Data Leak Chain',
                    'description': 'Directory listing exposes backup files with database',
                    'steps': [
                        'Directory listing enabled',
                        'Backup files accessible',
                        'Database dump downloadable',
                        'All data compromised'
                    ],
                    'risk': 'CRITICAL',
                    'remediation': 'Disable directory listing AND remove backup files'
                })
        
        # Chain 4: Admin panel -> Default creds -> Full control
        if any('admin panel' in t for t in finding_titles):
            if any('default' in t or 'credential' in t for t in finding_titles):
                chains.append({
                    'name': 'Admin Takeover Chain',
                    'description': 'Exposed admin panel + default credentials = Full control',
                    'steps': [
                        'Admin panel accessible',
                        'Default credentials work',
                        'Admin dashboard accessed',
                        'Full site control achieved'
                    ],
                    'risk': 'CRITICAL',
                    'remediation': 'Restrict admin access AND change default credentials'
                })
        
        if chains:
            self.findings.append({
                'category': 'attack_chains',
                'title': f'{len(chains)} Attack Chain(s) Identified',
                'chains': chains,
            })
        
        return chains

    # ================================================================
    # CVE MATCHING
    # ================================================================

    def match_cve(self, all_findings):
        """Match detected versions against known CVEs."""
        print("  [CVE] Checking for known vulnerabilities...")
        
        # Common vulnerable software patterns
        cve_database = {
            'wordpress': {
                'versions': ['4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7',
                           '5.0', '5.1', '5.2', '5.3', '5.4', '5.5', '5.6', '5.7', '5.8', '5.9'],
                'cves': {
                    '4.': ['CVE-2019-9978', 'CVE-2019-17671'],
                    '5.0': ['CVE-2019-17671', 'CVE-2020-5211'],
                    '5.1': ['CVE-2020-5211'],
                }
            },
            'apache': {
                'versions': ['2.4.49', '2.4.50', '2.4.51'],
                'cves': {
                    '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
                    '2.4.50': ['CVE-2021-42013'],
                }
            },
            'nginx': {
                'versions': ['1.0', '1.1', '1.2'],
                'cves': {
                    '1.0': ['CVE-2021-23017'],
                }
            },
            'php': {
                'versions': ['7.0', '7.1', '7.2', '7.3', '7.4', '8.0'],
                'cves': {
                    '7.0': ['CVE-2019-11043'],
                    '7.1': ['CVE-2019-11043'],
                    '7.2': ['CVE-2019-11043'],
                    '7.3': ['CVE-2019-11043'],
                }
            },
            'mysql': {
                'versions': ['5.6', '5.7', '8.0'],
                'cves': {
                    '5.6': ['CVE-2021-2307'],
                    '5.7': ['CVE-2021-2307'],
                }
            },
        }
        
        detected_cves = []
        
        # Check findings for version info
        for finding in all_findings:
            title = finding.get('title', '').lower()
            evidence = finding.get('evidence', '').lower()
            
            # Look for version numbers
            version_match = re.search(r'(\w+)\s*(?:version\s*)?(\d+\.\d+)', f"{title} {evidence}")
            
            if version_match:
                software = version_match.group(1).lower()
                version = version_match.group(2)
                
                if software in cve_database:
                    for vuln_version, cves in cve_database[software]['cves'].items():
                        if version.startswith(vuln_version):
                            for cve in cves:
                                detected_cves.append({
                                    'software': software,
                                    'version': version,
                                    'cve': cve,
                                    'severity': 'high',
                                })
        
        if detected_cves:
            self.findings.append({
                'category': 'cve',
                'title': f'{len(detected_cves)} Known CVE(s) Matched',
                'cves': detected_cves,
            })
        
        return detected_cves

    # ================================================================
    # EXECUTIVE SUMMARY
    # ================================================================

    def generate_executive_summary(self, all_findings, risk_score):
        """Generate executive summary for management."""
        print("  [EXEC] Generating executive summary...")
        
        severity_counts = {
            'critical': len([f for f in all_findings if f.get('severity') == 'critical']),
            'high': len([f for f in all_findings if f.get('severity') == 'high']),
            'medium': len([f for f in all_findings if f.get('severity') == 'medium']),
            'low': len([f for f in all_findings if f.get('severity') == 'low']),
            'info': len([f for f in all_findings if f.get('severity') == 'info']),
        }
        
        summary = {
            'title': 'Executive Summary',
            'date': datetime.now().strftime('%Y-%m-%d'),
            'risk_score': risk_score.get('score', 0),
            'risk_grade': risk_score.get('grade', 'F'),
            'total_issues': sum(severity_counts.values()),
            'severity_breakdown': severity_counts,
            'top_risks': [],
            'recommendations': [],
        }
        
        # Top risks
        critical_findings = [f for f in all_findings if f.get('severity') == 'critical']
        for finding in critical_findings[:5]:
            summary['top_risks'].append({
                'title': finding.get('title', 'Unknown'),
                'impact': 'High impact on security posture',
            })
        
        # Recommendations
        if severity_counts['critical'] > 0:
            summary['recommendations'].append('Immediately address all critical vulnerabilities')
        if severity_counts['high'] > 0:
            summary['recommendations'].append('Schedule high-priority fixes within 30 days')
        if risk_score.get('score', 0) < 50:
            summary['recommendations'].consider('Consider comprehensive security overhaul')
        
        summary['recommendations'].extend([
            'Implement security headers (CSP, HSTS, X-Frame-Options)',
            'Regular security scanning schedule',
            'Security training for development team',
        ])
        
        self.findings.append({
            'category': 'executive_summary',
            'title': 'Executive Summary',
            'summary': summary,
        })
        
        return summary


def analyze_intelligence(target_url, all_findings, scan_dir=None):
    """Convenience function for intelligence analysis."""
    analyzer = IntelligenceAnalyzer(target_url, scan_dir)
    
    risk_score = analyzer.calculate_risk_score(all_findings)
    chains = analyzer.analyze_vulnerability_chains(all_findings)
    cves = analyzer.match_cve(all_findings)
    summary = analyzer.generate_executive_summary(all_findings, risk_score)
    
    return {
        'findings': analyzer.findings,
        'risk_score': risk_score,
        'attack_chains': chains,
        'cves': cves,
        'executive_summary': summary,
    }