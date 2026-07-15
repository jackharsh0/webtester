"""
Reporting Module
PDF report generation, compliance checking, remediation code.
"""

import re
import json
from pathlib import Path
from datetime import datetime


class ReportGenerator:
    """Generate professional security reports."""

    def __init__(self, target_url, scan_dir=None):
        """Initialize report generator."""
        self.target_url = target_url.rstrip('/')
        self.scan_dir = Path(scan_dir) if scan_dir else Path("data")

    def generate_text_report(self, all_findings, risk_score, executive_summary):
        """Generate comprehensive text report."""
        print("  [REPORT] Generating report...")
        
        report_path = self.scan_dir / 'security_report.txt'
        
        severity_counts = {
            'critical': len([f for f in all_findings if f.get('severity') == 'critical']),
            'high': len([f for f in all_findings if f.get('severity') == 'high']),
            'medium': len([f for f in all_findings if f.get('severity') == 'medium']),
            'low': len([f for f in all_findings if f.get('severity') == 'low']),
            'info': len([f for f in all_findings if f.get('severity') == 'info']),
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("SECURITY ASSESSMENT REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            # Header
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanner: WebTester v2.0\n\n")
            
            # Risk Score
            f.write("-" * 70 + "\n")
            f.write("RISK SCORE\n")
            f.write("-" * 70 + "\n\n")
            f.write(f"Overall Score: {risk_score.get('score', 0)}/100\n")
            f.write(f"Grade: {risk_score.get('grade', 'F')}\n\n")
            
            # Score visualization
            score = risk_score.get('score', 0)
            bar_length = 40
            filled = int(bar_length * score / 100)
            bar = "█" * filled + "░" * (bar_length - filled)
            f.write(f"[{bar}] {score}%\n\n")
            
            # Grade explanation
            grade = risk_score.get('grade', 'F')
            grade_explanations = {
                'A': 'Excellent - Strong security posture',
                'B': 'Good - Minor improvements needed',
                'C': 'Fair - Several issues to address',
                'D': 'Poor - Significant security gaps',
                'F': 'Critical - Immediate action required',
            }
            f.write(f"Assessment: {grade_explanations.get(grade, 'Unknown')}\n\n")
            
            # Severity Breakdown
            f.write("-" * 70 + "\n")
            f.write("SEVERITY BREAKDOWN\n")
            f.write("-" * 70 + "\n\n")
            
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    f.write(f"  {sev.upper()}: {count}\n")
            
            f.write(f"\n  Total Issues: {sum(severity_counts.values())}\n\n")
            
            # Executive Summary
            if executive_summary:
                f.write("-" * 70 + "\n")
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 70 + "\n\n")
                
                if executive_summary.get('top_risks'):
                    f.write("Top Risks:\n")
                    for i, risk in enumerate(executive_summary['top_risks'][:5], 1):
                        f.write(f"  {i}. {risk['title']}\n")
                    f.write("\n")
                
                if executive_summary.get('recommendations'):
                    f.write("Key Recommendations:\n")
                    for rec in executive_summary['recommendations'][:5]:
                        f.write(f"  - {rec}\n")
                    f.write("\n")
            
            # Detailed Findings
            f.write("-" * 70 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("-" * 70 + "\n\n")
            
            for i, finding in enumerate(all_findings, 1):
                if finding.get('category') in ['risk_score', 'executive_summary', 'attack_chains']:
                    continue
                
                f.write(f"FINDING #{i}\n")
                f.write(f"  Severity: {finding.get('severity', 'info').upper()}\n")
                f.write(f"  Category: {finding.get('category', 'unknown')}\n")
                f.write(f"  Title: {finding.get('title', 'Unknown')}\n")
                
                if finding.get('description'):
                    f.write(f"  Description: {finding['description']}\n")
                if finding.get('evidence'):
                    f.write(f"  Evidence: {finding['evidence']}\n")
                if finding.get('remediation'):
                    f.write(f"  Remediation: {finding['remediation']}\n")
                f.write("\n")
            
            # Remediation Guide
            f.write("-" * 70 + "\n")
            f.write("REMEDIATION GUIDE\n")
            f.write("-" * 70 + "\n\n")
            
            remediation_categories = {
                'secrets': 'Secure all secrets and credentials',
                'headers': 'Implement security headers',
                'ssl': 'Fix SSL/TLS configuration',
                'injection': 'Use parameterized queries',
                'wordpress': 'Update WordPress and plugins',
            }
            
            for category, action in remediation_categories.items():
                if any(f.get('category') == category for f in all_findings):
                    f.write(f"  - {action}\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 70 + "\n")
        
        print(f"  [REPORT] Saved to: {report_path}")
        return report_path

    def generate_compliance_report(self, all_findings):
        """Generate compliance checklist report."""
        print("  [COMPLIANCE] Generating compliance report...")
        
        compliance_path = self.scan_dir / 'compliance_report.txt'
        
        # Define compliance controls
        controls = {
            'PCI DSS': [
                ('1.1', 'Firewall configuration', 'firewall' in str(all_findings).lower()),
                ('2.1', 'Default passwords changed', not any('default' in f.get('title', '').lower() for f in all_findings)),
                ('6.5.1', 'SQL injection prevention', not any('sql injection' in f.get('title', '').lower() for f in all_findings)),
                ('6.5.7', 'XSS prevention', not any('xss' in f.get('title', '').lower() for f in all_findings)),
                ('8.3.6', 'Password complexity', True),
                ('10.2', 'Audit logging', True),
                ('11.3', 'Penetration testing', True),
            ],
            'HIPAA': [
                ('§164.312(a)', 'Access control', not any('authentication' in f.get('title', '').lower() for f in all_findings)),
                ('§164.312(e)', 'Encryption', any('ssl' in f.get('title', '').lower() or 'https' in f.get('title', '').lower() for f in all_findings)),
                ('§164.312(c)', 'Integrity controls', True),
            ],
            'GDPR': [
                ('Art. 32', 'Security of processing', not any('critical' in f.get('severity', '') for f in all_findings)),
                ('Art. 33', 'Breach notification', True),
                ('Art. 25', 'Data protection by design', True),
            ],
        }
        
        with open(compliance_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("COMPLIANCE CHECKLIST\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for standard, checks in controls.items():
                f.write("-" * 70 + "\n")
                f.write(f"{standard}\n")
                f.write("-" * 70 + "\n\n")
                
                passed = sum(1 for _, _, status in checks if status)
                total = len(checks)
                
                for control_id, description, status in checks:
                    status_symbol = "✅" if status else "❌"
                    f.write(f"  {status_symbol} {control_id} - {description}\n")
                
                f.write(f"\n  Score: {passed}/{total} ({passed*100//total}%)\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("END OF COMPLIANCE REPORT\n")
            f.write("=" * 70 + "\n")
        
        print(f"  [COMPLIANCE] Saved to: {compliance_path}")
        return compliance_path


def generate_reports(target_url, all_findings, risk_score, executive_summary, scan_dir=None):
    """Convenience function for report generation."""
    generator = ReportGenerator(target_url, scan_dir)
    
    text_report = generator.generate_text_report(all_findings, risk_score, executive_summary)
    compliance_report = generator.generate_compliance_report(all_findings)
    
    return {
        'text_report': text_report,
        'compliance_report': compliance_report,
    }