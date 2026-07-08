"""
WebTester - Website Security Scanner v2.0
Downloads websites and runs 65+ security checks including WordPress-specific tests.

Usage:
    python webtester.py <url>                    # Scan website
    python webtester.py <url> --sqli             # SQL Injection test
    python webtester.py <url> --csp              # Generate CSP header
    python webtester.py --csp-only <scan_dir> <url>  # Generate CSP from existing scan
"""

import sys
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from colorama import init, Fore, Style
    init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

from scraper import WebsiteScraper
from scanner import SecurityScanner
from csp_generator import generate_csp_report, CSPGenerator
from sqli_scanner import SQLiScanner


# Color helpers
def colorize(text, color):
    """Apply color to text if colorama is available."""
    if not HAS_COLORAMA:
        return text
    
    colors = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'yellow': Fore.YELLOW,
        'blue': Fore.BLUE,
        'magenta': Fore.MAGENTA,
        'cyan': Fore.CYAN,
        'white': Fore.WHITE,
        'bright_red': Fore.LIGHTRED_EX,
        'bright_green': Fore.LIGHTGREEN_EX,
        'bright_yellow': Fore.LIGHTYELLOW_EX,
        'bright_cyan': Fore.LIGHTCYAN_EX,
        'reset': Style.RESET_ALL,
        'bold': Style.BRIGHT,
    }
    
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def print_banner():
    """Print the scanner banner."""
    banner = f"""
{colorize('=' * 60, 'cyan')}
{colorize('WEBTESTER', 'bold')} {colorize('-', 'white')} {colorize('Website Security Scanner v2.0', 'bright_cyan')}
{colorize('=' * 60, 'cyan')}
{colorize('  Built by jackharsh0 | github.com/jackharsh0', 'bright_cyan')}
{colorize('  "Security is not a product, but a process"', 'yellow')}
{colorize('=' * 60, 'cyan')}
"""
    print(banner)


def print_phase(phase_num, phase_name):
    """Print a phase header."""
    print()
    print(colorize(f"{'─' * 60}", 'cyan'))
    print(colorize(f"PHASE {phase_num}: {phase_name}", 'bold'))
    print(colorize(f"{'─' * 60}", 'cyan'))


def print_finding(finding):
    """Print a single finding with color based on severity."""
    severity = finding['severity']
    title = finding['title']
    
    severity_labels = {
        'critical': f"{colorize('[CRITICAL]', 'bright_red')}",
        'high': f"{colorize('[HIGH]', 'red')}",
        'medium': f"{colorize('[MEDIUM]', 'yellow')}",
        'low': f"{colorize('[LOW]', 'green')}",
        'info': f"{colorize('[INFO]', 'white')}",
    }
    
    print(f"  {severity_labels.get(severity, severity)} {title}")
    
    if finding.get('evidence'):
        evidence_lines = finding['evidence'].split('\n')
        for line in evidence_lines[:3]:  # Limit to 3 lines
            print(f"    {colorize('>', 'cyan')} {line}")
    
    if finding.get('remediation'):
        print(f"    {colorize('Fix:', 'bright_cyan')} {finding['remediation']}")
    
    print()


def print_summary(results, scrape_result, scan_result):
    """Print the final summary."""
    findings = scan_result['findings']
    stats = scan_result['stats']
    
    print()
    print(colorize('=' * 60, 'cyan'))
    print(colorize('SCAN RESULTS', 'bold'))
    print(colorize('=' * 60, 'cyan'))
    
    # Target info
    print(f"\n  {colorize('Target:', 'bright_cyan')} {results['url']}")
    print(f"  {colorize('Duration:', 'bright_cyan')} {results['duration']}")
    print(f"  {colorize('Files Downloaded:', 'bright_cyan')} {scrape_result['files_count']}")
    print(f"  {colorize('Total Size:', 'bright_cyan')} {scrape_result['total_size'] / 1024:.1f} KB")
    
    # Severity breakdown
    print(f"\n  {colorize('SEVERITY BREAKDOWN:', 'bold')}")
    
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    severity_colors = {
        'critical': 'bright_red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'green',
        'info': 'white',
    }
    
    total_findings = 0
    for severity in severity_order:
        count = stats.get(severity, 0)
        if count > 0:
            color = severity_colors[severity]
            print(f"    {colorize('*', color)} {severity.upper()}: {count}")
            total_findings += count
    
    print(f"\n  {colorize('Total Issues:', 'bold')} {total_findings}")
    print(f"  {colorize('Checks Run:', 'bright_cyan')} {stats.get('checks_run', 0)}")
    print(f"  {colorize('Checks Passed:', 'bright_green')} {stats.get('checks_passed', 0)}")
    
    # Top critical findings
    critical_findings = [f for f in findings if f['severity'] == 'critical']
    if critical_findings:
        print(f"\n  {colorize('TOP CRITICAL ISSUES:', 'bright_red')}")
        for i, finding in enumerate(critical_findings[:5], 1):
            print(f"    {colorize(f'{i}.', 'red')} {finding['title']}")
            if finding.get('remediation'):
                print(f"       {colorize('Fix:', 'bright_cyan')} {finding['remediation'][:80]}...")
    
    print()
    print(colorize('=' * 60, 'cyan'))
    print(f"  {colorize('Files saved to:', 'bright_cyan')} {results['output_dir']}")
    print(colorize('=' * 60, 'cyan'))
    
    # Footer promo
    print()
    print(colorize('  ' + '=' * 56, 'cyan'))
    print(colorize('  |', 'cyan') + colorize(' Built by jackharsh0', 'bright_cyan') + colorize(' |', 'cyan'))
    print(colorize('  |', 'cyan') + colorize(' github.com/jackharsh0/webtester', 'bright_cyan') + colorize(' |', 'cyan'))
    print(colorize('  |', 'cyan') + colorize(' "Hack the planet, secure the future"', 'yellow') + colorize(' |', 'cyan'))
    print(colorize('  ' + '=' * 56, 'cyan'))
    print()


def save_report(results, scrape_result, scan_result, output_dir):
    """Save a text report to file."""
    report_path = Path(output_dir) / 'report.txt'
    
    findings = scan_result['findings']
    stats = scan_result['stats']
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("WEBTESTER - Security Scan Report\n")
        f.write("=" * 60 + "\n\n")
        
        f.write(f"Target: {results['url']}\n")
        f.write(f"Date: {results['timestamp']}\n")
        f.write(f"Duration: {results['duration']}\n")
        f.write(f"Files Downloaded: {scrape_result['files_count']}\n")
        f.write(f"Total Size: {scrape_result['total_size'] / 1024:.1f} KB\n\n")
        
        f.write("-" * 60 + "\n")
        f.write("SEVERITY BREAKDOWN\n")
        f.write("-" * 60 + "\n")
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = stats.get(severity, 0)
            if count > 0:
                f.write(f"  {severity.upper()}: {count}\n")
        
        f.write(f"\nTotal Issues: {len(findings)}\n")
        f.write(f"Checks Run: {stats.get('checks_run', 0)}\n")
        f.write(f"Checks Passed: {stats.get('checks_passed', 0)}\n\n")
        
        f.write("-" * 60 + "\n")
        f.write("DETAILED FINDINGS\n")
        f.write("-" * 60 + "\n\n")
        
        for i, finding in enumerate(findings, 1):
            f.write(f"{i}. [{finding['severity'].upper()}] {finding['title']}\n")
            f.write(f"   Category: {finding['category']}\n")
            if finding.get('description'):
                f.write(f"   Description: {finding['description']}\n")
            if finding.get('evidence'):
                f.write(f"   Evidence: {finding['evidence']}\n")
            if finding.get('remediation'):
                f.write(f"   Remediation: {finding['remediation']}\n")
            f.write("\n")
        
        f.write("=" * 60 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 60 + "\n")
    
    return report_path


def generate_csp(target_url, scan_dir=None):
    """Generate CSP for a website."""
    print_banner()
    print(f"  {colorize('CSP GENERATOR', 'bold')}")
    print(f"  {colorize('Target:', 'bright_cyan')} {target_url}")
    print()
    
    if scan_dir:
        output_dir = scan_dir
    else:
        safe_domain = urlparse(target_url).netloc.replace('.', '_').replace(':', '_')
        output_dir = f"data/{safe_domain}"
    
    print(f"  {colorize('Analyzing website...', 'cyan')}")
    result = generate_csp_report(output_dir, target_url, output_dir)
    
    print(f"\n{colorize('=' * 60, 'cyan')}")
    print(colorize("GENERATED CONTENT-SECURITY-POLICY", 'bold'))
    print(colorize('=' * 60, 'cyan'))
    print(f"\n{colorize('CSP Header:', 'bright_cyan')}")
    print(f"  {result['csp']['csp']}")
    
    print(f"\n{colorize('Sources Found:', 'bright_cyan')}")
    sources = result['csp']['sources_found']
    print(f"  Scripts:  {sources['scripts']} domains")
    print(f"  Styles:   {sources['styles']} domains")
    print(f"  Images:   {sources['images']} domains")
    print(f"  Fonts:    {sources['fonts']} domains")
    print(f"  Connect:  {sources['connect']} domains")
    print(f"  Frames:   {sources['frames']} domains")
    
    print(f"\n{colorize('Files Generated:', 'bright_cyan')}")
    for f in result['files']:
        print(f"  {colorize('*', 'green')} {f}")
    
    print(f"\n{colorize('=' * 60, 'cyan')}")
    print(colorize("HOW TO USE", 'bold'))
    print(colorize('=' * 60, 'cyan'))
    print("""
  1. TEST FIRST (Report Only Mode):
     - Copy the CSP header
     - Add it as Content-Security-Policy-Report-Only
     - Monitor browser console for violations
     - Fix any broken functionality

  2. ENFORCE (After Testing):
     - Change header name to Content-Security-Policy
     - This will block all violations

  3. Server-Specific Files:
     - .htaccess.example     (Apache)
     - nginx.conf.example    (Nginx)
     - nodejs-middleware.js  (Node.js/Express)
     - flask-middleware.py    (Python/Flask)
     - wordpress-functions.php (WordPress)
""")
    print(colorize('=' * 60, 'cyan'))


def main():
    """Main entry point."""
    # Check for CSP-only mode
    if '--csp-only' in sys.argv:
        idx = sys.argv.index('--csp-only')
        if len(sys.argv) < idx + 3:
            print(f"\n  {colorize('Usage:', 'bold')} python webtester.py --csp-only <scan_dir> <url>")
            print(f"  {colorize('Example:', 'cyan')} python webtester.py --csp-only data/example_com https://example.com\n")
            sys.exit(1)
        scan_dir = sys.argv[idx + 1]
        target_url = sys.argv[idx + 2]
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        generate_csp(target_url, scan_dir)
        return
    
    # Check arguments
    if len(sys.argv) < 2:
        print(f"\n  {colorize('Usage:', 'bold')} python webtester.py <url>")
        print(f"  {colorize('SQLi Mode:', 'bold')} python webtester.py <url> --sqli")
        print(f"  {colorize('CSP Mode:', 'bold')} python webtester.py <url> --csp")
        print(f"  {colorize('Example:', 'cyan')} python webtester.py https://example.com")
        print(f"  {colorize('Example:', 'cyan')} python webtester.py https://example.com --sqli\n")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Check for flags
    generate_csp_only = '--csp' in sys.argv
    run_sqli = '--sqli' in sys.argv
    
    # Print banner
    print_banner()
    
    # Start timer
    start_time = datetime.now()
    timestamp = start_time.strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"  {colorize('Target:', 'bright_cyan')} {target_url}")
    print(f"  {colorize('Time:', 'bright_cyan')} {timestamp}")
    
    # ============================================
    # PHASE 1: DOWNLOAD WEBSITE
    # ============================================
    print_phase(1, "DOWNLOADING WEBSITE")
    
    scraper = WebsiteScraper(target_url, output_dir="data", max_depth=3, max_files=200)
    scrape_result = scraper.scrape()
    
    # ============================================
    # PHASE 2: SECURITY SCANNING
    # ============================================
    print_phase(2, "SECURITY SCANNING")
    
    scanner = SecurityScanner(target_url, scan_dir=scrape_result['output_dir'])
    scan_result = scanner.scan()
    
    # ============================================
    # PHASE 3: RESULTS
    # ============================================
    print_phase(3, "RESULTS")
    
    # End timer
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Prepare results
    results = {
        'url': target_url,
        'timestamp': timestamp,
        'duration': f"{duration:.1f} seconds",
        'output_dir': scrape_result['output_dir'],
    }
    
    # Print findings
    for finding in scan_result['findings']:
        print_finding(finding)
    
    # Print summary
    print_summary(results, scrape_result, scan_result)
    
    # Save report
    report_path = save_report(results, scrape_result, scan_result, scrape_result['output_dir'])
    print(f"  {colorize('Report saved to:', 'bright_cyan')} {report_path}\n")
    
    # ============================================
    # PHASE 4: SQL INJECTION TESTING (if requested)
    # ============================================
    if run_sqli:
        print_phase(4, "SQL INJECTION TESTING")
        
        sqli_scanner = SQLiScanner(target_url, scan_dir=scrape_result['output_dir'])
        sqli_result = sqli_scanner.scan()
        
        # Print SQLi findings
        for finding in sqli_result['findings']:
            print_finding(finding)
        
        # Generate SQLi report
        sqli_report = sqli_scanner.generate_client_report(scrape_result['output_dir'])
        print(f"  {colorize('SQLi Report saved to:', 'bright_cyan')} {sqli_report}\n")
    
    # ============================================
    # PHASE 5: CSP GENERATION (if requested)
    # ============================================
    if generate_csp_only or any(f['title'].startswith('Missing Content-Security-Policy') for f in scan_result['findings']):
        print_phase(5 if run_sqli else 4, "CSP GENERATION")
        generate_csp(target_url, scrape_result['output_dir'])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {colorize('Scan cancelled by user.', 'yellow')}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n  {colorize('Error:', 'red')} {str(e)}\n")
        sys.exit(1)