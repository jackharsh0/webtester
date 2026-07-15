"""
WebTester - Website Security Scanner v3.0
Downloads websites and runs 100+ security checks including WordPress, API, GraphQL, JWT, OAuth.

Usage:
    python webtester.py <url>                    # Basic scan
    python webtester.py <url> --sqli             # SQL Injection test
    python webtester.py <url> --api              # API Security test
    python webtester.py <url> --recon            # Reconnaissance
    python webtester.py <url> --advanced         # Advanced attacks
    python webtester.py <url> --full             # Full scan (all modules)
    python webtester.py <url> --csp              # Generate CSP header
    python webtester.py --batch urls.txt         # Batch scan from file
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
from api_security import APISecurityTester
from recon import ReconScanner
from advanced_attacks import AdvancedAttacks
from intelligence import analyze_intelligence
from reporting import generate_reports
from batch_scanner import BatchScanner


def colorize(text, color):
    """Apply color to text if colorama is available."""
    if not HAS_COLORAMA:
        return text
    colors = {
        'red': Fore.RED, 'green': Fore.GREEN, 'yellow': Fore.YELLOW,
        'blue': Fore.BLUE, 'cyan': Fore.CYAN, 'white': Fore.WHITE,
        'bright_red': Fore.LIGHTRED_EX, 'bright_green': Fore.LIGHTGREEN_EX,
        'bright_yellow': Fore.LIGHTYELLOW_EX, 'bright_cyan': Fore.LIGHTCYAN_EX,
        'reset': Style.RESET_ALL, 'bold': Style.BRIGHT,
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def print_banner():
    """Print the scanner banner."""
    banner = f"""
{colorize('=' * 60, 'cyan')}
{colorize('WEBTESTER', 'bold')} {colorize('-', 'white')} {colorize('Website Security Scanner v3.0', 'bright_cyan')}
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
    """Print a single finding."""
    severity = finding.get('severity', 'info')
    title = finding.get('title', 'Unknown')
    
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
        for line in evidence_lines[:3]:
            print(f"    {colorize('>', 'cyan')} {line}")
    
    if finding.get('remediation'):
        print(f"    {colorize('Fix:', 'bright_cyan')} {finding['remediation']}")
    
    print()


def print_summary(results, scrape_result, scan_result):
    """Print the final summary."""
    findings = scan_result.get('findings', [])
    stats = scan_result.get('stats', {})
    
    print()
    print(colorize('=' * 60, 'cyan'))
    print(colorize('SCAN RESULTS', 'bold'))
    print(colorize('=' * 60, 'cyan'))
    
    print(f"\n  {colorize('Target:', 'bright_cyan')} {results['url']}")
    print(f"  {colorize('Duration:', 'bright_cyan')} {results['duration']}")
    print(f"  {colorize('Files Downloaded:', 'bright_cyan')} {scrape_result.get('files_count', 0)}")
    
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    severity_colors = {
        'critical': 'bright_red', 'high': 'red', 'medium': 'yellow',
        'low': 'green', 'info': 'white',
    }
    
    print(f"\n  {colorize('SEVERITY BREAKDOWN:', 'bold')}")
    
    total_findings = 0
    for severity in severity_order:
        count = sum(1 for f in findings if f.get('severity') == severity)
        if count > 0:
            color = severity_colors[severity]
            print(f"    {colorize('*', color)} {severity.upper()}: {count}")
            total_findings += count
    
    print(f"\n  {colorize('Total Issues:', 'bold')} {total_findings}")
    
    critical_findings = [f for f in findings if f.get('severity') == 'critical']
    if critical_findings:
        print(f"\n  {colorize('TOP CRITICAL ISSUES:', 'bright_red')}")
        for i, finding in enumerate(critical_findings[:5], 1):
            print(f"    {colorize(f'{i}.', 'red')} {finding.get('title', 'Unknown')}")
    
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


def main():
    """Main entry point."""
    # Check for batch mode
    if '--batch' in sys.argv:
        idx = sys.argv.index('--batch')
        if len(sys.argv) < idx + 2:
            print(f"\n  {colorize('Usage:', 'bold')} python webtester.py --batch <urls_file>")
            sys.exit(1)
        
        urls_file = sys.argv[idx + 1]
        
        def scan_func(url):
            scraper = WebsiteScraper(url, output_dir="data", max_depth=3, max_files=100)
            scrape_result = scraper.scrape()
            scanner = SecurityScanner(url, scan_dir=scrape_result['output_dir'])
            return scanner.scan()
        
        batch = BatchScanner()
        batch.scan_batch(urls_file, scan_func)
        return
    
    # Check for CSP-only mode
    if '--csp-only' in sys.argv:
        idx = sys.argv.index('--csp-only')
        if len(sys.argv) < idx + 3:
            print(f"\n  {colorize('Usage:', 'bold')} python webtester.py --csp-only <scan_dir> <url>")
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
        print(f"  {colorize('Modes:', 'bold')}")
        print(f"    --sqli       SQL Injection testing")
        print(f"    --api        API Security testing (REST, GraphQL, JWT, OAuth)")
        print(f"    --recon      Reconnaissance (subdomains, ports, directories)")
        print(f"    --advanced   Advanced attacks (CORS, XXE, SSTI, CSRF)")
        print(f"    --full       Full scan (all modules)")
        print(f"    --csp        Generate CSP header")
        print(f"    --batch      Batch scan from file")
        print(f"  {colorize('Example:', 'cyan')} python webtester.py https://example.com --full\n")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Check for flags
    generate_csp_only = '--csp' in sys.argv
    run_sqli = '--sqli' in sys.argv
    run_api = '--api' in sys.argv
    run_recon = '--recon' in sys.argv
    run_advanced = '--advanced' in sys.argv
    run_full = '--full' in sys.argv
    
    # Full scan enables all modules
    if run_full:
        run_sqli = True
        run_api = True
        run_recon = True
        run_advanced = True
    
    # Print banner
    print_banner()
    
    # Start timer
    start_time = datetime.now()
    timestamp = start_time.strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"  {colorize('Target:', 'bright_cyan')} {target_url}")
    print(f"  {colorize('Time:', 'bright_cyan')} {timestamp}")
    
    # Collect all findings
    all_findings = []
    
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
    all_findings.extend(scan_result.get('findings', []))
    
    # ============================================
    # PHASE 3: RECONNAISSANCE (if requested)
    # ============================================
    if run_recon:
        print_phase(3, "RECONNAISSANCE")
        
        recon = ReconScanner(target_url, scan_dir=scrape_result['output_dir'])
        recon_result = recon.scan()
        all_findings.extend(recon_result.get('findings', []))
    
    # ============================================
    # PHASE 4: SQL INJECTION TESTING (if requested)
    # ============================================
    if run_sqli:
        print_phase(4, "SQL INJECTION TESTING")
        
        sqli_scanner = SQLiScanner(target_url, scan_dir=scrape_result['output_dir'])
        sqli_result = sqli_scanner.scan()
        all_findings.extend(sqli_result.get('findings', []))
    
    # ============================================
    # PHASE 5: API SECURITY TESTING (if requested)
    # ============================================
    if run_api:
        print_phase(5, "API SECURITY TESTING")
        
        api_tester = APISecurityTester(target_url, scan_dir=scrape_result['output_dir'])
        api_result = api_tester.scan()
        all_findings.extend(api_result.get('findings', []))
    
    # ============================================
    # PHASE 6: ADVANCED ATTACKS (if requested)
    # ============================================
    if run_advanced:
        print_phase(6, "ADVANCED ATTACKS")
        
        advanced = AdvancedAttacks(target_url, scan_dir=scrape_result['output_dir'])
        advanced_result = advanced.scan()
        all_findings.extend(advanced_result.get('findings', []))
    
    # ============================================
    # PHASE 7: INTELLIGENCE ANALYSIS
    # ============================================
    if len(all_findings) > 0:
        print_phase(7, "INTELLIGENCE ANALYSIS")
        
        intelligence = analyze_intelligence(target_url, all_findings, scan_dir=scrape_result['output_dir'])
        risk_score = intelligence.get('risk_score', {})
        executive_summary = intelligence.get('executive_summary', {})
    
    # ============================================
    # PHASE 8: RESULTS
    # ============================================
    print_phase(8, "RESULTS")
    
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
    for finding in all_findings:
        if finding.get('category') not in ['risk_score', 'executive_summary', 'attack_chains']:
            print_finding(finding)
    
    # Print summary
    print_summary(results, scrape_result, {'findings': all_findings, 'stats': scan_result.get('stats', {})})
    
    # ============================================
    # PHASE 9: REPORT GENERATION
    # ============================================
    print_phase(9, "REPORT GENERATION")
    
    reports = generate_reports(target_url, all_findings, risk_score, executive_summary, scan_dir=scrape_result['output_dir'])
    
    print(f"  {colorize('Reports generated:', 'bright_cyan')}")
    print(f"    - {reports['text_report']}")
    print(f"    - {reports['compliance_report']}")
    
    # ============================================
    # PHASE 10: CSP GENERATION (if requested)
    # ============================================
    if generate_csp_only or any(f.get('title', '').startswith('Missing Content-Security-Policy') for f in all_findings):
        print_phase(10, "CSP GENERATION")
        generate_csp(target_url, scrape_result['output_dir'])


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
    
    print(f"\n{colorize('Files Generated:', 'bright_cyan')}")
    for f in result['files']:
        print(f"  {colorize('*', 'green')} {f}")
    
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {colorize('Scan cancelled by user.', 'yellow')}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n  {colorize('Error:', 'red')} {str(e)}\n")
        sys.exit(1)