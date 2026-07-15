"""
Batch Scanning Module
Scan multiple URLs from a file.
"""

import os
from pathlib import Path
from datetime import datetime


class BatchScanner:
    """Batch scanning for multiple URLs."""

    def __init__(self):
        """Initialize batch scanner."""
        self.results = []

    def scan_batch(self, urls_file, scan_func):
        """Scan multiple URLs from a file."""
        print(f"\n{'='*60}")
        print(f"BATCH SCANNER")
        print(f"{'='*60}\n")
        
        # Read URLs from file
        urls_path = Path(urls_file)
        
        if not urls_path.exists():
            print(f"  [ERROR] File not found: {urls_file}")
            return []
        
        with open(urls_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"  Found {len(urls)} URLs to scan\n")
        
        # Scan each URL
        for i, url in enumerate(urls, 1):
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            print(f"\n[{i}/{len(urls)}] Scanning: {url}")
            print("-" * 40)
            
            try:
                result = scan_func(url)
                self.results.append({
                    'url': url,
                    'status': 'completed',
                    'findings': len(result.get('findings', [])),
                    'result': result,
                })
            except Exception as e:
                print(f"  [ERROR] {str(e)}")
                self.results.append({
                    'url': url,
                    'status': 'failed',
                    'error': str(e),
                })
        
        # Generate summary
        self._print_summary()
        
        return self.results

    def _print_summary(self):
        """Print batch scan summary."""
        print(f"\n{'='*60}")
        print(f"BATCH SCAN COMPLETE")
        print(f"{'='*60}\n")
        
        completed = sum(1 for r in self.results if r['status'] == 'completed')
        failed = sum(1 for r in self.results if r['status'] == 'failed')
        total_findings = sum(r.get('findings', 0) for r in self.results)
        
        print(f"  Total URLs: {len(self.results)}")
        print(f"  Completed: {completed}")
        print(f"  Failed: {failed}")
        print(f"  Total Findings: {total_findings}")
        
        print(f"\n  Results:")
        for result in self.results:
            status = "✅" if result['status'] == 'completed' else "❌"
            findings = result.get('findings', 0)
            print(f"    {status} {result['url']} ({findings} issues)")

    def generate_batch_report(self, output_dir="data"):
        """Generate batch scan report."""
        report_path = Path(output_dir) / 'batch_report.txt'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("BATCH SCAN REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total URLs: {len(self.results)}\n\n")
            
            for i, result in enumerate(self.results, 1):
                f.write(f"{i}. {result['url']}\n")
                f.write(f"   Status: {result['status']}\n")
                f.write(f"   Findings: {result.get('findings', 0)}\n\n")
        
        return report_path


def scan_batch(urls_file, scan_func):
    """Convenience function for batch scanning."""
    scanner = BatchScanner()
    return scanner.scan_batch(urls_file, scan_func)