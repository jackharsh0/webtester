"""
CSP (Content-Security-Policy) Generator
Analyzes website and generates proper CSP headers.
"""

import os
import re
from pathlib import Path
from urllib.parse import urlparse


class CSPGenerator:
    """Generates Content-Security-Policy headers based on website analysis."""

    def __init__(self, scan_dir=None, target_url=None):
        """Initialize CSP generator."""
        self.scan_dir = Path(scan_dir) if scan_dir else None
        self.target_url = target_url
        self.sources = {
            'script-src': set(),
            'style-src': set(),
            'img-src': set(),
            'font-src': set(),
            'connect-src': set(),
            'media-src': set(),
            'object-src': set(),
            'frame-src': set(),
            'frame-ancestors': set(),
            'form-action': set(),
            'base-uri': set(),
        }

    def analyze_website(self):
        """Analyze downloaded files to find all external sources."""
        if not self.scan_dir or not self.scan_dir.exists():
            return

        text_extensions = {'.html', '.htm', '.css', '.js', '.json', '.xml'}
        
        for file_path in self.scan_dir.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in text_extensions:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    self._extract_sources(content)
                except Exception:
                    pass

    def _extract_sources(self, content):
        """Extract all external sources from content."""
        # Script sources
        scripts = re.findall(r'(?:src|href)\s*=\s*["\']?(https?://[^"\'\s>]+)', content)
        for url in scripts:
            parsed = urlparse(url)
            if parsed.scheme in ('http', 'https'):
                self.sources['script-src'].add(f"{parsed.scheme}://{parsed.netloc}")

        # Style sources
        styles = re.findall(r'(?:href)\s*=\s*["\']?(https?://[^"\'\s>]+\.css)', content)
        for url in styles:
            parsed = urlparse(url)
            self.sources['style-src'].add(f"{parsed.scheme}://{parsed.netloc}")

        # Image sources
        images = re.findall(r'(?:src|href)\s*=\s*["\']?(https?://[^"\'\s>]+\.(?:png|jpg|jpeg|gif|svg|webp|ico))', content)
        for url in images:
            parsed = urlparse(url)
            self.sources['img-src'].add(f"{parsed.scheme}://{parsed.netloc}")

        # Font sources
        fonts = re.findall(r'(?:src|href)\s*=\s*["\']?(https?://[^"\'\s>]+\.(?:woff|woff2|ttf|otf|eot))', content)
        for url in fonts:
            parsed = urlparse(url)
            self.sources['font-src'].add(f"{parsed.scheme}://{parsed.netloc}")

        # Connect sources (API calls)
        connects = re.findall(r'(?:fetch|XMLHttpRequest|ajax|api|endpoint)\s*[\(]?\s*["\']?(https?://[^"\'\s\)]+)', content)
        for url in connects:
            parsed = urlparse(url)
            if parsed.scheme in ('http', 'https'):
                self.sources['connect-src'].add(f"{parsed.scheme}://{parsed.netloc}")

        # Frame sources
        frames = re.findall(r'(?:src)\s*=\s*["\']?(https?://[^"\'\s>]+)', content)
        for url in frames:
            parsed = urlparse(url)
            if 'youtube' in parsed.netloc or 'vimeo' in parsed.netloc or 'iframe' in content.lower():
                self.sources['frame-src'].add(f"{parsed.scheme}://{parsed.netloc}")

    def generate_csp(self, mode='report-only'):
        """
        Generate CSP header.
        
        Args:
            mode: 'enforce' or 'report-only'
            
        Returns:
            dict: CSP configuration
        """
        self.analyze_website()
        
        # Build CSP directives
        directives = []
        
        # Default source - start restrictive
        directives.append("default-src 'self'")
        
        # Script sources
        script_sources = list(self.sources['script-src'])
        if script_sources:
            # Keep only unique domains
            unique_domains = list(set(script_sources))[:10]  # Limit to 10
            directives.append(f"script-src 'self' {' '.join(unique_domains)}")
        else:
            directives.append("script-src 'self'")
        
        # Style sources
        style_sources = list(self.sources['style-src'])
        if style_sources:
            unique_domains = list(set(style_sources))[:10]
            directives.append(f"style-src 'self' 'unsafe-inline' {' '.join(unique_domains)}")
        else:
            directives.append("style-src 'self' 'unsafe-inline'")
        
        # Image sources
        img_sources = list(self.sources['img-src'])
        if img_sources:
            unique_domains = list(set(img_sources))[:10]
            directives.append(f"img-src 'self' data: https: {' '.join(unique_domains)}")
        else:
            directives.append("img-src 'self' data: https:")
        
        # Font sources
        font_sources = list(self.sources['font-src'])
        if font_sources:
            unique_domains = list(set(font_sources))[:10]
            directives.append(f"font-src 'self' {' '.join(unique_domains)}")
        else:
            directives.append("font-src 'self'")
        
        # Connect sources
        connect_sources = list(self.sources['connect-src'])
        if connect_sources:
            unique_domains = list(set(connect_sources))[:10]
            directives.append(f"connect-src 'self' {' '.join(unique_domains)}")
        else:
            directives.append("connect-src 'self'")
        
        # Frame sources
        frame_sources = list(self.sources['frame-src'])
        if frame_sources:
            unique_domains = list(set(frame_sources))[:10]
            directives.append(f"frame-src 'self' {' '.join(unique_domains)}")
        else:
            directives.append("frame-src 'self'")
        
        # Other directives
        directives.append("object-src 'none'")
        directives.append("base-uri 'self'")
        directives.append("form-action 'self'")
        directives.append("frame-ancestors 'none'")
        directives.append("upgrade-insecure-requests")
        
        # Build final CSP string
        csp_string = "; ".join(directives)
        
        return {
            'csp': csp_string,
            'mode': mode,
            'header_name': 'Content-Security-Policy' if mode == 'enforce' else 'Content-Security-Policy-Report-Only',
            'directives': directives,
            'sources_found': {
                'scripts': len(self.sources['script-src']),
                'styles': len(self.sources['style-src']),
                'images': len(self.sources['img-src']),
                'fonts': len(self.sources['font-src']),
                'connect': len(self.sources['connect-src']),
                'frames': len(self.sources['frame-src']),
            }
        }

    def generate_htaccess(self):
        """Generate .htaccess rules for Apache."""
        csp = self.generate_csp(mode='report-only')
        
        return f"""# Content-Security-Policy (Report Only - Test First)
<IfModule mod_headers.c>
    Header set Content-Security-Policy-Report-Only "{csp['csp']}"
</IfModule>

# After testing, uncomment below and comment above to enforce:
# <IfModule mod_headers.c>
#     Header set Content-Security-Policy "{csp['csp']}"
# </IfModule>
"""

    def generate_nginx(self):
        """Generate nginx configuration."""
        csp = self.generate_csp(mode='report-only')
        
        return f"""# Content-Security-Policy (Report Only - Test First)
add_header Content-Security-Policy-Report-Only "{csp['csp']}" always;

# After testing, uncomment below and comment above to enforce:
# add_header Content-Security-Policy "{csp['csp']}" always;
"""

    def generate_nodejs(self):
        """Generate Node.js/Express middleware."""
        csp = self.generate_csp(mode='report-only')
        
        return f"""// Content-Security-Policy Middleware
// Add this to your Express app

const cspMiddleware = (req, res, next) => {{
    // Report Only mode (test first)
    res.setHeader('Content-Security-Policy-Report-Only', `{csp['csp']}`);
    
    // After testing, use enforce mode:
    // res.setHeader('Content-Security-Policy', `{csp['csp']}`);
    
    next();
}};

module.exports = cspMiddleware;
"""

    def generate_python(self):
        """Generate Python/Flask middleware."""
        csp = self.generate_csp(mode='report-only')
        
        return f"""# Content-Security-Policy Middleware
# Add this to your Flask app

def add_csp_header(response):
    # Report Only mode (test first)
    response.headers['Content-Security-Policy-Report-Only'] = '{csp["csp"]}'
    
    # After testing, use enforce mode:
    # response.headers['Content-Security-Policy'] = '{csp["csp"]}'
    
    return response

# In your Flask app:
# app.after_request(add_csp_header)
"""

    def generate_wordpress(self):
        """Generate WordPress functions.php code."""
        csp = self.generate_csp(mode='report-only')
        
        return f"""<?php
// Content-Security-Policy Header
// Add this to your theme's functions.php

function add_csp_header() {{
    // Report Only mode (test first)
    header("Content-Security-Policy-Report-Only: {csp['csp']}");
    
    // After testing, use enforce mode:
    // header("Content-Security-Policy: {csp['csp']}");
}}
add_action('send_headers', 'add_csp_header');
?>


# Nginx Server Config
# Add to your server block or location block:

add_header Content-Security-Policy-Report-Only "{csp['csp']}" always;

# After testing, enforce:
# add_header Content-Security-Policy "{csp['csp']}" always;
"""


def generate_csp_report(scan_dir, target_url, output_dir="data"):
    """
    Generate CSP report for a website.
    
    Args:
        scan_dir: Directory containing downloaded files
        target_url: Target website URL
        output_dir: Output directory
        
    Returns:
        dict: Generated CSP configurations
    """
    generator = CSPGenerator(scan_dir, target_url)
    
    # Generate all formats
    csp = generator.generate_csp(mode='report-only')
    htaccess = generator.generate_htaccess()
    nginx = generator.generate_nginx()
    nodejs = generator.generate_nodejs()
    python = generator.generate_python()
    wordpress = generator.generate_wordpress()
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Save files
    files = {
        'csp-header.txt': csp['csp'],
        '.htaccess.example': htaccess,
        'nginx.conf.example': nginx,
        'nodejs-middleware.js': nodejs,
        'flask-middleware.py': python,
        'wordpress-functions.php': wordpress,
    }
    
    saved_files = []
    for filename, content in files.items():
        filepath = output_path / filename
        filepath.write_text(content, encoding='utf-8')
        saved_files.append(str(filepath))
    
    return {
        'csp': csp,
        'files': saved_files,
        'output_dir': str(output_path),
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python csp_generator.py <scan_dir> <target_url>")
        print("Example: python csp_generator.py data/example_com https://example.com")
        sys.exit(1)
    
    scan_dir = sys.argv[1]
    target_url = sys.argv[2]
    
    result = generate_csp_report(scan_dir, target_url)
    
    print("\n" + "=" * 60)
    print("CSP GENERATION COMPLETE")
    print("=" * 60)
    print(f"\nTarget: {target_url}")
    print(f"Files analyzed from: {scan_dir}")
    print(f"\nGenerated CSP:")
    print(f"  {result['csp']['csp']}")
    print(f"\nFiles saved to: {result['output_dir']}")
    for f in result['files']:
        print(f"  - {f}")
    print("\n" + "=" * 60)