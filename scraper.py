"""
Website Scraper Module
Downloads HTML, CSS, JS, images, and other files from a target website.
"""

import os
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse, unquote
from collections import deque

import requests
from bs4 import BeautifulSoup


class WebsiteScraper:
    """Downloads and archives a complete website locally."""

    # File extensions to download
    DOWNLOAD_EXTENSIONS = {
        # Web files
        '.html', '.htm', '.css', '.js', '.json', '.xml', '.txt',
        # Images
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # Fonts
        '.woff', '.woff2', '.ttf', '.otf', '.eot',
        # Media
        '.mp3', '.mp4', '.wav', '.avi',
        # Archives
        '.zip', '.tar', '.gz',
        # Other
        '.map', '.webmanifest',
    }

    def __init__(self, base_url, output_dir="data", max_depth=3, max_files=500):
        """
        Initialize the scraper.
        
        Args:
            base_url: Target website URL
            output_dir: Directory to save downloaded files
            max_depth: Maximum crawl depth (default: 3)
            max_files: Maximum files to download (default: 500)
        """
        self.base_url = base_url.rstrip('/')
        self.parsed_base = urlparse(self.base_url)
        self.domain = self.parsed_base.netloc
        
        # Create output directory based on domain
        safe_domain = self.domain.replace('.', '_').replace(':', '_')
        self.output_dir = Path(output_dir) / safe_domain
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_depth = max_depth
        self.max_files = max_files
        
        # Tracking
        self.downloaded = set()
        self.visited = set()
        self.files_count = 0
        self.total_size = 0
        self.all_urls = set()
        
        # Session with common headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Statistics
        self.stats = {
            'html': 0,
            'css': 0,
            'js': 0,
            'images': 0,
            'documents': 0,
            'other': 0,
        }

    def _get_file_extension(self, url):
        """Extract file extension from URL."""
        parsed = urlparse(url)
        path = unquote(parsed.path)
        _, ext = os.path.splitext(path)
        return ext.lower()

    def _get_save_path(self, url):
        """Determine local save path for a URL."""
        parsed = urlparse(url)
        path = unquote(parsed.path)
        
        if path.endswith('/') or not path:
            path = path + 'index.html'
        
        # Remove leading slash
        if path.startswith('/'):
            path = path[1:]
        
        return self.output_dir / path

    def _is_same_domain(self, url):
        """Check if URL belongs to the same domain."""
        parsed = urlparse(url)
        return parsed.netloc == '' or parsed.netloc == self.domain

    def _normalize_url(self, url, base_url):
        """Normalize and resolve relative URLs."""
        try:
            return urljoin(base_url, url)
        except Exception:
            return None

    def _is_downloadable(self, url):
        """Check if URL points to a downloadable file."""
        ext = self._get_file_extension(url)
        
        # If no extension, it's likely an HTML page
        if not ext:
            return True
        
        return ext in self.DOWNLOAD_EXTENSIONS

    def _get_category(self, ext):
        """Get file category based on extension."""
        if ext in ('.html', '.htm'):
            return 'html'
        elif ext == '.css':
            return 'css'
        elif ext == '.js':
            return 'js'
        elif ext in ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp'):
            return 'images'
        elif ext in ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'):
            return 'documents'
        else:
            return 'other'

    def _download_file(self, url, depth=0):
        """Download a single file and save it locally."""
        if url in self.downloaded:
            return None
        
        if len(self.downloaded) >= self.max_files:
            return None
        
        try:
            response = self.session.get(url, timeout=15, stream=True, verify=True)
            response.raise_for_status()
            
            # Get save path
            save_path = self._get_save_path(url)
            
            # Create directories
            save_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Get content type
            content_type = response.headers.get('content-type', '')
            
            # Determine if binary or text
            is_binary = any(t in content_type for t in [
                'image/', 'application/pdf', 'application/octet-stream',
                'font/', 'application/x-font'
            ])
            
            # Also check extension
            ext = self._get_file_extension(url)
            if ext in ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', 
                       '.bmp', '.pdf', '.woff', '.woff2', '.ttf', '.otf', '.eot',
                       '.mp3', '.mp4', '.zip'):
                is_binary = True
            
            # Save file
            if is_binary:
                with open(save_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            else:
                # Try to detect encoding
                encoding = response.encoding or 'utf-8'
                content = response.content.decode(encoding, errors='ignore')
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            # Update tracking
            file_size = os.path.getsize(save_path)
            self.downloaded.add(url)
            self.files_count += 1
            self.total_size += file_size
            
            # Update category stats
            category = self._get_category(ext)
            self.stats[category] = self.stats.get(category, 0) + 1
            
            return {
                'url': url,
                'path': str(save_path),
                'size': file_size,
                'category': category,
            }
            
        except requests.exceptions.RequestException as e:
            return None
        except Exception as e:
            return None

    def _extract_links(self, html_content, base_url):
        """Extract all links from HTML content."""
        soup = BeautifulSoup(html_content, 'lxml')
        links = set()
        
        # Extract from common tags
        tags_attrs = [
            ('a', 'href'),
            ('link', 'href'),
            ('script', 'src'),
            ('img', 'src'),
            ('source', 'src'),
            ('video', 'src'),
            ('audio', 'src'),
            ('iframe', 'src'),
            ('object', 'data'),
            ('embed', 'src'),
        ]
        
        for tag, attr in tags_attrs:
            for element in soup.find_all(tag):
                value = element.get(attr)
                if value:
                    normalized = self._normalize_url(value, base_url)
                    if normalized and self._is_same_domain(normalized):
                        links.add(normalized)
        
        # Extract from inline styles
        for element in soup.find_all(style=True):
            style_value = element.get('style', '')
            url_pattern = r'url\([\'"]?([^\'")\s]+)[\'"]?\)'
            for match in re.finditer(url_pattern, style_value):
                normalized = self._normalize_url(match.group(1), base_url)
                if normalized and self._is_same_domain(normalized):
                    links.add(normalized)
        
        return links

    def _extract_css_urls(self, css_content, base_url):
        """Extract URLs from CSS content."""
        urls = set()
        
        # Find url() patterns
        url_pattern = r'url\([\'"]?([^\'")\s]+)[\'"]?\)'
        for match in re.finditer(url_pattern, css_content):
            normalized = self._normalize_url(match.group(1), base_url)
            if normalized and self._is_same_domain(normalized):
                urls.add(normalized)
        
        # Find @import patterns
        import_pattern = r'@import\s+[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(import_pattern, css_content):
            normalized = self._normalize_url(match.group(1), base_url)
            if normalized and self._is_same_domain(normalized):
                urls.add(normalized)
        
        return urls

    def scrape(self):
        """
        Start scraping the website.
        
        Returns:
            dict: Scrape results with statistics
        """
        print(f"\n[DOWNLOAD] Starting website download...")
        print(f"[DOWNLOAD] Target: {self.base_url}")
        print(f"[DOWNLOAD] Output: {self.output_dir}")
        print()
        
        # Queue for BFS crawl: (url, depth)
        queue = deque([(self.base_url, 0)])
        
        while queue and len(self.downloaded) < self.max_files:
            url, depth = queue.popleft()
            
            # Skip if already visited or too deep
            if url in self.visited or depth > self.max_depth:
                continue
            
            self.visited.add(url)
            
            # Download the file
            result = self._download_file(url, depth)
            
            if result:
                ext = self._get_file_extension(url)
                
                # Print download status
                file_size = result['size']
                if file_size > 1024 * 1024:
                    size_str = f"{file_size / (1024*1024):.1f} MB"
                elif file_size > 1024:
                    size_str = f"{file_size / 1024:.1f} KB"
                else:
                    size_str = f"{file_size} B"
                
                print(f"[✓] Downloaded: {urlparse(url).path or '/'} ({size_str})")
                
                # If HTML, extract and queue more links
                if ext in ('.html', '.htm', '') or not ext:
                    try:
                        if result['size'] > 0:
                            with open(result['path'], 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            new_links = self._extract_links(content, url)
                            for link in new_links:
                                if link not in self.visited:
                                    queue.append((link, depth + 1))
                                    self.all_urls.add(link)
                    except Exception:
                        pass
                
                # If CSS, extract URLs
                elif ext == '.css':
                    try:
                        with open(result['path'], 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        new_links = self._extract_css_urls(content, url)
                        for link in new_links:
                            if link not in self.visited:
                                queue.append((link, depth + 1))
                                self.all_urls.add(link)
                    except Exception:
                        pass
        
        print()
        print(f"[DOWNLOAD] Complete!")
        print(f"[DOWNLOAD] Files downloaded: {self.files_count}")
        print(f"[DOWNLOAD] Total size: {self._format_size(self.total_size)}")
        
        return {
            'output_dir': str(self.output_dir),
            'files_count': self.files_count,
            'total_size': self.total_size,
            'stats': self.stats,
            'urls_found': len(self.all_urls),
        }

    def _format_size(self, size_bytes):
        """Format bytes to human readable size."""
        if size_bytes > 1024 * 1024:
            return f"{size_bytes / (1024*1024):.1f} MB"
        elif size_bytes > 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes} B"


def scrape_website(url, output_dir="data", max_depth=3, max_files=500):
    """
    Convenience function to scrape a website.
    
    Args:
        url: Target website URL
        output_dir: Directory to save files
        max_depth: Maximum crawl depth
        max_files: Maximum files to download
        
    Returns:
        dict: Scrape results
    """
    scraper = WebsiteScraper(url, output_dir, max_depth, max_files)
    return scraper.scrape()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scraper.py <url>")
        sys.exit(1)
    
    result = scrape_website(sys.argv[1])
    print(f"\nFiles saved to: {result['output_dir']}")