"""
JS Finder Integration Example for MoD v4.0.0.5
Shows how to integrate JavaScript Finder with any crawler or scanner
"""

from scanners.js_finder import get_js_finder, JSFinder
from utils.config import Config
import logging

logger = logging.getLogger("MoD.js_finder_integration")


class JSFinderIntegration:
    """Integration helper for JS Finder"""
    
    def __init__(self, config: Config):
        """Initialize JS Finder integration
        
        Args:
            config: Configuration object containing webhook URL
        """
        self.config = config
        self.js_finder: JSFinder = None
        self._initialize()
    
    def _initialize(self):
        """Initialize JS Finder with webhook URL from config"""
        webhook_url = self.config.load().get('integration', {}).get('js_finder_webhook', '')
        self.js_finder = get_js_finder(webhook_url=webhook_url)
        
        if webhook_url:
            logger.info(f"JS Finder initialized with webhook: {webhook_url[:50]}...")
        else:
            logger.warning("JS Finder initialized without webhook URL")
    
    def update_webhook(self, new_webhook_url: str):
        """Update webhook URL dynamically
        
        Args:
            new_webhook_url: New webhook URL
        """
        if self.js_finder:
            self.js_finder.update_webhook(new_webhook_url)
            logger.info(f"JS Finder webhook updated")
    
    def scan_crawler_response(self, url: str, html_content: str, send_webhook: bool = True) -> dict:
        """Scan HTML content from crawler for JavaScript
        
        This should be called from within your crawler after fetching each page.
        
        Args:
            url: The URL that was crawled
            html_content: The HTML response content
            send_webhook: Whether to send results to webhook
            
        Returns:
            Dictionary with scan results
        """
        # Perform scan
        result = self.js_finder.scan_page(url, html_content)
        
        # Send to webhook if enabled
        if send_webhook and self.js_finder.webhook_url:
            self.js_finder.send_to_webhook(result)
        
        return result.to_dict()
    
    def get_summary(self) -> dict:
        """Get summary of all detected JavaScript"""
        return self.js_finder.get_detected_files()


# Example Usage in a Scanner/Crawler:
# ====================================

class ExampleCrawler:
    """Example crawler that uses JS Finder"""
    
    def __init__(self, webhook_url: str = None):
        """Initialize crawler with optional JS Finder"""
        import requests
        self.session = requests.Session()
        self.webhook_url = webhook_url
        self.js_finder = get_js_finder(webhook_url=webhook_url)
    
    def crawl_url(self, url: str, follow_links: bool = False) -> dict:
        """Crawl a URL and analyze JavaScript
        
        Args:
            url: URL to crawl
            follow_links: Whether to follow links
            
        Returns:
            Dictionary with crawl and JS findings
        """
        try:
            # Fetch the page
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            html_content = response.text
            
            # Scan for JavaScript
            js_result = self.js_finder.scan_page(url, html_content)
            
            # Send results to webhook
            if self.js_finder.webhook_url:
                self.js_finder.send_to_webhook(js_result)
            
            return {
                'status': 'success',
                'url': url,
                'status_code': response.status_code,
                'js_findings': js_result.to_dict()
            }
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return {
                'status': 'error',
                'url': url,
                'error': str(e)
            }


# Usage Example:
"""
# In your main scanner/crawler code:

from utils.config import Config
from scanners.js_finder_integration import JSFinderIntegration, ExampleCrawler

# Initialize
config = Config()
config_data = config.load()

# Method 1: Using integration helper
js_integration = JSFinderIntegration(config)

# During crawling:
for url in urls_to_crawl:
    response = fetch(url)
    result = js_integration.scan_crawler_response(url, response.text)
    print(f"Found {result['total_js_files']} JS resources")

# Method 2: Using example crawler directly
webhook_url = config_data.get('integration', {}).get('js_finder_webhook', '')
crawler = ExampleCrawler(webhook_url=webhook_url)

result = crawler.crawl_url(target_url)  # Use actual target URL from user input
print(result)

# Update webhook at runtime
js_integration.update_webhook('https://your-webhook-url.com/...')

# Get summary of all findings
summary = js_integration.get_summary()
print(f"Total JS files detected: {summary['total_detected']}")
"""


if __name__ == '__main__':
    # Test the integration
    from utils.config import Config
    
    logging.basicConfig(level=logging.INFO)
    
    # Load config
    config = Config()
    config_data = config.load()
    
    # Test JS Finder
    webhook_url = config_data.get('integration', {}).get('js_finder_webhook', '')
    
    if not webhook_url:
        print("[WARN] Warning: No webhook URL configured")
        print("Set 'js_finder_webhook' in settings first")
        webhook_url = input("Enter webhook URL (or press Enter to skip): ").strip()
    
    # Example HTML
    test_html = """
    <html>
    <head>
        <script src="/js/jquery.js"></script>
        <script src="https://cdn.example-domain.com/react.min.js"></script>
    </head>
    <body>
        <script>
            const API_KEY = "sk-1234567890abcdef";
            fetch('/api/data')
                .then(r => r.json())
                .then(data => console.log(data));
        </script>
        <button onclick="alert('clicked')">Click Me</button>
    </body>
    </html>
    """
    
    # Test crawling
    crawler = ExampleCrawler(webhook_url=webhook_url)
    print("Testing JS Finder scanner...")
    
    # Use the target URL from user input (example placeholder)
    test_target_url = input("Enter target URL to scan (or press Enter to skip test): ").strip()
    if test_target_url:
        result = crawler.crawl_url(test_target_url)
        
        print("\n[OK] Test Results:")
        print(f"Status: {result['status']}")
        if result['status'] == 'success':
            js_findings = result.get('js_findings', {})
            print(f"Total JS files: {js_findings.get('total_js_files', 0)}")
            print(f"External JS: {js_findings.get('external_js_count', 0)}")
    else:
        print("ℹ️  No target URL provided. Skipping test scan.")
        print(f"Inline JS: {js_findings.get('inline_js_count', 0)}")
        print(f"Frameworks detected: {js_findings.get('frameworks', [])}")
