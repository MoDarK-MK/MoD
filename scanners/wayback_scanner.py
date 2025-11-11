# scanners/wayback_scanner.py
from typing import List, Dict
import requests
from urllib.parse import urlparse
import time


class WaybackScanner:
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session
    
    def fetch_urls(self, domain: str) -> List[Dict]:
        results = []
        
        clean_domain = self._clean_domain(domain)
        
        methods = [
            self._fetch_from_wayback_api,
            self._fetch_from_wayback_cdx,
            self._fetch_from_commoncrawl
        ]
        
        for method in methods:
            try:
                urls = method(clean_domain)
                if urls:
                    results.extend(urls)
                    break
            except Exception:
                continue
        
        return self._deduplicate_urls(results)
    
    def _clean_domain(self, domain: str) -> str:
        if domain.startswith('http://') or domain.startswith('https://'):
            parsed = urlparse(domain)
            return parsed.netloc
        return domain
    
    def _fetch_from_wayback_api(self, domain: str) -> List[Dict]:
        urls = []
        
        api_url = f'http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit=1000'
        
        try:
            response = self.session.get(api_url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data[1:]:
                    if len(entry) >= 3:
                        url_info = {
                            'url': entry[2],
                            'timestamp': entry[1] if len(entry) > 1 else '',
                            'status': entry[4] if len(entry) > 4 else '',
                            'mime_type': entry[3] if len(entry) > 3 else '',
                            'source': 'Wayback Machine'
                        }
                        urls.append(url_info)
        except Exception:
            pass
        
        return urls
    
    def _fetch_from_wayback_cdx(self, domain: str) -> List[Dict]:
        urls = []
        
        cdx_url = f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp,statuscode&collapse=urlkey'
        
        try:
            response = self.session.get(cdx_url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data[1:]:
                    if len(entry) >= 2:
                        url_info = {
                            'url': entry[0],
                            'timestamp': entry[1] if len(entry) > 1 else '',
                            'status': entry[2] if len(entry) > 2 else '',
                            'mime_type': '',
                            'source': 'Wayback CDX'
                        }
                        urls.append(url_info)
        except Exception:
            pass
        
        return urls
    
    def _fetch_from_commoncrawl(self, domain: str) -> List[Dict]:
        urls = []
        
        cc_url = f'http://index.commoncrawl.org/CC-MAIN-2024-10-index?url={domain}/*&output=json'
        
        try:
            response = self.session.get(cc_url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                
                for line in lines:
                    try:
                        data = eval(line)
                        url_info = {
                            'url': data.get('url', ''),
                            'timestamp': data.get('timestamp', ''),
                            'status': data.get('status', ''),
                            'mime_type': data.get('mime', ''),
                            'source': 'CommonCrawl'
                        }
                        urls.append(url_info)
                    except:
                        continue
        except Exception:
            pass
        
        return urls
    
    def _deduplicate_urls(self, urls: List[Dict]) -> List[Dict]:
        seen = set()
        unique_urls = []
        
        for url_info in urls:
            url = url_info['url']
            if url not in seen:
                seen.add(url)
                unique_urls.append(url_info)
        
        return unique_urls
    
    def get_statistics(self, urls: List[Dict]) -> Dict:
        if not urls:
            return {
                'total': 0,
                'by_status': {},
                'by_extension': {},
                'by_source': {}
            }
        
        stats = {
            'total': len(urls),
            'by_status': {},
            'by_extension': {},
            'by_source': {}
        }
        
        for url_info in urls:
            status = url_info.get('status', 'unknown')
            stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
            
            url = url_info.get('url', '')
            if '.' in url:
                ext = url.split('.')[-1].split('?')[0].split('#')[0]
                if len(ext) <= 5:
                    stats['by_extension'][ext] = stats['by_extension'].get(ext, 0) + 1
            
            source = url_info.get('source', 'unknown')
            stats['by_source'][source] = stats['by_source'].get(source, 0) + 1
        
        return stats
