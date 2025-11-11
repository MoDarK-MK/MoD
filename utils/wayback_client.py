import requests
from typing import List, Dict
from urllib.parse import quote

class WaybackClient:
    def __init__(self):
        self.base_url = "http://web.archive.org/cdx/search/cdx"
        self.session = requests.Session()
    
    def get_urls(self, domain: str, limit: int = 1000) -> List[str]:
        params = {
            'url': f'*.{domain}/*',
            'output': 'json',
            'fl': 'original',
            'collapse': 'urlkey',
            'limit': limit
        }
        try:
            response = self.session.get(self.base_url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data and len(data) > 1:
                    urls = [item[0] for item in data[1:]]
                    return urls
            return []
        except Exception:
            return []
    
    def get_archived_snapshots(self, url: str) -> List[Dict]:
        api_url = f"http://archive.org/wayback/available?url={quote(url)}"
        try:
            response = self.session.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                snapshots = data.get('archived_snapshots', {})
                if snapshots:
                    closest = snapshots.get('closest', {})
                    if closest:
                        return [{
                            'url': closest.get('url', ''),
                            'timestamp': closest.get('timestamp', ''),
                            'status': closest.get('status', ''),
                            'available': closest.get('available', False)
                        }]
            return []
        except Exception:
            return []
    
    def filter_urls_by_extension(self, urls: List[str], extensions: List[str]) -> List[str]:
        filtered = []
        for url in urls:
            for ext in extensions:
                if url.endswith(ext):
                    filtered.append(url)
                    break
        return filtered
    
    def filter_urls_by_keyword(self, urls: List[str], keywords: List[str]) -> List[str]:
        filtered = []
        for url in urls:
            for keyword in keywords:
                if keyword.lower() in url.lower():
                    filtered.append(url)
                    break
        return filtered