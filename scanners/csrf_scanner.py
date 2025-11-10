from typing import Dict, List
from core.request_handler import RequestHandler

class CSRFScanner:
    def __init__(self):
        self.request_handler = RequestHandler()
    
    def scan(self, url: str) -> List[Dict]:
        vulnerabilities = []
        response = self.request_handler.send_request(url)
        content = response.get('content', '').lower()
        headers = response.get('headers', {})
        has_csrf_token = 'csrf' in content or 'token' in content
        has_samesite = any('samesite' in str(v).lower() for v in headers.values())
        if not has_csrf_token and not has_samesite:
            vulnerabilities.append({
                'type': 'CSRF',
                'url': url,
                'severity': 'Medium',
                'description': 'Potential CSRF vulnerability',
                'evidence': 'No CSRF token or SameSite cookie protection found'
            })
        return vulnerabilities