from typing import Dict, List
from core.request_handler import RequestHandler
from core.vulnerability_detector import VulnerabilityDetector

class XSSScanner:
    def __init__(self):
        self.request_handler = RequestHandler()
        self.vulnerability_detector = VulnerabilityDetector()
    
    def scan(self, url: str, parameters: Dict = None) -> List[Dict]:
        vulnerabilities = []
        if not parameters:
            parameters = {'search': 'test', 'q': 'test', 'input': 'test'}
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>",
            "<select autofocus onfocus=alert('XSS')>",
            "<textarea autofocus onfocus=alert('XSS')>",
            "<marquee onstart=alert('XSS')>"
        ]
        for param_name in parameters.keys():
            for payload in payloads:
                test_params = parameters.copy()
                test_params[param_name] = payload
                response = self.request_handler.send_request(
                    url,
                    method='GET' if '?' in url else 'POST',
                    data=test_params
                )
                is_vulnerable, details = self.vulnerability_detector.detect(
                    response,
                    'XSS',
                    payload
                )
                if is_vulnerable:
                    vulnerabilities.append({
                        'type': 'XSS',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        **details
                    })
        return vulnerabilities