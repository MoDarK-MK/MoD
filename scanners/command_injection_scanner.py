from typing import Dict, List
import time
from core.request_handler import RequestHandler

class CommandInjectionScanner:
    def __init__(self):
        self.request_handler = RequestHandler()
    
    def scan(self, url: str, parameters: Dict = None) -> List[Dict]:
        vulnerabilities = []
        if not parameters:
            parameters = {'input': '', 'data': ''}
        payloads = [
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "`sleep 5`",
            "$(sleep 5)"
        ]
        for param_name in parameters.keys():
            for payload in payloads:
                test_params = parameters.copy()
                test_params[param_name] = payload
                response = self.request_handler.send_request(url, data=test_params)
                if response.get('response_time', 0) > 4:
                    vulnerabilities.append({
                        'type': 'Command Injection',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'severity': 'Critical',
                        'description': f'Time-based command injection detected',
                        'evidence': f'Response delayed by {response.get("response_time")} seconds'
                    })
        return vulnerabilities