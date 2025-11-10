from typing import Dict, List
import requests
import json

class APIScanner:
    def __init__(self):
        pass
    
    def scan(self, url: str) -> List[Dict]:
        vulnerabilities = []
        vulnerabilities.extend(self._test_broken_auth(url))
        vulnerabilities.extend(self._test_excessive_data_exposure(url))
        vulnerabilities.extend(self._test_lack_of_rate_limiting(url))
        vulnerabilities.extend(self._test_security_misconfiguration(url))
        vulnerabilities.extend(self._test_injection(url))
        return vulnerabilities
    
    def _test_broken_auth(self, url: str) -> List[Dict]:
        vulnerabilities = []
        auth_tests = [
            {'Authorization': 'Bearer invalid_token'},
            {'Authorization': 'Bearer '},
            {'Authorization': ''},
            {},
        ]
        for headers in auth_tests:
            try:
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'API Broken Authentication',
                        'url': url,
                        'severity': 'Critical',
                        'description': 'API accepts invalid or missing authentication',
                        'evidence': 'Server accepted invalid credentials'
                    })
                    break
            except Exception:
                pass
        return vulnerabilities
    
    def _test_excessive_data_exposure(self, url: str) -> List[Dict]:
        vulnerabilities = []
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                content = response.text
                sensitive_patterns = [
                    'password', 'secret', 'api_key', 'apikey', 'token',
                    'credit_card', 'ssn', 'social_security'
                ]
                for pattern in sensitive_patterns:
                    if pattern in content.lower():
                        vulnerabilities.append({
                            'type': 'API Excessive Data Exposure',
                            'url': url,
                            'severity': 'High',
                            'description': f'API exposes sensitive data: {pattern}',
                            'evidence': f'Pattern "{pattern}" found in response'
                        })
        except Exception:
            pass
        return vulnerabilities
    
    def _test_lack_of_rate_limiting(self, url: str) -> List[Dict]:
        vulnerabilities = []
        try:
            rapid_requests = 20
            success_count = 0
            for i in range(rapid_requests):
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    success_count += 1
            if success_count == rapid_requests:
                vulnerabilities.append({
                    'type': 'API Lack of Rate Limiting',
                    'url': url,
                    'severity': 'Medium',
                    'description': f'All {rapid_requests} rapid requests succeeded',
                    'evidence': 'No rate limiting detected'
                })
        except Exception:
            pass
        return vulnerabilities
    
    def _test_security_misconfiguration(self, url: str) -> List[Dict]:
        vulnerabilities = []
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            missing_headers = []
            if not headers.get('X-Content-Type-Options'):
                missing_headers.append('X-Content-Type-Options')
            if not headers.get('X-Frame-Options'):
                missing_headers.append('X-Frame-Options')
            if not headers.get('Strict-Transport-Security'):
                missing_headers.append('Strict-Transport-Security')
            if not headers.get('Content-Security-Policy'):
                missing_headers.append('Content-Security-Policy')
            if missing_headers:
                vulnerabilities.append({
                    'type': 'API Security Misconfiguration',
                    'url': url,
                    'severity': 'Medium',
                    'description': 'API missing security headers',
                    'evidence': f'Missing: {", ".join(missing_headers)}'
                })
        except Exception:
            pass
        return vulnerabilities
    
    def _test_injection(self, url: str) -> List[Dict]:
        vulnerabilities = []
        injection_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "'; DROP TABLE users--",
        ]
        for payload in injection_payloads:
            try:
                test_url = f"{url}?param={payload}"
                response = requests.get(test_url, timeout=10)
                if payload in response.text or 'error' in response.text.lower():
                    vulnerabilities.append({
                        'type': 'API Injection',
                        'url': test_url,
                        'severity': 'High',
                        'description': 'API vulnerable to injection',
                        'evidence': f'Payload: {payload}'
                    })
                    break
            except Exception:
                pass
        return vulnerabilities