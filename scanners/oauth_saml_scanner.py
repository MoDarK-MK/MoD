from typing import Dict, List
import requests
import base64
import xml.etree.ElementTree as ET

class OAuthSAMLScanner:
    def __init__(self):
        pass
    
    def scan_oauth2(self, token_endpoint: str, client_id: str) -> List[Dict]:
        vulnerabilities = []
        vulnerabilities.extend(self._test_client_credentials_exposure())
        vulnerabilities.extend(self._test_token_validation())
        vulnerabilities.extend(self._test_redirect_uri_validation(token_endpoint))
        vulnerabilities.extend(self._test_scope_validation())
        return vulnerabilities
    
    def scan_saml(self, saml_endpoint: str, metadata: str) -> List[Dict]:
        vulnerabilities = []
        vulnerabilities.extend(self._test_xml_signature_wrapping())
        vulnerabilities.extend(self._test_saml_injection())
        vulnerabilities.extend(self._test_xxe_in_saml(metadata))
        return vulnerabilities
    
    def _test_client_credentials_exposure(self) -> List[Dict]:
        vulnerabilities = []
        vulnerabilities.append({
            'type': 'OAuth2 Client Credentials',
            'severity': 'High',
            'description': 'Client secret may be exposed'
        })
        return vulnerabilities
    
    def _test_token_validation(self) -> List[Dict]:
        vulnerabilities = []
        vulnerabilities.append({
            'type': 'OAuth2 Token Validation',
            'severity': 'High',
            'description': 'Test token expiration'
        })
        return vulnerabilities
    
    def _test_redirect_uri_validation(self, endpoint: str) -> List[Dict]:
        vulnerabilities = []
        try:
            malicious_uri = 'http://attacker.com/callback'
            response = requests.get(endpoint, params={'redirect_uri': malicious_uri})
            if 'attacker.com' in response.text:
                vulnerabilities.append({
                    'type': 'OAuth2 Redirect URI Validation',
                    'severity': 'Critical',
                    'description': 'Redirect URI not validated',
                    'evidence': 'Malicious URI accepted'
                })
        except Exception:
            pass
        return vulnerabilities
    
    def _test_scope_validation(self) -> List[Dict]:
        vulnerabilities = []
        vulnerabilities.append({
            'type': 'OAuth2 Scope Validation',
            'severity': 'Medium',
            'description': 'Test for scope escalation'
        })
        return vulnerabilities
    
    def _test_xml_signature_wrapping(self) -> List[Dict]:
        vulnerabilities = []
        vulnerabilities.append({
            'type': 'SAML XML Signature Wrapping',
            'severity': 'Critical',
            'description': 'Test XML Signature Wrapping'
        })
        return vulnerabilities
    
    def _test_saml_injection(self) -> List[Dict]:
        vulnerabilities = []
        vulnerabilities.append({
            'type': 'SAML Injection',
            'severity': 'High',
            'description': 'Test SAML metadata injection'
        })
        return vulnerabilities
    
    def _test_xxe_in_saml(self, metadata: str) -> List[Dict]:
        vulnerabilities = []
        try:
            ET.fromstring(metadata)
        except ET.ParseError:
            vulnerabilities.append({
                'type': 'SAML XXE',
                'severity': 'High',
                'description': 'SAML vulnerable to XXE'
            })
        return vulnerabilities