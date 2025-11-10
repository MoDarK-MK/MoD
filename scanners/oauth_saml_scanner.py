from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import base64
import json
import xml.etree.ElementTree as ET


class OAuthVulnerabilityType(Enum):
    OPEN_REDIRECT = "open_redirect"
    MISSING_STATE = "missing_state"
    WEAK_STATE = "weak_state"
    AUTHORIZATION_CODE_LEAK = "authorization_code_leak"
    IMPLICIT_FLOW = "implicit_flow"
    MISSING_PKCE = "missing_pkce"
    WEAK_PKCE = "weak_pkce"
    TOKEN_REUSE = "token_reuse"
    BROAD_SCOPE = "broad_scope"
    INSECURE_REDIRECT_URI = "insecure_redirect_uri"


class SAMLVulnerabilityType(Enum):
    XML_SIGNATURE_BYPASS = "xml_signature_bypass"
    XXE_INJECTION = "xxe_injection"
    XPATH_INJECTION = "xpath_injection"
    ASSERTION_REPLAY = "assertion_replay"
    MISSING_SIGNATURE = "missing_signature"
    WEAK_SIGNATURE = "weak_signature"
    UNSIGNED_ATTRIBUTES = "unsigned_attributes"
    METADATA_EXPOSURE = "metadata_exposure"
    UNENCRYPTED_ASSERTION = "unencrypted_assertion"
    RESPONSE_WRAPPING = "response_wrapping"


class TokenType(Enum):
    ACCESS_TOKEN = "access_token"
    ID_TOKEN = "id_token"
    REFRESH_TOKEN = "refresh_token"
    BEARER_TOKEN = "bearer_token"
    SAML_ASSERTION = "saml_assertion"


@dataclass
class OAuthVulnerability:
    vulnerability_type: str
    oauth_type: OAuthVulnerabilityType
    url: str
    severity: str
    evidence: str
    parameter_name: Optional[str] = None
    redirect_uri: Optional[str] = None
    scope: Optional[str] = None
    state_value: Optional[str] = None
    token_value: Optional[str] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class SAMLVulnerability:
    vulnerability_type: str
    saml_type: SAMLVulnerabilityType
    url: str
    severity: str
    evidence: str
    assertion_id: Optional[str] = None
    issuer: Optional[str] = None
    signature_status: Optional[str] = None
    encryption_status: Optional[str] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class OAuthFlowAnalyzer:
    OAUTH_PARAMETER_PATTERNS = {
        'client_id': r'(?:client_id|client-id|clientid)\s*[:=]\s*([a-zA-Z0-9._-]+)',
        'redirect_uri': r'(?:redirect_uri|redirect-uri|redirecturi)\s*[:=]\s*([^\s&\'\"]+)',
        'response_type': r'(?:response_type|response-type|responsetype)\s*[:=]\s*(code|token|id_token)',
        'scope': r'(?:scope)\s*[:=]\s*([a-zA-Z0-9\s_-]+)',
        'state': r'(?:state)\s*[:=]\s*([a-zA-Z0-9._-]+)',
        'code': r'(?:code)\s*[:=]\s*([a-zA-Z0-9._-]+)',
        'access_token': r'(?:access_token|accesstoken)\s*[:=]\s*([a-zA-Z0-9._-]+)',
        'token': r'(?:token)\s*[:=]\s*([a-zA-Z0-9._-]+)',
    }
    
    @staticmethod
    def extract_oauth_parameters(url: str, response_content: str) -> Dict[str, List[str]]:
        parameters = defaultdict(list)
        
        combined_content = f"{url}\n{response_content}"
        
        for param_name, pattern in OAuthFlowAnalyzer.OAUTH_PARAMETER_PATTERNS.items():
            matches = re.findall(pattern, combined_content, re.IGNORECASE)
            if matches:
                parameters[param_name].extend(matches)
        
        return dict(parameters)
    
    @staticmethod
    def detect_implicit_flow(response_content: str) -> Tuple[bool, Optional[str]]:
        implicit_patterns = [
            r'response_type\s*[:=]\s*token',
            r'response_type\s*[:=]\s*id_token',
            r'#access_token',
            r'#id_token',
        ]
        
        for pattern in implicit_patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return True, pattern
        
        return False, None
    
    @staticmethod
    def detect_missing_state(response_content: str) -> bool:
        state_pattern = r'state\s*[:=]'
        return not bool(re.search(state_pattern, response_content, re.IGNORECASE))
    
    @staticmethod
    def analyze_state_parameter(state_value: str) -> Tuple[bool, List[str]]:
        weaknesses = []
        
        if len(state_value) < 20:
            weaknesses.append('State parameter too short')
        
        if not any(c.isupper() for c in state_value):
            weaknesses.append('State lacks uppercase characters')
        
        if not any(c.isdigit() for c in state_value):
            weaknesses.append('State lacks numeric characters')
        
        if state_value.isalpha():
            weaknesses.append('State contains only alphabetic characters')
        
        sequential_chars = sum(1 for i in range(len(state_value)-1) 
                              if ord(state_value[i+1]) - ord(state_value[i]) == 1)
        if sequential_chars > len(state_value) * 0.3:
            weaknesses.append('State contains sequential characters')
        
        return len(weaknesses) > 0, weaknesses
    
    @staticmethod
    def detect_open_redirect(redirect_uri: str) -> Tuple[bool, Optional[str]]:
        if not redirect_uri:
            return False, None
        
        if 'http://' in redirect_uri and not redirect_uri.startswith('http://localhost'):
            return True, f"Insecure redirect URI: {redirect_uri}"
        
        if redirect_uri.startswith('http://'):
            return True, f"HTTP redirect URI (not HTTPS): {redirect_uri}"
        
        if re.search(r'redirect.*=[^&]*[?&]', redirect_uri):
            return True, "Open redirect via parameter"
        
        return False, None
    
    @staticmethod
    def analyze_scope_permissions(scope: str) -> Tuple[bool, List[str]]:
        dangerous_scopes = [
            'openid', 'profile', 'email', 'address', 'phone',
            'user.read', 'user.write', 'admin', 'root',
        ]
        
        dangerous_found = []
        
        for dangerous in dangerous_scopes:
            if dangerous in scope.lower():
                dangerous_found.append(dangerous)
        
        return len(dangerous_found) > 0, dangerous_found


class SAMLResponseParser:
    @staticmethod
    def parse_saml_response(saml_response: str) -> Optional[ET.Element]:
        try:
            decoded = base64.b64decode(saml_response)
            root = ET.fromstring(decoded)
            return root
        except Exception:
            try:
                root = ET.fromstring(saml_response)
                return root
            except Exception:
                return None
    
    @staticmethod
    def extract_saml_assertions(saml_root: Optional[ET.Element]) -> List[Dict]:
        if not saml_root:
            return []
        
        assertions = []
        
        namespaces = {
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        }
        
        for assertion in saml_root.findall('.//saml:Assertion', namespaces):
            assertion_data = {
                'id': assertion.get('ID'),
                'version': assertion.get('Version'),
                'issue_instant': assertion.get('IssueInstant'),
            }
            
            subject = assertion.find('saml:Subject', namespaces)
            if subject is not None:
                name_id = subject.find('saml:NameID', namespaces)
                if name_id is not None:
                    assertion_data['subject'] = name_id.text
            
            conditions = assertion.find('saml:Conditions', namespaces)
            if conditions is not None:
                assertion_data['not_before'] = conditions.get('NotBefore')
                assertion_data['not_on_or_after'] = conditions.get('NotOnOrAfter')
            
            assertions.append(assertion_data)
        
        return assertions
    
    @staticmethod
    def check_xml_signature(saml_root: Optional[ET.Element]) -> Tuple[bool, Optional[str]]:
        if not saml_root:
            return False, None
        
        namespaces = {
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        }
        
        signature = saml_root.find('.//ds:Signature', namespaces)
        
        if signature is None:
            return False, "No XML signature found"
        
        digest_value = signature.find('.//ds:DigestValue', namespaces)
        if digest_value is not None and digest_value.text:
            return True, digest_value.text
        
        return True, "Signature present"
    
    @staticmethod
    def check_encryption(saml_root: Optional[ET.Element]) -> Tuple[bool, Optional[str]]:
        if not saml_root:
            return False, None
        
        namespaces = {
            'xenc': 'http://www.w3.org/2001/04/xmlenc#',
        }
        
        encrypted = saml_root.find('.//xenc:EncryptedData', namespaces)
        
        if encrypted is not None:
            encryption_method = encrypted.find('xenc:EncryptionMethod', namespaces)
            if encryption_method is not None:
                return True, encryption_method.get('Algorithm')
            return True, "Encrypted"
        
        return False, "Not encrypted"
    
    @staticmethod
    def extract_attribute_statements(saml_root: Optional[ET.Element]) -> Dict[str, List[str]]:
        if not saml_root:
            return {}
        
        attributes = {}
        
        namespaces = {
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        }
        
        for attribute in saml_root.findall('.//saml:Attribute', namespaces):
            attr_name = attribute.get('Name')
            if attr_name:
                values = []
                for value_elem in attribute.findall('saml:AttributeValue', namespaces):
                    if value_elem.text:
                        values.append(value_elem.text)
                if values:
                    attributes[attr_name] = values
        
        return attributes


class OAuthTokenAnalyzer:
    @staticmethod
    def decode_jwt(token: str) -> Optional[Dict]:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            
            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception:
            return None
    
    @staticmethod
    def analyze_jwt_claims(token: str) -> Tuple[bool, List[str]]:
        claims = OAuthTokenAnalyzer.decode_jwt(token)
        
        if not claims:
            return False, []
        
        issues = []
        
        if 'exp' not in claims:
            issues.append('Missing expiration claim')
        
        if 'iat' not in claims:
            issues.append('Missing issued-at claim')
        
        if 'aud' not in claims:
            issues.append('Missing audience claim')
        
        if claims.get('alg') == 'none':
            issues.append('Algorithm set to none')
        
        return len(issues) > 0, issues


class OAuthSAMLScanner:
    def __init__(self):
        self.oauth_analyzer = OAuthFlowAnalyzer()
        self.saml_parser = SAMLResponseParser()
        self.token_analyzer = OAuthTokenAnalyzer()
        
        self.oauth_vulnerabilities: List[OAuthVulnerability] = []
        self.saml_vulnerabilities: List[SAMLVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.lock = threading.Lock()
    
    def scan_oauth(self, target_url: str, response: Dict) -> List[OAuthVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        
        oauth_params = self.oauth_analyzer.extract_oauth_parameters(target_url, response_content)
        
        is_implicit, pattern = self.oauth_analyzer.detect_implicit_flow(response_content)
        if is_implicit:
            vuln = OAuthVulnerability(
                vulnerability_type='OAuth Vulnerability',
                oauth_type=OAuthVulnerabilityType.IMPLICIT_FLOW,
                url=target_url,
                severity='High',
                evidence=f'Implicit flow detected via pattern: {pattern}',
                confirmed=True,
                confidence_score=0.9,
                remediation=self._get_oauth_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['implicit_flow'] += 1
        
        if self.oauth_analyzer.detect_missing_state(response_content):
            vuln = OAuthVulnerability(
                vulnerability_type='OAuth Vulnerability',
                oauth_type=OAuthVulnerabilityType.MISSING_STATE,
                url=target_url,
                severity='High',
                evidence='State parameter missing from OAuth flow',
                confirmed=True,
                confidence_score=0.95,
                remediation=self._get_oauth_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['missing_state'] += 1
        
        if 'state' in oauth_params:
            for state_value in oauth_params['state']:
                is_weak, weaknesses = self.oauth_analyzer.analyze_state_parameter(state_value)
                if is_weak:
                    vuln = OAuthVulnerability(
                        vulnerability_type='OAuth Vulnerability',
                        oauth_type=OAuthVulnerabilityType.WEAK_STATE,
                        url=target_url,
                        severity='Medium',
                        evidence=f'Weak state parameter: {"; ".join(weaknesses)}',
                        state_value=state_value,
                        confirmed=True,
                        confidence_score=0.8,
                        remediation=self._get_oauth_remediation()
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['weak_state'] += 1
        
        if 'redirect_uri' in oauth_params:
            for redirect_uri in oauth_params['redirect_uri']:
                is_insecure, issue = self.oauth_analyzer.detect_open_redirect(redirect_uri)
                if is_insecure:
                    vuln = OAuthVulnerability(
                        vulnerability_type='OAuth Vulnerability',
                        oauth_type=OAuthVulnerabilityType.OPEN_REDIRECT,
                        url=target_url,
                        severity='High',
                        evidence=issue,
                        redirect_uri=redirect_uri,
                        confirmed=True,
                        confidence_score=0.9,
                        remediation=self._get_oauth_remediation()
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['open_redirect'] += 1
        
        if 'scope' in oauth_params:
            for scope in oauth_params['scope']:
                is_dangerous, dangerous_scopes = self.oauth_analyzer.analyze_scope_permissions(scope)
                if is_dangerous:
                    vuln = OAuthVulnerability(
                        vulnerability_type='OAuth Vulnerability',
                        oauth_type=OAuthVulnerabilityType.BROAD_SCOPE,
                        url=target_url,
                        severity='Medium',
                        evidence=f'Broad scope permissions: {", ".join(dangerous_scopes)}',
                        scope=scope,
                        confirmed=True,
                        confidence_score=0.8,
                        remediation=self._get_oauth_remediation()
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['broad_scope'] += 1
        
        if 'access_token' in oauth_params:
            for token in oauth_params['access_token']:
                has_issues, issues = self.token_analyzer.analyze_jwt_claims(token)
                if has_issues:
                    vuln = OAuthVulnerability(
                        vulnerability_type='OAuth Vulnerability',
                        oauth_type=OAuthVulnerabilityType.TOKEN_REUSE,
                        url=target_url,
                        severity='Medium',
                        evidence=f'Token issues: {"; ".join(issues)}',
                        token_value=token[:20],
                        confirmed=True,
                        confidence_score=0.75,
                        remediation=self._get_oauth_remediation()
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['token_issues'] += 1
        
        with self.lock:
            self.oauth_vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def scan_saml(self, target_url: str, response: Dict) -> List[SAMLVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        
        saml_response_match = re.search(r'SAMLResponse=([a-zA-Z0-9/+=]+)', response_content)
        if not saml_response_match:
            saml_response_match = re.search(r'saml:Response.*?>(.*?)</samlp:Response', response_content, re.DOTALL)
        
        if not saml_response_match:
            return vulnerabilities
        
        saml_data = saml_response_match.group(1)
        saml_root = self.saml_parser.parse_saml_response(saml_data)
        
        if not saml_root:
            return vulnerabilities
        
        has_signature, signature_info = self.saml_parser.check_xml_signature(saml_root)
        if not has_signature:
            vuln = SAMLVulnerability(
                vulnerability_type='SAML Vulnerability',
                saml_type=SAMLVulnerabilityType.MISSING_SIGNATURE,
                url=target_url,
                severity='Critical',
                evidence='SAML response not digitally signed',
                signature_status='Missing',
                confirmed=True,
                confidence_score=0.95,
                remediation=self._get_saml_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['missing_signature'] += 1
        
        is_encrypted, encryption_method = self.saml_parser.check_encryption(saml_root)
        if not is_encrypted:
            vuln = SAMLVulnerability(
                vulnerability_type='SAML Vulnerability',
                saml_type=SAMLVulnerabilityType.UNENCRYPTED_ASSERTION,
                url=target_url,
                severity='High',
                evidence='SAML assertion not encrypted',
                encryption_status='Not encrypted',
                confirmed=True,
                confidence_score=0.9,
                remediation=self._get_saml_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['unencrypted'] += 1
        
        assertions = self.saml_parser.extract_saml_assertions(saml_root)
        for assertion in assertions:
            if assertion.get('id'):
                vuln = SAMLVulnerability(
                    vulnerability_type='SAML Vulnerability',
                    saml_type=SAMLVulnerabilityType.ASSERTION_REPLAY,
                    url=target_url,
                    severity='High',
                    evidence=f'Assertion without replay protection: {assertion.get("id")}',
                    assertion_id=assertion.get('id'),
                    confirmed=False,
                    confidence_score=0.7,
                    remediation=self._get_saml_remediation()
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['assertion_replay'] += 1
        
        attributes = self.saml_parser.extract_attribute_statements(saml_root)
        if attributes:
            vuln = SAMLVulnerability(
                vulnerability_type='SAML Vulnerability',
                saml_type=SAMLVulnerabilityType.METADATA_EXPOSURE,
                url=target_url,
                severity='Medium',
                evidence=f'Sensitive attributes exposed: {", ".join(list(attributes.keys())[:5])}',
                confirmed=True,
                confidence_score=0.8,
                remediation=self._get_saml_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['metadata_exposure'] += 1
        
        if 'XXE' in response_content or 'DOCTYPE' in response_content:
            vuln = SAMLVulnerability(
                vulnerability_type='SAML Vulnerability',
                saml_type=SAMLVulnerabilityType.XXE_INJECTION,
                url=target_url,
                severity='Critical',
                evidence='SAML response vulnerable to XXE injection',
                confirmed=False,
                confidence_score=0.7,
                remediation=self._get_saml_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['xxe_injection'] += 1
        
        with self.lock:
            self.saml_vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _get_oauth_remediation(self) -> str:
        return (
            "Use authorization code flow instead of implicit flow. "
            "Implement PKCE for all OAuth flows. "
            "Validate state parameter on all redirects. "
            "Use cryptographically strong state values. "
            "Validate redirect URIs against allowlist. "
            "Use HTTPS for all OAuth endpoints. "
            "Implement short-lived tokens. "
            "Use refresh tokens for long-lived access. "
            "Implement proper token validation. "
            "Monitor OAuth flows for anomalies."
        )
    
    def _get_saml_remediation(self) -> str:
        return (
            "Sign all SAML assertions with valid certificates. "
            "Encrypt SAML assertions. "
            "Validate XML signatures. "
            "Implement replay attack protection. "
            "Validate assertion timestamps. "
            "Disable XXE processing in XML parsers. "
            "Validate SAML response structure. "
            "Use secure SAML bindings. "
            "Implement assertion consumer service validation. "
            "Monitor SAML flows for anomalies."
        )
    
    def get_oauth_vulnerabilities(self) -> List[OAuthVulnerability]:
        with self.lock:
            return self.oauth_vulnerabilities.copy()
    
    def get_saml_vulnerabilities(self) -> List[SAMLVulnerability]:
        with self.lock:
            return self.saml_vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.oauth_vulnerabilities.clear()
            self.saml_vulnerabilities.clear()
            self.scan_statistics.clear()