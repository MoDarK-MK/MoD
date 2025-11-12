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
import hashlib
import math


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
    MISSING_TOKEN_EXPIRY = "missing_token_expiry"
    JWT_NONE_ALGORITHM = "jwt_none_algorithm"


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
    ELEMENT_WRAPPING = "element_wrapping"
    SIGNATURE_STRIPPING = "signature_stripping"


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
    token_claims: Optional[Dict] = None
    entropy_score: float = 0.0
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
    signature_algorithm: Optional[str] = None
    certificate_info: Optional[Dict] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class OAuthFlowAnalyzer:
    OAUTH_PARAMETER_PATTERNS = {
        'client_id': re.compile(r'(?:client_id|client-id|clientid)\s*[:=]\s*([a-zA-Z0-9._\-]+)', re.I),
        'redirect_uri': re.compile(r'(?:redirect_uri|redirect-uri|redirecturi)\s*[:=]\s*([^\s&\'\"<>]+)', re.I),
        'response_type': re.compile(r'(?:response_type|response-type|responsetype)\s*[:=]\s*(code|token|id_token|id_token\s+token)', re.I),
        'scope': re.compile(r'(?:scope)\s*[:=]\s*([a-zA-Z0-9\s_\-\.]+)', re.I),
        'state': re.compile(r'(?:state)\s*[:=]\s*([a-zA-Z0-9._\-\+/=]+)', re.I),
        'code': re.compile(r'(?:code)\s*[:=]\s*([a-zA-Z0-9._\-\+/=]+)', re.I),
        'access_token': re.compile(r'(?:access_token|accesstoken)\s*[:=]\s*([a-zA-Z0-9._\-\+/=]+)', re.I),
        'id_token': re.compile(r'(?:id_token|idtoken)\s*[:=]\s*([a-zA-Z0-9._\-\+/=]+)', re.I),
        'refresh_token': re.compile(r'(?:refresh_token|refreshtoken)\s*[:=]\s*([a-zA-Z0-9._\-\+/=]+)', re.I),
        'nonce': re.compile(r'(?:nonce)\s*[:=]\s*([a-zA-Z0-9._\-\+/=]+)', re.I),
    }
    
    IMPLICIT_FLOW_PATTERNS = [
        re.compile(r'response_type\s*[:=]\s*(?:token|id_token)', re.I),
        re.compile(r'#(?:access_token|id_token|token)', re.I),
        re.compile(r'fragment.*(?:access_token|id_token|token)', re.I),
    ]
    
    @staticmethod
    def extract_oauth_parameters(url: str, response_content: str) -> Dict[str, List[str]]:
        parameters = defaultdict(list)
        
        combined_content = f"{url}\n{response_content}"
        
        for param_name, pattern in OAuthFlowAnalyzer.OAUTH_PARAMETER_PATTERNS.items():
            matches = pattern.findall(combined_content)
            if matches:
                unique_matches = list(set(matches))
                parameters[param_name].extend(unique_matches)
        
        return dict(parameters)
    
    @staticmethod
    def detect_implicit_flow(response_content: str) -> Tuple[bool, Optional[str]]:
        for pattern in OAuthFlowAnalyzer.IMPLICIT_FLOW_PATTERNS:
            match = pattern.search(response_content)
            if match:
                return True, match.group(0)
        
        return False, None
    
    @staticmethod
    def detect_missing_state(response_content: str) -> bool:
        state_pattern = r'state\s*[:=]'
        return not bool(re.search(state_pattern, response_content, re.I))
    
    @staticmethod
    def detect_missing_pkce(response_content: str) -> Tuple[bool, bool]:
        has_code_challenge = bool(re.search(r'code_challenge', response_content, re.I))
        has_code_verifier = bool(re.search(r'code_verifier', response_content, re.I))
        
        return not has_code_challenge, has_code_challenge
    
    @staticmethod
    def analyze_state_parameter(state_value: str) -> Tuple[bool, List[str], float]:
        weaknesses = []
        entropy_score = OAuthFlowAnalyzer._calculate_entropy(state_value)
        
        if len(state_value) < 20:
            weaknesses.append('State parameter too short (< 20 chars)')
        
        if not any(c.isupper() for c in state_value):
            weaknesses.append('State lacks uppercase characters')
        
        if not any(c.isdigit() for c in state_value):
            weaknesses.append('State lacks numeric characters')
        
        if not any(c in '!@#$%^&*_-+=.' for c in state_value):
            weaknesses.append('State lacks special characters')
        
        if state_value.isalpha():
            weaknesses.append('State contains only alphabetic characters')
        
        sequential_chars = sum(1 for i in range(len(state_value)-1) 
                              if ord(state_value[i+1]) - ord(state_value[i]) == 1)
        if sequential_chars > len(state_value) * 0.3:
            weaknesses.append('State contains sequential characters pattern')
        
        repeated_chars = max([state_value.count(c) for c in set(state_value)]) / len(state_value)
        if repeated_chars > 0.4:
            weaknesses.append('State has excessive character repetition')
        
        return len(weaknesses) > 0, weaknesses, entropy_score
    
    @staticmethod
    def _calculate_entropy(data: str) -> float:
        if not data:
            return 0.0
        
        frequencies = defaultdict(int)
        for char in data:
            frequencies[char] += 1
        
        entropy = 0.0
        total = len(data)
        
        for count in frequencies.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        max_entropy = math.log2(len(set(data))) if set(data) else 1
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
        
        return min(normalized_entropy, 1.0)
    
    @staticmethod
    def detect_open_redirect(redirect_uri: str) -> Tuple[bool, Optional[str]]:
        if not redirect_uri:
            return False, None
        
        if 'http://' in redirect_uri:
            if not redirect_uri.startswith('http://localhost') and not redirect_uri.startswith('http://127.0.0.1'):
                return True, f"Insecure HTTP redirect URI: {redirect_uri}"
        
        if redirect_uri.count('://') > 1:
            return True, f"Multiple protocol scheme detected: {redirect_uri}"
        
        if re.search(r'redirect(?:_uri)?=.*[?&]', redirect_uri):
            return True, "Open redirect via nested parameter"
        
        if re.search(r'javascript:', redirect_uri, re.I):
            return True, f"JavaScript URI detected: {redirect_uri}"
        
        if re.search(r'data:', redirect_uri, re.I):
            return True, f"Data URI detected: {redirect_uri}"
        
        if redirect_uri.endswith('/'):
            pass
        
        return False, None
    
    @staticmethod
    def analyze_scope_permissions(scope: str) -> Tuple[bool, List[str]]:
        dangerous_scopes = [
            'openid', 'profile', 'email', 'address', 'phone',
            'user.read', 'user.write', 'user.manage', 'admin',
            'root', 'write', 'delete', 'calendar', 'contacts',
            'files', 'offline', 'offline_access',
        ]
        
        dangerous_found = []
        scope_items = [s.strip() for s in scope.split()]
        
        for item in scope_items:
            for dangerous in dangerous_scopes:
                if dangerous.lower() in item.lower():
                    dangerous_found.append(item)
                    break
        
        return len(dangerous_found) > 0, list(set(dangerous_found))


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
                'signed': False,
                'encrypted': False,
            }
            
            subject = assertion.find('saml:Subject', namespaces)
            if subject is not None:
                name_id = subject.find('saml:NameID', namespaces)
                if name_id is not None:
                    assertion_data['subject'] = name_id.text
                    assertion_data['format'] = name_id.get('Format')
            
            conditions = assertion.find('saml:Conditions', namespaces)
            if conditions is not None:
                assertion_data['not_before'] = conditions.get('NotBefore')
                assertion_data['not_on_or_after'] = conditions.get('NotOnOrAfter')
                
                one_time_use = conditions.find('saml:OneTimeUse', namespaces)
                if one_time_use is not None:
                    assertion_data['one_time_use'] = True
            
            authn_stmt = assertion.find('saml:AuthnStatement', namespaces)
            if authn_stmt is not None:
                assertion_data['authn_instant'] = authn_stmt.get('AuthnInstant')
                assertion_data['session_index'] = authn_stmt.get('SessionIndex')
            
            assertions.append(assertion_data)
        
        return assertions
    
    @staticmethod
    def check_xml_signature(saml_root: Optional[ET.Element]) -> Tuple[bool, Optional[Dict]]:
        if not saml_root:
            return False, None
        
        namespaces = {
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        }
        
        signature = saml_root.find('.//ds:Signature', namespaces)
        
        if signature is None:
            return False, {'status': 'Missing', 'algorithm': None}
        
        signature_info = {'status': 'Present', 'algorithm': None}
        
        signature_method = signature.find('ds:SignatureMethod', namespaces)
        if signature_method is not None:
            signature_info['algorithm'] = signature_method.get('Algorithm')
        
        digest_method = signature.find('.//ds:DigestMethod', namespaces)
        if digest_method is not None:
            signature_info['digest_algorithm'] = digest_method.get('Algorithm')
        
        key_info = signature.find('ds:KeyInfo', namespaces)
        if key_info is not None:
            x509_data = key_info.find('ds:X509Data', namespaces)
            if x509_data is not None:
                signature_info['has_certificate'] = True
        
        return True, signature_info
    
    @staticmethod
    def check_encryption(saml_root: Optional[ET.Element]) -> Tuple[bool, Optional[Dict]]:
        if not saml_root:
            return False, None
        
        namespaces = {
            'xenc': 'http://www.w3.org/2001/04/xmlenc#',
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        }
        
        encrypted_data = saml_root.find('.//xenc:EncryptedData', namespaces)
        encrypted_key = saml_root.find('.//xenc:EncryptedKey', namespaces)
        
        if encrypted_data is not None or encrypted_key is not None:
            encryption_info = {'status': 'Encrypted', 'algorithms': []}
            
            if encrypted_data is not None:
                encryption_method = encrypted_data.find('xenc:EncryptionMethod', namespaces)
                if encryption_method is not None:
                    encryption_info['algorithms'].append(encryption_method.get('Algorithm'))
            
            if encrypted_key is not None:
                key_encryption_method = encrypted_key.find('xenc:EncryptionMethod', namespaces)
                if key_encryption_method is not None:
                    encryption_info['algorithms'].append(key_encryption_method.get('Algorithm'))
            
            return True, encryption_info
        
        return False, {'status': 'Not Encrypted'}
    
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
    
    @staticmethod
    def detect_xxe_vulnerability(saml_root: Optional[ET.Element]) -> Tuple[bool, List[str]]:
        if not saml_root:
            return False, []
        
        xxe_indicators = []
        xml_str = ET.tostring(saml_root, encoding='unicode')
        
        if '<!DOCTYPE' in xml_str or '<!ENTITY' in xml_str:
            xxe_indicators.append('DOCTYPE or ENTITY declaration found')
        
        if 'SYSTEM' in xml_str or 'PUBLIC' in xml_str:
            xxe_indicators.append('SYSTEM or PUBLIC identifier found')
        
        return len(xxe_indicators) > 0, xxe_indicators
    
    @staticmethod
    def detect_response_wrapping(saml_root: Optional[ET.Element]) -> Tuple[bool, List[str]]:
        if not saml_root:
            return False, []
        
        wrapping_indicators = []
        namespaces = {
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        }
        
        responses = saml_root.findall('.//samlp:Response', namespaces)
        if len(responses) > 1:
            wrapping_indicators.append('Multiple Response elements detected')
        
        assertions = saml_root.findall('.//saml:Assertion', namespaces)
        if len(assertions) > 2:
            wrapping_indicators.append('Multiple assertions detected - possible wrapping attack')
        
        return len(wrapping_indicators) > 0, wrapping_indicators


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
    def decode_jwt_header(token: str) -> Optional[Dict]:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header = parts[0]
            padding = 4 - len(header) % 4
            if padding != 4:
                header += '=' * padding
            
            decoded = base64.urlsafe_b64decode(header)
            return json.loads(decoded)
        except Exception:
            return None
    
    @staticmethod
    def analyze_jwt_claims(token: str) -> Tuple[bool, List[str], Optional[Dict]]:
        claims = OAuthTokenAnalyzer.decode_jwt(token)
        
        if not claims:
            return False, [], None
        
        issues = []
        
        if 'exp' not in claims:
            issues.append('Missing expiration (exp) claim')
        else:
            exp_time = claims.get('exp')
            current_time = time.time()
            if exp_time and exp_time <= current_time:
                issues.append('Token is already expired')
            elif exp_time and (exp_time - current_time) > 86400 * 365:
                issues.append('Token expiration too far in future (> 1 year)')
        
        if 'iat' not in claims:
            issues.append('Missing issued-at (iat) claim')
        
        if 'aud' not in claims:
            issues.append('Missing audience (aud) claim')
        
        if 'iss' not in claims:
            issues.append('Missing issuer (iss) claim')
        
        header = OAuthTokenAnalyzer.decode_jwt_header(token)
        if header:
            if header.get('alg') == 'none':
                issues.append('Algorithm set to none - allows signature bypass')
            elif header.get('alg') == 'HS256' and 'kid' not in header:
                issues.append('HS256 algorithm without key ID - potential algorithm confusion')
        
        return len(issues) > 0, issues, claims
    
    @staticmethod
    def detect_token_reuse(tokens: List[str]) -> Tuple[bool, List[str]]:
        if len(tokens) < 2:
            return False, []
        
        seen_tokens = set()
        duplicates = []
        
        for token in tokens:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if token_hash in seen_tokens:
                duplicates.append(token[:20])
            seen_tokens.add(token_hash)
        
        return len(duplicates) > 0, duplicates


class OAuthSAMLScanner:
    _oauth_remediation_cache = (
        "Use authorization code flow instead of implicit flow. "
        "Implement PKCE (Proof Key for Code Exchange) for all OAuth flows. "
        "Validate state parameter with cryptographically strong values (min 128 bits). "
        "Use HTTPS only for all OAuth endpoints (RFC 6234). "
        "Validate redirect URIs against allowlist - never allow wildcards. "
        "Implement short-lived access tokens (recommended: 5-15 minutes). "
        "Use refresh tokens for long-lived access with rotation. "
        "Implement proper token validation and signature verification. "
        "Use secure cookie flags (Secure, HttpOnly, SameSite). "
        "Monitor OAuth flows for anomalies and suspicious patterns. "
        "Implement rate limiting on token endpoints. "
        "Use strong encryption for stored tokens. "
        "Implement token expiration and cleanup. "
        "Disable token introspection in production if possible."
    )
    
    _saml_remediation_cache = (
        "Sign all SAML assertions with valid X.509 certificates. "
        "Encrypt SAML assertions using strong encryption algorithms (AES-256). "
        "Validate XML signatures with proper certificate validation. "
        "Implement replay attack protection with assertion IDs and timestamps. "
        "Validate assertion NotBefore and NotOnOrAfter conditions. "
        "Disable XXE processing in XML parsers (DTD disabled). "
        "Validate SAML response structure and schema. "
        "Use secure SAML bindings (HTTP-POST over HTTPS). "
        "Implement assertion consumer service (ACS) URL validation. "
        "Monitor SAML flows for anomalies. "
        "Implement one-time use restrictions on assertions. "
        "Use strong signature algorithms (RSA-SHA256 minimum). "
        "Validate issuer and audience claims. "
        "Implement session management and invalidation."
    )
    
    def __init__(self):
        self.oauth_analyzer = OAuthFlowAnalyzer()
        self.saml_parser = SAMLResponseParser()
        self.token_analyzer = OAuthTokenAnalyzer()
        
        self.oauth_vulnerabilities: List[OAuthVulnerability] = []
        self.saml_vulnerabilities: List[SAMLVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.tested_tokens: Set[str] = set()
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
                severity='Critical',
                evidence=f'Implicit flow detected: {pattern}',
                confirmed=True,
                confidence_score=0.95,
                remediation=self._oauth_remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['implicit_flow'] += 1
        
        is_missing_pkce, has_code_challenge = self.oauth_analyzer.detect_missing_pkce(response_content)
        if is_missing_pkce and 'code' in oauth_params:
            vuln = OAuthVulnerability(
                vulnerability_type='OAuth Vulnerability',
                oauth_type=OAuthVulnerabilityType.MISSING_PKCE,
                url=target_url,
                severity='High',
                evidence='PKCE (code_challenge) not implemented with authorization code flow',
                confirmed=True,
                confidence_score=0.9,
                remediation=self._oauth_remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['missing_pkce'] += 1
        
        if self.oauth_analyzer.detect_missing_state(response_content):
            vuln = OAuthVulnerability(
                vulnerability_type='OAuth Vulnerability',
                oauth_type=OAuthVulnerabilityType.MISSING_STATE,
                url=target_url,
                severity='Critical',
                evidence='State parameter missing from OAuth flow - vulnerable to CSRF',
                confirmed=True,
                confidence_score=0.98,
                remediation=self._oauth_remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['missing_state'] += 1
        
        if 'state' in oauth_params:
            for state_value in oauth_params['state']:
                is_weak, weaknesses, entropy = self.oauth_analyzer.analyze_state_parameter(state_value)
                if is_weak:
                    vuln = OAuthVulnerability(
                        vulnerability_type='OAuth Vulnerability',
                        oauth_type=OAuthVulnerabilityType.WEAK_STATE,
                        url=target_url,
                        severity='High',
                        evidence=f'Weak state: {"; ".join(weaknesses)} | Entropy: {entropy:.3f}',
                        state_value=state_value,
                        entropy_score=entropy,
                        confirmed=True,
                        confidence_score=0.85,
                        remediation=self._oauth_remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['weak_state'] += 1
        
        if 'redirect_uri' in oauth_params:
            for redirect_uri in oauth_params['redirect_uri']:
                is_insecure, issue = self.oauth_analyzer.detect_open_redirect(redirect_uri)
                if is_insecure:
                    vuln = OAuthVulnerability(
                        vulnerability_type='OAuth Vulnerability',
                        oauth_type=OAuthVulnerabilityType.OPEN_REDIRECT if 'http://' in redirect_uri else OAuthVulnerabilityType.INSECURE_REDIRECT_URI,
                        url=target_url,
                        severity='High' if 'http://' in redirect_uri else 'Medium',
                        evidence=issue,
                        redirect_uri=redirect_uri,
                        confirmed=True,
                        confidence_score=0.92,
                        remediation=self._oauth_remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['insecure_redirect'] += 1
        
        if 'scope' in oauth_params:
            for scope in oauth_params['scope']:
                is_dangerous, dangerous_scopes = self.oauth_analyzer.analyze_scope_permissions(scope)
                if is_dangerous:
                    vuln = OAuthVulnerability(
                        vulnerability_type='OAuth Vulnerability',
                        oauth_type=OAuthVulnerabilityType.BROAD_SCOPE,
                        url=target_url,
                        severity='High',
                        evidence=f'Broad scope permissions: {", ".join(dangerous_scopes)}',
                        scope=scope,
                        confirmed=True,
                        confidence_score=0.8,
                        remediation=self._oauth_remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['broad_scope'] += 1
        
        for token_type in ['access_token', 'id_token', 'refresh_token']:
            if token_type in oauth_params:
                for token in oauth_params[token_type]:
                    token_hash = hashlib.sha256(token.encode()).hexdigest()
                    
                    if token_hash in self.tested_tokens:
                        continue
                    
                    with self.lock:
                        self.tested_tokens.add(token_hash)
                    
                    has_issues, issues, claims = self.token_analyzer.analyze_jwt_claims(token)
                    
                    if has_issues:
                        severity = 'Critical' if 'none' in str(issues).lower() else 'High'
                        
                        vuln = OAuthVulnerability(
                            vulnerability_type='OAuth Vulnerability',
                            oauth_type=OAuthVulnerabilityType.MISSING_TOKEN_EXPIRY if 'expiration' in str(issues).lower() else OAuthVulnerabilityType.JWT_NONE_ALGORITHM,
                            url=target_url,
                            severity=severity,
                            evidence=f'{token_type} issues: {"; ".join(issues)}',
                            token_value=token[:30],
                            token_claims=claims,
                            confirmed=True,
                            confidence_score=0.88,
                            remediation=self._oauth_remediation_cache
                        )
                        vulnerabilities.append(vuln)
                        self.scan_statistics['token_issues'] += 1
        
        with self.lock:
            self.oauth_vulnerabilities.extend(vulnerabilities)
            self.scan_statistics['oauth_scans'] += 1
        
        return vulnerabilities
    
    def scan_saml(self, target_url: str, response: Dict) -> List[SAMLVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        
        saml_response_match = re.search(r'SAMLResponse=([a-zA-Z0-9/+=]+)', response_content)
        if not saml_response_match:
            saml_response_match = re.search(r'samlp:Response[^>]*>(.*?)</samlp:Response', response_content, re.DOTALL | re.I)
        
        if not saml_response_match:
            return vulnerabilities
        
        saml_data = saml_response_match.group(1)
        saml_root = self.saml_parser.parse_saml_response(saml_data)
        
        if not saml_root:
            return vulnerabilities
        
        has_signature, signature_info = self.saml_parser.check_xml_signature(saml_root)
        if not has_signature or signature_info.get('status') == 'Missing':
            vuln = SAMLVulnerability(
                vulnerability_type='SAML Vulnerability',
                saml_type=SAMLVulnerabilityType.MISSING_SIGNATURE,
                url=target_url,
                severity='Critical',
                evidence='SAML response not digitally signed - allows response injection',
                signature_status='Missing',
                confirmed=True,
                confidence_score=0.98,
                remediation=self._saml_remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['missing_signature'] += 1
        elif signature_info:
            if signature_info.get('algorithm') and 'SHA1' in signature_info.get('algorithm', ''):
                vuln = SAMLVulnerability(
                    vulnerability_type='SAML Vulnerability',
                    saml_type=SAMLVulnerabilityType.WEAK_SIGNATURE,
                    url=target_url,
                    severity='High',
                    evidence=f'Weak signature algorithm: {signature_info.get("algorithm")}',
                    signature_algorithm=signature_info.get('algorithm'),
                    confirmed=True,
                    confidence_score=0.85,
                    remediation=self._saml_remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['weak_signature'] += 1
        
        is_encrypted, encryption_info = self.saml_parser.check_encryption(saml_root)
        if not is_encrypted:
            vuln = SAMLVulnerability(
                vulnerability_type='SAML Vulnerability',
                saml_type=SAMLVulnerabilityType.UNENCRYPTED_ASSERTION,
                url=target_url,
                severity='High',
                evidence='SAML assertion not encrypted - sensitive data exposed in transit',
                encryption_status='Not encrypted',
                confirmed=True,
                confidence_score=0.92,
                remediation=self._saml_remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['unencrypted'] += 1
        
        has_xxe, xxe_indicators = self.saml_parser.detect_xxe_vulnerability(saml_root)
        if has_xxe:
            vuln = SAMLVulnerability(
                vulnerability_type='SAML Vulnerability',
                saml_type=SAMLVulnerabilityType.XXE_INJECTION,
                url=target_url,
                severity='Critical',
                evidence=f'XXE injection indicators: {"; ".join(xxe_indicators)}',
                confirmed=False,
                confidence_score=0.75,
                remediation=self._saml_remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['xxe_injection'] += 1
        
        has_wrapping, wrapping_indicators = self.saml_parser.detect_response_wrapping(saml_root)
        if has_wrapping:
            vuln = SAMLVulnerability(
                vulnerability_type='SAML Vulnerability',
                saml_type=SAMLVulnerabilityType.RESPONSE_WRAPPING,
                url=target_url,
                severity='High',
                evidence=f'Response wrapping indicators: {"; ".join(wrapping_indicators)}',
                confirmed=False,
                confidence_score=0.8,
                remediation=self._saml_remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['response_wrapping'] += 1
        
        assertions = self.saml_parser.extract_saml_assertions(saml_root)
        for assertion in assertions:
            if assertion.get('id'):
                if 'not_on_or_after' not in assertion or 'not_before' not in assertion:
                    vuln = SAMLVulnerability(
                        vulnerability_type='SAML Vulnerability',
                        saml_type=SAMLVulnerabilityType.ASSERTION_REPLAY,
                        url=target_url,
                        severity='High',
                        evidence=f'Assertion {assertion.get("id")} missing lifetime constraints',
                        assertion_id=assertion.get('id'),
                        confirmed=True,
                        confidence_score=0.85,
                        remediation=self._saml_remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['assertion_replay'] += 1
        
        attributes = self.saml_parser.extract_attribute_statements(saml_root)
        if attributes:
            sensitive_attrs = [k for k in attributes.keys() if any(s in k.lower() for s in ['password', 'secret', 'token', 'key', 'ssn'])]
            
            severity = 'High' if sensitive_attrs else 'Medium'
            
            vuln = SAMLVulnerability(
                vulnerability_type='SAML Vulnerability',
                saml_type=SAMLVulnerabilityType.METADATA_EXPOSURE,
                url=target_url,
                severity=severity,
                evidence=f'Attributes exposed: {", ".join(list(attributes.keys())[:10])} (Sensitive: {len(sensitive_attrs)})',
                confirmed=True,
                confidence_score=0.8,
                remediation=self._saml_remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['metadata_exposure'] += 1
        
        with self.lock:
            self.saml_vulnerabilities.extend(vulnerabilities)
            self.scan_statistics['saml_scans'] += 1
        
        return vulnerabilities
    
    def get_oauth_vulnerabilities(self) -> List[OAuthVulnerability]:
        with self.lock:
            return self.oauth_vulnerabilities.copy()
    
    def get_saml_vulnerabilities(self) -> List[SAMLVulnerability]:
        with self.lock:
            return self.saml_vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def get_tested_tokens(self) -> Set[str]:
        with self.lock:
            return self.tested_tokens.copy()
    
    def clear(self):
        with self.lock:
            self.oauth_vulnerabilities.clear()
            self.saml_vulnerabilities.clear()
            self.scan_statistics.clear()
            self.tested_tokens.clear()