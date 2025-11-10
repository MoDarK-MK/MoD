from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
from bs4 import BeautifulSoup
import threading
import time
import hashlib


class CSRFVulnerabilityType(Enum):
    NO_TOKEN = "no_token"
    WEAK_TOKEN = "weak_token"
    TOKEN_NOT_VALIDATED = "token_not_validated"
    TOKEN_REUSE = "token_reuse"
    PREDICTABLE_TOKEN = "predictable_token"
    MISSING_SAMESITE = "missing_samesite"
    WEAK_ORIGIN_CHECK = "weak_origin_check"
    METHOD_OVERRIDE = "method_override"


class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class SameSiteValue(Enum):
    STRICT = "Strict"
    LAX = "Lax"
    NONE = "None"
    MISSING = "Missing"


@dataclass
class CSRFToken:
    name: str
    value: str
    form_name: Optional[str] = None
    token_length: int = 0
    is_randomized: bool = False
    entropy_score: float = 0.0
    created_at: float = field(default_factory=time.time)
    last_used: Optional[float] = None
    usage_count: int = 0
    
    def __post_init__(self):
        self.token_length = len(self.value)
        self.entropy_score = self._calculate_entropy()
    
    def _calculate_entropy(self) -> float:
        if not self.value:
            return 0.0
        
        char_freq = defaultdict(int)
        for char in self.value:
            char_freq[char] += 1
        
        entropy = 0.0
        for freq in char_freq.values():
            prob = freq / len(self.value)
            if prob > 0:
                entropy -= prob * (prob ** 0.5)
        
        return min(entropy / len(self.value), 1.0)


@dataclass
class CSRFVulnerability:
    vulnerability_type: str
    csrf_type: CSRFVulnerabilityType
    url: str
    form_name: Optional[str] = None
    form_action: Optional[str] = None
    form_method: str = "POST"
    severity: str = "High"
    evidence: str = ""
    tokens_found: List[CSRFToken] = field(default_factory=list)
    missing_tokens: List[str] = field(default_factory=list)
    samesite_status: str = "Missing"
    origin_check_status: Optional[str] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class FormAnalyzer:
    @staticmethod
    def extract_forms(html_content: str) -> List[Dict]:
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'name': form.get('name', ''),
                    'id': form.get('id', ''),
                    'action': form.get('action', ''),
                    'method': form.get('method', 'POST').upper(),
                    'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                    'inputs': [],
                    'hidden_fields': [],
                    'buttons': [],
                }
                
                for input_tag in form.find_all('input'):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'required': 'required' in input_tag.attrs,
                    }
                    
                    if input_data['type'] == 'hidden':
                        form_data['hidden_fields'].append(input_data)
                    else:
                        form_data['inputs'].append(input_data)
                
                for button in form.find_all('button'):
                    button_data = {
                        'name': button.get('name', ''),
                        'type': button.get('type', 'submit'),
                        'value': button.get('value', ''),
                    }
                    form_data['buttons'].append(button_data)
                
                forms.append(form_data)
            
            return forms
        except:
            return []
    
    @staticmethod
    def find_csrf_tokens(form: Dict) -> List[CSRFToken]:
        csrf_keywords = ['csrf', 'token', 'nonce', 'xsrf', 'authenticity', '_token', '__token']
        tokens = []
        
        for hidden_field in form.get('hidden_fields', []):
            field_name = hidden_field.get('name', '').lower()
            
            if any(keyword in field_name for keyword in csrf_keywords):
                token = CSRFToken(
                    name=hidden_field['name'],
                    value=hidden_field.get('value', ''),
                    form_name=form.get('name')
                )
                tokens.append(token)
        
        return tokens


class CookieAnalyzer:
    @staticmethod
    def analyze_samesite_cookie(cookies: Dict[str, str]) -> Tuple[Optional[SameSiteValue], List[str]]:
        issues = []
        samesite_value = SameSiteValue.MISSING
        
        for cookie_header in cookies.values():
            if isinstance(cookie_header, str):
                if 'SameSite=Strict' in cookie_header:
                    samesite_value = SameSiteValue.STRICT
                elif 'SameSite=Lax' in cookie_header:
                    samesite_value = SameSiteValue.LAX
                elif 'SameSite=None' in cookie_header:
                    samesite_value = SameSiteValue.NONE
                    issues.append('SameSite=None allows cross-site cookie transmission')
                else:
                    samesite_value = SameSiteValue.MISSING
                    issues.append('SameSite attribute missing from cookie')
        
        return samesite_value, issues
    
    @staticmethod
    def analyze_httponly_flag(cookies: Dict[str, str]) -> Tuple[bool, List[str]]:
        issues = []
        has_httponly = False
        
        for cookie_header in cookies.values():
            if isinstance(cookie_header, str):
                if 'HttpOnly' in cookie_header:
                    has_httponly = True
                else:
                    issues.append('HttpOnly flag missing - cookie vulnerable to XSS')
        
        return has_httponly, issues
    
    @staticmethod
    def analyze_secure_flag(cookies: Dict[str, str]) -> Tuple[bool, List[str]]:
        issues = []
        has_secure = False
        
        for cookie_header in cookies.values():
            if isinstance(cookie_header, str):
                if 'Secure' in cookie_header:
                    has_secure = True
                else:
                    issues.append('Secure flag missing - cookie may be transmitted over HTTP')
        
        return has_secure, issues


class TokenRandomnessAnalyzer:
    @staticmethod
    def analyze_token_randomness(tokens: List[CSRFToken]) -> Tuple[bool, float]:
        if len(tokens) < 2:
            return True, 0.8
        
        token_values = [t.value for t in tokens]
        unique_chars = set()
        
        for token in token_values:
            unique_chars.update(token)
        
        uniqueness_ratio = len(unique_chars) / 256
        
        if uniqueness_ratio < 0.3:
            return False, 0.3
        
        avg_entropy = sum(t.entropy_score for t in tokens) / len(tokens)
        
        return avg_entropy > 0.6, avg_entropy
    
    @staticmethod
    def detect_predictable_pattern(tokens: List[str]) -> Tuple[bool, Optional[str]]:
        if len(tokens) < 3:
            return False, None
        
        if all(tokens[0] == t for t in tokens):
            return True, "All tokens are identical"
        
        try:
            token_ints = []
            for token in tokens:
                try:
                    token_ints.append(int(token, 16))
                except ValueError:
                    token_ints.append(int(token))
            
            if len(token_ints) >= 2:
                diffs = [token_ints[i+1] - token_ints[i] for i in range(len(token_ints)-1)]
                if all(d == diffs[0] for d in diffs):
                    return True, f"Sequential pattern detected (increment: {diffs[0]})"
        except:
            pass
        
        return False, None


class OriginRefererAnalyzer:
    @staticmethod
    def analyze_origin_validation(request_headers: Dict, response_headers: Dict) -> Tuple[bool, List[str]]:
        issues = []
        has_origin_check = False
        
        origin = request_headers.get('Origin')
        referer = request_headers.get('Referer')
        
        if not origin and not referer:
            issues.append('Neither Origin nor Referer header present')
        
        accept_origin = response_headers.get('Access-Control-Allow-Origin')
        if accept_origin == '*':
            issues.append('Access-Control-Allow-Origin: * allows any origin')
            has_origin_check = False
        elif accept_origin:
            has_origin_check = True
        else:
            issues.append('No CORS headers configured')
        
        return has_origin_check, issues
    
    @staticmethod
    def detect_weak_origin_check(response_headers: Dict) -> Tuple[bool, List[str]]:
        issues = []
        
        allow_origin = response_headers.get('Access-Control-Allow-Origin', '')
        
        if allow_origin == '*':
            issues.append('Wildcard CORS policy allows any origin')
        
        if allow_origin.endswith('.example.com'):
            issues.append('Overly broad subdomain matching in CORS')
        
        if 'null' in allow_origin.lower():
            issues.append('Null origin accepted - vulnerable to file:// protocol')
        
        return len(issues) > 0, issues


class HTTPMethodOverrideDetector:
    @staticmethod
    def detect_method_override(html_content: str, headers: Dict) -> Tuple[bool, List[str]]:
        issues = []
        
        method_override_headers = ['X-HTTP-Method-Override', 'X-Method-Override', 'X-HTTP-Method']
        
        for header in method_override_headers:
            if header in headers:
                issues.append(f'HTTP Method Override detected via {header}')
        
        if '_method' in html_content or '_REQUEST_METHOD' in html_content:
            issues.append('POST parameter-based method override detected')
        
        return len(issues) > 0, issues


class CSRFScanner:
    def __init__(self):
        self.form_analyzer = FormAnalyzer()
        self.cookie_analyzer = CookieAnalyzer()
        self.token_analyzer = TokenRandomnessAnalyzer()
        self.origin_analyzer = OriginRefererAnalyzer()
        self.method_override_detector = HTTPMethodOverrideDetector()
        
        self.vulnerabilities: List[CSRFVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.collected_tokens: Dict[str, List[CSRFToken]] = {}
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict) -> List[CSRFVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_headers = response.get('headers', {})
        request_headers = response.get('request_headers', {})
        cookies = response.get('cookies', {})
        
        forms = self.form_analyzer.extract_forms(response_content)
        
        samesite_status, samesite_issues = self.cookie_analyzer.analyze_samesite_cookie(cookies)
        httponly_status, httponly_issues = self.cookie_analyzer.analyze_httponly_flag(cookies)
        secure_status, secure_issues = self.cookie_analyzer.analyze_secure_flag(cookies)
        
        method_override_detected, method_override_issues = self.method_override_detector.detect_method_override(
            response_content,
            request_headers
        )
        
        origin_check, origin_issues = self.origin_analyzer.analyze_origin_validation(
            request_headers,
            response_headers
        )
        
        weak_origin, weak_origin_issues = self.origin_analyzer.detect_weak_origin_check(response_headers)
        
        for form in forms:
            if form['method'].upper() in ['POST', 'PUT', 'DELETE', 'PATCH']:
                tokens = self.form_analyzer.find_csrf_tokens(form)
                
                if not tokens:
                    vuln = CSRFVulnerability(
                        vulnerability_type='CSRF',
                        csrf_type=CSRFVulnerabilityType.NO_TOKEN,
                        url=target_url,
                        form_name=form.get('name'),
                        form_action=form.get('action'),
                        form_method=form.get('method'),
                        severity='High',
                        evidence='No CSRF token found in form',
                        missing_tokens=['token', 'csrf_token', 'nonce'],
                        samesite_status=samesite_status.value if samesite_status else 'Missing',
                        confirmed=True,
                        remediation=self._get_remediation()
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['no_token'] += 1
                
                else:
                    token_values = [t.value for t in tokens]
                    is_randomized, randomness_score = self.token_analyzer.analyze_token_randomness(tokens)
                    
                    if not is_randomized:
                        vuln = CSRFVulnerability(
                            vulnerability_type='CSRF',
                            csrf_type=CSRFVulnerabilityType.PREDICTABLE_TOKEN,
                            url=target_url,
                            form_name=form.get('name'),
                            form_action=form.get('action'),
                            form_method=form.get('method'),
                            severity='High',
                            evidence=f'Token entropy score: {randomness_score:.2f}',
                            tokens_found=tokens,
                            samesite_status=samesite_status.value if samesite_status else 'Missing',
                            confirmed=True,
                            confidence_score=randomness_score,
                            remediation=self._get_remediation()
                        )
                        vulnerabilities.append(vuln)
                        self.scan_statistics['predictable_token'] += 1
                    
                    is_predictable, pattern = self.token_analyzer.detect_predictable_pattern(token_values)
                    if is_predictable:
                        vuln = CSRFVulnerability(
                            vulnerability_type='CSRF',
                            csrf_type=CSRFVulnerabilityType.PREDICTABLE_TOKEN,
                            url=target_url,
                            form_name=form.get('name'),
                            form_action=form.get('action'),
                            form_method=form.get('method'),
                            severity='High',
                            evidence=f'Predictable pattern: {pattern}',
                            tokens_found=tokens,
                            samesite_status=samesite_status.value if samesite_status else 'Missing',
                            confirmed=True,
                            remediation=self._get_remediation()
                        )
                        vulnerabilities.append(vuln)
                        self.scan_statistics['predictable_pattern'] += 1
        
        if samesite_status == SameSiteValue.MISSING or samesite_status == SameSiteValue.NONE:
            vuln = CSRFVulnerability(
                vulnerability_type='CSRF',
                csrf_type=CSRFVulnerabilityType.MISSING_SAMESITE,
                url=target_url,
                severity='Medium',
                evidence='SameSite cookie attribute missing or set to None',
                samesite_status=samesite_status.value if samesite_status else 'Missing',
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['missing_samesite'] += 1
        
        if weak_origin:
            vuln = CSRFVulnerability(
                vulnerability_type='CSRF',
                csrf_type=CSRFVulnerabilityType.WEAK_ORIGIN_CHECK,
                url=target_url,
                severity='High',
                evidence='Weak origin validation detected',
                origin_check_status='Weak',
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['weak_origin'] += 1
        
        if method_override_detected:
            vuln = CSRFVulnerability(
                vulnerability_type='CSRF',
                csrf_type=CSRFVulnerabilityType.METHOD_OVERRIDE,
                url=target_url,
                severity='Medium',
                evidence='HTTP method override detected',
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['method_override'] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
            self.collected_tokens[target_url] = [t for form in forms for t in self.form_analyzer.find_csrf_tokens(form)]
        
        return vulnerabilities
    
    def _get_remediation(self) -> str:
        return (
            "Implement CSRF tokens (double-submit cookie or token in request). "
            "Set SameSite=Strict or SameSite=Lax on session cookies. "
            "Validate Origin and Referer headers. "
            "Disable HTTP method override functionality. "
            "Use short-lived tokens with proper randomization. "
            "Implement correct CORS policy. "
            "Disable cross-origin resource sharing unless necessary. "
            "Use HttpOnly and Secure flags on cookies."
        )
    
    def get_vulnerabilities(self) -> List[CSRFVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def get_collected_tokens(self, url: str) -> Optional[List[CSRFToken]]:
        return self.collected_tokens.get(url)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.collected_tokens.clear()