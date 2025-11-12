from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
from bs4 import BeautifulSoup
import threading
import time
import hashlib
import math


class CSRFVulnerabilityType(Enum):
    NO_TOKEN = "no_token"
    WEAK_TOKEN = "weak_token"
    TOKEN_NOT_VALIDATED = "token_not_validated"
    TOKEN_REUSE = "token_reuse"
    PREDICTABLE_TOKEN = "predictable_token"
    MISSING_SAMESITE = "missing_samesite"
    WEAK_ORIGIN_CHECK = "weak_origin_check"
    METHOD_OVERRIDE = "method_override"
    TOKEN_FIXATION = "token_fixation"
    DOUBLE_SUBMIT_BYPASS = "double_submit_bypass"


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
    shannon_entropy: float = 0.0
    char_diversity: float = 0.0
    created_at: float = field(default_factory=time.time)
    last_used: Optional[float] = None
    usage_count: int = 0
    
    def __post_init__(self):
        self.token_length = len(self.value)
        self.entropy_score = self._calculate_entropy()
        self.shannon_entropy = self._calculate_shannon_entropy()
        self.char_diversity = self._calculate_char_diversity()
        self.is_randomized = self._detect_randomization()
    
    def _calculate_entropy(self) -> float:
        if not self.value:
            return 0.0
        
        char_freq = defaultdict(int)
        for char in self.value:
            char_freq[char] += 1
        
        entropy = 0.0
        total_chars = len(self.value)
        
        for freq in char_freq.values():
            prob = freq / total_chars
            if prob > 0:
                entropy -= prob * math.log2(prob)
        
        max_entropy = math.log2(total_chars) if total_chars > 0 else 1
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
        
        return min(normalized_entropy, 1.0)
    
    def _calculate_shannon_entropy(self) -> float:
        if not self.value:
            return 0.0
        
        frequencies = defaultdict(int)
        for char in self.value:
            frequencies[char] += 1
        
        entropy = 0.0
        length = len(self.value)
        
        for count in frequencies.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_char_diversity(self) -> float:
        if not self.value:
            return 0.0
        
        unique_chars = len(set(self.value))
        total_chars = len(self.value)
        
        return unique_chars / total_chars if total_chars > 0 else 0.0
    
    def _detect_randomization(self) -> bool:
        return self.entropy_score > 0.7 and self.char_diversity > 0.5


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
    cookie_flags: Dict[str, bool] = field(default_factory=dict)
    method_override_vectors: List[str] = field(default_factory=list)
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class FormAnalyzer:
    _csrf_keywords = frozenset([
        'csrf', 'token', 'nonce', 'xsrf', 'authenticity', '_token', '__token',
        'csrfmiddlewaretoken', 'csrf_token', 'authenticity_token', '_csrf',
        'anti-forgery', 'request_token', 'security_token', 'form_token'
    ])
    
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
                    'autocomplete': form.get('autocomplete', ''),
                    'target': form.get('target', ''),
                    'inputs': [],
                    'hidden_fields': [],
                    'buttons': [],
                    'textarea': [],
                    'select': [],
                }
                
                for input_tag in form.find_all('input'):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'required': 'required' in input_tag.attrs,
                        'readonly': 'readonly' in input_tag.attrs,
                        'disabled': 'disabled' in input_tag.attrs,
                    }
                    
                    if input_data['type'] == 'hidden':
                        form_data['hidden_fields'].append(input_data)
                    else:
                        form_data['inputs'].append(input_data)
                
                for textarea in form.find_all('textarea'):
                    form_data['textarea'].append({
                        'name': textarea.get('name', ''),
                        'value': textarea.text,
                    })
                
                for select in form.find_all('select'):
                    form_data['select'].append({
                        'name': select.get('name', ''),
                        'options': [opt.get('value', '') for opt in select.find_all('option')],
                    })
                
                for button in form.find_all('button'):
                    button_data = {
                        'name': button.get('name', ''),
                        'type': button.get('type', 'submit'),
                        'value': button.get('value', ''),
                    }
                    form_data['buttons'].append(button_data)
                
                forms.append(form_data)
            
            return forms
        except Exception:
            return []
    
    @staticmethod
    def find_csrf_tokens(form: Dict) -> List[CSRFToken]:
        tokens = []
        
        for hidden_field in form.get('hidden_fields', []):
            field_name = hidden_field.get('name', '').lower()
            
            if any(keyword in field_name for keyword in FormAnalyzer._csrf_keywords):
                token = CSRFToken(
                    name=hidden_field['name'],
                    value=hidden_field.get('value', ''),
                    form_name=form.get('name') or form.get('id')
                )
                tokens.append(token)
        
        return tokens
    
    @staticmethod
    def detect_ajax_csrf_headers(html_content: str) -> List[str]:
        header_patterns = [
            r'["\']X-CSRF-Token["\']',
            r'["\']X-XSRF-Token["\']',
            r'["\']X-Requested-With["\']',
            r'setRequestHeader\(["\']([^"\']+)["\']',
        ]
        
        detected_headers = []
        for pattern in header_patterns:
            matches = re.findall(pattern, html_content, re.I)
            detected_headers.extend(matches)
        
        return list(set(detected_headers))


class CookieAnalyzer:
    @staticmethod
    def analyze_samesite_cookie(cookies: Dict[str, str]) -> Tuple[Optional[SameSiteValue], List[str]]:
        issues = []
        samesite_value = SameSiteValue.MISSING
        
        for cookie_name, cookie_header in cookies.items():
            if isinstance(cookie_header, str):
                cookie_lower = cookie_header.lower()
                
                if 'samesite=strict' in cookie_lower:
                    samesite_value = SameSiteValue.STRICT
                elif 'samesite=lax' in cookie_lower:
                    samesite_value = SameSiteValue.LAX
                elif 'samesite=none' in cookie_lower:
                    samesite_value = SameSiteValue.NONE
                    issues.append(f'Cookie "{cookie_name}": SameSite=None allows cross-site transmission')
                    
                    if 'secure' not in cookie_lower:
                        issues.append(f'Cookie "{cookie_name}": SameSite=None without Secure flag')
                else:
                    issues.append(f'Cookie "{cookie_name}": SameSite attribute missing')
        
        return samesite_value, issues
    
    @staticmethod
    def analyze_httponly_flag(cookies: Dict[str, str]) -> Tuple[bool, List[str]]:
        issues = []
        has_httponly = False
        
        for cookie_name, cookie_header in cookies.items():
            if isinstance(cookie_header, str):
                if 'httponly' in cookie_header.lower():
                    has_httponly = True
                else:
                    issues.append(f'Cookie "{cookie_name}": HttpOnly flag missing - vulnerable to XSS')
        
        return has_httponly, issues
    
    @staticmethod
    def analyze_secure_flag(cookies: Dict[str, str]) -> Tuple[bool, List[str]]:
        issues = []
        has_secure = False
        
        for cookie_name, cookie_header in cookies.items():
            if isinstance(cookie_header, str):
                if 'secure' in cookie_header.lower():
                    has_secure = True
                else:
                    issues.append(f'Cookie "{cookie_name}": Secure flag missing - may be transmitted over HTTP')
        
        return has_secure, issues
    
    @staticmethod
    def analyze_cookie_domain(cookies: Dict[str, str]) -> Tuple[bool, List[str]]:
        issues = []
        has_domain = False
        
        for cookie_name, cookie_header in cookies.items():
            if isinstance(cookie_header, str):
                domain_match = re.search(r'Domain=([^;]+)', cookie_header, re.I)
                if domain_match:
                    has_domain = True
                    domain = domain_match.group(1).strip()
                    
                    if domain.startswith('.'):
                        issues.append(f'Cookie "{cookie_name}": Broad domain scope "{domain}" allows subdomain access')
        
        return has_domain, issues
    
    @staticmethod
    def analyze_cookie_path(cookies: Dict[str, str]) -> Tuple[bool, List[str]]:
        issues = []
        has_path = False
        
        for cookie_name, cookie_header in cookies.items():
            if isinstance(cookie_header, str):
                path_match = re.search(r'Path=([^;]+)', cookie_header, re.I)
                if path_match:
                    has_path = True
                    path = path_match.group(1).strip()
                    
                    if path == '/':
                        issues.append(f'Cookie "{cookie_name}": Broad path scope "/" accessible from all paths')
        
        return has_path, issues


class TokenRandomnessAnalyzer:
    @staticmethod
    def analyze_token_randomness(tokens: List[CSRFToken]) -> Tuple[bool, float]:
        if not tokens:
            return False, 0.0
        
        if len(tokens) == 1:
            token = tokens[0]
            return token.is_randomized, token.entropy_score
        
        avg_entropy = sum(t.entropy_score for t in tokens) / len(tokens)
        avg_shannon = sum(t.shannon_entropy for t in tokens) / len(tokens)
        avg_diversity = sum(t.char_diversity for t in tokens) / len(tokens)
        
        combined_score = (avg_entropy * 0.4 + avg_shannon * 0.3 + avg_diversity * 0.3)
        
        is_random = combined_score > 0.65
        
        return is_random, combined_score
    
    @staticmethod
    def detect_predictable_pattern(tokens: List[str]) -> Tuple[bool, Optional[str]]:
        if len(tokens) < 2:
            return False, None
        
        if all(tokens[0] == t for t in tokens):
            return True, "All tokens are identical"
        
        if len(tokens) >= 2:
            if tokens[0] == tokens[1]:
                return True, "Token reuse detected"
        
        try:
            token_ints = []
            for token in tokens:
                try:
                    if all(c in '0123456789abcdefABCDEF' for c in token):
                        token_ints.append(int(token, 16))
                    else:
                        token_ints.append(int(token))
                except ValueError:
                    continue
            
            if len(token_ints) >= 3:
                diffs = [token_ints[i+1] - token_ints[i] for i in range(len(token_ints)-1)]
                
                if all(d == diffs[0] for d in diffs) and diffs[0] != 0:
                    return True, f"Sequential pattern (increment: {diffs[0]})"
                
                if all(d == 1 for d in diffs):
                    return True, "Incrementing by 1"
        except Exception:
            pass
        
        timestamp_pattern = re.compile(r'^\d{10,13}$')
        if all(timestamp_pattern.match(t) for t in tokens):
            return True, "Timestamp-based tokens detected"
        
        return False, None
    
    @staticmethod
    def calculate_token_strength(token: CSRFToken) -> Tuple[str, float]:
        score = 0.0
        
        if token.token_length >= 32:
            score += 0.3
        elif token.token_length >= 16:
            score += 0.15
        
        score += token.entropy_score * 0.3
        score += token.shannon_entropy * 0.2
        score += token.char_diversity * 0.2
        
        if score >= 0.8:
            return "Strong", score
        elif score >= 0.5:
            return "Medium", score
        else:
            return "Weak", score


class OriginRefererAnalyzer:
    @staticmethod
    def analyze_origin_validation(request_headers: Dict, response_headers: Dict) -> Tuple[bool, List[str]]:
        issues = []
        has_origin_check = False
        
        origin = request_headers.get('Origin', '').lower()
        referer = request_headers.get('Referer', '').lower()
        
        if not origin and not referer:
            issues.append('Neither Origin nor Referer header present in request')
        
        allow_origin = response_headers.get('Access-Control-Allow-Origin', '')
        
        if allow_origin == '*':
            issues.append('Access-Control-Allow-Origin: * allows any origin')
            has_origin_check = False
        elif allow_origin:
            has_origin_check = True
            
            if 'null' in allow_origin.lower():
                issues.append('Null origin accepted in CORS policy')
        else:
            issues.append('No CORS headers configured')
        
        allow_credentials = response_headers.get('Access-Control-Allow-Credentials', '').lower()
        if allow_credentials == 'true' and allow_origin == '*':
            issues.append('CORS allows credentials with wildcard origin - security risk')
        
        return has_origin_check, issues
    
    @staticmethod
    def detect_weak_origin_check(response_headers: Dict) -> Tuple[bool, List[str]]:
        issues = []
        
        allow_origin = response_headers.get('Access-Control-Allow-Origin', '')
        
        if allow_origin == '*':
            issues.append('Wildcard CORS policy allows any origin')
        
        wildcard_pattern = re.compile(r'\*\.[\w-]+\.[\w-]+')
        if wildcard_pattern.search(allow_origin):
            issues.append('Wildcard subdomain matching in CORS allows broad access')
        
        if 'null' in allow_origin.lower():
            issues.append('Null origin accepted - vulnerable to file:// protocol attacks')
        
        allow_methods = response_headers.get('Access-Control-Allow-Methods', '')
        dangerous_methods = {'PUT', 'DELETE', 'PATCH', 'TRACE'}
        if any(method in allow_methods.upper() for method in dangerous_methods):
            issues.append('Dangerous HTTP methods allowed via CORS')
        
        return len(issues) > 0, issues
    
    @staticmethod
    def detect_referer_validation(response_content: str) -> Tuple[bool, str]:
        referer_patterns = [
            r'document\.referrer',
            r'HTTP_REFERER',
            r'getHeader\(["\']Referer["\']',
            r'request\.headers\[["\']referer["\']',
        ]
        
        for pattern in referer_patterns:
            if re.search(pattern, response_content, re.I):
                return True, f"Referer validation detected: {pattern}"
        
        return False, ""


class HTTPMethodOverrideDetector:
    _method_override_headers = frozenset([
        'X-HTTP-Method-Override', 'X-Method-Override', 'X-HTTP-Method',
        'X-METHODOVERRIDE', 'X-HTTP-METHOD-OVERRIDE'
    ])
    
    _method_override_params = frozenset([
        '_method', '_METHOD', 'X-HTTP-Method-Override', '_request_method',
        '__METHOD__', 'method'
    ])
    
    @staticmethod
    def detect_method_override(html_content: str, headers: Dict) -> Tuple[bool, List[str]]:
        issues = []
        
        for header in HTTPMethodOverrideDetector._method_override_headers:
            if header in headers or header.lower() in {k.lower() for k in headers}:
                issues.append(f'HTTP Method Override via header: {header}')
        
        for param in HTTPMethodOverrideDetector._method_override_params:
            if param in html_content:
                issues.append(f'HTTP Method Override via parameter: {param}')
        
        form_method_override = re.search(r'<input[^>]*name=["\']_method["\'][^>]*value=["\'](\w+)["\']', html_content, re.I)
        if form_method_override:
            method = form_method_override.group(1)
            issues.append(f'Form-based method override to {method}')
        
        return len(issues) > 0, issues


class CSRFScanner:
    _remediation_cache = (
        "Implement CSRF tokens (double-submit cookie or synchronizer token pattern). "
        "Use cryptographically strong random tokens with sufficient entropy. "
        "Set SameSite=Strict or SameSite=Lax on all session cookies. "
        "Validate Origin and Referer headers on state-changing requests. "
        "Disable HTTP method override functionality. "
        "Use short-lived tokens with proper expiration. "
        "Implement per-request tokens instead of per-session tokens. "
        "Apply correct CORS policy with specific origins. "
        "Use HttpOnly and Secure flags on all cookies. "
        "Implement CAPTCHA for sensitive operations. "
        "Use custom headers for AJAX requests. "
        "Validate token on server-side for every request."
    )
    
    def __init__(self):
        self.form_analyzer = FormAnalyzer()
        self.cookie_analyzer = CookieAnalyzer()
        self.token_analyzer = TokenRandomnessAnalyzer()
        self.origin_analyzer = OriginRefererAnalyzer()
        self.method_override_detector = HTTPMethodOverrideDetector()
        
        self.vulnerabilities: List[CSRFVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.collected_tokens: Dict[str, List[CSRFToken]] = defaultdict(list)
        self.token_history: Dict[str, List[str]] = defaultdict(list)
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
        domain_status, domain_issues = self.cookie_analyzer.analyze_cookie_domain(cookies)
        path_status, path_issues = self.cookie_analyzer.analyze_cookie_path(cookies)
        
        cookie_flags = {
            'httponly': httponly_status,
            'secure': secure_status,
            'samesite': samesite_status != SameSiteValue.MISSING,
        }
        
        method_override_detected, method_override_issues = self.method_override_detector.detect_method_override(
            response_content,
            request_headers
        )
        
        origin_check, origin_issues = self.origin_analyzer.analyze_origin_validation(
            request_headers,
            response_headers
        )
        
        weak_origin, weak_origin_issues = self.origin_analyzer.detect_weak_origin_check(response_headers)
        
        referer_validation, referer_info = self.origin_analyzer.detect_referer_validation(response_content)
        
        ajax_csrf_headers = self.form_analyzer.detect_ajax_csrf_headers(response_content)
        
        for form in forms:
            if form['method'].upper() in ['POST', 'PUT', 'DELETE', 'PATCH']:
                tokens = self.form_analyzer.find_csrf_tokens(form)
                
                if not tokens:
                    evidence_parts = ['No CSRF token found in form']
                    
                    if not ajax_csrf_headers:
                        evidence_parts.append('No AJAX CSRF headers detected')
                    
                    vuln = CSRFVulnerability(
                        vulnerability_type='CSRF',
                        csrf_type=CSRFVulnerabilityType.NO_TOKEN,
                        url=target_url,
                        form_name=form.get('name') or form.get('id'),
                        form_action=form.get('action'),
                        form_method=form.get('method'),
                        severity='Critical',
                        evidence=' | '.join(evidence_parts),
                        missing_tokens=list(FormAnalyzer._csrf_keywords),
                        samesite_status=samesite_status.value if samesite_status else 'Missing',
                        cookie_flags=cookie_flags,
                        confirmed=True,
                        confidence_score=0.95,
                        remediation=self._remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['no_token'] += 1
                
                else:
                    for token in tokens:
                        self.token_history[target_url].append(token.value)
                    
                    token_values = [t.value for t in tokens]
                    
                    for token in tokens:
                        strength, score = self.token_analyzer.calculate_token_strength(token)
                        
                        if strength == "Weak":
                            vuln = CSRFVulnerability(
                                vulnerability_type='CSRF',
                                csrf_type=CSRFVulnerabilityType.WEAK_TOKEN,
                                url=target_url,
                                form_name=form.get('name') or form.get('id'),
                                form_action=form.get('action'),
                                form_method=form.get('method'),
                                severity='High',
                                evidence=f'Weak token strength: {strength} (score: {score:.2f}) | Length: {token.token_length} | Entropy: {token.entropy_score:.2f}',
                                tokens_found=tokens,
                                samesite_status=samesite_status.value if samesite_status else 'Missing',
                                cookie_flags=cookie_flags,
                                confirmed=True,
                                confidence_score=score,
                                remediation=self._remediation_cache
                            )
                            vulnerabilities.append(vuln)
                            self.scan_statistics['weak_token'] += 1
                    
                    is_randomized, randomness_score = self.token_analyzer.analyze_token_randomness(tokens)
                    
                    if not is_randomized:
                        vuln = CSRFVulnerability(
                            vulnerability_type='CSRF',
                            csrf_type=CSRFVulnerabilityType.PREDICTABLE_TOKEN,
                            url=target_url,
                            form_name=form.get('name') or form.get('id'),
                            form_action=form.get('action'),
                            form_method=form.get('method'),
                            severity='High',
                            evidence=f'Low token randomness: {randomness_score:.2f} | Tokens analyzed: {len(tokens)}',
                            tokens_found=tokens,
                            samesite_status=samesite_status.value if samesite_status else 'Missing',
                            cookie_flags=cookie_flags,
                            confirmed=True,
                            confidence_score=1.0 - randomness_score,
                            remediation=self._remediation_cache
                        )
                        vulnerabilities.append(vuln)
                        self.scan_statistics['predictable_token'] += 1
                    
                    history = self.token_history.get(target_url, [])
                    if len(history) >= 2:
                        is_predictable, pattern = self.token_analyzer.detect_predictable_pattern(history)
                        if is_predictable:
                            vuln = CSRFVulnerability(
                                vulnerability_type='CSRF',
                                csrf_type=CSRFVulnerabilityType.PREDICTABLE_TOKEN,
                                url=target_url,
                                form_name=form.get('name') or form.get('id'),
                                form_action=form.get('action'),
                                form_method=form.get('method'),
                                severity='Critical',
                                evidence=f'Predictable pattern detected: {pattern} | Tokens analyzed: {len(history)}',
                                tokens_found=tokens,
                                samesite_status=samesite_status.value if samesite_status else 'Missing',
                                cookie_flags=cookie_flags,
                                confirmed=True,
                                confidence_score=0.98,
                                remediation=self._remediation_cache
                            )
                            vulnerabilities.append(vuln)
                            self.scan_statistics['predictable_pattern'] += 1
        
        if samesite_status == SameSiteValue.MISSING or samesite_status == SameSiteValue.NONE:
            severity = 'High' if samesite_status == SameSiteValue.NONE else 'Medium'
            evidence_parts = [f'SameSite: {samesite_status.value if samesite_status else "Missing"}']
            evidence_parts.extend(samesite_issues[:3])
            
            vuln = CSRFVulnerability(
                vulnerability_type='CSRF',
                csrf_type=CSRFVulnerabilityType.MISSING_SAMESITE,
                url=target_url,
                severity=severity,
                evidence=' | '.join(evidence_parts),
                samesite_status=samesite_status.value if samesite_status else 'Missing',
                cookie_flags=cookie_flags,
                confirmed=True,
                confidence_score=0.9,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['missing_samesite'] += 1
        
        if weak_origin:
            vuln = CSRFVulnerability(
                vulnerability_type='CSRF',
                csrf_type=CSRFVulnerabilityType.WEAK_ORIGIN_CHECK,
                url=target_url,
                severity='High',
                evidence=f'Weak origin validation: {" | ".join(weak_origin_issues[:5])}',
                origin_check_status='Weak',
                cookie_flags=cookie_flags,
                confirmed=True,
                confidence_score=0.85,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['weak_origin'] += 1
        
        if method_override_detected:
            vuln = CSRFVulnerability(
                vulnerability_type='CSRF',
                csrf_type=CSRFVulnerabilityType.METHOD_OVERRIDE,
                url=target_url,
                severity='Medium',
                evidence=f'HTTP method override vectors: {" | ".join(method_override_issues[:5])}',
                method_override_vectors=method_override_issues,
                cookie_flags=cookie_flags,
                confirmed=True,
                confidence_score=0.8,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['method_override'] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
            for form in forms:
                form_tokens = self.form_analyzer.find_csrf_tokens(form)
                self.collected_tokens[target_url].extend(form_tokens)
            self.scan_statistics['total_scans'] += 1
        
        return vulnerabilities
    
    def get_vulnerabilities(self) -> List[CSRFVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def get_collected_tokens(self, url: str) -> Optional[List[CSRFToken]]:
        return self.collected_tokens.get(url, [])
    
    def get_token_history(self, url: str) -> List[str]:
        return self.token_history.get(url, [])
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.collected_tokens.clear()
            self.token_history.clear()