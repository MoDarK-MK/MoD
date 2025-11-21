from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from collections import defaultdict
from bs4 import BeautifulSoup
import threading
import time
import hashlib
import math
import base64

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
    NULL_BYTE_BYPASS = "null_byte_bypass"
    HEADER_INJECTION = "header_injection"
    JSON_HIJACKING = "json_hijacking"

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
        self.entropy_score = self._calc_entropy()
        self.shannon_entropy = self._calc_shannon()
        self.char_diversity = self._calc_diversity()
        self.is_randomized = self._detect_random()
    
    def _calc_entropy(self) -> float:
        if not self.value:
            return 0.0
        freq = defaultdict(int)
        for c in self.value:
            freq[c] += 1
        entropy = 0.0
        total = len(self.value)
        for f in freq.values():
            p = f / total
            if p > 0:
                entropy -= p * math.log2(p)
        max_entropy = math.log2(total) if total > 0 else 1
        return min(entropy / max_entropy, 1.0) if max_entropy > 0 else 0
    
    def _calc_shannon(self) -> float:
        if not self.value:
            return 0.0
        freq = defaultdict(int)
        for c in self.value:
            freq[c] += 1
        entropy = 0.0
        length = len(self.value)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
    
    def _calc_diversity(self) -> float:
        if not self.value:
            return 0.0
        unique = len(set(self.value))
        total = len(self.value)
        return unique / total if total > 0 else 0.0
    
    def _detect_random(self) -> bool:
        return self.entropy_score > 0.68 and self.char_diversity > 0.48

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

class MegaFormAnalyzer:
    CSRF_KEYWORDS = frozenset([
        'csrf', 'token', 'nonce', 'xsrf', 'authenticity', '_token', '__token',
        'csrfmiddlewaretoken', 'csrf_token', 'authenticity_token', '_csrf',
        'anti-forgery', 'request_token', 'security_token', 'form_token',
        'csrftoken', 'x-csrf-token', 'x-xsrf-token', '__requestverificationtoken'
    ])
    
    @staticmethod
    def extract_forms(html: str) -> List[Dict]:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'name': form.get('name', ''),
                    'id': form.get('id', ''),
                    'action': form.get('action', ''),
                    'method': form.get('method', 'POST').upper(),
                    'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                    'inputs': [],
                    'hidden': [],
                    'buttons': [],
                }
                
                for inp in form.find_all('input'):
                    data = {
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', ''),
                    }
                    if data['type'] == 'hidden':
                        form_data['hidden'].append(data)
                    else:
                        form_data['inputs'].append(data)
                
                forms.append(form_data)
            
            return forms
        except:
            return []
    
    @staticmethod
    def find_csrf_tokens(form: Dict) -> List[CSRFToken]:
        tokens = []
        for hidden in form.get('hidden', []):
            name = hidden.get('name', '').lower()
            if any(kw in name for kw in MegaFormAnalyzer.CSRF_KEYWORDS):
                tokens.append(CSRFToken(
                    name=hidden['name'],
                    value=hidden.get('value', ''),
                    form_name=form.get('name') or form.get('id')
                ))
        return tokens
    
    @staticmethod
    def detect_ajax_csrf(html: str) -> List[str]:
        patterns = [
            r'["\']X-CSRF-Token["\']',
            r'["\']X-XSRF-Token["\']',
            r'["\']X-Requested-With["\']',
            r'setRequestHeader\(["\']([^"\']+)["\']',
        ]
        detected = []
        for p in patterns:
            detected.extend(re.findall(p, html, re.I))
        return list(set(detected))

class MegaCookieAnalyzer:
    @staticmethod
    def analyze_samesite(cookies: Dict) -> Tuple[Optional[SameSiteValue], List[str]]:
        issues = []
        samesite = SameSiteValue.MISSING
        
        for name, header in cookies.items():
            if isinstance(header, str):
                lower = header.lower()
                if 'samesite=strict' in lower:
                    samesite = SameSiteValue.STRICT
                elif 'samesite=lax' in lower:
                    samesite = SameSiteValue.LAX
                elif 'samesite=none' in lower:
                    samesite = SameSiteValue.NONE
                    issues.append(f'{name}: SameSite=None cross-site')
                    if 'secure' not in lower:
                        issues.append(f'{name}: SameSite=None without Secure')
                else:
                    issues.append(f'{name}: SameSite missing')
        
        return samesite, issues
    
    @staticmethod
    def analyze_flags(cookies: Dict) -> Tuple[Dict[str, bool], List[str]]:
        flags = {'httponly': False, 'secure': False, 'samesite': False}
        issues = []
        
        for name, header in cookies.items():
            if isinstance(header, str):
                lower = header.lower()
                if 'httponly' in lower:
                    flags['httponly'] = True
                else:
                    issues.append(f'{name}: HttpOnly missing')
                
                if 'secure' in lower:
                    flags['secure'] = True
                else:
                    issues.append(f'{name}: Secure missing')
                
                if 'samesite' in lower:
                    flags['samesite'] = True
        
        return flags, issues

class MegaTokenAnalyzer:
    @staticmethod
    def analyze_randomness(tokens: List[CSRFToken]) -> Tuple[bool, float]:
        if not tokens:
            return False, 0.0
        
        if len(tokens) == 1:
            t = tokens[0]
            return t.is_randomized, t.entropy_score
        
        avg_entropy = sum(t.entropy_score for t in tokens) / len(tokens)
        avg_shannon = sum(t.shannon_entropy for t in tokens) / len(tokens)
        avg_div = sum(t.char_diversity for t in tokens) / len(tokens)
        
        score = (avg_entropy * 0.4 + avg_shannon * 0.3 + avg_div * 0.3)
        return score > 0.63, score
    
    @staticmethod
    def detect_pattern(tokens: List[str]) -> Tuple[bool, Optional[str]]:
        if len(tokens) < 2:
            return False, None
        
        if all(tokens[0] == t for t in tokens):
            return True, "All identical"
        
        if tokens[0] == tokens[1]:
            return True, "Token reuse"
        
        try:
            ints = []
            for t in tokens:
                try:
                    if all(c in '0123456789abcdefABCDEF' for c in t):
                        ints.append(int(t, 16))
                    else:
                        ints.append(int(t))
                except:
                    continue
            
            if len(ints) >= 3:
                diffs = [ints[i+1] - ints[i] for i in range(len(ints)-1)]
                if all(d == diffs[0] for d in diffs) and diffs[0] != 0:
                    return True, f"Sequential (inc: {diffs[0]})"
                if all(d == 1 for d in diffs):
                    return True, "Incrementing by 1"
        except:
            pass
        
        ts_pattern = re.compile(r'^\d{10,13}$')
        if all(ts_pattern.match(t) for t in tokens):
            return True, "Timestamp-based"
        
        return False, None
    
    @staticmethod
    def calc_strength(token: CSRFToken) -> Tuple[str, float]:
        score = 0.0
        
        if token.token_length >= 32:
            score += 0.3
        elif token.token_length >= 16:
            score += 0.15
        
        score += token.entropy_score * 0.3
        score += token.shannon_entropy * 0.2
        score += token.char_diversity * 0.2
        
        if score >= 0.78:
            return "Strong", score
        elif score >= 0.48:
            return "Medium", score
        else:
            return "Weak", score

class MegaOriginAnalyzer:
    @staticmethod
    def analyze_origin(req_headers: Dict, resp_headers: Dict) -> Tuple[bool, List[str]]:
        issues = []
        has_check = False
        
        origin = req_headers.get('Origin', '').lower()
        referer = req_headers.get('Referer', '').lower()
        
        if not origin and not referer:
            issues.append('No Origin/Referer in request')
        
        allow_origin = resp_headers.get('Access-Control-Allow-Origin', '')
        
        if allow_origin == '*':
            issues.append('CORS wildcard allows any origin')
            has_check = False
        elif allow_origin:
            has_check = True
            if 'null' in allow_origin.lower():
                issues.append('Null origin accepted')
        
        allow_cred = resp_headers.get('Access-Control-Allow-Credentials', '').lower()
        if allow_cred == 'true' and allow_origin == '*':
            issues.append('Credentials + wildcard origin')
        
        return has_check, issues
    
    @staticmethod
    def detect_weak_origin(resp_headers: Dict) -> Tuple[bool, List[str]]:
        issues = []
        allow_origin = resp_headers.get('Access-Control-Allow-Origin', '')
        
        if allow_origin == '*':
            issues.append('Wildcard CORS')
        
        if 'null' in allow_origin.lower():
            issues.append('Null origin accepted')
        
        allow_methods = resp_headers.get('Access-Control-Allow-Methods', '')
        dangerous = {'PUT', 'DELETE', 'PATCH', 'TRACE'}
        if any(m in allow_methods.upper() for m in dangerous):
            issues.append(f'Dangerous methods: {allow_methods}')
        
        return bool(issues), issues

class MegaMethodOverrideDetector:
    HEADERS = frozenset(['X-HTTP-Method-Override', 'X-Method-Override', 'X-HTTP-Method'])
    PARAMS = frozenset(['_method', '_METHOD', '__METHOD__', 'method'])
    
    @staticmethod
    def detect(html: str, headers: Dict) -> Tuple[bool, List[str]]:
        issues = []
        
        for h in MegaMethodOverrideDetector.HEADERS:
            if h in headers or h.lower() in {k.lower() for k in headers}:
                issues.append(f'Override via header: {h}')
        
        for p in MegaMethodOverrideDetector.PARAMS:
            if p in html:
                issues.append(f'Override via param: {p}')
        
        form_override = re.search(r'<input[^>]*name=["\']_method["\'][^>]*value=["\'](\w+)["\']', html, re.I)
        if form_override:
            issues.append(f'Form override to {form_override.group(1)}')
        
        return bool(issues), issues

class CSRFScanner:
    def __init__(self, max_workers: int = 16):
        self.form_analyzer = MegaFormAnalyzer()
        self.cookie_analyzer = MegaCookieAnalyzer()
        self.token_analyzer = MegaTokenAnalyzer()
        self.origin_analyzer = MegaOriginAnalyzer()
        self.method_detector = MegaMethodOverrideDetector()
        
        self.vulnerabilities = []
        self.collected_tokens = defaultdict(list)
        self.token_history = defaultdict(list)
        self.lock = threading.Lock()
        self.max_workers = max_workers
    
    def scan(self, url: str, response: Dict) -> List[CSRFVulnerability]:
        vulns = []
        content = response.get('content', '')
        resp_headers = response.get('headers', {})
        req_headers = response.get('request_headers', {})
        cookies = response.get('cookies', {})
        
        forms = self.form_analyzer.extract_forms(content)
        
        samesite, samesite_issues = self.cookie_analyzer.analyze_samesite(cookies)
        cookie_flags, cookie_issues = self.cookie_analyzer.analyze_flags(cookies)
        
        method_override, method_issues = self.method_detector.detect(content, req_headers)
        origin_check, origin_issues = self.origin_analyzer.analyze_origin(req_headers, resp_headers)
        weak_origin, weak_issues = self.origin_analyzer.detect_weak_origin(resp_headers)
        
        ajax_headers = self.form_analyzer.detect_ajax_csrf(content)
        
        for form in forms:
            if form['method'].upper() in ['POST', 'PUT', 'DELETE', 'PATCH']:
                tokens = self.form_analyzer.find_csrf_tokens(form)
                
                if not tokens:
                    evidence = ['No CSRF token']
                    if not ajax_headers:
                        evidence.append('No AJAX CSRF headers')
                    
                    vulns.append(CSRFVulnerability(
                        vulnerability_type='CSRF',
                        csrf_type=CSRFVulnerabilityType.NO_TOKEN,
                        url=url,
                        form_name=form.get('name') or form.get('id'),
                        form_action=form.get('action'),
                        form_method=form.get('method'),
                        severity='Critical',
                        evidence=' | '.join(evidence),
                        missing_tokens=list(MegaFormAnalyzer.CSRF_KEYWORDS),
                        samesite_status=samesite.value if samesite else 'Missing',
                        cookie_flags=cookie_flags,
                        confirmed=True,
                        confidence_score=0.96,
                        remediation=self._remediation()
                    ))
                else:
                    for token in tokens:
                        self.token_history[url].append(token.value)
                    
                    for token in tokens:
                        strength, score = self.token_analyzer.calc_strength(token)
                        
                        if strength == "Weak":
                            vulns.append(CSRFVulnerability(
                                vulnerability_type='CSRF',
                                csrf_type=CSRFVulnerabilityType.WEAK_TOKEN,
                                url=url,
                                form_name=form.get('name') or form.get('id'),
                                form_action=form.get('action'),
                                form_method=form.get('method'),
                                severity='High',
                                evidence=f'Weak: {strength} (score: {score:.2f}) | Len: {token.token_length} | Entropy: {token.entropy_score:.2f}',
                                tokens_found=tokens,
                                samesite_status=samesite.value if samesite else 'Missing',
                                cookie_flags=cookie_flags,
                                confirmed=True,
                                confidence_score=score,
                                remediation=self._remediation()
                            ))
                    
                    is_random, rand_score = self.token_analyzer.analyze_randomness(tokens)
                    if not is_random:
                        vulns.append(CSRFVulnerability(
                            vulnerability_type='CSRF',
                            csrf_type=CSRFVulnerabilityType.PREDICTABLE_TOKEN,
                            url=url,
                            form_name=form.get('name') or form.get('id'),
                            form_action=form.get('action'),
                            form_method=form.get('method'),
                            severity='High',
                            evidence=f'Low randomness: {rand_score:.2f} | Tokens: {len(tokens)}',
                            tokens_found=tokens,
                            samesite_status=samesite.value if samesite else 'Missing',
                            cookie_flags=cookie_flags,
                            confirmed=True,
                            confidence_score=1.0 - rand_score,
                            remediation=self._remediation()
                        ))
                    
                    history = self.token_history.get(url, [])
                    if len(history) >= 2:
                        is_pred, pattern = self.token_analyzer.detect_pattern(history)
                        if is_pred:
                            vulns.append(CSRFVulnerability(
                                vulnerability_type='CSRF',
                                csrf_type=CSRFVulnerabilityType.PREDICTABLE_TOKEN,
                                url=url,
                                form_name=form.get('name') or form.get('id'),
                                form_action=form.get('action'),
                                form_method=form.get('method'),
                                severity='Critical',
                                evidence=f'Pattern: {pattern} | Tokens: {len(history)}',
                                tokens_found=tokens,
                                samesite_status=samesite.value if samesite else 'Missing',
                                cookie_flags=cookie_flags,
                                confirmed=True,
                                confidence_score=0.98,
                                remediation=self._remediation()
                            ))
        
        if samesite == SameSiteValue.MISSING or samesite == SameSiteValue.NONE:
            severity = 'High' if samesite == SameSiteValue.NONE else 'Medium'
            evidence = [f'SameSite: {samesite.value if samesite else "Missing"}']
            evidence.extend(samesite_issues[:3])
            
            vulns.append(CSRFVulnerability(
                vulnerability_type='CSRF',
                csrf_type=CSRFVulnerabilityType.MISSING_SAMESITE,
                url=url,
                severity=severity,
                evidence=' | '.join(evidence),
                samesite_status=samesite.value if samesite else 'Missing',
                cookie_flags=cookie_flags,
                confirmed=True,
                confidence_score=0.91,
                remediation=self._remediation()
            ))
        
        if weak_origin:
            vulns.append(CSRFVulnerability(
                vulnerability_type='CSRF',
                csrf_type=CSRFVulnerabilityType.WEAK_ORIGIN_CHECK,
                url=url,
                severity='High',
                evidence=f'Weak origin: {" | ".join(weak_issues[:5])}',
                origin_check_status='Weak',
                cookie_flags=cookie_flags,
                confirmed=True,
                confidence_score=0.86,
                remediation=self._remediation()
            ))
        
        if method_override:
            vulns.append(CSRFVulnerability(
                vulnerability_type='CSRF',
                csrf_type=CSRFVulnerabilityType.METHOD_OVERRIDE,
                url=url,
                severity='Medium',
                evidence=f'Method override: {" | ".join(method_issues[:5])}',
                method_override_vectors=method_issues,
                cookie_flags=cookie_flags,
                confirmed=True,
                confidence_score=0.82,
                remediation=self._remediation()
            ))
        
        with self.lock:
            self.vulnerabilities.extend(vulns)
            for form in forms:
                self.collected_tokens[url].extend(self.form_analyzer.find_csrf_tokens(form))
        
        return vulns
    
    def _remediation(self):
        return (
            "1. Strong random CSRF tokens. "
            "2. SameSite=Strict/Lax cookies. "
            "3. Origin/Referer validation. "
            "4. Disable method override. "
            "5. Short-lived tokens. "
            "6. Per-request tokens. "
            "7. Strict CORS policy. "
            "8. HttpOnly + Secure flags. "
            "9. CAPTCHA for sensitive ops. "
            "10. Custom AJAX headers."
        )
    
    def get_vulnerabilities(self):
        with self.lock: return self.vulnerabilities.copy()
    
    def get_collected_tokens(self, url):
        return self.collected_tokens.get(url, [])
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.collected_tokens.clear()
            self.token_history.clear()
