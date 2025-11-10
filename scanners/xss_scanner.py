from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time


class XSSType(Enum):
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"
    MUTATION = "mutation"
    ATTRIBUTE = "attribute"
    TAG = "tag"
    EVENT_HANDLER = "event_handler"
    JAVASCRIPT_PROTOCOL = "javascript_protocol"
    DATA_URI = "data_uri"
    SVG_INJECTION = "svg_injection"


class PayloadContext(Enum):
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT_STRING = "javascript_string"
    JAVASCRIPT_CODE = "javascript_code"
    CSS_VALUE = "css_value"
    CSS_URL = "css_url"
    JSON_VALUE = "json_value"
    URL_PARAMETER = "url_parameter"
    DATA_ATTRIBUTE = "data_attribute"


@dataclass
class XSSPayload:
    payload: str
    xss_type: XSSType
    context: PayloadContext
    severity: str = "High"
    bypass_techniques: List[str] = field(default_factory=list)
    requires_user_interaction: bool = False
    detection_patterns: List[str] = field(default_factory=list)
    false_positive_risk: float = 0.1


@dataclass
class XSSVulnerability:
    vulnerability_type: str
    xss_type: XSSType
    url: str
    parameter: str
    payload: str
    context: PayloadContext
    severity: str
    evidence: str
    response_time: float
    payload_position: int
    surrounding_html: str
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class ContextAnalyzer:
    CONTEXT_PATTERNS = {
        PayloadContext.HTML_BODY: r'<(body|div|p|span)[^>]*>.*?{payload}.*?</\1>',
        PayloadContext.HTML_ATTRIBUTE: r'(href|src|title|alt|data-[a-z]+)=["\'].*?{payload}.*?["\']',
        PayloadContext.JAVASCRIPT_STRING: r'(["\'])\s*\+\s*{payload}\s*\+\s*\1',
        PayloadContext.JAVASCRIPT_CODE: r'<script[^>]*>.*?{payload}.*?</script>',
        PayloadContext.CSS_VALUE: r'(style|color|background|border)[^:]*:\s*[^;]*{payload}[^;]*;',
        PayloadContext.JSON_VALUE: r':\s*["\']?.*?{payload}.*?["\']?[,\}]',
    }
    
    @staticmethod
    def detect_context(response_content: str, payload: str) -> List[PayloadContext]:
        detected_contexts = []
        
        for context, pattern in ContextAnalyzer.CONTEXT_PATTERNS.items():
            try:
                regex = re.compile(pattern.format(payload=re.escape(payload)), re.IGNORECASE | re.DOTALL)
                if regex.search(response_content):
                    detected_contexts.append(context)
            except:
                pass
        
        if not detected_contexts:
            if payload in response_content:
                detected_contexts.append(PayloadContext.HTML_BODY)
        
        return detected_contexts
    
    @staticmethod
    def get_surrounding_html(response_content: str, payload: str, context_size: int = 100) -> str:
        try:
            idx = response_content.find(payload)
            if idx == -1:
                return ""
            
            start = max(0, idx - context_size)
            end = min(len(response_content), idx + len(payload) + context_size)
            
            return response_content[start:end]
        except:
            return ""


class PayloadVariantGenerator:
    def __init__(self):
        self.variants_cache: Dict[str, List[str]] = {}
    
    def generate_variants(self, base_payload: str, context: PayloadContext) -> List[str]:
        cache_key = f"{base_payload}:{context.value}"
        
        if cache_key in self.variants_cache:
            return self.variants_cache[cache_key]
        
        variants = [base_payload]
        
        if context == PayloadContext.HTML_BODY:
            variants.extend(self._html_body_variants(base_payload))
        elif context == PayloadContext.HTML_ATTRIBUTE:
            variants.extend(self._html_attribute_variants(base_payload))
        elif context == PayloadContext.JAVASCRIPT_STRING:
            variants.extend(self._javascript_string_variants(base_payload))
        elif context == PayloadContext.JAVASCRIPT_CODE:
            variants.extend(self._javascript_code_variants(base_payload))
        elif context == PayloadContext.CSS_VALUE:
            variants.extend(self._css_variants(base_payload))
        
        self.variants_cache[cache_key] = variants
        return variants
    
    def _html_body_variants(self, payload: str) -> List[str]:
        return [
            f'<script>{payload}</script>',
            f'<img src=x onerror="{payload}">',
            f'<svg onload="{payload}">',
            f'<body onload="{payload}">',
            f'<iframe src="javascript:{payload}">',
        ]
    
    def _html_attribute_variants(self, payload: str) -> List[str]:
        return [
            f'"{payload}"',
            f"'{payload}'",
            f' {payload} ',
            f'"{payload}" style="',
            f"' onclick='{payload}' '",
        ]
    
    def _javascript_string_variants(self, payload: str) -> List[str]:
        return [
            f'";{payload};"',
            f"';{payload};'",
            f'` + {payload} + `',
            f'${{{payload}}}',
            f'`{payload}`',
        ]
    
    def _javascript_code_variants(self, payload: str) -> List[str]:
        return [
            f'({payload})',
            f'[{payload}]',
            f'{{{payload}}}',
            f'eval({payload})',
            f'setTimeout("{payload}", 0)',
        ]
    
    def _css_variants(self, payload: str) -> List[str]:
        return [
            f'url({payload})',
            f'url("{payload}")',
            f"url('{payload}')",
            f'expression({payload})',
            f'behavior: url({payload})',
        ]


class XSSDetectionEngine:
    def __init__(self):
        self.detection_patterns = self._build_detection_patterns()
        self.lock = threading.Lock()
    
    def _build_detection_patterns(self) -> Dict[XSSType, List[Pattern]]:
        patterns = {
            XSSType.REFLECTED: [
                re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
                re.compile(r'on\w+\s*=\s*["\']?.*?["\']?', re.IGNORECASE),
                re.compile(r'javascript:', re.IGNORECASE),
            ],
            XSSType.DOM_BASED: [
                re.compile(r'eval\s*\(', re.IGNORECASE),
                re.compile(r'innerHTML\s*=', re.IGNORECASE),
                re.compile(r'document\.write\s*\(', re.IGNORECASE),
            ],
            XSSType.SVG_INJECTION: [
                re.compile(r'<svg[^>]*>', re.IGNORECASE),
                re.compile(r'<image[^>]*xlink:href', re.IGNORECASE),
                re.compile(r'<animate[^>]*onbegin', re.IGNORECASE),
            ],
            XSSType.EVENT_HANDLER: [
                re.compile(r'onload\s*=', re.IGNORECASE),
                re.compile(r'onerror\s*=', re.IGNORECASE),
                re.compile(r'onclick\s*=', re.IGNORECASE),
                re.compile(r'onmouseover\s*=', re.IGNORECASE),
            ],
            XSSType.ATTRIBUTE: [
                re.compile(r'<img[^>]*src=', re.IGNORECASE),
                re.compile(r'<a[^>]*href=', re.IGNORECASE),
                re.compile(r'<link[^>]*href=', re.IGNORECASE),
            ],
        }
        
        return patterns
    
    def detect_xss(self, response_content: str, payload: str) -> Tuple[bool, Optional[XSSType], float]:
        with self.lock:
            for xss_type, patterns in self.detection_patterns.items():
                for pattern in patterns:
                    if pattern.search(response_content):
                        if payload in response_content or self._check_payload_encoding(response_content, payload):
                            confidence = self._calculate_confidence(xss_type, response_content, payload)
                            return True, xss_type, confidence
        
        return False, None, 0.0
    
    def _check_payload_encoding(self, response_content: str, payload: str) -> bool:
        encoded_variants = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;').replace("'", '&#x27;'),
            payload.encode('utf-8').hex(),
        ]
        
        return any(variant in response_content for variant in encoded_variants)
    
    def _calculate_confidence(self, xss_type: XSSType, response_content: str, payload: str) -> float:
        confidence = 0.5
        
        if payload in response_content:
            confidence += 0.4
        
        if xss_type == XSSType.REFLECTED:
            confidence += 0.15
        elif xss_type == XSSType.DOM_BASED:
            confidence += 0.2
        elif xss_type == XSSType.SVG_INJECTION:
            confidence += 0.15
        
        return min(confidence, 1.0)


class WAFBypassEngine:
    BYPASS_TECHNIQUES = {
        'case_alternation': lambda p: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
        'unicode_escape': lambda p: '\\u' + '\\u'.join(f'{ord(c):04x}' for c in p),
        'html_entity': lambda p: ''.join(f'&#{ord(c)};' for c in p),
        'url_encoding': lambda p: '%'.join(f'{ord(c):02x}' for c in p),
        'comment_injection': lambda p: p.replace('script', 'scr/**/ipt'),
        'attribute_encoding': lambda p: p.replace('"', '&quot;').replace("'", '&#x27;'),
    }
    
    @staticmethod
    def apply_bypass(payload: str, technique: str) -> Optional[str]:
        if technique in WAFBypassEngine.BYPASS_TECHNIQUES:
            try:
                return WAFBypassEngine.BYPASS_TECHNIQUES[technique](payload)
            except:
                return None
        return None
    
    @staticmethod
    def generate_bypass_variants(payload: str) -> List[str]:
        variants = [payload]
        
        for technique in WAFBypassEngine.BYPASS_TECHNIQUES.keys():
            variant = WAFBypassEngine.apply_bypass(payload, technique)
            if variant and variant not in variants:
                variants.append(variant)
        
        return variants


class ReflectionAnalyzer:
    @staticmethod
    def analyze_reflection(original_payload: str, response_content: str) -> Dict[str, any]:
        analysis = {
            'is_reflected': original_payload in response_content,
            'reflection_count': response_content.count(original_payload),
            'reflection_positions': [],
            'surrounding_context': [],
            'encoding_detected': False,
            'filtering_applied': False,
        }
        
        idx = 0
        while True:
            idx = response_content.find(original_payload, idx)
            if idx == -1:
                break
            
            analysis['reflection_positions'].append(idx)
            
            start = max(0, idx - 50)
            end = min(len(response_content), idx + len(original_payload) + 50)
            analysis['surrounding_context'].append(response_content[start:end])
            
            idx += len(original_payload)
        
        if not analysis['is_reflected']:
            encoded_variants = [
                original_payload.replace('<', '&lt;'),
                original_payload.replace('"', '&quot;'),
                original_payload.encode('utf-8').hex(),
            ]
            
            if any(variant in response_content for variant in encoded_variants):
                analysis['encoding_detected'] = True
                analysis['is_reflected'] = True
        
        return analysis


class DOMXSSDetector:
    DOM_SINKS = [
        'innerHTML', 'outerHTML', 'insertAdjacentHTML',
        'write', 'writeln', 'eval', 'setTimeout', 'setInterval',
        'execScript', 'Function', 'fromCharCode',
    ]
    
    DOM_SOURCES = [
        'location', 'document.URL', 'document.documentURI',
        'document.referrer', 'location.hash', 'location.search',
        'window.name', 'document.cookie',
    ]
    
    @staticmethod
    def detect_dom_xss_risk(response_content: str) -> Tuple[bool, List[str]]:
        risks = []
        
        for sink in DOMXSSDetector.DOM_SINKS:
            if sink in response_content:
                for source in DOMXSSDetector.DOM_SOURCES:
                    pattern = rf'{source}.*?{sink}'
                    if re.search(pattern, response_content, re.IGNORECASE | re.DOTALL):
                        risks.append(f"{source} -> {sink}")
        
        return len(risks) > 0, risks


class XSSScanner:
    def __init__(self):
        self.detection_engine = XSSDetectionEngine()
        self.variant_generator = PayloadVariantGenerator()
        self.waf_bypass_engine = WAFBypassEngine()
        self.reflection_analyzer = ReflectionAnalyzer()
        self.dom_detector = DOMXSSDetector()
        self.context_analyzer = ContextAnalyzer()
        
        self.vulnerabilities: List[XSSVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: List[str]) -> List[XSSVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        
        if not response_content:
            return vulnerabilities
        
        is_dom_risk, dom_risks = self.dom_detector.detect_dom_xss_risk(response_content)
        
        for parameter in self._extract_parameters(target_url):
            for payload in payloads:
                detected_contexts = self.context_analyzer.detect_context(response_content, payload)
                
                for context in detected_contexts:
                    variants = self.variant_generator.generate_variants(payload, context)
                    bypass_variants = self.waf_bypass_engine.generate_bypass_variants(payload)
                    
                    all_variants = list(set(variants + bypass_variants))
                    
                    for variant in all_variants:
                        is_vulnerable, xss_type, confidence = self.detection_engine.detect_xss(
                            response_content,
                            variant
                        )
                        
                        if is_vulnerable:
                            reflection = self.reflection_analyzer.analyze_reflection(variant, response_content)
                            surrounding_html = self.context_analyzer.get_surrounding_html(
                                response_content,
                                variant
                            )
                            
                            vuln = XSSVulnerability(
                                vulnerability_type='XSS',
                                xss_type=xss_type or XSSType.REFLECTED,
                                url=target_url,
                                parameter=parameter,
                                payload=variant,
                                context=context,
                                severity=self._determine_severity(xss_type, reflection),
                                evidence=variant,
                                response_time=response_time,
                                payload_position=reflection['reflection_positions'][0] if reflection['reflection_positions'] else -1,
                                surrounding_html=surrounding_html,
                                confidence_score=confidence,
                                confirmed=reflection['is_reflected'],
                                remediation=self._get_remediation(context)
                            )
                            
                            if self._is_valid_vulnerability(vuln):
                                vulnerabilities.append(vuln)
                                self.scan_statistics[xss_type.value] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _extract_parameters(self, url: str) -> List[str]:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys()) if params else ['default']
    
    def _determine_severity(self, xss_type: Optional[XSSType], reflection: Dict) -> str:
        if xss_type == XSSType.STORED:
            return 'Critical'
        elif xss_type == XSSType.DOM_BASED:
            return 'High'
        elif reflection.get('is_reflected'):
            return 'High'
        return 'Medium'
    
    def _is_valid_vulnerability(self, vuln: XSSVulnerability) -> bool:
        if vuln.confidence_score < 0.6:
            return False
        
        if 'test' in vuln.payload.lower() or 'debug' in vuln.payload.lower():
            return False
        
        return True
    
    def _get_remediation(self, context: PayloadContext) -> str:
        remediations = {
            PayloadContext.HTML_BODY: 'Encode output using HTML entity encoding (e.g., <, >, &)',
            PayloadContext.HTML_ATTRIBUTE: 'Use attribute encoding and proper quote escaping',
            PayloadContext.JAVASCRIPT_STRING: 'Use JSON encoding and avoid eval()',
            PayloadContext.JAVASCRIPT_CODE: 'Use Content Security Policy (CSP) headers',
            PayloadContext.CSS_VALUE: 'Validate CSS values and use CSS-specific encoding',
            PayloadContext.JSON_VALUE: 'Use proper JSON encoding',
            PayloadContext.URL_PARAMETER: 'Use URL encoding for parameters',
            PayloadContext.DATA_ATTRIBUTE: 'Validate and encode data attributes',
        }
        return remediations.get(context, 'Implement output encoding')
    
    def get_vulnerabilities(self) -> List[XSSVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()