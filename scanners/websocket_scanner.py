from typing import Dict, List, Optional, Tuple, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import json
import base64
import hashlib


class WebSocketVulnerabilityType(Enum):
    INSECURE_CONNECTION = "insecure_connection"
    NO_AUTHENTICATION = "no_authentication"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    MESSAGE_INJECTION = "message_injection"
    DATA_EXPOSURE = "data_exposure"
    UNVALIDATED_INPUT = "unvalidated_input"
    LACK_OF_RATE_LIMITING = "lack_of_rate_limiting"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    PROTOCOL_CONFUSION = "protocol_confusion"
    INFORMATION_DISCLOSURE = "information_disclosure"


class MessageType(Enum):
    TEXT = "text"
    BINARY = "binary"
    JSON = "json"
    PROTOBUF = "protobuf"
    UNKNOWN = "unknown"


class ConnectionStatus(Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    TIMEOUT = "timeout"
    AUTHENTICATED = "authenticated"
    UNAUTHENTICATED = "unauthenticated"


@dataclass
class WebSocketEndpoint:
    url: str
    protocol: str
    port: int
    secure: bool
    path: str
    query_params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    requires_auth: bool = False
    auth_token: Optional[str] = None
    connection_status: ConnectionStatus = ConnectionStatus.DISCONNECTED
    supported_subprotocols: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)


@dataclass
class WebSocketMessage:
    message_id: str
    direction: str
    message_type: MessageType
    content: str
    content_bytes: Optional[bytes] = None
    timestamp: float = field(default_factory=time.time)
    is_response: bool = False
    response_time: float = 0.0
    metadata: Dict = field(default_factory=dict)


@dataclass
class WebSocketVulnerability:
    vulnerability_type: str
    ws_type: WebSocketVulnerabilityType
    url: str
    severity: str
    evidence: str
    affected_endpoint: str
    affected_operations: List[str] = field(default_factory=list)
    data_exposed: Optional[List[str]] = None
    injection_payload: Optional[str] = None
    bypass_method: Optional[str] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class WebSocketEndpointDiscovery:
    WS_ENDPOINT_PATTERNS = [
        r'wss?://[^\s\'"]+',
        r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
        r'ws\.connect\s*\(\s*["\']([^"\']+)["\']',
        r'socket\.io',
        r'\.on\s*\(\s*["\']connect',
    ]
    
    @staticmethod
    def discover_endpoints(response_content: str, base_url: str) -> List[WebSocketEndpoint]:
        endpoints = []
        
        for pattern in WebSocketEndpointDiscovery.WS_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, response_content, re.IGNORECASE)
            
            for match in matches:
                ws_url = match if isinstance(match, str) else match[0] if match else ''
                
                if not ws_url:
                    continue
                
                if ws_url.startswith('/'):
                    from urllib.parse import urlparse
                    parsed = urlparse(base_url)
                    ws_url = f"ws{'s' if parsed.scheme == 'https' else ''}://{parsed.netloc}{ws_url}"
                
                try:
                    endpoint = WebSocketEndpointDiscovery._parse_ws_url(ws_url)
                    if endpoint:
                        endpoints.append(endpoint)
                except Exception:
                    pass
        
        return endpoints
    
    @staticmethod
    def _parse_ws_url(url: str) -> Optional[WebSocketEndpoint]:
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            
            secure = parsed.scheme == 'wss'
            port = parsed.port or (443 if secure else 80)
            
            query_params = urllib.parse.parse_qs(parsed.query)
            query_params = {k: v[0] if v else '' for k, v in query_params.items()}
            
            return WebSocketEndpoint(
                url=url,
                protocol=parsed.scheme,
                port=port,
                secure=secure,
                path=parsed.path or '/',
                query_params=query_params
            )
        except Exception:
            return None


class WebSocketAuthenticationAnalyzer:
    AUTH_PATTERNS = {
        'token_in_url': r'[?&](token|auth|key|api_key)=([a-zA-Z0-9._-]+)',
        'token_in_header': r'Authorization:\s*(Bearer|Basic|Token)\s+([a-zA-Z0-9._-]+)',
        'jwt_token': r'eyJ[\w.-]*',
        'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?',
    }
    
    @staticmethod
    def analyze_authentication(endpoint: WebSocketEndpoint, response_content: str) -> Tuple[bool, Optional[str], Dict]:
        auth_info = {}
        requires_auth = False
        auth_method = None
        
        for auth_type, pattern in WebSocketAuthenticationAnalyzer.AUTH_PATTERNS.items():
            matches = re.findall(pattern, response_content)
            if matches:
                requires_auth = True
                auth_method = auth_type
                auth_info[auth_type] = matches
        
        if endpoint.query_params:
            for key, value in endpoint.query_params.items():
                if any(keyword in key.lower() for keyword in ['token', 'auth', 'key', 'session']):
                    requires_auth = True
                    auth_method = 'url_parameter'
                    auth_info['url_params'] = endpoint.query_params
        
        return requires_auth, auth_method, auth_info
    
    @staticmethod
    def detect_missing_authentication(messages_received: List[str]) -> Tuple[bool, float]:
        if not messages_received:
            return True, 0.9
        
        full_content = '\n'.join(messages_received)
        
        auth_keywords = ['authenticated', 'authorized', 'login', 'logged in', 'user']
        auth_found = any(keyword in full_content.lower() for keyword in auth_keywords)
        
        if not auth_found:
            return True, 0.8
        
        return False, 0.0


class MessageAnalyzer:
    @staticmethod
    def determine_message_type(message: str) -> MessageType:
        try:
            json.loads(message)
            return MessageType.JSON
        except json.JSONDecodeError:
            pass
        
        try:
            base64.b64decode(message, validate=True)
            return MessageType.BINARY
        except Exception:
            pass
        
        if isinstance(message, bytes):
            return MessageType.BINARY
        
        if message.startswith('{') or message.startswith('['):
            return MessageType.JSON
        
        return MessageType.TEXT
    
    @staticmethod
    def extract_sensitive_data(message: str) -> Tuple[bool, List[str]]:
        sensitive_patterns = {
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?',
            'token': r'(?i)(token|auth|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9._-]+)["\']?',
            'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s,;]+)["\']?',
            'private_key': r'-----BEGIN PRIVATE KEY-----',
        }
        
        exposed_data = []
        
        for data_type, pattern in sensitive_patterns.items():
            if re.search(pattern, message):
                exposed_data.append(data_type)
        
        return len(exposed_data) > 0, exposed_data
    
    @staticmethod
    def detect_injection_vectors(message: str) -> Tuple[bool, List[str]]:
        injection_patterns = {
            'xss': [
                r'<script[^>]*>',
                r'javascript:',
                r'onerror\s*=',
            ],
            'sql_injection': [
                r"'\s*OR\s*'1'='1",
                r";\s*(DROP|DELETE|UPDATE|INSERT)",
            ],
            'command_injection': [
                r';\s*(ls|cat|wget|curl)',
                r'\|\s*(nc|bash|sh)',
            ],
            'json_injection': [
                r'"\s*:\s*[^}]*"',
                r'\$[a-zA-Z_]',
            ],
        }
        
        detected_vectors = []
        
        for vector_type, patterns in injection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, message):
                    detected_vectors.append(vector_type)
                    break
        
        return len(detected_vectors) > 0, detected_vectors
    
    @staticmethod
    def analyze_message_pattern(messages: List[str]) -> Dict:
        analysis = {
            'total_messages': len(messages),
            'average_size': sum(len(m) for m in messages) / len(messages) if messages else 0,
            'message_types': defaultdict(int),
            'contains_sensitive_data': False,
            'contains_injection_vectors': False,
            'unique_patterns': set(),
        }
        
        for message in messages:
            msg_type = MessageAnalyzer.determine_message_type(message)
            analysis['message_types'][msg_type.value] += 1
            
            has_sensitive, _ = MessageAnalyzer.extract_sensitive_data(message)
            if has_sensitive:
                analysis['contains_sensitive_data'] = True
            
            has_injection, _ = MessageAnalyzer.detect_injection_vectors(message)
            if has_injection:
                analysis['contains_injection_vectors'] = True
            
            if len(message) > 50:
                pattern = message[:30]
                analysis['unique_patterns'].add(pattern)
        
        analysis['unique_patterns'] = list(analysis['unique_patterns'])
        return analysis


class RateLimitingDetector:
    @staticmethod
    def detect_rate_limiting(message_timestamps: List[float], threshold_per_second: int = 100) -> Tuple[bool, float]:
        if len(message_timestamps) < 10:
            return False, 0.0
        
        sorted_timestamps = sorted(message_timestamps)
        
        rate = len(sorted_timestamps) / (sorted_timestamps[-1] - sorted_timestamps[0] + 1)
        
        if rate > threshold_per_second:
            return False, 0.0
        
        return True, rate
    
    @staticmethod
    def detect_missing_rate_limiting(sent_messages: int, timespan_seconds: float) -> Tuple[bool, float]:
        if timespan_seconds == 0:
            return True, float(sent_messages)
        
        rate = sent_messages / timespan_seconds
        
        if rate > 10:
            return True, rate
        
        return False, rate


class AccessControlAnalyzer:
    @staticmethod
    def test_horizontal_privilege_escalation(user_ids: List[str], response_contents: List[str]) -> Tuple[bool, List[str]]:
        if len(response_contents) < 2:
            return False, []
        
        accessible_ids = []
        
        for idx, response in enumerate(response_contents):
            if response and len(response) > 10:
                accessible_ids.append(user_ids[idx] if idx < len(user_ids) else str(idx))
        
        if len(accessible_ids) > 1:
            return True, accessible_ids
        
        return False, []
    
    @staticmethod
    def test_vertical_privilege_escalation(admin_operations: List[str], response_contents: List[str]) -> Tuple[bool, List[str]]:
        executed_operations = []
        
        success_indicators = ['success', 'true', 'updated', 'deleted', 'created', 'executed']
        
        for op, response in zip(admin_operations, response_contents):
            if any(indicator in response.lower() for indicator in success_indicators):
                executed_operations.append(op)
        
        if executed_operations:
            return True, executed_operations
        
        return False, []


class WebSocketScanner:
    def __init__(self):
        self.endpoint_discovery = WebSocketEndpointDiscovery()
        self.auth_analyzer = WebSocketAuthenticationAnalyzer()
        self.message_analyzer = MessageAnalyzer()
        self.rate_limit_detector = RateLimitingDetector()
        self.access_control_analyzer = AccessControlAnalyzer()
        
        self.discovered_endpoints: Dict[str, WebSocketEndpoint] = {}
        self.vulnerabilities: List[WebSocketVulnerability] = []
        self.messages_captured: Dict[str, List[WebSocketMessage]] = defaultdict(list)
        self.scan_statistics = defaultdict(int)
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict) -> List[WebSocketVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_headers = response.get('headers', {})
        
        endpoints = self.endpoint_discovery.discover_endpoints(response_content, target_url)
        
        with self.lock:
            for endpoint in endpoints:
                self.discovered_endpoints[endpoint.url] = endpoint
        
        for endpoint in endpoints:
            endpoint_vulnerabilities = self._analyze_endpoint(endpoint, response_content, response_headers)
            vulnerabilities.extend(endpoint_vulnerabilities)
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _analyze_endpoint(self, endpoint: WebSocketEndpoint, response_content: str,
                         response_headers: Dict) -> List[WebSocketVulnerability]:
        vulnerabilities = []
        
        if not endpoint.secure:
            vuln = WebSocketVulnerability(
                vulnerability_type='WebSocket Vulnerability',
                ws_type=WebSocketVulnerabilityType.INSECURE_CONNECTION,
                url=endpoint.url,
                severity='High',
                evidence='WebSocket connection uses unencrypted ws:// instead of wss://',
                affected_endpoint=endpoint.url,
                confirmed=True,
                confidence_score=0.95,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['insecure_ws'] += 1
        
        requires_auth, auth_method, auth_info = self.auth_analyzer.analyze_authentication(endpoint, response_content)
        
        if not requires_auth:
            vuln = WebSocketVulnerability(
                vulnerability_type='WebSocket Vulnerability',
                ws_type=WebSocketVulnerabilityType.NO_AUTHENTICATION,
                url=endpoint.url,
                severity='High',
                evidence='WebSocket endpoint does not require authentication',
                affected_endpoint=endpoint.url,
                confirmed=True,
                confidence_score=0.9,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['no_auth_ws'] += 1
        
        sensitive_data_patterns = [
            r'user', r'id', r'password', r'email', r'credit', r'ssn', r'token', r'api'
        ]
        
        if any(pattern in response_content.lower() for pattern in sensitive_data_patterns):
            has_data, data_types = self.message_analyzer.extract_sensitive_data(response_content)
            if has_data:
                vuln = WebSocketVulnerability(
                    vulnerability_type='WebSocket Vulnerability',
                    ws_type=WebSocketVulnerabilityType.DATA_EXPOSURE,
                    url=endpoint.url,
                    severity='Critical',
                    evidence=f'Sensitive data exposure: {", ".join(data_types)}',
                    affected_endpoint=endpoint.url,
                    data_exposed=data_types,
                    confirmed=True,
                    confidence_score=0.85,
                    remediation=self._get_remediation()
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['data_exposure_ws'] += 1
        
        has_injection, injection_types = self.message_analyzer.detect_injection_vectors(response_content)
        if has_injection:
            vuln = WebSocketVulnerability(
                vulnerability_type='WebSocket Vulnerability',
                ws_type=WebSocketVulnerabilityType.MESSAGE_INJECTION,
                url=endpoint.url,
                severity='High',
                evidence=f'Potential injection vectors: {", ".join(injection_types)}',
                affected_endpoint=endpoint.url,
                confirmed=False,
                confidence_score=0.7,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['injection_ws'] += 1
        
        csp_header = response_headers.get('Content-Security-Policy', '')
        if not csp_header:
            vuln = WebSocketVulnerability(
                vulnerability_type='WebSocket Vulnerability',
                ws_type=WebSocketVulnerabilityType.INFORMATION_DISCLOSURE,
                url=endpoint.url,
                severity='Medium',
                evidence='Missing Content-Security-Policy header increases attack surface',
                affected_endpoint=endpoint.url,
                confirmed=True,
                confidence_score=0.8,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['missing_csp_ws'] += 1
        
        return vulnerabilities
    
    def analyze_captured_messages(self, endpoint_url: str, messages: List[WebSocketMessage]) -> Dict:
        analysis = {
            'total_messages': len(messages),
            'message_analysis': {},
            'vulnerabilities_detected': [],
        }
        
        message_texts = [m.content for m in messages]
        msg_analysis = self.message_analyzer.analyze_message_pattern(message_texts)
        analysis['message_analysis'] = msg_analysis
        
        timestamps = [m.timestamp for m in messages]
        if len(timestamps) > 1:
            has_rate_limiting, rate = self.rate_limit_detector.detect_rate_limiting(timestamps)
            analysis['has_rate_limiting'] = has_rate_limiting
            analysis['message_rate'] = rate
        
        with self.lock:
            self.messages_captured[endpoint_url] = messages
        
        return analysis
    
    def _get_remediation(self) -> str:
        return (
            "Use WSS (WebSocket Secure) instead of WS. "
            "Implement strong authentication and authorization. "
            "Validate and sanitize all incoming messages. "
            "Implement rate limiting on WebSocket connections. "
            "Use message encryption for sensitive data. "
            "Implement message signing/integrity checks. "
            "Use same-origin policy checks. "
            "Implement proper access control for all operations. "
            "Monitor WebSocket connections for anomalies. "
            "Implement proper error handling without information disclosure."
        )
    
    def get_discovered_endpoints(self) -> Dict[str, WebSocketEndpoint]:
        with self.lock:
            return self.discovered_endpoints.copy()
    
    def get_vulnerabilities(self) -> List[WebSocketVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_captured_messages(self, endpoint_url: str) -> List[WebSocketMessage]:
        with self.lock:
            return self.messages_captured.get(endpoint_url, []).copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.discovered_endpoints.clear()
            self.vulnerabilities.clear()
            self.messages_captured.clear()
            self.scan_statistics.clear()