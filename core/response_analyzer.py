from typing import Dict, List, Optional, Tuple, Set, Pattern, Any
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict, Counter
import hashlib
from urllib.parse import urlparse, parse_qs
from html.parser import HTMLParser
import json


class ContentType(Enum):
    HTML = "text/html"
    JSON = "application/json"
    XML = "application/xml"
    PLAIN_TEXT = "text/plain"
    FORM_DATA = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    BINARY = "application/octet-stream"
    UNKNOWN = "unknown"


class ResponseQuality(Enum):
    EXCELLENT = 5
    GOOD = 4
    ACCEPTABLE = 3
    POOR = 2
    VERY_POOR = 1


@dataclass
class ContentAnalysis:
    """Analyze HTML content structure and complexity.
    
    Attributes:
        content_type: Detected content type.
        size: Content size in bytes.
        encoding: Character encoding.
        is_compressed: Whether content is compressed.
        has_javascript: Whether content contains scripts.
        has_forms: Whether content contains forms.
        has_comments: Whether content contains comments.
    """
    # Complexity scoring constants
    SIZE_FACTOR = 20
    SIZE_DIVISOR = 1000000
    FORM_MULTIPLIER = 10
    INPUT_MULTIPLIER = 2
    SCRIPT_MULTIPLIER = 15
    STYLE_MULTIPLIER = 5
    LINK_MULTIPLIER = 2
    MAX_SCORE = 100.0
    
    content_type: ContentType
    size: int
    encoding: Optional[str]
    is_compressed: bool
    has_javascript: bool
    has_forms: bool
    has_comments: bool
    form_count: int = 0
    input_count: int = 0
    script_count: int = 0
    style_count: int = 0
    comment_count: int = 0
    link_count: int = 0
    image_count: int = 0
    
    def get_complexity_score(self) -> float:
        """Calculate content complexity score (0-100).
        
        Returns:
            Complexity score based on content structure.
        """
        score = 0.0
        score += min(self.size / self.SIZE_DIVISOR, 1.0) * self.SIZE_FACTOR
        score += self.form_count * self.FORM_MULTIPLIER
        score += self.input_count * self.INPUT_MULTIPLIER
        score += self.script_count * self.SCRIPT_MULTIPLIER
        score += self.style_count * self.STYLE_MULTIPLIER
        score += self.link_count * self.LINK_MULTIPLIER
        return min(score, self.MAX_SCORE)


@dataclass
class HeaderAnalysis:
    """Analyze HTTP response headers for security and caching.
    
    Attributes:
        security_headers: Present security headers.
        missing_security_headers: Missing security headers.
        caching_info: Caching directives.
        compression: Compression method.
        server_info: Server identification.
        set_cookies: Cookie directives.
        cors_headers: CORS configuration.
        custom_headers: Custom headers.
    """
    # Security scoring constants
    INITIAL_SCORE = 100.0
    MIN_SCORE = 0.0
    HSTS_PENALTY = 10
    CSP_PENALTY = 15
    X_CONTENT_TYPE_PENALTY = 10
    X_FRAME_PENALTY = 10
    X_XSS_PENALTY = 10
    HTTPONLY_PENALTY = 5
    
    security_headers: Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)
    caching_info: Dict[str, str] = field(default_factory=dict)
    compression: Optional[str] = None
    server_info: Optional[str] = None
    set_cookies: List[Dict[str, str]] = field(default_factory=list)
    cors_headers: Dict[str, str] = field(default_factory=dict)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    def get_security_score(self) -> float:
        """Calculate security score based on headers (0-100).
        
        Returns:
            Security score.
        """
        score = self.INITIAL_SCORE
        
        critical_headers = {
            'strict-transport-security': self.HSTS_PENALTY,
            'content-security-policy': self.CSP_PENALTY,
            'x-content-type-options': self.X_CONTENT_TYPE_PENALTY,
            'x-frame-options': self.X_FRAME_PENALTY,
            'x-xss-protection': self.X_XSS_PENALTY,
        }
        
        for header, penalty in critical_headers.items():
            if header not in self.security_headers:
                score -= penalty
        
        if 'set-cookie' in [h.lower() for h in self.set_cookies]:
            if not any('httponly' in str(c).lower() for c in self.set_cookies):
                score -= self.HTTPONLY_PENALTY
        
        return max(score, self.MIN_SCORE)


@dataclass
class ResponseAnomaly:
    anomaly_type: str
    severity: str
    description: str
    evidence: str
    confidence: float = 0.8


class HTMLContentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.inputs = []
        self.scripts = []
        self.styles = []
        self.links = []
        self.images = []
        self.comments = []
        self.current_form = None
        self.raw_text = []
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == 'form':
            form_data = {
                'method': attrs_dict.get('method', 'GET').upper(),
                'action': attrs_dict.get('action', ''),
                'enctype': attrs_dict.get('enctype', ''),
                'inputs': []
            }
            self.current_form = form_data
            self.forms.append(form_data)
        
        elif tag == 'input':
            input_data = {
                'name': attrs_dict.get('name', ''),
                'type': attrs_dict.get('type', 'text'),
                'value': attrs_dict.get('value', ''),
                'required': 'required' in attrs,
            }
            self.inputs.append(input_data)
            if self.current_form:
                self.current_form['inputs'].append(input_data)
        
        elif tag == 'textarea':
            textarea_data = {
                'name': attrs_dict.get('name', ''),
                'type': 'textarea',
                'required': 'required' in attrs,
            }
            self.inputs.append(textarea_data)
            if self.current_form:
                self.current_form['inputs'].append(textarea_data)
        
        elif tag == 'select':
            select_data = {
                'name': attrs_dict.get('name', ''),
                'type': 'select',
                'required': 'required' in attrs,
            }
            self.inputs.append(select_data)
            if self.current_form:
                self.current_form['inputs'].append(select_data)
        
        elif tag == 'script':
            self.scripts.append({'src': attrs_dict.get('src', ''), 'inline': False})
        
        elif tag == 'style':
            self.styles.append({'src': attrs_dict.get('src', ''), 'inline': False})
        
        elif tag == 'link':
            self.links.append({
                'rel': attrs_dict.get('rel', ''),
                'href': attrs_dict.get('href', ''),
                'type': attrs_dict.get('type', '')
            })
        
        elif tag == 'img':
            self.images.append({
                'src': attrs_dict.get('src', ''),
                'alt': attrs_dict.get('alt', ''),
                'title': attrs_dict.get('title', '')
            })
    
    def handle_endtag(self, tag):
        if tag == 'form':
            self.current_form = None
    
    def handle_comment(self, data):
        self.comments.append(data.strip())
    
    def handle_data(self, data):
        if data.strip():
            self.raw_text.append(data.strip())
    
    def get_text(self) -> str:
        return ' '.join(self.raw_text)


class ResponseComparator:
    def __init__(self):
        self.baseline: Optional[Dict] = None
        self.comparison_history: List[Dict] = []
    
    def set_baseline(self, response: Dict):
        self.baseline = {
            'content_hash': hashlib.md5(response.get('content', '').encode()).hexdigest(),
            'content_length': len(response.get('content', '')),
            'status_code': response.get('status_code', 0),
        }
    
    def compare_with_baseline(self, response: Dict) -> Dict:
        if not self.baseline:
            return {'has_baseline': False}
        
        current_hash = hashlib.md5(response.get('content', '').encode()).hexdigest()
        current_length = len(response.get('content', ''))
        current_status = response.get('status_code', 0)
        
        comparison = {
            'has_baseline': True,
            'content_changed': current_hash != self.baseline['content_hash'],
            'length_changed': current_length != self.baseline['content_length'],
            'status_changed': current_status != self.baseline['status_code'],
            'size_difference': current_length - self.baseline['content_length'],
            'hash_similarity': self._calculate_hash_similarity(current_hash, self.baseline['content_hash']),
        }
        
        self.comparison_history.append(comparison)
        return comparison
    
    def _calculate_hash_similarity(self, hash1: str, hash2: str) -> float:
        matches = sum(1 for a, b in zip(hash1, hash2) if a == b)
        return (matches / len(hash1)) * 100


class PatternDetector:
    PATTERNS = {
        'error_messages': [
            r'(?i)(error|exception|fatal|warning|notice)',
            r'(?i)(stack trace|traceback|debug)',
            r'(?i)(undefined|null|none)',
        ],
        'database_errors': [
            r'(?i)(sql|database|query|table|column)',
            r'(?i)(mysql|postgresql|oracle|mssql)',
        ],
        'server_info': [
            r'(?i)(apache|nginx|iis|tomcat|node)',
            r'(?i)(server\s*:|powered\s*by:)',
        ],
        'credentials': [
            r'(?i)(password|api[_-]?key|token|secret)',
            r'(?i)(username|email|user[_-]?id)',
        ],
        'sensitive_data': [
            r'(?i)(private|confidential|secret)',
            r'(?i)(ssn|credit[_-]?card|phone)',
        ],
        'injection_signs': [
            r'["\'].*["\'].*or.*["\'].*["\']',
            r'<script|javascript:|onerror=|onclick=',
        ],
        'api_endpoints': [
            r'/api/v\d+/',
            r'/rest/',
            r'/graphql',
        ],
    }
    
    @staticmethod
    def detect_patterns(content: str, pattern_type: str) -> List[Tuple[str, str]]:
        if pattern_type not in PatternDetector.PATTERNS:
            return []
        
        matches = []
        for pattern in PatternDetector.PATTERNS[pattern_type]:
            regex = re.compile(pattern)
            found = regex.findall(content)
            for match in found:
                matches.append((pattern, match if isinstance(match, str) else match[0]))
        
        return matches


class ResponseStatistics:
    def __init__(self):
        self.status_codes: Counter = Counter()
        self.content_types: Counter = Counter()
        self.response_times: List[float] = []
        self.content_sizes: List[int] = []
    
    def add_response(self, status_code: int, content_type: str, response_time: float, content_size: int):
        self.status_codes[status_code] += 1
        self.content_types[content_type] += 1
        self.response_times.append(response_time)
        self.content_sizes.append(content_size)
    
    def get_statistics(self) -> Dict:
        if not self.response_times:
            return {}
        
        return {
            'total_responses': sum(self.status_codes.values()),
            'status_code_distribution': dict(self.status_codes),
            'content_type_distribution': dict(self.content_types),
            'average_response_time': sum(self.response_times) / len(self.response_times),
            'median_response_time': sorted(self.response_times)[len(self.response_times) // 2],
            'min_response_time': min(self.response_times),
            'max_response_time': max(self.response_times),
            'average_content_size': sum(self.content_sizes) / len(self.content_sizes),
            'total_content_size': sum(self.content_sizes),
        }


class ResponseAnalyzer:
    """Comprehensive HTTP response analysis with security and quality scoring."""
    
    # Anomaly detection thresholds
    RESPONSE_TIME_THRESHOLD = 10  # seconds
    MAX_RESPONSE_SIZE = 10000000  # bytes (10MB)
    QUALITY_SCORE_INITIAL = 100.0
    QUALITY_SCORE_FAILED_REQUEST = 20
    QUALITY_SCORE_SLOW_RESPONSE = 10
    QUALITY_SCORE_LARGE_RESPONSE = 15
    QUALITY_MIN = 0.0
    
    # HTTP status code ranges
    HTTP_SUCCESS_MIN = 200
    HTTP_SUCCESS_MAX = 300
    HTTP_REDIRECT_MIN = 300
    HTTP_REDIRECT_MAX = 400
    HTTP_CLIENT_ERROR_MIN = 400
    HTTP_CLIENT_ERROR_MAX = 500
    HTTP_SERVER_ERROR_MIN = 500
    
    def __init__(self):
        """Initialize response analyzer with pattern detector and comparator."""
        self.pattern_detector = PatternDetector()
        self.response_comparator = ResponseComparator()
        self.statistics = ResponseStatistics()
    
    def analyze(self, response: Dict) -> Dict:
        """Perform comprehensive analysis on response.
        
        Args:
            response: Response dictionary with status_code, content, headers, response_time.
            
        Returns:
            Analysis result with basic_info, headers, content, security, anomalies, quality_score.
        """
        return {
            'basic_info': self._analyze_basic_info(response),
            'headers': self._analyze_headers(response.get('headers', {})),
            'content': self._analyze_content(response.get('content', ''), response.get('headers', {})),
            'security': self._analyze_security(response),
            'anomalies': self._detect_anomalies(response),
            'quality_score': self._calculate_quality_score(response),
        }
    
    def _analyze_basic_info(self, response: Dict) -> Dict:
        """Analyze basic response information.
        
        Args:
            response: Response dictionary.
            
        Returns:
            Basic info with status codes, timing, and classification.
        """
        status_code = response.get('status_code', 0)
        return {
            'status_code': status_code,
            'response_time': response.get('response_time', 0),
            'content_length': len(response.get('content', '')),
            'is_successful': self.HTTP_SUCCESS_MIN <= status_code < self.HTTP_SUCCESS_MAX,
            'is_redirect': self.HTTP_REDIRECT_MIN <= status_code < self.HTTP_REDIRECT_MAX,
            'is_client_error': self.HTTP_CLIENT_ERROR_MIN <= status_code < self.HTTP_CLIENT_ERROR_MAX,
            'is_server_error': status_code >= self.HTTP_SERVER_ERROR_MIN,
        }
    
    def _analyze_headers(self, headers: Dict) -> Dict:
        analysis = HeaderAnalysis()
        
        security_headers = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-frame-options': 'X-Frame-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
        }
        
        for header_name, display_name in security_headers.items():
            if header_name in {k.lower() for k in headers.keys()}:
                for k, v in headers.items():
                    if k.lower() == header_name:
                        analysis.security_headers[display_name] = v
            else:
                analysis.missing_security_headers.append(display_name)
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        if 'cache-control' in headers_lower:
            analysis.caching_info['cache_control'] = headers_lower['cache-control']
        if 'expires' in headers_lower:
            analysis.caching_info['expires'] = headers_lower['expires']
        if 'etag' in headers_lower:
            analysis.caching_info['etag'] = headers_lower['etag']
        
        if 'content-encoding' in headers_lower:
            analysis.compression = headers_lower['content-encoding']
        
        if 'server' in headers_lower:
            analysis.server_info = headers_lower['server']
        
        if 'set-cookie' in headers_lower:
            cookies = headers_lower['set-cookie'] if isinstance(headers_lower['set-cookie'], list) else [headers_lower['set-cookie']]
            for cookie in cookies:
                analysis.set_cookies.append({'cookie': cookie})
        
        cors_related = ['access-control-allow-origin', 'access-control-allow-methods', 
                       'access-control-allow-headers', 'access-control-allow-credentials']
        for header in cors_related:
            if header in headers_lower:
                analysis.cors_headers[header] = headers_lower[header]
        
        custom = {k: v for k, v in headers_lower.items() 
                 if k not in security_headers and k not in cors_related and 
                 k not in ['cache-control', 'expires', 'etag', 'content-encoding', 'server', 'set-cookie']}
        analysis.custom_headers = custom
        
        return {
            'security_headers': analysis.security_headers,
            'missing_security_headers': analysis.missing_security_headers,
            'caching_info': analysis.caching_info,
            'compression': analysis.compression,
            'server_info': analysis.server_info,
            'set_cookies': analysis.set_cookies,
            'cors_headers': analysis.cors_headers,
            'custom_headers': analysis.custom_headers,
            'security_score': analysis.get_security_score(),
        }
    
    def _analyze_content(self, content: str, headers: Dict) -> Dict:
        content_type = self._determine_content_type(content, headers)
        
        if content_type == ContentType.HTML or content_type == ContentType.UNKNOWN:
            return self._analyze_html_content(content)
        elif content_type == ContentType.JSON:
            return self._analyze_json_content(content)
        elif content_type == ContentType.XML:
            return self._analyze_xml_content(content)
        else:
            return self._analyze_plain_content(content)
    
    def _determine_content_type(self, content: str, headers: Dict) -> ContentType:
        content_type_header = headers.get('Content-Type', '').lower()
        
        if 'application/json' in content_type_header:
            return ContentType.JSON
        elif 'application/xml' in content_type_header or 'text/xml' in content_type_header:
            return ContentType.XML
        elif 'text/html' in content_type_header:
            return ContentType.HTML
        elif 'text/plain' in content_type_header:
            return ContentType.PLAIN_TEXT
        
        if content.strip().startswith('{') or content.strip().startswith('['):
            return ContentType.JSON
        elif content.strip().startswith('<'):
            return ContentType.HTML
        
        return ContentType.UNKNOWN
    
    def _analyze_html_content(self, content: str) -> Dict:
        try:
            parser = HTMLContentParser()
            parser.feed(content)
            
            analysis = ContentAnalysis(
                content_type=ContentType.HTML,
                size=len(content),
                encoding=self._extract_encoding(content),
                is_compressed=False,
                has_javascript=len(parser.scripts) > 0,
                has_forms=len(parser.forms) > 0,
                has_comments=len(parser.comments) > 0,
                form_count=len(parser.forms),
                input_count=len(parser.inputs),
                script_count=len(parser.scripts),
                style_count=len(parser.styles),
                comment_count=len(parser.comments),
                link_count=len(parser.links),
                image_count=len(parser.images),
            )
            
            return {
                'content_type': ContentType.HTML.value,
                'size': analysis.size,
                'encoding': analysis.encoding,
                'forms': parser.forms,
                'inputs': parser.inputs,
                'scripts': parser.scripts,
                'styles': parser.styles,
                'links': parser.links,
                'images': parser.images,
                'comments': parser.comments,
                'text_preview': parser.get_text()[:200],
                'complexity_score': analysis.get_complexity_score(),
            }
        except Exception as e:
            import logging
            logging.debug(f"HTML parsing error: {e}")
            return {
                'content_type': ContentType.HTML.value,
                'size': len(content),
                'parsing_error': True,
            }
    
    def _analyze_json_content(self, content: str) -> Dict:
        try:
            data = json.loads(content)
            
            def count_keys(obj, depth=0):
                if depth > 10:
                    return 0
                if isinstance(obj, dict):
                    return len(obj) + sum(count_keys(v, depth + 1) for v in obj.values())
                elif isinstance(obj, list):
                    return sum(count_keys(item, depth + 1) for item in obj)
                return 0
            
            return {
                'content_type': ContentType.JSON.value,
                'size': len(content),
                'valid_json': True,
                'structure': str(type(data)),
                'key_count': count_keys(data),
                'preview': str(data)[:200],
            }
        except (json.JSONDecodeError, ValueError) as e:
            import logging
            logging.debug(f"JSON parsing error: {e}")
            return {
                'content_type': ContentType.JSON.value,
                'size': len(content),
                'valid_json': False,
                'error': 'Invalid JSON',
            }
    
    def _analyze_xml_content(self, content: str) -> Dict:
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            
            def count_elements(elem):
                return 1 + sum(count_elements(child) for child in elem)
            
            return {
                'content_type': ContentType.XML.value,
                'size': len(content),
                'valid_xml': True,
                'root_tag': root.tag,
                'element_count': count_elements(root),
                'has_dtd': '<!DOCTYPE' in content.upper(),
            }
        except Exception as e:
            import logging
            logging.debug(f"XML parsing error: {e}")
            return {
                'content_type': ContentType.XML.value,
                'size': len(content),
                'valid_xml': False,
                'error': 'Invalid XML',
            }
    
    def _analyze_plain_content(self, content: str) -> Dict:
        lines = content.split('\n')
        
        return {
            'content_type': ContentType.PLAIN_TEXT.value,
            'size': len(content),
            'line_count': len(lines),
            'preview': content[:200],
        }
    
    def _extract_encoding(self, content: str) -> Optional[str]:
        match = re.search(r'charset=([^\s;]+)', content, re.IGNORECASE)
        return match.group(1) if match else None
    
    def _analyze_security(self, response: Dict) -> Dict:
        content = response.get('content', '').lower()
        
        security_findings = {
            'has_error_messages': bool(self.pattern_detector.detect_patterns(content, 'error_messages')),
            'has_database_errors': bool(self.pattern_detector.detect_patterns(content, 'database_errors')),
            'has_server_info': bool(self.pattern_detector.detect_patterns(content, 'server_info')),
            'has_credentials': bool(self.pattern_detector.detect_patterns(content, 'credentials')),
            'has_sensitive_data': bool(self.pattern_detector.detect_patterns(content, 'sensitive_data')),
            'has_injection_signs': bool(self.pattern_detector.detect_patterns(content, 'injection_signs')),
            'error_patterns': self.pattern_detector.detect_patterns(content, 'error_messages'),
            'database_errors': self.pattern_detector.detect_patterns(content, 'database_errors'),
            'server_info': self.pattern_detector.detect_patterns(content, 'server_info'),
        }
        
        return security_findings
    
    def _detect_anomalies(self, response: Dict) -> List[Dict]:
        """Detect anomalies in response.
        
        Args:
            response: Response dictionary.
            
        Returns:
            List of detected anomalies with type, severity, description.
        """
        anomalies = []
        
        # Check response time
        if response.get('response_time', 0) > self.RESPONSE_TIME_THRESHOLD:
            anomalies.append({
                'type': 'slow_response',
                'severity': 'medium',
                'description': f'Response time {response.get("response_time")}s exceeds threshold of {self.RESPONSE_TIME_THRESHOLD}s',
            })
        
        # Check for no response
        if response.get('status_code', 0) == 0:
            anomalies.append({
                'type': 'no_response',
                'severity': 'high',
                'description': 'No response received from server',
            })
        
        # Check for not found
        if response.get('status_code', 0) == 404:
            anomalies.append({
                'type': 'not_found',
                'severity': 'low',
                'description': 'Resource not found',
            })
        
        # Check for server errors
        if response.get('status_code', 0) >= self.HTTP_SERVER_ERROR_MIN:
            anomalies.append({
                'type': 'server_error',
                'severity': 'high',
                'description': f'Server error: {response.get("status_code")}',
            })
        
        # Check for large response
        content_size = len(response.get('content', ''))
        if content_size > self.MAX_RESPONSE_SIZE:
            anomalies.append({
                'type': 'large_response',
                'severity': 'medium',
                'description': f'Response size {content_size} bytes exceeds threshold of {self.MAX_RESPONSE_SIZE} bytes',
            })
        
        return anomalies
    
    def _calculate_quality_score(self, response: Dict) -> Dict:
        score = 100.0
        
        if not (200 <= response.get('status_code', 0) < 300):
            score -= 20
        
        if response.get('response_time', 0) > 5:
            score -= 10
        
        content_size = len(response.get('content', ''))
        if content_size == 0:
            score -= 50
        elif content_size > 10000000:
            score -= 15
        
        return {
            'overall_score': max(score, 0),
            'quality_level': ResponseQuality(max(1, min(5, int(score / 20)))).name,
        }
    
    def compare_responses(self, baseline: Dict, current: Dict) -> Dict:
        self.response_comparator.set_baseline(baseline)
        return self.response_comparator.compare_with_baseline(current)
    
    def get_statistics_summary(self) -> Dict:
        return self.statistics.get_statistics()