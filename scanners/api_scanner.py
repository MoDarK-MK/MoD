from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import json


class APIVulnerabilityType(Enum):
    BROKEN_AUTHENTICATION = "broken_authentication"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    INSUFFICIENT_ACCESS_CONTROL = "insufficient_access_control"
    IMPROPER_ENCRYPTION = "improper_encryption"
    INJECTION = "injection"
    RATE_LIMITING_MISSING = "rate_limiting_missing"
    VERSIONING_EXPOSURE = "versioning_exposure"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    API_KEY_HARDCODED = "api_key_hardcoded"


class AuthenticationMethod(Enum):
    NONE = "none"
    BASIC_AUTH = "basic_auth"
    BEARER_TOKEN = "bearer_token"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    MTLS = "mtls"
    CUSTOM = "custom"


class APIEndpointType(Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    SOAP = "soap"
    WEBHOOK = "webhook"
    GRPC = "grpc"
    JSONRPC = "jsonrpc"


@dataclass
class APIEndpoint:
    path: str
    method: str
    endpoint_type: APIEndpointType
    parameters: List[str] = field(default_factory=list)
    required_auth: bool = False
    auth_method: AuthenticationMethod = AuthenticationMethod.NONE
    returns_sensitive_data: bool = False
    is_admin_endpoint: bool = False
    rate_limited: bool = False
    uses_https: bool = True
    discovered_at: float = field(default_factory=time.time)


@dataclass
class APIVulnerability:
    vulnerability_type: str
    api_type: APIVulnerabilityType
    url: str
    endpoint_path: str
    http_method: str
    severity: str
    evidence: str
    response_status: int
    response_size: int
    auth_required: bool
    auth_bypassed: bool = False
    sensitive_data_exposed: Optional[List[str]] = None
    rate_limit_status: Optional[str] = None
    endpoint_parameters: List[str] = field(default_factory=list)
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class APIEndpointDiscovery:
    COMMON_API_PATHS = [
        '/api/v1/', '/api/v2/', '/api/v3/',
        '/rest/api/', '/rest/api/v1/',
        '/graphql',
        '/ws/', '/websocket/',
        '/rpc/', '/jsonrpc/',
        '/.well-known/openapi.json',
        '/.well-known/swagger.json',
        '/swagger.json', '/swagger.yaml',
        '/openapi.json', '/openapi.yaml',
        '/api-docs', '/api/docs',
        '/admin/', '/api/admin/',
        '/internal/', '/api/internal/',
    ]
    
    @staticmethod
    def discover_endpoints(response_content: str, base_url: str) -> List[APIEndpoint]:
        endpoints = []
        
        api_pattern = r'(["\']?)(/api/[a-zA-Z0-9/_-]+)\1'
        matches = re.findall(api_pattern, response_content)
        
        for match in matches:
            path = match[1] if isinstance(match, tuple) else match
            endpoint = APIEndpoint(
                path=path,
                method='GET',
                endpoint_type=APIEndpointType.REST
            )
            endpoints.append(endpoint)
        
        graphql_pattern = r'(query|mutation|subscription)\s*{[^}]*}'
        if re.search(graphql_pattern, response_content):
            endpoints.append(APIEndpoint(
                path='/graphql',
                method='POST',
                endpoint_type=APIEndpointType.GRAPHQL
            ))
        
        return endpoints
    
    @staticmethod
    def extract_parameters_from_endpoint(endpoint_path: str) -> List[str]:
        param_pattern = r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}|:([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(param_pattern, endpoint_path)
        return [m[0] or m[1] for m in matches]


class AuthenticationAnalyzer:
    @staticmethod
    def detect_authentication_method(response_headers: Dict, response_content: str) -> AuthenticationMethod:
        auth_header = response_headers.get('Authorization', '')
        www_authenticate = response_headers.get('WWW-Authenticate', '').lower()
        
        if 'bearer' in auth_header.lower():
            return AuthenticationMethod.BEARER_TOKEN
        elif 'basic' in auth_header.lower():
            return AuthenticationMethod.BASIC_AUTH
        elif 'digest' in www_authenticate:
            return AuthenticationMethod.BASIC_AUTH
        elif 'bearer' in www_authenticate:
            return AuthenticationMethod.BEARER_TOKEN
        
        if 'x-api-key' in response_headers or 'api-key' in response_headers or 'apikey' in response_headers:
            return AuthenticationMethod.API_KEY
        
        if 'x-api-key' in response_content.lower() or 'api_key' in response_content.lower():
            return AuthenticationMethod.API_KEY
        
        return AuthenticationMethod.NONE
    
    @staticmethod
    def detect_auth_bypass(unauthorized_response: str, authenticated_response: str) -> Tuple[bool, float]:
        if len(unauthorized_response) != len(authenticated_response):
            return True, 0.7
        
        unauthorized_hash = hash(unauthorized_response)
        authenticated_hash = hash(authenticated_response)
        
        if unauthorized_hash == authenticated_hash:
            return True, 0.9
        
        return False, 0.0


class DataExposureAnalyzer:
    SENSITIVE_PATTERNS = {
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'api_key': r'(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?',
        'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s,;]+)["\']?',
        'token': r'(?i)(token|auth|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9._-]+)["\']?',
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'private_key': r'-----BEGIN PRIVATE KEY-----',
        'database_uri': r'(?i)(mongodb|mysql|postgresql|redis):\/\/[^\/]+',
    }
    
    @staticmethod
    def analyze_response_data(response_content: str) -> Tuple[bool, List[str], Dict]:
        exposed_data = []
        findings = defaultdict(list)
        
        try:
            data = json.loads(response_content)
            response_str = json.dumps(data)
        except:
            response_str = response_content
        
        for data_type, pattern in DataExposureAnalyzer.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, response_str)
            if matches:
                exposed_data.append(data_type)
                findings[data_type] = matches[:3]
        
        return len(exposed_data) > 0, exposed_data, dict(findings)


class RateLimitingAnalyzer:
    RATE_LIMIT_HEADERS = [
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset',
        'RateLimit-Limit',
        'RateLimit-Remaining',
        'RateLimit-Reset',
        'X-Rate-Limit-Limit',
    ]
    
    @staticmethod
    def detect_rate_limiting(response_headers: Dict) -> Tuple[bool, Optional[Dict]]:
        rate_limit_info = {}
        
        for header in RateLimitingAnalyzer.RATE_LIMIT_HEADERS:
            for key, value in response_headers.items():
                if key.lower() == header.lower():
                    rate_limit_info[header] = value
        
        if rate_limit_info:
            return True, rate_limit_info
        
        if response_headers.get('Retry-After'):
            return True, {'Retry-After': response_headers.get('Retry-After')}
        
        return False, None
    
    @staticmethod
    def detect_missing_rate_limiting(responses: List[Dict]) -> Tuple[bool, int]:
        if len(responses) < 10:
            return False, 0
        
        success_responses = sum(1 for r in responses if r.get('status_code') == 200)
        
        if success_responses == len(responses):
            return True, len(responses)
        
        return False, 0


class CORSAnalyzer:
    @staticmethod
    def analyze_cors_policy(response_headers: Dict) -> Tuple[bool, List[str]]:
        cors_issues = []
        
        allow_origin = response_headers.get('Access-Control-Allow-Origin', '')
        
        if allow_origin == '*':
            cors_issues.append('Wildcard CORS policy allows any origin')
        
        if allow_origin.lower() == 'null':
            cors_issues.append('Null origin accepted - vulnerable to file:// protocol')
        
        if not allow_origin:
            return False, []
        
        allow_methods = response_headers.get('Access-Control-Allow-Methods', '')
        if 'DELETE' in allow_methods and 'PUT' in allow_methods:
            cors_issues.append('Dangerous HTTP methods allowed via CORS')
        
        allow_headers = response_headers.get('Access-Control-Allow-Headers', '')
        if allow_headers == '*':
            cors_issues.append('Wildcard in Access-Control-Allow-Headers')
        
        credentials = response_headers.get('Access-Control-Allow-Credentials', '')
        if credentials.lower() == 'true' and (allow_origin == '*' or allow_origin.lower() == 'null'):
            cors_issues.append('CORS credentials allowed with permissive origin policy')
        
        return len(cors_issues) > 0, cors_issues


class GraphQLAnalyzer:
    @staticmethod
    def detect_graphql_endpoint(response_content: str, response_headers: Dict) -> bool:
        if 'application/json' in response_headers.get('Content-Type', ''):
            if 'errors' in response_content or '__typename' in response_content:
                return True
        
        if '{"data"' in response_content or 'query' in response_content.lower():
            return True
        
        return False
    
    @staticmethod
    def detect_introspection_enabled(response_content: str) -> bool:
        introspection_keywords = [
            '__schema',
            '__type',
            '__typename',
            'queryType',
            'mutationType',
            'subscriptionType',
        ]
        
        return any(keyword in response_content for keyword in introspection_keywords)
    
    @staticmethod
    def extract_graphql_fields(response_content: str) -> List[str]:
        fields = []
        
        field_pattern = r'"name"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]*)"'
        fields.extend(re.findall(field_pattern, response_content))
        
        return list(set(fields))


class APIVersioningAnalyzer:
    VERSION_PATTERNS = [
        r'/api/v(\d+(?:\.\d+)?)',
        r'/v(\d+(?:\.\d+)?)/api',
        r'version=(\d+(?:\.\d+)?)',
        r'api-version:\s*(\d+(?:\.\d+)?)',
    ]
    
    @staticmethod
    def detect_api_versions(urls: List[str], headers: Dict) -> List[str]:
        versions = set()
        
        all_text = '\n'.join(urls) + '\n' + str(headers)
        
        for pattern in APIVersioningAnalyzer.VERSION_PATTERNS:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            versions.update(matches)
        
        return sorted(list(versions))
    
    @staticmethod
    def detect_version_exposure(response_headers: Dict, response_content: str) -> Tuple[bool, Optional[str]]:
        version_headers = ['API-Version', 'X-API-Version', 'X-Version', 'Server']
        
        for header in version_headers:
            for key, value in response_headers.items():
                if key.lower() == header.lower():
                    return True, value
        
        version_pattern = r'(?i)version\s*[:=]\s*["\']?(\d+\.\d+\.\d+)["\']?'
        match = re.search(version_pattern, response_content)
        if match:
            return True, match.group(1)
        
        return False, None


class APIScanner:
    def __init__(self):
        self.endpoint_discovery = APIEndpointDiscovery()
        self.auth_analyzer = AuthenticationAnalyzer()
        self.data_analyzer = DataExposureAnalyzer()
        self.rate_limit_analyzer = RateLimitingAnalyzer()
        self.cors_analyzer = CORSAnalyzer()
        self.graphql_analyzer = GraphQLAnalyzer()
        self.version_analyzer = APIVersioningAnalyzer()
        
        self.vulnerabilities: List[APIVulnerability] = []
        self.discovered_endpoints: List[APIEndpoint] = []
        self.scan_statistics = defaultdict(int)
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict) -> List[APIVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_headers = response.get('headers', {})
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        endpoints = self.endpoint_discovery.discover_endpoints(response_content, target_url)
        with self.lock:
            self.discovered_endpoints.extend(endpoints)
        
        auth_method = self.auth_analyzer.detect_authentication_method(response_headers, response_content)
        
        if auth_method == AuthenticationMethod.NONE and status_code == 200:
            vuln = APIVulnerability(
                vulnerability_type='API Vulnerability',
                api_type=APIVulnerabilityType.BROKEN_AUTHENTICATION,
                url=target_url,
                endpoint_path=target_url,
                http_method='GET',
                severity='High',
                evidence='No authentication method detected',
                response_status=status_code,
                response_size=len(response_content),
                auth_required=False,
                auth_bypassed=True,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['no_auth'] += 1
        
        data_exposed, exposed_types, findings = self.data_analyzer.analyze_response_data(response_content)
        if data_exposed:
            vuln = APIVulnerability(
                vulnerability_type='API Vulnerability',
                api_type=APIVulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                url=target_url,
                endpoint_path=target_url,
                http_method='GET',
                severity='Critical',
                evidence=f'Sensitive data exposed: {", ".join(exposed_types)}',
                response_status=status_code,
                response_size=len(response_content),
                sensitive_data_exposed=exposed_types,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['data_exposure'] += 1
        
        rate_limited, rate_info = self.rate_limit_analyzer.detect_rate_limiting(response_headers)
        if not rate_limited and status_code == 200:
            vuln = APIVulnerability(
                vulnerability_type='API Vulnerability',
                api_type=APIVulnerabilityType.RATE_LIMITING_MISSING,
                url=target_url,
                endpoint_path=target_url,
                http_method='GET',
                severity='Medium',
                evidence='No rate limiting headers detected',
                response_status=status_code,
                response_size=len(response_content),
                rate_limit_status='Missing',
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['no_rate_limit'] += 1
        
        cors_issue, cors_problems = self.cors_analyzer.analyze_cors_policy(response_headers)
        if cors_issue:
            vuln = APIVulnerability(
                vulnerability_type='API Vulnerability',
                api_type=APIVulnerabilityType.CORS_MISCONFIGURATION,
                url=target_url,
                endpoint_path=target_url,
                http_method='GET',
                severity='High',
                evidence=f'CORS issues: {"; ".join(cors_problems)}',
                response_status=status_code,
                response_size=len(response_content),
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['cors_issue'] += 1
        
        is_graphql = self.graphql_analyzer.detect_graphql_endpoint(response_content, response_headers)
        if is_graphql:
            introspection = self.graphql_analyzer.detect_introspection_enabled(response_content)
            if introspection:
                fields = self.graphql_analyzer.extract_graphql_fields(response_content)
                vuln = APIVulnerability(
                    vulnerability_type='API Vulnerability',
                    api_type=APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
                    url=target_url,
                    endpoint_path='/graphql',
                    http_method='POST',
                    severity='High',
                    evidence=f'GraphQL introspection enabled, fields exposed: {", ".join(fields[:5])}',
                    response_status=status_code,
                    response_size=len(response_content),
                    endpoint_parameters=fields,
                    confirmed=True,
                    remediation=self._get_remediation()
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['graphql_introspection'] += 1
        
        version_exposed, version = self.version_analyzer.detect_version_exposure(response_headers, response_content)
        if version_exposed:
            vuln = APIVulnerability(
                vulnerability_type='API Vulnerability',
                api_type=APIVulnerabilityType.VERSIONING_EXPOSURE,
                url=target_url,
                endpoint_path=target_url,
                http_method='GET',
                severity='Low',
                evidence=f'API version exposed: {version}',
                response_status=status_code,
                response_size=len(response_content),
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['version_exposure'] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _get_remediation(self) -> str:
        return (
            "Implement strong authentication (OAuth2, JWT, mTLS). "
            "Validate and sanitize all API inputs. "
            "Implement proper authorization checks. "
            "Use HTTPS with TLS 1.2+. "
            "Implement rate limiting and throttling. "
            "Hide API version information. "
            "Disable GraphQL introspection in production. "
            "Remove sensitive data from API responses. "
            "Implement CORS restrictions. "
            "Monitor API usage for anomalies. "
            "Implement API versioning and deprecation."
        )
    
    def get_vulnerabilities(self) -> List[APIVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_discovered_endpoints(self) -> List[APIEndpoint]:
        with self.lock:
            return self.discovered_endpoints.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.discovered_endpoints.clear()
            self.scan_statistics.clear()