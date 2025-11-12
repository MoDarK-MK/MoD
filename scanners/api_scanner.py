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
        '/api/v1/', '/api/v2/', '/api/v3/', '/api/v4/', '/api/v5/',
        '/rest/api/', '/rest/api/v1/', '/rest/api/v2/',
        '/graphql', '/graphql/v1',
        '/ws/', '/websocket/', '/socket.io/',
        '/rpc/', '/jsonrpc/', '/xmlrpc/',
        '/.well-known/openapi.json', '/.well-known/swagger.json',
        '/swagger.json', '/swagger.yaml', '/swagger-ui.html',
        '/openapi.json', '/openapi.yaml', '/openapi.yml',
        '/api-docs', '/api/docs', '/docs', '/documentation',
        '/admin/', '/api/admin/', '/admin/api/',
        '/internal/', '/api/internal/', '/private/',
        '/v1/', '/v2/', '/v3/',
    ]
    
    _api_pattern = re.compile(r'(["\']?)(/(?:api|rest|graphql|rpc|ws|v\d+)/[a-zA-Z0-9/_\-\.]+)\1')
    _graphql_pattern = re.compile(r'(query|mutation|subscription|__schema|__type)\s*[{(]')
    _param_pattern = re.compile(r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}|:([a-zA-Z_][a-zA-Z0-9_]*)')
    _json_endpoint_pattern = re.compile(r'"(?:url|endpoint|path)"\s*:\s*"([^"]+)"')
    
    @staticmethod
    def discover_endpoints(response_content: str, base_url: str) -> List[APIEndpoint]:
        endpoints = []
        seen = set()
        
        matches = APIEndpointDiscovery._api_pattern.findall(response_content)
        for match in matches:
            path = match[1] if isinstance(match, tuple) else match
            if path not in seen:
                seen.add(path)
                endpoint = APIEndpoint(
                    path=path,
                    method='GET',
                    endpoint_type=APIEndpointType.REST,
                    parameters=APIEndpointDiscovery.extract_parameters_from_endpoint(path)
                )
                endpoints.append(endpoint)
        
        json_matches = APIEndpointDiscovery._json_endpoint_pattern.findall(response_content)
        for path in json_matches:
            if path.startswith('/') and path not in seen:
                seen.add(path)
                endpoints.append(APIEndpoint(
                    path=path,
                    method='GET',
                    endpoint_type=APIEndpointType.REST,
                    parameters=APIEndpointDiscovery.extract_parameters_from_endpoint(path)
                ))
        
        if APIEndpointDiscovery._graphql_pattern.search(response_content):
            if '/graphql' not in seen:
                endpoints.append(APIEndpoint(
                    path='/graphql',
                    method='POST',
                    endpoint_type=APIEndpointType.GRAPHQL
                ))
        
        return endpoints
    
    @staticmethod
    def extract_parameters_from_endpoint(endpoint_path: str) -> List[str]:
        matches = APIEndpointDiscovery._param_pattern.findall(endpoint_path)
        return [m[0] or m[1] for m in matches]


class AuthenticationAnalyzer:
    @staticmethod
    def detect_authentication_method(response_headers: Dict, response_content: str) -> AuthenticationMethod:
        auth_header = response_headers.get('Authorization', '').lower()
        www_authenticate = response_headers.get('WWW-Authenticate', '').lower()
        
        if 'bearer' in auth_header or 'bearer' in www_authenticate:
            return AuthenticationMethod.BEARER_TOKEN
        if 'basic' in auth_header or 'basic' in www_authenticate or 'digest' in www_authenticate:
            return AuthenticationMethod.BASIC_AUTH
        
        for key in response_headers:
            key_lower = key.lower()
            if 'api' in key_lower and 'key' in key_lower:
                return AuthenticationMethod.API_KEY
        
        content_lower = response_content.lower()
        if 'api_key' in content_lower or 'x-api-key' in content_lower or 'apikey' in content_lower:
            return AuthenticationMethod.API_KEY
        
        if 'jwt' in content_lower or 'jsonwebtoken' in content_lower:
            return AuthenticationMethod.JWT
        
        if 'oauth' in content_lower or 'oauth2' in content_lower:
            return AuthenticationMethod.OAUTH2
        
        return AuthenticationMethod.NONE
    
    @staticmethod
    def detect_auth_bypass(unauthorized_response: str, authenticated_response: str) -> Tuple[bool, float]:
        len_diff = abs(len(unauthorized_response) - len(authenticated_response))
        
        if len_diff > 100:
            return True, 0.7
        
        if hash(unauthorized_response) == hash(authenticated_response):
            return True, 0.9
        
        similarity = len(set(unauthorized_response) & set(authenticated_response)) / max(len(set(unauthorized_response)), len(set(authenticated_response)))
        if similarity > 0.95:
            return True, 0.85
        
        return False, 0.0


class DataExposureAnalyzer:
    SENSITIVE_PATTERNS = {
        'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'api_key': re.compile(r'(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
        'password': re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s,;]{4,})["\']?'),
        'token': re.compile(r'(?i)(token|auth|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9._\-]{20,})["\']?'),
        'email': re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'),
        'private_key': re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----'),
        'database_uri': re.compile(r'(?i)(mongodb|mysql|postgresql|redis|sqlite):\/\/[^\s\'"]+'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'jwt': re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
        'phone': re.compile(r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b'),
        'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    }
    
    @staticmethod
    def analyze_response_data(response_content: str) -> Tuple[bool, List[str], Dict]:
        exposed_data = []
        findings = {}
        
        for data_type, pattern in DataExposureAnalyzer.SENSITIVE_PATTERNS.items():
            matches = pattern.findall(response_content)
            if matches:
                exposed_data.append(data_type)
                findings[data_type] = matches[:3]
        
        return len(exposed_data) > 0, exposed_data, findings


class RateLimitingAnalyzer:
    RATE_LIMIT_HEADERS = frozenset([
        'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
        'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset',
        'x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset',
        'retry-after', 'x-retry-after'
    ])
    
    @staticmethod
    def detect_rate_limiting(response_headers: Dict) -> Tuple[bool, Optional[Dict]]:
        rate_limit_info = {}
        
        for key in response_headers:
            if key.lower() in RateLimitingAnalyzer.RATE_LIMIT_HEADERS:
                rate_limit_info[key] = response_headers[key]
        
        return bool(rate_limit_info), rate_limit_info if rate_limit_info else None
    
    @staticmethod
    def detect_missing_rate_limiting(responses: List[Dict]) -> Tuple[bool, int]:
        if len(responses) < 5:
            return False, 0
        
        success_responses = sum(1 for r in responses if r.get('status_code') == 200)
        
        if success_responses >= len(responses) * 0.9:
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
        dangerous_methods = {'DELETE', 'PUT', 'PATCH', 'TRACE', 'CONNECT'}
        if any(method in allow_methods for method in dangerous_methods):
            cors_issues.append('Dangerous HTTP methods allowed via CORS')
        
        allow_headers = response_headers.get('Access-Control-Allow-Headers', '')
        if allow_headers == '*':
            cors_issues.append('Wildcard in Access-Control-Allow-Headers')
        
        credentials = response_headers.get('Access-Control-Allow-Credentials', '')
        if credentials.lower() == 'true' and (allow_origin == '*' or allow_origin.lower() == 'null'):
            cors_issues.append('CORS credentials allowed with permissive origin policy')
        
        max_age = response_headers.get('Access-Control-Max-Age', '')
        if max_age and int(max_age) > 86400:
            cors_issues.append('Excessive CORS preflight cache duration')
        
        return len(cors_issues) > 0, cors_issues


class GraphQLAnalyzer:
    _introspection_keywords = frozenset(['__schema', '__type', '__typename', 'queryType', 'mutationType', 'subscriptionType', '__Field', '__InputValue'])
    _field_pattern = re.compile(r'"(?:name|kind)"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]*)"')
    _mutation_pattern = re.compile(r'mutation\s+(\w+)')
    
    @staticmethod
    def detect_graphql_endpoint(response_content: str, response_headers: Dict) -> bool:
        content_type = response_headers.get('Content-Type', '')
        
        if 'application/json' in content_type:
            if any(keyword in response_content for keyword in ['errors', '__typename', 'data', 'query']):
                return True
        
        if '{"data"' in response_content or '"query"' in response_content or '"mutation"' in response_content:
            return True
        
        return False
    
    @staticmethod
    def detect_introspection_enabled(response_content: str) -> bool:
        return any(keyword in response_content for keyword in GraphQLAnalyzer._introspection_keywords)
    
    @staticmethod
    def extract_graphql_fields(response_content: str) -> List[str]:
        fields = list(set(GraphQLAnalyzer._field_pattern.findall(response_content)))
        return fields
    
    @staticmethod
    def detect_mutations(response_content: str) -> List[str]:
        return list(set(GraphQLAnalyzer._mutation_pattern.findall(response_content)))


class APIVersioningAnalyzer:
    _version_patterns = [
        re.compile(r'/api/v(\d+(?:\.\d+)?)'),
        re.compile(r'/v(\d+(?:\.\d+)?)/'),
        re.compile(r'version[=:](\d+(?:\.\d+)?)'),
        re.compile(r'api-version[:\s]+(\d+(?:\.\d+)?)'),
    ]
    _version_content_pattern = re.compile(r'(?i)(?:version|ver|v)["\s:=]+(\d+(?:\.\d+){0,2})')
    
    @staticmethod
    def detect_api_versions(urls: List[str], headers: Dict) -> List[str]:
        versions = set()
        all_text = '\n'.join(urls) + '\n' + str(headers)
        
        for pattern in APIVersioningAnalyzer._version_patterns:
            versions.update(pattern.findall(all_text))
        
        return sorted(list(versions), reverse=True)
    
    @staticmethod
    def detect_version_exposure(response_headers: Dict, response_content: str) -> Tuple[bool, Optional[str]]:
        version_headers = {'api-version', 'x-api-version', 'x-version', 'server', 'x-powered-by'}
        
        for key, value in response_headers.items():
            if key.lower() in version_headers:
                return True, value
        
        match = APIVersioningAnalyzer._version_content_pattern.search(response_content[:2000])
        if match:
            return True, match.group(1)
        
        return False, None


class APIScanner:
    _remediation_cache = (
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
        if endpoints:
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
                confidence_score=0.9,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
        
        data_exposed, exposed_types, findings = self.data_analyzer.analyze_response_data(response_content)
        if data_exposed:
            vuln = APIVulnerability(
                vulnerability_type='API Vulnerability',
                api_type=APIVulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                url=target_url,
                endpoint_path=target_url,
                http_method='GET',
                severity='Critical',
                evidence=f'Sensitive data exposed: {", ".join(exposed_types)} - Examples: {str(findings)[:200]}',
                response_status=status_code,
                response_size=len(response_content),
                sensitive_data_exposed=exposed_types,
                auth_required=False,
                confirmed=True,
                confidence_score=0.95,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
        
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
                auth_required=False,
                rate_limit_status='Missing',
                confirmed=True,
                confidence_score=0.75,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
        
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
                auth_required=False,
                confirmed=True,
                confidence_score=0.9,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
        
        is_graphql = self.graphql_analyzer.detect_graphql_endpoint(response_content, response_headers)
        if is_graphql:
            introspection = self.graphql_analyzer.detect_introspection_enabled(response_content)
            if introspection:
                fields = self.graphql_analyzer.extract_graphql_fields(response_content)
                mutations = self.graphql_analyzer.detect_mutations(response_content)
                vuln = APIVulnerability(
                    vulnerability_type='API Vulnerability',
                    api_type=APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
                    url=target_url,
                    endpoint_path='/graphql',
                    http_method='POST',
                    severity='High',
                    evidence=f'GraphQL introspection enabled. Fields: {", ".join(fields[:10])}. Mutations: {", ".join(mutations[:5])}',
                    response_status=status_code,
                    response_size=len(response_content),
                    auth_required=False,
                    endpoint_parameters=fields + mutations,
                    confirmed=True,
                    confidence_score=0.95,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
        
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
                auth_required=False,
                confirmed=True,
                confidence_score=0.7,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
        
        if vulnerabilities:
            with self.lock:
                self.vulnerabilities.extend(vulnerabilities)
                for vuln in vulnerabilities:
                    self.scan_statistics[vuln.api_type.value] += 1
        
        return vulnerabilities
    
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
