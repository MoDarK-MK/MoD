from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import threading
import time
import json
import base64
import hashlib
import hmac

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
    MASS_ASSIGNMENT = "mass_assignment"
    BOLA_IDOR = "bola_idor"
    BFLA = "bfla"
    SSRF_API = "ssrf_api"
    XXE_API = "xxe_api"
    SQLI_API = "sqli_api"
    NOSQLI_API = "nosqli_api"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    JWT_VULNERABILITY = "jwt_vulnerability"
    OAUTH_MISCONFIGURATION = "oauth_misconfiguration"
    API_ABUSE = "api_abuse"
    BUSINESS_LOGIC_FLAW = "business_logic_flaw"

class AuthenticationMethod(Enum):
    NONE = "none"
    BASIC_AUTH = "basic_auth"
    BEARER_TOKEN = "bearer_token"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    MTLS = "mtls"
    CUSTOM = "custom"
    SESSION_COOKIE = "session_cookie"
    DIGEST_AUTH = "digest_auth"
    HAWK_AUTH = "hawk_auth"
    AWS_SIGNATURE = "aws_signature"

class APIEndpointType(Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    SOAP = "soap"
    WEBHOOK = "webhook"
    GRPC = "grpc"
    JSONRPC = "jsonrpc"
    WEBSOCKET = "websocket"
    XMLRPC = "xmlrpc"

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
    attack_vector: List[str] = field(default_factory=list)
    exploit_complexity: str = "Medium"
    timestamp: float = field(default_factory=time.time)

class MegaEndpointDiscovery:
    COMMON_PATHS = [
        '/api/v1/', '/api/v2/', '/api/v3/', '/api/v4/', '/api/v5/', '/api/v6/',
        '/rest/api/', '/rest/v1/', '/rest/v2/', '/rest/v3/',
        '/graphql', '/graphql/v1', '/gql', '/query', '/graphiql',
        '/ws/', '/websocket/', '/socket.io/', '/sockjs/', '/wss/',
        '/rpc/', '/jsonrpc/', '/xmlrpc/', '/grpc/', '/api/rpc/',
        '/.well-known/openapi.json', '/.well-known/swagger.json', '/.well-known/api-docs',
        '/swagger.json', '/swagger.yaml', '/swagger-ui.html', '/swagger-ui/', '/swagger/',
        '/openapi.json', '/openapi.yaml', '/openapi.yml', '/api.json', '/api.yaml',
        '/api-docs', '/api/docs', '/docs', '/documentation', '/redoc', '/rapidoc',
        '/admin/', '/api/admin/', '/admin/api/', '/administrator/', '/api/administrator/',
        '/internal/', '/api/internal/', '/private/', '/api/private/', '/api/debug/',
        '/v1/', '/v2/', '/v3/', '/v4/', '/v5/', '/v6/', '/v7/', '/v8/',
        '/users', '/user', '/customers', '/customer', '/accounts', '/account', '/profile', '/profiles',
        '/orders', '/order', '/products', '/product', '/items', '/item', '/data', '/files', '/file',
        '/auth', '/login', '/register', '/signup', '/oauth', '/token', '/refresh', '/logout',
        '/health', '/status', '/metrics', '/debug', '/test', '/ping', '/version', '/info',
        '/search', '/find', '/query', '/filter', '/export', '/import', '/upload', '/download',
        '/payment', '/checkout', '/invoice', '/billing', '/subscription', '/plans',
    ]
    
    ADMIN_KEYWORDS = ['admin', 'administrator', 'root', 'superuser', 'internal', 'debug', 'test', 'dev', 'staging', 'console']
    SENSITIVE_KEYWORDS = ['password', 'secret', 'token', 'key', 'auth', 'credential', 'backup', 'export', 'config', 'settings']
    
    @staticmethod
    def discover_all(response: str, base_url: str) -> List[APIEndpoint]:
        endpoints = []
        seen = set()
        
        patterns = [
            re.compile(r'["\']?(/?(?:api|rest|graphql|gql|rpc|ws|wss|v\d+)/[a-zA-Z0-9/_\-\.{}:]+)["\']?'),
            re.compile(r'"(?:url|endpoint|path|href|action|route)"\s*:\s*"([^"]+)"'),
            re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\s+([/a-zA-Z0-9_\-{}:]+)'),
        ]
        
        for pattern in patterns:
            for match in pattern.findall(response):
                path = match.strip('\'" ') if isinstance(match, str) else match[1] if isinstance(match, tuple) else match
                if path and path.startswith('/') and path not in seen and len(path) > 2:
                    seen.add(path)
                    endpoints.append(APIEndpoint(
                        path=path,
                        method='GET',
                        endpoint_type=MegaEndpointDiscovery._detect_type(path),
                        parameters=MegaEndpointDiscovery._extract_params(path),
                        is_admin_endpoint=any(kw in path.lower() for kw in MegaEndpointDiscovery.ADMIN_KEYWORDS),
                        returns_sensitive_data=any(kw in path.lower() for kw in MegaEndpointDiscovery.SENSITIVE_KEYWORDS)
                    ))
        
        if re.search(r'\b(query|mutation|subscription|__schema|__type)\s*[{(]', response):
            if '/graphql' not in seen:
                endpoints.append(APIEndpoint(path='/graphql', method='POST', endpoint_type=APIEndpointType.GRAPHQL))
        
        return endpoints
    
    @staticmethod
    def _detect_type(path: str) -> APIEndpointType:
        if any(x in path for x in ['graphql', 'gql']): return APIEndpointType.GRAPHQL
        if any(x in path for x in ['ws', 'socket']): return APIEndpointType.WEBSOCKET
        if 'rpc' in path: return APIEndpointType.JSONRPC
        if 'soap' in path: return APIEndpointType.SOAP
        return APIEndpointType.REST
    
    @staticmethod
    def _extract_params(path: str) -> List[str]:
        param_pattern = re.compile(r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}|:([a-zA-Z_][a-zA-Z0-9_]*)')
        matches = param_pattern.findall(path)
        return [m[0] or m[1] for m in matches]

class SuperAuthAnalyzer:
    JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*')
    
    @staticmethod
    def detect_auth(headers: Dict, content: str) -> AuthenticationMethod:
        auth = headers.get('Authorization', '').lower()
        www_auth = headers.get('WWW-Authenticate', '').lower()
        
        if 'bearer' in auth:
            if SuperAuthAnalyzer.JWT_PATTERN.search(auth):
                return AuthenticationMethod.JWT
            return AuthenticationMethod.BEARER_TOKEN
        
        if 'basic' in auth or 'basic' in www_auth:
            return AuthenticationMethod.BASIC_AUTH
        
        if 'digest' in auth or 'digest' in www_auth:
            return AuthenticationMethod.DIGEST_AUTH
        
        if 'hawk' in auth:
            return AuthenticationMethod.HAWK_AUTH
        
        for key in headers:
            kl = key.lower()
            if 'api' in kl and 'key' in kl:
                return AuthenticationMethod.API_KEY
            if 'x-amz-' in kl or 'authorization' in kl and 'aws' in headers.get(key, '').lower():
                return AuthenticationMethod.AWS_SIGNATURE
        
        if 'set-cookie' in str(headers).lower():
            return AuthenticationMethod.SESSION_COOKIE
        
        cl = content.lower()
        if SuperAuthAnalyzer.JWT_PATTERN.search(content):
            return AuthenticationMethod.JWT
        if 'oauth' in cl:
            return AuthenticationMethod.OAUTH2
        if 'api_key' in cl or 'apikey' in cl:
            return AuthenticationMethod.API_KEY
        
        return AuthenticationMethod.NONE
    
    @staticmethod
    def analyze_jwt(token: str) -> Tuple[bool, List[str]]:
        issues = []
        parts = token.split('.')
        if len(parts) != 3:
            return False, []
        
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            if header.get('alg', '').lower() in ['none', 'hs256'] and len(parts[2]) < 10:
                issues.append('Weak or missing JWT signature')
            
            if 'exp' not in payload:
                issues.append('JWT missing expiration')
            else:
                exp = payload['exp']
                if exp - time.time() > 86400 * 365:
                    issues.append('JWT expiration too long (>1 year)')
            
            if 'iat' not in payload:
                issues.append('JWT missing issued-at')
            
            if header.get('alg') == 'HS256' and 'kid' in header:
                issues.append('JWT vulnerable to key confusion attack')
            
            if 'role' in payload or 'admin' in str(payload).lower():
                issues.append('JWT contains privileged claims (mass assignment risk)')
        except:
            pass
        
        return bool(issues), issues

class MegaSensitiveDataScanner:
    PATTERNS = {
        'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'api_key': re.compile(r'(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
        'password': re.compile(r'(?i)(password|passwd|pwd|pass)\s*[:=]\s*["\']?([^"\'\s,;]{4,})["\']?'),
        'token': re.compile(r'(?i)(token|auth|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9._\-]{20,})["\']?'),
        'email': re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'),
        'private_key': re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----'),
        'ssh_key': re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        'database_uri': re.compile(r'(?i)(mongodb|mysql|postgresql|redis|sqlite|mssql):\/\/[^\s\'"]+'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'aws_secret': re.compile(r'(?i)aws.{0,20}?["\'][0-9a-zA-Z\/+]{40}["\']'),
        'jwt': re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*'),
        'phone': re.compile(r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b'),
        'ip_private': re.compile(r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b'),
        'slack_token': re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'),
        'github_token': re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        'stripe_key': re.compile(r'(?:r|s)k_live_[0-9a-zA-Z]{24,}'),
        'google_api': re.compile(r'AIza[0-9A-Za-z\\-_]{35}'),
        'oauth_secret': re.compile(r'(?i)(client_secret|consumer_secret)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
    }
    
    @staticmethod
    def scan(content: str) -> Tuple[bool, List[str], Dict]:
        exposed = []
        findings = {}
        
        for dtype, pattern in MegaSensitiveDataScanner.PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                exposed.append(dtype)
                findings[dtype] = matches[:3]
        
        return bool(exposed), exposed, findings

class AdvancedCORS:
    @staticmethod
    def analyze(headers: Dict) -> Tuple[bool, List[str], float]:
        issues = []
        severity = 0.0
        
        origin = headers.get('Access-Control-Allow-Origin', '')
        
        if origin == '*':
            issues.append('Wildcard CORS (*)')
            severity = max(severity, 0.9)
        
        if origin.lower() == 'null':
            issues.append('Null origin accepted')
            severity = max(severity, 0.85)
        
        methods = headers.get('Access-Control-Allow-Methods', '')
        dangerous = ['DELETE', 'PUT', 'PATCH', 'TRACE', 'CONNECT']
        if any(m in methods for m in dangerous):
            issues.append(f'Dangerous methods: {methods}')
            severity = max(severity, 0.8)
        
        allow_headers = headers.get('Access-Control-Allow-Headers', '')
        if allow_headers == '*':
            issues.append('Wildcard headers')
            severity = max(severity, 0.75)
        
        credentials = headers.get('Access-Control-Allow-Credentials', '').lower()
        if credentials == 'true':
            if origin in ['*', 'null']:
                issues.append('Credentials + permissive origin (critical)')
                severity = 1.0
            else:
                issues.append('Credentials enabled')
                severity = max(severity, 0.7)
        
        return bool(issues), issues, severity

class GraphQLMegaAnalyzer:
    INTROSPECTION_QUERY = '{ __schema { types { name fields { name type { name } } } queryType { name } mutationType { name } } }'
    
    @staticmethod
    def detect_graphql(content: str, headers: Dict) -> bool:
        indicators = ['__schema', '__type', '__typename', 'queryType', 'mutationType', '"data":', '"errors":', '"query":']
        return sum(1 for ind in indicators if ind in content) >= 2
    
    @staticmethod
    def detect_introspection(content: str) -> bool:
        return '__schema' in content or '__type' in content
    
    @staticmethod
    def extract_schema(content: str) -> Dict:
        types = list(set(re.findall(r'"name"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]*)"', content)))
        mutations = list(set(re.findall(r'mutation\s+(\w+)', content)))
        queries = list(set(re.findall(r'query\s+(\w+)', content)))
        subscriptions = list(set(re.findall(r'subscription\s+(\w+)', content)))
        return {'types': types[:30], 'mutations': mutations[:15], 'queries': queries[:15], 'subscriptions': subscriptions[:10]}

class BOLAIDORMegaDetector:
    @staticmethod
    def detect_ids(url: str, content: str) -> Tuple[bool, List[str], str]:
        patterns = [
            (r'/(\d+)(?:/|$|\?)', 'numeric_path_id'),
            (r'[?&]id=(\d+)', 'numeric_query_id'),
            (r'[?&]user_?id=(\d+)', 'user_id'),
            (r'[?&]account_?id=(\d+)', 'account_id'),
            (r'[?&]order_?id=(\d+)', 'order_id'),
            (r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', 'uuid'),
            (r'[?&]key=([a-zA-Z0-9_\-]{20,})', 'key_param'),
        ]
        
        ids = []
        id_type = 'unknown'
        for pattern, dtype in patterns:
            matches = re.findall(pattern, url + content)
            if matches:
                ids.extend(matches)
                id_type = dtype
        
        return bool(ids), ids[:10], id_type

class MassAssignmentMegaDetector:
    CRITICAL_FIELDS = ['role', 'is_admin', 'admin', 'superuser', 'privilege', 'permission', 'permissions', 'active', 'verified', 'is_active', 'is_verified', 'is_superuser']
    
    @staticmethod
    def detect(content: str) -> Tuple[bool, List[str], float]:
        found = []
        for field in MassAssignmentMegaDetector.CRITICAL_FIELDS:
            pattern = rf'["\']?{field}["\']?\s*:\s*'
            if re.search(pattern, content, re.IGNORECASE):
                found.append(field)
        
        confidence = min(len(found) * 0.2 + 0.5, 1.0) if found else 0.0
        return bool(found), found, confidence

class APIScanner:
    def __init__(self, max_workers: int = 20):
        self.endpoint_discovery = MegaEndpointDiscovery()
        self.auth_analyzer = SuperAuthAnalyzer()
        self.data_scanner = MegaSensitiveDataScanner()
        self.cors_analyzer = AdvancedCORS()
        self.graphql_analyzer = GraphQLMegaAnalyzer()
        self.bola_detector = BOLAIDORMegaDetector()
        self.mass_detector = MassAssignmentMegaDetector()
        
        self.vulnerabilities = []
        self.discovered_endpoints = []
        self.lock = threading.Lock()
        self.max_workers = max_workers
    
    def scan(self, url: str, response: Dict) -> List[APIVulnerability]:
        vulns = []
        content = response.get('content', '')
        headers = response.get('headers', {})
        status = response.get('status_code', 0)
        
        endpoints = self.endpoint_discovery.discover_all(content, url)
        with self.lock:
            self.discovered_endpoints.extend(endpoints)
        
        auth = self.auth_analyzer.detect_auth(headers, content)
        if auth == AuthenticationMethod.NONE and status == 200:
            vulns.append(self._vuln(APIVulnerabilityType.BROKEN_AUTHENTICATION, url, 'No auth', status, len(content), 'Critical', 0.93))
        
        if auth == AuthenticationMethod.JWT:
            jwt_match = self.auth_analyzer.JWT_PATTERN.search(content + str(headers))
            if jwt_match:
                has_issues, issues = self.auth_analyzer.analyze_jwt(jwt_match.group(0))
                if has_issues:
                    vulns.append(self._vuln(APIVulnerabilityType.JWT_VULNERABILITY, url, f'JWT: {", ".join(issues)}', status, len(content), 'High', 0.89))
        
        exposed, types, findings = self.data_scanner.scan(content)
        if exposed:
            vulns.append(self._vuln(APIVulnerabilityType.SENSITIVE_DATA_EXPOSURE, url, f'Exposed: {", ".join(types)} | {str(findings)[:200]}', status, len(content), 'Critical', 0.97, sensitive_data_exposed=types))
        
        cors_issue, cors_problems, cors_severity = self.cors_analyzer.analyze(headers)
        if cors_issue:
            severity = 'Critical' if cors_severity >= 0.9 else 'High' if cors_severity >= 0.75 else 'Medium'
            vulns.append(self._vuln(APIVulnerabilityType.CORS_MISCONFIGURATION, url, f'CORS: {"; ".join(cors_problems)}', status, len(content), severity, cors_severity))
        
        is_gql = self.graphql_analyzer.detect_graphql(content, headers)
        if is_gql:
            intro = self.graphql_analyzer.detect_introspection(content)
            if intro:
                schema = self.graphql_analyzer.extract_schema(content)
                vulns.append(self._vuln(APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE, url, f'GraphQL intro | Schema: {schema}', status, len(content), 'High', 0.95))
        
        bola, ids, id_type = self.bola_detector.detect_ids(url, content)
        if bola:
            vulns.append(self._vuln(APIVulnerabilityType.BOLA_IDOR, url, f'BOLA/IDOR ({id_type}) | IDs: {", ".join(ids)}', status, len(content), 'High', 0.84))
        
        mass_vuln, fields, mass_conf = self.mass_detector.detect(content)
        if mass_vuln:
            vulns.append(self._vuln(APIVulnerabilityType.MASS_ASSIGNMENT, url, f'Mass assignment | Fields: {", ".join(fields)}', status, len(content), 'High', mass_conf))
        
        with self.lock:
            self.vulnerabilities.extend(vulns)
        
        return vulns
    
    def _vuln(self, api_type, url, evidence, status, size, severity, confidence, **kwargs):
        return APIVulnerability(
            vulnerability_type='API Vulnerability',
            api_type=api_type,
            url=url,
            endpoint_path=url,
            http_method='GET',
            severity=severity,
            evidence=evidence,
            response_status=status,
            response_size=size,
            auth_required=False,
            confirmed=True,
            confidence_score=confidence,
            remediation=self._remediation(),
            **kwargs
        )
    
    def _remediation(self):
        return (
            "1. OAuth2/JWT with short expiration. "
            "2. TLS 1.3+ only. "
            "3. Rate limit: 100req/min. "
            "4. Input validation (regex, type, length). "
            "5. Disable GraphQL introspection. "
            "6. Strict CORS (no wildcard). "
            "7. Authorization checks (BOLA/IDOR). "
            "8. Mass assignment protection. "
            "9. Data minimization. "
            "10. WAF + monitoring."
        )
    
    def get_vulnerabilities(self):
        with self.lock: return self.vulnerabilities.copy()
    
    def get_discovered_endpoints(self):
        with self.lock: return self.discovered_endpoints.copy()
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.discovered_endpoints.clear()
