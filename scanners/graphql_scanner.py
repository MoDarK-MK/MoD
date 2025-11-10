from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import json


class GraphQLVulnerabilityType(Enum):
    INTROSPECTION_ENABLED = "introspection_enabled"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    INSUFFICIENT_INPUT_VALIDATION = "insufficient_input_validation"
    ALIAS_ATTACK = "alias_attack"
    DEPTH_LIMIT_BYPASS = "depth_limit_bypass"
    BATCH_ATTACK = "batch_attack"
    BROKEN_AUTHENTICATION = "broken_authentication"
    BROKEN_AUTHORIZATION = "broken_authorization"
    SENSITIVE_DATA_IN_LOGS = "sensitive_data_in_logs"
    GRAPHQL_INJECTION = "graphql_injection"


class QueryType(Enum):
    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"
    FRAGMENT = "fragment"
    UNKNOWN = "unknown"


class ScalarType(Enum):
    STRING = "String"
    INT = "Int"
    FLOAT = "Float"
    BOOLEAN = "Boolean"
    ID = "ID"
    CUSTOM = "Custom"


@dataclass
class GraphQLField:
    name: str
    field_type: str
    is_required: bool = False
    is_list: bool = False
    arguments: List[Dict] = field(default_factory=list)
    return_type: Optional[str] = None
    description: Optional[str] = None
    is_deprecated: bool = False
    deprecation_reason: Optional[str] = None


@dataclass
class GraphQLType:
    name: str
    kind: str
    fields: List[GraphQLField] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    possible_types: List[str] = field(default_factory=list)
    enum_values: List[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class GraphQLEndpoint:
    url: str
    method: str
    introspection_enabled: bool = False
    authentication_required: bool = False
    types_discovered: Dict[str, GraphQLType] = field(default_factory=dict)
    operations: List[str] = field(default_factory=list)
    mutations: List[str] = field(default_factory=list)
    subscriptions: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)


@dataclass
class GraphQLVulnerability:
    vulnerability_type: str
    graphql_type: GraphQLVulnerabilityType
    url: str
    severity: str
    evidence: str
    affected_fields: List[str] = field(default_factory=list)
    affected_types: List[str] = field(default_factory=list)
    query_used: Optional[str] = None
    response_data: Optional[str] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class GraphQLEndpointDiscovery:
    GRAPHQL_ENDPOINTS = [
        '/graphql',
        '/api/graphql',
        '/gql',
        '/api/gql',
        '/query',
        '/graphql/',
        '/v1/graphql',
        '/v2/graphql',
        '/.graphql',
        '/graphiql',
        '/apollo',
        '/relay',
    ]
    
    @staticmethod
    def discover_graphql_endpoints(base_url: str) -> List[GraphQLEndpoint]:
        endpoints = []
        
        for endpoint_path in GraphQLEndpointDiscovery.GRAPHQL_ENDPOINTS:
            url = base_url.rstrip('/') + endpoint_path
            endpoint = GraphQLEndpoint(
                url=url,
                method='POST'
            )
            endpoints.append(endpoint)
        
        return endpoints


class IntrospectionQueryBuilder:
    FULL_INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
        __schema {
            types {
                name
                kind
                description
                fields {
                    name
                    type {
                        name
                        kind
                        ofType {
                            name
                            kind
                        }
                    }
                    args {
                        name
                        type {
                            name
                            kind
                        }
                    }
                }
                enumValues {
                    name
                }
                interfaces {
                    name
                }
                possibleTypes {
                    name
                }
            }
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
        }
    }
    '''
    
    @staticmethod
    def build_introspection_query() -> str:
        return IntrospectionQueryBuilder.FULL_INTROSPECTION_QUERY.strip()
    
    @staticmethod
    def build_field_discovery_query(type_name: str) -> str:
        return f'''
        query {{
            __type(name: "{type_name}") {{
                name
                fields {{
                    name
                    args {{
                        name
                        type {{
                            name
                        }}
                    }}
                }}
            }}
        }}
        '''


class GraphQLPayloadGenerator:
    @staticmethod
    def generate_alias_attack_payload(query: str, iterations: int = 100) -> str:
        aliases = []
        for i in range(iterations):
            aliases.append(f"a{i}: {query}")
        
        return "query { " + " ".join(aliases) + " }"
    
    @staticmethod
    def generate_deep_nested_query(depth: int = 100) -> str:
        query = "user { "
        for _ in range(depth):
            query += "profile { "
        query += "name"
        query += " }" * (depth + 1)
        return f"query {{ {query} }}"
    
    @staticmethod
    def generate_batch_query(query: str, batch_size: int = 100) -> List[Dict]:
        return [{"query": query} for _ in range(batch_size)]
    
    @staticmethod
    def generate_injection_payload(field: str) -> str:
        injection_variants = [
            f'{field} { __typename }',
            f'{field} {{ __schema {{ types {{ name }} }} }}',
            f'{{ {field}; __typename }}',
            f'{{ {field} \n __typename }}',
        ]
        return ' '.join([f"query {{ {v} }}" for v in injection_variants])


class IntrospectionAnalyzer:
    @staticmethod
    def parse_introspection_response(response_content: str) -> Tuple[bool, Dict]:
        try:
            data = json.loads(response_content)
            
            if 'data' in data and '__schema' in data['data']:
                schema = data['data']['__schema']
                return True, schema
            
            return False, {}
        except json.JSONDecodeError:
            return False, {}
    
    @staticmethod
    def extract_types_from_schema(schema: Dict) -> Dict[str, GraphQLType]:
        types = {}
        
        if 'types' not in schema:
            return types
        
        for type_info in schema['types']:
            gql_type = GraphQLType(
                name=type_info.get('name', ''),
                kind=type_info.get('kind', ''),
                description=type_info.get('description'),
            )
            
            if 'fields' in type_info and type_info['fields']:
                for field_info in type_info['fields']:
                    field = GraphQLField(
                        name=field_info.get('name', ''),
                        field_type=IntrospectionAnalyzer._extract_type(field_info.get('type', {})),
                        arguments=field_info.get('args', []),
                        is_deprecated=field_info.get('isDeprecated', False),
                        deprecation_reason=field_info.get('deprecationReason'),
                    )
                    gql_type.fields.append(field)
            
            if 'enumValues' in type_info:
                gql_type.enum_values = [e['name'] for e in type_info['enumValues']]
            
            types[type_info.get('name', '')] = gql_type
        
        return types
    
    @staticmethod
    def _extract_type(type_obj: Dict) -> str:
        if 'ofType' in type_obj:
            return f"[{IntrospectionAnalyzer._extract_type(type_obj['ofType'])}]"
        return type_obj.get('name', 'Unknown')
    
    @staticmethod
    def find_sensitive_fields(types: Dict[str, GraphQLType]) -> List[Tuple[str, str]]:
        sensitive_patterns = [
            'password', 'token', 'secret', 'key', 'credential',
            'ssn', 'credit', 'card', 'email', 'phone',
            'address', 'account', 'user', 'profile',
        ]
        
        sensitive_fields = []
        
        for type_name, gql_type in types.items():
            for field in gql_type.fields:
                field_name_lower = field.name.lower()
                if any(pattern in field_name_lower for pattern in sensitive_patterns):
                    sensitive_fields.append((type_name, field.name))
        
        return sensitive_fields
    
    @staticmethod
    def extract_mutations(schema: Dict) -> List[str]:
        mutations = []
        
        if 'mutationType' in schema and schema['mutationType']:
            mutation_type_name = schema['mutationType'].get('name')
            
            for type_info in schema.get('types', []):
                if type_info.get('name') == mutation_type_name:
                    for field in type_info.get('fields', []):
                        mutations.append(field.get('name'))
        
        return mutations


class QueryComplexityAnalyzer:
    @staticmethod
    def analyze_query_depth(query: str) -> int:
        depth_count = 0
        max_depth = 0
        current_depth = 0
        
        for char in query:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth -= 1
        
        return max_depth
    
    @staticmethod
    def analyze_query_width(query: str) -> int:
        fields = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:{(]', query)
        return len(set(fields))
    
    @staticmethod
    def estimate_query_complexity(query: str, depth_weight: float = 1.0, width_weight: float = 1.0) -> float:
        depth = QueryComplexityAnalyzer.analyze_query_depth(query)
        width = QueryComplexityAnalyzer.analyze_query_width(query)
        
        complexity = (depth * depth_weight) + (width * width_weight)
        return complexity
    
    @staticmethod
    def detect_alias_attack(query: str) -> Tuple[bool, int]:
        alias_pattern = r'([a-zA-Z0-9_]+)\s*:\s*([a-zA-Z0-9_]+)'
        aliases = re.findall(alias_pattern, query)
        
        if len(aliases) > 10:
            return True, len(aliases)
        
        return False, len(aliases)


class ErrorAnalyzer:
    @staticmethod
    def parse_graphql_errors(response_content: str) -> List[Dict]:
        try:
            data = json.loads(response_content)
            if 'errors' in data:
                return data['errors']
        except json.JSONDecodeError:
            pass
        
        return []
    
    @staticmethod
    def detect_information_disclosure(errors: List[Dict]) -> Tuple[bool, List[str]]:
        disclosure_patterns = [
            'line', 'column', 'positions',
            'path', 'extensions',
            'stacktrace', 'traceback',
            'sql', 'database', 'query',
            'file', 'directory', 'path',
        ]
        
        disclosures = []
        
        for error in errors:
            error_str = json.dumps(error).lower()
            for pattern in disclosure_patterns:
                if pattern in error_str:
                    disclosures.append(f"Error contains: {pattern}")
        
        return len(disclosures) > 0, disclosures


class GraphQLScanner:
    def __init__(self):
        self.endpoint_discovery = GraphQLEndpointDiscovery()
        self.introspection_analyzer = IntrospectionAnalyzer()
        self.payload_generator = GraphQLPayloadGenerator()
        self.query_analyzer = QueryComplexityAnalyzer()
        self.error_analyzer = ErrorAnalyzer()
        
        self.discovered_endpoints: Dict[str, GraphQLEndpoint] = {}
        self.vulnerabilities: List[GraphQLVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict) -> List[GraphQLVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        status_code = response.get('status_code', 0)
        
        endpoints = self.endpoint_discovery.discover_graphql_endpoints(target_url)
        
        for endpoint in endpoints:
            introspection_query = IntrospectionQueryBuilder.build_introspection_query()
            
            is_graphql, schema = self.introspection_analyzer.parse_introspection_response(response_content)
            
            if is_graphql and schema:
                endpoint.introspection_enabled = True
                types = self.introspection_analyzer.extract_types_from_schema(schema)
                endpoint.types_discovered = types
                
                sensitive_fields = self.introspection_analyzer.find_sensitive_fields(types)
                
                if sensitive_fields:
                    vuln = GraphQLVulnerability(
                        vulnerability_type='GraphQL Vulnerability',
                        graphql_type=GraphQLVulnerabilityType.INTROSPECTION_ENABLED,
                        url=endpoint.url,
                        severity='High',
                        evidence=f'Introspection enabled, {len(sensitive_fields)} sensitive fields discovered',
                        affected_fields=[f[1] for f in sensitive_fields],
                        affected_types=[f[0] for f in sensitive_fields],
                        response_data=json.dumps(sensitive_fields),
                        confirmed=True,
                        confidence_score=0.95,
                        remediation=self._get_remediation()
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['introspection_enabled'] += 1
                
                mutations = self.introspection_analyzer.extract_mutations(schema)
                if mutations:
                    vuln = GraphQLVulnerability(
                        vulnerability_type='GraphQL Vulnerability',
                        graphql_type=GraphQLVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
                        url=endpoint.url,
                        severity='Medium',
                        evidence=f'Mutations available: {", ".join(mutations[:5])}',
                        affected_fields=mutations,
                        confirmed=True,
                        confidence_score=0.85,
                        remediation=self._get_remediation()
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['mutations_exposed'] += 1
            
            alias_payload = self.payload_generator.generate_alias_attack_payload('user { id }', 50)
            is_vulnerable_alias, alias_count = self.query_analyzer.detect_alias_attack(alias_payload)
            
            if is_vulnerable_alias:
                vuln = GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.ALIAS_ATTACK,
                    url=endpoint.url,
                    severity='Medium',
                    evidence=f'Alias attack possible with {alias_count} aliases',
                    query_used=alias_payload,
                    confirmed=False,
                    confidence_score=0.7,
                    remediation=self._get_remediation()
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['alias_attack'] += 1
            
            deep_query = self.payload_generator.generate_deep_nested_query(50)
            depth = self.query_analyzer.analyze_query_depth(deep_query)
            
            if depth > 20:
                vuln = GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.DEPTH_LIMIT_BYPASS,
                    url=endpoint.url,
                    severity='Medium',
                    evidence=f'Query depth of {depth} possible without limit',
                    query_used=deep_query[:100],
                    confirmed=False,
                    confidence_score=0.8,
                    remediation=self._get_remediation()
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['depth_limit_bypass'] += 1
            
            errors = self.error_analyzer.parse_graphql_errors(response_content)
            has_disclosure, disclosure_types = self.error_analyzer.detect_information_disclosure(errors)
            
            if has_disclosure:
                vuln = GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.SENSITIVE_DATA_IN_LOGS,
                    url=endpoint.url,
                    severity='Medium',
                    evidence=f'Error messages expose: {", ".join(disclosure_types[:3])}',
                    response_data=json.dumps(errors[:2]),
                    confirmed=True,
                    confidence_score=0.85,
                    remediation=self._get_remediation()
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['info_disclosure'] += 1
        
        with self.lock:
            for endpoint in endpoints:
                self.discovered_endpoints[endpoint.url] = endpoint
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def test_query_execution(self, endpoint_url: str, query: str) -> Tuple[bool, Optional[str]]:
        complexity = self.query_analyzer.estimate_query_complexity(query)
        
        if complexity > 1000:
            return False, f"Query complexity too high: {complexity}"
        
        return True, None
    
    def _get_remediation(self) -> str:
        return (
            "Disable GraphQL introspection in production. "
            "Implement query complexity analysis. "
            "Set depth limits on queries. "
            "Implement rate limiting. "
            "Validate and sanitize all inputs. "
            "Implement proper authentication and authorization. "
            "Use allow-lists for operations. "
            "Implement request batching limits. "
            "Remove sensitive data from error messages. "
            "Monitor GraphQL queries for suspicious patterns."
        )
    
    def get_discovered_endpoints(self) -> Dict[str, GraphQLEndpoint]:
        with self.lock:
            return self.discovered_endpoints.copy()
    
    def get_vulnerabilities(self) -> List[GraphQLVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.discovered_endpoints.clear()
            self.vulnerabilities.clear()
            self.scan_statistics.clear()