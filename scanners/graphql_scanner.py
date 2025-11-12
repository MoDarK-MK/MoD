from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import json
import hashlib


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
    CIRCULAR_QUERY = "circular_query"
    FIELD_DUPLICATION = "field_duplication"
    DOS_VULNERABILITY = "dos_vulnerability"


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
    is_sensitive: bool = False
    has_side_effects: bool = False


@dataclass
class GraphQLType:
    name: str
    kind: str
    fields: List[GraphQLField] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    possible_types: List[str] = field(default_factory=list)
    enum_values: List[str] = field(default_factory=list)
    description: Optional[str] = None
    is_input_type: bool = False
    is_union_type: bool = False


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
    queries: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)
    schema_hash: Optional[str] = None
    depth_limit: Optional[int] = None
    complexity_limit: Optional[int] = None


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
    complexity_score: float = 0.0
    depth_score: int = 0
    width_score: int = 0
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class GraphQLEndpointDiscovery:
    GRAPHQL_ENDPOINTS = [
        '/graphql', '/api/graphql', '/gql', '/api/gql', '/query',
        '/graphql/', '/v1/graphql', '/v2/graphql', '/v3/graphql',
        '/.graphql', '/graphiql', '/apollo', '/relay',
        '/graphql/v1', '/graphql/v2', '/api/v1/graphql',
        '/api/v2/graphql', '/graphql/console', '/graphql-explorer',
        '/playground', '/graphql/playground', '/altair',
    ]
    
    GRAPHQL_INDICATORS = [
        rb'"__schema"', rb'"__type"', rb'"queryType"',
        rb'"mutationType"', rb'"subscriptionType"',
        rb'GraphQL', rb'graphql',
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
    
    @staticmethod
    def detect_graphql_response(response_content: str) -> bool:
        try:
            response_bytes = response_content.encode('utf-8')
            return any(indicator in response_bytes for indicator in GraphQLEndpointDiscovery.GRAPHQL_INDICATORS)
        except:
            return False


class IntrospectionQueryBuilder:
    FULL_INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
        __schema {
            types {
                name
                kind
                description
                fields(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                    type {
                        name
                        kind
                        ofType {
                            name
                            kind
                            ofType {
                                name
                                kind
                            }
                        }
                    }
                    args {
                        name
                        description
                        type {
                            name
                            kind
                            ofType {
                                name
                                kind
                            }
                        }
                        defaultValue
                    }
                }
                enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                }
                interfaces {
                    name
                    kind
                }
                possibleTypes {
                    name
                    kind
                }
                inputFields {
                    name
                    type {
                        name
                        kind
                    }
                }
            }
            queryType {
                name
                fields {
                    name
                }
            }
            mutationType {
                name
                fields {
                    name
                }
            }
            subscriptionType {
                name
                fields {
                    name
                }
            }
            directives {
                name
                description
                locations
                args {
                    name
                    type {
                        name
                    }
                }
            }
        }
    }
    '''
    
    MINIMAL_INTROSPECTION = '''
    {
        __schema {
            queryType { name }
            mutationType { name }
            types { name kind }
        }
    }
    '''
    
    @staticmethod
    def build_introspection_query() -> str:
        return IntrospectionQueryBuilder.FULL_INTROSPECTION_QUERY.strip()
    
    @staticmethod
    def build_minimal_introspection() -> str:
        return IntrospectionQueryBuilder.MINIMAL_INTROSPECTION.strip()
    
    @staticmethod
    def build_field_discovery_query(type_name: str) -> str:
        return f'''
        query {{
            __type(name: "{type_name}") {{
                name
                kind
                fields {{
                    name
                    description
                    type {{
                        name
                        kind
                    }}
                    args {{
                        name
                        type {{
                            name
                            kind
                        }}
                    }}
                }}
            }}
        }}
        '''
    
    @staticmethod
    def build_enum_discovery_query(type_name: str) -> str:
        return f'''
        query {{
            __type(name: "{type_name}") {{
                name
                kind
                enumValues {{
                    name
                    description
                }}
            }}
        }}
        '''


class GraphQLPayloadGenerator:
    @staticmethod
    def generate_alias_attack_payload(query: str, iterations: int = 100) -> str:
        aliases = []
        for i in range(iterations):
            aliases.append(f"alias{i}: {query}")
        
        return "query AliasAttack { " + " ".join(aliases) + " }"
    
    @staticmethod
    def generate_deep_nested_query(depth: int = 100) -> str:
        query = "user { "
        for i in range(depth):
            query += f"profile{i} {{ "
        query += "id name"
        query += " }" * (depth + 1)
        return f"query DeepNested {{ {query} }}"
    
    @staticmethod
    def generate_batch_query(query: str, batch_size: int = 100) -> List[Dict]:
        return [{"query": query, "operationName": f"Op{i}"} for i in range(batch_size)]
    
    @staticmethod
    def generate_injection_payload(field: str) -> List[str]:
        injection_variants = [
            f'query {{ {field} {{ __typename }} }}',
            f'query {{ {field} {{ __schema {{ types {{ name }} }} }} }}',
            f'{{ {field}; __typename }}',
            f'{{ {field} \\n __typename }}',
            f'query {{ {field}(id: "1\' OR \'1\'=\'1") {{ id }} }}',
            f'query {{ {field}(id: "1\\"; DROP TABLE users--") {{ id }} }}',
        ]
        return injection_variants
    
    @staticmethod
    def generate_circular_query(field: str, depth: int = 50) -> str:
        query = field + " { "
        for _ in range(depth):
            query += field + " { "
        query += "id"
        query += " }" * (depth + 1)
        return f"query Circular {{ {query} }}"
    
    @staticmethod
    def generate_field_duplication_payload(field: str, count: int = 100) -> str:
        fields = " ".join([field] * count)
        return f"query FieldDupe {{ user {{ {fields} }} }}"


class IntrospectionAnalyzer:
    _sensitive_patterns = frozenset([
        'password', 'passwd', 'pwd', 'token', 'secret', 'key', 'credential',
        'ssn', 'social', 'credit', 'card', 'cvv', 'email', 'phone', 'mobile',
        'address', 'account', 'user', 'profile', 'private', 'confidential',
        'auth', 'session', 'cookie', 'api_key', 'apikey', 'access_token',
    ])
    
    @staticmethod
    def parse_introspection_response(response_content: str) -> Tuple[bool, Dict]:
        try:
            data = json.loads(response_content)
            
            if 'data' in data and '__schema' in data['data']:
                schema = data['data']['__schema']
                return True, schema
            
            if 'data' in data and '__type' in data['data']:
                return True, {'types': [data['data']['__type']]}
            
            return False, {}
        except json.JSONDecodeError:
            return False, {}
    
    @staticmethod
    def extract_types_from_schema(schema: Dict) -> Dict[str, GraphQLType]:
        types = {}
        
        if 'types' not in schema:
            return types
        
        for type_info in schema['types']:
            if not type_info or 'name' not in type_info:
                continue
            
            gql_type = GraphQLType(
                name=type_info.get('name', ''),
                kind=type_info.get('kind', ''),
                description=type_info.get('description'),
                is_input_type=type_info.get('kind') == 'INPUT_OBJECT',
                is_union_type=type_info.get('kind') == 'UNION',
            )
            
            if 'fields' in type_info and type_info['fields']:
                for field_info in type_info['fields']:
                    field = GraphQLField(
                        name=field_info.get('name', ''),
                        field_type=IntrospectionAnalyzer._extract_type(field_info.get('type', {})),
                        arguments=field_info.get('args', []),
                        is_deprecated=field_info.get('isDeprecated', False),
                        deprecation_reason=field_info.get('deprecationReason'),
                        description=field_info.get('description'),
                        is_sensitive=IntrospectionAnalyzer._is_sensitive_field(field_info.get('name', '')),
                    )
                    gql_type.fields.append(field)
            
            if 'enumValues' in type_info and type_info['enumValues']:
                gql_type.enum_values = [e.get('name', '') for e in type_info['enumValues']]
            
            if 'interfaces' in type_info and type_info['interfaces']:
                gql_type.interfaces = [i.get('name', '') for i in type_info['interfaces']]
            
            if 'possibleTypes' in type_info and type_info['possibleTypes']:
                gql_type.possible_types = [p.get('name', '') for p in type_info['possibleTypes']]
            
            types[type_info.get('name', '')] = gql_type
        
        return types
    
    @staticmethod
    def _extract_type(type_obj: Dict) -> str:
        if not type_obj:
            return 'Unknown'
        
        if 'ofType' in type_obj and type_obj['ofType']:
            inner_type = IntrospectionAnalyzer._extract_type(type_obj['ofType'])
            kind = type_obj.get('kind', '')
            
            if kind == 'LIST':
                return f"[{inner_type}]"
            elif kind == 'NON_NULL':
                return f"{inner_type}!"
            
            return inner_type
        
        return type_obj.get('name', 'Unknown')
    
    @staticmethod
    def _is_sensitive_field(field_name: str) -> bool:
        field_lower = field_name.lower()
        return any(pattern in field_lower for pattern in IntrospectionAnalyzer._sensitive_patterns)
    
    @staticmethod
    def find_sensitive_fields(types: Dict[str, GraphQLType]) -> List[Tuple[str, str, str]]:
        sensitive_fields = []
        
        for type_name, gql_type in types.items():
            for field in gql_type.fields:
                if field.is_sensitive:
                    sensitive_fields.append((type_name, field.name, field.field_type))
        
        return sensitive_fields
    
    @staticmethod
    def extract_mutations(schema: Dict) -> List[str]:
        mutations = []
        
        if 'mutationType' in schema and schema['mutationType']:
            mutation_type_name = schema['mutationType'].get('name')
            
            for type_info in schema.get('types', []):
                if type_info.get('name') == mutation_type_name:
                    for field in type_info.get('fields', []):
                        mutations.append(field.get('name', ''))
        
        return mutations
    
    @staticmethod
    def extract_queries(schema: Dict) -> List[str]:
        queries = []
        
        if 'queryType' in schema and schema['queryType']:
            query_type_name = schema['queryType'].get('name')
            
            for type_info in schema.get('types', []):
                if type_info.get('name') == query_type_name:
                    for field in type_info.get('fields', []):
                        queries.append(field.get('name', ''))
        
        return queries
    
    @staticmethod
    def extract_subscriptions(schema: Dict) -> List[str]:
        subscriptions = []
        
        if 'subscriptionType' in schema and schema['subscriptionType']:
            subscription_type_name = schema['subscriptionType'].get('name')
            
            for type_info in schema.get('types', []):
                if type_info.get('name') == subscription_type_name:
                    for field in type_info.get('fields', []):
                        subscriptions.append(field.get('name', ''))
        
        return subscriptions
    
    @staticmethod
    def calculate_schema_hash(schema: Dict) -> str:
        schema_str = json.dumps(schema, sort_keys=True)
        return hashlib.sha256(schema_str.encode()).hexdigest()


class QueryComplexityAnalyzer:
    @staticmethod
    def analyze_query_depth(query: str) -> int:
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
        fields = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[:{(]', query)
        return len(set(fields))
    
    @staticmethod
    def estimate_query_complexity(query: str, depth_weight: float = 2.0, width_weight: float = 1.5) -> float:
        depth = QueryComplexityAnalyzer.analyze_query_depth(query)
        width = QueryComplexityAnalyzer.analyze_query_width(query)
        
        complexity = (depth * depth_weight) + (width * width_weight)
        return complexity
    
    @staticmethod
    def detect_alias_attack(query: str) -> Tuple[bool, int]:
        alias_pattern = re.compile(r'\b([a-zA-Z0-9_]+)\s*:\s*([a-zA-Z0-9_]+)')
        aliases = alias_pattern.findall(query)
        
        if len(aliases) > 10:
            return True, len(aliases)
        
        return False, len(aliases)
    
    @staticmethod
    def detect_circular_references(query: str) -> Tuple[bool, List[str]]:
        field_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\{')
        fields = field_pattern.findall(query)
        
        field_count = {}
        for field in fields:
            field_count[field] = field_count.get(field, 0) + 1
        
        circular = [f for f, count in field_count.items() if count > 3]
        
        return len(circular) > 0, circular
    
    @staticmethod
    def detect_field_duplication(query: str) -> Tuple[bool, Dict[str, int]]:
        field_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\(|{|\s|$)')
        fields = field_pattern.findall(query)
        
        field_count = {}
        for field in fields:
            field_count[field] = field_count.get(field, 0) + 1
        
        duplicates = {f: count for f, count in field_count.items() if count > 5}
        
        return len(duplicates) > 0, duplicates
    
    @staticmethod
    def calculate_estimated_response_size(query: str, avg_field_size: int = 100) -> int:
        depth = QueryComplexityAnalyzer.analyze_query_depth(query)
        width = QueryComplexityAnalyzer.analyze_query_width(query)
        
        estimated_size = (width ** depth) * avg_field_size
        return min(estimated_size, 1000000000)


class ErrorAnalyzer:
    _disclosure_patterns = frozenset([
        'line', 'column', 'positions', 'locations',
        'path', 'extensions', 'exception',
        'stacktrace', 'traceback', 'stack trace',
        'sql', 'database', 'query', 'syntax',
        'file', 'directory', 'path', 'error',
        'internal', 'debug', 'trace',
    ])
    
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
        disclosures = []
        
        for error in errors:
            error_str = json.dumps(error).lower()
            
            for pattern in ErrorAnalyzer._disclosure_patterns:
                if pattern in error_str:
                    disclosures.append(f"Error exposes: {pattern}")
        
        return len(disclosures) > 0, list(set(disclosures))
    
    @staticmethod
    def extract_error_messages(errors: List[Dict]) -> List[str]:
        messages = []
        
        for error in errors:
            if 'message' in error:
                messages.append(error['message'])
        
        return messages
    
    @staticmethod
    def detect_sql_errors(errors: List[Dict]) -> bool:
        sql_keywords = ['sql', 'database', 'syntax', 'mysql', 'postgres', 'oracle', 'sqlite']
        
        for error in errors:
            error_str = json.dumps(error).lower()
            if any(keyword in error_str for keyword in sql_keywords):
                return True
        
        return False


class GraphQLScanner:
    _remediation_cache = (
        "Disable GraphQL introspection in production environment. "
        "Implement query complexity analysis and limits. "
        "Set maximum query depth limits (recommended: 10-15). "
        "Implement rate limiting and throttling. "
        "Validate and sanitize all inputs. "
        "Implement proper authentication and authorization. "
        "Use operation allow-lists (persisted queries). "
        "Implement request batching limits. "
        "Remove sensitive data from error messages. "
        "Monitor GraphQL queries for suspicious patterns. "
        "Implement query cost analysis. "
        "Use DataLoader to prevent N+1 queries. "
        "Implement timeout mechanisms. "
        "Disable field suggestions in production. "
        "Use schema validation."
    )
    
    def __init__(self):
        self.endpoint_discovery = GraphQLEndpointDiscovery()
        self.introspection_analyzer = IntrospectionAnalyzer()
        self.payload_generator = GraphQLPayloadGenerator()
        self.query_analyzer = QueryComplexityAnalyzer()
        self.error_analyzer = ErrorAnalyzer()
        self.introspection_builder = IntrospectionQueryBuilder()
        
        self.discovered_endpoints: Dict[str, GraphQLEndpoint] = {}
        self.vulnerabilities: List[GraphQLVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.tested_queries: Set[str] = set()
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict) -> List[GraphQLVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        status_code = response.get('status_code', 0)
        
        if not self.endpoint_discovery.detect_graphql_response(response_content):
            return vulnerabilities
        
        endpoints = self.endpoint_discovery.discover_graphql_endpoints(target_url)
        
        for endpoint in endpoints:
            introspection_query = self.introspection_builder.build_introspection_query()
            
            is_graphql, schema = self.introspection_analyzer.parse_introspection_response(response_content)
            
            if is_graphql and schema:
                endpoint.introspection_enabled = True
                endpoint.schema_hash = self.introspection_analyzer.calculate_schema_hash(schema)
                
                types = self.introspection_analyzer.extract_types_from_schema(schema)
                endpoint.types_discovered = types
                
                queries = self.introspection_analyzer.extract_queries(schema)
                endpoint.queries = queries
                
                mutations = self.introspection_analyzer.extract_mutations(schema)
                endpoint.mutations = mutations
                
                subscriptions = self.introspection_analyzer.extract_subscriptions(schema)
                endpoint.subscriptions = subscriptions
                
                sensitive_fields = self.introspection_analyzer.find_sensitive_fields(types)
                
                if sensitive_fields:
                    vuln = GraphQLVulnerability(
                        vulnerability_type='GraphQL Vulnerability',
                        graphql_type=GraphQLVulnerabilityType.INTROSPECTION_ENABLED,
                        url=endpoint.url,
                        severity='High',
                        evidence=f'Introspection enabled: {len(types)} types, {len(sensitive_fields)} sensitive fields | Schema hash: {endpoint.schema_hash[:16]}',
                        affected_fields=[f[1] for f in sensitive_fields],
                        affected_types=[f[0] for f in sensitive_fields],
                        response_data=json.dumps(sensitive_fields[:10]),
                        confirmed=True,
                        confidence_score=0.95,
                        remediation=self._remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['introspection_enabled'] += 1
                
                if mutations:
                    vuln = GraphQLVulnerability(
                        vulnerability_type='GraphQL Vulnerability',
                        graphql_type=GraphQLVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
                        url=endpoint.url,
                        severity='Medium',
                        evidence=f'{len(mutations)} mutations exposed: {", ".join(mutations[:10])}',
                        affected_fields=mutations,
                        confirmed=True,
                        confidence_score=0.85,
                        remediation=self._remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['mutations_exposed'] += 1
                
                if subscriptions:
                    vuln = GraphQLVulnerability(
                        vulnerability_type='GraphQL Vulnerability',
                        graphql_type=GraphQLVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
                        url=endpoint.url,
                        severity='Low',
                        evidence=f'{len(subscriptions)} subscriptions available: {", ".join(subscriptions[:5])}',
                        affected_fields=subscriptions,
                        confirmed=True,
                        confidence_score=0.7,
                        remediation=self._remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['subscriptions_exposed'] += 1
            
            alias_payload = self.payload_generator.generate_alias_attack_payload('user { id }', 100)
            is_vulnerable_alias, alias_count = self.query_analyzer.detect_alias_attack(alias_payload)
            complexity_alias = self.query_analyzer.estimate_query_complexity(alias_payload)
            
            if is_vulnerable_alias and alias_count > 50:
                vuln = GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.ALIAS_ATTACK,
                    url=endpoint.url,
                    severity='High',
                    evidence=f'Alias attack: {alias_count} aliases | Complexity: {complexity_alias:.2f}',
                    query_used=alias_payload[:200],
                    complexity_score=complexity_alias,
                    confirmed=False,
                    confidence_score=0.75,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['alias_attack'] += 1
            
            deep_query = self.payload_generator.generate_deep_nested_query(100)
            depth = self.query_analyzer.analyze_query_depth(deep_query)
            complexity_deep = self.query_analyzer.estimate_query_complexity(deep_query)
            
            if depth > 20:
                vuln = GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.DEPTH_LIMIT_BYPASS,
                    url=endpoint.url,
                    severity='High',
                    evidence=f'Deep nesting: {depth} levels | Complexity: {complexity_deep:.2f}',
                    query_used=deep_query[:200],
                    depth_score=depth,
                    complexity_score=complexity_deep,
                    confirmed=False,
                    confidence_score=0.8,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['depth_limit_bypass'] += 1
            
            circular_query = self.payload_generator.generate_circular_query('user', 50)
            is_circular, circular_fields = self.query_analyzer.detect_circular_references(circular_query)
            
            if is_circular:
                vuln = GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.CIRCULAR_QUERY,
                    url=endpoint.url,
                    severity='Medium',
                    evidence=f'Circular references: {", ".join(circular_fields[:5])}',
                    query_used=circular_query[:200],
                    affected_fields=circular_fields,
                    confirmed=False,
                    confidence_score=0.7,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['circular_query'] += 1
            
            field_dupe_payload = self.payload_generator.generate_field_duplication_payload('id', 100)
            is_duped, duped_fields = self.query_analyzer.detect_field_duplication(field_dupe_payload)
            
            if is_duped:
                vuln = GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.FIELD_DUPLICATION,
                    url=endpoint.url,
                    severity='Medium',
                    evidence=f'Field duplication: {", ".join([f"{k}:{v}x" for k, v in list(duped_fields.items())[:3]])}',
                    query_used=field_dupe_payload[:200],
                    confirmed=False,
                    confidence_score=0.7,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['field_duplication'] += 1
            
            batch_payload = self.payload_generator.generate_batch_query('{ user { id } }', 100)
            if len(batch_payload) >= 50:
                vuln = GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.BATCH_ATTACK,
                    url=endpoint.url,
                    severity='Medium',
                    evidence=f'Batch attack: {len(batch_payload)} operations in single request',
                    query_used=json.dumps(batch_payload[:3]),
                    confirmed=False,
                    confidence_score=0.75,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['batch_attack'] += 1
            
            errors = self.error_analyzer.parse_graphql_errors(response_content)
            if errors:
                has_disclosure, disclosure_types = self.error_analyzer.detect_information_disclosure(errors)
                
                if has_disclosure:
                    vuln = GraphQLVulnerability(
                        vulnerability_type='GraphQL Vulnerability',
                        graphql_type=GraphQLVulnerabilityType.SENSITIVE_DATA_IN_LOGS,
                        url=endpoint.url,
                        severity='Medium',
                        evidence=f'Information disclosure: {", ".join(disclosure_types[:5])}',
                        response_data=json.dumps(errors[:3]),
                        confirmed=True,
                        confidence_score=0.85,
                        remediation=self._remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['info_disclosure'] += 1
                
                if self.error_analyzer.detect_sql_errors(errors):
                    vuln = GraphQLVulnerability(
                        vulnerability_type='GraphQL Vulnerability',
                        graphql_type=GraphQLVulnerabilityType.GRAPHQL_INJECTION,
                        url=endpoint.url,
                        severity='Critical',
                        evidence='SQL errors detected in GraphQL responses',
                        response_data=json.dumps(errors[:2]),
                        confirmed=True,
                        confidence_score=0.9,
                        remediation=self._remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['sql_injection'] += 1
        
        with self.lock:
            for endpoint in endpoints:
                self.discovered_endpoints[endpoint.url] = endpoint
            self.vulnerabilities.extend(vulnerabilities)
            self.scan_statistics['total_scans'] += 1
        
        return vulnerabilities
    
    def test_query_execution(self, endpoint_url: str, query: str) -> Tuple[bool, Optional[str]]:
        complexity = self.query_analyzer.estimate_query_complexity(query)
        depth = self.query_analyzer.analyze_query_depth(query)
        estimated_size = self.query_analyzer.calculate_estimated_response_size(query)
        
        if complexity > 1000:
            return False, f"Query complexity too high: {complexity:.2f}"
        
        if depth > 50:
            return False, f"Query depth too deep: {depth}"
        
        if estimated_size > 10000000:
            return False, f"Estimated response too large: {estimated_size} bytes"
        
        query_hash = hashlib.sha256(query.encode()).hexdigest()
        if query_hash in self.tested_queries:
            return False, "Query already tested"
        
        with self.lock:
            self.tested_queries.add(query_hash)
        
        return True, None
    
    def get_discovered_endpoints(self) -> Dict[str, GraphQLEndpoint]:
        with self.lock:
            return self.discovered_endpoints.copy()
    
    def get_vulnerabilities(self) -> List[GraphQLVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def get_tested_queries(self) -> Set[str]:
        with self.lock:
            return self.tested_queries.copy()
    
    def clear(self):
        with self.lock:
            self.discovered_endpoints.clear()
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.tested_queries.clear()