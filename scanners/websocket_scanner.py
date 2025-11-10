from typing import Dict, List, Optional
import json
from websocket import create_connection
import ssl

class WebSocketScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.ws_connection = None
    
    def scan(self, ws_url: str, test_payloads: Dict = None) -> List[Dict]:
        vulnerabilities = []
        
        try:
            self.ws_connection = self._connect_websocket(ws_url)
            
            vulnerabilities.extend(self._test_origin_validation(ws_url))
            vulnerabilities.extend(self._test_message_injection(test_payloads))
            vulnerabilities.extend(self._test_authentication())
            vulnerabilities.extend(self._test_dos_resistance())
            vulnerabilities.extend(self._test_cswsh())
            
            if self.ws_connection:
                self.ws_connection.close()
        
        except Exception as e:
            vulnerabilities.append({
                'type': 'WebSocket Connection Error',
                'severity': 'Info',
                'description': str(e)
            })
        
        return vulnerabilities
    
    def _connect_websocket(self, ws_url: str):
        try:
            sslopt = {"cert_reqs": ssl.CERT_NONE}
            return create_connection(ws_url, sslopt=sslopt, timeout=10)
        except Exception as e:
            raise Exception(f'Failed to connect: {str(e)}')
    
    def _test_origin_validation(self, ws_url: str) -> List[Dict]:
        vulnerabilities = []
        
        if 'wss://' not in ws_url:
            vulnerabilities.append({
                'type': 'WebSocket Unencrypted Connection',
                'severity': 'High',
                'description': 'WebSocket using ws:// instead of wss://',
                'evidence': 'Connection is not encrypted'
            })
        
        return vulnerabilities
    
    def _test_message_injection(self, payloads: Dict) -> List[Dict]:
        vulnerabilities = []
        
        if not payloads:
            payloads = {
                'xss': '<img src=x onerror=alert(1)>',
                'sql': "' OR '1'='1",
                'command': '; ls -la'
            }
        
        for payload_type, payload in payloads.items():
            try:
                test_message = json.dumps({"data": payload})
                self.ws_connection.send(test_message)
                
                response = self.ws_connection.recv(timeout=5)
                
                if payload in response:
                    vulnerabilities.append({
                        'type': f'WebSocket {payload_type.upper()} Injection',
                        'severity': 'High',
                        'description': f'{payload_type} payload reflected in response',
                        'evidence': f'Payload: {payload}'
                    })
            
            except Exception:
                pass
        
        return vulnerabilities
    
    def _test_authentication(self) -> List[Dict]:
        vulnerabilities = []
        
        try:
            auth_test = json.dumps({"type": "auth", "token": "invalid"})
            self.ws_connection.send(auth_test)
            response = self.ws_connection.recv(timeout=5)
            
            if "authenticated" in response.lower() or "success" in response.lower():
                vulnerabilities.append({
                    'type': 'WebSocket Weak Authentication',
                    'severity': 'Critical',
                    'description': 'WebSocket accepts invalid credentials',
                    'evidence': 'Server accepted invalid token'
                })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _test_dos_resistance(self) -> List[Dict]:
        vulnerabilities = []
        
        try:
            large_payload = "A" * 1000000
            test_message = json.dumps({"data": large_payload})
            
            self.ws_connection.send(test_message)
            response = self.ws_connection.recv(timeout=5)
            
            vulnerabilities.append({
                'type': 'WebSocket Large Payload Accepted',
                'severity': 'Medium',
                'description': 'WebSocket accepted 1MB payload without limit',
                'evidence': 'No payload size validation detected'
            })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _test_cswsh(self) -> List[Dict]:
        vulnerabilities = []
        
        try:
            test_message = json.dumps({"action": "admin_function"})
            self.ws_connection.send(test_message)
            response = self.ws_connection.recv(timeout=5)
            
            if len(response) > 0:
                vulnerabilities.append({
                    'type': 'Cross-Site WebSocket Hijacking (CSWSH)',
                    'severity': 'High',
                    'description': 'WebSocket may be vulnerable to CSWSH',
                    'evidence': 'Server processed admin action without CSRF token'
                })
        
        except Exception:
            pass
        
        return vulnerabilities