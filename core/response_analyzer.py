from typing import Dict, List
from bs4 import BeautifulSoup
import re

class ResponseAnalyzer:
    def __init__(self):
        pass
    
    def analyze(self, response: Dict) -> Dict:
        analysis = {
            'forms': self._extract_forms(response),
            'inputs': self._extract_inputs(response),
            'links': self._extract_links(response),
            'cookies': self._extract_cookies(response),
            'headers': self._analyze_headers(response),
            'technologies': self._detect_technologies(response)
        }
        
        return analysis
    
    def _extract_forms(self, response: Dict) -> List[Dict]:
        forms = []
        content = response.get('content', '')
        
        soup = BeautifulSoup(content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                form_data['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                })
            
            forms.append(form_data)
        
        return forms
    
    def _extract_inputs(self, response: Dict) -> List[Dict]:
        inputs = []
        content = response.get('content', '')
        
        soup = BeautifulSoup(content, 'html.parser')
        
        for input_tag in soup.find_all('input'):
            inputs.append({
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', '')
            })
        
        return inputs
    
    def _extract_links(self, response: Dict) -> List[str]:
        links = []
        content = response.get('content', '')
        
        soup = BeautifulSoup(content, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            links.append(link['href'])
        
        return links
    
    def _extract_cookies(self, response: Dict) -> List[Dict]:
        cookies = []
        headers = response.get('headers', {})
        
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            cookies.append({
                'raw': set_cookie,
                'secure': 'Secure' in set_cookie,
                'httponly': 'HttpOnly' in set_cookie,
                'samesite': 'SameSite' in set_cookie
            })
        
        return cookies
    
    def _analyze_headers(self, response: Dict) -> Dict:
        headers = response.get('headers', {})
        
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-XSS-Protection': headers.get('X-XSS-Protection')
        }
        
        return {
            'security_headers': security_headers,
            'server': headers.get('Server', 'Unknown'),
            'powered_by': headers.get('X-Powered-By', 'Unknown')
        }
    
    def _detect_technologies(self, response: Dict) -> List[str]:
        technologies = []
        content = response.get('content', '').lower()
        headers = response.get('headers', {})
        
        tech_patterns = {
            'WordPress': r'wp-content|wp-includes',
            'Joomla': r'joomla',
            'Drupal': r'drupal',
            'PHP': r'\.php',
            'ASP.NET': r'\.aspx|asp\.net',
            'Node.js': r'express',
            'React': r'react',
            'Angular': r'angular',
            'Vue.js': r'vue'
        }
        
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, content):
                technologies.append(tech)
        
        server = headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            technologies.append(f"Powered by: {powered_by}")
        
        return list(set(technologies))