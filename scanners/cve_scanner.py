# scanners/cve_scanner.py
from typing import List, Dict, Optional, Tuple, Set
import requests
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json


class CVEScanner:
    
    def __init__(self, timeout: int = 10, max_workers: int = 20, user_agent: str = None):
        self.timeout = timeout
        self.max_workers = max_workers
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        self.session = self._create_session()
        self.scan_cache = {}
        self.fingerprint_cache = {}
        self.vulnerability_cache = {}
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })
        session.max_redirects = 5
        return session
    
    def scan(self, target_url: str, severity_filter: str = 'ALL', 
             categories: List[str] = None, enable_deep_scan: bool = True,
             enable_fingerprinting: bool = True) -> List[Dict]:
        
        if not self._validate_url(target_url):
            raise ValueError('Invalid target URL')
        
        vulnerabilities = []
        
        cache_key = hashlib.md5(f"{target_url}{severity_filter}".encode()).hexdigest()
        if cache_key in self.scan_cache:
            return self.scan_cache[cache_key]
        
        from core.cve_payloads import CVEPayloads
        cve_list = CVEPayloads.get_all_cves()
        
        if severity_filter != 'ALL':
            cve_list = [cve for cve in cve_list if cve['severity'] == severity_filter or 
                       (severity_filter == 'HIGH' and cve['severity'] == 'CRITICAL')]
        
        if categories:
            cve_list = [cve for cve in cve_list if cve['category'] in categories]
        
        base_fingerprint = None
        if enable_fingerprinting:
            base_fingerprint = self._advanced_fingerprinting(target_url)
        
        if not base_fingerprint and enable_deep_scan:
            return vulnerabilities
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self._test_cve_advanced,
                    target_url,
                    cve,
                    base_fingerprint,
                    enable_deep_scan
                ): cve for cve in cve_list
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=self.timeout * 2)
                    if result:
                        vulnerabilities.append(result)
                except Exception:
                    continue
        
        vulnerabilities = sorted(vulnerabilities, key=lambda x: (x['score'], x['confidence']), reverse=True)
        self.scan_cache[cache_key] = vulnerabilities
        
        return vulnerabilities
    
    def _validate_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _advanced_fingerprinting(self, target_url: str) -> Optional[Dict]:
        try:
            response = self.session.get(
                target_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            fingerprint = {
                'url': target_url,
                'status_code': response.status_code,
                'content': response.text.lower(),
                'headers': {k.lower(): v.lower() for k, v in response.headers.items()},
                'cookies': {k: v for k, v in response.cookies.items()},
                'response_time': response.elapsed.total_seconds(),
                'content_length': len(response.content),
                'content_hash': hashlib.sha256(response.content).hexdigest(),
                'server': response.headers.get('Server', '').lower(),
                'powered_by': response.headers.get('X-Powered-By', '').lower(),
                'technologies': self._detect_technologies_advanced(response),
                'cms': self._detect_cms(response),
                'framework': self._detect_framework(response),
                'waf': self._detect_waf(response),
                'os': self._detect_os(response),
                'database': self._detect_database(response),
                'ports_open': self._scan_common_ports(target_url),
            }
            
            return fingerprint
            
        except Exception:
            return None
    
    def _detect_technologies_advanced(self, response: requests.Response) -> Dict:
        technologies = {
            'web_servers': [],
            'frameworks': [],
            'languages': [],
            'cms': [],
            'js_frameworks': [],
            'libraries': []
        }
        
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        web_servers = {
            'apache': ['server: apache', 'apache/'],
            'nginx': ['server: nginx', 'nginx/'],
            'iis': ['server: microsoft-iis', 'x-aspnet-version'],
            'tomcat': ['server: apache tomcat', 'tomcat/'],
            'lighttpd': ['server: lighttpd'],
        }
        
        frameworks = {
            'django': ['django', 'x-django-version'],
            'flask': ['flask', 'x-powered-by: flask'],
            'rails': ['rails', 'x-powered-by: rails'],
            'express': ['express', 'x-powered-by: express'],
            'laravel': ['laravel', 'x-powered-by: php', 'laravel_session'],
            'spring': ['/spring/', 'spring framework'],
            'asp.net': ['x-aspnet-version', 'x-aspnetmvc-version'],
        }
        
        cms_list = {
            'wordpress': ['/wp-content/', '/wp-includes/', 'wp-json', 'wordpress'],
            'drupal': ['/sites/default/', 'drupal.js', 'x-drupal'],
            'joomla': ['/components/', '/modules/', 'joomla'],
            'magento': ['/skin/frontend/', 'mage/', 'magento'],
        }
        
        js_frameworks = {
            'react': ['react', '_next', '__react', 'react-id'],
            'vue': ['vue.js', '__vue__', 'v-app'],
            'angular': ['ng-version', 'angular', '__ng'],
            'jquery': ['jquery', '$'],
        }
        
        for tech, signatures in web_servers.items():
            if any(sig in content or any(sig in v for v in headers.values()) for sig in signatures):
                technologies['web_servers'].append(tech)
        
        for tech, signatures in frameworks.items():
            if any(sig in content or any(sig in v for v in headers.values()) for sig in signatures):
                technologies['frameworks'].append(tech)
        
        for tech, signatures in cms_list.items():
            if any(sig in content for sig in signatures):
                technologies['cms'].append(tech)
        
        for tech, signatures in js_frameworks.items():
            if any(sig in content for sig in signatures):
                technologies['js_frameworks'].append(tech)
        
        return technologies
    
    def _detect_cms(self, response: requests.Response) -> str:
        content = response.text.lower()
        
        cms_signatures = {
            'wordpress': ['wp-content', 'wp-includes', 'wp-json'],
            'drupal': ['sites/default', 'drupal.js', 'x-drupal-version'],
            'joomla': ['components/com_', 'joomla'],
            'magento': ['skin/frontend', 'mage/'],
            'prestashop': ['modules/', 'classes/'],
            'opencart': ['/catalog/', '/admin/'],
            'wix': ['wix.com', 'www.wix.com'],
            'shopify': ['cdn.shopify.com', 'myshopify.com'],
        }
        
        for cms, signatures in cms_signatures.items():
            if any(sig in content for sig in signatures):
                return cms
        
        return 'Unknown'
    
    def _detect_framework(self, response: requests.Response) -> str:
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        framework_signatures = {
            'django': ['django', 'csrftoken'],
            'flask': ['flask', 'jinja'],
            'rails': ['rails', '__requestId__'],
            'express': ['x-powered-by: express'],
            'laravel': ['laravel_session', 'csrf-token'],
            'spring': ['/spring-', 'org.springframework'],
            'asp.net': ['x-aspnet-version', '__viewstate'],
            'jsp': ['jsessionid'],
        }
        
        for framework, signatures in framework_signatures.items():
            if any(sig in content or any(sig in v for v in headers.values()) for sig in signatures):
                return framework
        
        return 'Unknown'
    
    def _detect_waf(self, response: requests.Response) -> str:
        headers = response.headers
        
        waf_signatures = {
            'CloudFlare': ['cf-ray', 'cf-cache-status'],
            'AWS WAF': ['x-amzn-RequestId'],
            'Imperva': ['x-iinfo', 'x-protected-by'],
            'F5 BIG-IP': ['x-lb-', 'bigipserverid'],
            'Barracuda': ['x-barracuda-', 'barracuda-encrypted'],
            'ModSecurity': ['modsecurity'],
            'Akamai': ['akamai-origin-hop'],
            'DDoS-GUARD': ['ddos-guard'],
        }
        
        for waf, signatures in waf_signatures.items():
            if any(sig.lower() in str(headers).lower() for sig in signatures):
                return waf
        
        return 'None'
    
    def _detect_os(self, response: requests.Response) -> str:
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        os_signatures = {
            'Windows': ['windows', 'iis', 'asp.net'],
            'Linux': ['linux', 'nginx', 'apache'],
            'macOS': ['darwin', 'osx'],
            'FreeBSD': ['freebsd'],
        }
        
        for os, signatures in os_signatures.items():
            if any(sig in content or any(sig in v for v in headers.values()) for sig in signatures):
                return os
        
        return 'Unknown'
    
    def _detect_database(self, response: requests.Response) -> List[str]:
        content = response.text.lower()
        
        database_signatures = {
            'MySQL': ['mysql', 'mariadb'],
            'PostgreSQL': ['postgresql', 'postgres'],
            'MongoDB': ['mongodb', 'mongoose'],
            'Oracle': ['oracle', 'ojdbc'],
            'MSSQL': ['mssql', 'sql server'],
            'Redis': ['redis', 'redisearch'],
            'Elasticsearch': ['elasticsearch', 'kibana'],
        }
        
        detected = []
        for db, signatures in database_signatures.items():
            if any(sig in content for sig in signatures):
                detected.append(db)
        
        return detected
    
    def _scan_common_ports(self, target_url: str) -> List[int]:
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(':')[0]
        
        common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443, 9200]
        open_ports = []
        
        for port in common_ports:
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports
    
    def _test_cve_advanced(self, target_url: str, cve: Dict, fingerprint: Dict, enable_deep_scan: bool) -> Optional[Dict]:
        try:
            if not self._check_patterns_advanced(cve, fingerprint):
                return None
            
            verification_result = self._verify_cve_advanced(target_url, cve, fingerprint)
            
            if not verification_result['is_vulnerable']:
                return None
            
            return {
                'id': cve['id'],
                'name': cve['name'],
                'severity': cve['severity'],
                'score': cve['score'],
                'description': cve['description'],
                'category': cve['category'],
                'reference': cve['reference'],
                'affected_software': cve.get('affected_software', []),
                'cvss_vector': cve.get('cvss_vector', ''),
                'fix_available': cve.get('fix_available', False),
                'publication_date': cve.get('publication_date', ''),
                'found_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'target': target_url,
                'confidence': self._calculate_confidence_advanced(cve, fingerprint, verification_result),
                'verification_method': verification_result.get('method', 'PATTERN_MATCH'),
                'evidence': verification_result.get('evidence', []),
                'exploitable': verification_result.get('exploitable', False)
            }
            
        except Exception:
            return None
    
    def _check_patterns_advanced(self, cve: Dict, fingerprint: Dict) -> bool:
        if not fingerprint:
            return False
        
        content = fingerprint.get('content', '')
        headers = fingerprint.get('headers', {})
        technologies = fingerprint.get('technologies', {})
        cms = fingerprint.get('cms', 'Unknown')
        
        patterns = cve.get('patterns', [])
        pattern_matches = 0
        
        for pattern in patterns:
            pattern_lower = pattern.lower()
            
            if pattern_lower in content:
                pattern_matches += 1
                continue
            
            if any(pattern_lower in str(v).lower() for v in headers.values()):
                pattern_matches += 1
                continue
            
            if cms.lower() == pattern_lower:
                pattern_matches += 1
                continue
            
            all_techs = (technologies.get('frameworks', []) + 
                        technologies.get('web_servers', []) + 
                        technologies.get('cms', []))
            
            if any(pattern_lower in str(tech).lower() for tech in all_techs):
                pattern_matches += 1
        
        match_percentage = (pattern_matches / len(patterns) * 100) if patterns else 0
        return match_percentage >= 25
    
    def _verify_cve_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        category = cve.get('category', 'UNKNOWN')
        
        verification_methods = {
            'RCE': self._verify_rce_advanced,
            'SQLi': self._verify_sqli_advanced,
            'XSS': self._verify_xss_advanced,
            'SSRF': self._verify_ssrf_advanced,
            'XXE': self._verify_xxe_advanced,
            'SSTI': self._verify_ssti_advanced,
            'PATH_TRAVERSAL': self._verify_path_traversal_advanced,
            'LFI': self._verify_lfi_advanced,
            'DESERIALIZATION': self._verify_deserialization_advanced,
            'IDOR': self._verify_idor_advanced,
            'CSRF': self._verify_csrf_advanced,
            'INFO_DISCLOSURE': self._verify_info_disclosure_advanced,
            'MISCONFIGURATION': self._verify_misconfiguration_advanced,
            'NoSQLi': self._verify_nosqli_advanced,
        }
        
        verifier = verification_methods.get(category, self._verify_generic_advanced)
        return verifier(target_url, cve, fingerprint)
    
    def _verify_rce_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'RCE_CHECK'}
        
        test_payloads = [
            {'payload': 'test_param=`id`', 'indicator': ['uid=', 'gid='], 'type': 'SHELL'},
            {'payload': 'cmd=whoami', 'indicator': ['root', 'administrator'], 'type': 'WHOAMI'},
            {'payload': 'exec=sleep 5', 'indicator': 'delay', 'type': 'TIME_BASED'},
        ]
        
        for test in test_payloads:
            try:
                test_url = f"{target_url}?{test['payload']}"
                start_time = time.time()
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                response_time = time.time() - start_time
                
                if test['type'] == 'TIME_BASED' and response_time > 4:
                    result['is_vulnerable'] = True
                    result['exploitable'] = True
                    result['evidence'].append(f'Time delay detected: {response_time:.2f}s')
                    result['method'] = 'TIME_BASED_RCE'
                    return result
                
                if isinstance(test['indicator'], list):
                    if any(ind in response.text for ind in test['indicator']):
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f"RCE indicator found: {test['indicator']}")
                        result['method'] = 'PAYLOAD_RESPONSE'
                        return result
                
            except requests.Timeout:
                result['is_vulnerable'] = True
                result['exploitable'] = True
                result['evidence'].append('Timeout - possible RCE')
                result['method'] = 'TIMEOUT_RCE'
                return result
            except Exception:
                continue
        
        return result
    
    def _verify_sqli_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'SQLI_CHECK'}
        
        injectable_params = self._identify_injectable_params(target_url)
        
        sql_tests = [
            {'payload': "' OR '1'='1", 'type': 'OR_BASED', 'indicators': ['error', 'syntax']},
            {'payload': "' AND 1=1--", 'type': 'AND_BASED', 'indicators': ['error']},
            {'payload': "' UNION SELECT NULL--", 'type': 'UNION_BASED', 'indicators': ['columns']},
            {'payload': "'; SLEEP(5)--", 'type': 'TIME_BASED', 'delay': 5},
        ]
        
        for param in injectable_params[:5]:
            for test in sql_tests:
                try:
                    test_url = f"{target_url}?{param}={test['payload']}"
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    response_time = time.time() - start_time
                    
                    if test['type'] == 'TIME_BASED' and response_time > test.get('delay', 3):
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'Time-based SQLi on {param}')
                        result['method'] = 'TIME_BASED_SQLI'
                        return result
                    
                    sql_errors = ['SQL syntax', 'mysql_', 'sqlite', 'postgresql', 'SQLSTATE']
                    if any(err.lower() in response.text.lower() for err in sql_errors):
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'SQL error on {param}')
                        result['method'] = 'ERROR_BASED_SQLI'
                        return result
                    
                except Exception:
                    continue
        
        return result
    
    def _verify_xss_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'XSS_CHECK'}
        
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)',
        ]
        
        injectable_params = self._identify_injectable_params(target_url)
        
        for param in injectable_params[:5]:
            for payload in xss_payloads:
                try:
                    test_url = f"{target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if payload in response.text:
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'XSS payload reflected in {param}')
                        result['method'] = 'REFLECTED_XSS'
                        return result
                    
                except Exception:
                    continue
        
        return result
    
    def _verify_ssrf_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'SSRF_CHECK'}
        
        ssrf_payloads = [
            'http://127.0.0.1:8080',
            'http://127.0.0.1:3306',
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://localhost:6379',
        ]
        
        injectable_params = self._identify_injectable_params(target_url)
        
        for param in injectable_params[:3]:
            for payload in ssrf_payloads:
                try:
                    test_url = f"{target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout * 2, verify=False)
                    
                    ssrf_indicators = ['metadata', 'credentials', 'ami-id', 'REDIS', 'MySQL']
                    if any(ind in response.text for ind in ssrf_indicators):
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'SSRF to {payload}')
                        result['method'] = 'METADATA_ACCESS'
                        return result
                    
                except Exception:
                    continue
        
        return result
    
    def _verify_xxe_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'XXE_CHECK'}
        
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://localhost:8080">]><test>&xxe;</test>',
        ]
        
        for payload in xxe_payloads:
            try:
                response = self.session.post(
                    target_url,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.timeout,
                    verify=False
                )
                
                xxe_indicators = ['root:', 'daemon:', 'bin:', 'sys:']
                if any(ind in response.text for ind in xxe_indicators):
                    result['is_vulnerable'] = True
                    result['exploitable'] = True
                    result['evidence'].append('XXE file disclosure')
                    result['method'] = 'FILE_DISCLOSURE_XXE'
                    return result
                
            except Exception:
                continue
        
        return result
    
    def _verify_ssti_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'SSTI_CHECK'}
        
        ssti_payloads = [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('<%=7*7%>', '49'),
            ('[=7*7=]', '49'),
        ]
        
        injectable_params = self._identify_injectable_params(target_url)
        
        for param in injectable_params[:5]:
            for payload, expected in ssti_payloads:
                try:
                    test_url = f"{target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if expected in response.text:
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'SSTI in {param}')
                        result['method'] = 'EXPRESSION_EVAL_SSTI'
                        return result
                    
                except Exception:
                    continue
        
        return result
    
    def _verify_path_traversal_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'PT_CHECK'}
        
        traversal_payloads = [
            '../../../../etc/passwd',
            '..\\..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
        ]
        
        injectable_params = self._identify_injectable_params(target_url)
        
        for param in injectable_params[:5]:
            for payload in traversal_payloads:
                try:
                    test_url = f"{target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if 'root:' in response.text or '[boot loader]' in response.text:
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'File disclosure in {param}')
                        result['method'] = 'FILE_DISCLOSURE_PT'
                        return result
                    
                except Exception:
                    continue
        
        return result
    
    def _verify_lfi_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        return self._verify_path_traversal_advanced(target_url, cve, fingerprint)
    
    def _verify_deserialization_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'DESER_CHECK'}
        
        if 'java' in cve.get('description', '').lower() or 'serialization' in fingerprint.get('content', '').lower():
            result['is_vulnerable'] = True
            result['exploitable'] = False
            result['evidence'].append('Java deserialization framework detected')
            result['method'] = 'FRAMEWORK_DETECTION'
        
        return result
    
    def _verify_idor_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'IDOR_CHECK'}
        
        try:
            test_urls = [
                f"{target_url}?id=1",
                f"{target_url}?id=2",
                f"{target_url}?user=1",
                f"{target_url}?user=2",
            ]
            
            responses = {}
            for test_url in test_urls:
                try:
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    responses[test_url] = resp.status_code
                except:
                    pass
            
            if len(set(responses.values())) == 1 and 200 in responses.values():
                result['is_vulnerable'] = True
                result['evidence'].append('Same response for different IDs')
                result['method'] = 'IDOR_PATTERN'
        
        except Exception:
            pass
        
        return result
    
    def _verify_csrf_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'CSRF_CHECK'}
        return result
    
    def _verify_info_disclosure_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'INFO_CHECK'}
        
        sensitive_paths = ['/.git/config', '/.env', '/web.config', '/admin', '/.well-known/security.txt']
        
        for path in sensitive_paths:
            try:
                test_url = urljoin(target_url, path)
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    result['is_vulnerable'] = True
                    result['evidence'].append(f'Accessible: {path}')
                    result['method'] = 'SENSITIVE_PATH_ACCESSIBLE'
                    return result
                
            except Exception:
                continue
        
        return result
    
    def _verify_misconfiguration_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'MISC_CHECK'}
        
        try:
            response = self.session.get(target_url, timeout=self.timeout, verify=False)
            
            debug_indicators = ['debug', 'test', 'localhost', 'password', 'secret']
            found_indicators = [ind for ind in debug_indicators if ind in response.text.lower()]
            
            if found_indicators:
                result['is_vulnerable'] = True
                result['evidence'].append(f'Debug indicators: {found_indicators}')
                result['method'] = 'DEBUG_DETECTION'
        
        except Exception:
            pass
        
        return result
    
    def _verify_nosqli_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'NOSQLI_CHECK'}
        return result
    
    def _verify_generic_advanced(self, target_url: str, cve: Dict, fingerprint: Dict) -> Dict:
        return {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'GENERIC_CHECK'}
    
    def _identify_injectable_params(self, target_url: str) -> List[str]:
        params = []
        
        parsed = urlparse(target_url)
        query_params = parse_qs(parsed.query)
        params.extend(query_params.keys())
        
        common_params = ['id', 'q', 'search', 'query', 'keyword', 'name', 'user', 'file', 'page', 'data', 'url', 'path', 'cmd', 'exec', 'function']
        params.extend(common_params)
        
        return list(set(params))[:10]
    
    def _calculate_confidence_advanced(self, cve: Dict, fingerprint: Dict, verification: Dict) -> float:
        confidence = 0.0
        
        if verification.get('is_vulnerable'):
            confidence = 0.5
        
        if verification.get('exploitable'):
            confidence += 0.3
        
        evidence_count = len(verification.get('evidence', []))
        confidence += min(evidence_count * 0.05, 0.2)
        
        return min(confidence, 1.0)
    
    def get_scan_report(self, vulnerabilities: List[Dict]) -> Dict:
        if not vulnerabilities:
            return {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'exploitable': 0,
                'by_category': {},
                'avg_score': 0,
                'avg_confidence': 0,
                'high_priority': []
            }
        
        report = {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW'),
            'exploitable': sum(1 for v in vulnerabilities if v.get('exploitable', False)),
            'by_category': {},
            'avg_score': sum(v['score'] for v in vulnerabilities) / len(vulnerabilities),
            'avg_confidence': sum(v['confidence'] for v in vulnerabilities) / len(vulnerabilities),
            'high_priority': [v for v in vulnerabilities if v['severity'] in ['CRITICAL', 'HIGH'] and v.get('exploitable', False)][:5]
        }
        
        for vuln in vulnerabilities:
            cat = vuln['category']
            report['by_category'][cat] = report['by_category'].get(cat, 0) + 1
        
        return report
