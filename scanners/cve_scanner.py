from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import re
import time
import hashlib
import json
import socket
from urllib.parse import urljoin, urlparse, parse_qs
from collections import defaultdict
import threading

class CVESeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class CVECategory(Enum):
    RCE = "RCE"
    SQLI = "SQLi"
    XSS = "XSS"
    SSRF = "SSRF"
    XXE = "XXE"
    SSTI = "SSTI"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    LFI = "LFI"
    DESERIALIZATION = "DESERIALIZATION"
    IDOR = "IDOR"
    CSRF = "CSRF"
    INFO_DISCLOSURE = "INFO_DISCLOSURE"
    MISCONFIGURATION = "MISCONFIGURATION"
    NOSQLI = "NoSQLi"
    PROTOTYPE_POLLUTION = "PROTOTYPE_POLLUTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"

@dataclass
class Fingerprint:
    url: str
    status_code: int
    content: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    response_time: float
    content_length: int
    content_hash: str
    server: str
    powered_by: str
    technologies: Dict[str, List[str]]
    cms: str
    framework: str
    waf: str
    os: str
    database: List[str]
    ports_open: List[int]
    js_libraries: List[str]
    security_headers: Dict[str, bool]

@dataclass
class CVEVulnerability:
    id: str
    name: str
    severity: str
    score: float
    description: str
    category: str
    reference: str
    affected_software: List[str]
    cvss_vector: str
    fix_available: bool
    publication_date: str
    found_at: str
    target: str
    confidence: float
    verification_method: str
    evidence: List[str]
    exploitable: bool
    exploit_code: Optional[str] = None
    remediation: str = ""

class MegaTechnologyDetector:
    WEB_SERVERS = {
        'apache': ['server: apache', 'apache/', 'x-powered-by: apache'],
        'nginx': ['server: nginx', 'nginx/'],
        'iis': ['server: microsoft-iis', 'x-aspnet-version', 'x-aspnetmvc-version'],
        'tomcat': ['server: apache tomcat', 'tomcat/', 'x-catalina'],
        'lighttpd': ['server: lighttpd'],
        'caddy': ['server: caddy'],
        'litespeed': ['server: litespeed'],
    }
    
    FRAMEWORKS = {
        'django': ['django', 'x-django-version', 'csrfmiddlewaretoken'],
        'flask': ['flask', 'x-powered-by: flask', 'werkzeug'],
        'rails': ['rails', 'x-powered-by: rails', 'x-runtime'],
        'express': ['express', 'x-powered-by: express'],
        'laravel': ['laravel', 'laravel_session', 'x-powered-by: php'],
        'spring': ['/spring-', 'org.springframework', 'x-application-context'],
        'asp.net': ['x-aspnet-version', 'x-aspnetmvc-version', '__viewstate'],
        'fastapi': ['fastapi', 'x-process-time'],
        'gin': ['x-powered-by: gin'],
    }
    
    CMS = {
        'wordpress': ['/wp-content/', '/wp-includes/', 'wp-json', '/wp-admin/'],
        'drupal': ['/sites/default/', 'drupal.js', 'x-drupal', '/core/'],
        'joomla': ['/components/', '/modules/', 'joomla', '/administrator/'],
        'magento': ['/skin/frontend/', 'mage/', 'magento', '/pub/'],
        'prestashop': ['/modules/', '/classes/', 'prestashop'],
        'opencart': ['/catalog/', 'route=', 'opencart'],
        'wix': ['wix.com', 'www.wix.com'],
        'shopify': ['cdn.shopify.com', 'myshopify.com'],
        'contentful': ['contentful.com'],
    }
    
    JS_FRAMEWORKS = {
        'react': ['react', '_next', '__react', 'react-id', 'data-reactroot'],
        'vue': ['vue.js', '__vue__', 'v-app', 'data-v-'],
        'angular': ['ng-version', 'angular', '__ng', 'ng-app'],
        'jquery': ['jquery', '$.', 'jquery.min.js'],
        'ember': ['ember', 'ember.js'],
        'svelte': ['svelte', '_svelte'],
        'next.js': ['_next/', '__next', 'next.js'],
    }
    
    @staticmethod
    def detect_all(response: requests.Response) -> Dict[str, List[str]]:
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        technologies = {
            'web_servers': [],
            'frameworks': [],
            'cms': [],
            'js_frameworks': [],
            'libraries': []
        }
        
        for tech, sigs in MegaTechnologyDetector.WEB_SERVERS.items():
            if any(s in content or any(s in v for v in headers.values()) for s in sigs):
                technologies['web_servers'].append(tech)
        
        for tech, sigs in MegaTechnologyDetector.FRAMEWORKS.items():
            if any(s in content or any(s in v for v in headers.values()) for s in sigs):
                technologies['frameworks'].append(tech)
        
        for tech, sigs in MegaTechnologyDetector.CMS.items():
            if any(s in content for s in sigs):
                technologies['cms'].append(tech)
        
        for tech, sigs in MegaTechnologyDetector.JS_FRAMEWORKS.items():
            if any(s in content for s in sigs):
                technologies['js_frameworks'].append(tech)
        
        return technologies

class MegaWAFDetector:
    SIGNATURES = {
        'CloudFlare': ['cf-ray', 'cf-cache-status', '__cfduid'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-'],
        'Imperva': ['x-iinfo', 'x-protected-by', 'incapsula'],
        'F5 BIG-IP': ['x-lb-', 'bigipserver', 'f5'],
        'Barracuda': ['x-barracuda', 'barracuda'],
        'ModSecurity': ['modsecurity', 'mod_security'],
        'Akamai': ['akamai', 'ak-'],
        'DDoS-GUARD': ['ddos-guard'],
        'Sucuri': ['x-sucuri-id', 'sucuri'],
        'Wordfence': ['wordfence'],
    }
    
    @staticmethod
    def detect(response: requests.Response) -> str:
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for waf, sigs in MegaWAFDetector.SIGNATURES.items():
            if any(s in str(headers) for s in sigs):
                return waf
        
        return 'None'

class MegaPortScanner:
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]
    
    @staticmethod
    def scan(domain: str, timeout: float = 1) -> List[int]:
        open_ports = []
        
        for port in MegaPortScanner.COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports

class MegaSecurityHeaderAnalyzer:
    REQUIRED_HEADERS = [
        'strict-transport-security',
        'x-frame-options',
        'x-content-type-options',
        'content-security-policy',
        'x-xss-protection',
        'referrer-policy',
        'permissions-policy'
    ]
    
    @staticmethod
    def analyze(headers: Dict) -> Dict[str, bool]:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        return {h: h in headers_lower for h in MegaSecurityHeaderAnalyzer.REQUIRED_HEADERS}

class CVEScanner:
    def __init__(self, timeout: int = 10, max_workers: int = 25, user_agent: str = None):
        self.timeout = timeout
        self.max_workers = max_workers
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.session = self._create_session()
        self.scan_cache = {}
        self.vulnerabilities = []
        self.lock = threading.Lock()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        session.max_redirects = 5
        return session
    
    def scan(self, target_url: str, severity_filter: str = 'ALL', 
             categories: List[str] = None, enable_deep_scan: bool = True) -> List[CVEVulnerability]:
        
        if not self._validate_url(target_url):
            raise ValueError('Invalid URL')
        
        cache_key = hashlib.md5(f"{target_url}{severity_filter}".encode()).hexdigest()
        if cache_key in self.scan_cache:
            return self.scan_cache[cache_key]
        
        from core.cve_payloads import CVEPayloads
        cve_list = CVEPayloads.get_all_cves()
        
        if severity_filter != 'ALL':
            cve_list = [c for c in cve_list if c['severity'] == severity_filter]
        
        if categories:
            cve_list = [c for c in cve_list if c['category'] in categories]
        
        fingerprint = self._mega_fingerprint(target_url)
        if not fingerprint:
            return []
        
        vulns = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._test_cve, target_url, cve, fingerprint): cve 
                for cve in cve_list
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=self.timeout * 2)
                    if result:
                        vulns.append(result)
                except:
                    continue
        
        vulns = sorted(vulns, key=lambda x: (x.score, x.confidence), reverse=True)
        
        with self.lock:
            self.vulnerabilities.extend(vulns)
            self.scan_cache[cache_key] = vulns
        
        return vulns
    
    def _validate_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _mega_fingerprint(self, url: str) -> Optional[Fingerprint]:
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            technologies = MegaTechnologyDetector.detect_all(response)
            waf = MegaWAFDetector.detect(response)
            
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            ports = MegaPortScanner.scan(domain)
            
            security_headers = MegaSecurityHeaderAnalyzer.analyze(response.headers)
            
            return Fingerprint(
                url=url,
                status_code=response.status_code,
                content=response.text.lower(),
                headers={k.lower(): v.lower() for k, v in response.headers.items()},
                cookies={k: v for k, v in response.cookies.items()},
                response_time=response.elapsed.total_seconds(),
                content_length=len(response.content),
                content_hash=hashlib.sha256(response.content).hexdigest(),
                server=response.headers.get('Server', '').lower(),
                powered_by=response.headers.get('X-Powered-By', '').lower(),
                technologies=technologies,
                cms=technologies['cms'][0] if technologies['cms'] else 'Unknown',
                framework=technologies['frameworks'][0] if technologies['frameworks'] else 'Unknown',
                waf=waf,
                os=self._detect_os(response),
                database=self._detect_db(response),
                ports_open=ports,
                js_libraries=technologies['js_frameworks'],
                security_headers=security_headers
            )
        except:
            return None
    
    def _detect_os(self, response: requests.Response) -> str:
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        os_sigs = {
            'Windows': ['windows', 'iis', 'asp.net', 'microsoft'],
            'Linux': ['linux', 'nginx', 'apache', 'ubuntu', 'debian'],
            'macOS': ['darwin', 'osx', 'mac'],
            'FreeBSD': ['freebsd'],
        }
        
        for os, sigs in os_sigs.items():
            if any(s in content or any(s in v for v in headers.values()) for s in sigs):
                return os
        
        return 'Unknown'
    
    def _detect_db(self, response: requests.Response) -> List[str]:
        content = response.text.lower()
        
        db_sigs = {
            'MySQL': ['mysql', 'mariadb'],
            'PostgreSQL': ['postgresql', 'postgres'],
            'MongoDB': ['mongodb', 'mongo'],
            'Redis': ['redis'],
            'MSSQL': ['mssql', 'sql server'],
            'Oracle': ['oracle'],
            'Elasticsearch': ['elasticsearch'],
        }
        
        detected = []
        for db, sigs in db_sigs.items():
            if any(s in content for s in sigs):
                detected.append(db)
        
        return detected
    
    def _test_cve(self, url: str, cve: Dict, fp: Fingerprint) -> Optional[CVEVulnerability]:
        try:
            if not self._check_patterns(cve, fp):
                return None
            
            verification = self._verify_cve(url, cve, fp)
            
            if not verification['is_vulnerable']:
                return None
            
            return CVEVulnerability(
                id=cve['id'],
                name=cve['name'],
                severity=cve['severity'],
                score=cve['score'],
                description=cve['description'],
                category=cve['category'],
                reference=cve['reference'],
                affected_software=cve.get('affected_software', []),
                cvss_vector=cve.get('cvss_vector', ''),
                fix_available=cve.get('fix_available', False),
                publication_date=cve.get('publication_date', ''),
                found_at=time.strftime('%Y-%m-%d %H:%M:%S'),
                target=url,
                confidence=self._calc_confidence(cve, fp, verification),
                verification_method=verification.get('method', 'PATTERN'),
                evidence=verification.get('evidence', []),
                exploitable=verification.get('exploitable', False),
                exploit_code=verification.get('exploit_code'),
                remediation=self._get_remediation(cve)
            )
        except:
            return None
    
    def _check_patterns(self, cve: Dict, fp: Fingerprint) -> bool:
        if not fp:
            return False
        
        patterns = cve.get('patterns', [])
        if not patterns:
            return False
        
        matches = 0
        
        for pattern in patterns:
            p = pattern.lower()
            
            if p in fp.content:
                matches += 1
            elif any(p in v for v in fp.headers.values()):
                matches += 1
            elif fp.cms.lower() == p:
                matches += 1
            elif fp.framework.lower() == p:
                matches += 1
            elif any(p in str(t).lower() for tech_list in fp.technologies.values() for t in tech_list):
                matches += 1
        
        return (matches / len(patterns) * 100) >= 20 if patterns else False
    
    def _verify_cve(self, url: str, cve: Dict, fp: Fingerprint) -> Dict:
        category = cve.get('category', 'UNKNOWN')
        
        verifiers = {
            'RCE': self._verify_rce,
            'SQLi': self._verify_sqli,
            'XSS': self._verify_xss,
            'SSRF': self._verify_ssrf,
            'XXE': self._verify_xxe,
            'SSTI': self._verify_ssti,
            'PATH_TRAVERSAL': self._verify_path_traversal,
        }
        
        verifier = verifiers.get(category, self._verify_generic)
        return verifier(url, cve, fp)
    
    def _verify_rce(self, url: str, cve: Dict, fp: Fingerprint) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'RCE'}
        
        payloads = [
            {'p': '`id`', 'i': ['uid=', 'gid=']},
            {'p': 'whoami', 'i': ['root', 'admin']},
            {'p': 'sleep 5', 'i': 'delay'},
        ]
        
        for test in payloads:
            try:
                test_url = f"{url}?cmd={test['p']}"
                start = time.time()
                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                elapsed = time.time() - start
                
                if test['i'] == 'delay' and elapsed > 4:
                    result['is_vulnerable'] = True
                    result['exploitable'] = True
                    result['evidence'].append(f'Time delay: {elapsed:.2f}s')
                    return result
                
                if isinstance(test['i'], list) and any(i in resp.text for i in test['i']):
                    result['is_vulnerable'] = True
                    result['exploitable'] = True
                    result['evidence'].append(f"RCE confirmed: {test['i']}")
                    return result
            except:
                pass
        
        return result
    
    def _verify_sqli(self, url: str, cve: Dict, fp: Fingerprint) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'SQLI'}
        
        params = self._extract_params(url)
        
        payloads = ["' OR '1'='1", "' AND 1=1--", "'; SLEEP(5)--"]
        
        for param in params[:5]:
            for payload in payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    start = time.time()
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    elapsed = time.time() - start
                    
                    if elapsed > 4:
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'Time-based SQLi on {param}')
                        return result
                    
                    errors = ['SQL syntax', 'mysql', 'sqlite', 'postgresql']
                    if any(e in resp.text.lower() for e in errors):
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'SQL error on {param}')
                        return result
                except:
                    pass
        
        return result
    
    def _verify_xss(self, url: str, cve: Dict, fp: Fingerprint) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'XSS'}
        
        params = self._extract_params(url)
        payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
        
        for param in params[:5]:
            for payload in payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if payload in resp.text:
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'XSS on {param}')
                        return result
                except:
                    pass
        
        return result
    
    def _verify_ssrf(self, url: str, cve: Dict, fp: Fingerprint) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'SSRF'}
        
        params = self._extract_params(url)
        payloads = ['http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/']
        
        for param in params[:3]:
            for payload in payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    resp = self.session.get(test_url, timeout=self.timeout * 2, verify=False)
                    
                    if any(i in resp.text for i in ['metadata', 'ami-id']):
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'SSRF to {payload}')
                        return result
                except:
                    pass
        
        return result
    
    def _verify_xxe(self, url: str, cve: Dict, fp: Fingerprint) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'XXE'}
        
        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        
        try:
            resp = self.session.post(url, data=payload, headers={'Content-Type': 'application/xml'}, timeout=self.timeout, verify=False)
            
            if any(i in resp.text for i in ['root:', 'daemon:']):
                result['is_vulnerable'] = True
                result['exploitable'] = True
                result['evidence'].append('XXE file disclosure')
        except:
            pass
        
        return result
    
    def _verify_ssti(self, url: str, cve: Dict, fp: Fingerprint) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'SSTI'}
        
        params = self._extract_params(url)
        payloads = [('{{7*7}}', '49'), ('${7*7}', '49')]
        
        for param in params[:5]:
            for payload, expected in payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if expected in resp.text:
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'SSTI on {param}')
                        return result
                except:
                    pass
        
        return result
    
    def _verify_path_traversal(self, url: str, cve: Dict, fp: Fingerprint) -> Dict:
        result = {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'PT'}
        
        params = self._extract_params(url)
        payloads = ['../../../../etc/passwd', '..\\..\\..\\windows\\win.ini']
        
        for param in params[:5]:
            for payload in payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if 'root:' in resp.text or '[boot loader]' in resp.text:
                        result['is_vulnerable'] = True
                        result['exploitable'] = True
                        result['evidence'].append(f'File disclosure on {param}')
                        return result
                except:
                    pass
        
        return result
    
    def _verify_generic(self, url: str, cve: Dict, fp: Fingerprint) -> Dict:
        return {'is_vulnerable': False, 'exploitable': False, 'evidence': [], 'method': 'GENERIC'}
    
    def _extract_params(self, url: str) -> List[str]:
        params = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        params.extend(query_params.keys())
        params.extend(['id', 'q', 'search', 'query', 'name', 'file', 'page', 'url'])
        return list(set(params))[:10]
    
    def _calc_confidence(self, cve: Dict, fp: Fingerprint, verification: Dict) -> float:
        confidence = 0.0
        
        if verification.get('is_vulnerable'):
            confidence = 0.5
        
        if verification.get('exploitable'):
            confidence += 0.3
        
        evidence_count = len(verification.get('evidence', []))
        confidence += min(evidence_count * 0.05, 0.2)
        
        return min(confidence, 1.0)
    
    def _get_remediation(self, cve: Dict) -> str:
        return f"Update software. Apply patches. Review {cve['reference']}. Implement WAF rules. Monitor logs."
    
    def get_vulnerabilities(self):
        with self.lock:
            return self.vulnerabilities.copy()
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_cache.clear()
