from typing import List, Dict, Optional, Tuple
import requests
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from datetime import datetime
import json
from core.cve_payloads import CVEPayloads


class CVEScanner:
    
    def __init__(self, timeout: int = 10, max_workers: int = 15, user_agent: str = None):
        self.timeout = timeout
        self.max_workers = max_workers
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        self.session = self._create_session()
        self.results_cache = {}
        
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        session.max_redirects = 5
        return session
    
    def scan(self, target_url: str, severity_filter: str = 'ALL', 
             categories: List[str] = None) -> List[Dict]:
        
        if not self._validate_url(target_url):
            raise ValueError('Invalid target URL')
        
        vulnerabilities = []
        cve_list = CVEPayloads.get_all_cves()
        
        if severity_filter != 'ALL':
            cve_list = self._filter_by_severity(cve_list, severity_filter)
        
        if categories:
            cve_list = self._filter_by_category(cve_list, categories)
        
        base_fingerprint = self._fingerprint_target(target_url)
        
        if not base_fingerprint:
            return vulnerabilities
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self._test_cve, 
                    target_url, 
                    cve, 
                    base_fingerprint
                ): cve for cve in cve_list
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=self.timeout * 2)
                    if result:
                        vulnerabilities.append(result)
                except Exception:
                    continue
        
        return sorted(vulnerabilities, key=lambda x: x['score'], reverse=True)
    
    def _validate_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _filter_by_severity(self, cve_list: List[Dict], severity: str) -> List[Dict]:
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_level = severity_order.get(severity, 0)
        
        return [
            cve for cve in cve_list 
            if severity_order.get(cve['severity'], 0) >= min_level
        ]
    
    def _filter_by_category(self, cve_list: List[Dict], categories: List[str]) -> List[Dict]:
        return [cve for cve in cve_list if cve['category'] in categories]
    
    def _fingerprint_target(self, target_url: str) -> Optional[Dict]:
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
                'server': response.headers.get('Server', '').lower(),
                'powered_by': response.headers.get('X-Powered-By', '').lower(),
                'technologies': self._detect_technologies(response)
            }
            
            return fingerprint
            
        except Exception:
            return None
    
    def _detect_technologies(self, response: requests.Response) -> List[str]:
        technologies = []
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        tech_signatures = {
            'wordpress': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'drupal': ['/sites/default/', 'drupal.js', 'x-drupal'],
            'joomla': ['/components/', '/modules/', 'joomla'],
            'magento': ['/skin/frontend/', 'mage/cookies'],
            'apache': ['server: apache'],
            'nginx': ['server: nginx'],
            'php': ['x-powered-by: php', '.php'],
            'asp.net': ['x-aspnet-version', 'x-aspnetmvc-version'],
            'java': ['jsessionid', 'x-powered-by: jsp'],
            'nodejs': ['x-powered-by: express', 'x-powered-by: node'],
            'python': ['x-powered-by: flask', 'x-powered-by: django'],
            'ruby': ['x-powered-by: phusion', 'x-powered-by: rails'],
            'spring': ['/spring/', 'spring framework'],
            'struts': ['/struts/', '.action'],
            'laravel': ['laravel', 'x-powered-by: php'],
            'react': ['react', '_next'],
            'vue': ['vue.js', '__vue__'],
            'angular': ['ng-version', 'angular'],
            'jquery': ['jquery'],
        }
        
        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig in content or any(sig in v for v in headers.values()):
                    technologies.append(tech)
                    break
        
        return list(set(technologies))
    
    def _test_cve(self, target_url: str, cve: Dict, fingerprint: Dict) -> Optional[Dict]:
        try:
            if not self._check_patterns(cve['patterns'], fingerprint):
                return None
            
            if not self._verify_with_payloads(target_url, cve, fingerprint):
                return None
            
            return {
                'id': cve['id'],
                'name': cve['name'],
                'severity': cve['severity'],
                'score': cve['score'],
                'description': cve['description'],
                'category': cve['category'],
                'reference': cve['reference'],
                'found_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'target': target_url,
                'confidence': self._calculate_confidence(cve, fingerprint)
            }
            
        except Exception:
            return None
    
    def _check_patterns(self, patterns: List[str], fingerprint: Dict) -> bool:
        content = fingerprint['content']
        headers = fingerprint['headers']
        technologies = fingerprint['technologies']
        
        pattern_matches = 0
        
        for pattern in patterns:
            pattern_lower = pattern.lower()
            
            if pattern_lower in content:
                pattern_matches += 1
                continue
            
            if any(pattern_lower in v for v in headers.values()):
                pattern_matches += 1
                continue
            
            if any(pattern_lower in tech for tech in technologies):
                pattern_matches += 1
                continue
        
        return pattern_matches >= (len(patterns) * 0.3)
    
    def _verify_with_payloads(self, target_url: str, cve: Dict, fingerprint: Dict) -> bool:
        category = cve['category']
        payloads = cve['payloads'][:3]
        
        verification_methods = {
            'RCE': self._verify_rce,
            'SQLi': self._verify_sqli,
            'XSS': self._verify_xss,
            'SSRF': self._verify_ssrf,
            'XXE': self._verify_xxe,
            'SSTI': self._verify_ssti,
            'PATH_TRAVERSAL': self._verify_path_traversal,
            'DESERIALIZATION': self._verify_deserialization,
            'INFO_DISCLOSURE': self._verify_info_disclosure,
            'MISCONFIGURATION': self._verify_misconfiguration,
            'NoSQLi': self._verify_nosqli,
            'DOS': self._verify_dos,
            'PROTOTYPE_POLLUTION': self._verify_prototype_pollution
        }
        
        verify_method = verification_methods.get(category, self._default_verification)
        return verify_method(target_url, payloads, fingerprint)
    
    def _verify_rce(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                test_url = f"{url}?cmd={payload}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                rce_indicators = ['49', '7777', 'uid=', 'gid=', 'groups=', 'root:', 'bin/bash', 'cmd.exe']
                
                if any(indicator in response.text for indicator in rce_indicators):
                    return True
                
                if payload in response.text and response.status_code == 200:
                    return True
                    
            except:
                continue
        
        return False
    
    def _verify_sqli(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                test_url = f"{url}?id={payload}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                sql_errors = [
                    'sql syntax', 'mysql', 'sqlite', 'postgresql', 'oracle', 'mssql',
                    'syntax error', 'sqlstate', 'warning:', 'error in your sql',
                    'mysql_fetch', 'mysql_num_rows', 'pg_query', 'pg_exec',
                    'odbc_exec', 'microsoft ole db', 'unclosed quotation'
                ]
                
                response_lower = response.text.lower()
                
                if any(error in response_lower for error in sql_errors):
                    return True
                
                if response.status_code == 500 and 'database' in response_lower:
                    return True
                    
            except:
                continue
        
        return False
    
    def _verify_xss(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                test_url = f"{url}?q={payload}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if payload in response.text and response.status_code == 200:
                    return True
                    
            except:
                continue
        
        return False
    
    def _verify_ssrf(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                test_url = f"{url}?url={payload}"
                response = self.session.get(test_url, timeout=self.timeout * 2, verify=False)
                
                ssrf_indicators = ['169.254.169.254', 'metadata', 'credentials', 'token', 'ami-id', 'instance-id']
                
                if any(indicator in response.text.lower() for indicator in ssrf_indicators):
                    return True
                    
            except:
                continue
        
        return False
    
    def _verify_xxe(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                response = self.session.post(
                    url, 
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.timeout,
                    verify=False
                )
                
                xxe_indicators = ['root:', 'daemon:', 'bin:', 'sys:', '[boot loader]', '[operating systems]']
                
                if any(indicator in response.text.lower() for indicator in xxe_indicators):
                    return True
                    
            except:
                continue
        
        return False
    
    def _verify_ssti(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                test_url = f"{url}?name={payload}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if '49' in response.text or '7777' in response.text:
                    return True
                
                if response.status_code == 500 and any(err in response.text.lower() for err in ['template', 'jinja', 'twig']):
                    return True
                    
            except:
                continue
        
        return False
    
    def _verify_path_traversal(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                test_url = urljoin(url, payload)
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                path_indicators = ['root:', '[boot loader]', '[fonts]', '[extensions]', '[mci extensions]']
                
                if response.status_code == 200:
                    if any(indicator in response.text.lower() for indicator in path_indicators):
                        return True
                        
            except:
                continue
        
        return False
    
    def _verify_deserialization(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                response = self.session.post(
                    url,
                    data=payload,
                    timeout=self.timeout,
                    verify=False
                )
                
                if response.status_code in [200, 500]:
                    deser_indicators = ['serialization', 'object', 'unserialize', 'pickle']
                    if any(indicator in response.text.lower() for indicator in deser_indicators):
                        return True
                        
            except:
                continue
        
        return False
    
    def _verify_info_disclosure(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                test_url = urljoin(url, payload)
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    info_indicators = ['version', 'debug', 'config', 'password', 'secret', 'key', 'token']
                    if any(indicator in response.text.lower() for indicator in info_indicators):
                        return True
                        
            except:
                continue
        
        return False
    
    def _verify_misconfiguration(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        return self._verify_info_disclosure(url, payloads, fingerprint)
    
    def _verify_nosqli(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                response = self.session.post(
                    url,
                    json=json.loads(payload) if payload.startswith('{') else {'query': payload},
                    timeout=self.timeout,
                    verify=False
                )
                
                if response.status_code in [200, 500]:
                    if 'error' not in response.text.lower():
                        return True
                        
            except:
                continue
        
        return False
    
    def _verify_dos(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        return False
    
    def _verify_prototype_pollution(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                test_url = f"{url}?{payload}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    return True
                    
            except:
                continue
        
        return False
    
    def _default_verification(self, url: str, payloads: List[str], fingerprint: Dict) -> bool:
        for payload in payloads:
            try:
                test_url = f"{url}?test={payload}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if payload in response.text:
                    return True
                    
            except:
                continue
        
        return False
    
    def _calculate_confidence(self, cve: Dict, fingerprint: Dict) -> str:
        score = 0
        
        pattern_matches = sum(
            1 for pattern in cve['patterns']
            if pattern.lower() in fingerprint['content'] or
            any(pattern.lower() in v for v in fingerprint['headers'].values())
        )
        
        score += (pattern_matches / len(cve['patterns'])) * 40
        
        if any(tech in cve['description'].lower() for tech in fingerprint['technologies']):
            score += 30
        
        if fingerprint['server'] and any(s in fingerprint['server'] for s in cve['patterns']):
            score += 20
        
        if fingerprint['powered_by'] and any(p in fingerprint['powered_by'] for p in cve['patterns']):
            score += 10
        
        if score >= 80:
            return 'HIGH'
        elif score >= 60:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_scan_statistics(self, vulnerabilities: List[Dict]) -> Dict:
        if not vulnerabilities:
            return {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'by_category': {},
                'avg_score': 0
            }
        
        stats = {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW'),
            'by_category': {},
            'avg_score': sum(v['score'] for v in vulnerabilities) / len(vulnerabilities)
        }
        
        for vuln in vulnerabilities:
            category = vuln['category']
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
        
        return stats
    
    def export_results(self, vulnerabilities: List[Dict], format: str = 'json') -> str:
        if format == 'json':
            return json.dumps(vulnerabilities, indent=2)
        
        elif format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=['id', 'name', 'severity', 'score', 'category', 'found_at'])
            writer.writeheader()
            writer.writerows(vulnerabilities)
            return output.getvalue()
        
        elif format == 'html':
            html = '<html><head><title>CVE Scan Results</title></head><body>'
            html += '<h1>CVE Scan Results</h1><table border="1">'
            html += '<tr><th>CVE ID</th><th>Name</th><th>Severity</th><th>Score</th><th>Category</th></tr>'
            
            for vuln in vulnerabilities:
                html += f'<tr><td>{vuln["id"]}</td><td>{vuln["name"]}</td>'
                html += f'<td>{vuln["severity"]}</td><td>{vuln["score"]}</td><td>{vuln["category"]}</td></tr>'
            
            html += '</table></body></html>'
            return html
        
        return ''
