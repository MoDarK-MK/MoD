from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .payload_generator import PayloadGenerator
from .vulnerability_detector import VulnerabilityDetector
from .request_handler import RequestHandler
from .response_analyzer import ResponseAnalyzer
from .auth_manager import AuthManager
from utils.logger import Logger

class ScannerEngine:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.payload_generator = PayloadGenerator()
        self.vulnerability_detector = VulnerabilityDetector()
        self.request_handler = RequestHandler()
        self.response_analyzer = ResponseAnalyzer()
        self.auth_manager = AuthManager()
        self.logger = Logger()
        self.results = []
        self.is_scanning = False
        
    def set_authentication(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager
        self.request_handler.set_auth_headers(auth_manager.get_auth_header())
    
    def set_proxy(self, proxy_url: str):
        self.request_handler.set_proxy(proxy_url)
    
    def start_scan(self, target_url: str, scan_types: List[str], callback=None) -> List[Dict]:
        self.is_scanning = True
        self.results = []
        
        self.logger.info(f"Starting scan on {target_url}")
        
        parsed_url = urlparse(target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = parse_qs(parsed_url.query)
        
        if not params:
            params = {"id": ["1"]}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for scan_type in scan_types:
                if not self.is_scanning:
                    break
                    
                future = executor.submit(
                    self._scan_vulnerability,
                    base_url,
                    params,
                    scan_type,
                    callback
                )
                futures.append(future)
            
            for future in as_completed(futures):
                if not self.is_scanning:
                    break
                try:
                    result = future.result()
                    if result:
                        self.results.extend(result)
                except Exception as e:
                    self.logger.error(f"Scan error: {str(e)}")
        
        self.is_scanning = False
        return self.results
    
    def stop_scan(self):
        self.is_scanning = False
        self.logger.info("Scan stopped by user")
    
    def _scan_vulnerability(self, base_url: str, params: Dict, scan_type: str, callback=None) -> List[Dict]:
        vulnerabilities = []
        
        payloads = self.payload_generator.generate_payloads(scan_type)
        
        for payload in payloads:
            if not self.is_scanning:
                break
                
            for param_name in params.keys():
                if not self.is_scanning:
                    break
                    
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = self._build_url(base_url, test_params)
                
                try:
                    response = self.request_handler.send_request(test_url)
                    
                    is_vulnerable, details = self.vulnerability_detector.detect(
                        response,
                        scan_type,
                        payload
                    )
                    
                    if is_vulnerable:
                        vuln_data = {
                            'type': scan_type,
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': details.get('severity', 'Medium'),
                            'description': details.get('description', ''),
                            'evidence': details.get('evidence', '')
                        }
                        vulnerabilities.append(vuln_data)
                        
                        if callback:
                            callback(vuln_data)
                        
                        self.logger.warning(f"Vulnerability found: {scan_type} in {param_name}")
                
                except Exception as e:
                    self.logger.error(f"Request error: {str(e)}")
        
        return vulnerabilities
    
    def _build_url(self, base_url: str, params: Dict) -> str:
        parsed = urlparse(base_url)
        query_string = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query_string,
            parsed.fragment
        ))