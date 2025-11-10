from typing import Dict, List, Optional, Callable, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from dataclasses import dataclass, field
from enum import Enum
import time
import threading
from collections import defaultdict
import hashlib

from .payload_generator import PayloadGenerator
from .vulnerability_detector import VulnerabilityDetector
from .request_handler import RequestHandler
from .response_analyzer import ResponseAnalyzer
from .auth_manager import AuthManager
from .cache_manager import CacheManager
from utils.logger import Logger


class ScanPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class ScanStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanMetrics:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    vulnerabilities_found: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    average_response_time: float = 0.0
    request_times: List[float] = field(default_factory=list)
    
    def get_duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time
    
    def get_success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    def update_average_response_time(self):
        if self.request_times:
            self.average_response_time = sum(self.request_times) / len(self.request_times)


@dataclass
class ScanConfig:
    max_workers: int = 10
    timeout: int = 30
    request_delay: float = 0.5
    retry_attempts: int = 3
    verify_ssl: bool = False
    follow_redirects: bool = True
    allow_cookies: bool = True
    randomize_payload_order: bool = True
    enable_caching: bool = True
    cache_ttl: int = 3600
    priority: ScanPriority = ScanPriority.MEDIUM
    enable_rate_limiting: bool = True
    rate_limit_per_second: int = 10
    batch_size: int = 50


class RateLimiter:
    def __init__(self, requests_per_second: int):
        self.requests_per_second = requests_per_second
        self.request_times: List[float] = []
        self.lock = threading.Lock()
    
    def acquire(self):
        with self.lock:
            now = time.time()
            self.request_times = [t for t in self.request_times if now - t < 1.0]
            
            if len(self.request_times) >= self.requests_per_second:
                sleep_time = 1.0 - (now - self.request_times[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    now = time.time()
            
            self.request_times.append(now)


class ParameterExtractor:
    @staticmethod
    def extract_from_url(url: str) -> Dict[str, List[str]]:
        parsed = urlparse(url)
        return parse_qs(parsed.query) if parsed.query else {}
    
    @staticmethod
    def extract_from_form(html: str) -> Dict[str, str]:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        params = {}
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                value = input_tag.get('value', '')
                if name:
                    params[name] = value
        return params
    
    @staticmethod
    def extract_from_headers(response_headers: Dict) -> Dict[str, str]:
        injectable_headers = {
            'User-Agent': response_headers.get('User-Agent', ''),
            'Referer': response_headers.get('Referer', ''),
            'Cookie': response_headers.get('Cookie', ''),
            'X-Forwarded-For': response_headers.get('X-Forwarded-For', ''),
            'X-Original-URL': response_headers.get('X-Original-URL', '')
        }
        return {k: v for k, v in injectable_headers.items() if v}


class ScanResultAggregator:
    def __init__(self):
        self.vulnerabilities: List[Dict] = []
        self.vulnerability_lock = threading.Lock()
        self.deduplication_cache: Set[str] = set()
    
    def add_vulnerability(self, vuln: Dict) -> bool:
        vuln_hash = self._hash_vulnerability(vuln)
        
        with self.vulnerability_lock:
            if vuln_hash in self.deduplication_cache:
                return False
            
            self.deduplication_cache.add(vuln_hash)
            self.vulnerabilities.append(vuln)
            return True
    
    def _hash_vulnerability(self, vuln: Dict) -> str:
        hashable = f"{vuln.get('type')}{vuln.get('url')}{vuln.get('parameter')}{vuln.get('payload')}"
        return hashlib.md5(hashable.encode()).hexdigest()
    
    def get_vulnerabilities(self) -> List[Dict]:
        with self.vulnerability_lock:
            return self.vulnerabilities.copy()
    
    def get_vulnerability_summary(self) -> Dict[str, int]:
        summary = defaultdict(int)
        for vuln in self.get_vulnerabilities():
            severity = vuln.get('severity', 'Unknown')
            summary[severity] += 1
        return dict(summary)


class ScannerEngine:
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.payload_generator = PayloadGenerator()
        self.vulnerability_detector = VulnerabilityDetector()
        self.request_handler = RequestHandler(timeout=self.config.timeout, verify_ssl=self.config.verify_ssl)
        self.response_analyzer = ResponseAnalyzer()
        self.auth_manager = AuthManager()
        self.cache_manager = CacheManager(ttl=self.config.cache_ttl) if self.config.enable_caching else None
        self.logger = Logger()
        
        self.status = ScanStatus.IDLE
        self.metrics = ScanMetrics()
        self.result_aggregator = ScanResultAggregator()
        self.parameter_extractor = ParameterExtractor()
        self.rate_limiter = RateLimiter(self.config.rate_limit_per_second) if self.config.enable_rate_limiting else None
        
        self.is_scanning = False
        self.scan_lock = threading.Lock()
        self.pause_event = threading.Event()
        self.pause_event.set()
    
    def set_authentication(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager
        self.request_handler.set_auth_headers(auth_manager.get_auth_header())
    
    def set_proxy(self, proxy_url: str, username: Optional[str] = None, password: Optional[str] = None):
        if proxy_url:
            if username and password:
                proxy_url = proxy_url.replace('://', f'://{username}:{password}@')
            self.request_handler.set_proxy(proxy_url)
        else:
            self.request_handler.set_proxy(None)
    
    def start_scan(self, target_url: str, scan_types: List[str], callback: Optional[Callable] = None) -> List[Dict]:
        with self.scan_lock:
            if self.is_scanning:
                self.logger.warning("Scan already in progress")
                return []
            
            self.is_scanning = True
            self.status = ScanStatus.RUNNING
            self.metrics = ScanMetrics()
            self.result_aggregator = ScanResultAggregator()
        
        try:
            self.logger.info(f"Starting comprehensive scan on {target_url}")
            
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            params = self.parameter_extractor.extract_from_url(target_url)
            
            if not params:
                params = {"id": ["1"]}
            
            initial_response = self._fetch_initial_response(base_url)
            if initial_response and initial_response.get('success'):
                form_params = self.parameter_extractor.extract_from_form(initial_response.get('content', ''))
                params.update({k: [v] for k, v in form_params.items()})
            
            scan_types = self._validate_scan_types(scan_types)
            
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures: Dict[Future, str] = {}
                
                for scan_type in scan_types:
                    if not self.is_scanning:
                        break
                    
                    future = executor.submit(
                        self._execute_scan_type,
                        base_url,
                        params,
                        scan_type,
                        callback
                    )
                    futures[future] = scan_type
                
                for future in as_completed(futures):
                    if not self.is_scanning:
                        break
                    
                    scan_type = futures[future]
                    try:
                        result = future.result()
                        self.logger.debug(f"Completed {scan_type} scan with {len(result)} findings")
                    except Exception as e:
                        self.logger.error(f"Error in {scan_type} scan: {str(e)}")
            
            self.status = ScanStatus.COMPLETED
            self.metrics.end_time = time.time()
            
            return self.result_aggregator.get_vulnerabilities()
        
        except Exception as e:
            self.status = ScanStatus.FAILED
            self.logger.critical(f"Scan failed: {str(e)}")
            return []
        
        finally:
            with self.scan_lock:
                self.is_scanning = False
    
    def _fetch_initial_response(self, url: str) -> Optional[Dict]:
        try:
            response = self.request_handler.send_request(url)
            self.metrics.total_requests += 1
            if response.get('success'):
                self.metrics.successful_requests += 1
                self.metrics.request_times.append(response.get('response_time', 0))
            else:
                self.metrics.failed_requests += 1
            return response
        except Exception as e:
            self.logger.error(f"Failed to fetch initial response: {str(e)}")
            return None
    
    def _validate_scan_types(self, scan_types: List[str]) -> List[str]:
        valid_types = {
            'XSS', 'SQL', 'RCE', 'CommandInjection', 'SSRF', 'CSRF',
            'XXE', 'FileUpload', 'API', 'WebSocket', 'GraphQL', 'SSTI', 'LDAP', 'OAuth2'
        }
        return [st for st in scan_types if st in valid_types]
    
    def _execute_scan_type(self, base_url: str, params: Dict, scan_type: str, callback: Optional[Callable] = None) -> List[Dict]:
        vulnerabilities = []
        
        try:
            payloads = self.payload_generator.generate_payloads(scan_type)
            
            if self.config.randomize_payload_order:
                import random
                payloads = payloads.copy()
                random.shuffle(payloads)
            
            for batch_idx in range(0, len(payloads), self.config.batch_size):
                if not self.is_scanning:
                    break
                
                batch = payloads[batch_idx:batch_idx + self.config.batch_size]
                
                for payload in batch:
                    if not self.is_scanning:
                        break
                    
                    self.pause_event.wait()
                    
                    if self.rate_limiter:
                        self.rate_limiter.acquire()
                    
                    time.sleep(self.config.request_delay)
                    
                    for param_name in params.keys():
                        if not self.is_scanning:
                            break
                        
                        cache_key = f"{scan_type}:{base_url}:{param_name}:{payload[:50]}"
                        
                        if self.cache_manager:
                            cached_result = self.cache_manager.get(cache_key)
                            if cached_result is not None:
                                if cached_result:
                                    vulnerabilities.extend(cached_result)
                                continue
                        
                        test_url = self._build_test_url(base_url, params, param_name, payload)
                        
                        response = self._perform_request_with_retry(test_url)
                        self.metrics.total_requests += 1
                        
                        if response and response.get('success'):
                            self.metrics.successful_requests += 1
                            self.metrics.request_times.append(response.get('response_time', 0))
                            
                            is_vulnerable, details = self.vulnerability_detector.detect(
                                response,
                                scan_type,
                                payload
                            )
                            
                            if is_vulnerable:
                                vuln_data = self._create_vulnerability_record(
                                    scan_type, test_url, param_name, payload, details
                                )
                                
                                if self.result_aggregator.add_vulnerability(vuln_data):
                                    vulnerabilities.append(vuln_data)
                                    
                                    if callback:
                                        callback(vuln_data)
                                    
                                    self.metrics.vulnerabilities_found += 1
                                    self.logger.warning(f"[{scan_type}] Vulnerability found in {param_name}")
                            
                            if self.cache_manager:
                                self.cache_manager.set(cache_key, [vuln_data] if is_vulnerable else [])
                        else:
                            self.metrics.failed_requests += 1
        
        except Exception as e:
            self.logger.error(f"Error executing {scan_type} scan: {str(e)}")
        
        return vulnerabilities
    
    def _perform_request_with_retry(self, url: str) -> Optional[Dict]:
        for attempt in range(self.config.retry_attempts):
            try:
                response = self.request_handler.send_request(url)
                if response.get('success'):
                    return response
            except Exception as e:
                if attempt == self.config.retry_attempts - 1:
                    self.logger.debug(f"Request failed after {self.config.retry_attempts} attempts: {str(e)}")
                else:
                    time.sleep(0.5 * (attempt + 1))
        
        return None
    
    def _build_test_url(self, base_url: str, params: Dict, param_name: str, payload: str) -> str:
        test_params = params.copy()
        test_params[param_name] = [payload]
        
        parsed = urlparse(base_url)
        query_string = urlencode(test_params, doseq=True)
        
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query_string,
            parsed.fragment
        ))
    
    def _create_vulnerability_record(self, scan_type: str, url: str, parameter: str, payload: str, details: Dict) -> Dict:
        return {
            'type': scan_type,
            'url': url,
            'parameter': parameter,
            'payload': payload,
            'severity': details.get('severity', 'Medium'),
            'description': details.get('description', ''),
            'evidence': details.get('evidence', ''),
            'timestamp': time.time(),
            'confirmed': True
        }
    
    def pause_scan(self):
        self.pause_event.clear()
        self.status = ScanStatus.PAUSED
        self.logger.info("Scan paused")
    
    def resume_scan(self):
        self.pause_event.set()
        self.status = ScanStatus.RUNNING
        self.logger.info("Scan resumed")
    
    def stop_scan(self):
        with self.scan_lock:
            self.is_scanning = False
            self.status = ScanStatus.CANCELLED
        self.metrics.end_time = time.time()
        self.logger.info("Scan stopped by user")
    
    def get_scan_metrics(self) -> ScanMetrics:
        self.metrics.update_average_response_time()
        return self.metrics
    
    def get_scan_summary(self) -> Dict:
        return {
            'status': self.status.value,
            'total_requests': self.metrics.total_requests,
            'successful_requests': self.metrics.successful_requests,
            'failed_requests': self.metrics.failed_requests,
            'vulnerabilities_found': self.metrics.vulnerabilities_found,
            'success_rate': f"{self.metrics.get_success_rate():.2f}%",
            'average_response_time': f"{self.metrics.average_response_time:.3f}s",
            'scan_duration': f"{self.metrics.get_duration():.2f}s",
            'vulnerability_summary': self.result_aggregator.get_vulnerability_summary()
        }
    
    def export_results(self, format: str = 'json') -> str:
        import json
        
        vulnerabilities = self.result_aggregator.get_vulnerabilities()
        summary = self.get_scan_summary()
        
        export_data = {
            'summary': summary,
            'vulnerabilities': vulnerabilities,
            'timestamp': time.time()
        }
        
        if format == 'json':
            return json.dumps(export_data, indent=2, default=str)
        
        return ""
