import requests
from typing import Dict, Optional, List, Tuple, Any
from urllib3.exceptions import InsecureRequestWarning
from dataclasses import dataclass, field
from enum import Enum
import time
import threading
from collections import defaultdict
import hashlib
from abc import ABC, abstractmethod

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class RequestStatus(Enum):
    PENDING = "pending"
    SENT = "sent"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class RequestConfig:
    timeout: int = 10
    verify_ssl: bool = False
    allow_redirects: bool = True
    allow_cookies: bool = True
    retry_attempts: int = 3
    retry_delay: float = 1.0
    connection_pool_size: int = 50
    max_retries: int = 3
    backoff_factor: float = 0.5
    raise_on_redirect: bool = False
    raise_on_status: bool = False


@dataclass
class RequestMetrics:
    url: str
    method: str
    status_code: int
    request_time: float
    response_time: float
    content_length: int
    timestamp: float = field(default_factory=time.time)
    retry_count: int = 0
    is_cached: bool = False
    error: Optional[str] = None


class ResponseValidator:
    @staticmethod
    def is_valid_response(response: requests.Response) -> bool:
        return response is not None and hasattr(response, 'status_code')
    
    @staticmethod
    def is_successful(status_code: int) -> bool:
        return 200 <= status_code < 300
    
    @staticmethod
    def is_redirect(status_code: int) -> bool:
        return 300 <= status_code < 400
    
    @staticmethod
    def is_client_error(status_code: int) -> bool:
        return 400 <= status_code < 500
    
    @staticmethod
    def is_server_error(status_code: int) -> bool:
        return 500 <= status_code < 600
    
    @staticmethod
    def should_retry(status_code: int, method: str) -> bool:
        non_retryable = {400, 401, 403, 404}
        retryable_methods = {'GET', 'HEAD', 'OPTIONS'}
        return status_code not in non_retryable and method in retryable_methods


class ProxyManager:
    def __init__(self):
        self.proxy_url: Optional[str] = None
        self.proxy_auth: Optional[Tuple[str, str]] = None
        self.proxy_type: str = "http"
        self.rotation_list: List[str] = []
        self.current_index: int = 0
    
    def set_proxy(self, proxy_url: str, username: Optional[str] = None, password: Optional[str] = None):
        self.proxy_url = proxy_url
        if username and password:
            self.proxy_auth = (username, password)
    
    def set_proxy_list(self, proxies: List[str]):
        self.rotation_list = proxies.copy()
        self.current_index = 0
    
    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        if not self.proxy_url:
            return None
        
        proxy_url = self.proxy_url
        if self.proxy_auth:
            username, password = self.proxy_auth
            proxy_url = proxy_url.replace('://', f'://{username}:{password}@')
        
        return {
            'http': proxy_url,
            'https': proxy_url,
        }
    
    def get_next_proxy(self) -> Optional[str]:
        if not self.rotation_list:
            return self.proxy_url
        
        proxy = self.rotation_list[self.current_index % len(self.rotation_list)]
        self.current_index += 1
        return proxy
    
    def clear(self):
        self.proxy_url = None
        self.proxy_auth = None
        self.rotation_list = []
        self.current_index = 0


class CookieManager:
    def __init__(self):
        self.cookie_jar = requests.cookies.RequestsCookieJar()
        self.persistent_cookies: Dict[str, str] = {}
    
    def add_cookie(self, name: str, value: str, domain: str = "", path: str = "/"):
        self.persistent_cookies[name] = value
        self.cookie_jar.set(name, value, domain=domain, path=path)
    
    def get_cookies(self) -> Dict[str, str]:
        return dict(self.cookie_jar)
    
    def clear(self):
        self.cookie_jar.clear()
        self.persistent_cookies.clear()
    
    def get_cookie_jar(self) -> requests.cookies.RequestsCookieJar:
        return self.cookie_jar


class HeaderManager:
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    def __init__(self):
        self.headers = self.DEFAULT_HEADERS.copy()
        self.auth_headers: Dict[str, str] = {}
        self.custom_headers: Dict[str, str] = {}
    
    def set_user_agent(self, user_agent: str):
        self.headers['User-Agent'] = user_agent
    
    def add_header(self, key: str, value: str):
        self.custom_headers[key] = value
    
    def add_headers(self, headers: Dict[str, str]):
        self.custom_headers.update(headers)
    
    def set_auth_header(self, header: Dict[str, str]):
        self.auth_headers = header.copy()
    
    def get_headers(self) -> Dict[str, str]:
        combined = self.headers.copy()
        combined.update(self.auth_headers)
        combined.update(self.custom_headers)
        return combined
    
    def remove_header(self, key: str):
        self.custom_headers.pop(key, None)
    
    def clear_custom_headers(self):
        self.custom_headers.clear()
    
    def randomize_headers(self):
        import random
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15',
        ]
        self.headers['User-Agent'] = random.choice(user_agents)


class RetryStrategy:
    def __init__(self, max_retries: int = 3, backoff_factor: float = 0.5):
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.retry_count = 0
    
    def get_retry_delay(self) -> float:
        return self.backoff_factor ** self.retry_count
    
    def should_retry(self) -> bool:
        return self.retry_count < self.max_retries
    
    def increment(self):
        self.retry_count += 1
    
    def reset(self):
        self.retry_count = 0


class RequestMetricsCollector:
    def __init__(self):
        self.metrics: List[RequestMetrics] = []
        self.lock = threading.Lock()
    
    def add_metric(self, metric: RequestMetrics):
        with self.lock:
            self.metrics.append(metric)
    
    def get_statistics(self) -> Dict:
        with self.lock:
            if not self.metrics:
                return {}
            
            total_time = sum(m.response_time for m in self.metrics)
            avg_time = total_time / len(self.metrics)
            failed = sum(1 for m in self.metrics if m.error)
            
            return {
                'total_requests': len(self.metrics),
                'failed_requests': failed,
                'success_rate': f"{((len(self.metrics) - failed) / len(self.metrics) * 100):.2f}%",
                'average_response_time': f"{avg_time:.3f}s",
                'total_response_time': f"{total_time:.3f}s",
                'min_response_time': f"{min(m.response_time for m in self.metrics):.3f}s",
                'max_response_time': f"{max(m.response_time for m in self.metrics):.3f}s",
            }
    
    def get_by_status_code(self) -> Dict[int, int]:
        with self.lock:
            status_dist = defaultdict(int)
            for metric in self.metrics:
                status_dist[metric.status_code] += 1
            return dict(status_dist)
    
    def clear(self):
        with self.lock:
            self.metrics.clear()


class SessionManager:
    def __init__(self, config: RequestConfig):
        self.session = requests.Session()
        self.config = config
        self.header_manager = HeaderManager()
        self.cookie_manager = CookieManager()
        self.proxy_manager = ProxyManager()
        
        self._configure_session()
    
    def _configure_session(self):
        self.session.headers.update(self.header_manager.get_headers())
        self.session.cookies = self.cookie_manager.get_cookie_jar()
        
        retry_strategy = requests.adapters.Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config.connection_pool_size,
            pool_maxsize=self.config.connection_pool_size,
        )
        
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
    
    def get_session(self) -> requests.Session:
        return self.session
    
    def close(self):
        self.session.close()


class RequestHandler:
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.config = RequestConfig(timeout=timeout, verify_ssl=verify_ssl)
        self.session_manager = SessionManager(self.config)
        self.metrics_collector = RequestMetricsCollector()
        self.request_cache: Dict[str, Dict] = {}
        self.cache_lock = threading.Lock()
    
    def set_proxy(self, proxy_url: Optional[str], username: Optional[str] = None, password: Optional[str] = None):
        if proxy_url:
            self.session_manager.proxy_manager.set_proxy(proxy_url, username, password)
            proxies = self.session_manager.proxy_manager.get_proxy_dict()
            if proxies:
                self.session_manager.session.proxies.update(proxies)
        else:
            self.session_manager.proxy_manager.clear()
            self.session_manager.session.proxies.clear()
    
    def set_auth_headers(self, headers: Dict[str, str]):
        self.session_manager.header_manager.set_auth_header(headers)
        self.session_manager.session.headers.update(headers)
    
    def add_header(self, key: str, value: str):
        self.session_manager.header_manager.add_header(key, value)
        self.session_manager.session.headers.update({key: value})
    
    def add_headers(self, headers: Dict[str, str]):
        self.session_manager.header_manager.add_headers(headers)
        self.session_manager.session.headers.update(headers)
    
    def set_user_agent(self, user_agent: str):
        self.session_manager.header_manager.set_user_agent(user_agent)
        self.session_manager.session.headers.update({'User-Agent': user_agent})
    
    def add_cookie(self, name: str, value: str):
        self.session_manager.cookie_manager.add_cookie(name, value)
    
    def add_cookies(self, cookies: Dict[str, str]):
        for name, value in cookies.items():
            self.session_manager.cookie_manager.add_cookie(name, value)
    
    def _get_cache_key(self, url: str, method: str, data: Optional[Dict] = None) -> str:
        cache_input = f"{method}:{url}:{str(data or {})}"
        return hashlib.md5(cache_input.encode()).hexdigest()
    
    def _get_cached_response(self, cache_key: str) -> Optional[Dict]:
        with self.cache_lock:
            if cache_key in self.request_cache:
                cached = self.request_cache[cache_key]
                if time.time() - cached.get('timestamp', 0) < 3600:
                    return cached
                else:
                    del self.request_cache[cache_key]
        return None
    
    def _cache_response(self, cache_key: str, response: Dict):
        with self.cache_lock:
            response['timestamp'] = time.time()
            self.request_cache[cache_key] = response
    
    def send_request(self, url: str, method: str = "GET", data: Optional[Dict] = None,
                    headers: Optional[Dict] = None, timeout: Optional[int] = None,
                    allow_cache: bool = False) -> Dict:
        
        if method.upper() == "GET" and allow_cache:
            cache_key = self._get_cache_key(url, method, data)
            cached = self._get_cached_response(cache_key)
            if cached:
                cached['is_cached'] = True
                return cached
        
        retry_strategy = RetryStrategy(self.config.retry_attempts, self.config.backoff_factor)
        request_timeout = timeout or self.config.timeout
        
        while retry_strategy.should_retry():
            try:
                start_time = time.time()
                
                request_headers = self.session_manager.header_manager.get_headers()
                if headers:
                    request_headers.update(headers)
                
                if method.upper() == "GET":
                    response = self.session_manager.session.get(
                        url,
                        timeout=request_timeout,
                        verify=self.config.verify_ssl,
                        allow_redirects=self.config.allow_redirects,
                        headers=request_headers,
                    )
                elif method.upper() == "POST":
                    response = self.session_manager.session.post(
                        url,
                        data=data,
                        timeout=request_timeout,
                        verify=self.config.verify_ssl,
                        allow_redirects=self.config.allow_redirects,
                        headers=request_headers,
                    )
                elif method.upper() == "PUT":
                    response = self.session_manager.session.put(
                        url,
                        data=data,
                        timeout=request_timeout,
                        verify=self.config.verify_ssl,
                        allow_redirects=self.config.allow_redirects,
                        headers=request_headers,
                    )
                elif method.upper() == "DELETE":
                    response = self.session_manager.session.delete(
                        url,
                        timeout=request_timeout,
                        verify=self.config.verify_ssl,
                        allow_redirects=self.config.allow_redirects,
                        headers=request_headers,
                    )
                elif method.upper() == "PATCH":
                    response = self.session_manager.session.patch(
                        url,
                        data=data,
                        timeout=request_timeout,
                        verify=self.config.verify_ssl,
                        allow_redirects=self.config.allow_redirects,
                        headers=request_headers,
                    )
                else:
                    response = self.session_manager.session.request(
                        method,
                        url,
                        data=data,
                        timeout=request_timeout,
                        verify=self.config.verify_ssl,
                        allow_redirects=self.config.allow_redirects,
                        headers=request_headers,
                    )
                
                response_time = time.time() - start_time
                
                if not ResponseValidator.is_valid_response(response):
                    raise Exception("Invalid response object")
                
                result = {
                    'url': url,
                    'method': method.upper(),
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content': response.text,
                    'response_time': response_time,
                    'success': ResponseValidator.is_successful(response.status_code),
                    'cookies': dict(response.cookies),
                }
                
                metric = RequestMetrics(
                    url=url,
                    method=method.upper(),
                    status_code=response.status_code,
                    request_time=start_time,
                    response_time=response_time,
                    content_length=len(response.content),
                    retry_count=retry_strategy.retry_count,
                )
                
                self.metrics_collector.add_metric(metric)
                
                if method.upper() == "GET" and allow_cache:
                    cache_key = self._get_cache_key(url, method, data)
                    self._cache_response(cache_key, result)
                
                return result
            
            except requests.exceptions.Timeout:
                retry_strategy.increment()
                if retry_strategy.should_retry():
                    time.sleep(retry_strategy.get_retry_delay())
                else:
                    return {
                        'url': url,
                        'method': method.upper(),
                        'status_code': 0,
                        'headers': {},
                        'content': '',
                        'response_time': time.time() - start_time,
                        'success': False,
                        'error': 'Request timeout',
                    }
            
            except requests.exceptions.ConnectionError:
                retry_strategy.increment()
                if retry_strategy.should_retry():
                    time.sleep(retry_strategy.get_retry_delay())
                else:
                    return {
                        'url': url,
                        'method': method.upper(),
                        'status_code': 0,
                        'headers': {},
                        'content': '',
                        'response_time': 0,
                        'success': False,
                        'error': 'Connection error',
                    }
            
            except requests.exceptions.RequestException as e:
                retry_strategy.increment()
                if retry_strategy.should_retry():
                    time.sleep(retry_strategy.get_retry_delay())
                else:
                    return {
                        'url': url,
                        'method': method.upper(),
                        'status_code': 0,
                        'headers': {},
                        'content': '',
                        'response_time': 0,
                        'success': False,
                        'error': str(e),
                    }
            
            except Exception as e:
                return {
                    'url': url,
                    'method': method.upper(),
                    'status_code': 0,
                    'headers': {},
                    'content': '',
                    'response_time': 0,
                    'success': False,
                    'error': str(e),
                }
    
    def send_batch_requests(self, urls: List[str], method: str = "GET") -> List[Dict]:
        results = []
        for url in urls:
            result = self.send_request(url, method)
            results.append(result)
        return results
    
    def clear_cache(self):
        with self.cache_lock:
            self.request_cache.clear()
    
    def get_metrics(self) -> Dict:
        return self.metrics_collector.get_statistics()
    
    def get_status_code_distribution(self) -> Dict[int, int]:
        return self.metrics_collector.get_by_status_code()
    
    def close(self):
        self.session_manager.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()