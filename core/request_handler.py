import requests
from typing import Dict, Optional
import time
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class RequestHandler:
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.proxy = None
        self.auth_headers = {}
    
    def set_proxy(self, proxy_url: str):
        if proxy_url:
            self.proxy = {
                'http': proxy_url,
                'https': proxy_url
            }
        else:
            self.proxy = None
    
    def set_auth_headers(self, headers: Dict[str, str]):
        self.auth_headers = headers
        self.session.headers.update(headers)
    
    def send_request(self, url: str, method: str = 'GET', data: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict:
        start_time = time.time()
        
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                    proxies=self.proxy
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                    proxies=self.proxy,
                    headers=request_headers
                )
            else:
                response = self.session.request(
                    method,
                    url,
                    data=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                    proxies=self.proxy,
                    headers=request_headers
                )
            
            response_time = time.time() - start_time
            
            return {
                'url': url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'response_time': response_time,
                'success': True
            }
        
        except requests.exceptions.Timeout:
            return {
                'url': url,
                'status_code': 0,
                'headers': {},
                'content': '',
                'response_time': time.time() - start_time,
                'success': False,
                'error': 'Request timeout'
            }
        
        except requests.exceptions.ConnectionError:
            return {
                'url': url,
                'status_code': 0,
                'headers': {},
                'content': '',
                'response_time': 0,
                'success': False,
                'error': 'Connection error'
            }
        
        except Exception as e:
            return {
                'url': url,
                'status_code': 0,
                'headers': {},
                'content': '',
                'response_time': 0,
                'success': False,
                'error': str(e)
            }