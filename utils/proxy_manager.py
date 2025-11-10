from typing import Dict, Optional

class ProxyManager:
    def __init__(self):
        self.proxy_url = None
        self.proxy_type = None
        self.proxy_auth = None
    
    def set_proxy(self, proxy_url: str, proxy_type: str = 'http', username: Optional[str] = None, password: Optional[str] = None):
        self.proxy_url = proxy_url
        self.proxy_type = proxy_type
        if username and password:
            self.proxy_auth = {
                'username': username,
                'password': password
            }
        else:
            self.proxy_auth = None
    
    def get_proxy_dict(self) -> Dict[str, str]:
        if not self.proxy_url:
            return {}
        if self.proxy_auth:
            username = self.proxy_auth['username']
            password = self.proxy_auth['password']
            proxy_with_auth = self.proxy_url.replace('://', f'://{username}:{password}@')
        else:
            proxy_with_auth = self.proxy_url
        return {
            'http': proxy_with_auth,
            'https': proxy_with_auth
        }
    
    def clear_proxy(self):
        self.proxy_url = None
        self.proxy_type = None
        self.proxy_auth = None