from typing import Dict, Optional
import logging

logger = logging.getLogger("MoD.proxy_manager")

class ProxyManager:
    """Manage HTTP/HTTPS proxy configuration with optional authentication."""
    
    def __init__(self):
        """Initialize proxy manager."""
        self.proxy_url: Optional[str] = None
        self.proxy_type: str = 'http'
        self.proxy_auth: Optional[Dict[str, str]] = None
    
    def set_proxy(self, proxy_url: str, proxy_type: str = 'http', username: Optional[str] = None, password: Optional[str] = None) -> None:
        """Configure proxy with optional authentication.
        
        Args:
            proxy_url: Proxy URL (format: http://host:port or socks5://host:port).
            proxy_type: Proxy type ('http', 'https', 'socks5').
            username: Optional proxy username.
            password: Optional proxy password.
        """
        if not proxy_url or not isinstance(proxy_url, str):
            logger.warning("Invalid proxy URL provided")
            return
        
        self.proxy_url = proxy_url
        self.proxy_type = proxy_type
        if username and password:
            self.proxy_auth = {
                'username': username,
                'password': password
            }
        else:
            self.proxy_auth = None
        
        logger.debug(f"Proxy configured: {proxy_type}://{proxy_url}")
    
    def get_proxy_dict(self) -> Dict[str, str]:
        """Get proxy dictionary for requests library.
        
        Returns:
            Dictionary with 'http' and 'https' keys or empty dict if no proxy.
        """
        if not self.proxy_url:
            return {}
        
        proxy_url = self.proxy_url
        if self.proxy_auth:
            username = self.proxy_auth.get('username', '')
            password = self.proxy_auth.get('password', '')
            if username and password:
                proxy_url = self.proxy_url.replace('://', f'://{username}:{password}@')
        
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    
    def clear_proxy(self) -> None:
        """Clear proxy configuration."""
        self.proxy_url = None
        self.proxy_type = 'http'
        self.proxy_auth = None
        logger.debug("Proxy configuration cleared")