from typing import List, Dict
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.request_handler import RequestHandler

class SubdomainScanner:
    def __init__(self):
        self.request_handler = RequestHandler()
        self.found_subdomains = []
    
    def scan(self, domain: str, wordlist: List[str] = None) -> List[Dict]:
        if wordlist is None:
            wordlist = self._get_default_wordlist()
        results = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._check_subdomain, subdomain, domain): subdomain 
                      for subdomain in wordlist}
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception:
                    pass
        return results
    
    def _check_subdomain(self, subdomain: str, domain: str) -> Dict:
        full_domain = f"{subdomain}.{domain}"
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            ips = [str(answer) for answer in answers]
            try:
                response = self.request_handler.send_request(f"http://{full_domain}")
                status_code = response.get('status_code', 0)
                title = self._extract_title(response.get('content', ''))
            except:
                status_code = 0
                title = ''
            return {
                'subdomain': full_domain,
                'ips': ips,
                'status_code': status_code,
                'title': title,
                'type': 'Subdomain Discovery'
            }
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except Exception:
            return None
    
    def _extract_title(self, html: str) -> str:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.find('title')
            return title.string if title else ''
        except:
            return ''
    
    def _get_default_wordlist(self) -> List[str]:
        return [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'app', 'blog', 'shop', 'store', 'portal', 'dashboard',
            'cpanel', 'webmail', 'smtp', 'pop', 'imap', 'ns1', 'ns2',
            'vpn', 'remote', 'secure', 'login', 'auth', 'beta', 'demo',
            'old', 'new', 'mobile', 'm', 'wap', 'static', 'media',
            'assets', 'cdn', 'images', 'img', 'files', 'docs', 'support'
        ]