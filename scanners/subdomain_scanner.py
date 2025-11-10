from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import socket
import dns.resolver
import dns.exception


class SubdomainDiscoveryMethod(Enum):
    DNS_RESOLUTION = "dns_resolution"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    SEARCH_ENGINE = "search_engine"
    WORDLIST = "wordlist"
    BRUTE_FORCE = "brute_force"
    ZONE_TRANSFER = "zone_transfer"
    REVERSE_DNS = "reverse_dns"
    WAYBACK_MACHINE = "wayback_machine"


class SubdomainStatus(Enum):
    ACTIVE = "active"
    DEAD = "dead"
    HIDDEN = "hidden"
    WILDCARD = "wildcard"
    CDN = "cdn"
    ALIAS = "alias"


class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ResolvedSubdomain:
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    status: SubdomainStatus = SubdomainStatus.ACTIVE
    response_code: Optional[int] = None
    content_length: int = 0
    web_server: Optional[str] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    certificates: List[Dict] = field(default_factory=list)
    is_cdn: bool = False
    cdn_provider: Optional[str] = None
    is_cloud: bool = False
    cloud_provider: Optional[str] = None
    discovered_method: SubdomainDiscoveryMethod = SubdomainDiscoveryMethod.DNS_RESOLUTION
    discovery_timestamp: float = field(default_factory=time.time)
    last_checked: float = field(default_factory=time.time)
    is_vulnerable: bool = False
    threat_level: ThreatLevel = ThreatLevel.INFO


@dataclass
class SubdomainVulnerability:
    vulnerability_type: str
    subdomain: str
    ip_address: str
    severity: str
    evidence: str
    response_code: int
    web_server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    is_cdn: bool = False
    cdn_provider: Optional[str] = None
    threat_level: ThreatLevel = ThreatLevel.INFO
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class DNSResolver:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def resolve_subdomain(self, subdomain: str) -> Tuple[bool, List[str]]:
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            ips = [str(rdata) for rdata in answers]
            return True, ips
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False, []
        except Exception:
            return False, []
    
    def resolve_aaaa_records(self, subdomain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(subdomain, 'AAAA')
            return [str(rdata) for rdata in answers]
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            return []
    
    def resolve_cname(self, subdomain: str) -> Optional[str]:
        try:
            answers = self.resolver.resolve(subdomain, 'CNAME')
            return str(answers[0].target)
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception:
            return None
    
    def resolve_mx_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [str(rdata.exchange) for rdata in answers]
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            return []
    
    def resolve_txt_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(rdata).replace('"', '') for rdata in answers]
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            return []
    
    def attempt_zone_transfer(self, domain: str, nameserver: str) -> Optional[List[str]]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
            subdomains = []
            for name, node in zone.items():
                subdomains.append(str(name.to_text(origin=zone.origin)))
            return subdomains
        except Exception:
            return None



class CDNDetector:
    CDN_IPS = {
        'cloudflare': [
            '1.1.1.1', '1.0.0.1',
        ],
        'aws_cloudfront': [
            '52.84.0.0/16', '52.222.0.0/16',
        ],
        'akamai': [
            '2.16.0.0/13', '2.56.0.0/14',
        ],
        'fastly': [
            '151.101.0.0/16',
        ],
    }
    
    CDN_DOMAINS = {
        'cloudflare': [
            '.cloudflare.com',
            'cdnjs.cloudflare.com',
        ],
        'aws': [
            'cloudfront.net',
            '.awscdn.com',
        ],
        'akamai': [
            'akamaized.net',
            'akamaitech.net',
        ],
        'fastly': [
            'fastly.net',
            'global.fastly.net',
        ],
    }
    
    @staticmethod
    def detect_cdn(ip_address: str, cname: Optional[str]) -> Tuple[bool, Optional[str]]:
        if cname:
            for cdn_name, domains in CDNDetector.CDN_DOMAINS.items():
                for domain in domains:
                    if domain in cname.lower():
                        return True, cdn_name
        
        try:
            ip_obj = __import__('ipaddress').ip_address(ip_address)
            for cdn_name, ranges in CDNDetector.CDN_IPS.items():
                for ip_range in ranges:
                    if '/' in ip_range:
                        network = __import__('ipaddress').ip_network(ip_range)
                        if ip_obj in network:
                            return True, cdn_name
        except ValueError:
            pass
        
        return False, None


class CloudProviderDetector:
    CLOUD_PROVIDERS = {
        'aws': [
            'amazonaws.com',
            'elb.amazonaws.com',
            'elasticbeanstalk.com',
            's3.amazonaws.com',
        ],
        'gcp': [
            'appspot.com',
            'cloudfunctions.net',
            'cloud.google.com',
            'gstatic.com',
        ],
        'azure': [
            'azurewebsites.net',
            'cloudapp.azure.com',
            'blob.core.windows.net',
            'azurecontainer.io',
        ],
        'heroku': [
            'herokuapp.com',
        ],
        'vercel': [
            'vercel.app',
        ],
        'netlify': [
            'netlify.app',
        ],
    }
    
    @staticmethod
    def detect_cloud_provider(cname: Optional[str], domain: str) -> Tuple[bool, Optional[str]]:
        check_domain = cname or domain
        
        if not check_domain:
            return False, None
        
        check_domain = check_domain.lower()
        
        for provider, indicators in CloudProviderDetector.CLOUD_PROVIDERS.items():
            for indicator in indicators:
                if indicator in check_domain:
                    return True, provider
        
        return False, None


class WebServerDetector:
    @staticmethod
    def detect_web_server(response_headers: Dict) -> Optional[str]:
        server_header = response_headers.get('Server', '')
        
        if server_header:
            return server_header.split('/')[0]
        
        x_powered_by = response_headers.get('X-Powered-By', '')
        if x_powered_by:
            return x_powered_by
        
        x_aspnet_version = response_headers.get('X-AspNet-Version', '')
        if x_aspnet_version:
            return 'ASP.NET'
        
        return None


class TechnologyDetector:
    TECHNOLOGY_SIGNATURES = {
        'wordpress': [
            r'/wp-content/',
            r'/wp-admin/',
            r'wp-version',
            r'wordpress',
        ],
        'drupal': [
            r'/sites/default/',
            r'/sites/all/',
            r'drupal',
        ],
        'joomla': [
            r'/components/com_',
            r'joomla',
        ],
        'magento': [
            r'/media/catalog/',
            r'magento',
        ],
        'shopify': [
            r'shopify-analytics',
            r'shopify',
        ],
    }
    
    @staticmethod
    def detect_technologies(response_content: str, response_headers: Dict) -> List[str]:
        detected = []
        
        for tech, signatures in TechnologyDetector.TECHNOLOGY_SIGNATURES.items():
            for signature in signatures:
                if re.search(signature, response_content + str(response_headers), re.IGNORECASE):
                    detected.append(tech)
                    break
        
        return list(set(detected))


class WildcardSubdomainDetector:
    @staticmethod
    def detect_wildcard(domain: str, resolver: DNSResolver) -> Tuple[bool, Optional[List[str]]]:
        random_subdomain = f"xyztest{int(time.time())}.{domain}"
        
        try:
            is_resolved, ips = resolver.resolve_subdomain(random_subdomain)
            if is_resolved:
                return True, ips
        except Exception:
            pass
        
        return False, None


class SubdomainEnumerator:
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'test', 'api', 'dev', 'staging',
        'prod', 'backup', 'old', 'new', 'beta', 'alpha', 'demo', 'app',
        'cdn', 'static', 'images', 'files', 'download', 'support', 'help',
        'blog', 'shop', 'store', 'portal', 'panel', 'manage', 'user',
        'account', 'login', 'auth', 'mail', 'smtp', 'imap', 'vpn',
        'proxy', 'gateway', 'dns', 'secure', 'ssl', 'git', 'svn',
        'jenkins', 'monitoring', 'grafana', 'kibana', 'elastic', 'redis',
        'mysql', 'postgres', 'mongo', 'db', 'database', 'cache',
    ]
    
    @staticmethod
    def generate_subdomains(domain: str) -> List[str]:
        return [f"{subdomain}.{domain}" for subdomain in SubdomainEnumerator.COMMON_SUBDOMAINS]


class SubdomainScanner:
    def __init__(self):
        self.dns_resolver = DNSResolver()
        self.cdn_detector = CDNDetector()
        self.cloud_detector = CloudProviderDetector()
        self.web_server_detector = WebServerDetector()
        self.tech_detector = TechnologyDetector()
        self.wildcard_detector = WildcardSubdomainDetector()
        self.enumerator = SubdomainEnumerator()
        
        self.discovered_subdomains: Dict[str, ResolvedSubdomain] = {}
        self.vulnerabilities: List[SubdomainVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.lock = threading.Lock()
    
    def scan_domain(self, domain: str) -> List[ResolvedSubdomain]:
        resolved_subdomains = []
        
        has_wildcard, wildcard_ips = self.wildcard_detector.detect_wildcard(domain, self.dns_resolver)
        
        subdomains_to_check = self.enumerator.generate_subdomains(domain)
        
        for subdomain in subdomains_to_check:
            is_resolved, ips = self.dns_resolver.resolve_subdomain(subdomain)
            
            if is_resolved:
                if has_wildcard and ips == wildcard_ips:
                    status = SubdomainStatus.WILDCARD
                else:
                    status = SubdomainStatus.ACTIVE
                
                cname = self.dns_resolver.resolve_cname(subdomain)
                
                is_cdn, cdn_provider = self.cdn_detector.detect_cdn(ips[0] if ips else '', cname)
                is_cloud, cloud_provider = self.cloud_detector.detect_cloud_provider(cname, domain)
                
                resolved = ResolvedSubdomain(
                    subdomain=subdomain,
                    ip_addresses=ips,
                    status=status,
                    is_cdn=is_cdn,
                    cdn_provider=cdn_provider,
                    is_cloud=is_cloud,
                    cloud_provider=cloud_provider,
                    discovered_method=SubdomainDiscoveryMethod.DNS_RESOLUTION
                )
                
                resolved_subdomains.append(resolved)
                self.scan_statistics['resolved'] += 1
            else:
                self.scan_statistics['not_resolved'] += 1
        
        with self.lock:
            for subdomain_obj in resolved_subdomains:
                self.discovered_subdomains[subdomain_obj.subdomain] = subdomain_obj
        
        return resolved_subdomains
    
    def check_http_status(self, subdomain: ResolvedSubdomain, response: Dict) -> ResolvedSubdomain:
        status_code = response.get('status_code', 0)
        content = response.get('content', '')
        headers = response.get('headers', {})
        
        subdomain.response_code = status_code
        subdomain.content_length = len(content)
        subdomain.web_server = self.web_server_detector.detect_web_server(headers)
        subdomain.technologies = self.tech_detector.detect_technologies(content, headers)
        
        title_match = re.search(r'<title>([^<]+)</title>', content)
        if title_match:
            subdomain.title = title_match.group(1)
        
        return subdomain
    
    def analyze_dns_records(self, domain: str) -> Dict[str, List[str]]:
        dns_info = {}
        
        mx_records = self.dns_resolver.resolve_mx_records(domain)
        if mx_records:
            dns_info['MX'] = mx_records
            self.scan_statistics['mx_records_found'] += 1
        
        txt_records = self.dns_resolver.resolve_txt_records(domain)
        if txt_records:
            dns_info['TXT'] = txt_records
            self.scan_statistics['txt_records_found'] += 1
        
        spf_records = [r for r in txt_records if r.startswith('v=spf1')]
        if spf_records:
            dns_info['SPF'] = spf_records
        
        dmarc_records = []
        try:
            dmarc = self.dns_resolver.resolve_txt_records(f"_dmarc.{domain}")
            dmarc_records = [r for r in dmarc if r.startswith('v=DMARC1')]
        except:
            pass
        
        if dmarc_records:
            dns_info['DMARC'] = dmarc_records
        
        return dns_info
    
    def identify_vulnerabilities(self, subdomain: ResolvedSubdomain) -> List[SubdomainVulnerability]:
        vulnerabilities = []
        
        if subdomain.status == SubdomainStatus.DEAD or not subdomain.response_code:
            return vulnerabilities
        
        if subdomain.response_code == 200 and not subdomain.web_server:
            vuln = SubdomainVulnerability(
                vulnerability_type='Missing Security Headers',
                subdomain=subdomain.subdomain,
                ip_address=subdomain.ip_addresses[0] if subdomain.ip_addresses else '',
                severity='Medium',
                evidence='Web server identification header missing',
                response_code=subdomain.response_code,
                threat_level=ThreatLevel.MEDIUM,
                confirmed=False,
                confidence_score=0.6,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
        
        if subdomain.response_code == 200 and not subdomain.title:
            vuln = SubdomainVulnerability(
                vulnerability_type='Generic Response',
                subdomain=subdomain.subdomain,
                ip_address=subdomain.ip_addresses[0] if subdomain.ip_addresses else '',
                severity='Low',
                evidence='Empty or missing page title detected',
                response_code=subdomain.response_code,
                threat_level=ThreatLevel.INFO,
                confirmed=False,
                confidence_score=0.5,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
        
        if subdomain.is_cdn and not subdomain.cdn_provider:
            vuln = SubdomainVulnerability(
                vulnerability_type='Unknown CDN Provider',
                subdomain=subdomain.subdomain,
                ip_address=subdomain.ip_addresses[0] if subdomain.ip_addresses else '',
                severity='Low',
                evidence='CDN detected but provider unknown',
                response_code=subdomain.response_code,
                is_cdn=True,
                threat_level=ThreatLevel.INFO,
                confirmed=False,
                confidence_score=0.7,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
        
        if subdomain.status == SubdomainStatus.WILDCARD:
            vuln = SubdomainVulnerability(
                vulnerability_type='Wildcard DNS Record',
                subdomain=subdomain.subdomain,
                ip_address=subdomain.ip_addresses[0] if subdomain.ip_addresses else '',
                severity='Low',
                evidence='Wildcard DNS record allowing subdomain spoofing',
                response_code=subdomain.response_code,
                threat_level=ThreatLevel.LOW,
                confirmed=True,
                confidence_score=0.9,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
            self.scan_statistics['vulnerabilities_found'] += len(vulnerabilities)
        
        return vulnerabilities
    
    def _get_remediation(self) -> str:
        return (
            "Implement proper DNS security configuration. "
            "Disable unnecessary subdomains. "
            "Configure appropriate security headers on all subdomains. "
            "Use strong SSL/TLS certificates. "
            "Implement DDoS protection for subdomains. "
            "Monitor subdomain creation and DNS changes. "
            "Implement DNS DNSSEC. "
            "Use subdomain takeover protection."
        )
    
    def get_discovered_subdomains(self) -> Dict[str, ResolvedSubdomain]:
        with self.lock:
            return self.discovered_subdomains.copy()
    
    def get_vulnerabilities(self) -> List[SubdomainVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.discovered_subdomains.clear()
            self.vulnerabilities.clear()
            self.scan_statistics.clear()