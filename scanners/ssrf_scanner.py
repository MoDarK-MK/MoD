from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address


class SSRFType(Enum):
    BASIC_SSRF = "basic_ssrf"
    BLIND_SSRF = "blind_ssrf"
    TIME_BASED_SSRF = "time_based_ssrf"
    DNS_EXFILTRATION = "dns_exfiltration"
    HTTP_REDIRECT = "http_redirect"
    PROTOCOL_CONFUSION = "protocol_confusion"
    PARTIAL_URL = "partial_url"


class TargetType(Enum):
    INTERNAL_IP = "internal_ip"
    METADATA_SERVICE = "metadata_service"
    LOCALHOST = "localhost"
    CLOUD_PROVIDER = "cloud_provider"
    FILE_PROTOCOL = "file_protocol"
    CUSTOM_PROTOCOL = "custom_protocol"
    NETWORK_SERVICE = "network_service"


class CloudProvider(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    ALIBABA = "alibaba"
    DIGITALOCEAN = "digitalocean"
    HEROKU = "heroku"


@dataclass
class SSRFPayload:
    payload: str
    ssrf_type: SSRFType
    target_type: TargetType
    cloud_provider: Optional[CloudProvider] = None
    severity: str = "High"
    detection_indicators: List[str] = field(default_factory=list)
    requires_confirmation: bool = True
    false_positive_risk: float = 0.2


@dataclass
class SSRFVulnerability:
    vulnerability_type: str
    ssrf_type: SSRFType
    target_type: TargetType
    cloud_provider: Optional[CloudProvider]
    url: str
    parameter: str
    payload: str
    severity: str
    evidence: str
    response_time: float
    response_status: int
    internal_service_detected: Optional[str] = None
    metadata_accessed: bool = False
    internal_ip_revealed: Optional[str] = None
    port_open: bool = False
    port_number: Optional[int] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class IPAddressValidator:
    PRIVATE_RANGES = [
        ip_network('10.0.0.0/8'),
        ip_network('172.16.0.0/12'),
        ip_network('192.168.0.0/16'),
        ip_network('127.0.0.0/8'),
        ip_network('169.254.0.0/16'),
        ip_network('224.0.0.0/4'),
        ip_network('240.0.0.0/4'),
    ]
    
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        try:
            ip = ip_address(ip_str)
            return any(ip in private_range for private_range in IPAddressValidator.PRIVATE_RANGES)
        except ValueError:
            return False
    
    @staticmethod
    def is_localhost(ip_str: str) -> bool:
        return ip_str in ['localhost', '127.0.0.1', '::1', '0.0.0.0']
    
    @staticmethod
    def extract_ip_addresses(url: str) -> List[str]:
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        return re.findall(ip_pattern, url)
    
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        try:
            ip_address(ip_str)
            return True
        except ValueError:
            return False


class MetadataServiceDetector:
    METADATA_SERVICES = {
        CloudProvider.AWS: {
            'endpoint': '169.254.169.254',
            'paths': [
                '/latest/meta-data/',
                '/latest/user-data/',
                '/latest/api/token',
                '/latest/dynamic/instance-identity/document',
                '/latest/meta-data/iam/security-credentials/',
            ],
            'indicators': ['ami-', 'aws', 'AccessKeyId', 'SecretAccessKey'],
        },
        CloudProvider.GCP: {
            'endpoint': 'metadata.google.internal',
            'paths': [
                '/computeMetadata/v1/',
                '/computeMetadata/v1/instance/service-accounts/',
                '/computeMetadata/v1/instance/identity',
            ],
            'indicators': ['google', 'gcp', 'service-accounts', 'default'],
        },
        CloudProvider.AZURE: {
            'endpoint': '169.254.169.254',
            'paths': [
                '/metadata/instance/',
                '/metadata/instance/compute',
            ],
            'indicators': ['Azure', 'vmId', 'subscriptionId'],
        },
        CloudProvider.DIGITALOCEAN: {
            'endpoint': '169.254.169.254',
            'paths': [
                '/metadata/v1/',
                '/metadata/v1/id',
            ],
            'indicators': ['DigitalOcean', 'droplet_id'],
        },
        CloudProvider.ALIBABA: {
            'endpoint': '100.100.100.200',
            'paths': [
                '/latest/meta-data/',
            ],
            'indicators': ['Alibaba', 'alibaba'],
        },
    }
    
    @staticmethod
    def detect_metadata_service(response_content: str) -> Tuple[bool, Optional[CloudProvider], List[str]]:
        detected_indicators = []
        detected_provider = None
        
        for provider, config in MetadataServiceDetector.METADATA_SERVICES.items():
            for indicator in config['indicators']:
                if indicator in response_content:
                    detected_indicators.append(indicator)
                    if not detected_provider:
                        detected_provider = provider
        
        return len(detected_indicators) > 0, detected_provider, detected_indicators
    
    @staticmethod
    def get_metadata_service_config(provider: CloudProvider) -> Dict:
        return MetadataServiceDetector.METADATA_SERVICES.get(provider, {})


class InternalServiceDetector:
    COMMON_INTERNAL_SERVICES = {
        80: ['http', 'web', 'api', 'admin', 'portal'],
        443: ['https', 'ssl', 'secure'],
        3306: ['mysql', 'database', 'db'],
        5432: ['postgresql', 'postgres'],
        6379: ['redis', 'cache'],
        27017: ['mongodb', 'mongo'],
        5000: ['flask', 'python', 'api'],
        8000: ['django', 'python'],
        8080: ['tomcat', 'proxy', 'service'],
        8443: ['https', 'api', 'service'],
        9200: ['elasticsearch', 'elastic', 'search'],
        9300: ['elasticsearch', 'elastic'],
        3389: ['rdp', 'remote', 'windows'],
        22: ['ssh', 'remote', 'server'],
        21: ['ftp', 'file', 'transfer'],
    }
    
    SERVICE_RESPONSE_PATTERNS = {
        'MySQL': r"(?i)mysql.*error|mysql_fetch",
        'PostgreSQL': r"(?i)postgresql.*error|pg_",
        'Redis': r"(?i)redis|WRONGTYPE|ERR",
        'MongoDB': r"(?i)mongodb|MongoError",
        'Elasticsearch': r"(?i)elasticsearch|lucene",
        'Tomcat': r"(?i)tomcat|apache",
        'Jenkins': r"(?i)jenkins",
        'Docker': r"(?i)docker|container",
        'FTP': r"(?i)220.*ftp|connected",
    }
    
    @staticmethod
    def detect_internal_service(response_content: str, port: int) -> Tuple[bool, Optional[str], List[str]]:
        detected_services = []
        
        for service_name, pattern in InternalServiceDetector.SERVICE_RESPONSE_PATTERNS.items():
            if re.search(pattern, response_content):
                detected_services.append(service_name)
        
        if port in InternalServiceDetector.COMMON_INTERNAL_SERVICES:
            port_services = InternalServiceDetector.COMMON_INTERNAL_SERVICES[port]
            for service in port_services:
                if service in response_content.lower():
                    detected_services.append(service.upper())
        
        primary_service = detected_services[0] if detected_services else None
        return len(detected_services) > 0, primary_service, detected_services
    
    @staticmethod
    def get_default_ports() -> Dict[str, int]:
        return {
            'mysql': 3306,
            'postgresql': 5432,
            'redis': 6379,
            'mongodb': 27017,
            'elasticsearch': 9200,
            'tomcat': 8080,
            'jenkins': 8080,
            'ssh': 22,
            'ftp': 21,
        }


class URLObfuscationBypass:
    BYPASS_TECHNIQUES = [
        lambda url: url.replace('127.0.0.1', '0'),
        lambda url: url.replace('127.0.0.1', '0.0.0.0'),
        lambda url: url.replace('127.0.0.1', '127.0.1.1'),
        lambda url: url.replace('http://', 'HTTP://'),
        lambda url: url.replace('localhost', 'LOCALHOST'),
        lambda url: url.replace('http://', 'http%3a//'),
        lambda url: url.replace('/', '%2f'),
        lambda url: url.replace('.', '%2e'),
        lambda url: url.replace('169.254.169.254', '169.254.169.254.nip.io'),
    ]
    
    @staticmethod
    def generate_bypass_urls(base_url: str) -> List[str]:
        bypassed = [base_url]
        
        for technique in URLObfuscationBypass.BYPASS_TECHNIQUES:
            try:
                bypassed_url = technique(base_url)
                if bypassed_url not in bypassed:
                    bypassed.append(bypassed_url)
            except:
                pass
        
        return bypassed


class ResponseAnalyzer:
    @staticmethod
    def analyze_ssrf_response(response_content: str, baseline_response: str,
                            response_time: float, status_code: int) -> Tuple[Optional[SSRFType], float]:
        if response_content != baseline_response:
            return SSRFType.BASIC_SSRF, 0.9
        
        if response_time > 5:
            return SSRFType.TIME_BASED_SSRF, 0.8
        
        if status_code in [200, 301, 302, 307]:
            if len(response_content) > 100:
                return SSRFType.BASIC_SSRF, 0.85
        
        return SSRFType.BLIND_SSRF, 0.6


class PortScanningDetector:
    COMMON_PORTS = [21, 22, 80, 443, 3306, 5432, 6379, 8000, 8080, 8443, 9200]
    
    @staticmethod
    def extract_port_number(url: str) -> Optional[int]:
        match = re.search(r':(\d+)', url)
        return int(match.group(1)) if match else None
    
    @staticmethod
    def detect_port_open(response_content: str, response_time: float,
                        status_code: int) -> Tuple[bool, float]:
        confidence = 0.0
        
        if status_code != 0:
            confidence += 0.5
        
        if len(response_content) > 10:
            confidence += 0.3
        
        if response_time < 5:
            confidence += 0.2
        
        return confidence > 0.5, min(confidence, 1.0)


class SSRFScanner:
    def __init__(self):
        self.ip_validator = IPAddressValidator()
        self.metadata_detector = MetadataServiceDetector()
        self.service_detector = InternalServiceDetector()
        self.url_bypass = URLObfuscationBypass()
        self.response_analyzer = ResponseAnalyzer()
        self.port_detector = PortScanningDetector()
        
        self.vulnerabilities: List[SSRFVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.baseline_responses: Dict[str, str] = {}
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: List[str],
            baseline_response: Optional[str] = None) -> List[SSRFVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        if baseline_response is None:
            baseline_response = response_content
        
        parameter = self._extract_parameter_name(target_url)
        
        for payload in payloads:
            is_vulnerable, ssrf_type, target_type, evidence = self._test_payload(
                response_content,
                baseline_response,
                payload,
                response_time,
                status_code
            )
            
            if is_vulnerable:
                internal_service, service_name, services = self.service_detector.detect_internal_service(
                    response_content,
                    self.port_detector.extract_port_number(payload) or 80
                )
                
                metadata_detected, cloud_provider, metadata_indicators = self.metadata_detector.detect_metadata_service(
                    response_content
                )
                
                port_open, port_confidence = self.port_detector.detect_port_open(
                    response_content,
                    response_time,
                    status_code
                )
                
                ips = self.ip_validator.extract_ip_addresses(response_content)
                internal_ip = None
                for ip in ips:
                    if self.ip_validator.is_private_ip(ip):
                        internal_ip = ip
                        break
                
                vuln = SSRFVulnerability(
                    vulnerability_type='Server-Side Request Forgery',
                    ssrf_type=ssrf_type,
                    target_type=target_type,
                    cloud_provider=cloud_provider if metadata_detected else None,
                    url=target_url,
                    parameter=parameter,
                    payload=payload,
                    severity=self._determine_severity(ssrf_type, metadata_detected),
                    evidence=evidence,
                    response_time=response_time,
                    response_status=status_code,
                    internal_service_detected=service_name,
                    metadata_accessed=metadata_detected,
                    internal_ip_revealed=internal_ip,
                    port_open=port_open,
                    port_number=self.port_detector.extract_port_number(payload),
                    confirmed=internal_service or metadata_detected,
                    remediation=self._get_remediation()
                )
                
                if self._is_valid_vulnerability(vuln):
                    vulnerabilities.append(vuln)
                    self.scan_statistics[ssrf_type.value] += 1
            
            bypass_urls = self.url_bypass.generate_bypass_urls(payload)
            for bypass_url in bypass_urls[1:]:
                is_vulnerable, ssrf_type, target_type, evidence = self._test_payload(
                    response_content,
                    baseline_response,
                    bypass_url,
                    response_time,
                    status_code
                )
                
                if is_vulnerable and not any(v.payload == bypass_url for v in vulnerabilities):
                    vuln = SSRFVulnerability(
                        vulnerability_type='Server-Side Request Forgery',
                        ssrf_type=SSRFType.BASIC_SSRF,
                        target_type=target_type,
                        cloud_provider=None,
                        url=target_url,
                        parameter=parameter,
                        payload=bypass_url,
                        severity='High',
                        evidence=f"Bypass technique detected: {evidence}",
                        response_time=response_time,
                        response_status=status_code,
                        confirmed=True,
                        remediation=self._get_remediation()
                    )
                    vulnerabilities.append(vuln)
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _test_payload(self, response_content: str, baseline_response: str,
                     payload: str, response_time: float,
                     status_code: int) -> Tuple[bool, Optional[SSRFType], TargetType, str]:
        
        if self.ip_validator.is_localhost(payload):
            return True, SSRFType.BASIC_SSRF, TargetType.LOCALHOST, "Localhost access detected"
        
        ips = self.ip_validator.extract_ip_addresses(payload)
        if ips:
            for ip in ips:
                if self.ip_validator.is_private_ip(ip):
                    return True, SSRFType.BASIC_SSRF, TargetType.INTERNAL_IP, f"Private IP accessed: {ip}"
        
        if '169.254.169.254' in payload or 'metadata.google.internal' in payload:
            return True, SSRFType.BASIC_SSRF, TargetType.METADATA_SERVICE, "Metadata service endpoint detected"
        
        metadata_detected, cloud_provider, indicators = self.metadata_detector.detect_metadata_service(response_content)
        if metadata_detected:
            return True, SSRFType.BASIC_SSRF, TargetType.METADATA_SERVICE, f"Cloud metadata accessed: {cloud_provider.value}"
        
        internal_service, service_name, services = self.service_detector.detect_internal_service(
            response_content,
            self.port_detector.extract_port_number(payload) or 80
        )
        if internal_service:
            return True, SSRFType.BASIC_SSRF, TargetType.NETWORK_SERVICE, f"Internal service detected: {service_name}"
        
        if 'file://' in payload:
            return True, SSRFType.BASIC_SSRF, TargetType.FILE_PROTOCOL, "File protocol detected"
        
        if response_content != baseline_response:
            ssrf_type, confidence = self.response_analyzer.analyze_ssrf_response(
                response_content,
                baseline_response,
                response_time,
                status_code
            )
            if confidence > 0.7:
                return True, ssrf_type, TargetType.CUSTOM_PROTOCOL, f"Response modification detected ({confidence:.0%} confidence)"
        
        return False, None, TargetType.CUSTOM_PROTOCOL, ""
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else 'parameter'
    
    def _determine_severity(self, ssrf_type: Optional[SSRFType], metadata_detected: bool) -> str:
        if metadata_detected:
            return 'Critical'
        
        if ssrf_type == SSRFType.BASIC_SSRF:
            return 'High'
        elif ssrf_type == SSRFType.BLIND_SSRF:
            return 'Medium'
        
        return 'High'
    
    def _is_valid_vulnerability(self, vuln: SSRFVulnerability) -> bool:
        if vuln.confidence_score < 0.6:
            return False
        
        if any(word in vuln.payload.lower() for word in ['test', 'example', 'sample']):
            return False
        
        return vuln.confirmed or (vuln.response_status != 0 and vuln.response_status != 404)
    
    def _get_remediation(self) -> str:
        return (
            "Implement strict URL validation with allowlist of allowed hosts. "
            "Disable unused URL schemes (file://, gopher://, etc). "
            "Use URL parsing libraries correctly. "
            "Block access to private IP ranges and metadata endpoints. "
            "Implement network segmentation. "
            "Use WAF rules to detect SSRF attempts. "
            "Monitor outbound connections. "
            "Use DNS allowlisting for external requests."
        )
    
    def get_vulnerabilities(self) -> List[SSRFVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def set_baseline_response(self, parameter: str, response: str):
        self.baseline_responses[parameter] = response
    
    def get_baseline_response(self, parameter: str) -> Optional[str]:
        return self.baseline_responses.get(parameter)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.baseline_responses.clear()