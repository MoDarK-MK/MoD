from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
import hashlib
import socket
import struct
import base64
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed


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
        ip_network('::1/128'),
        ip_network('fc00::/7'),
        ip_network('fe80::/10'),
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
        localhost_variants = [
            'localhost', '127.0.0.1', '::1', '0.0.0.0', '0', '0x7f000001',
            '0177.0.0.1', '2130706433', '017700000001', '0x7f.0x0.0x0.0x1',
            '[::1]', '127.1', '127.0.1'
        ]
        return ip_str.lower() in localhost_variants
    
    @staticmethod
    def extract_ip_addresses(url: str) -> List[str]:
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        return re.findall(ipv4_pattern, url) + re.findall(ipv6_pattern, url)
    
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        try:
            ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def ip_to_decimal(ip_str: str) -> Optional[int]:
        try:
            packed = socket.inet_aton(ip_str)
            return struct.unpack("!I", packed)[0]
        except:
            return None
    
    @staticmethod
    def ip_to_hex(ip_str: str) -> Optional[str]:
        try:
            return '0x' + ''.join([f'{int(octet):02x}' for octet in ip_str.split('.')])
        except:
            return None
    
    @staticmethod
    def ip_to_octal(ip_str: str) -> Optional[str]:
        try:
            return '.'.join([f'0{int(octet):o}' for octet in ip_str.split('.')])
        except:
            return None


class MetadataServiceDetector:
    METADATA_SERVICES = {
        CloudProvider.AWS: {
            'endpoints': ['169.254.169.254', '169.254.170.2'],
            'paths': [
                '/latest/meta-data/',
                '/latest/user-data/',
                '/latest/api/token',
                '/latest/dynamic/instance-identity/document',
                '/latest/meta-data/iam/security-credentials/',
                '/latest/meta-data/placement/availability-zone',
                '/latest/meta-data/public-ipv4',
                '/latest/meta-data/hostname',
            ],
            'indicators': ['ami-', 'aws', 'AccessKeyId', 'SecretAccessKey', 'instanceId', 'region'],
            'headers': {'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
        },
        CloudProvider.GCP: {
            'endpoints': ['metadata.google.internal', '169.254.169.254'],
            'paths': [
                '/computeMetadata/v1/',
                '/computeMetadata/v1/instance/service-accounts/',
                '/computeMetadata/v1/instance/identity',
                '/computeMetadata/v1/project/project-id',
                '/computeMetadata/v1/instance/attributes/',
            ],
            'indicators': ['google', 'gcp', 'service-accounts', 'default', 'projectId'],
            'headers': {'Metadata-Flavor': 'Google'},
        },
        CloudProvider.AZURE: {
            'endpoints': ['169.254.169.254'],
            'paths': [
                '/metadata/instance/',
                '/metadata/instance/compute',
                '/metadata/instance/network',
                '/metadata/identity/oauth2/token',
            ],
            'indicators': ['Azure', 'vmId', 'subscriptionId', 'resourceGroupName'],
            'headers': {'Metadata': 'true'},
        },
        CloudProvider.DIGITALOCEAN: {
            'endpoints': ['169.254.169.254'],
            'paths': [
                '/metadata/v1/',
                '/metadata/v1/id',
                '/metadata/v1/hostname',
                '/metadata/v1/region',
            ],
            'indicators': ['DigitalOcean', 'droplet_id', 'region'],
            'headers': {},
        },
        CloudProvider.ALIBABA: {
            'endpoints': ['100.100.100.200'],
            'paths': [
                '/latest/meta-data/',
                '/latest/meta-data/instance-id',
                '/latest/meta-data/image-id',
            ],
            'indicators': ['Alibaba', 'alibaba', 'instance-id'],
            'headers': {},
        },
    }
    
    @staticmethod
    def detect_metadata_service(response_content: str) -> Tuple[bool, Optional[CloudProvider], List[str]]:
        detected_indicators = []
        detected_provider = None
        max_score = 0
        
        for provider, config in MetadataServiceDetector.METADATA_SERVICES.items():
            score = 0
            provider_indicators = []
            
            for indicator in config['indicators']:
                if indicator in response_content:
                    score += 1
                    provider_indicators.append(indicator)
            
            if score > max_score:
                max_score = score
                detected_provider = provider
                detected_indicators = provider_indicators
        
        return max_score > 0, detected_provider, detected_indicators
    
    @staticmethod
    def get_metadata_service_config(provider: CloudProvider) -> Dict:
        return MetadataServiceDetector.METADATA_SERVICES.get(provider, {})


class InternalServiceDetector:
    COMMON_INTERNAL_SERVICES = {
        20: ['ftp-data'],
        21: ['ftp', 'file', 'transfer'],
        22: ['ssh', 'remote', 'server'],
        23: ['telnet'],
        25: ['smtp', 'mail'],
        53: ['dns'],
        80: ['http', 'web', 'api', 'admin', 'portal'],
        110: ['pop3', 'mail'],
        143: ['imap', 'mail'],
        443: ['https', 'ssl', 'secure'],
        445: ['smb', 'windows', 'share'],
        1433: ['mssql', 'sqlserver'],
        1521: ['oracle', 'database'],
        3306: ['mysql', 'database', 'db'],
        3389: ['rdp', 'remote', 'windows'],
        5000: ['flask', 'python', 'api'],
        5432: ['postgresql', 'postgres'],
        5672: ['rabbitmq', 'amqp'],
        6379: ['redis', 'cache'],
        8000: ['django', 'python'],
        8080: ['tomcat', 'proxy', 'service'],
        8443: ['https', 'api', 'service'],
        9000: ['php-fpm'],
        9200: ['elasticsearch', 'elastic', 'search'],
        9300: ['elasticsearch', 'elastic'],
        11211: ['memcached', 'cache'],
        27017: ['mongodb', 'mongo'],
        50070: ['hadoop'],
    }
    
    SERVICE_RESPONSE_PATTERNS = {
        'MySQL': r"(?i)mysql.*error|mysql_fetch|mysql_connect|native password",
        'PostgreSQL': r"(?i)postgresql.*error|pg_|postgres",
        'Redis': r"(?i)redis|WRONGTYPE|ERR|PONG|-NOAUTH",
        'MongoDB': r"(?i)mongodb|MongoError|db version|wire version",
        'Elasticsearch': r"(?i)elasticsearch|lucene|_cluster|_nodes",
        'Tomcat': r"(?i)apache tomcat|tomcat.*version",
        'Jenkins': r"(?i)jenkins|hudson",
        'Docker': r"(?i)docker|container|api version",
        'FTP': r"(?i)220.*ftp|connected|welcome",
        'SSH': r"(?i)ssh|openssh|protocol",
        'RabbitMQ': r"(?i)rabbitmq|amqp",
        'Memcached': r"(?i)memcached|stats|version",
        'SMTP': r"(?i)220.*smtp|mail server|postfix|sendmail",
        'Apache': r"(?i)apache.*server|it works",
        'Nginx': r"(?i)nginx|welcome to nginx",
        'Kubernetes': r"(?i)kubernetes|k8s|api/v1",
        'Consul': r"(?i)consul",
        'Etcd': r"(?i)etcd",
    }
    
    @staticmethod
    def detect_internal_service(response_content: str, port: int) -> Tuple[bool, Optional[str], List[str]]:
        detected_services = []
        confidence_scores = {}
        
        for service_name, pattern in InternalServiceDetector.SERVICE_RESPONSE_PATTERNS.items():
            matches = re.findall(pattern, response_content)
            if matches:
                detected_services.append(service_name)
                confidence_scores[service_name] = len(matches)
        
        if port in InternalServiceDetector.COMMON_INTERNAL_SERVICES:
            port_services = InternalServiceDetector.COMMON_INTERNAL_SERVICES[port]
            for service in port_services:
                if service in response_content.lower():
                    service_upper = service.upper()
                    if service_upper not in detected_services:
                        detected_services.append(service_upper)
                        confidence_scores[service_upper] = 1
        
        primary_service = max(confidence_scores.items(), key=lambda x: x[1])[0] if confidence_scores else (detected_services[0] if detected_services else None)
        return len(detected_services) > 0, primary_service, detected_services
    
    @staticmethod
    def get_default_ports() -> Dict[str, int]:
        return {
            'mysql': 3306, 'postgresql': 5432, 'redis': 6379, 'mongodb': 27017,
            'elasticsearch': 9200, 'tomcat': 8080, 'jenkins': 8080, 'ssh': 22,
            'ftp': 21, 'smtp': 25, 'rabbitmq': 5672, 'memcached': 11211,
        }


class URLObfuscationBypass:
    @staticmethod
    def generate_bypass_urls(base_url: str) -> List[str]:
        bypassed = [base_url]
        
        if '127.0.0.1' in base_url:
            bypassed.extend([
                base_url.replace('127.0.0.1', '0'),
                base_url.replace('127.0.0.1', '0.0.0.0'),
                base_url.replace('127.0.0.1', '127.0.1'),
                base_url.replace('127.0.0.1', '127.1'),
                base_url.replace('127.0.0.1', '2130706433'),
                base_url.replace('127.0.0.1', '0x7f000001'),
                base_url.replace('127.0.0.1', '017700000001'),
                base_url.replace('127.0.0.1', '0177.0.0.1'),
                base_url.replace('127.0.0.1', '0x7f.0x0.0x0.0x1'),
            ])
        
        if 'localhost' in base_url:
            bypassed.extend([
                base_url.replace('localhost', 'LOCALHOST'),
                base_url.replace('localhost', 'LocalHost'),
                base_url.replace('localhost', '127.0.0.1'),
                base_url.replace('localhost', '0'),
                base_url.replace('localhost', 'localhost.'),
                base_url.replace('localhost', '[::1]'),
            ])
        
        if '169.254.169.254' in base_url:
            bypassed.extend([
                base_url.replace('169.254.169.254', '169.254.169.254.nip.io'),
                base_url.replace('169.254.169.254', '169.254.169.254.xip.io'),
                base_url.replace('169.254.169.254', '0xA9FEA9FE'),
                base_url.replace('169.254.169.254', '2852039166'),
            ])
        
        if 'http://' in base_url:
            bypassed.extend([
                base_url.replace('http://', 'HTTP://'),
                base_url.replace('http://', 'hTtP://'),
                base_url.replace('http://', 'http%3a//'),
            ])
        
        if '/' in base_url:
            bypassed.append(base_url.replace('/', '%2f'))
        
        if '.' in base_url:
            bypassed.append(base_url.replace('.', '%2e'))
        
        parsed = urllib.parse.urlparse(base_url)
        if parsed.hostname:
            bypassed.extend([
                base_url.replace(parsed.hostname, parsed.hostname + '@127.0.0.1'),
                base_url.replace(parsed.hostname, '127.0.0.1#' + parsed.hostname),
                base_url.replace(parsed.hostname, parsed.hostname + '%00'),
                base_url.replace(parsed.hostname, parsed.hostname + '%0a'),
            ])
        
        return list(set(bypassed))


class ResponseAnalyzer:
    @staticmethod
    def analyze_ssrf_response(response_content: str, baseline_response: str,
                            response_time: float, status_code: int) -> Tuple[Optional[SSRFType], float]:
        confidence = 0.0
        ssrf_type = SSRFType.BLIND_SSRF
        
        if response_content != baseline_response:
            diff_ratio = len(set(response_content) - set(baseline_response)) / max(len(response_content), 1)
            if diff_ratio > 0.3:
                confidence = 0.9
                ssrf_type = SSRFType.BASIC_SSRF
            elif diff_ratio > 0.1:
                confidence = 0.75
                ssrf_type = SSRFType.BASIC_SSRF
            else:
                confidence = 0.6
        
        if response_time > 10:
            confidence = max(confidence, 0.85)
            ssrf_type = SSRFType.TIME_BASED_SSRF
        elif response_time > 5:
            confidence = max(confidence, 0.75)
            ssrf_type = SSRFType.TIME_BASED_SSRF
        
        if status_code in [200, 201, 204]:
            confidence += 0.15
        elif status_code in [301, 302, 303, 307, 308]:
            confidence += 0.1
            ssrf_type = SSRFType.HTTP_REDIRECT
        
        if len(response_content) > 100:
            confidence += 0.05
        
        if any(keyword in response_content.lower() for keyword in ['error', 'exception', 'warning', 'denied', 'forbidden']):
            confidence -= 0.1
        
        return ssrf_type, min(max(confidence, 0.0), 1.0)
    
    @staticmethod
    def detect_dns_exfiltration(response_content: str, payload: str) -> Tuple[bool, float]:
        dns_indicators = [
            r'nslookup', r'dig\s+', r'host\s+', r'dns', r'resolve',
            r'\b[a-z0-9]{32,}\..*\.(com|net|org|io)\b',
        ]
        
        matches = sum(1 for pattern in dns_indicators if re.search(pattern, response_content, re.IGNORECASE))
        confidence = min(matches * 0.3, 1.0)
        
        return matches > 0, confidence


class PortScanningDetector:
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        1433, 1521, 3306, 3389, 5000, 5432, 5672, 6379, 8000,
        8080, 8443, 9000, 9200, 9300, 11211, 27017, 50070
    ]
    
    @staticmethod
    def extract_port_number(url: str) -> Optional[int]:
        match = re.search(r':(\d+)', url)
        if match:
            port = int(match.group(1))
            return port if 1 <= port <= 65535 else None
        return None
    
    @staticmethod
    def detect_port_open(response_content: str, response_time: float,
                        status_code: int) -> Tuple[bool, float]:
        confidence = 0.0
        
        if status_code != 0 and status_code != 404:
            confidence += 0.5
        
        if status_code in [200, 301, 302, 401, 403]:
            confidence += 0.2
        
        if len(response_content) > 10:
            confidence += 0.2
        
        if response_time < 5:
            confidence += 0.1
        
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
        self.max_workers = 10
    
    def scan(self, target_url: str, response: Dict, payloads: List[str],
            baseline_response: Optional[str] = None) -> List[SSRFVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        if baseline_response is None:
            baseline_response = response_content
        
        parameter = self._extract_parameter_name(target_url)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for payload in payloads:
                future = executor.submit(
                    self._test_single_payload,
                    target_url, parameter, payload, response_content,
                    baseline_response, response_time, status_code
                )
                futures.append(future)
                
                bypass_urls = self.url_bypass.generate_bypass_urls(payload)
                for bypass_url in bypass_urls[1:]:
                    future = executor.submit(
                        self._test_single_payload,
                        target_url, parameter, bypass_url, response_content,
                        baseline_response, response_time, status_code
                    )
                    futures.append(future)
            
            for future in as_completed(futures):
                vuln = future.result()
                if vuln:
                    vulnerabilities.append(vuln)
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _test_single_payload(self, target_url: str, parameter: str, payload: str,
                            response_content: str, baseline_response: str,
                            response_time: float, status_code: int) -> Optional[SSRFVulnerability]:
        
        is_vulnerable, ssrf_type, target_type, evidence, confidence = self._test_payload(
            response_content, baseline_response, payload, response_time, status_code
        )
        
        if not is_vulnerable:
            return None
        
        internal_service, service_name, services = self.service_detector.detect_internal_service(
            response_content,
            self.port_detector.extract_port_number(payload) or 80
        )
        
        metadata_detected, cloud_provider, metadata_indicators = self.metadata_detector.detect_metadata_service(
            response_content
        )
        
        port_open, port_confidence = self.port_detector.detect_port_open(
            response_content, response_time, status_code
        )
        
        ips = self.ip_validator.extract_ip_addresses(response_content)
        internal_ip = next((ip for ip in ips if self.ip_validator.is_private_ip(ip)), None)
        
        dns_exfil_detected, dns_confidence = self.response_analyzer.detect_dns_exfiltration(
            response_content, payload
        )
        
        if dns_exfil_detected:
            ssrf_type = SSRFType.DNS_EXFILTRATION
            confidence = max(confidence, dns_confidence)
        
        final_confidence = min(confidence * (1.2 if metadata_detected else 1.0) * 
                              (1.1 if internal_service else 1.0), 1.0)
        
        vuln = SSRFVulnerability(
            vulnerability_type='Server-Side Request Forgery',
            ssrf_type=ssrf_type,
            target_type=target_type,
            cloud_provider=cloud_provider if metadata_detected else None,
            url=target_url,
            parameter=parameter,
            payload=payload,
            severity=self._determine_severity(ssrf_type, metadata_detected, internal_service),
            evidence=evidence,
            response_time=response_time,
            response_status=status_code,
            internal_service_detected=service_name,
            metadata_accessed=metadata_detected,
            internal_ip_revealed=internal_ip,
            port_open=port_open,
            port_number=self.port_detector.extract_port_number(payload),
            confirmed=internal_service or metadata_detected or final_confidence > 0.85,
            confidence_score=final_confidence,
            remediation=self._get_remediation()
        )
        
        if self._is_valid_vulnerability(vuln):
            with self.lock:
                self.scan_statistics[ssrf_type.value] += 1
            return vuln
        
        return None
    
    def _test_payload(self, response_content: str, baseline_response: str,
                     payload: str, response_time: float,
                     status_code: int) -> Tuple[bool, Optional[SSRFType], TargetType, str, float]:
        
        if self.ip_validator.is_localhost(payload):
            return True, SSRFType.BASIC_SSRF, TargetType.LOCALHOST, "Localhost access detected", 0.95
        
        ips = self.ip_validator.extract_ip_addresses(payload)
        for ip in ips:
            if self.ip_validator.is_private_ip(ip):
                return True, SSRFType.BASIC_SSRF, TargetType.INTERNAL_IP, f"Private IP accessed: {ip}", 0.92
        
        if '169.254.169.254' in payload or 'metadata.google.internal' in payload or '100.100.100.200' in payload:
            return True, SSRFType.BASIC_SSRF, TargetType.METADATA_SERVICE, "Metadata service endpoint detected", 0.98
        
        metadata_detected, cloud_provider, indicators = self.metadata_detector.detect_metadata_service(response_content)
        if metadata_detected:
            confidence = min(0.85 + (len(indicators) * 0.05), 1.0)
            return True, SSRFType.BASIC_SSRF, TargetType.METADATA_SERVICE, f"Cloud metadata accessed: {cloud_provider.value}", confidence
        
        internal_service, service_name, services = self.service_detector.detect_internal_service(
            response_content,
            self.port_detector.extract_port_number(payload) or 80
        )
        if internal_service:
            confidence = min(0.80 + (len(services) * 0.05), 0.95)
            return True, SSRFType.BASIC_SSRF, TargetType.NETWORK_SERVICE, f"Internal service detected: {service_name}", confidence
        
        protocol_patterns = {
            'file://': (TargetType.FILE_PROTOCOL, 0.96),
            'gopher://': (TargetType.CUSTOM_PROTOCOL, 0.93),
            'dict://': (TargetType.CUSTOM_PROTOCOL, 0.93),
            'ftp://': (TargetType.CUSTOM_PROTOCOL, 0.88),
            'tftp://': (TargetType.CUSTOM_PROTOCOL, 0.88),
            'ldap://': (TargetType.CUSTOM_PROTOCOL, 0.90),
        }
        
        for protocol, (target_type, confidence) in protocol_patterns.items():
            if protocol in payload.lower():
                return True, SSRFType.PROTOCOL_CONFUSION, target_type, f"{protocol.upper()} protocol detected", confidence
        
        ssrf_type, confidence = self.response_analyzer.analyze_ssrf_response(
            response_content, baseline_response, response_time, status_code
        )
        
        if confidence > 0.7:
            return True, ssrf_type, TargetType.CUSTOM_PROTOCOL, f"Response analysis confidence: {confidence:.0%}", confidence
        
        return False, None, TargetType.CUSTOM_PROTOCOL, "", 0.0
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else 'parameter'
    
    def _determine_severity(self, ssrf_type: Optional[SSRFType], metadata_detected: bool, 
                           internal_service: bool) -> str:
        if metadata_detected:
            return 'Critical'
        
        if ssrf_type == SSRFType.BASIC_SSRF:
            return 'Critical' if internal_service else 'High'
        elif ssrf_type == SSRFType.TIME_BASED_SSRF:
            return 'High'
        elif ssrf_type == SSRFType.PROTOCOL_CONFUSION:
            return 'High'
        elif ssrf_type == SSRFType.DNS_EXFILTRATION:
            return 'High'
        elif ssrf_type == SSRFType.BLIND_SSRF:
            return 'Medium'
        
        return 'High'
    
    def _is_valid_vulnerability(self, vuln: SSRFVulnerability) -> bool:
        if vuln.confidence_score < 0.6:
            return False
        
        if any(word in vuln.payload.lower() for word in ['test', 'example', 'sample', 'demo']):
            if vuln.confidence_score < 0.85:
                return False
        
        if vuln.response_status == 404 and not vuln.confirmed:
            return False
        
        return True
    
    def _get_remediation(self) -> str:
        return (
            "1. Implement strict allowlist-based URL validation for all user-supplied URLs. "
            "2. Disable unnecessary URL schemes (file://, gopher://, dict://, ftp://, ldap://). "
            "3. Use robust URL parsing libraries and validate all components separately. "
            "4. Block requests to private IP ranges (RFC1918) and metadata endpoints. "
            "5. Implement network segmentation to isolate internal services. "
            "6. Deploy WAF rules to detect and block SSRF attack patterns. "
            "7. Monitor and log all outbound connections from application servers. "
            "8. Use DNS allowlisting and disable DNS rebinding. "
            "9. Implement response validation to prevent data exfiltration. "
            "10. Apply principle of least privilege for service accounts."
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
