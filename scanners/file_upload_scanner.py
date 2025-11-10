from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import mimetypes
import hashlib


class FileUploadVulnerabilityType(Enum):
    UNRESTRICTED_FILE_UPLOAD = "unrestricted_file_upload"
    EXECUTABLE_UPLOAD = "executable_upload"
    ARCHIVE_BOMB = "archive_bomb"
    POLYGLOT_FILE = "polyglot_file"
    MIME_TYPE_BYPASS = "mime_type_bypass"
    EXTENSION_BYPASS = "extension_bypass"
    PATH_TRAVERSAL = "path_traversal"
    SYMLINK_ATTACK = "symlink_attack"
    ZIP_SLIP = "zip_slip"
    NULL_BYTE_INJECTION = "null_byte_injection"


class FileType(Enum):
    EXECUTABLE = "executable"
    SCRIPT = "script"
    ARCHIVE = "archive"
    IMAGE = "image"
    DOCUMENT = "document"
    MEDIA = "media"
    COMPRESSED = "compressed"
    POLYGLOT = "polyglot"
    UNKNOWN = "unknown"


class MalwareIndicator(Enum):
    EICAR = "eicar"
    WEBSHELL_PATTERN = "webshell_pattern"
    SUSPICIOUS_FUNCTION = "suspicious_function"
    OBFUSCATION = "obfuscation"
    MALICIOUS_MACRO = "malicious_macro"


@dataclass
class UploadedFile:
    filename: str
    mime_type: str
    file_size: int
    file_extension: str
    file_type: FileType
    upload_path: Optional[str] = None
    upload_timestamp: float = field(default_factory=time.time)
    content_hash: Optional[str] = None
    is_accessible: bool = False
    access_url: Optional[str] = None


@dataclass
class FileUploadVulnerability:
    vulnerability_type: str
    upload_type: FileUploadVulnerabilityType
    url: str
    file_parameter: str
    uploaded_filename: str
    file_type: FileType
    severity: str
    evidence: str
    file_size: int
    mime_type: str
    file_extension: str
    uploaded_to_webroot: bool = False
    file_accessible: bool = False
    file_access_url: Optional[str] = None
    dangerous_extension: bool = False
    mime_type_mismatch: bool = False
    polyglot_detected: bool = False
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class FileTypeValidator:
    DANGEROUS_EXTENSIONS = {
        'executable': [
            'exe', 'bat', 'cmd', 'com', 'scr', 'vbs', 'js', 'jar', 'zip',
            'msi', 'app', 'sh', 'bash', 'ksh', 'csh', 'zsh', 'py', 'rb', 'pl',
            'elf', 'bin', 'so', 'dll', 'sys', 'drv'
        ],
        'script': [
            'php', 'php3', 'php4', 'php5', 'phtml', 'phar',
            'jsp', 'jspx', 'jsw', 'jsv', 'jspf',
            'asp', 'asps', 'cer', 'asa', 'ashx', 'asmx',
            'cgi', 'fcgi', 'pl', 'pm',
            'py', 'pyw', 'pyc', 'pyo',
            'rb', 'rbw',
            'java', 'class', 'jar'
        ],
        'archive': [
            'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'iso'
        ],
    }
    
    SAFE_MIME_TYPES = {
        'image/jpeg': ['jpg', 'jpeg'],
        'image/png': ['png'],
        'image/gif': ['gif'],
        'image/webp': ['webp'],
        'application/pdf': ['pdf'],
        'text/plain': ['txt'],
    }
    
    @staticmethod
    def is_dangerous_extension(filename: str) -> Tuple[bool, Optional[str]]:
        extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        for category, extensions in FileTypeValidator.DANGEROUS_EXTENSIONS.items():
            if extension in extensions:
                return True, category
        
        return False, None
    
    @staticmethod
    def detect_double_extension(filename: str) -> Tuple[bool, List[str]]:
        parts = filename.rsplit('.', 2)
        if len(parts) >= 3:
            return True, parts[-2:]
        return False, []
    
    @staticmethod
    def detect_null_byte_injection(filename: str) -> bool:
        return '\x00' in filename
    
    @staticmethod
    def validate_mime_type(mime_type: str, filename: str) -> Tuple[bool, Optional[str]]:
        extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        for safe_mime, safe_extensions in FileTypeValidator.SAFE_MIME_TYPES.items():
            if mime_type == safe_mime and extension in safe_extensions:
                return True, None
        
        if mime_type.startswith('image/') and extension in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
            return True, None
        
        if mime_type.startswith('application/') and extension in ['pdf', 'doc', 'docx', 'xls', 'xlsx']:
            return True, None
        
        return False, f"MIME type {mime_type} doesn't match extension .{extension}"


class PolyglotFileDetector:
    FILE_SIGNATURES = {
        'php_html': {
            'pattern': rb'<\?php.*?<html',
            'indicators': ['<?php', '<html'],
            'polyglot_types': [FileType.SCRIPT, FileType.IMAGE]
        },
        'php_jpeg': {
            'pattern': rb'\xFF\xD8\xFF.*\?php',
            'indicators': ['JPEG header', '<?php'],
            'polyglot_types': [FileType.IMAGE, FileType.SCRIPT]
        },
        'php_gif': {
            'pattern': rb'GIF89a.*\?php|GIF87a.*\?php',
            'indicators': ['GIF header', '<?php'],
            'polyglot_types': [FileType.IMAGE, FileType.SCRIPT]
        },
        'php_png': {
            'pattern': rb'\x89PNG.*\?php',
            'indicators': ['PNG header', '<?php'],
            'polyglot_types': [FileType.IMAGE, FileType.SCRIPT]
        },
    }
    
    @staticmethod
    def detect_polyglot(file_content: bytes) -> Tuple[bool, List[str]]:
        detected_types = []
        
        for polyglot_type, config in PolyglotFileDetector.FILE_SIGNATURES.items():
            if re.search(config['pattern'], file_content):
                detected_types.append(polyglot_type)
        
        return len(detected_types) > 0, detected_types


class WebshellDetector:
    WEBSHELL_PATTERNS = {
        'php_webshell': [
            rb'eval\s*\(\s*\$_(GET|POST|REQUEST)',
            rb'system\s*\(\s*\$_(GET|POST|REQUEST)',
            rb'passthru\s*\(\s*\$_(GET|POST|REQUEST)',
            rb'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)',
            rb'exec\s*\(\s*\$_(GET|POST|REQUEST)',
        ],
        'asp_webshell': [
            rb'Request\.QueryString',
            rb'CreateObject\s*\(\s*["\']WScript\.Shell',
            rb'objShell\.Exec',
        ],
        'jsp_webshell': [
            rb'Runtime\.getRuntime\(\)\.exec',
            rb'request\.getParameter',
            rb'ProcessBuilder',
        ],
        'generic_patterns': [
            rb'(?i)(cmd|command|execute|shell|backdoor)',
            rb'(?i)base64_decode',
            rb'(?i)rot13',
            rb'(?i)preg_replace.*\/e',
        ]
    }
    
    @staticmethod
    def detect_webshell(file_content: bytes) -> Tuple[bool, List[str]]:
        detected_shells = []
        
        for shell_type, patterns in WebshellDetector.WEBSHELL_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, file_content):
                    detected_shells.append(shell_type)
                    break
        
        return len(detected_shells) > 0, detected_shells


class ArchiveBombDetector:
    @staticmethod
    def detect_archive_bomb(file_size: int, decompressed_estimate: int) -> Tuple[bool, float]:
        compression_ratio = decompressed_estimate / max(file_size, 1)
        
        if compression_ratio > 100:
            return True, min(compression_ratio / 1000, 1.0)
        
        return False, 0.0
    
    @staticmethod
    def detect_zip_slip(filename: str) -> bool:
        return '..' in filename or filename.startswith('/')


class FileAccessibilityChecker:
    WEB_ACCESSIBLE_PATHS = [
        '/uploads',
        '/files',
        '/download',
        '/media',
        '/public',
        '/static',
        '/assets',
        '/tmp',
    ]
    
    @staticmethod
    def is_web_accessible(upload_path: str) -> bool:
        for path in FileAccessibilityChecker.WEB_ACCESSIBLE_PATHS:
            if path in upload_path.lower():
                return True
        return False
    
    @staticmethod
    def construct_access_url(base_url: str, upload_path: str, filename: str) -> Optional[str]:
        if FileAccessibilityChecker.is_web_accessible(upload_path):
            return f"{base_url}/uploads/{filename}"
        return None


class MalwareSignatureDetector:
    EICAR_TEST_FILE = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    
    @staticmethod
    def detect_eicar(file_content: bytes) -> bool:
        return MalwareSignatureDetector.EICAR_TEST_FILE in file_content
    
    @staticmethod
    def detect_suspicious_functions(file_content: bytes, file_extension: str) -> List[str]:
        suspicious = []
        
        if file_extension in ['php', 'phtml', 'php3', 'php4', 'php5']:
            php_functions = [
                rb'eval\s*\(',
                rb'system\s*\(',
                rb'exec\s*\(',
                rb'passthru\s*\(',
                rb'shell_exec\s*\(',
                rb'proc_open\s*\(',
                rb'popen\s*\(',
            ]
            for func in php_functions:
                if re.search(func, file_content):
                    suspicious.append(func.decode('utf-8', errors='ignore'))
        
        elif file_extension in ['asp', 'aspx', 'cer', 'asa']:
            asp_functions = [
                rb'CreateObject.*WScript\.Shell',
                rb'Execute\s*\(',
                rb'Eval\s*\(',
            ]
            for func in asp_functions:
                if re.search(func, file_content):
                    suspicious.append(func.decode('utf-8', errors='ignore'))
        
        return suspicious
    
    @staticmethod
    def detect_obfuscation(file_content: bytes) -> Tuple[bool, List[str]]:
        obfuscation_indicators = []
        
        if re.search(rb'base64_decode\s*\(', file_content):
            obfuscation_indicators.append('Base64_encoding')
        
        if re.search(rb'str_rot13\s*\(', file_content):
            obfuscation_indicators.append('ROT13_encoding')
        
        if re.search(rb'gzcompress|gzdeflate|gzencode', file_content):
            obfuscation_indicators.append('Compression_encoding')
        
        if re.search(rb'preg_replace.*\/e', file_content):
            obfuscation_indicators.append('Regex_eval')
        
        hex_ratio = len(re.findall(rb'\\x[0-9a-f]{2}', file_content)) / max(len(file_content), 1)
        if hex_ratio > 0.3:
            obfuscation_indicators.append('Hex_encoding')
        
        return len(obfuscation_indicators) > 0, obfuscation_indicators


class FileUploadScanner:
    def __init__(self):
        self.type_validator = FileTypeValidator()
        self.polyglot_detector = PolyglotFileDetector()
        self.webshell_detector = WebshellDetector()
        self.archive_bomb_detector = ArchiveBombDetector()
        self.accessibility_checker = FileAccessibilityChecker()
        self.malware_detector = MalwareSignatureDetector()
        
        self.vulnerabilities: List[FileUploadVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.uploaded_files: Dict[str, UploadedFile] = {}
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, uploaded_file: Dict, response: Dict) -> List[FileUploadVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        filename = uploaded_file.get('filename', '')
        file_size = uploaded_file.get('file_size', 0)
        mime_type = uploaded_file.get('mime_type', '')
        file_content = uploaded_file.get('file_content', b'')
        file_parameter = uploaded_file.get('parameter', 'file')
        upload_path = uploaded_file.get('upload_path')
        
        extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        file_type = self._determine_file_type(filename, mime_type, file_content)
        
        is_dangerous, danger_category = self.type_validator.is_dangerous_extension(filename)
        if is_dangerous:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.EXECUTABLE_UPLOAD,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='Critical',
                evidence=f'Dangerous extension detected: .{extension} ({danger_category})',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                dangerous_extension=True,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['dangerous_extension'] += 1
        
        has_double_ext, double_exts = self.type_validator.detect_double_extension(filename)
        if has_double_ext:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.EXTENSION_BYPASS,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='High',
                evidence=f'Double extension detected: {".".join(double_exts)}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['double_extension'] += 1
        
        has_null_byte = self.type_validator.detect_null_byte_injection(filename)
        if has_null_byte:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.NULL_BYTE_INJECTION,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='High',
                evidence='Null byte detected in filename',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['null_byte'] += 1
        
        is_polyglot, polyglot_types = self.polyglot_detector.detect_polyglot(file_content)
        if is_polyglot:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.POLYGLOT_FILE,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='High',
                evidence=f'Polyglot file detected: {", ".join(polyglot_types)}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                polyglot_detected=True,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['polyglot_file'] += 1
        
        is_webshell, webshell_types = self.webshell_detector.detect_webshell(file_content)
        if is_webshell:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.EXECUTABLE_UPLOAD,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='Critical',
                evidence=f'Webshell detected: {", ".join(webshell_types)}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['webshell_detected'] += 1
        
        suspicious_funcs = self.malware_detector.detect_suspicious_functions(file_content, extension)
        if suspicious_funcs:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.EXECUTABLE_UPLOAD,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='High',
                evidence=f'Suspicious functions detected: {", ".join(suspicious_funcs[:3])}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['suspicious_functions'] += 1
        
        is_obfuscated, obfuscation_types = self.malware_detector.detect_obfuscation(file_content)
        if is_obfuscated:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.EXECUTABLE_UPLOAD,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='Medium',
                evidence=f'Code obfuscation detected: {", ".join(obfuscation_types)}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['obfuscation'] += 1
        
        is_zip_slip = self.archive_bomb_detector.detect_zip_slip(filename)
        if is_zip_slip:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.ZIP_SLIP,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='High',
                evidence='Path traversal detected in archive filename',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                confirmed=True,
                remediation=self._get_remediation()
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['zip_slip'] += 1
        
        if upload_path:
            is_accessible = self.accessibility_checker.is_web_accessible(upload_path)
            if is_accessible:
                access_url = self.accessibility_checker.construct_access_url(target_url, upload_path, filename)
                vuln = FileUploadVulnerability(
                    vulnerability_type='File Upload Vulnerability',
                    upload_type=FileUploadVulnerabilityType.UNRESTRICTED_FILE_UPLOAD,
                    url=target_url,
                    file_parameter=file_parameter,
                    uploaded_filename=filename,
                    file_type=file_type,
                    severity='High' if not is_dangerous else 'Critical',
                    evidence=f'File uploaded to web-accessible path: {upload_path}',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    uploaded_to_webroot=True,
                    file_accessible=True,
                    file_access_url=access_url,
                    confirmed=True,
                    remediation=self._get_remediation()
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['web_accessible'] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
            uploaded_file_obj = UploadedFile(
                filename=filename,
                mime_type=mime_type,
                file_size=file_size,
                file_extension=extension,
                file_type=file_type,
                upload_path=upload_path,
                is_accessible=any(v.file_accessible for v in vulnerabilities)
            )
            self.uploaded_files[filename] = uploaded_file_obj
        
        return vulnerabilities
    
    def _determine_file_type(self, filename: str, mime_type: str, file_content: bytes) -> FileType:
        extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        if extension in FileTypeValidator.DANGEROUS_EXTENSIONS['executable']:
            return FileType.EXECUTABLE
        elif extension in FileTypeValidator.DANGEROUS_EXTENSIONS['script']:
            return FileType.SCRIPT
        elif extension in FileTypeValidator.DANGEROUS_EXTENSIONS['archive']:
            return FileType.ARCHIVE
        elif mime_type.startswith('image/'):
            return FileType.IMAGE
        elif mime_type.startswith('audio/') or mime_type.startswith('video/'):
            return FileType.MEDIA
        elif mime_type == 'application/pdf':
            return FileType.DOCUMENT
        
        return FileType.UNKNOWN
    
    def _get_remediation(self) -> str:
        return (
            "Implement strict file upload validation. "
            "Validate file extension against allowlist. "
            "Check MIME type server-side. "
            "Verify file content/magic bytes. "
            "Store uploads outside web root. "
            "Disable script execution in upload directory. "
            "Use random filenames for uploaded files. "
            "Implement antivirus scanning. "
            "Set proper file permissions. "
            "Implement file size limits. "
            "Use content disposition headers."
        )
    
    def get_vulnerabilities(self) -> List[FileUploadVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.uploaded_files.clear()