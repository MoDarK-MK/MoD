from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import mimetypes
import hashlib
import math


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
    DOUBLE_EXTENSION = "double_extension"
    HTACCESS_UPLOAD = "htaccess_upload"
    SVG_XSS = "svg_xss"


class FileType(Enum):
    EXECUTABLE = "executable"
    SCRIPT = "script"
    ARCHIVE = "archive"
    IMAGE = "image"
    DOCUMENT = "document"
    MEDIA = "media"
    COMPRESSED = "compressed"
    POLYGLOT = "polyglot"
    CONFIG = "config"
    UNKNOWN = "unknown"


class MalwareIndicator(Enum):
    EICAR = "eicar"
    WEBSHELL_PATTERN = "webshell_pattern"
    SUSPICIOUS_FUNCTION = "suspicious_function"
    OBFUSCATION = "obfuscation"
    MALICIOUS_MACRO = "malicious_macro"
    REVERSE_SHELL = "reverse_shell"
    BACKDOOR = "backdoor"


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
    sha256_hash: Optional[str] = None
    is_accessible: bool = False
    access_url: Optional[str] = None
    malware_indicators: List[MalwareIndicator] = field(default_factory=list)
    entropy_score: float = 0.0


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
    webshell_detected: bool = False
    malware_indicators: List[str] = field(default_factory=list)
    obfuscation_techniques: List[str] = field(default_factory=list)
    suspicious_functions: List[str] = field(default_factory=list)
    file_hash: Optional[str] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class FileTypeValidator:
    DANGEROUS_EXTENSIONS = {
        'executable': frozenset([
            'exe', 'bat', 'cmd', 'com', 'scr', 'vbs', 'js', 'jar',
            'msi', 'app', 'sh', 'bash', 'ksh', 'csh', 'zsh', 'py', 'rb', 'pl',
            'elf', 'bin', 'so', 'dll', 'sys', 'drv', 'pif', 'gadget'
        ]),
        'script': frozenset([
            'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'phps', 'php5s',
            'jsp', 'jspx', 'jsw', 'jsv', 'jspf',
            'asp', 'aspx', 'cer', 'asa', 'ashx', 'asmx', 'cdx',
            'cgi', 'fcgi', 'pl', 'pm', 'cgi',
            'py', 'pyw', 'pyc', 'pyo', 'pyd',
            'rb', 'rbw', 'erb',
            'java', 'class', 'jar', 'war'
        ]),
        'archive': frozenset([
            'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'iso',
            'lz', 'lzma', 'z', 'cab', 'arj', 'ace'
        ]),
        'config': frozenset([
            'htaccess', 'htpasswd', 'ini', 'conf', 'config', 'cfg'
        ]),
    }
    
    SAFE_MIME_TYPES = {
        'image/jpeg': frozenset(['jpg', 'jpeg', 'jpe']),
        'image/png': frozenset(['png']),
        'image/gif': frozenset(['gif']),
        'image/webp': frozenset(['webp']),
        'image/bmp': frozenset(['bmp']),
        'image/tiff': frozenset(['tiff', 'tif']),
        'application/pdf': frozenset(['pdf']),
        'text/plain': frozenset(['txt']),
        'text/csv': frozenset(['csv']),
    }
    
    MAGIC_BYTES = {
        'jpeg': [b'\xFF\xD8\xFF'],
        'png': [b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'],
        'gif': [b'GIF87a', b'GIF89a'],
        'pdf': [b'%PDF-'],
        'zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
        'rar': [b'Rar!\x1A\x07'],
        '7z': [b'7z\xBC\xAF\x27\x1C'],
        'elf': [b'\x7FELF'],
        'pe': [b'MZ'],
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
        parts = filename.split('.')
        if len(parts) >= 3:
            extensions = parts[-2:]
            
            if any(ext in FileTypeValidator.DANGEROUS_EXTENSIONS['script'] for ext in extensions):
                return True, extensions
        
        return False, []
    
    @staticmethod
    def detect_null_byte_injection(filename: str) -> bool:
        return '\x00' in filename or '%00' in filename
    
    @staticmethod
    def validate_mime_type(mime_type: str, filename: str) -> Tuple[bool, Optional[str]]:
        extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        for safe_mime, safe_extensions in FileTypeValidator.SAFE_MIME_TYPES.items():
            if mime_type == safe_mime:
                if extension in safe_extensions:
                    return True, None
                else:
                    return False, f"Extension .{extension} doesn't match MIME type {mime_type}"
        
        if mime_type.startswith('image/') and extension in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp']:
            return True, None
        
        if mime_type.startswith('application/') and extension in ['pdf', 'doc', 'docx', 'xls', 'xlsx']:
            return True, None
        
        return False, f"MIME type {mime_type} doesn't match extension .{extension}"
    
    @staticmethod
    def verify_magic_bytes(file_content: bytes, claimed_type: str) -> Tuple[bool, Optional[str]]:
        if not file_content or len(file_content) < 8:
            return False, "File too small to verify"
        
        for file_type, magic_list in FileTypeValidator.MAGIC_BYTES.items():
            for magic in magic_list:
                if file_content.startswith(magic):
                    if file_type == claimed_type:
                        return True, None
                    else:
                        return False, f"Magic bytes indicate {file_type}, not {claimed_type}"
        
        return False, "Unknown or invalid magic bytes"
    
    @staticmethod
    def detect_case_manipulation(filename: str) -> bool:
        extension = filename.rsplit('.', 1)[-1] if '.' in filename else ''
        
        if extension != extension.lower() and extension != extension.upper():
            return True
        
        return False


class PolyglotFileDetector:
    FILE_SIGNATURES = {
        'php_html': {
            'pattern': re.compile(rb'<\?php.*?<html', re.DOTALL),
            'indicators': ['<?php', '<html'],
            'polyglot_types': [FileType.SCRIPT, FileType.IMAGE]
        },
        'php_jpeg': {
            'pattern': re.compile(rb'\xFF\xD8\xFF.*?\?php', re.DOTALL),
            'indicators': ['JPEG header', '<?php'],
            'polyglot_types': [FileType.IMAGE, FileType.SCRIPT]
        },
        'php_gif': {
            'pattern': re.compile(rb'GIF8[79]a.*?\?php', re.DOTALL),
            'indicators': ['GIF header', '<?php'],
            'polyglot_types': [FileType.IMAGE, FileType.SCRIPT]
        },
        'php_png': {
            'pattern': re.compile(rb'\x89PNG.*?\?php', re.DOTALL),
            'indicators': ['PNG header', '<?php'],
            'polyglot_types': [FileType.IMAGE, FileType.SCRIPT]
        },
        'jsp_jpeg': {
            'pattern': re.compile(rb'\xFF\xD8\xFF.*?<%@', re.DOTALL),
            'indicators': ['JPEG header', '<%@'],
            'polyglot_types': [FileType.IMAGE, FileType.SCRIPT]
        },
        'asp_jpeg': {
            'pattern': re.compile(rb'\xFF\xD8\xFF.*?<%', re.DOTALL),
            'indicators': ['JPEG header', '<%'],
            'polyglot_types': [FileType.IMAGE, FileType.SCRIPT]
        },
    }
    
    @staticmethod
    def detect_polyglot(file_content: bytes) -> Tuple[bool, List[str]]:
        detected_types = []
        
        for polyglot_type, config in PolyglotFileDetector.FILE_SIGNATURES.items():
            if config['pattern'].search(file_content):
                detected_types.append(polyglot_type)
        
        return len(detected_types) > 0, detected_types
    
    @staticmethod
    def detect_svg_xss(file_content: bytes) -> Tuple[bool, List[str]]:
        xss_patterns = [
            rb'<script[^>]*>',
            rb'javascript:',
            rb'on\w+\s*=',
            rb'<iframe[^>]*>',
            rb'eval\s*\(',
        ]
        
        detected = []
        for pattern in xss_patterns:
            if re.search(pattern, file_content, re.I):
                detected.append(pattern.decode('utf-8', errors='ignore'))
        
        return len(detected) > 0, detected


class WebshellDetector:
    WEBSHELL_PATTERNS = {
        'php_webshell': [
            re.compile(rb'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)', re.I),
            re.compile(rb'system\s*\(\s*\$_(GET|POST|REQUEST)', re.I),
            re.compile(rb'passthru\s*\(\s*\$_(GET|POST|REQUEST)', re.I),
            re.compile(rb'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)', re.I),
            re.compile(rb'exec\s*\(\s*\$_(GET|POST|REQUEST)', re.I),
            re.compile(rb'proc_open\s*\(\s*\$_(GET|POST)', re.I),
            re.compile(rb'popen\s*\(\s*\$_(GET|POST)', re.I),
            re.compile(rb'assert\s*\(\s*\$_(GET|POST|REQUEST)', re.I),
        ],
        'asp_webshell': [
            re.compile(rb'Request\.QueryString', re.I),
            re.compile(rb'CreateObject\s*\(\s*["\']WScript\.Shell', re.I),
            re.compile(rb'objShell\.Exec', re.I),
            re.compile(rb'Response\.Write\s*\(\s*Request', re.I),
            re.compile(rb'Server\.CreateObject.*WScript\.Shell', re.I),
        ],
        'jsp_webshell': [
            re.compile(rb'Runtime\.getRuntime\(\)\.exec', re.I),
            re.compile(rb'request\.getParameter', re.I),
            re.compile(rb'ProcessBuilder', re.I),
            re.compile(rb'java\.lang\.Runtime', re.I),
        ],
        'python_webshell': [
            re.compile(rb'os\.system\s*\(', re.I),
            re.compile(rb'subprocess\.call\s*\(', re.I),
            re.compile(rb'subprocess\.Popen\s*\(', re.I),
            re.compile(rb'eval\s*\(\s*request', re.I),
        ],
        'generic_patterns': [
            re.compile(rb'(?i)(cmd|command|execute|shell|backdoor|c99|r57|b374k)'),
            re.compile(rb'(?i)base64_decode.*eval', re.DOTALL),
            re.compile(rb'(?i)rot13.*eval', re.DOTALL),
            re.compile(rb'(?i)preg_replace.*\/e', re.I),
            re.compile(rb'(?i)assert.*\$_(GET|POST|REQUEST)', re.I),
        ]
    }
    
    @staticmethod
    def detect_webshell(file_content: bytes) -> Tuple[bool, List[str]]:
        detected_shells = []
        
        for shell_type, patterns in WebshellDetector.WEBSHELL_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(file_content):
                    detected_shells.append(shell_type)
                    break
        
        return len(detected_shells) > 0, list(set(detected_shells))
    
    @staticmethod
    def detect_reverse_shell(file_content: bytes) -> Tuple[bool, List[str]]:
        reverse_shell_patterns = [
            rb'fsockopen\s*\(',
            rb'socket_create\s*\(',
            rb'stream_socket_client\s*\(',
            rb'nc\s+-e\s+',
            rb'bash\s+-i\s+>&\s+',
            rb'/dev/tcp/',
        ]
        
        detected = []
        for pattern in reverse_shell_patterns:
            if re.search(pattern, file_content, re.I):
                detected.append(pattern.decode('utf-8', errors='ignore'))
        
        return len(detected) > 0, detected


class ArchiveBombDetector:
    @staticmethod
    def detect_archive_bomb(file_size: int, decompressed_estimate: int) -> Tuple[bool, float]:
        if file_size == 0:
            return False, 0.0
        
        compression_ratio = decompressed_estimate / file_size
        
        if compression_ratio > 1000:
            return True, min(compression_ratio / 10000, 1.0)
        elif compression_ratio > 100:
            return True, min(compression_ratio / 1000, 0.8)
        
        return False, 0.0
    
    @staticmethod
    def detect_zip_slip(filename: str) -> Tuple[bool, str]:
        if '..' in filename:
            return True, "Parent directory traversal (..)"
        
        if filename.startswith('/'):
            return True, "Absolute path"
        
        if filename.startswith('\\'):
            return True, "Windows absolute path"
        
        if re.search(r'[<>:"|?*]', filename):
            return True, "Invalid filename characters"
        
        return False, ""
    
    @staticmethod
    def detect_nested_archives(file_content: bytes) -> Tuple[bool, int]:
        archive_signatures = [b'PK\x03\x04', b'Rar!', b'7z\xBC\xAF\x27\x1C']
        
        nested_count = 0
        for signature in archive_signatures:
            nested_count += file_content.count(signature)
        
        return nested_count > 2, nested_count


class FileAccessibilityChecker:
    WEB_ACCESSIBLE_PATHS = frozenset([
        '/uploads', '/files', '/download', '/media', '/public', '/static',
        '/assets', '/tmp', '/temp', '/images', '/pictures', '/documents',
        '/data', '/content', '/resources', '/user', '/users'
    ])
    
    @staticmethod
    def is_web_accessible(upload_path: str) -> bool:
        upload_path_lower = upload_path.lower()
        return any(path in upload_path_lower for path in FileAccessibilityChecker.WEB_ACCESSIBLE_PATHS)
    
    @staticmethod
    def construct_access_url(base_url: str, upload_path: str, filename: str) -> Optional[str]:
        if FileAccessibilityChecker.is_web_accessible(upload_path):
            clean_path = upload_path.strip('/').split('/')[-1]
            return f"{base_url.rstrip('/')}/{clean_path}/{filename}"
        return None
    
    @staticmethod
    def detect_htaccess_upload(filename: str, file_content: bytes) -> Tuple[bool, List[str]]:
        if filename.lower() in ['.htaccess', 'htaccess', '.htpasswd']:
            return True, ['Configuration file upload']
        
        htaccess_directives = [
            rb'AddHandler',
            rb'SetHandler',
            rb'php_value',
            rb'php_flag',
            rb'Options\s+\+ExecCGI',
        ]
        
        detected = []
        for directive in htaccess_directives:
            if re.search(directive, file_content, re.I):
                detected.append(directive.decode('utf-8', errors='ignore'))
        
        return len(detected) > 0, detected


class MalwareSignatureDetector:
    EICAR_TEST_FILE = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    
    @staticmethod
    def detect_eicar(file_content: bytes) -> bool:
        return MalwareSignatureDetector.EICAR_TEST_FILE in file_content
    
    @staticmethod
    def detect_suspicious_functions(file_content: bytes, file_extension: str) -> List[str]:
        suspicious = []
        
        function_patterns = {
            'php': [
                rb'eval\s*\(', rb'system\s*\(', rb'exec\s*\(', rb'passthru\s*\(',
                rb'shell_exec\s*\(', rb'proc_open\s*\(', rb'popen\s*\(',
                rb'pcntl_exec\s*\(', rb'assert\s*\(', rb'create_function\s*\(',
                rb'preg_replace.*\/e', rb'call_user_func\s*\(',
            ],
            'asp': [
                rb'CreateObject.*WScript\.Shell', rb'Execute\s*\(', rb'Eval\s*\(',
                rb'Server\.Execute', rb'Response\.Write.*Request',
            ],
            'jsp': [
                rb'Runtime\.getRuntime\(\)\.exec', rb'ProcessBuilder',
                rb'java\.lang\.Runtime', rb'ScriptEngine',
            ],
            'python': [
                rb'os\.system', rb'subprocess\.call', rb'subprocess\.Popen',
                rb'eval\s*\(', rb'exec\s*\(', rb'__import__',
            ]
        }
        
        ext_category = None
        if file_extension in ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar']:
            ext_category = 'php'
        elif file_extension in ['asp', 'aspx', 'cer', 'asa']:
            ext_category = 'asp'
        elif file_extension in ['jsp', 'jspx']:
            ext_category = 'jsp'
        elif file_extension in ['py', 'pyw']:
            ext_category = 'python'
        
        if ext_category and ext_category in function_patterns:
            for func_pattern in function_patterns[ext_category]:
                if re.search(func_pattern, file_content, re.I):
                    suspicious.append(func_pattern.decode('utf-8', errors='ignore'))
        
        return suspicious
    
    @staticmethod
    def detect_obfuscation(file_content: bytes) -> Tuple[bool, List[str]]:
        obfuscation_indicators = []
        
        obfuscation_patterns = {
            'base64': rb'base64_decode\s*\(',
            'rot13': rb'str_rot13\s*\(',
            'gzinflate': rb'gzinflate\s*\(',
            'gzuncompress': rb'gzuncompress\s*\(',
            'gzdecode': rb'gzdecode\s*\(',
            'hex2bin': rb'hex2bin\s*\(',
            'chr': rb'chr\s*\(\s*\d+\s*\)',
            'eval_base64': rb'eval\s*\(\s*base64_decode',
        }
        
        for obf_type, pattern in obfuscation_patterns.items():
            if re.search(pattern, file_content, re.I):
                obfuscation_indicators.append(obf_type)
        
        hex_ratio = len(re.findall(rb'\\x[0-9a-fA-F]{2}', file_content)) / max(len(file_content), 1)
        if hex_ratio > 0.3:
            obfuscation_indicators.append('high_hex_encoding')
        
        octal_ratio = len(re.findall(rb'\\[0-7]{3}', file_content)) / max(len(file_content), 1)
        if octal_ratio > 0.2:
            obfuscation_indicators.append('high_octal_encoding')
        
        return len(obfuscation_indicators) > 0, obfuscation_indicators
    
    @staticmethod
    def calculate_entropy(file_content: bytes) -> float:
        if not file_content:
            return 0.0
        
        frequencies = defaultdict(int)
        for byte in file_content:
            frequencies[byte] += 1
        
        entropy = 0.0
        length = len(file_content)
        
        for count in frequencies.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy


class FileUploadScanner:
    _remediation_cache = (
        "Implement strict file upload validation with allowlist approach. "
        "Validate file extension against allowlist only. "
        "Check MIME type server-side and verify magic bytes. "
        "Store all uploads outside web root directory. "
        "Disable script execution in upload directory (.htaccess). "
        "Use random filenames with UUID for uploaded files. "
        "Implement antivirus/malware scanning on upload. "
        "Set restrictive file permissions (644 for files). "
        "Implement strict file size limits. "
        "Use Content-Disposition header for downloads. "
        "Validate file content, not just extension. "
        "Scan for polyglot files and webshells. "
        "Strip metadata from uploaded files. "
        "Implement rate limiting on uploads."
    )
    
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
        self.file_hashes: Set[str] = set()
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
        upload_path = uploaded_file.get('upload_path', '')
        
        extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        file_type = self._determine_file_type(filename, mime_type, file_content)
        
        file_hash = hashlib.sha256(file_content).hexdigest() if file_content else None
        entropy_score = self.malware_detector.calculate_entropy(file_content)
        
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
                evidence=f'Dangerous extension: .{extension} (category: {danger_category})',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                dangerous_extension=True,
                file_hash=file_hash,
                confirmed=True,
                confidence_score=0.95,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['dangerous_extension'] += 1
        
        has_double_ext, double_exts = self.type_validator.detect_double_extension(filename)
        if has_double_ext:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.DOUBLE_EXTENSION,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='High',
                evidence=f'Double extension bypass: {".".join(double_exts)}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                file_hash=file_hash,
                confirmed=True,
                confidence_score=0.9,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['double_extension'] += 1
        
        if self.type_validator.detect_case_manipulation(filename):
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.EXTENSION_BYPASS,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='Medium',
                evidence=f'Case manipulation in extension: {filename.rsplit(".", 1)[-1]}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                file_hash=file_hash,
                confirmed=True,
                confidence_score=0.75,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['case_manipulation'] += 1
        
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
                evidence='Null byte injection in filename',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                file_hash=file_hash,
                confirmed=True,
                confidence_score=0.95,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['null_byte'] += 1
        
        mime_valid, mime_error = self.type_validator.validate_mime_type(mime_type, filename)
        if not mime_valid and mime_error:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.MIME_TYPE_BYPASS,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='Medium',
                evidence=f'MIME type mismatch: {mime_error}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                mime_type_mismatch=True,
                file_hash=file_hash,
                confirmed=True,
                confidence_score=0.7,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['mime_mismatch'] += 1
        
        if file_content:
            magic_valid, magic_error = self.type_validator.verify_magic_bytes(file_content, extension)
            if not magic_valid and magic_error:
                vuln = FileUploadVulnerability(
                    vulnerability_type='File Upload Vulnerability',
                    upload_type=FileUploadVulnerabilityType.MIME_TYPE_BYPASS,
                    url=target_url,
                    file_parameter=file_parameter,
                    uploaded_filename=filename,
                    file_type=file_type,
                    severity='High',
                    evidence=f'Magic bytes verification failed: {magic_error}',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    file_hash=file_hash,
                    confirmed=True,
                    confidence_score=0.85,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['magic_bytes_mismatch'] += 1
        
        if file_content:
            is_polyglot, polyglot_types = self.polyglot_detector.detect_polyglot(file_content)
            if is_polyglot:
                vuln = FileUploadVulnerability(
                    vulnerability_type='File Upload Vulnerability',
                    upload_type=FileUploadVulnerabilityType.POLYGLOT_FILE,
                    url=target_url,
                    file_parameter=file_parameter,
                    uploaded_filename=filename,
                    file_type=file_type,
                    severity='Critical',
                    evidence=f'Polyglot file detected: {", ".join(polyglot_types)}',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    polyglot_detected=True,
                    file_hash=file_hash,
                    confirmed=True,
                    confidence_score=0.95,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['polyglot_file'] += 1
            
            if extension == 'svg':
                is_svg_xss, xss_patterns = self.polyglot_detector.detect_svg_xss(file_content)
                if is_svg_xss:
                    vuln = FileUploadVulnerability(
                        vulnerability_type='File Upload Vulnerability',
                        upload_type=FileUploadVulnerabilityType.SVG_XSS,
                        url=target_url,
                        file_parameter=file_parameter,
                        uploaded_filename=filename,
                        file_type=file_type,
                        severity='High',
                        evidence=f'SVG XSS vectors detected: {", ".join(xss_patterns[:3])}',
                        file_size=file_size,
                        mime_type=mime_type,
                        file_extension=extension,
                        file_hash=file_hash,
                        confirmed=True,
                        confidence_score=0.9,
                        remediation=self._remediation_cache
                    )
                    vulnerabilities.append(vuln)
                    self.scan_statistics['svg_xss'] += 1
        
        if file_content:
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
                    evidence=f'Webshell detected: {", ".join(webshell_types)} | Entropy: {entropy_score:.2f}',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    webshell_detected=True,
                    malware_indicators=webshell_types,
                    file_hash=file_hash,
                    confirmed=True,
                    confidence_score=0.98,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['webshell_detected'] += 1
            
            is_reverse_shell, reverse_patterns = self.webshell_detector.detect_reverse_shell(file_content)
            if is_reverse_shell:
                vuln = FileUploadVulnerability(
                    vulnerability_type='File Upload Vulnerability',
                    upload_type=FileUploadVulnerabilityType.EXECUTABLE_UPLOAD,
                    url=target_url,
                    file_parameter=file_parameter,
                    uploaded_filename=filename,
                    file_type=file_type,
                    severity='Critical',
                    evidence=f'Reverse shell detected: {", ".join(reverse_patterns[:3])}',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    file_hash=file_hash,
                    confirmed=True,
                    confidence_score=0.95,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['reverse_shell'] += 1
        
        if file_content:
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
                    evidence=f'Suspicious functions: {", ".join(suspicious_funcs[:5])}',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    suspicious_functions=suspicious_funcs,
                    file_hash=file_hash,
                    confirmed=True,
                    confidence_score=0.8,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['suspicious_functions'] += 1
        
        if file_content:
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
                    evidence=f'Code obfuscation: {", ".join(obfuscation_types)}',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    obfuscation_techniques=obfuscation_types,
                    file_hash=file_hash,
                    confirmed=True,
                    confidence_score=0.75,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['obfuscation'] += 1
        
        if file_content:
            if self.malware_detector.detect_eicar(file_content):
                vuln = FileUploadVulnerability(
                    vulnerability_type='File Upload Vulnerability',
                    upload_type=FileUploadVulnerabilityType.EXECUTABLE_UPLOAD,
                    url=target_url,
                    file_parameter=file_parameter,
                    uploaded_filename=filename,
                    file_type=file_type,
                    severity='Critical',
                    evidence='EICAR test file detected',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    file_hash=file_hash,
                    confirmed=True,
                    confidence_score=1.0,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['eicar_detected'] += 1
        
        is_zip_slip, zip_slip_reason = self.archive_bomb_detector.detect_zip_slip(filename)
        if is_zip_slip:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.ZIP_SLIP,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=file_type,
                severity='High',
                evidence=f'Path traversal: {zip_slip_reason}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                file_hash=file_hash,
                confirmed=True,
                confidence_score=0.9,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['zip_slip'] += 1
        
        if file_content and extension in ['zip', 'rar', '7z', 'tar', 'gz']:
            is_nested, nest_count = self.archive_bomb_detector.detect_nested_archives(file_content)
            if is_nested:
                vuln = FileUploadVulnerability(
                    vulnerability_type='File Upload Vulnerability',
                    upload_type=FileUploadVulnerabilityType.ARCHIVE_BOMB,
                    url=target_url,
                    file_parameter=file_parameter,
                    uploaded_filename=filename,
                    file_type=file_type,
                    severity='Medium',
                    evidence=f'Nested archives detected: {nest_count} levels',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    file_hash=file_hash,
                    confirmed=True,
                    confidence_score=0.7,
                    remediation=self._remediation_cache
                )
                vulnerabilities.append(vuln)
                self.scan_statistics['nested_archive'] += 1
        
        is_htaccess, htaccess_directives = self.accessibility_checker.detect_htaccess_upload(filename, file_content)
        if is_htaccess:
            vuln = FileUploadVulnerability(
                vulnerability_type='File Upload Vulnerability',
                upload_type=FileUploadVulnerabilityType.HTACCESS_UPLOAD,
                url=target_url,
                file_parameter=file_parameter,
                uploaded_filename=filename,
                file_type=FileType.CONFIG,
                severity='Critical',
                evidence=f'Configuration file upload: {", ".join(htaccess_directives[:3])}',
                file_size=file_size,
                mime_type=mime_type,
                file_extension=extension,
                file_hash=file_hash,
                confirmed=True,
                confidence_score=1.0,
                remediation=self._remediation_cache
            )
            vulnerabilities.append(vuln)
            self.scan_statistics['htaccess_upload'] += 1
        
        if upload_path:
            is_accessible = self.accessibility_checker.is_web_accessible(upload_path)
            if is_accessible:
                access_url = self.accessibility_checker.construct_access_url(target_url, upload_path, filename)
                
                severity = 'Critical' if (is_dangerous or is_webshell) else 'High'
                
                vuln = FileUploadVulnerability(
                    vulnerability_type='File Upload Vulnerability',
                    upload_type=FileUploadVulnerabilityType.UNRESTRICTED_FILE_UPLOAD,
                    url=target_url,
                    file_parameter=file_parameter,
                    uploaded_filename=filename,
                    file_type=file_type,
                    severity=severity,
                    evidence=f'File in web-accessible path: {upload_path} | Access URL: {access_url}',
                    file_size=file_size,
                    mime_type=mime_type,
                    file_extension=extension,
                    uploaded_to_webroot=True,
                    file_accessible=True,
                    file_access_url=access_url,
                    file_hash=file_hash,
                    confirmed=True,
                    confidence_score=0.95,
                    remediation=self._remediation_cache
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
                content_hash=file_hash,
                sha256_hash=file_hash,
                is_accessible=any(v.file_accessible for v in vulnerabilities),
                entropy_score=entropy_score,
                malware_indicators=[MalwareIndicator.WEBSHELL_PATTERN] if is_webshell else []
            )
            self.uploaded_files[filename] = uploaded_file_obj
            
            if file_hash:
                self.file_hashes.add(file_hash)
            
            self.scan_statistics['total_files_scanned'] += 1
        
        return vulnerabilities
    
    def _determine_file_type(self, filename: str, mime_type: str, file_content: bytes) -> FileType:
        extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        if extension in FileTypeValidator.DANGEROUS_EXTENSIONS['executable']:
            return FileType.EXECUTABLE
        elif extension in FileTypeValidator.DANGEROUS_EXTENSIONS['script']:
            return FileType.SCRIPT
        elif extension in FileTypeValidator.DANGEROUS_EXTENSIONS['archive']:
            return FileType.ARCHIVE
        elif extension in FileTypeValidator.DANGEROUS_EXTENSIONS['config']:
            return FileType.CONFIG
        elif mime_type.startswith('image/'):
            return FileType.IMAGE
        elif mime_type.startswith('audio/') or mime_type.startswith('video/'):
            return FileType.MEDIA
        elif mime_type == 'application/pdf' or extension in ['pdf', 'doc', 'docx']:
            return FileType.DOCUMENT
        
        return FileType.UNKNOWN
    
    def get_vulnerabilities(self) -> List[FileUploadVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def get_uploaded_files(self) -> Dict[str, UploadedFile]:
        with self.lock:
            return self.uploaded_files.copy()
    
    def get_file_hashes(self) -> Set[str]:
        with self.lock:
            return self.file_hashes.copy()
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.uploaded_files.clear()
            self.file_hashes.clear()