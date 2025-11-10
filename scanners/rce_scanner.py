from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time


class RCEType(Enum):
    COMMAND_EXECUTION = "command_execution"
    CODE_INJECTION = "code_injection"
    TEMPLATE_INJECTION = "template_injection"
    DESERIALIZATION = "deserialization"
    FILE_INCLUSION = "file_inclusion"
    XXE_INJECTION = "xxe_injection"
    LDAP_INJECTION = "ldap_injection"
    OS_COMMAND_INJECTION = "os_command_injection"


class ExecutionContext(Enum):
    SHELL_COMMAND = "shell_command"
    PYTHON_CODE = "python_code"
    PHP_CODE = "php_code"
    JAVA_CODE = "java_code"
    NODEJS_CODE = "nodejs_code"
    RUBY_CODE = "ruby_code"
    PERL_CODE = "perl_code"
    ASP_CODE = "asp_code"


class CommandSeparator(Enum):
    SEMICOLON = ";"
    PIPE = "|"
    PIPE_PIPE = "||"
    AND = "&"
    AND_AND = "&&"
    NEWLINE = "\n"
    BACKTICK = "`"
    DOLLAR_PAREN = "$("
    COMMAND_SUBSTITUTION = "`cmd`"


@dataclass
class RCEPayload:
    payload: str
    rce_type: RCEType
    execution_context: ExecutionContext
    command_separator: Optional[CommandSeparator] = None
    severity: str = "Critical"
    detection_indicators: List[str] = field(default_factory=list)
    requires_confirmation: bool = True
    false_positive_risk: float = 0.1


@dataclass
class RCEVulnerability:
    vulnerability_type: str
    rce_type: RCEType
    execution_context: Optional[ExecutionContext]
    url: str
    parameter: str
    payload: str
    severity: str
    evidence: str
    response_time: float
    output_captured: bool
    command_output: Optional[str] = None
    system_info: Optional[Dict] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class SystemOutputAnalyzer:
    UNIX_COMMANDS_OUTPUT = {
        'ls': {
            'pattern': r'^(?:[-d])([-r]){9}',
            'indicators': ['drwx', '-rw-', 'total'],
        },
        'id': {
            'pattern': r'uid=\d+.*gid=\d+',
            'indicators': ['uid=', 'gid=', 'groups='],
        },
        'whoami': {
            'pattern': r'^[a-zA-Z0-9_-]+$',
            'indicators': ['root', 'admin', 'www-data', 'nobody'],
        },
        'pwd': {
            'pattern': r'^/[\w/.-]*$',
            'indicators': ['/', 'home', 'var', 'tmp'],
        },
        'uname': {
            'pattern': r'(?i)(linux|unix|darwin|freebsd)',
            'indicators': ['Linux', 'Unix', 'Darwin'],
        },
        'cat': {
            'pattern': r'root:.*:/bin/.*',
            'indicators': ['root:', 'bin/bash', 'bin/sh'],
        },
    }
    
    @staticmethod
    def analyze_output(response_content: str) -> Tuple[bool, List[str], List[str]]:
        found_indicators = []
        matched_commands = []
        
        for command, config in SystemOutputAnalyzer.UNIX_COMMANDS_OUTPUT.items():
            pattern = config['pattern']
            indicators = config['indicators']
            
            if re.search(pattern, response_content, re.MULTILINE):
                matched_commands.append(command)
                
                for indicator in indicators:
                    if indicator in response_content:
                        found_indicators.append(indicator)
        
        is_command_output = len(matched_commands) > 0
        return is_command_output, matched_commands, found_indicators


class DirectoryListingDetector:
    UNIX_DIR_PATTERNS = [
        r'total\s+\d+',
        r'^([-d])([-r]){9}\s+\d+\s+\w+\s+\w+\s+\d+',
        r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}',
    ]
    
    WINDOWS_DIR_PATTERNS = [
        r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}',
        r'<DIR>|[0-9,]+ bytes',
        r'[A-Z]:\\[\w\\]+',
    ]
    
    @staticmethod
    def detect_directory_listing(response_content: str) -> Tuple[bool, Optional[str], List[str]]:
        unix_matches = []
        for pattern in DirectoryListingDetector.UNIX_DIR_PATTERNS:
            if re.search(pattern, response_content, re.MULTILINE):
                unix_matches.append(pattern)
        
        windows_matches = []
        for pattern in DirectoryListingDetector.WINDOWS_DIR_PATTERNS:
            if re.search(pattern, response_content, re.MULTILINE):
                windows_matches.append(pattern)
        
        if len(unix_matches) >= 2:
            return True, 'unix', unix_matches
        elif len(windows_matches) >= 2:
            return True, 'windows', windows_matches
        
        return False, None, []


class ProcessListAnalyzer:
    UNIX_PS_PATTERN = r'(?i)\b(sshd|apache|nginx|mysql|postgres|mongod|redis-server|node)\b'
    WINDOWS_TASKLIST_PATTERN = r'(?i)(explorer\.exe|svchost\.exe|lsass\.exe|svchost\.exe|spoolsv\.exe)'
    
    @staticmethod
    def analyze_process_list(response_content: str) -> Tuple[bool, Optional[str], List[str]]:
        unix_processes = re.findall(ProcessListAnalyzer.UNIX_PS_PATTERN, response_content)
        windows_processes = re.findall(ProcessListAnalyzer.WINDOWS_TASKLIST_PATTERN, response_content)
        
        if len(unix_processes) >= 2:
            return True, 'unix', list(set(unix_processes))
        elif len(windows_processes) >= 2:
            return True, 'windows', list(set(windows_processes))
        
        return False, None, []


class FileSystemFingerprinting:
    UNIX_FILES = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/version']
    WINDOWS_FILES = ['C:\\windows\\system32\\config\\sam', 'C:\\boot.ini']
    
    @staticmethod
    def detect_filesystem(response_content: str) -> Tuple[Optional[str], List[str]]:
        unix_files = [f for f in FileSystemFingerprinting.UNIX_FILES if f in response_content]
        windows_files = [f for f in FileSystemFingerprinting.WINDOWS_FILES if f in response_content]
        
        if unix_files:
            return 'unix', unix_files
        elif windows_files:
            return 'windows', windows_files
        
        return None, []


class ReverseShellDetector:
    REVERSE_SHELL_PATTERNS = [
        r"bash\s+-i\s+>[\w/&\s]+",
        r"nc\s+-e\s+/bin/\w+",
        r"perl\s+-e\s+",
        r"python\s+-c\s+",
        r"ruby\s+-r\s+",
        r"php\s+-r\s+",
    ]
    
    @staticmethod
    def detect_reverse_shell_attempt(payload: str) -> Tuple[bool, Optional[str]]:
        for pattern in ReverseShellDetector.REVERSE_SHELL_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return True, pattern
        
        if any(keyword in payload for keyword in ['attacker.com', '127.0.0.1', 'localhost', '/dev/tcp']):
            return True, 'network_connection_pattern'
        
        return False, None


class TimingBasedRCEAnalyzer:
    @staticmethod
    def analyze_timing(baseline_time: float, test_time: float, 
                      expected_delay: int = 5) -> Tuple[bool, float, float]:
        time_difference = test_time - baseline_time
        threshold = expected_delay * 0.8
        
        is_delayed = time_difference >= threshold
        confidence = min((time_difference / (expected_delay * 1.5)) * 100, 100.0)
        
        return is_delayed, time_difference, confidence


class CodeInjectionDetector:
    INJECTION_SIGNATURES = {
        'php': [
            r"(?i)<?php\s+system|eval|exec|shell_exec|passthru",
            r"(?i)<?php\s+\$_GET\[",
            r"(?i)phpinfo\(\)",
        ],
        'python': [
            r"(?i)import\s+os\s*;\s*os\.system",
            r"(?i)exec\(|eval\(",
            r"__import__\(",
        ],
        'nodejs': [
            r"require\(['\"]child_process",
            r"exec\(|execFile\(",
            r"spawn\(",
        ],
        'ruby': [
            r"system\(|%x\{|backtick",
            r"Kernel\.system",
        ],
    }
    
    @staticmethod
    def detect_code_injection(response_content: str, execution_context: ExecutionContext) -> Tuple[bool, List[str]]:
        context_key = execution_context.value.split('_')[0].lower()
        
        if context_key not in CodeInjectionDetector.INJECTION_SIGNATURES:
            return False, []
        
        signatures = CodeInjectionDetector.INJECTION_SIGNATURES[context_key]
        matches = []
        
        for signature in signatures:
            if re.search(signature, response_content, re.MULTILINE):
                matches.append(signature)
        
        return len(matches) > 0, matches


class RCEScanner:
    def __init__(self):
        self.output_analyzer = SystemOutputAnalyzer()
        self.directory_detector = DirectoryListingDetector()
        self.process_analyzer = ProcessListAnalyzer()
        self.fs_fingerprinting = FileSystemFingerprinting()
        self.reverse_shell_detector = ReverseShellDetector()
        self.timing_analyzer = TimingBasedRCEAnalyzer()
        self.code_injection_detector = CodeInjectionDetector()
        
        self.vulnerabilities: List[RCEVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.baseline_responses: Dict[str, str] = {}
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: List[str],
            baseline_response: Optional[str] = None) -> List[RCEVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        if baseline_response is None:
            baseline_response = response_content
        
        parameter = self._extract_parameter_name(target_url)
        
        for payload in payloads:
            is_vulnerable, rce_type, context, evidence = self._test_payload(
                response_content,
                baseline_response,
                payload,
                response_time,
                status_code
            )
            
            if is_vulnerable:
                command_output, system_info = self._extract_system_info(response_content)
                
                vuln = RCEVulnerability(
                    vulnerability_type='Remote Code Execution',
                    rce_type=rce_type,
                    execution_context=context,
                    url=target_url,
                    parameter=parameter,
                    payload=payload,
                    severity='Critical',
                    evidence=evidence,
                    response_time=response_time,
                    output_captured=bool(command_output),
                    command_output=command_output,
                    system_info=system_info,
                    confirmed=True,
                    remediation=self._get_remediation()
                )
                
                if self._is_valid_vulnerability(vuln):
                    vulnerabilities.append(vuln)
                    self.scan_statistics[rce_type.value] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _test_payload(self, response_content: str, baseline_response: str,
                     payload: str, response_time: float,
                     status_code: int) -> Tuple[bool, RCEType, Optional[ExecutionContext], str]:
        
        is_output, commands, indicators = self.output_analyzer.analyze_output(response_content)
        if is_output and len(indicators) >= 2:
            context = self._detect_execution_context(payload, commands)
            return True, RCEType.COMMAND_EXECUTION, context, f"Command output detected: {', '.join(indicators[:3])}"
        
        is_dir_listing, os_type, patterns = self.directory_detector.detect_directory_listing(response_content)
        if is_dir_listing:
            return True, RCEType.OS_COMMAND_INJECTION, ExecutionContext.SHELL_COMMAND, f"Directory listing detected ({os_type})"
        
        is_process_list, os_type, processes = self.process_analyzer.analyze_process_list(response_content)
        if is_process_list:
            return True, RCEType.COMMAND_EXECUTION, ExecutionContext.SHELL_COMMAND, f"Process list detected: {', '.join(processes[:3])}"
        
        filesystem, files = self.fs_fingerprinting.detect_filesystem(response_content)
        if filesystem:
            return True, RCEType.FILE_INCLUSION, ExecutionContext.SHELL_COMMAND, f"Filesystem detected ({filesystem}): {files[0]}"
        
        is_reverse_shell, pattern = self.reverse_shell_detector.detect_reverse_shell_attempt(payload)
        if is_reverse_shell:
            return True, RCEType.CODE_INJECTION, None, f"Reverse shell pattern detected: {pattern}"
        
        if response_time > 5:
            return True, RCEType.COMMAND_EXECUTION, ExecutionContext.SHELL_COMMAND, f"Time-based RCE: {response_time:.2f}s delay"
        
        context = self._detect_execution_context(payload, [])
        if context:
            is_injection, matches = self.code_injection_detector.detect_code_injection(response_content, context)
            if is_injection:
                return True, RCEType.CODE_INJECTION, context, f"Code injection detected in {context.value}"
        
        return False, RCEType.COMMAND_EXECUTION, None, ""
    
    def _detect_execution_context(self, payload: str, commands: List[str]) -> Optional[ExecutionContext]:
        payload_lower = payload.lower()
        
        if 'python' in payload_lower or any(c in payload_lower for c in ['os.system', 'subprocess', '__import__']):
            return ExecutionContext.PYTHON_CODE
        elif 'php' in payload_lower or any(c in payload_lower for c in ['system(', 'exec(', 'shell_exec(']):
            return ExecutionContext.PHP_CODE
        elif 'java' in payload_lower or 'ProcessBuilder' in payload:
            return ExecutionContext.JAVA_CODE
        elif 'node' in payload_lower or 'require(' in payload:
            return ExecutionContext.NODEJS_CODE
        elif 'ruby' in payload_lower or 'system(' in payload:
            return ExecutionContext.RUBY_CODE
        elif 'perl' in payload_lower:
            return ExecutionContext.PERL_CODE
        elif any(cmd in commands for cmd in ['bash', 'sh', 'cmd', 'powershell']):
            return ExecutionContext.SHELL_COMMAND
        
        return ExecutionContext.SHELL_COMMAND
    
    def _extract_system_info(self, response_content: str) -> Tuple[Optional[str], Optional[Dict]]:
        command_output = None
        system_info = {}
        
        if 'Linux' in response_content or 'linux' in response_content:
            system_info['os'] = 'Linux'
        elif 'Windows' in response_content or 'windows' in response_content:
            system_info['os'] = 'Windows'
        elif 'Darwin' in response_content:
            system_info['os'] = 'macOS'
        
        version_match = re.search(r'(\d+\.\d+\.\d+[\w-]*)', response_content)
        if version_match:
            system_info['version'] = version_match.group(1)
        
        user_match = re.search(r'uid=\d+\((\w+)\)', response_content)
        if user_match:
            system_info['current_user'] = user_match.group(1)
        
        pwd_match = re.search(r'^(/[\w/.-]+)$', response_content, re.MULTILINE)
        if pwd_match:
            system_info['current_directory'] = pwd_match.group(1)
        
        first_lines = '\n'.join(response_content.split('\n')[:10])
        if len(first_lines) > 0 and not '<' in first_lines:
            command_output = first_lines[:200]
        
        return command_output, system_info if system_info else None
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else 'parameter'
    
    def _is_valid_vulnerability(self, vuln: RCEVulnerability) -> bool:
        if vuln.confidence_score < 0.7:
            return False
        
        if any(word in vuln.payload.lower() for word in ['test', 'debug', 'sample']):
            return False
        
        return vuln.confirmed or vuln.output_captured
    
    def _get_remediation(self) -> str:
        return (
            "Avoid using system command execution functions. "
            "Use safe alternatives (e.g., libraries instead of shell commands). "
            "Validate and sanitize all inputs strictly. "
            "Use allowlists for permitted commands/functions. "
            "Run application with minimal privileges. "
            "Disable dangerous functions (system, exec, shell_exec, passthru, eval). "
            "Implement Web Application Firewall (WAF) rules."
        )
    
    def get_vulnerabilities(self) -> List[RCEVulnerability]:
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