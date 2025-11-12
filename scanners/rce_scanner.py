from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import hashlib
import math


class RCEType(Enum):
    COMMAND_EXECUTION = "command_execution"
    CODE_INJECTION = "code_injection"
    TEMPLATE_INJECTION = "template_injection"
    DESERIALIZATION = "deserialization"
    FILE_INCLUSION = "file_inclusion"
    XXE_INJECTION = "xxe_injection"
    LDAP_INJECTION = "ldap_injection"
    OS_COMMAND_INJECTION = "os_command_injection"
    PROCESS_INJECTION = "process_injection"


class ExecutionContext(Enum):
    SHELL_COMMAND = "shell_command"
    PYTHON_CODE = "python_code"
    PHP_CODE = "php_code"
    JAVA_CODE = "java_code"
    NODEJS_CODE = "nodejs_code"
    RUBY_CODE = "ruby_code"
    PERL_CODE = "perl_code"
    ASP_CODE = "asp_code"
    POWERSHELL = "powershell"


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
    os_fingerprint: Optional[str] = None
    processes_detected: List[str] = field(default_factory=list)
    files_detected: List[str] = field(default_factory=list)
    confirmed: bool = False
    confidence_score: float = 0.8
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class SystemOutputAnalyzer:
    UNIX_COMMANDS_OUTPUT = {
        'ls': {
            'pattern': re.compile(r'^(?:[-dlcbps])([-r][-w][-x]){3}\s+\d+', re.M),
            'indicators': ['drwx', '-rw-', 'total', '-rwx', 'lrwx'],
        },
        'id': {
            'pattern': re.compile(r'uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)', re.M),
            'indicators': ['uid=', 'gid=', 'groups=', 'context='],
        },
        'whoami': {
            'pattern': re.compile(r'^[a-zA-Z0-9_\-]{2,32}$', re.M),
            'indicators': ['root', 'admin', 'www-data', 'nobody', 'system'],
        },
        'pwd': {
            'pattern': re.compile(r'^/(?:[\w\-/.]+)?$', re.M),
            'indicators': ['/', 'home', 'var', 'tmp', 'opt', 'srv'],
        },
        'uname': {
            'pattern': re.compile(r'(?i)(linux|unix|darwin|freebsd|openbsd|sunos)', re.M),
            'indicators': ['Linux', 'Darwin', 'BSD', 'SunOS', 'GNU'],
        },
        'cat': {
            'pattern': re.compile(r'root:[^:]*:[0-9]+:[0-9]+:[^:]*:[^:]*:(?:/bin/\w+)?', re.M),
            'indicators': ['root:', 'bin/bash', 'bin/sh', 'nologin', '/root'],
        },
        'ps': {
            'pattern': re.compile(r'PID\s+(?:TTY|STAT|CPU)\s+TIME\s+CMD', re.M | re.I),
            'indicators': ['sshd', 'apache', 'nginx', 'mysql', 'postgres', 'mongod'],
        },
        'ifconfig': {
            'pattern': re.compile(r'(?i)inet\s+(?:addr:)?\d+\.\d+\.\d+\.\d+', re.M),
            'indicators': ['inet ', 'ether ', 'netmask', 'broadcast', 'hwaddr'],
        },
        'ipconfig': {
            'pattern': re.compile(r'(?i)IPv4 Address|Subnet Mask|Default Gateway', re.M),
            'indicators': ['IPv4', 'IPv6', 'Subnet', 'Gateway', 'DHCP'],
        },
        'hostname': {
            'pattern': re.compile(r'^[\w\-\.]{2,255}$', re.M),
            'indicators': ['-', '.local', '.corp', '.domain'],
        },
        'systeminfo': {
            'pattern': re.compile(r'(?i)OS Name|OS Version|System Type|Processor', re.M),
            'indicators': ['OS Name', 'OS Version', 'System Type', 'Processor', 'RAM'],
        },
    }
    
    @staticmethod
    def analyze_output(response_content: str) -> Tuple[bool, List[str], List[str]]:
        found_indicators = []
        matched_commands = []
        
        for command, config in SystemOutputAnalyzer.UNIX_COMMANDS_OUTPUT.items():
            pattern = config['pattern']
            indicators = config['indicators']
            
            if pattern.search(response_content):
                matched_commands.append(command)
                
                for indicator in indicators:
                    if indicator in response_content:
                        found_indicators.append(indicator)
        
        is_command_output = len(matched_commands) > 0
        return is_command_output, matched_commands, list(set(found_indicators))
    
    @staticmethod
    def extract_process_details(response_content: str) -> Dict[str, List[str]]:
        processes = {}
        
        ps_lines = re.findall(r'^(\w+)\s+(\d+)\s+(.+)$', response_content, re.M)
        if ps_lines:
            for user, pid, rest in ps_lines[:20]:
                if user not in processes:
                    processes[user] = []
                processes[user].append(f"PID:{pid} {rest[:50]}")
        
        return processes


class DirectoryListingDetector:
    UNIX_DIR_PATTERNS = [
        re.compile(r'total\s+\d+', re.M),
        re.compile(r'^([-d])([-r][-w][-x]){3}\s+\d+\s+\w+\s+\w+\s+\d+', re.M),
        re.compile(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', re.M),
        re.compile(r'^drwx[\w\-\.]+\s+\d+', re.M),
    ]
    
    WINDOWS_DIR_PATTERNS = [
        re.compile(r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s+(?:AM|PM)', re.M),
        re.compile(r'<DIR>|[0-9,]+ bytes', re.M),
        re.compile(r'[A-Z]:\\[\w\\]+', re.M),
        re.compile(r'Volume Serial Number', re.M | re.I),
    ]
    
    @staticmethod
    def extract_files(response_content: str, os_type: str) -> List[str]:
        files = []
        
        if os_type == 'unix':
            file_pattern = re.compile(r'(?:^|\s)([\w\-\./]+)(?:\s|$)', re.M)
            matches = file_pattern.findall(response_content)
            files = [m for m in matches if '/' in m or m.startswith('.')][:20]
        elif os_type == 'windows':
            file_pattern = re.compile(r'([A-Z]:\\[\w\\\.]+)', re.M | re.I)
            files = file_pattern.findall(response_content)[:20]
        
        return list(set(files))
    
    @staticmethod
    def detect_directory_listing(response_content: str) -> Tuple[bool, Optional[str], List[str]]:
        unix_matches = 0
        for pattern in DirectoryListingDetector.UNIX_DIR_PATTERNS:
            if pattern.search(response_content):
                unix_matches += 1
        
        windows_matches = 0
        for pattern in DirectoryListingDetector.WINDOWS_DIR_PATTERNS:
            if pattern.search(response_content):
                windows_matches += 1
        
        if unix_matches >= 2:
            files = DirectoryListingDetector.extract_files(response_content, 'unix')
            return True, 'unix', files
        elif windows_matches >= 2:
            files = DirectoryListingDetector.extract_files(response_content, 'windows')
            return True, 'windows', files
        
        return False, None, []


class ProcessListAnalyzer:
    UNIX_PS_PATTERN = re.compile(
        r'\b(sshd|apache2?|nginx|mysql|postgres|mongod|redis-server|node|python|java|ruby|perl|php-fpm|tomcat|jboss)\b',
        re.I
    )
    WINDOWS_TASKLIST_PATTERN = re.compile(
        r'\b(explorer\.exe|svchost\.exe|lsass\.exe|spoolsv\.exe|services\.exe|csrss\.exe|conhost\.exe|powershell\.exe|cmd\.exe)\b',
        re.I
    )
    
    @staticmethod
    def analyze_process_list(response_content: str) -> Tuple[bool, Optional[str], List[str]]:
        unix_processes = ProcessListAnalyzer.UNIX_PS_PATTERN.findall(response_content)
        windows_processes = ProcessListAnalyzer.WINDOWS_TASKLIST_PATTERN.findall(response_content)
        
        if len(unix_processes) >= 2:
            return True, 'unix', list(set(unix_processes))[:15]
        elif len(windows_processes) >= 2:
            return True, 'windows', list(set(windows_processes))[:15]
        
        return False, None, []
    
    @staticmethod
    def extract_process_pids(response_content: str) -> Dict[str, str]:
        pids = {}
        
        pid_pattern = re.compile(r'(\w+)\s+(\d{3,6})\s+', re.M)
        matches = pid_pattern.findall(response_content)
        
        for process, pid in matches[:20]:
            if process not in pids:
                pids[process] = pid
        
        return pids


class FileSystemFingerprinting:
    UNIX_SENSITIVE_FILES = frozenset([
        '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/resolv.conf',
        '/proc/version', '/proc/cpuinfo', '/root/.bash_history',
        '/home', '/var/www', '/opt', '/srv',
    ])
    
    WINDOWS_SENSITIVE_FILES = frozenset([
        'C:\\windows\\system32\\config\\sam', 'C:\\boot.ini',
        'C:\\windows\\win.ini', 'C:\\pagefile.sys',
    ])
    
    UNIX_PATHS = re.compile(r'(?:^|\s|["\'])((?:/[\w\-\.]+)+)(?:\s|["\']|$)', re.M)
    WINDOWS_PATHS = re.compile(r'(?:^|\s|["\'])?([A-Z]:\\[\w\-\\\.\s]+)(?:\s|["\']|$)', re.M | re.I)
    
    @staticmethod
    def detect_filesystem(response_content: str) -> Tuple[Optional[str], List[str]]:
        unix_files = [f for f in FileSystemFingerprinting.UNIX_SENSITIVE_FILES if f in response_content]
        windows_files = [f for f in FileSystemFingerprinting.WINDOWS_SENSITIVE_FILES if f in response_content]
        
        if unix_files:
            return 'unix', unix_files
        elif windows_files:
            return 'windows', windows_files
        
        return None, []
    
    @staticmethod
    def extract_file_paths(response_content: str) -> Tuple[Optional[str], List[str]]:
        unix_paths = FileSystemFingerprinting.UNIX_PATHS.findall(response_content)
        windows_paths = FileSystemFingerprinting.WINDOWS_PATHS.findall(response_content)
        
        if unix_paths:
            unique_paths = list(set(unix_paths))[:10]
            return 'unix', unique_paths
        elif windows_paths:
            unique_paths = list(set(windows_paths))[:10]
            return 'windows', unique_paths
        
        return None, []


class ReverseShellDetector:
    REVERSE_SHELL_PATTERNS = [
        re.compile(r'bash\s+-i\s+>[\w/&\s]+', re.I),
        re.compile(r'nc\s+-e\s+/bin/\w+', re.I),
        re.compile(r'perl\s+-e\s+.*socket', re.I | re.S),
        re.compile(r'python\s+-c\s+.*socket', re.I | re.S),
        re.compile(r'ruby\s+-r\s+socket', re.I),
        re.compile(r'php\s+-r\s+.*exec', re.I),
        re.compile(r'/dev/tcp/[\d\.]+/\d+', re.I),
        re.compile(r'/dev/udp/[\d\.]+/\d+', re.I),
    ]
    
    @staticmethod
    def detect_reverse_shell_attempt(payload: str) -> Tuple[bool, Optional[str]]:
        for pattern in ReverseShellDetector.REVERSE_SHELL_PATTERNS:
            if pattern.search(payload):
                return True, pattern.pattern
        
        network_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload)
        network_hosts = re.findall(r'(?:attacker|target|malicious|hacker|evil)\.[\w\.]+', payload, re.I)
        
        if network_ips or network_hosts:
            return True, 'network_endpoint'
        
        return False, None


class TimingBasedRCEAnalyzer:
    @staticmethod
    def analyze_timing(baseline_time: float, test_time: float, 
                      expected_delay: int = 5) -> Tuple[bool, float, float]:
        if baseline_time == 0:
            baseline_time = 0.1
        
        time_difference = test_time - baseline_time
        threshold = expected_delay * 0.7
        upper_threshold = expected_delay * 1.5
        
        is_delayed = threshold <= time_difference <= (expected_delay + 10)
        
        if is_delayed:
            confidence = min((time_difference / expected_delay) * 100, 100.0)
        else:
            confidence = 0.0
        
        return is_delayed, time_difference, confidence
    
    @staticmethod
    def detect_timing_patterns(response_times: List[float]) -> Tuple[bool, float]:
        if len(response_times) < 3:
            return False, 0.0
        
        avg_time = sum(response_times) / len(response_times)
        variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)
        std_dev = math.sqrt(variance)
        
        is_consistent = std_dev < avg_time * 0.2
        
        return is_consistent, std_dev


class CodeInjectionDetector:
    INJECTION_SIGNATURES = {
        'php': [
            re.compile(r'<?php\s+(?:system|eval|exec|shell_exec|passthru|proc_open|popen)', re.I),
            re.compile(r'<?php\s+\$_(?:GET|POST|REQUEST|COOKIE|FILES)\[', re.I),
            re.compile(r'phpinfo\s*\(\)', re.I),
            re.compile(r'assert\s*\(', re.I),
            re.compile(r'create_function\s*\(', re.I),
        ],
        'python': [
            re.compile(r'(?:import\s+os|from\s+os)\s*;?\s*os\.(?:system|popen|exec|remove)', re.I),
            re.compile(r'(?:eval|exec|__import__)\s*\(', re.I),
            re.compile(r'subprocess\.(?:Popen|call|check_output)', re.I),
            re.compile(r'pickle\.(?:loads|load)', re.I),
        ],
        'nodejs': [
            re.compile(r"require\(['\"]child_process['\"]", re.I),
            re.compile(r'(?:exec|execFile|spawn)\s*\(', re.I),
            re.compile(r'vm\.runInThisContext', re.I),
        ],
        'ruby': [
            re.compile(r'(?:system|exec|backtick|%x)\s*[\(\{]', re.I),
            re.compile(r'Kernel\.(?:system|exec)', re.I),
            re.compile(r'IO\.popen', re.I),
        ],
        'java': [
            re.compile(r'Runtime\.getRuntime\(\)\.exec', re.I),
            re.compile(r'ProcessBuilder', re.I),
            re.compile(r'java\.lang\.Runtime', re.I),
        ],
        'perl': [
            re.compile(r'system\s*\(', re.I),
            re.compile(r'exec\s*\(', re.I),
            re.compile(r'backtick|qx', re.I),
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
            if signature.search(response_content):
                matches.append(signature.pattern[:50])
        
        return len(matches) > 0, matches


class TemplateInjectionDetector:
    TEMPLATE_PATTERNS = {
        'jinja2': re.compile(r'{{.*?}}|{%.*?%}', re.DOTALL),
        'erb': re.compile(r'<%.*?%>|<%=.*?%>', re.DOTALL),
        'twig': re.compile(r'{{.*?}}|{%.*?%}', re.DOTALL),
        'freemarker': re.compile(r'<#.*?>', re.DOTALL),
        'velocity': re.compile(r'\$[{\w].*?[}]|\$.*?\s', re.DOTALL),
    }
    
    TEMPLATE_KEYWORDS = {
        'jinja2': ['self', '__class__', '__subclasses__', 'config'],
        'erb': ['system', 'exec', 'eval', '`'],
        'twig': ['_self', 'attribute', 'dump'],
        'velocity': ['math', 'tool'],
    }
    
    @staticmethod
    def detect_template_injection(response_content: str, payload: str) -> Tuple[bool, List[str]]:
        detected_templates = []
        
        for template_type, pattern in TemplateInjectionDetector.TEMPLATE_PATTERNS.items():
            if pattern.search(response_content):
                keywords = TemplateInjectionDetector.TEMPLATE_KEYWORDS.get(template_type, [])
                
                for keyword in keywords:
                    if keyword in response_content:
                        detected_templates.append(template_type)
                        break
        
        return len(detected_templates) > 0, detected_templates


class RCEScanner:
    _remediation_cache = (
        "Avoid using system command execution functions. "
        "Use safe alternatives (language libraries instead of shell commands). "
        "Validate and sanitize all inputs with strict allowlists. "
        "Use allowlists for permitted commands and functions. "
        "Run application with minimal privileges (least privilege). "
        "Disable dangerous functions (system, exec, eval, passthru, shell_exec). "
        "Implement Web Application Firewall (WAF) rules. "
        "Use operating system-level restrictions (SELinux, AppArmor). "
        "Implement input length limits. "
        "Use secure coding practices and code review. "
        "Monitor system calls and process execution. "
        "Implement rate limiting on execution endpoints. "
        "Use containerization and sandboxing. "
        "Implement proper error handling without information disclosure."
    )
    
    def __init__(self):
        self.output_analyzer = SystemOutputAnalyzer()
        self.directory_detector = DirectoryListingDetector()
        self.process_analyzer = ProcessListAnalyzer()
        self.fs_fingerprinting = FileSystemFingerprinting()
        self.reverse_shell_detector = ReverseShellDetector()
        self.timing_analyzer = TimingBasedRCEAnalyzer()
        self.code_injection_detector = CodeInjectionDetector()
        self.template_detector = TemplateInjectionDetector()
        
        self.vulnerabilities: List[RCEVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.baseline_responses: Dict[str, str] = {}
        self.response_times: Dict[str, List[float]] = defaultdict(list)
        self.tested_payloads: Set[str] = set()
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: List[str],
            baseline_response: Optional[str] = None, baseline_time: Optional[float] = None) -> List[RCEVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        if baseline_response is None:
            baseline_response = response_content
        
        if baseline_time is None:
            baseline_time = response_time * 0.5
        
        parameter = self._extract_parameter_name(target_url)
        
        for payload in payloads:
            payload_hash = hashlib.md5(payload.encode()).hexdigest()
            
            if payload_hash in self.tested_payloads:
                continue
            
            with self.lock:
                self.tested_payloads.add(payload_hash)
            
            is_vulnerable, rce_type, context, evidence, confidence = self._test_payload(
                response_content,
                baseline_response,
                payload,
                response_time,
                baseline_time,
                status_code
            )
            
            if is_vulnerable:
                command_output, system_info = self._extract_system_info(response_content)
                os_fingerprint, detected_files = self.fs_fingerprinting.extract_file_paths(response_content)
                is_dir, dir_os, dir_files = self.directory_detector.detect_directory_listing(response_content)
                is_proc, proc_os, processes = self.process_analyzer.analyze_process_list(response_content)
                
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
                    os_fingerprint=os_fingerprint or dir_os or proc_os,
                    processes_detected=processes if is_proc else [],
                    files_detected=detected_files + (dir_files if is_dir else []),
                    confirmed=True,
                    confidence_score=confidence,
                    remediation=self._remediation_cache
                )
                
                if self._is_valid_vulnerability(vuln):
                    vulnerabilities.append(vuln)
                    
                    with self.lock:
                        self.scan_statistics[rce_type.value] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
            self.scan_statistics['total_scans'] += 1
        
        return vulnerabilities
    
    def _test_payload(self, response_content: str, baseline_response: str, payload: str,
                     response_time: float, baseline_time: float, status_code: int) -> Tuple[bool, RCEType, Optional[ExecutionContext], str, float]:
        
        is_output, commands, indicators = self.output_analyzer.analyze_output(response_content)
        if is_output and len(indicators) >= 2:
            context = self._detect_execution_context(payload, commands)
            confidence = min(0.9 + (len(indicators) * 0.02), 1.0)
            return True, RCEType.COMMAND_EXECUTION, context, f"Command output: {', '.join(indicators[:5])}", confidence
        
        is_dir_listing, os_type, files = self.directory_detector.detect_directory_listing(response_content)
        if is_dir_listing:
            files_str = ', '.join(files[:5]) if files else 'files detected'
            return True, RCEType.OS_COMMAND_INJECTION, ExecutionContext.SHELL_COMMAND, f"Directory listing ({os_type}): {files_str}", 0.88
        
        is_process_list, os_type, processes = self.process_analyzer.analyze_process_list(response_content)
        if is_process_list:
            return True, RCEType.COMMAND_EXECUTION, ExecutionContext.SHELL_COMMAND, f"Process list detected: {', '.join(processes[:3])}", 0.85
        
        filesystem, files = self.fs_fingerprinting.detect_filesystem(response_content)
        if filesystem:
            return True, RCEType.FILE_INCLUSION, ExecutionContext.SHELL_COMMAND, f"Filesystem detected: {', '.join(files)}", 0.92
        
        is_template, templates = self.template_detector.detect_template_injection(response_content, payload)
        if is_template:
            return True, RCEType.TEMPLATE_INJECTION, None, f"Template injection: {', '.join(templates)}", 0.8
        
        is_reverse_shell, pattern = self.reverse_shell_detector.detect_reverse_shell_attempt(payload)
        if is_reverse_shell:
            return True, RCEType.CODE_INJECTION, self._detect_execution_context(payload, []), f"Reverse shell pattern: {pattern}", 0.75
        
        is_delayed, time_diff, timing_confidence = self.timing_analyzer.analyze_timing(baseline_time, response_time, 5)
        if is_delayed and timing_confidence > 75:
            return True, RCEType.COMMAND_EXECUTION, ExecutionContext.SHELL_COMMAND, f"Time-based RCE: {time_diff:.2f}s", timing_confidence / 100
        
        context = self._detect_execution_context(payload, [])
        if context:
            is_injection, matches = self.code_injection_detector.detect_code_injection(response_content, context)
            if is_injection:
                return True, RCEType.CODE_INJECTION, context, f"Code injection in {context.value}: {len(matches)} patterns", 0.82
        
        if response_content != baseline_response and len(response_content) > len(baseline_response) * 1.5:
            return True, RCEType.DESERIALIZATION, self._detect_execution_context(payload, []), "Unusual response size increase", 0.65
        
        return False, RCEType.COMMAND_EXECUTION, None, "", 0.0
    
    def _detect_execution_context(self, payload: str, commands: List[str]) -> Optional[ExecutionContext]:
        payload_lower = payload.lower()
        
        if any(keyword in payload_lower for keyword in ['python', 'os.system', 'subprocess', '__import__', 'exec(', 'eval(']):
            return ExecutionContext.PYTHON_CODE
        elif any(keyword in payload_lower for keyword in ['php', 'system(', 'shell_exec(', 'passthru(', '<?php']):
            return ExecutionContext.PHP_CODE
        elif any(keyword in payload_lower for keyword in ['java', 'ProcessBuilder', 'Runtime.getRuntime']):
            return ExecutionContext.JAVA_CODE
        elif any(keyword in payload_lower for keyword in ['node', 'require', 'child_process', 'spawn']):
            return ExecutionContext.NODEJS_CODE
        elif any(keyword in payload_lower for keyword in ['ruby', 'system(', '%x{', '`']):
            return ExecutionContext.RUBY_CODE
        elif any(keyword in payload_lower for keyword in ['perl', 'backtick', 'qx']):
            return ExecutionContext.PERL_CODE
        elif any(keyword in payload_lower for keyword in ['powershell', 'Get-', 'Set-', 'Write-']):
            return ExecutionContext.POWERSHELL
        elif any(cmd in commands for cmd in ['bash', 'sh', 'cmd', 'powershell']):
            return ExecutionContext.SHELL_COMMAND
        
        return ExecutionContext.SHELL_COMMAND
    
    def _extract_system_info(self, response_content: str) -> Tuple[Optional[str], Optional[Dict]]:
        command_output = None
        system_info = {}
        
        if any(keyword in response_content for keyword in ['Linux', 'linux', 'GNU']):
            system_info['os'] = 'Linux'
        elif any(keyword in response_content for keyword in ['Windows', 'windows', 'WINDOWS']):
            system_info['os'] = 'Windows'
        elif 'Darwin' in response_content:
            system_info['os'] = 'macOS'
        elif any(keyword in response_content for keyword in ['BSD', 'FreeBSD', 'OpenBSD']):
            system_info['os'] = 'BSD'
        
        version_match = re.search(r'(?:version|Version)\s*[=:]*\s*(\d+(?:\.\d+)*[\w\-]*)', response_content)
        if version_match:
            system_info['version'] = version_match.group(1)
        
        kernel_match = re.search(r'(\d+\.\d+\.\d+[\w\-]*)', response_content)
        if kernel_match:
            system_info['kernel'] = kernel_match.group(1)
        
        user_match = re.search(r'uid=\d+\((\w+)\)', response_content)
        if user_match:
            system_info['current_user'] = user_match.group(1)
        
        uid_match = re.search(r'uid=(\d+)', response_content)
        if uid_match:
            system_info['uid'] = uid_match.group(1)
        
        pwd_match = re.search(r'^(/(?:[\w\-\.]+)*)$', response_content, re.M)
        if pwd_match:
            system_info['current_directory'] = pwd_match.group(1)
        
        cpu_match = re.search(r'(?i)processor.*:\s*(\d+)', response_content)
        if cpu_match:
            system_info['cpu_cores'] = cpu_match.group(1)
        
        mem_match = re.search(r'(?i)MemTotal:\s*(\d+)', response_content)
        if mem_match:
            system_info['memory_kb'] = mem_match.group(1)
        
        first_lines = '\n'.join(response_content.split('\n')[:20])
        if len(first_lines) > 0 and not any(tag in first_lines for tag in ['<', '>', '{', '}']):
            command_output = first_lines[:300]
        
        return command_output, system_info if system_info else None
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            return list(params.keys())[0]
        
        path_parts = parsed.path.split('/')
        return path_parts[-1] if path_parts and path_parts[-1] else 'parameter'
    
    def _is_valid_vulnerability(self, vuln: RCEVulnerability) -> bool:
        if vuln.confidence_score < 0.6:
            return False
        
        false_positive_keywords = ['test', 'debug', 'sample', 'example', 'demo', 'mock']
        if any(word in vuln.payload.lower() for word in false_positive_keywords):
            if not vuln.output_captured and vuln.confidence_score < 0.85:
                return False
        
        return vuln.confirmed or vuln.output_captured or vuln.confidence_score >= 0.82
    
    def get_vulnerabilities(self) -> List[RCEVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def get_tested_payloads(self) -> Set[str]:
        with self.lock:
            return self.tested_payloads.copy()
    
    def set_baseline_response(self, parameter: str, response: str, response_time: float = 0.0):
        self.baseline_responses[parameter] = response
    
    def get_baseline_response(self, parameter: str) -> Optional[str]:
        return self.baseline_responses.get(parameter)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.baseline_responses.clear()
            self.response_times.clear()
            self.tested_payloads.clear()