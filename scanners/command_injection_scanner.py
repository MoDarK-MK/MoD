from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
from urllib.parse import urlparse, parse_qs


class CommandInjectionType(Enum):
    IN_BAND = "in_band"
    OUT_OF_BAND = "out_of_band"
    BLIND_INJECTION = "blind_injection"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    FILTER_BYPASS = "filter_bypass"
    DOUBLE_BLIND = "double_blind"
    STACKED_QUERIES = "stacked_queries"


class OSSeparator(Enum):
    SEMICOLON = ";"
    PIPE = "|"
    PIPE_PIPE = "||"
    AND = "&"
    AND_AND = "&&"
    NEWLINE = "\n"
    BACKTICK = "`"
    DOLLAR_PAREN = "$("
    PERCENT_PAREN = "%("
    CARRIAGE_RETURN = "\r"
    COMMAND_SUBSTITUTION = "$()"


class ShellType(Enum):
    BASH = "bash"
    SH = "sh"
    ZSH = "zsh"
    FISH = "fish"
    CSH = "csh"
    KSH = "ksh"
    CMD = "cmd"
    POWERSHELL = "powershell"
    UNKNOWN = "unknown"


@dataclass
class CommandPayload:
    payload: str
    injection_type: CommandInjectionType
    separator: OSSeparator
    shell_type: ShellType
    command: str
    severity: str = "Critical"
    detection_indicators: List[str] = field(default_factory=list)
    requires_confirmation: bool = True
    false_positive_risk: float = 0.2


@dataclass
class CommandInjectionVulnerability:
    vulnerability_type: str
    injection_type: CommandInjectionType
    shell_type: Optional[ShellType]
    url: str
    parameter: str
    payload: str
    severity: str
    evidence: str
    response_time: float
    command_executed: bool
    output_captured: Optional[str] = None
    executed_command: Optional[str] = None
    shell_detected: Optional[str] = None
    confirmed: bool = False
    confidence_score: float = 0.8
    bypass_techniques: List[str] = field(default_factory=list)
    error_types: List[str] = field(default_factory=list)
    indicators_found: List[str] = field(default_factory=list)
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class CommandExecutionDetector:
    COMMAND_PATTERNS = {
        'ls': {
            'output_pattern': re.compile(r'^([-dlcbps])([-r][-w][-x]){3}'),
            'indicators': ['drwx', '-rw-', 'total', '-rwxr', 'lrwx'],
            'shell_types': [ShellType.BASH, ShellType.SH, ShellType.ZSH, ShellType.KSH],
        },
        'dir': {
            'output_pattern': re.compile(r'(?i)Directory of|Volume in drive|<DIR>'),
            'indicators': ['Directory of', '<DIR>', 'Volume'],
            'shell_types': [ShellType.CMD],
        },
        'id': {
            'output_pattern': re.compile(r'uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)'),
            'indicators': ['uid=', 'gid=', 'groups=', 'context='],
            'shell_types': [ShellType.BASH, ShellType.SH, ShellType.ZSH],
        },
        'whoami': {
            'output_pattern': re.compile(r'^[a-zA-Z0-9_\-]+$', re.MULTILINE),
            'indicators': ['root', 'admin', 'www-data', 'nginx', 'apache', 'nobody'],
            'shell_types': [ShellType.BASH, ShellType.SH, ShellType.CMD],
        },
        'pwd': {
            'output_pattern': re.compile(r'^/[\w/\-\.]+$', re.MULTILINE),
            'indicators': ['/home/', '/var/', '/usr/', '/opt/', '/etc/'],
            'shell_types': [ShellType.BASH, ShellType.SH, ShellType.ZSH],
        },
        'ipconfig': {
            'output_pattern': re.compile(r'(?i)IPv[46] Address|Subnet Mask|Default Gateway|Adapter'),
            'indicators': ['IPv4', 'IPv6', 'Adapter', 'Subnet Mask', 'Default Gateway'],
            'shell_types': [ShellType.CMD, ShellType.POWERSHELL],
        },
        'ifconfig': {
            'output_pattern': re.compile(r'(?i)inet\s+(?:addr:)?\d+\.\d+\.\d+\.\d+'),
            'indicators': ['inet ', 'ether ', 'netmask', 'broadcast'],
            'shell_types': [ShellType.BASH, ShellType.SH],
        },
        'systeminfo': {
            'output_pattern': re.compile(r'(?i)OS Name|OS Version|System Type|Processor'),
            'indicators': ['OS Name', 'OS Version', 'System Type', 'Processor'],
            'shell_types': [ShellType.CMD, ShellType.POWERSHELL],
        },
        'uname': {
            'output_pattern': re.compile(r'(?i)linux|darwin|freebsd|sunos'),
            'indicators': ['Linux', 'Darwin', 'GNU', 'x86_64', 'aarch64'],
            'shell_types': [ShellType.BASH, ShellType.SH, ShellType.ZSH],
        },
        'cat': {
            'output_pattern': re.compile(r'(?s).{10,}'),
            'indicators': ['root:', 'bin:', 'daemon:', 'etc/', 'var/'],
            'shell_types': [ShellType.BASH, ShellType.SH],
        },
        'type': {
            'output_pattern': re.compile(r'(?i)(?:The|This) (?:system|file) cannot'),
            'indicators': ['The system cannot', 'is not recognized'],
            'shell_types': [ShellType.CMD],
        },
    }
    
    @staticmethod
    def detect_command_execution(response_content: str) -> Tuple[bool, List[str], List[str]]:
        detected_commands = []
        indicators_found = []
        
        for command, config in CommandExecutionDetector.COMMAND_PATTERNS.items():
            pattern = config['output_pattern']
            indicators = config['indicators']
            
            if pattern.search(response_content):
                detected_commands.append(command)
                
                for indicator in indicators:
                    if indicator in response_content:
                        indicators_found.append(indicator)
        
        return len(detected_commands) > 0, detected_commands, list(set(indicators_found))
    
    @staticmethod
    def detect_process_listing(response_content: str) -> bool:
        ps_patterns = [
            re.compile(r'PID\s+TTY\s+TIME\s+CMD'),
            re.compile(r'USER\s+PID\s+%CPU\s+%MEM'),
            re.compile(r'(?i)Image Name\s+PID\s+Session Name'),
        ]
        
        return any(pattern.search(response_content) for pattern in ps_patterns)
    
    @staticmethod
    def detect_network_output(response_content: str) -> bool:
        network_patterns = [
            re.compile(r'(?i)(?:tcp|udp)\s+\d+\s+\d+\.\d+\.\d+\.\d+:\d+'),
            re.compile(r'(?i)netstat|listening|established'),
            re.compile(r'(?i)Proto\s+Local Address\s+Foreign Address'),
        ]
        
        return any(pattern.search(response_content) for pattern in network_patterns)


class TimingBasedCommandAnalyzer:
    DELAY_COMMANDS = {
        ShellType.BASH: ['sleep', 'ping -c'],
        ShellType.SH: ['sleep', 'ping -c'],
        ShellType.ZSH: ['sleep', 'ping -c'],
        ShellType.CMD: ['timeout', 'ping -n'],
        ShellType.POWERSHELL: ['Start-Sleep', 'ping -n'],
    }
    
    _delay_patterns = {
        'sleep': re.compile(r'sleep\s+(\d+)'),
        'timeout': re.compile(r'timeout\s+(?:/t\s+)?(\d+)'),
        'Start-Sleep': re.compile(r'Start-Sleep\s+-(?:s|Seconds)\s+(\d+)'),
        'ping': re.compile(r'ping\s+-[cn]\s+(\d+)'),
    }
    
    @staticmethod
    def analyze_delay(baseline_time: float, test_time: float, expected_delay: int = 5) -> Tuple[bool, float, float]:
        time_difference = test_time - baseline_time
        threshold = expected_delay * 0.7
        upper_threshold = expected_delay * 1.3
        
        is_delayed = threshold <= time_difference <= (expected_delay + 10)
        
        if is_delayed:
            confidence = min((time_difference / expected_delay) * 100, 100.0)
        else:
            confidence = 0.0
        
        return is_delayed, time_difference, confidence
    
    @staticmethod
    def extract_delay_command(payload: str, shell_type: ShellType) -> Optional[int]:
        delay_cmds = TimingBasedCommandAnalyzer.DELAY_COMMANDS.get(shell_type, [])
        
        for cmd in delay_cmds:
            cmd_key = cmd.split()[0]
            pattern = TimingBasedCommandAnalyzer._delay_patterns.get(cmd_key)
            
            if pattern:
                match = pattern.search(payload)
                if match:
                    return int(match.group(1))
        
        return None
    
    @staticmethod
    def detect_timing_variations(response_times: List[float]) -> Tuple[bool, float]:
        if len(response_times) < 3:
            return False, 0.0
        
        avg_time = sum(response_times) / len(response_times)
        variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)
        std_dev = variance ** 0.5
        
        is_suspicious = std_dev > 1.5
        
        return is_suspicious, std_dev


class SeparatorAnalyzer:
    SEPARATOR_PATTERNS = {
        OSSeparator.SEMICOLON: re.compile(r';'),
        OSSeparator.PIPE: re.compile(r'\|(?!\|)'),
        OSSeparator.PIPE_PIPE: re.compile(r'\|\|'),
        OSSeparator.AND: re.compile(r'&(?!&)'),
        OSSeparator.AND_AND: re.compile(r'&&'),
        OSSeparator.NEWLINE: re.compile(r'\n'),
        OSSeparator.BACKTICK: re.compile(r'`'),
        OSSeparator.DOLLAR_PAREN: re.compile(r'\$\('),
        OSSeparator.PERCENT_PAREN: re.compile(r'%\('),
        OSSeparator.CARRIAGE_RETURN: re.compile(r'\r'),
    }
    
    @staticmethod
    def detect_separators(payload: str) -> List[OSSeparator]:
        found_separators = []
        
        for separator, pattern in SeparatorAnalyzer.SEPARATOR_PATTERNS.items():
            if pattern.search(payload):
                found_separators.append(separator)
        
        return found_separators
    
    @staticmethod
    def extract_injected_command(payload: str, separator: OSSeparator) -> Optional[str]:
        pattern = SeparatorAnalyzer.SEPARATOR_PATTERNS[separator]
        parts = pattern.split(payload)
        
        if len(parts) >= 2:
            command = parts[-1].strip()
            
            if command.endswith(')'):
                command = command[:-1].strip()
            
            return command
        
        return None
    
    @staticmethod
    def detect_command_chaining(payload: str) -> int:
        chain_count = 0
        for separator in SeparatorAnalyzer.SEPARATOR_PATTERNS.values():
            chain_count += len(separator.findall(payload))
        
        return chain_count


class FilterBypassDetector:
    BYPASS_TECHNIQUES = {
        'case_manipulation': re.compile(r'(?:[a-z]\*[a-z]|[A-Z]\*[A-Z])'),
        'backslash_escape': re.compile(r'\\[a-z]'),
        'comment_injection': re.compile(r'/\*\*/|<!--.*-->'),
        'hex_encoding': re.compile(r'\\x[0-9a-fA-F]{2}'),
        'octal_encoding': re.compile(r'\\[0-7]{3}'),
        'environment_variables': re.compile(r'\$[A-Z_]+|\${[^}]+}'),
        'globbing': re.compile(r'[*?[\]]'),
        'brace_expansion': re.compile(r'\{[^}]+,[^}]+\}'),
        'unicode_escape': re.compile(r'\\u[0-9a-fA-F]{4}'),
        'base64_encoding': re.compile(r'(?:echo|printf)\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64'),
        'variable_expansion': re.compile(r'\$\{[^}]+\}'),
        'null_byte_injection': re.compile(r'%00|\\0'),
        'wildcard_obfuscation': re.compile(r'\$\{\w+//'),
        'double_encoding': re.compile(r'%25[0-9a-fA-F]{2}'),
    }
    
    @staticmethod
    def detect_bypass_techniques(payload: str) -> List[str]:
        detected_techniques = []
        
        for technique, pattern in FilterBypassDetector.BYPASS_TECHNIQUES.items():
            if pattern.search(payload):
                detected_techniques.append(technique)
        
        return detected_techniques
    
    @staticmethod
    def calculate_obfuscation_complexity(payload: str) -> float:
        complexity = 0.0
        
        techniques = FilterBypassDetector.detect_bypass_techniques(payload)
        complexity += len(techniques) * 0.2
        
        special_chars = len(re.findall(r'[^a-zA-Z0-9\s]', payload))
        complexity += min(special_chars / 10, 0.3)
        
        encoding_layers = len(re.findall(r'(?:base64|hex|oct|\\x|\\u)', payload))
        complexity += encoding_layers * 0.1
        
        return min(complexity, 1.0)


class ShellDetectionEngine:
    SHELL_INDICATORS = {
        ShellType.BASH: [
            re.compile(r'bash.*version', re.I),
            re.compile(r'\$BASH_VERSION'),
            re.compile(r'GNU bash'),
            re.compile(r'bash-\d+\.\d+'),
        ],
        ShellType.SH: [
            re.compile(r'sh.*version', re.I),
            re.compile(r'POSIX.*sh', re.I),
            re.compile(r'sh:\s+.+:'),
        ],
        ShellType.ZSH: [
            re.compile(r'zsh\s+\d+\.\d+', re.I),
            re.compile(r'\$ZSH_VERSION'),
        ],
        ShellType.CMD: [
            re.compile(r'Microsoft Windows', re.I),
            re.compile(r'cmd\.exe', re.I),
            re.compile(r'C:\\Windows', re.I),
            re.compile(r'C:\\Program Files', re.I),
        ],
        ShellType.POWERSHELL: [
            re.compile(r'PowerShell', re.I),
            re.compile(r'powershell\.exe', re.I),
            re.compile(r'PS\s+C:\\'),
            re.compile(r'Get-ChildItem|Set-Location|Write-Host'),
        ],
    }
    
    COMMAND_SHELL_MAPPING = {
        'ipconfig': ShellType.CMD,
        'systeminfo': ShellType.CMD,
        'tasklist': ShellType.CMD,
        'dir': ShellType.CMD,
        'type': ShellType.CMD,
        'Get-': ShellType.POWERSHELL,
        'Set-': ShellType.POWERSHELL,
        'Start-Sleep': ShellType.POWERSHELL,
        'ls': ShellType.BASH,
        'cat': ShellType.BASH,
        'grep': ShellType.BASH,
        'awk': ShellType.BASH,
        'sed': ShellType.BASH,
        'id': ShellType.BASH,
        'whoami': ShellType.BASH,
        'pwd': ShellType.BASH,
        'uname': ShellType.BASH,
    }
    
    _prompt_patterns = {
        re.compile(r'\$\s*$|#\s*$', re.M): ShellType.BASH,
        re.compile(r'>\s*$', re.M): ShellType.CMD,
        re.compile(r'PS\s+[A-Z]:\\.*>\s*$', re.M): ShellType.POWERSHELL,
        re.compile(r'%\s*$', re.M): ShellType.ZSH,
    }
    
    @staticmethod
    def detect_shell_type(response_content: str, payload: str) -> Optional[ShellType]:
        for command, shell_type in ShellDetectionEngine.COMMAND_SHELL_MAPPING.items():
            if command in payload:
                return shell_type
        
        for shell_type, indicators in ShellDetectionEngine.SHELL_INDICATORS.items():
            for indicator in indicators:
                if indicator.search(response_content):
                    return shell_type
        
        prompt_shell = ShellDetectionEngine.detect_shell_prompt(response_content)
        if prompt_shell:
            return prompt_shell
        
        return ShellType.UNKNOWN
    
    @staticmethod
    def detect_shell_prompt(response_content: str) -> Optional[ShellType]:
        for pattern, shell_type in ShellDetectionEngine._prompt_patterns.items():
            if pattern.search(response_content):
                return shell_type
        
        return None
    
    @staticmethod
    def detect_interactive_shell(response_content: str) -> bool:
        interactive_indicators = [
            r'Last login:',
            r'Welcome to',
            r'\$ $',
            r'# $',
            r'PS .*>',
            r'C:\\.*>',
        ]
        
        return any(re.search(indicator, response_content) for indicator in interactive_indicators)


class ErrorBasedCommandAnalyzer:
    ERROR_PATTERNS = {
        'command_not_found': re.compile(r"(?i)(command not found|'.*' is not recognized|No such file or directory)"),
        'permission_denied': re.compile(r"(?i)(permission denied|access is denied|operation not permitted)"),
        'syntax_error': re.compile(r"(?i)(syntax error|unexpected token|parse error|invalid syntax)"),
        'file_not_found': re.compile(r"(?i)(cannot find (?:the )?(?:path|file)|no such file|does not exist)"),
        'shell_error': re.compile(r"(?i)(sh:|bash:|cmd:|powershell:)"),
        'execution_error': re.compile(r"(?i)(cannot execute|execution failed|unable to run)"),
        'segmentation_fault': re.compile(r"(?i)(segmentation fault|core dumped)"),
    }
    
    @staticmethod
    def analyze_error_response(response_content: str) -> Tuple[bool, List[str], List[str]]:
        errors_found = []
        error_messages = []
        
        for error_type, pattern in ErrorBasedCommandAnalyzer.ERROR_PATTERNS.items():
            matches = pattern.findall(response_content)
            if matches:
                errors_found.append(error_type)
                error_messages.extend(matches[:2])
        
        return len(errors_found) > 0, errors_found, error_messages
    
    @staticmethod
    def detect_stack_trace(response_content: str) -> bool:
        stack_trace_patterns = [
            r'Traceback \(most recent call last\)',
            r'at .*\.java:\d+',
            r'in .*\.py", line \d+',
            r'Stack trace:',
        ]
        
        return any(re.search(pattern, response_content) for pattern in stack_trace_patterns)


class OutputObfuscationDetector:
    OBFUSCATION_PATTERNS = [
        (r'[^\x20-\x7E]', 0.05),
        (r'\\x[0-9a-fA-F]{2}', 0.1),
        (r'&#\d+;', 0.1),
        (r'%[0-9a-fA-F]{2}', 0.08),
        (r'\x00', 0.2),
    ]
    
    @staticmethod
    def detect_obfuscation(response_content: str) -> Tuple[bool, float]:
        obfuscation_score = 0.0
        
        for pattern, weight in OutputObfuscationDetector.OBFUSCATION_PATTERNS:
            matches = len(re.findall(pattern, response_content))
            obfuscation_score += matches * weight
        
        obfuscation_score = min(obfuscation_score, 1.0)
        is_obfuscated = obfuscation_score > 0.3
        
        return is_obfuscated, obfuscation_score
    
    @staticmethod
    def detect_binary_output(response_content: str) -> bool:
        binary_threshold = sum(1 for c in response_content if ord(c) < 32 or ord(c) > 126)
        return binary_threshold > len(response_content) * 0.3


class CommandInjectionScanner:
    _remediation_cache = (
        "Avoid using system command execution functions. "
        "Use language-specific libraries instead of shell commands. "
        "Implement strict input validation with allowlists. "
        "Use parameterization/escaping for all inputs. "
        "Run application with minimal privileges. "
        "Disable dangerous system functions. "
        "Implement Web Application Firewall (WAF) rules. "
        "Use security context isolation (containers, sandboxes). "
        "Apply principle of least privilege. "
        "Sanitize all user inputs before processing. "
        "Use safe APIs that don't invoke shell interpreters."
    )
    
    def __init__(self):
        self.execution_detector = CommandExecutionDetector()
        self.timing_analyzer = TimingBasedCommandAnalyzer()
        self.separator_analyzer = SeparatorAnalyzer()
        self.filter_bypass_detector = FilterBypassDetector()
        self.shell_detector = ShellDetectionEngine()
        self.error_analyzer = ErrorBasedCommandAnalyzer()
        self.obfuscation_detector = OutputObfuscationDetector()
        
        self.vulnerabilities: List[CommandInjectionVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.baseline_responses: Dict[str, str] = {}
        self.baseline_times: Dict[str, float] = {}
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: List[str],
            baseline_response: Optional[str] = None, baseline_time: Optional[float] = None) -> List[CommandInjectionVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        if baseline_response is None:
            baseline_response = response_content
        
        if baseline_time is None:
            baseline_time = response_time
        
        parameter = self._extract_parameter_name(target_url)
        
        for payload in payloads:
            is_vulnerable, injection_type, evidence, confidence = self._test_payload(
                response_content,
                baseline_response,
                payload,
                response_time,
                baseline_time,
                status_code
            )
            
            if is_vulnerable:
                separators = self.separator_analyzer.detect_separators(payload)
                separator = separators[0] if separators else OSSeparator.SEMICOLON
                
                shell_type = self.shell_detector.detect_shell_type(response_content, payload)
                injected_command = self.separator_analyzer.extract_injected_command(payload, separator)
                bypass_techniques = self.filter_bypass_detector.detect_bypass_techniques(payload)
                
                command_executed, detected_commands, indicators = self.execution_detector.detect_command_execution(response_content)
                output_captured = '\n'.join(indicators[:10]) if indicators else None
                
                is_error, error_types, error_messages = self.error_analyzer.analyze_error_response(response_content)
                
                vuln = CommandInjectionVulnerability(
                    vulnerability_type='OS Command Injection',
                    injection_type=injection_type,
                    shell_type=shell_type,
                    url=target_url,
                    parameter=parameter,
                    payload=payload,
                    severity=self._calculate_severity(injection_type, command_executed, bypass_techniques),
                    evidence=evidence,
                    response_time=response_time,
                    command_executed=command_executed,
                    output_captured=output_captured,
                    executed_command=injected_command,
                    shell_detected=shell_type.value if shell_type else None,
                    confirmed=command_executed or (injection_type == CommandInjectionType.TIME_BASED and confidence > 0.9),
                    confidence_score=confidence,
                    bypass_techniques=bypass_techniques,
                    error_types=error_types if is_error else [],
                    indicators_found=indicators,
                    remediation=self._remediation_cache
                )
                
                if self._is_valid_vulnerability(vuln):
                    vulnerabilities.append(vuln)
                    
                    with self.lock:
                        self.scan_statistics[injection_type.value] += 1
                        self.scan_statistics['total'] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _test_payload(self, response_content: str, baseline_response: str, payload: str,
                     response_time: float, baseline_time: float, status_code: int) -> Tuple[bool, CommandInjectionType, str, float]:
        
        command_executed, commands, indicators = self.execution_detector.detect_command_execution(response_content)
        if command_executed and len(indicators) >= 2:
            confidence = min(0.85 + (len(indicators) * 0.05), 1.0)
            return True, CommandInjectionType.IN_BAND, f"Command execution detected: {', '.join(commands)} | Indicators: {', '.join(indicators[:5])}", confidence
        
        if self.execution_detector.detect_process_listing(response_content):
            return True, CommandInjectionType.IN_BAND, "Process listing detected (ps/tasklist output)", 0.9
        
        if self.execution_detector.detect_network_output(response_content):
            return True, CommandInjectionType.IN_BAND, "Network command output detected (netstat/ifconfig)", 0.88
        
        is_error, error_types, error_messages = self.error_analyzer.analyze_error_response(response_content)
        if is_error and len(error_types) >= 2:
            return True, CommandInjectionType.ERROR_BASED, f"Error-based injection: {', '.join(error_types)} | Messages: {', '.join(error_messages[:3])}", 0.75
        
        if self.error_analyzer.detect_stack_trace(response_content):
            return True, CommandInjectionType.ERROR_BASED, "Stack trace detected in response", 0.7
        
        if response_time > 3:
            is_delayed, time_diff, confidence = self.timing_analyzer.analyze_delay(baseline_time, response_time, 5)
            if is_delayed:
                return True, CommandInjectionType.TIME_BASED, f"Time-based injection confirmed: {time_diff:.2f}s delay (expected: 5s)", confidence / 100
        
        size_diff = abs(len(response_content) - len(baseline_response))
        if size_diff > 500:
            if any(indicator in response_content for indicator in ['drwx', 'total', 'Directory of', 'uid=']):
                return True, CommandInjectionType.IN_BAND, f"Significant response size change: {size_diff} bytes | Command output detected", 0.82
        
        bypass_techniques = self.filter_bypass_detector.detect_bypass_techniques(payload)
        obfuscation_complexity = self.filter_bypass_detector.calculate_obfuscation_complexity(payload)
        
        if len(bypass_techniques) >= 3 and obfuscation_complexity > 0.5:
            return True, CommandInjectionType.FILTER_BYPASS, f"Advanced filter bypass: {', '.join(bypass_techniques[:5])} | Complexity: {obfuscation_complexity:.2f}", 0.68
        
        is_obfuscated, obfuscation_score = self.obfuscation_detector.detect_obfuscation(response_content)
        if is_obfuscated and any(keyword in response_content for keyword in ['uid=', 'root', 'admin', '/home/', '/var/']):
            return True, CommandInjectionType.OUT_OF_BAND, f"Obfuscated command output detected | Score: {obfuscation_score:.2f}", 0.65
        
        if self.obfuscation_detector.detect_binary_output(response_content):
            return True, CommandInjectionType.OUT_OF_BAND, "Binary data detected in response", 0.6
        
        chain_count = self.separator_analyzer.detect_command_chaining(payload)
        if chain_count >= 3:
            return True, CommandInjectionType.STACKED_QUERIES, f"Stacked command execution detected: {chain_count} chained commands", 0.7
        
        return False, CommandInjectionType.BLIND_INJECTION, "", 0.0
    
    def _extract_parameter_name(self, url: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            return list(params.keys())[0]
        
        path_parts = parsed.path.split('/')
        return path_parts[-1] if path_parts else 'parameter'
    
    def _is_valid_vulnerability(self, vuln: CommandInjectionVulnerability) -> bool:
        if vuln.confidence_score < 0.55:
            return False
        
        false_positive_keywords = ['test', 'debug', 'sample', 'example', 'demo']
        if any(word in vuln.payload.lower() for word in false_positive_keywords):
            if not vuln.command_executed:
                return False
        
        if vuln.injection_type == CommandInjectionType.ERROR_BASED and not vuln.error_types:
            return False
        
        return vuln.confirmed or vuln.command_executed or vuln.confidence_score >= 0.8
    
    def _calculate_severity(self, injection_type: CommandInjectionType, command_executed: bool, bypass_techniques: List[str]) -> str:
        if command_executed:
            return 'Critical'
        
        if injection_type == CommandInjectionType.TIME_BASED:
            return 'High'
        
        if injection_type == CommandInjectionType.IN_BAND:
            return 'Critical'
        
        if len(bypass_techniques) >= 3:
            return 'High'
        
        if injection_type == CommandInjectionType.ERROR_BASED:
            return 'Medium'
        
        return 'Medium'
    
    def get_vulnerabilities(self) -> List[CommandInjectionVulnerability]:
        with self.lock:
            return self.vulnerabilities.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        with self.lock:
            return dict(self.scan_statistics)
    
    def set_baseline_response(self, parameter: str, response: str, response_time: float = 0.0):
        self.baseline_responses[parameter] = response
        self.baseline_times[parameter] = response_time
    
    def get_baseline_response(self, parameter: str) -> Optional[str]:
        return self.baseline_responses.get(parameter)
    
    def get_baseline_time(self, parameter: str) -> Optional[float]:
        return self.baseline_times.get(parameter)
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.baseline_responses.clear()
            self.baseline_times.clear()