from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time


class CommandInjectionType(Enum):
    IN_BAND = "in_band"
    OUT_OF_BAND = "out_of_band"
    BLIND_INJECTION = "blind_injection"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    FILTER_BYPASS = "filter_bypass"


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
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class CommandExecutionDetector:
    COMMAND_PATTERNS = {
        'ls': {
            'output_pattern': r'^([-d])([-r]){9}',
            'indicators': ['drwx', '-rw-', 'total'],
            'shell_types': [ShellType.BASH, ShellType.SH, ShellType.ZSH],
        },
        'id': {
            'output_pattern': r'uid=\d+.*gid=\d+',
            'indicators': ['uid=', 'gid=', 'groups='],
            'shell_types': [ShellType.BASH, ShellType.SH],
        },
        'whoami': {
            'output_pattern': r'^[a-zA-Z0-9_-]+$',
            'indicators': ['root', 'admin', 'www-data'],
            'shell_types': [ShellType.BASH, ShellType.SH],
        },
        'ipconfig': {
            'output_pattern': r'(?i)ipv4|ipv6|adapter',
            'indicators': ['IPv4', 'IPv6', 'Adapter'],
            'shell_types': [ShellType.CMD, ShellType.POWERSHELL],
        },
        'systeminfo': {
            'output_pattern': r'(?i)os name|os version',
            'indicators': ['OS Name', 'OS Version'],
            'shell_types': [ShellType.CMD, ShellType.POWERSHELL],
        },
    }
    
    @staticmethod
    def detect_command_execution(response_content: str) -> Tuple[bool, List[str], List[str]]:
        detected_commands = []
        indicators_found = []
        
        for command, config in CommandExecutionDetector.COMMAND_PATTERNS.items():
            pattern = config['output_pattern']
            indicators = config['indicators']
            
            if re.search(pattern, response_content, re.MULTILINE):
                detected_commands.append(command)
                
                for indicator in indicators:
                    if indicator in response_content:
                        indicators_found.append(indicator)
        
        return len(detected_commands) > 0, detected_commands, indicators_found


class TimingBasedCommandAnalyzer:
    DELAY_COMMANDS = {
        ShellType.BASH: 'sleep',
        ShellType.SH: 'sleep',
        ShellType.CMD: 'timeout',
        ShellType.POWERSHELL: 'Start-Sleep',
    }
    
    @staticmethod
    def analyze_delay(baseline_time: float, test_time: float,
                     expected_delay: int = 5) -> Tuple[bool, float, float]:
        time_difference = test_time - baseline_time
        threshold = expected_delay * 0.7
        
        is_delayed = time_difference >= threshold
        confidence = min((time_difference / (expected_delay * 1.5)) * 100, 100.0)
        
        return is_delayed, time_difference, confidence
    
    @staticmethod
    def extract_delay_command(payload: str, shell_type: ShellType) -> Optional[int]:
        delay_cmd = TimingBasedCommandAnalyzer.DELAY_COMMANDS.get(shell_type)
        
        if not delay_cmd:
            return None
        
        pattern = rf'{delay_cmd}\s+(\d+)'
        match = re.search(pattern, payload)
        
        return int(match.group(1)) if match else None


class SeparatorAnalyzer:
    SEPARATOR_PATTERNS = {
        OSSeparator.SEMICOLON: r';',
        OSSeparator.PIPE: r'\|(?!\|)',
        OSSeparator.PIPE_PIPE: r'\|\|',
        OSSeparator.AND: r'&(?!&)',
        OSSeparator.AND_AND: r'&&',
        OSSeparator.NEWLINE: r'\n',
        OSSeparator.BACKTICK: r'`',
        OSSeparator.DOLLAR_PAREN: r'\$\(',
    }
    
    @staticmethod
    def detect_separators(payload: str) -> List[OSSeparator]:
        found_separators = []
        
        for separator, pattern in SeparatorAnalyzer.SEPARATOR_PATTERNS.items():
            if re.search(pattern, payload):
                found_separators.append(separator)
        
        return found_separators
    
    @staticmethod
    def extract_injected_command(payload: str, separator: OSSeparator) -> Optional[str]:
        pattern = SeparatorAnalyzer.SEPARATOR_PATTERNS[separator]
        parts = re.split(pattern, payload)
        
        if len(parts) >= 2:
            return parts[-1].strip()
        
        return None


class FilterBypassDetector:
    BYPASS_TECHNIQUES = {
        'case_manipulation': r'[a-z]\*[a-z]',
        'backslash_escape': r'\\',
        'comment_injection': r'/\*\*/',
        'hex_encoding': r'\\x[0-9a-f]{2}',
        'octal_encoding': r'\\[0-7]{3}',
        'environment_variables': r'\$[A-Z_]+',
        'globbing': r'[*?[\]]',
        'brace_expansion': r'\{[^}]+,[^}]+\}',
    }
    
    @staticmethod
    def detect_bypass_techniques(payload: str) -> List[str]:
        detected_techniques = []
        
        for technique, pattern in FilterBypassDetector.BYPASS_TECHNIQUES.items():
            if re.search(pattern, payload, re.IGNORECASE):
                detected_techniques.append(technique)
        
        return detected_techniques


class ShellDetectionEngine:
    SHELL_INDICATORS = {
        ShellType.BASH: [
            r'bash.*version',
            r'\$BASH_VERSION',
            r'set -o',
            r'alias',
        ],
        ShellType.SH: [
            r'sh.*version',
            r'POSIX.*sh',
            r'sh: .+:',
        ],
        ShellType.CMD: [
            r'Microsoft Windows',
            r'cmd\.exe',
            r'C:\\',
            r'>',
        ],
        ShellType.POWERSHELL: [
            r'PowerShell',
            r'powershell\.exe',
            r'PS>',
            r'Get-ChildItem',
        ],
    }
    
    @staticmethod
    def detect_shell_type(response_content: str, payload: str) -> Optional[ShellType]:
        
        if 'ipconfig' in payload or 'systeminfo' in payload or 'tasklist' in payload:
            return ShellType.CMD
        
        if 'powershell' in payload.lower() or 'Get-' in payload:
            return ShellType.POWERSHELL
        
        if 'sleep' in payload or 'whoami' in payload or 'id' in payload:
            return ShellType.BASH
        
        for shell_type, indicators in ShellDetectionEngine.SHELL_INDICATORS.items():
            for indicator in indicators:
                if re.search(indicator, response_content, re.IGNORECASE):
                    return shell_type
        
        return ShellType.UNKNOWN
    
    @staticmethod
    def detect_shell_prompt(response_content: str) -> Optional[ShellType]:
        prompts = {
            r'\$\s*$|#\s*$': ShellType.BASH,
            r'>\s*$': ShellType.CMD,
            r'PS>': ShellType.POWERSHELL,
        }
        
        for pattern, shell_type in prompts.items():
            if re.search(pattern, response_content, re.MULTILINE):
                return shell_type
        
        return None


class ErrorBasedCommandAnalyzer:
    ERROR_PATTERNS = {
        'command_not_found': r"(?i)(command not found|'.*' is not recognized)",
        'permission_denied': r"(?i)(permission denied|access is denied)",
        'syntax_error': r"(?i)(syntax error|unexpected token)",
        'file_not_found': r"(?i)(no such file or directory|cannot find the path)",
    }
    
    @staticmethod
    def analyze_error_response(response_content: str) -> Tuple[bool, List[str]]:
        errors_found = []
        
        for error_type, pattern in ErrorBasedCommandAnalyzer.ERROR_PATTERNS.items():
            if re.search(pattern, response_content):
                errors_found.append(error_type)
        
        return len(errors_found) > 0, errors_found


class OutputObfuscationDetector:
    OBFUSCATION_PATTERNS = [
        r'[^\x20-\x7E]',
        r'\x00',
        r'\\x[0-9a-f]{2}',
        r'&#\d+;',
        r'%[0-9a-f]{2}',
    ]
    
    @staticmethod
    def detect_obfuscation(response_content: str) -> Tuple[bool, float]:
        obfuscation_score = 0.0
        
        for pattern in OutputObfuscationDetector.OBFUSCATION_PATTERNS:
            matches = len(re.findall(pattern, response_content))
            obfuscation_score += matches * 0.1
        
        is_obfuscated = obfuscation_score > 0.3
        obfuscation_score = min(obfuscation_score, 1.0)
        
        return is_obfuscated, obfuscation_score


class CommandInjectionScanner:
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
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: List[str],
            baseline_response: Optional[str] = None) -> List[CommandInjectionVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        if baseline_response is None:
            baseline_response = response_content
        
        parameter = self._extract_parameter_name(target_url)
        
        for payload in payloads:
            is_vulnerable, injection_type, evidence = self._test_payload(
                response_content,
                baseline_response,
                payload,
                response_time,
                status_code
            )
            
            if is_vulnerable:
                separators = self.separator_analyzer.detect_separators(payload)
                separator = separators[0] if separators else OSSeparator.SEMICOLON
                
                shell_type = self.shell_detector.detect_shell_type(response_content, payload)
                injected_command = self.separator_analyzer.extract_injected_command(payload, separator)
                bypass_techniques = self.filter_bypass_detector.detect_bypass_techniques(payload)
                
                command_executed, detected_commands, indicators = self.execution_detector.detect_command_execution(response_content)
                output_captured = '\n'.join(indicators[:5]) if indicators else None
                
                vuln = CommandInjectionVulnerability(
                    vulnerability_type='OS Command Injection',
                    injection_type=injection_type,
                    shell_type=shell_type,
                    url=target_url,
                    parameter=parameter,
                    payload=payload,
                    severity='Critical',
                    evidence=evidence,
                    response_time=response_time,
                    command_executed=command_executed,
                    output_captured=output_captured,
                    executed_command=injected_command,
                    shell_detected=shell_type.value if shell_type else None,
                    confirmed=command_executed,
                    remediation=self._get_remediation()
                )
                
                if self._is_valid_vulnerability(vuln):
                    vulnerabilities.append(vuln)
                    self.scan_statistics[injection_type.value] += 1
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _test_payload(self, response_content: str, baseline_response: str,
                     payload: str, response_time: float,
                     status_code: int) -> Tuple[bool, CommandInjectionType, str]:
        
        command_executed, commands, indicators = self.execution_detector.detect_command_execution(response_content)
        if command_executed and len(indicators) >= 2:
            return True, CommandInjectionType.IN_BAND, f"Command execution detected: {', '.join(indicators[:3])}"
        
        is_error, error_types = self.error_analyzer.analyze_error_response(response_content)
        if is_error:
            return True, CommandInjectionType.ERROR_BASED, f"Error-based injection detected: {', '.join(error_types)}"
        
        if response_time > 5:
            delay_cmd = self.timing_analyzer.extract_delay_command(payload, ShellType.BASH)
            if delay_cmd and response_time >= delay_cmd * 0.8:
                return True, CommandInjectionType.TIME_BASED, f"Time-based injection: {response_time:.2f}s delay"
        
        size_diff = abs(len(response_content) - len(baseline_response))
        if size_diff > 500 and 'total' in response_content and 'drwx' in response_content:
            return True, CommandInjectionType.IN_BAND, f"Directory listing detected (size diff: {size_diff} bytes)"
        
        bypass_techniques = self.filter_bypass_detector.detect_bypass_techniques(payload)
        if len(bypass_techniques) >= 2:
            return True, CommandInjectionType.FILTER_BYPASS, f"Filter bypass detected: {', '.join(bypass_techniques[:2])}"
        
        is_obfuscated, obfuscation_score = self.obfuscation_detector.detect_obfuscation(response_content)
        if is_obfuscated and 'uid=' in response_content:
            return True, CommandInjectionType.OUT_OF_BAND, "Obfuscated command output detected"
        
        return False, CommandInjectionType.BLIND_INJECTION, ""
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else 'parameter'
    
    def _is_valid_vulnerability(self, vuln: CommandInjectionVulnerability) -> bool:
        if vuln.confidence_score < 0.6:
            return False
        
        if any(word in vuln.payload.lower() for word in ['test', 'debug', 'sample']):
            return False
        
        return vuln.confirmed or vuln.command_executed
    
    def _get_remediation(self) -> str:
        return (
            "Avoid using system command execution functions. "
            "Use language-specific libraries instead of shell commands. "
            "Implement strict input validation with allowlists. "
            "Use parameterization/escaping for all inputs. "
            "Run application with minimal privileges. "
            "Disable dangerous system functions. "
            "Implement Web Application Firewall (WAF) rules. "
            "Use security context isolation (containers, sandboxes)."
        )
    
    def get_vulnerabilities(self) -> List[CommandInjectionVulnerability]:
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