from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import threading
import time
from urllib.parse import urlparse, parse_qs
import base64
import hashlib

class CommandInjectionType(Enum):
    IN_BAND = "in_band"
    OUT_OF_BAND = "out_of_band"
    BLIND_INJECTION = "blind_injection"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    FILTER_BYPASS = "filter_bypass"
    DOUBLE_BLIND = "double_blind"
    STACKED_QUERIES = "stacked_queries"
    POLYGLOT = "polyglot"
    EXPRESSION_INJECTION = "expression_injection"

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
    false_positive_risk: float = 0.15

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

class MegaCommandDetector:
    PATTERNS = {
        'ls': {
            'regex': re.compile(r'^([-dlcbps])([-r][-w][-x]){3}'),
            'indicators': ['drwx', '-rw-', 'total', '-rwxr', 'lrwx', 'drwxr', 'drwxrwx'],
            'shells': [ShellType.BASH, ShellType.SH, ShellType.ZSH, ShellType.KSH],
        },
        'dir': {
            'regex': re.compile(r'(?i)Directory of|Volume in drive|<DIR>|\d{2}/\d{2}/\d{4}'),
            'indicators': ['Directory of', '<DIR>', 'Volume', 'bytes free'],
            'shells': [ShellType.CMD],
        },
        'id': {
            'regex': re.compile(r'uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)'),
            'indicators': ['uid=', 'gid=', 'groups=', 'context='],
            'shells': [ShellType.BASH, ShellType.SH, ShellType.ZSH],
        },
        'whoami': {
            'regex': re.compile(r'^[a-zA-Z0-9_\-]+$', re.MULTILINE),
            'indicators': ['root', 'admin', 'www-data', 'nginx', 'apache', 'nobody', 'system'],
            'shells': [ShellType.BASH, ShellType.SH, ShellType.CMD, ShellType.POWERSHELL],
        },
        'pwd': {
            'regex': re.compile(r'^/[\w/\-\.]+$', re.MULTILINE),
            'indicators': ['/home/', '/var/', '/usr/', '/opt/', '/etc/', '/root/'],
            'shells': [ShellType.BASH, ShellType.SH, ShellType.ZSH],
        },
        'ipconfig': {
            'regex': re.compile(r'(?i)IPv[46] Address|Subnet Mask|Default Gateway|Ethernet adapter'),
            'indicators': ['IPv4', 'IPv6', 'Adapter', 'Subnet Mask', 'Default Gateway', 'DNS Servers'],
            'shells': [ShellType.CMD, ShellType.POWERSHELL],
        },
        'ifconfig': {
            'regex': re.compile(r'(?i)inet\s+(?:addr:)?\d+\.\d+\.\d+\.\d+'),
            'indicators': ['inet ', 'ether ', 'netmask', 'broadcast', 'inet6'],
            'shells': [ShellType.BASH, ShellType.SH],
        },
        'systeminfo': {
            'regex': re.compile(r'(?i)OS Name|OS Version|System Type|Processor\(s\)'),
            'indicators': ['OS Name', 'OS Version', 'System Type', 'Processor', 'Total Physical Memory'],
            'shells': [ShellType.CMD, ShellType.POWERSHELL],
        },
        'uname': {
            'regex': re.compile(r'(?i)linux|darwin|freebsd|sunos|netbsd'),
            'indicators': ['Linux', 'Darwin', 'GNU', 'x86_64', 'aarch64', 'armv7l'],
            'shells': [ShellType.BASH, ShellType.SH, ShellType.ZSH],
        },
        'cat': {
            'regex': re.compile(r'(?s).{10,}'),
            'indicators': ['root:', 'bin:', 'daemon:', 'etc/', 'var/', 'usr/'],
            'shells': [ShellType.BASH, ShellType.SH],
        },
        'ps': {
            'regex': re.compile(r'PID\s+TTY\s+TIME\s+CMD|USER\s+PID\s+%CPU'),
            'indicators': ['PID', 'TTY', 'CMD', '%CPU', '%MEM'],
            'shells': [ShellType.BASH, ShellType.SH, ShellType.ZSH],
        },
        'tasklist': {
            'regex': re.compile(r'(?i)Image Name\s+PID\s+Session Name'),
            'indicators': ['Image Name', 'PID', 'Session Name', 'Mem Usage'],
            'shells': [ShellType.CMD, ShellType.POWERSHELL],
        },
        'netstat': {
            'regex': re.compile(r'(?i)(?:tcp|udp)\s+\d+\s+\d+\.\d+\.\d+\.\d+:\d+'),
            'indicators': ['ESTABLISHED', 'LISTENING', 'Proto', 'Local Address', 'Foreign Address'],
            'shells': [ShellType.BASH, ShellType.SH, ShellType.CMD, ShellType.POWERSHELL],
        },
        'hostname': {
            'regex': re.compile(r'^[a-zA-Z0-9\-\.]+$', re.MULTILINE),
            'indicators': ['server', 'host', 'localhost', 'web', 'prod'],
            'shells': [ShellType.BASH, ShellType.SH, ShellType.CMD],
        },
    }
    
    @staticmethod
    def detect_all(response: str) -> Tuple[bool, List[str], List[str]]:
        cmds = []
        inds = []
        
        for cmd, config in MegaCommandDetector.PATTERNS.items():
            if config['regex'].search(response):
                cmds.append(cmd)
                for ind in config['indicators']:
                    if ind in response:
                        inds.append(ind)
        
        return bool(cmds), cmds, list(set(inds))

class AdvancedTimingAnalyzer:
    @staticmethod
    def analyze_delay(baseline: float, test: float, expected: int = 5) -> Tuple[bool, float, float]:
        diff = test - baseline
        threshold = expected * 0.65
        upper = expected * 1.4
        
        is_delayed = threshold <= diff <= (expected + 12)
        confidence = min((diff / expected) * 95, 99.0) if is_delayed else 0.0
        
        return is_delayed, diff, confidence
    
    @staticmethod
    def detect_timing_patterns(times: List[float]) -> Tuple[bool, float]:
        if len(times) < 3:
            return False, 0.0
        
        avg = sum(times) / len(times)
        variance = sum((t - avg) ** 2 for t in times) / len(times)
        std_dev = variance ** 0.5
        
        return std_dev > 1.8, std_dev

class MegaSeparatorAnalyzer:
    SEPARATORS = {
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
    def detect(payload: str) -> List[OSSeparator]:
        found = []
        for sep, pattern in MegaSeparatorAnalyzer.SEPARATORS.items():
            if pattern.search(payload):
                found.append(sep)
        return found
    
    @staticmethod
    def extract_command(payload: str, sep: OSSeparator) -> Optional[str]:
        pattern = MegaSeparatorAnalyzer.SEPARATORS[sep]
        parts = pattern.split(payload)
        
        if len(parts) >= 2:
            cmd = parts[-1].strip()
            if cmd.endswith(')'):
                cmd = cmd[:-1].strip()
            return cmd
        return None
    
    @staticmethod
    def count_chaining(payload: str) -> int:
        count = 0
        for pattern in MegaSeparatorAnalyzer.SEPARATORS.values():
            count += len(pattern.findall(payload))
        return count

class MegaBypassDetector:
    TECHNIQUES = {
        'case_manipulation': re.compile(r'(?:[a-z]\*[a-z]|[A-Z]\*[A-Z])'),
        'backslash_escape': re.compile(r'\\[a-z]'),
        'comment_injection': re.compile(r'/\*\*/|<!--.*-->|#.*$'),
        'hex_encoding': re.compile(r'\\x[0-9a-fA-F]{2}'),
        'octal_encoding': re.compile(r'\\[0-7]{3}'),
        'environment_var': re.compile(r'\$[A-Z_]+|\${[^}]+}'),
        'globbing': re.compile(r'[*?[\]]'),
        'brace_expansion': re.compile(r'\{[^}]+,[^}]+\}'),
        'unicode_escape': re.compile(r'\\u[0-9a-fA-F]{4}'),
        'base64': re.compile(r'(?:echo|printf)\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64'),
        'variable_expansion': re.compile(r'\$\{[^}]+\}'),
        'null_byte': re.compile(r'%00|\\0'),
        'wildcard_obfuscation': re.compile(r'\$\{\w+//'),
        'double_encoding': re.compile(r'%25[0-9a-fA-F]{2}'),
        'concatenation': re.compile(r'["\']?\+["\']?'),
        'quoting': re.compile(r'["\'][^"\']*["\']'),
    }
    
    @staticmethod
    def detect(payload: str) -> List[str]:
        found = []
        for tech, pattern in MegaBypassDetector.TECHNIQUES.items():
            if pattern.search(payload):
                found.append(tech)
        return found
    
    @staticmethod
    def complexity_score(payload: str) -> float:
        score = 0.0
        
        techs = MegaBypassDetector.detect(payload)
        score += len(techs) * 0.18
        
        special = len(re.findall(r'[^a-zA-Z0-9\s]', payload))
        score += min(special / 8, 0.35)
        
        encoding_layers = len(re.findall(r'(?:base64|hex|oct|\\x|\\u)', payload))
        score += encoding_layers * 0.12
        
        return min(score, 1.0)

class MegaShellDetector:
    INDICATORS = {
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
    
    CMD_MAPPING = {
        'ipconfig': ShellType.CMD,
        'systeminfo': ShellType.CMD,
        'tasklist': ShellType.CMD,
        'dir': ShellType.CMD,
        'Get-': ShellType.POWERSHELL,
        'Set-': ShellType.POWERSHELL,
        'ls': ShellType.BASH,
        'cat': ShellType.BASH,
        'grep': ShellType.BASH,
        'id': ShellType.BASH,
        'whoami': ShellType.BASH,
        'pwd': ShellType.BASH,
        'uname': ShellType.BASH,
    }
    
    @staticmethod
    def detect(response: str, payload: str) -> Optional[ShellType]:
        for cmd, shell in MegaShellDetector.CMD_MAPPING.items():
            if cmd in payload:
                return shell
        
        for shell, indicators in MegaShellDetector.INDICATORS.items():
            for ind in indicators:
                if ind.search(response):
                    return shell
        
        return ShellType.UNKNOWN

class MegaErrorAnalyzer:
    ERRORS = {
        'command_not_found': re.compile(r"(?i)(command not found|'.*' is not recognized|No such file or directory)"),
        'permission_denied': re.compile(r"(?i)(permission denied|access is denied|operation not permitted)"),
        'syntax_error': re.compile(r"(?i)(syntax error|unexpected token|parse error|invalid syntax)"),
        'file_not_found': re.compile(r"(?i)(cannot find (?:the )?(?:path|file)|no such file|does not exist)"),
        'shell_error': re.compile(r"(?i)(sh:|bash:|cmd:|powershell:)"),
        'execution_error': re.compile(r"(?i)(cannot execute|execution failed|unable to run)"),
        'segmentation_fault': re.compile(r"(?i)(segmentation fault|core dumped)"),
        'access_violation': re.compile(r"(?i)(access violation|memory.*error)"),
    }
    
    @staticmethod
    def analyze(response: str) -> Tuple[bool, List[str], List[str]]:
        errors = []
        messages = []
        
        for etype, pattern in MegaErrorAnalyzer.ERRORS.items():
            matches = pattern.findall(response)
            if matches:
                errors.append(etype)
                messages.extend(matches[:2])
        
        return bool(errors), errors, messages

class CommandInjectionScanner:
    def __init__(self, max_workers: int = 18):
        self.cmd_detector = MegaCommandDetector()
        self.timing_analyzer = AdvancedTimingAnalyzer()
        self.sep_analyzer = MegaSeparatorAnalyzer()
        self.bypass_detector = MegaBypassDetector()
        self.shell_detector = MegaShellDetector()
        self.error_analyzer = MegaErrorAnalyzer()
        
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.max_workers = max_workers
    
    def scan(self, url: str, response: Dict, payloads: List[str],
            baseline_response: Optional[str] = None, baseline_time: Optional[float] = None) -> List[CommandInjectionVulnerability]:
        vulns = []
        content = response.get('content', '')
        resp_time = response.get('response_time', 0)
        status = response.get('status_code', 0)
        
        if baseline_response is None:
            baseline_response = content
        if baseline_time is None:
            baseline_time = resp_time
        
        param = self._extract_param(url)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for payload in payloads:
                future = executor.submit(
                    self._test_payload,
                    url, param, payload, content, baseline_response, resp_time, baseline_time, status
                )
                futures.append(future)
            
            for future in as_completed(futures):
                vuln = future.result()
                if vuln:
                    vulns.append(vuln)
        
        with self.lock:
            self.vulnerabilities.extend(vulns)
        
        return vulns
    
    def _test_payload(self, url, param, payload, content, baseline, resp_time, base_time, status):
        is_vuln, inj_type, evidence, confidence = self._analyze(
            content, baseline, payload, resp_time, base_time, status
        )
        
        if not is_vuln:
            return None
        
        seps = self.sep_analyzer.detect(payload)
        sep = seps[0] if seps else OSSeparator.SEMICOLON
        
        shell = self.shell_detector.detect(content, payload)
        cmd = self.sep_analyzer.extract_command(payload, sep)
        bypass = self.bypass_detector.detect(payload)
        
        cmd_executed, cmds, inds = self.cmd_detector.detect_all(content)
        output = '\n'.join(inds[:12]) if inds else None
        
        is_error, errors, msgs = self.error_analyzer.analyze(content)
        
        severity = self._calc_severity(inj_type, cmd_executed, bypass)
        
        return CommandInjectionVulnerability(
            vulnerability_type='Command Injection',
            injection_type=inj_type,
            shell_type=shell,
            url=url,
            parameter=param,
            payload=payload,
            severity=severity,
            evidence=evidence,
            response_time=resp_time,
            command_executed=cmd_executed,
            output_captured=output,
            executed_command=cmd,
            shell_detected=shell.value if shell else None,
            confirmed=cmd_executed or (inj_type == CommandInjectionType.TIME_BASED and confidence > 0.88),
            confidence_score=confidence,
            bypass_techniques=bypass,
            error_types=errors if is_error else [],
            indicators_found=inds,
            remediation=self._remediation()
        )
    
    def _analyze(self, content, baseline, payload, resp_time, base_time, status):
        cmd_exec, cmds, inds = self.cmd_detector.detect_all(content)
        if cmd_exec and len(inds) >= 2:
            conf = min(0.87 + (len(inds) * 0.04), 0.99)
            return True, CommandInjectionType.IN_BAND, f"Cmd exec: {', '.join(cmds)} | Inds: {', '.join(inds[:6])}", conf
        
        is_err, errors, msgs = self.error_analyzer.analyze(content)
        if is_err and len(errors) >= 2:
            return True, CommandInjectionType.ERROR_BASED, f"Errors: {', '.join(errors)} | {', '.join(msgs[:3])}", 0.77
        
        if resp_time > 3:
            delayed, diff, conf = self.timing_analyzer.analyze_delay(base_time, resp_time, 5)
            if delayed:
                return True, CommandInjectionType.TIME_BASED, f"Time-based: {diff:.2f}s delay (expected 5s)", conf / 100
        
        size_diff = abs(len(content) - len(baseline))
        if size_diff > 600:
            if any(x in content for x in ['drwx', 'total', 'uid=', 'Directory']):
                return True, CommandInjectionType.IN_BAND, f"Size change: {size_diff}B | Cmd output", 0.84
        
        bypass = self.bypass_detector.detect(payload)
        complexity = self.bypass_detector.complexity_score(payload)
        
        if len(bypass) >= 3 and complexity > 0.5:
            return True, CommandInjectionType.FILTER_BYPASS, f"Bypass: {', '.join(bypass[:6])} | Complexity: {complexity:.2f}", 0.71
        
        chain = self.sep_analyzer.count_chaining(payload)
        if chain >= 3:
            return True, CommandInjectionType.STACKED_QUERIES, f"Stacked: {chain} chained cmds", 0.72
        
        return False, CommandInjectionType.BLIND_INJECTION, "", 0.0
    
    def _calc_severity(self, inj_type, cmd_exec, bypass):
        if cmd_exec:
            return 'Critical'
        if inj_type == CommandInjectionType.TIME_BASED:
            return 'High'
        if inj_type == CommandInjectionType.IN_BAND:
            return 'Critical'
        if len(bypass) >= 3:
            return 'High'
        return 'Medium'
    
    def _extract_param(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            return list(params.keys())[0]
        path = parsed.path.split('/')
        return path[-1] if path else 'parameter'
    
    def _remediation(self):
        return (
            "1. Avoid system() calls - use language libraries. "
            "2. Input validation with strict allowlists. "
            "3. Parameterization + escaping. "
            "4. Run with minimal privileges. "
            "5. Disable dangerous functions. "
            "6. WAF rules for command patterns. "
            "7. Container/sandbox isolation. "
            "8. Least privilege principle. "
            "9. Sanitize ALL inputs. "
            "10. Safe APIs (no shell invocation)."
        )
    
    def get_vulnerabilities(self):
        with self.lock: return self.vulnerabilities.copy()
    
    def clear(self):
        with self.lock: self.vulnerabilities.clear()
