from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time
import hashlib
import math


class SQLInjectionType(Enum):
    UNION_BASED = "union_based"
    ERROR_BASED = "error_based"
    TIME_BASED_BLIND = "time_based_blind"
    BOOLEAN_BASED_BLIND = "boolean_based_blind"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"
    SECOND_ORDER = "second_order"
    DIOS = "dios"
    REGRESSION = "regression"


class DatabaseType(Enum):
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MARIADB = "mariadb"
    MONGODB = "mongodb"
    CASSANDRA = "cassandra"
    DERBY = "derby"
    HSQLDB = "hsqldb"


class SQLPayloadType(Enum):
    AUTHENTICATION_BYPASS = "authentication_bypass"
    UNION_SELECT = "union_select"
    TIME_DELAY = "time_delay"
    BOOLEAN_CONDITION = "boolean_condition"
    INFORMATION_SCHEMA = "information_schema"
    DATA_EXFILTRATION = "data_exfiltration"
    STACKED_COMMAND = "stacked_command"
    COMMENT_BASED = "comment_based"
    ENCODING_BYPASS = "encoding_bypass"


@dataclass
class SQLPayload:
    payload: str
    injection_type: SQLInjectionType
    database_type: DatabaseType
    payload_type: SQLPayloadType
    severity: str = "Critical"
    detection_indicators: List[str] = field(default_factory=list)
    requires_data_confirmation: bool = True
    false_positive_risk: float = 0.15
    payload_hash: Optional[str] = None


@dataclass
class SQLVulnerability:
    vulnerability_type: str
    injection_type: SQLInjectionType
    database_type: Optional[DatabaseType]
    url: str
    parameter: str
    payload: str
    severity: str
    evidence: str
    response_time: float
    response_size_change: int
    error_message: str
    column_count: Optional[int] = None
    data_types: List[str] = field(default_factory=list)
    confirmed: bool = False
    confidence_score: float = 0.8
    extracted_data: Optional[str] = None
    database_fingerprint: Optional[Dict] = None
    table_structures: List[Dict] = field(default_factory=list)
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class ErrorMessageAnalyzer:
    ERROR_SIGNATURES = {
        DatabaseType.MYSQL: [
            re.compile(r'(?i)mysql.*error|mysql_fetch|mysql_num_rows', re.M),
            re.compile(r'(?i)sql syntax|check the manual', re.M),
            re.compile(r'(?i)column.*not.*found|unknown.*column', re.M),
            re.compile(r'(?i)table.*doesn\'t exist|unknown.*table', re.M),
            re.compile(r'(?i)syntax error near|sql syntax error', re.M),
        ],
        DatabaseType.POSTGRESQL: [
            re.compile(r'(?i)postgresql.*error|pg_|pgsql', re.M),
            re.compile(r'(?i)query failed|syntax error', re.M),
            re.compile(r'(?i)relation.*does.*not.*exist', re.M),
            re.compile(r'(?i)permission denied|access denied', re.M),
            re.compile(r'ERROR.*?syntax|ERROR.*?column', re.M),
        ],
        DatabaseType.MSSQL: [
            re.compile(r'(?i)mssql|microsoft sql server', re.M),
            re.compile(r'(?i)syntax error|incorrect syntax', re.M),
            re.compile(r'(?i)server: msg|level \d+, state \d+', re.M),
            re.compile(r'(?i)sql server.*error', re.M),
            re.compile(r"Msg \d+, Level \d+", re.M),
        ],
        DatabaseType.ORACLE: [
            re.compile(r'(?i)oracle.*error|ORA-\d+', re.M),
            re.compile(r'(?i)invalid sql|sql command not properly ended', re.M),
            re.compile(r'(?i)table or view does not exist', re.M),
            re.compile(r'ORA-\d+: .+', re.M),
        ],
        DatabaseType.SQLITE: [
            re.compile(r'(?i)sqlite.*error|database.*locked', re.M),
            re.compile(r'(?i)syntax error|near.*:', re.M),
            re.compile(r'(?i)no such table|table.*already exists', re.M),
        ],
    }
    
    @staticmethod
    def analyze_error_message(response_content: str) -> Tuple[bool, Optional[DatabaseType], List[str], float]:
        errors_found = []
        detected_database = None
        error_count = 0
        
        for db_type, patterns in ErrorMessageAnalyzer.ERROR_SIGNATURES.items():
            for pattern in patterns:
                matches = pattern.findall(response_content)
                if matches:
                    errors_found.extend(matches)
                    error_count += len(matches)
                    if not detected_database:
                        detected_database = db_type
        
        confidence = min(error_count * 0.15, 1.0)
        
        return len(errors_found) > 0, detected_database, list(set(errors_found)), confidence


class TimingAnalyzer:
    @staticmethod
    def analyze_timing(baseline_response_time: float, test_response_time: float,
                      delay_seconds: int = 5) -> Tuple[bool, float, float]:
        if baseline_response_time == 0:
            baseline_response_time = 0.1
        
        time_difference = test_response_time - baseline_response_time
        expected_minimum = delay_seconds * 0.7
        upper_threshold = delay_seconds * 1.3
        
        is_delayed = expected_minimum <= time_difference <= (delay_seconds + 5)
        
        if is_delayed:
            confidence = min((time_difference / delay_seconds) * 100, 100.0)
        else:
            confidence = 0.0
        
        return is_delayed, time_difference, confidence
    
    @staticmethod
    def detect_timing_consistency(response_times: List[float]) -> Tuple[bool, float]:
        if len(response_times) < 3:
            return False, 0.0
        
        avg_time = sum(response_times) / len(response_times)
        variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)
        std_dev = math.sqrt(variance)
        
        is_consistent = std_dev < avg_time * 0.2
        
        return is_consistent, std_dev


class UnionBasedDetector:
    HTML_PATTERNS = [
        re.compile(r'<table[^>]*>.*?</table>', re.DOTALL | re.I),
        re.compile(r'<tr[^>]*>.*?</tr>', re.DOTALL | re.I),
        re.compile(r'<td[^>]*>.*?</td>', re.DOTALL | re.I),
    ]
    
    @staticmethod
    def analyze_union_response(response_content: str, baseline_response: str) -> Tuple[bool, float, List[str]]:
        indicators = []
        confidence_score = 0.0
        
        union_keywords = response_content.upper().count('UNION') - baseline_response.upper().count('UNION')
        if union_keywords > 0:
            indicators.append(f'UNION keyword appears {union_keywords} additional times')
            confidence_score += 0.15
        
        select_keywords = response_content.upper().count('SELECT') - baseline_response.upper().count('SELECT')
        if select_keywords > 0:
            indicators.append(f'SELECT keyword appears {select_keywords} additional times')
            confidence_score += 0.10
        
        baseline_tables = len(re.findall(r'<table', baseline_response, re.I))
        response_tables = len(re.findall(r'<table', response_content, re.I))
        if response_tables > baseline_tables:
            indicators.append(f'Additional tables: {response_tables - baseline_tables}')
            confidence_score += 0.15
        
        baseline_rows = len(re.findall(r'<tr', baseline_response, re.I))
        response_rows = len(re.findall(r'<tr', response_content, re.I))
        if response_rows > baseline_rows + 2:
            indicators.append(f'Additional rows: {response_rows - baseline_rows}')
            confidence_score += 0.20
        
        response_lines = response_content.split('\n')
        baseline_lines = baseline_response.split('\n')
        line_diff = len(response_lines) - len(baseline_lines)
        
        if line_diff > 10:
            indicators.append(f'Structure change: {line_diff} additional lines')
            confidence_score += 0.15
        
        baseline_size = len(baseline_response)
        response_size = len(response_content)
        size_increase = (response_size - baseline_size) / max(baseline_size, 1)
        
        if 0.3 < size_increase < 5.0:
            indicators.append(f'Response size increased by {size_increase * 100:.1f}%')
            confidence_score += 0.10
        
        return len(indicators) > 0, confidence_score * 100, indicators
    
    @staticmethod
    def detect_column_count(response_content: str) -> Optional[int]:
        columns = len(re.findall(r'<td[^>]*>', response_content, re.I))
        rows = len(re.findall(r'<tr[^>]*>', response_content, re.I))
        
        if rows > 0 and columns > 0:
            return columns // rows
        
        return None


class BooleanBasedAnalyzer:
    @staticmethod
    def analyze_boolean_responses(true_response: str, false_response: str,
                                  test_response: str) -> Tuple[bool, float]:
        true_size = len(true_response)
        false_size = len(false_response)
        test_size = len(test_response)
        
        size_difference = abs(true_size - false_size)
        
        if size_difference < 50:
            return False, 0.0
        
        true_keywords = set(re.findall(r'\b\w+\b', true_response.lower()))
        false_keywords = set(re.findall(r'\b\w+\b', false_response.lower()))
        test_keywords = set(re.findall(r'\b\w+\b', test_response.lower()))
        
        true_match = len(true_keywords & test_keywords) / max(len(true_keywords), 1)
        false_match = len(false_keywords & test_keywords) / max(len(false_keywords), 1)
        
        match_difference = abs(true_match - false_match)
        
        if match_difference < 0.2:
            return False, 0.0
        
        if true_size == test_size:
            return True, 85.0
        
        if false_size == test_size:
            return True, 75.0
        
        similarity_score = abs(true_match - false_match) * 100
        
        return similarity_score > 30, min(similarity_score, 95.0)


class DataExtractionAnalyzer:
    EXTRACTION_PATTERNS = {
        'usernames': re.compile(r'\b(?:admin|root|user|administrator|guest|test|demo)\b', re.I),
        'emails': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', re.I),
        'passwords': re.compile(r'(?i)(?:password|passwd|pwd|secret|pass)\s*[:=\s]+([^\s,;]+)', re.I),
        'ip_addresses': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        'phone_numbers': re.compile(r'\b(?:\+?1[-.]?)?\(?(?:[0-9]{3})\)?[-.]?(?:[0-9]{3})[-.]?(?:[0-9]{4})\b'),
        'credit_cards': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        'api_keys': re.compile(r'(?i)(?:api[_-]?key|token|secret|apikey)\s*[:=\s]+([^\s,;\'\"]+)', re.I),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'database_names': re.compile(r'(?i)(?:database|db|schema)\s*[:=\s]+([^\s,;\'\"]+)', re.I),
        'table_names': re.compile(r'(?i)(?:table|tbl)\s*[:=\s]+([^\s,;\'\"]+)', re.I),
    }
    
    @staticmethod
    def extract_sensitive_data(response_content: str) -> Dict[str, List[str]]:
        extracted = {}
        
        for data_type, pattern in DataExtractionAnalyzer.EXTRACTION_PATTERNS.items():
            matches = pattern.findall(response_content)
            if matches:
                unique_matches = list(set(matches))[:20]
                extracted[data_type] = unique_matches
        
        return extracted
    
    @staticmethod
    def calculate_data_extraction_risk(extracted_data: Dict[str, List[str]]) -> float:
        sensitive_fields = ['passwords', 'credit_cards', 'ssn', 'api_keys']
        sensitive_count = sum(len(v) for k, v in extracted_data.items() if k in sensitive_fields)
        
        total_count = sum(len(v) for v in extracted_data.values())
        
        if total_count == 0:
            return 0.0
        
        return (sensitive_count / total_count) * 100


class PayloadMutationEngine:
    WHITESPACE_REPLACEMENTS = [
        ('/**/', ' ', 'comment'),
        ('%20', ' ', 'url_space'),
        ('%09', ' ', 'tab'),
        ('%0a', ' ', 'newline'),
        ('%0d', ' ', 'carriage_return'),
        ('%0c', ' ', 'form_feed'),
        ('/*!50000 */', ' ', 'mysql_version'),
    ]
    
    CASE_VARIATIONS = [
        'UNION', 'Union', 'uNiOn', 'UnIoN',
        'SELECT', 'Select', 'sElEcT', 'SeLeCt',
    ]
    
    @staticmethod
    def generate_mutations(base_payload: str, injection_type: SQLInjectionType) -> List[str]:
        mutations = [base_payload]
        mutation_set = {hashlib.md5(base_payload.encode()).hexdigest()}
        
        for replacement, original, name in PayloadMutationEngine.WHITESPACE_REPLACEMENTS:
            mutated = base_payload.replace(original, replacement)
            mutated_hash = hashlib.md5(mutated.encode()).hexdigest()
            if mutated_hash not in mutation_set:
                mutations.append(mutated)
                mutation_set.add(mutated_hash)
        
        for case_variant in PayloadMutationEngine.CASE_VARIATIONS:
            original = case_variant.upper()
            mutated = base_payload.replace(original, case_variant)
            mutated_hash = hashlib.md5(mutated.encode()).hexdigest()
            if mutated_hash not in mutation_set:
                mutations.append(mutated)
                mutation_set.add(mutated_hash)
        
        if injection_type == SQLInjectionType.UNION_BASED:
            mutations.extend([
                base_payload.replace('UNION', 'union all'),
                base_payload.replace('UNION', 'UNION DISTINCT'),
                base_payload.replace('SELECT', '/*!50000SELECT*/'),
                base_payload.replace('SELECT', '/*!50001SELECT*/'),
            ])
        
        elif injection_type == SQLInjectionType.TIME_BASED_BLIND:
            replacements = {
                'SLEEP': ['BENCHMARK', 'WAITFOR', 'PG_SLEEP', 'pg_sleep', 'DBMS_LOCK.SLEEP'],
                'SLEEP(5)': ['BENCHMARK(10000000,MD5("a"))', 'WAITFOR DELAY \'00:00:05\''],
            }
            
            for original, variants in replacements.items():
                for variant in variants:
                    mutated = base_payload.replace(original, variant)
                    mutated_hash = hashlib.md5(mutated.encode()).hexdigest()
                    if mutated_hash not in mutation_set:
                        mutations.append(mutated)
                        mutation_set.add(mutated_hash)
        
        elif injection_type == SQLInjectionType.BOOLEAN_BASED_BLIND:
            mutations.extend([
                base_payload.replace('1=1', '\'\'=\'\''),
                base_payload.replace('1=1', 'true'),
                base_payload.replace('1=2', 'false'),
            ])
        
        return mutations[:30]


class DatabaseFingerprinting:
    VERSION_PATTERNS = {
        DatabaseType.MYSQL: re.compile(r'mysql\s*(?:version\s+)?(\d+\.\d+\.\d+)', re.I),
        DatabaseType.POSTGRESQL: re.compile(r'PostgreSQL\s+(\d+\.\d+)', re.I),
        DatabaseType.MSSQL: re.compile(r'Microsoft SQL Server\s+(\d+)', re.I),
        DatabaseType.ORACLE: re.compile(r'Oracle\s+.*?Release\s+(\d+\.\d+)', re.I),
        DatabaseType.SQLITE: re.compile(r'SQLite\s+(?:version\s+)?(\d+\.\d+\.\d+)', re.I),
    }
    
    TABLE_PATTERNS = {
        'common_tables': re.compile(r'\b(?:users|admin|accounts|products|orders|customers|employees|departments)\b', re.I),
        'system_tables': re.compile(r'\b(?:information_schema|sys|pg_catalog|dba_tables)\b', re.I),
    }
    
    @staticmethod
    def fingerprint_database(response_content: str, detected_db: Optional[DatabaseType]) -> Dict[str, any]:
        fingerprint = {
            'database_type': detected_db.value if detected_db else None,
            'version': None,
            'tables': [],
            'columns': [],
            'users': [],
            'system_info': {},
        }
        
        if detected_db and detected_db in DatabaseFingerprinting.VERSION_PATTERNS:
            pattern = DatabaseFingerprinting.VERSION_PATTERNS[detected_db]
            match = pattern.search(response_content)
            if match:
                fingerprint['version'] = match.group(1)
        
        common_tables = DatabaseFingerprinting.TABLE_PATTERNS['common_tables'].findall(response_content)
        fingerprint['tables'] = list(set(common_tables))[:15]
        
        system_tables = DatabaseFingerprinting.TABLE_PATTERNS['system_tables'].findall(response_content)
        fingerprint['system_info']['system_tables'] = list(set(system_tables))[:10]
        
        column_pattern = re.compile(r'(?i)(?:column|field|attribute)\s+([a-zA-Z_]\w*)', re.I)
        columns = column_pattern.findall(response_content)
        fingerprint['columns'] = list(set(columns))[:20]
        
        return fingerprint


class SQLScanner:
    _remediation_cache = (
        "Use parameterized queries/prepared statements exclusively. "
        "Implement strict input validation with allowlists. "
        "Apply proper output encoding based on context. "
        "Use ORM frameworks that provide built-in SQL injection protection. "
        "Implement least privilege database access with restricted user accounts. "
        "Monitor database queries for suspicious patterns. "
        "Use Web Application Firewall (WAF) with SQL injection rules. "
        "Implement comprehensive logging and audit trails. "
        "Conduct regular security testing and code reviews. "
        "Keep database software updated with latest security patches. "
        "Disable dangerous functions (xp_cmdshell, FILE, INTO OUTFILE). "
        "Use error handling to avoid exposing database errors to users."
    )
    
    def __init__(self):
        self.error_analyzer = ErrorMessageAnalyzer()
        self.timing_analyzer = TimingAnalyzer()
        self.union_detector = UnionBasedDetector()
        self.boolean_analyzer = BooleanBasedAnalyzer()
        self.data_extractor = DataExtractionAnalyzer()
        self.mutation_engine = PayloadMutationEngine()
        self.fingerprinting = DatabaseFingerprinting()
        
        self.vulnerabilities: List[SQLVulnerability] = []
        self.scan_statistics = defaultdict(int)
        self.baseline_responses: Dict[str, str] = {}
        self.timing_baselines: Dict[str, List[float]] = defaultdict(list)
        self.tested_payloads: Set[str] = set()
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: List[str],
            baseline_response: Optional[str] = None, baseline_time: Optional[float] = None) -> List[SQLVulnerability]:
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
            
            is_vulnerable, injection_type, detected_db, evidence, confidence = self._test_payload(
                response_content,
                baseline_response,
                payload,
                response_time,
                baseline_time,
                status_code
            )
            
            if is_vulnerable:
                extracted_data = self.data_extractor.extract_sensitive_data(response_content)
                extraction_risk = self.data_extractor.calculate_data_extraction_risk(extracted_data)
                database_fingerprint = self.fingerprinting.fingerprint_database(response_content, detected_db)
                column_count = self.union_detector.detect_column_count(response_content)
                
                vuln = SQLVulnerability(
                    vulnerability_type='SQL Injection',
                    injection_type=injection_type,
                    database_type=detected_db,
                    url=target_url,
                    parameter=parameter,
                    payload=payload,
                    severity=self._determine_severity(injection_type, extraction_risk),
                    evidence=evidence,
                    response_time=response_time,
                    response_size_change=len(response_content) - len(baseline_response),
                    error_message=self._extract_error_message(response_content),
                    column_count=column_count,
                    confirmed=True,
                    confidence_score=confidence,
                    extracted_data=str(extracted_data) if extracted_data else None,
                    database_fingerprint=database_fingerprint,
                    remediation=self._remediation_cache
                )
                
                if self._is_valid_vulnerability(vuln):
                    vulnerabilities.append(vuln)
                    
                    with self.lock:
                        self.scan_statistics[injection_type.value] += 1
            
            mutations = self.mutation_engine.generate_mutations(payload, injection_type if injection_type else SQLInjectionType.UNION_BASED)
            
            for idx, mutation in enumerate(mutations[1:], 1):
                mutation_hash = hashlib.md5(mutation.encode()).hexdigest()
                
                if mutation_hash in self.tested_payloads:
                    continue
                
                with self.lock:
                    self.tested_payloads.add(mutation_hash)
                
                is_vulnerable, injection_type, detected_db, evidence, confidence = self._test_payload(
                    response_content,
                    baseline_response,
                    mutation,
                    response_time,
                    baseline_time,
                    status_code
                )
                
                if is_vulnerable and not any(v.payload == mutation for v in vulnerabilities):
                    extracted_data = self.data_extractor.extract_sensitive_data(response_content)
                    extraction_risk = self.data_extractor.calculate_data_extraction_risk(extracted_data)
                    
                    vuln = SQLVulnerability(
                        vulnerability_type='SQL Injection',
                        injection_type=injection_type,
                        database_type=detected_db,
                        url=target_url,
                        parameter=parameter,
                        payload=mutation,
                        severity=self._determine_severity(injection_type, extraction_risk),
                        evidence=evidence,
                        response_time=response_time,
                        response_size_change=len(response_content) - len(baseline_response),
                        error_message=self._extract_error_message(response_content),
                        database_fingerprint=self.fingerprinting.fingerprint_database(response_content, detected_db),
                        confirmed=True,
                        confidence_score=confidence,
                        remediation=self._remediation_cache
                    )
                    
                    vulnerabilities.append(vuln)
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
            self.scan_statistics['total_scans'] += 1
        
        return vulnerabilities
    
    def _test_payload(self, response_content: str, baseline_response: str, payload: str,
                     response_time: float, baseline_time: float, status_code: int) -> Tuple[bool, Optional[SQLInjectionType], Optional[DatabaseType], str, float]:
        
        is_error, detected_db, errors, error_confidence = self.error_analyzer.analyze_error_message(response_content)
        if is_error and error_confidence > 0.5:
            confidence = min(error_confidence + 0.2, 1.0)
            return True, SQLInjectionType.ERROR_BASED, detected_db, str(errors[0]), confidence
        
        is_union, union_confidence, indicators = self.union_detector.analyze_union_response(
            response_content,
            baseline_response
        )
        if is_union and union_confidence > 40:
            return True, SQLInjectionType.UNION_BASED, detected_db, str(indicators[0] if indicators else 'Union detected'), union_confidence / 100
        
        is_delayed, time_diff, timing_confidence = self.timing_analyzer.analyze_timing(baseline_time, response_time, 5)
        if is_delayed and timing_confidence > 70:
            return True, SQLInjectionType.TIME_BASED_BLIND, detected_db, f"Delay: {time_diff:.2f}s", timing_confidence / 100
        
        is_boolean, boolean_confidence = self.boolean_analyzer.analyze_boolean_responses(
            baseline_response,
            response_content,
            response_content
        )
        if is_boolean and boolean_confidence > 60:
            return True, SQLInjectionType.BOOLEAN_BASED_BLIND, detected_db, f"Boolean: {boolean_confidence:.1f}%", boolean_confidence / 100
        
        if 'STACK' in payload.upper() or ';DROP' in payload.upper():
            if status_code in [200, 500]:
                return True, SQLInjectionType.STACKED_QUERIES, detected_db, "Stacked query", 0.75
        
        if response_content != baseline_response and len(response_content) > len(baseline_response) * 2:
            size_factor = len(response_content) / max(len(baseline_response), 1)
            confidence = min(size_factor * 0.3, 0.8)
            if confidence > 0.6:
                return True, SQLInjectionType.DIOS, detected_db, f"Large response detected", confidence
        
        return False, None, detected_db, "", 0.0
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            return list(params.keys())[0]
        
        path_parts = parsed.path.split('/')
        return path_parts[-1] if path_parts and path_parts[-1] else 'parameter'
    
    def _extract_error_message(self, response_content: str) -> str:
        error_patterns = [
            re.compile(r'(?i)(error|exception|fatal|syntax|ORA-\d+|Msg \d+)\s*[:\-]?\s*(.{0,100})', re.M),
            re.compile(r'(?i)<(?:h[1-6]|div|p)>.*?(error|exception).*?</(?:h[1-6]|div|p)>', re.I | re.S),
        ]
        
        for pattern in error_patterns:
            matches = pattern.findall(response_content)
            if matches:
                if isinstance(matches[0], tuple):
                    return matches[0][-1][:150]
                else:
                    return str(matches[0])[:150]
        
        return ""
    
    def _determine_severity(self, injection_type: Optional[SQLInjectionType], extraction_risk: float = 0.0) -> str:
        if extraction_risk > 50:
            return 'Critical'
        
        severity_map = {
            SQLInjectionType.UNION_BASED: 'Critical',
            SQLInjectionType.ERROR_BASED: 'High',
            SQLInjectionType.TIME_BASED_BLIND: 'High',
            SQLInjectionType.BOOLEAN_BASED_BLIND: 'Medium',
            SQLInjectionType.STACKED_QUERIES: 'Critical',
            SQLInjectionType.OUT_OF_BAND: 'Critical',
            SQLInjectionType.SECOND_ORDER: 'High',
            SQLInjectionType.DIOS: 'High',
        }
        
        return severity_map.get(injection_type, 'High')
    
    def _is_valid_vulnerability(self, vuln: SQLVulnerability) -> bool:
        if vuln.confidence_score < 0.55:
            return False
        
        false_positive_keywords = ['test', 'debug', 'sample', 'example', 'demo', 'mock', 'bench']
        if any(word in vuln.payload.lower() for word in false_positive_keywords):
            if vuln.confidence_score < 0.8:
                return False
        
        return vuln.confirmed or vuln.confidence_score >= 0.75
    
    def get_vulnerabilities(self) -> List[SQLVulnerability]:
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
        if response_time > 0:
            self.timing_baselines[parameter].append(response_time)
    
    def get_baseline_response(self, parameter: str) -> Optional[str]:
        return self.baseline_responses.get(parameter)
    
    def get_baseline_timing(self, parameter: str) -> Optional[float]:
        times = self.timing_baselines.get(parameter, [])
        if times:
            return sum(times) / len(times)
        return None
    
    def clear(self):
        with self.lock:
            self.vulnerabilities.clear()
            self.scan_statistics.clear()
            self.baseline_responses.clear()
            self.timing_baselines.clear()
            self.tested_payloads.clear()