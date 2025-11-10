from typing import Dict, List, Optional, Tuple, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import threading
import time


class SQLInjectionType(Enum):
    UNION_BASED = "union_based"
    ERROR_BASED = "error_based"
    TIME_BASED_BLIND = "time_based_blind"
    BOOLEAN_BASED_BLIND = "boolean_based_blind"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"
    SECOND_ORDER = "second_order"


class DatabaseType(Enum):
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MARIADB = "mariadb"
    MONGODB = "mongodb"
    CASSANDRA = "cassandra"


class SQLPayloadType(Enum):
    AUTHENTICATION_BYPASS = "authentication_bypass"
    UNION_SELECT = "union_select"
    TIME_DELAY = "time_delay"
    BOOLEAN_CONDITION = "boolean_condition"
    INFORMATION_SCHEMA = "information_schema"
    DATA_EXFILTRATION = "data_exfiltration"
    STACKED_COMMAND = "stacked_command"
    COMMENT_BASED = "comment_based"


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
    confirmed: bool = False
    confidence_score: float = 0.8
    extracted_data: Optional[str] = None
    database_fingerprint: Optional[Dict] = None
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


class ErrorMessageAnalyzer:
    ERROR_SIGNATURES = {
        DatabaseType.MYSQL: [
            r"(?i)mysql.*error|mysql_fetch|mysql_num_rows",
            r"(?i)sql syntax|check the manual",
            r"(?i)column.*not.*found|unknown.*column",
            r"(?i)table.*doesn't exist|unknown.*table",
        ],
        DatabaseType.POSTGRESQL: [
            r"(?i)postgresql.*error|pg_|pgsql",
            r"(?i)query failed|syntax error",
            r"(?i)relation.*does.*not.*exist",
            r"(?i)permission denied|access denied",
        ],
        DatabaseType.MSSQL: [
            r"(?i)mssql|microsoft sql server",
            r"(?i)syntax error|incorrect syntax",
            r"(?i)server: msg|level \d+, state \d+",
            r"(?i)sql server.*error",
        ],
        DatabaseType.ORACLE: [
            r"(?i)oracle.*error|ORA-\d+",
            r"(?i)invalid sql|sql command not properly ended",
            r"(?i)table or view does not exist",
        ],
        DatabaseType.SQLITE: [
            r"(?i)sqlite.*error|database.*locked",
            r"(?i)syntax error|near.*:",
            r"(?i)no such table|table.*already exists",
        ],
    }
    
    @staticmethod
    def analyze_error_message(response_content: str) -> Tuple[bool, Optional[DatabaseType], List[str]]:
        errors_found = []
        detected_database = None
        
        for db_type, patterns in ErrorMessageAnalyzer.ERROR_SIGNATURES.items():
            for pattern in patterns:
                matches = re.findall(pattern, response_content, re.MULTILINE)
                if matches:
                    errors_found.extend(matches)
                    if not detected_database:
                        detected_database = db_type
        
        return len(errors_found) > 0, detected_database, errors_found


class TimingAnalyzer:
    @staticmethod
    def analyze_timing(baseline_response_time: float, test_response_time: float,
                      delay_seconds: int = 5) -> Tuple[bool, float, float]:
        time_difference = test_response_time - baseline_response_time
        expected_minimum = delay_seconds * 0.8
        
        is_delayed = time_difference > expected_minimum
        confidence = min((time_difference / (delay_seconds * 1.5)) * 100, 100.0)
        
        return is_delayed, time_difference, confidence


class UnionBasedDetector:
    @staticmethod
    def analyze_union_response(response_content: str, baseline_response: str) -> Tuple[bool, float, List[str]]:
        indicators = []
        
        if 'UNION' in response_content.upper():
            indicators.append('UNION keyword in response')
        
        if '<table' in response_content.lower():
            new_rows = response_content.count('<tr')
            baseline_rows = baseline_response.count('<tr')
            if new_rows > baseline_rows:
                indicators.append(f'Additional table rows detected: {new_rows - baseline_rows}')
        
        response_lines = response_content.split('\n')
        baseline_lines = baseline_response.split('\n')
        
        line_difference = abs(len(response_lines) - len(baseline_lines))
        if line_difference > 5:
            indicators.append(f'Response structure change: {line_difference} additional lines')
        
        confidence = len(indicators) * 0.3
        return len(indicators) > 0, confidence, indicators


class BooleanBasedAnalyzer:
    @staticmethod
    def analyze_boolean_responses(true_response: str, false_response: str,
                                  test_response: str) -> Tuple[bool, float]:
        true_size = len(true_response)
        false_size = len(false_response)
        test_size = len(test_response)
        
        size_difference = abs(true_size - false_size)
        
        if size_difference < 10:
            return False, 0.0
        
        true_content_match = len(set(true_response) & set(test_response)) / max(len(set(true_response)), 1)
        false_content_match = len(set(false_response) & set(test_response)) / max(len(set(false_response)), 1)
        
        if abs(true_content_match - false_content_match) < 0.3:
            return False, 0.0
        
        if true_content_match > false_content_match:
            confidence = true_content_match * 100
            return True, confidence
        else:
            return False, 0.0


class DataExtractionAnalyzer:
    EXTRACTION_PATTERNS = {
        'usernames': r"(?i)(admin|root|user|administrator|guest)",
        'emails': r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        'passwords': r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*[^\s,;]+",
        'ip_addresses': r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        'credit_cards': r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        'api_keys': r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*[^\s,;]+",
    }
    
    @staticmethod
    def extract_sensitive_data(response_content: str) -> Dict[str, List[str]]:
        extracted = {}
        
        for data_type, pattern in DataExtractionAnalyzer.EXTRACTION_PATTERNS.items():
            matches = re.findall(pattern, response_content)
            if matches:
                extracted[data_type] = list(set(matches))
        
        return extracted


class PayloadMutationEngine:
    @staticmethod
    def generate_mutations(base_payload: str, injection_type: SQLInjectionType) -> List[str]:
        mutations = [base_payload]
        
        mutations.extend([
            base_payload.replace(' ', '/**/'),
            base_payload.replace(' ', '%20'),
            base_payload.replace(' ', '%09'),
            base_payload.replace(' ', '%0a'),
        ])
        
        if injection_type == SQLInjectionType.UNION_BASED:
            mutations.extend([
                base_payload.replace('UNION', 'UnIoN'),
                base_payload.replace('SELECT', '/*!50000SELECT*/'),
                base_payload.replace('UNION', 'union all'),
            ])
        
        elif injection_type == SQLInjectionType.TIME_BASED_BLIND:
            mutations.extend([
                base_payload.replace('SLEEP', 'BENCHMARK'),
                base_payload.replace('SLEEP', 'WAITFOR'),
                base_payload.replace('SLEEP', 'PG_SLEEP'),
            ])
        
        return list(set(mutations))


class DatabaseFingerprinting:
    VERSION_QUERIES = {
        DatabaseType.MYSQL: "SELECT @@version",
        DatabaseType.POSTGRESQL: "SELECT version()",
        DatabaseType.MSSQL: "SELECT @@version",
        DatabaseType.ORACLE: "SELECT * FROM v$version",
        DatabaseType.SQLITE: "SELECT sqlite_version()",
    }
    
    TABLE_QUERIES = {
        DatabaseType.MYSQL: "SELECT table_name FROM information_schema.tables",
        DatabaseType.POSTGRESQL: "SELECT tablename FROM pg_tables",
        DatabaseType.MSSQL: "SELECT name FROM sys.tables",
        DatabaseType.ORACLE: "SELECT table_name FROM user_tables",
    }
    
    @staticmethod
    def fingerprint_database(response_content: str, detected_db: DatabaseType) -> Dict[str, any]:
        fingerprint = {
            'database_type': detected_db.value if detected_db else None,
            'version': None,
            'tables': [],
            'columns': [],
            'users': [],
        }
        
        version_patterns = [
            r"(\d+\.\d+\.\d+[\w-]*)",
            r"(?i)(MySQL|PostgreSQL|MSSQL|Oracle|SQLite)\s+([\d.]+)",
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, response_content)
            if matches:
                fingerprint['version'] = str(matches[0])
                break
        
        table_pattern = r"(?i)(users|admin|products|orders|customers|accounts)"
        fingerprint['tables'] = list(set(re.findall(table_pattern, response_content)))
        
        return fingerprint


class SQLScanner:
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
        self.lock = threading.Lock()
    
    def scan(self, target_url: str, response: Dict, payloads: List[str],
            baseline_response: Optional[str] = None) -> List[SQLVulnerability]:
        vulnerabilities = []
        response_content = response.get('content', '')
        response_time = response.get('response_time', 0)
        status_code = response.get('status_code', 0)
        
        if baseline_response is None:
            baseline_response = response_content
        
        parameter = self._extract_parameter_name(target_url)
        
        for payload in payloads:
            is_vulnerable, injection_type, detected_db, evidence = self._test_payload(
                response_content,
                baseline_response,
                payload,
                response_time,
                status_code
            )
            
            if is_vulnerable:
                extracted_data = self.data_extractor.extract_sensitive_data(response_content)
                database_fingerprint = self.fingerprinting.fingerprint_database(response_content, detected_db)
                
                vuln = SQLVulnerability(
                    vulnerability_type='SQL Injection',
                    injection_type=injection_type,
                    database_type=detected_db,
                    url=target_url,
                    parameter=parameter,
                    payload=payload,
                    severity=self._determine_severity(injection_type),
                    evidence=evidence,
                    response_time=response_time,
                    response_size_change=len(response_content) - len(baseline_response),
                    error_message=self._extract_error_message(response_content),
                    confirmed=True,
                    extracted_data=str(extracted_data) if extracted_data else None,
                    database_fingerprint=database_fingerprint,
                    remediation=self._get_remediation()
                )
                
                if self._is_valid_vulnerability(vuln):
                    vulnerabilities.append(vuln)
                    self.scan_statistics[injection_type.value] += 1
            
            mutations = self.mutation_engine.generate_mutations(payload, injection_type or SQLInjectionType.UNION_BASED)
            
            for mutation in mutations[1:]:
                is_vulnerable, injection_type, detected_db, evidence = self._test_payload(
                    response_content,
                    baseline_response,
                    mutation,
                    response_time,
                    status_code
                )
                
                if is_vulnerable and not any(v.payload == mutation for v in vulnerabilities):
                    vuln = SQLVulnerability(
                        vulnerability_type='SQL Injection',
                        injection_type=injection_type,
                        database_type=detected_db,
                        url=target_url,
                        parameter=parameter,
                        payload=mutation,
                        severity=self._determine_severity(injection_type),
                        evidence=evidence,
                        response_time=response_time,
                        response_size_change=len(response_content) - len(baseline_response),
                        error_message=self._extract_error_message(response_content),
                        database_fingerprint=self.fingerprinting.fingerprint_database(response_content, detected_db),
                        remediation=self._get_remediation()
                    )
                    
                    vulnerabilities.append(vuln)
        
        with self.lock:
            self.vulnerabilities.extend(vulnerabilities)
        
        return vulnerabilities
    
    def _test_payload(self, response_content: str, baseline_response: str,
                     payload: str, response_time: float,
                     status_code: int) -> Tuple[bool, SQLInjectionType, Optional[DatabaseType], str]:
        
        is_error, detected_db, errors = self.error_analyzer.analyze_error_message(response_content)
        if is_error:
            return True, SQLInjectionType.ERROR_BASED, detected_db, str(errors[0])
        
        is_union, union_confidence, indicators = self.union_detector.analyze_union_response(
            response_content,
            baseline_response
        )
        if is_union and union_confidence > 50:
            return True, SQLInjectionType.UNION_BASED, detected_db, str(indicators[0])
        
        if response_time > 5:
            return True, SQLInjectionType.TIME_BASED_BLIND, detected_db, f"Response delayed by {response_time}s"
        
        is_boolean, boolean_confidence = self.boolean_analyzer.analyze_boolean_responses(
            baseline_response,
            response_content,
            response_content
        )
        if is_boolean and boolean_confidence > 70:
            return True, SQLInjectionType.BOOLEAN_BASED_BLIND, detected_db, f"Boolean response detected ({boolean_confidence:.1f}% confidence)"
        
        if 'STACK' in payload.upper() or ';' in payload:
            if status_code in [200, 500]:
                return True, SQLInjectionType.STACKED_QUERIES, detected_db, "Stacked query executed"
        
        return False, SQLInjectionType.UNION_BASED, detected_db, ""
    
    def _extract_parameter_name(self, url: str) -> str:
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else 'parameter'
    
    def _extract_error_message(self, response_content: str) -> str:
        error_patterns = [
            r"(?i)(error|exception|fatal).*?:\s*(.{50})",
            r"(?i)sql.*?error.*?:\s*(.{50})",
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, response_content)
            if match:
                return match.group(2) if match.lastindex >= 2 else match.group(0)
        
        return ""
    
    def _determine_severity(self, injection_type: SQLInjectionType) -> str:
        severity_map = {
            SQLInjectionType.UNION_BASED: 'Critical',
            SQLInjectionType.ERROR_BASED: 'Critical',
            SQLInjectionType.TIME_BASED_BLIND: 'High',
            SQLInjectionType.BOOLEAN_BASED_BLIND: 'High',
            SQLInjectionType.STACKED_QUERIES: 'Critical',
            SQLInjectionType.OUT_OF_BAND: 'Critical',
            SQLInjectionType.SECOND_ORDER: 'High',
        }
        return severity_map.get(injection_type, 'High')
    
    def _is_valid_vulnerability(self, vuln: SQLVulnerability) -> bool:
        if vuln.confidence_score < 0.6:
            return False
        
        if any(word in vuln.payload.lower() for word in ['test', 'debug', 'sample']):
            return False
        
        return vuln.confirmed
    
    def _get_remediation(self) -> str:
        return (
            "Use parameterized queries/prepared statements. "
            "Validate and sanitize all user inputs. "
            "Apply proper output encoding. "
            "Use ORM frameworks when possible. "
            "Implement least privilege database access."
        )
    
    def get_vulnerabilities(self) -> List[SQLVulnerability]:
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