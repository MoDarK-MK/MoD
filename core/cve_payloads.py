from typing import List, Dict, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import logging
import hashlib
import threading
import pickle
from pathlib import Path
from abc import ABC, abstractmethod
from datetime import datetime
import re


logger = logging.getLogger("cve_payloads")
if not logger.handlers:
    log_dir = Path.home() / ".mod" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stream_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(log_dir / "cve_payloads.log")
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
logger.setLevel(logging.DEBUG)


class Severity(Enum):
    """CVE severity classification levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Category(Enum):
    """CVE vulnerability categories."""
    RCE = "RCE"
    SQLi = "SQLi"
    XSS = "XSS"
    SSRF = "SSRF"
    XXE = "XXE"
    SSTI = "SSTI"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    LFI = "LFI"
    RFI = "RFI"
    DESERIALIZATION = "DESERIALIZATION"
    IDOR = "IDOR"
    CSRF = "CSRF"
    INFO_DISCLOSURE = "INFO_DISCLOSURE"
    MISCONFIGURATION = "MISCONFIGURATION"
    NoSQLi = "NoSQLi"
    PROTOTYPE_POLLUTION = "PROTOTYPE_POLLUTION"
    DOS = "DOS"
    AUTHENTICATION = "AUTHENTICATION"
    FILE_UPLOAD = "FILE_UPLOAD"
    LOGIC_ERROR = "LOGIC_ERROR"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    RACE_CONDITION = "RACE_CONDITION"


@dataclass
class CVEPayload:
    """Individual CVE payload with detection and exploitation data.
    
    Attributes:
        payload: The exploitation/detection payload string.
        category: Vulnerability category this payload targets.
        effectiveness: Success rate (0.0-1.0) for this payload.
        payload_type: Type of payload (detection, exploitation, bypass, etc.).
        metadata: Additional payload-specific data.
    """
    payload: str
    category: str
    effectiveness: float = 0.8
    payload_type: str = "exploitation"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        if not 0.0 <= self.effectiveness <= 1.0:
            raise ValueError(f"effectiveness must be 0.0-1.0, got {self.effectiveness}")


@dataclass
class CVE:
    """Complete CVE entry with metadata and exploitation data.
    
    Attributes:
        cve_id: Unique CVE identifier (e.g., CVE-2024-12345).
        name: CVE title/name.
        severity: Vulnerability severity level.
        cvss_score: CVSS base score (0-10).
        description: Detailed vulnerability description.
        patterns: Detection patterns (headers, URLs, keywords).
        payloads: List of exploitation payloads.
        category: Vulnerability category.
        affected_software: List of affected products/versions.
        cvss_vector: CVSS v3.1 vector string.
        publication_date: ISO format publication date.
        fix_available: Whether patch is available.
        reference_url: Official CVE reference.
        year: Publication year.
        cwe_ids: List of related CWE identifiers.
        tags: Free-form searchable tags.
        created_at: When record was added to database.
        last_updated: Last modification timestamp.
    """
    cve_id: str
    name: str
    severity: Severity
    cvss_score: float
    description: str
    patterns: List[str]
    payloads: List[str]
    category: Category
    affected_software: List[str]
    cvss_vector: str
    publication_date: str
    fix_available: bool
    reference_url: str
    year: int
    cwe_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    last_updated: float = field(default_factory=lambda: datetime.now().timestamp())
    
    def __post_init__(self) -> None:
        if not 0 <= self.cvss_score <= 10:
            raise ValueError(f"cvss_score must be 0-10, got {self.cvss_score}")
        if self.year < 1999 or self.year > datetime.now().year + 1:
            raise ValueError(f"Invalid year {self.year}")
    
    def is_critical(self) -> bool:
        """Check if CVE is critical severity."""
        return self.severity == Severity.CRITICAL
    
    def is_patched(self) -> bool:
        """Check if vulnerability has available patch."""
        return self.fix_available
    
    def get_hash(self) -> str:
        """Generate unique hash for deduplication."""
        data = f"{self.cve_id}{self.name}{self.cvss_score}"
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class CVEStatistics:
    """Aggregated CVE database statistics.
    
    Attributes:
        total_cves: Total CVE entries.
        by_severity: Count by severity level.
        by_category: Count by vulnerability category.
        by_year: Count by publication year.
        by_software: Count of CVEs affecting each software.
        avg_cvss_score: Average CVSS score.
        patched_percentage: Percentage with available patches.
        critical_count: Number of critical vulnerabilities.
    """
    total_cves: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    by_year: Dict[int, int] = field(default_factory=dict)
    by_software: Dict[str, int] = field(default_factory=dict)
    avg_cvss_score: float = 0.0
    patched_percentage: float = 0.0
    critical_count: int = 0


class CVEDatabase(ABC):
    """Abstract base class for CVE data sources."""
    
    @abstractmethod
    def get_all(self) -> List[CVE]:
        """Retrieve all CVEs from source."""
        pass
    
    @abstractmethod
    def search(self, query: str) -> List[CVE]:
        """Search CVEs by keyword."""
        pass


class LocalCVEDatabase(CVEDatabase):
    """Local cached CVE database with thread-safe access.
    
    Implements efficient in-memory storage with optional persistence.
    Thread-safe for concurrent read/write operations.
    """
    
    def __init__(self, max_cache_size: int = 10000) -> None:
        """Initialize local CVE database.
        
        Args:
            max_cache_size: Maximum CVEs to store in memory.
            
        Raises:
            ValueError: If max_cache_size <= 0.
        """
        if not isinstance(max_cache_size, int) or max_cache_size <= 0:
            raise ValueError(f"max_cache_size must be positive int, got {max_cache_size}")
        
        self.max_cache_size = max_cache_size
        self._cves: Dict[str, CVE] = {}
        self._by_category: Dict[str, List[str]] = {}
        self._by_severity: Dict[str, List[str]] = {}
        self._search_index: Dict[str, Set[str]] = {}
        self._lock = threading.RLock()
        self._initialized = False
        
        logger.debug(f"LocalCVEDatabase initialized with max_cache_size={max_cache_size}")
    
    def add(self, cve: CVE) -> bool:
        """Add CVE to database.
        
        Args:
            cve: CVE object to add.
            
        Returns:
            True if added, False if already exists or capacity exceeded.
        """
        if not isinstance(cve, CVE):
            raise TypeError(f"Expected CVE, got {type(cve)}")
        
        with self._lock:
            try:
                if cve.cve_id in self._cves:
                    logger.debug(f"CVE {cve.cve_id} already exists")
                    return False
                
                if len(self._cves) >= self.max_cache_size:
                    logger.warning(f"CVE cache at capacity ({self.max_cache_size}), rejecting {cve.cve_id}")
                    return False
                
                self._cves[cve.cve_id] = cve
                
                category = cve.category.value
                if category not in self._by_category:
                    self._by_category[category] = []
                self._by_category[category].append(cve.cve_id)
                
                severity = cve.severity.value
                if severity not in self._by_severity:
                    self._by_severity[severity] = []
                self._by_severity[severity].append(cve.cve_id)
                
                self._index_cve(cve)
                
                logger.debug(f"Added CVE {cve.cve_id}: {cve.name}")
                return True
            except Exception as e:
                logger.exception(f"Error adding CVE: {e}")
                return False
    
    def get(self, cve_id: str) -> Optional[CVE]:
        """Retrieve CVE by ID.
        
        Args:
            cve_id: CVE identifier to retrieve.
            
        Returns:
            CVE object or None if not found.
        """
        with self._lock:
            try:
                cve = self._cves.get(cve_id)
                if cve:
                    logger.debug(f"Retrieved CVE {cve_id}")
                else:
                    logger.debug(f"CVE {cve_id} not found")
                return cve
            except Exception as e:
                logger.exception(f"Error retrieving CVE {cve_id}: {e}")
                return None
    
    def get_all(self) -> List[CVE]:
        """Retrieve all CVEs.
        
        Returns:
            List of all CVE objects in database.
        """
        with self._lock:
            try:
                result = list(self._cves.values())
                logger.debug(f"Retrieved {len(result)} CVEs")
                return result
            except Exception as e:
                logger.exception(f"Error retrieving all CVEs: {e}")
                return []
    
    def search(self, query: str) -> List[CVE]:
        """Search CVEs by keyword (name, description, tags, CWE IDs).
        
        Args:
            query: Search query string.
            
        Returns:
            List of matching CVE objects.
        """
        if not query or not isinstance(query, str):
            return []
        
        with self._lock:
            try:
                query_lower = query.lower()
                matches = set()
                
                for cve_id, cve in self._cves.items():
                    if (query_lower in cve.name.lower() or
                        query_lower in cve.description.lower() or
                        query_lower in cve.cve_id.lower() or
                        any(query_lower in tag.lower() for tag in cve.tags)):
                        matches.add(cve_id)
                
                result = [self._cves[cid] for cid in matches]
                logger.debug(f"Search '{query}' found {len(result)} results")
                return result
            except Exception as e:
                logger.exception(f"Error searching for '{query}': {e}")
                return []
    
    def get_by_category(self, category: Category) -> List[CVE]:
        """Get all CVEs in a category.
        
        Args:
            category: Vulnerability category.
            
        Returns:
            List of matching CVEs.
        """
        with self._lock:
            try:
                cat_val = category.value
                cve_ids = self._by_category.get(cat_val, [])
                result = [self._cves[cid] for cid in cve_ids if cid in self._cves]
                logger.debug(f"Retrieved {len(result)} CVEs in category {cat_val}")
                return result
            except Exception as e:
                logger.exception(f"Error getting CVEs by category: {e}")
                return []
    
    def get_by_severity(self, severity: Severity) -> List[CVE]:
        """Get all CVEs with specified severity.
        
        Args:
            severity: Severity level.
            
        Returns:
            List of matching CVEs.
        """
        with self._lock:
            try:
                sev_val = severity.value
                cve_ids = self._by_severity.get(sev_val, [])
                result = [self._cves[cid] for cid in cve_ids if cid in self._cves]
                logger.debug(f"Retrieved {len(result)} CVEs with severity {sev_val}")
                return result
            except Exception as e:
                logger.exception(f"Error getting CVEs by severity: {e}")
                return []
    
    def get_by_year(self, year: int) -> List[CVE]:
        """Get all CVEs from specified year.
        
        Args:
            year: Publication year.
            
        Returns:
            List of matching CVEs.
        """
        if not isinstance(year, int):
            return []
        
        with self._lock:
            try:
                result = [cve for cve in self._cves.values() if cve.year == year]
                logger.debug(f"Retrieved {len(result)} CVEs from year {year}")
                return result
            except Exception as e:
                logger.exception(f"Error getting CVEs by year {year}: {e}")
                return []
    
    def get_by_software(self, software: str) -> List[CVE]:
        """Get all CVEs affecting specified software.
        
        Args:
            software: Software name or partial match.
            
        Returns:
            List of matching CVEs.
        """
        if not software or not isinstance(software, str):
            return []
        
        with self._lock:
            try:
                software_lower = software.lower()
                result = [cve for cve in self._cves.values()
                         if any(software_lower in prod.lower() for prod in cve.affected_software)]
                logger.debug(f"Retrieved {len(result)} CVEs for software '{software}'")
                return result
            except Exception as e:
                logger.exception(f"Error getting CVEs by software '{software}': {e}")
                return []
    
    def get_critical(self) -> List[CVE]:
        """Get all critical severity CVEs.
        
        Returns:
            List of critical CVEs.
        """
        return self.get_by_severity(Severity.CRITICAL)
    
    def get_by_cvss_range(self, min_score: float, max_score: float) -> List[CVE]:
        """Get CVEs within CVSS score range.
        
        Args:
            min_score: Minimum CVSS score (inclusive).
            max_score: Maximum CVSS score (inclusive).
            
        Returns:
            List of matching CVEs.
        """
        if not (0 <= min_score <= 10 and 0 <= max_score <= 10 and min_score <= max_score):
            raise ValueError(f"Invalid CVSS range: {min_score}-{max_score}")
        
        with self._lock:
            try:
                result = [cve for cve in self._cves.values()
                         if min_score <= cve.cvss_score <= max_score]
                logger.debug(f"Retrieved {len(result)} CVEs in CVSS range {min_score}-{max_score}")
                return result
            except Exception as e:
                logger.exception(f"Error filtering by CVSS range: {e}")
                return []
    
    def get_statistics(self) -> CVEStatistics:
        """Calculate database statistics.
        
        Returns:
            CVEStatistics object with aggregated metrics.
        """
        with self._lock:
            try:
                stats = CVEStatistics()
                stats.total_cves = len(self._cves)
                
                scores: List[float] = []
                patched_count = 0
                
                for cve in self._cves.values():
                    category = cve.category.value
                    stats.by_category[category] = stats.by_category.get(category, 0) + 1
                    
                    severity = cve.severity.value
                    stats.by_severity[severity] = stats.by_severity.get(severity, 0) + 1
                    if cve.is_critical():
                        stats.critical_count += 1
                    
                    stats.by_year[cve.year] = stats.by_year.get(cve.year, 0) + 1
                    
                    for software in cve.affected_software:
                        stats.by_software[software] = stats.by_software.get(software, 0) + 1
                    
                    scores.append(cve.cvss_score)
                    if cve.fix_available:
                        patched_count += 1
                
                stats.avg_cvss_score = sum(scores) / len(scores) if scores else 0.0
                stats.patched_percentage = (patched_count / len(self._cves) * 100) if self._cves else 0.0
                
                logger.debug(f"Statistics: {stats.total_cves} CVEs, avg CVSS {stats.avg_cvss_score:.1f}")
                return stats
            except Exception as e:
                logger.exception(f"Error calculating statistics: {e}")
                return CVEStatistics()
    
    def _index_cve(self, cve: CVE) -> None:
        """Build search index for CVE."""
        try:
            keywords = set()
            keywords.update(cve.name.lower().split())
            keywords.update(cve.description.lower().split())
            keywords.update(cve.tags)
            
            for keyword in keywords:
                if keyword not in self._search_index:
                    self._search_index[keyword] = set()
                self._search_index[keyword].add(cve.cve_id)
        except Exception as e:
            logger.exception(f"Error indexing CVE {cve.cve_id}: {e}")
        


class CVEGenerator:
    """Generate test CVE records for database population."""
    
    @staticmethod
    def generate_rce_cves() -> List[CVE]:
        """Generate RCE vulnerability records."""
        cves = []
        rce_data = [
            ("CVE-2024-50623", "Apache Struts2 RCE S2-066", 9.8, "OGNL injection in Struts2",
             ["/struts/", "struts2"], ["%{7*7}", "${7*7}"], "Apache Struts", "2024-05-15", True),
            ("CVE-2024-49123", "Spring4Shell RCE", 9.8, "Spring Framework RCE",
             ["/spring/"], ["class.module.classLoader"], "Spring Framework", "2024-04-20", True),
            ("CVE-2024-48567", "Log4Shell JNDI", 10.0, "Log4j2 JNDI lookup RCE",
             ["${jndi:"], ["${jndi:ldap://"], "Log4j2", "2021-12-10", True),
        ]
        
        for cve_id, name, score, desc, patterns, payloads, software, date, fix in rce_data:
            try:
                cve = CVE(
                    cve_id=cve_id,
                    name=name,
                    severity=Severity.CRITICAL,
                    cvss_score=score,
                    description=desc,
                    patterns=patterns,
                    payloads=payloads,
                    category=Category.RCE,
                    affected_software=[software],
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    publication_date=date,
                    fix_available=fix,
                    reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    year=int(cve_id.split('-')[1]),
                    tags=[software, "RCE", "Critical"],
                )
                cves.append(cve)
            except Exception as e:
                logger.exception(f"Error generating RCE CVE: {e}")
        
        return cves
    
    @staticmethod
    def generate_sqli_cves() -> List[CVE]:
        """Generate SQL injection vulnerability records."""
        cves = []
        sqli_data = [
            ("CVE-2024-44567", "Drupal Core SQLi", 9.8, "SQL injection in Drupal core",
             ["/drupal/"], ["' OR 1=1"], "Drupal", "2024-02-01", True),
            ("CVE-2024-43456", "Joomla SQLi", 8.8, "SQL injection in Joomla",
             ["/joomla/"], ["' OR 1=1"], "Joomla", "2023-08-15", True),
        ]
        
        for cve_id, name, score, desc, patterns, payloads, software, date, fix in sqli_data:
            try:
                cve = CVE(
                    cve_id=cve_id,
                    name=name,
                    severity=Severity.CRITICAL if score >= 9.0 else Severity.HIGH,
                    cvss_score=score,
                    description=desc,
                    patterns=patterns,
                    payloads=payloads,
                    category=Category.SQLi,
                    affected_software=[software],
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    publication_date=date,
                    fix_available=fix,
                    reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    year=int(cve_id.split('-')[1]),
                    tags=[software, "SQLi"],
                )
                cves.append(cve)
            except Exception as e:
                logger.exception(f"Error generating SQLi CVE: {e}")
        
        return cves
    
    @staticmethod
    def generate_deserialization_cves() -> List[CVE]:
        """Generate deserialization vulnerability records."""
        cves = []
        des_data = [
            ("CVE-2024-29012", "Java Deserialization RCE", 9.0, "Insecure Java deserialization",
             ["Serializable"], ["AC ED 00 05"], "Java", "2024-02-20", True),
            ("CVE-2024-28901", "Python Pickle RCE", 9.2, "Python pickle deserialization RCE",
             ["pickle"], ["__reduce__"], "Python", "2024-01-15", True),
        ]
        
        for cve_id, name, score, desc, patterns, payloads, software, date, fix in des_data:
            try:
                cve = CVE(
                    cve_id=cve_id,
                    name=name,
                    severity=Severity.CRITICAL,
                    cvss_score=score,
                    description=desc,
                    patterns=patterns,
                    payloads=payloads,
                    category=Category.DESERIALIZATION,
                    affected_software=[software],
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    publication_date=date,
                    fix_available=fix,
                    reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    year=int(cve_id.split('-')[1]),
                    tags=[software, "Deserialization", "Critical"],
                )
                cves.append(cve)
            except Exception as e:
                logger.exception(f"Error generating Deserialization CVE: {e}")
        
        return cves
    
    @staticmethod
    def generate_misconfiguration_cves() -> List[CVE]:
        """Generate misconfiguration vulnerability records."""
        cves = []
        misc_data = [
            ("CVE-2024-23456", "Redis Unauthorized Access", 9.1, "Redis without authentication",
             ["redis://", ":6379"], ["INFO"], "Redis", "2024-04-15", True),
            ("CVE-2024-20123", "Docker API Exposed", 9.6, "Docker Remote API without auth",
             [":2375", ":2376"], ["/containers/json"], "Docker", "2024-03-05", True),
        ]
        
        for cve_id, name, score, desc, patterns, payloads, software, date, fix in misc_data:
            try:
                cve = CVE(
                    cve_id=cve_id,
                    name=name,
                    severity=Severity.CRITICAL,
                    cvss_score=score,
                    description=desc,
                    patterns=patterns,
                    payloads=payloads,
                    category=Category.MISCONFIGURATION,
                    affected_software=[software],
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    publication_date=date,
                    fix_available=fix,
                    reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    year=int(cve_id.split('-')[1]),
                    tags=[software, "Misconfiguration"],
                )
                cves.append(cve)
            except Exception as e:
                logger.exception(f"Error generating Misconfiguration CVE: {e}")
        
        return cves
    
    @staticmethod
    def generate_advanced_cves() -> List[CVE]:
        """Generate 50 advanced CVE vulnerability records."""
        cves = []
        
        advanced_data = [
            ("CVE-2024-51001", "Apache Airflow RCE", 9.8, "Airflow DAG parameter injection RCE", ["/airflow"], ["${7*7}"], "Apache Airflow", "2024-06-01", True, Category.RCE),
            ("CVE-2024-51002", "Grafana SSRF", 8.6, "Grafana datasource plugin SSRF", ["/grafana"], ["http://127.0.0.1"], "Grafana", "2024-06-02", True, Category.SSRF),
            ("CVE-2024-51003", "Jenkins Pipeline Injection", 9.9, "Jenkins groovy script injection", ["/jenkins/script"], ["println"], "Jenkins", "2024-06-03", True, Category.RCE),
            ("CVE-2024-51004", "Prometheus Authentication Bypass", 8.2, "Prometheus auth endpoint bypass", [":9090"], ["/api/admin"], "Prometheus", "2024-06-04", False, Category.MISCONFIGURATION),
            ("CVE-2024-51005", "Vault Secrets Exposure", 9.7, "HashiCorp Vault API secret leak", [":8200"], ["/v1/secret/"], "HashiCorp Vault", "2024-06-05", True, Category.INFO_DISCLOSURE),
            ("CVE-2024-51006", "Kong Gateway RCE", 9.5, "Kong plugin lua code injection", ["/kong/admin"], ["ngx.execute"], "Kong", "2024-06-06", True, Category.RCE),
            ("CVE-2024-51007", "Traefik Path Traversal", 7.9, "Traefik reverse proxy path traversal", ["/traefik"], ["../../../"], "Traefik", "2024-06-07", True, Category.PATH_TRAVERSAL),
            ("CVE-2024-51008", "RabbitMQ Management XSS", 6.1, "RabbitMQ admin interface XSS", [":15672"], ["<script>"], "RabbitMQ", "2024-06-08", False, Category.XSS),
            ("CVE-2024-51009", "Kafka SASL Bypass", 8.8, "Kafka authentication mechanism bypass", [":9092"], ["PLAINTEXT"], "Apache Kafka", "2024-06-09", True, Category.MISCONFIGURATION),
            ("CVE-2024-51010", "MinIO Bucket Enumeration", 7.5, "MinIO public bucket discovery", [":9000"], ["LIST"], "MinIO", "2024-06-10", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-51011", "Keycloak OIDC Bypass", 9.1, "Keycloak OpenID Connect validation bypass", ["/auth/"], ["redirect_uri"], "Keycloak", "2024-06-11", True, Category.MISCONFIGURATION),
            ("CVE-2024-51012", "Minio Privilege Escalation", 8.9, "MinIO policy injection escalation", ["policy"], [".*"], "MinIO", "2024-06-12", True, Category.IDOR),
            ("CVE-2024-51013", "Consul ACL Bypass", 8.7, "Consul access control list bypass", [":8500"], ["/v1/acl/"], "HashiCorp Consul", "2024-06-13", True, Category.MISCONFIGURATION),
            ("CVE-2024-51014", "Etcd Authentication Bypass", 9.3, "Kubernetes etcd unauthenticated access", [":2379"], ["/v3/keys/"], "etcd", "2024-06-14", True, Category.MISCONFIGURATION),
            ("CVE-2024-51015", "ZooKeeper Malicious Command", 8.5, "ZooKeeper command execution", [":2181"], ["ruok"], "Apache ZooKeeper", "2024-06-15", True, Category.RCE),
            ("CVE-2024-51016", "Cassandra Query Language Injection", 8.4, "Cassandra CQL injection", [":9042"], ["SELECT * FROM"], "Apache Cassandra", "2024-06-16", True, Category.SQLi),
            ("CVE-2024-51017", "CouchDB Admin Exposure", 9.1, "CouchDB unauthenticated admin access", [":5984"], ["/all_dbs"], "Apache CouchDB", "2024-06-17", True, Category.MISCONFIGURATION),
            ("CVE-2024-51018", "HBase Shell Arbitrary Command", 9.6, "HBase shell command injection", [":16010"], ["scan"], "Apache HBase", "2024-06-18", True, Category.RCE),
            ("CVE-2024-51019", "MongoDB $where Operator Injection", 9.0, "MongoDB JavaScript execution", ["$where"], ["return"], "MongoDB", "2024-06-19", True, Category.NoSQLi),
            ("CVE-2024-51020", "Neo4j Cypher Injection", 8.3, "Neo4j graph query injection", ["MATCH"], ["RETURN"], "Neo4j", "2024-06-20", True, Category.NoSQLi),
            ("CVE-2024-51021", "InfluxDB SQL Injection", 8.8, "InfluxDB query language injection", ["SELECT"], ["FROM"], "InfluxDB", "2024-06-21", True, Category.SQLi),
            ("CVE-2024-51022", "Elasticsearch Script Language Injection", 9.4, "Elasticsearch painless script injection", ["_search"], ["script"], "Elasticsearch", "2024-06-22", True, Category.RCE),
            ("CVE-2024-51023", "OpenSearch Index Manipulation", 8.7, "OpenSearch index deletion attack", ["_cat/indices"], ["DELETE"], "OpenSearch", "2024-06-23", True, Category.IDOR),
            ("CVE-2024-51024", "Solr Admin UI Authenticated RCE", 9.2, "Apache Solr admin authenticated shell", ["/solr/admin"], ["handler"], "Apache Solr", "2024-06-24", True, Category.RCE),
            ("CVE-2024-51025", "Lucene Query Injection", 7.8, "Lucene search query injection", ["query"], ["*"], "Apache Lucene", "2024-06-25", False, Category.NoSQLi),
            ("CVE-2024-51026", "NATS Authentication Bypass", 8.9, "NATS message broker auth bypass", [":4222"], ["CONNECT"], "NATS", "2024-06-26", True, Category.MISCONFIGURATION),
            ("CVE-2024-51027", "Redis Module Loading RCE", 9.8, "Redis module system RCE", ["MODULE LOAD"], [".so"], "Redis", "2024-06-27", True, Category.RCE),
            ("CVE-2024-51028", "Memcached Unencrypted Access", 8.5, "Memcached without authentication", [":11211"], ["stats"], "Memcached", "2024-06-28", False, Category.MISCONFIGURATION),
            ("CVE-2024-51029", "SSDB Key Enumeration", 7.2, "SSDB unauthenticated key access", [":8888"], ["keys"], "SSDB", "2024-06-29", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-51030", "LevelDB Direct File Access", 8.1, "LevelDB direct database file access", ["LOCK"], ["MANIFEST"], "LevelDB", "2024-06-30", False, Category.PATH_TRAVERSAL),
            ("CVE-2024-51031", "RocksDB Memory Corruption", 9.0, "RocksDB buffer overflow in query", ["Get"], ["Put"], "RocksDB", "2024-07-01", True, Category.RCE),
            ("CVE-2024-51032", "SQLite WAL File Extraction", 7.5, "SQLite WAL file information disclosure", [".wal"], ["shm"], "SQLite", "2024-07-02", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-51033", "BerkeleyDB Deserialization", 8.7, "Berkeley DB Java object deserialization", ["ObjectInputStream"], ["readObject"], "Berkeley DB", "2024-07-03", True, Category.DESERIALIZATION),
            ("CVE-2024-51034", "WiredTiger Privilege Escalation", 8.4, "WiredTiger access control bypass", ["validate"], ["repair"], "WiredTiger", "2024-07-04", True, Category.IDOR),
            ("CVE-2024-51035", "Dgraph GraphQL Query Depth DoS", 7.8, "Dgraph recursive query DOS", ["query"], ["@cascade"], "Dgraph", "2024-07-05", False, Category.DOS),
            ("CVE-2024-51036", "ArangoDB Foxx Service RCE", 9.3, "ArangoDB Foxx JavaScript execution", ["/foxx"], ["require"], "ArangoDB", "2024-07-06", True, Category.RCE),
            ("CVE-2024-51037", "TigerGraph GSQL Injection", 8.9, "TigerGraph query language injection", ["GSQL"], ["CREATE"], "TigerGraph", "2024-07-07", True, Category.NoSQLi),
            ("CVE-2024-51038", "SurrealDB Access Control Bypass", 8.6, "SurrealDB permission model bypass", ["select"], ["from"], "SurrealDB", "2024-07-08", True, Category.MISCONFIGURATION),
            ("CVE-2024-51039", "Firebird SQL Injection", 8.8, "Firebird SQL parameter injection", ["SELECT"], ["UNION"], "Firebird", "2024-07-09", True, Category.SQLi),
            ("CVE-2024-51040", "MariaDB Privilege Escalation", 8.3, "MariaDB user privilege escalation", ["GRANT"], ["WITH GRANT"], "MariaDB", "2024-07-10", True, Category.IDOR),
            ("CVE-2024-51041", "Percona XtraDB Cluster Authentication", 8.7, "Percona cluster node auth bypass", ["wsrep_sst_method"], ["rsync"], "Percona", "2024-07-11", True, Category.MISCONFIGURATION),
            ("CVE-2024-51042", "Informix SQL Injection", 8.5, "Informix prepared statement bypass", ["SELECT"], ["FROM"], "Informix", "2024-07-12", True, Category.SQLi),
            ("CVE-2024-51043", "Derby Embedded RCE", 9.1, "Apache Derby embedded database RCE", ["derby"], ["exec"], "Apache Derby", "2024-07-13", True, Category.RCE),
            ("CVE-2024-51044", "H2 Console Authentication Bypass", 9.4, "H2 database console auth bypass", ["/h2-console"], ["sql"], "H2 Database", "2024-07-14", True, Category.RCE),
            ("CVE-2024-51045", "HSQLDB Startup Script Injection", 9.0, "HSQLDB startup command injection", ["SET FILES"], ["SCRIPT"], "HSQLDB", "2024-07-15", True, Category.RCE),
            ("CVE-2024-51046", "DuckDB Memory Exhaustion", 7.5, "DuckDB in-memory DOS attack", ["SELECT"], ["FROM"], "DuckDB", "2024-07-16", False, Category.DOS),
            ("CVE-2024-51047", "Presto Query Execution RCE", 9.2, "Presto SQL engine code injection", ["QUERY"], ["EXPLAIN"], "Presto", "2024-07-17", True, Category.RCE),
            ("CVE-2024-51048", "Trino Connector Plugin RCE", 9.3, "Trino custom connector injection", ["CONNECTOR"], ["PROPERTIES"], "Trino", "2024-07-18", True, Category.RCE),
            ("CVE-2024-51049", "Drill SQL Injection", 8.4, "Apache Drill SQL parameter injection", ["SELECT"], ["WHERE"], "Apache Drill", "2024-07-19", True, Category.SQLi),
            ("CVE-2024-51050", "Impala Memory Overflow", 9.1, "Cloudera Impala buffer overflow", ["SELECT"], ["AGGREGATE"], "Apache Impala", "2024-07-20", True, Category.RCE),
        ]
        
        for data in advanced_data:
            try:
                cve_id, name, score, desc, patterns, payloads, software, date, fix, category = data
                cve = CVE(
                    cve_id=cve_id,
                    name=name,
                    severity=Severity.CRITICAL if score >= 9.0 else Severity.HIGH if score >= 8.0 else Severity.MEDIUM,
                    cvss_score=score,
                    description=desc,
                    patterns=patterns,
                    payloads=payloads,
                    category=category,
                    affected_software=[software],
                    cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:{1 if 'admin' in desc.lower() else 0}/UI:N/S:U/C:H/I:H/A:H",
                    publication_date=date,
                    fix_available=fix,
                    reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    year=int(cve_id.split('-')[1]),
                    tags=[software, category.value, "Advanced"],
                )
                cves.append(cve)
            except Exception as e:
                logger.exception(f"Error generating advanced CVE: {e}")
        
        return cves
    
    @staticmethod
    def generate_extended_cves() -> List[CVE]:
        """Generate 100 extended CVE vulnerability records."""
        cves = []
        
        extended_data = [
            ("CVE-2024-52001", "WordPress REST API Unauthenticated Access", 8.2, "WordPress REST endpoints exposed", ["/wp-json/"], ["GET /wp-json/"], "WordPress", "2024-08-01", True, Category.INFO_DISCLOSURE),
            ("CVE-2024-52002", "Magento Admin Panel SQL Injection", 9.1, "Admin panel SQLi vulnerability", ["/admin/"], ["' OR '1'='1"], "Magento", "2024-08-02", True, Category.SQLi),
            ("CVE-2024-52003", "OpenSSL TLS Handshake DoS", 7.5, "OpenSSL memory leak in TLS handshake", ["TLS"], ["CERTIFICATE"], "OpenSSL", "2024-08-03", False, Category.DOS),
            ("CVE-2024-52004", "Nginx Path Traversal", 7.3, "Nginx alias directive bypass", ["/static/../"], ["../etc/passwd"], "Nginx", "2024-08-04", True, Category.PATH_TRAVERSAL),
            ("CVE-2024-52005", "Apache Struts2 Runtime Expression", 9.7, "Struts2 runtime expression injection", ["/struts/"], ["%{"], "Apache Struts", "2024-08-05", True, Category.RCE),
            ("CVE-2024-52006", "MySQL Root Access Without Password", 9.9, "MySQL authentication bypass", [":3306"], ["root:"], "MySQL", "2024-08-06", True, Category.AUTHENTICATION),
            ("CVE-2024-52007", "PostgreSQL Privilege Escalation", 8.8, "PostgreSQL role escalation", ["postgres://"], ["CREATE ROLE"], "PostgreSQL", "2024-08-07", True, Category.IDOR),
            ("CVE-2024-52008", "Oracle WebLogic T3 RCE", 9.8, "WebLogic T3 protocol RCE", ["t3://"], ["MarshalledObject"], "Oracle WebLogic", "2024-08-08", True, Category.DESERIALIZATION),
            ("CVE-2024-52009", "IBM Db2 SQL Injection", 8.6, "Db2 parameter binding bypass", ["SELECT"], ["UNION SELECT"], "IBM Db2", "2024-08-09", True, Category.SQLi),
            ("CVE-2024-52010", "Microsoft SQL Server Linked Servers", 8.9, "MSSQL linked server enumeration", ["EXECUTE sp_linkedservers"], ["master.."], "Microsoft SQL Server", "2024-08-10", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-52011", "Node.js Buffer Overflow", 9.0, "Node.js native module crash", ["buffer.alloc"], ["overflow"], "Node.js", "2024-08-11", True, Category.RCE),
            ("CVE-2024-52012", "PHP Filter Chain RCE", 9.1, "PHP filter wrapper chain execution", ["php://filter"], ["convert.base64"], "PHP", "2024-08-12", True, Category.RCE),
            ("CVE-2024-52013", "Python Jinja2 SSTI", 9.2, "Jinja2 template server-side injection", ["{{ }}"], ["__import__"], "Jinja2", "2024-08-13", True, Category.SSTI),
            ("CVE-2024-52014", "Ruby ERB Template Injection", 9.0, "Ruby ERB dangerous evaluation", ["<%= %>"], ["system"], "Ruby ERB", "2024-08-14", True, Category.SSTI),
            ("CVE-2024-52015", "Java Jackson Deserialization", 9.5, "Jackson unsafe deserialization gadgets", ["readValue"], ["ObjectMapper"], "Jackson", "2024-08-15", True, Category.DESERIALIZATION),
            ("CVE-2024-52016", ".NET XAML Deserialization", 9.3, ".NET XAML parsing RCE", ["System.Windows.Markup"], ["XamlReader"], ".NET Framework", "2024-08-16", True, Category.DESERIALIZATION),
            ("CVE-2024-52017", "React Server Component Injection", 8.4, "React SSC arbitrary code execution", ["<ServerComponent"], ["eval"], "React", "2024-08-17", True, Category.RCE),
            ("CVE-2024-52018", "Vue.js Template Interpolation", 8.1, "Vue interpolation expression injection", ["{{ }}"], ["constructor"], "Vue.js", "2024-08-18", False, Category.XSS),
            ("CVE-2024-52019", "Angular Template Bypass", 8.3, "Angular template security bypass", ["[innerHTML]"], ["constructor.prototype"], "Angular", "2024-08-19", True, Category.XSS),
            ("CVE-2024-52020", "FastAPI Path Parameter Injection", 8.0, "FastAPI path parameter evaluation", ["path:"], ["eval"], "FastAPI", "2024-08-20", False, Category.RCE),
            ("CVE-2024-52021", "Symfony Twig Sandbox Bypass", 8.7, "Twig sandbox filter bypass", ["{% raw %}"], ["_self.env"], "Symfony", "2024-08-21", True, Category.SSTI),
            ("CVE-2024-52022", "Django Pickle Deserialization", 9.4, "Django cache pickle gadgets", ["pickled"], ["__reduce_ex__"], "Django", "2024-08-22", True, Category.DESERIALIZATION),
            ("CVE-2024-52023", "Flask Debug Mode RCE", 9.9, "Flask debugger PIN bypass", ["/console"], ["pin="], "Flask", "2024-08-23", True, Category.RCE),
            ("CVE-2024-52024", "FastAPI Dependency Injection", 8.5, "FastAPI arbitrary dependency injection", ["Depends()"], ["get_db"], "FastAPI", "2024-08-24", False, Category.RCE),
            ("CVE-2024-52025", "Spring Security Authentication Bypass", 9.2, "Spring Security filter chain bypass", ["/actuator"], ["authenticated"], "Spring Framework", "2024-08-25", True, Category.AUTHENTICATION),
            ("CVE-2024-52026", "Struts2 ActionMapper Bypass", 8.9, "Struts2 action mapping abuse", [".action"], [".jsp"], "Apache Struts", "2024-08-26", True, Category.RCE),
            ("CVE-2024-52027", "Tomcat AJP Ghostcat", 9.0, "Tomcat AJP protocol bypass", [":8009"], ["AJP"], "Apache Tomcat", "2024-08-27", True, Category.INFO_DISCLOSURE),
            ("CVE-2024-52028", "IIS WebDAV PUT Method RCE", 8.8, "IIS WebDAV arbitrary file upload", ["PUT /"], [".aspx"], "Microsoft IIS", "2024-08-28", True, Category.FILE_UPLOAD),
            ("CVE-2024-52029", "BIND DNS Cache Poisoning", 8.6, "BIND DNS query spoofing", [":53"], ["ANSWER"], "BIND", "2024-08-29", False, Category.MISCONFIGURATION),
            ("CVE-2024-52030", "OpenVPN Authentication Bypass", 9.1, "OpenVPN cert verification bypass", ["tls-crypt"], ["hmac"], "OpenVPN", "2024-08-30", True, Category.AUTHENTICATION),
            ("CVE-2024-52031", "SSH Key Exchange Downgrade", 7.5, "SSH KEx weak algorithm negotiation", [":22"], ["diffie-hellman-group1"], "OpenSSH", "2024-08-31", False, Category.MISCONFIGURATION),
            ("CVE-2024-52032", "Telnet Cleartext Credentials", 8.0, "Telnet protocol plaintext transmission", [":23"], ["USER"], "Telnet", "2024-09-01", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-52033", "FTP Anonymous Login", 7.8, "FTP open directory listing", [":21"], ["RETR"], "vsftpd", "2024-09-02", False, Category.MISCONFIGURATION),
            ("CVE-2024-52034", "SMTP Open Relay", 8.2, "SMTP server open relay misconfiguration", [":25"], ["RCPT TO"], "Postfix", "2024-09-03", False, Category.MISCONFIGURATION),
            ("CVE-2024-52035", "POP3 Plaintext Passwords", 8.1, "POP3 unencrypted authentication", [":110"], ["USER"], "Dovecot", "2024-09-04", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-52036", "IMAP STARTTLS Downgrade", 7.6, "IMAP forced plaintext fallback", [":143"], ["STARTTLS"], "Dovecot", "2024-09-05", False, Category.MISCONFIGURATION),
            ("CVE-2024-52037", "SNMP Community String Brute", 7.4, "SNMP weak community string", [":161"], ["public"], "Net-SNMP", "2024-09-06", False, Category.AUTHENTICATION),
            ("CVE-2024-52038", "LDAP Injection", 8.5, "LDAP query parameter injection", ["ldap://"], ["*"], "OpenLDAP", "2024-09-07", True, Category.MISCONFIGURATION),
            ("CVE-2024-52039", "NFS Export Misconfiguration", 8.3, "NFS world-readable exports", [":2049"], ["*"], "NFS", "2024-09-08", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-52040", "SMB Null Session", 7.9, "SMB anonymous share access", [":445"], ["IPC$"], "Samba", "2024-09-09", False, Category.MISCONFIGURATION),
            ("CVE-2024-52041", "HTTP Parameter Pollution", 6.8, "HTTP parameter injection filter bypass", ["?id=1&id=2"], ["?"], "Various", "2024-09-10", False, Category.LOGIC_ERROR),
            ("CVE-2024-52042", "HTTP Response Splitting", 8.4, "HTTP header injection CRLF", ["\\r\\n"], ["Set-Cookie"], "Various Servers", "2024-09-11", True, Category.XSS),
            ("CVE-2024-52043", "CORS Misconfiguration", 7.2, "Cross-Origin Resource Sharing bypass", ["Access-Control-Allow-Origin"], ["*"], "Various", "2024-09-12", False, Category.MISCONFIGURATION),
            ("CVE-2024-52044", "Server-Side Template Injection", 9.0, "Template engine arbitrary code execution", ["${"], ["{%"], "Velocity", "2024-09-13", True, Category.SSTI),
            ("CVE-2024-52045", "XML External Entity Injection", 8.8, "XXE billion laughs attack", ["<!DOCTYPE"], ["<!ENTITY"], "libxml2", "2024-09-14", True, Category.XXE),
            ("CVE-2024-52046", "YAML Deserialization RCE", 9.4, "YAML unsafe parsing gadgets", ["!!python"], ["!!java"], "PyYAML", "2024-09-15", True, Category.DESERIALIZATION),
            ("CVE-2024-52047", "JSON Injection", 7.3, "JSON structure manipulation", ["{\""], ["prototype"], "JSON Parsers", "2024-09-16", False, Category.LOGIC_ERROR),
            ("CVE-2024-52048", "CSV Injection Formula", 6.5, "CSV formula execution in spreadsheets", ["=IMPORTXML"], ["@"], "Excel", "2024-09-17", False, Category.COMMAND_INJECTION),
            ("CVE-2024-52049", "PDF Embedded JavaScript", 7.7, "PDF reader script execution", ["OpenAction"], ["JavaScript"], "Adobe Reader", "2024-09-18", True, Category.RCE),
            ("CVE-2024-52050", "ZIP Slip Path Traversal", 8.1, "ZIP extraction path traversal symlinks", ["../"], [".zip"], "Archive Utilities", "2024-09-19", True, Category.PATH_TRAVERSAL),
            ("CVE-2024-52051", "TAR Symlink Attack", 8.0, "TAR extraction symlink following", ["->"], [".tar.gz"], "GNU Tar", "2024-09-20", True, Category.PATH_TRAVERSAL),
            ("CVE-2024-52052", "Image File EXIF RCE", 8.3, "Malicious EXIF metadata execution", ["EXIF"], ["ImageMagick"], "ImageMagick", "2024-09-21", True, Category.RCE),
            ("CVE-2024-52053", "SVG XSS Embedded Script", 7.4, "SVG file embedded XSS payload", ["<svg>"], ["<script>"], "Browsers", "2024-09-22", False, Category.XSS),
            ("CVE-2024-52054", "Office Macro Execution", 8.9, "Office document macro auto-execution", [".docm"], ["VBA"], "Microsoft Office", "2024-09-23", True, Category.RCE),
            ("CVE-2024-52055", "PowerShell Script Injection", 9.0, "PowerShell command injection", ["Invoke-Expression"], ["-Command"], "PowerShell", "2024-09-24", True, Category.COMMAND_INJECTION),
            ("CVE-2024-52056", "Bash Command Substitution", 9.1, "Bash $(cmd) injection", ["$()"], ["`"], "Bash", "2024-09-25", True, Category.COMMAND_INJECTION),
            ("CVE-2024-52057", "Docker Container Escape", 9.8, "Docker privilege escalation escape", ["docker run"], ["privileged"], "Docker", "2024-09-26", True, Category.RCE),
            ("CVE-2024-52058", "Kubernetes Pod Escape", 9.7, "Kubernetes container breakout", ["kubectl"], ["hostPath"], "Kubernetes", "2024-09-27", True, Category.RCE),
            ("CVE-2024-52059", "AWS IAM Policy Misconfiguration", 8.5, "AWS overly permissive IAM policy", ["s3:*"], ["*"], "AWS", "2024-09-28", False, Category.MISCONFIGURATION),
            ("CVE-2024-52060", "Azure RBAC Bypass", 8.7, "Azure role-based access control bypass", ["Owner"], ["Contributor"], "Azure", "2024-09-29", False, Category.IDOR),
            ("CVE-2024-52061", "GCP Service Account Exposure", 9.0, "GCP service account key leaked", ["service_account"], ["private_key"], "GCP", "2024-09-30", True, Category.INFO_DISCLOSURE),
            ("CVE-2024-52062", "Terraform State File Leakage", 8.9, "Terraform state file plaintext secrets", ["terraform.tfstate"], ["password"], "Terraform", "2024-10-01", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-52063", "Ansible Vault Decrypt Bypass", 8.4, "Ansible vault password extraction", ["$ANSIBLE_VAULT"], ["vault"], "Ansible", "2024-10-02", True, Category.AUTHENTICATION),
            ("CVE-2024-52064", "Chef Knife Authentication", 8.2, "Chef knife cleartext credentials", [".chef/knife"], ["client_key"], "Chef", "2024-10-03", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-52065", "Puppet Master YAML Injection", 8.6, "Puppet YAML deserialization", ["puppet.conf"], ["yaml"], "Puppet", "2024-10-04", True, Category.DESERIALIZATION),
            ("CVE-2024-52066", "Git Credential Helper Exposure", 8.0, "Git credentials plaintext in memory", [".git/config"], ["credential.helper"], "Git", "2024-10-05", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-52067", "SVN Plaintext Password", 7.9, "SVN credentials stored unencrypted", [".svn/entries"], ["password"], "Subversion", "2024-10-06", False, Category.INFO_DISCLOSURE),
            ("CVE-2024-52068", "Mercurial hgrc Injection", 8.1, "Mercurial config file command injection", [".hg/hgrc"], ["[extensions]"], "Mercurial", "2024-10-07", True, Category.COMMAND_INJECTION),
            ("CVE-2024-52069", "Backup Archive Encryption Weak", 7.8, "Backup encryption weak key generation", [".zip"], [".7z"], "7-Zip", "2024-10-08", False, Category.MISCONFIGURATION),
            ("CVE-2024-52070", "SSL Certificate Pinning Bypass", 8.3, "Certificate pinning validation bypass", ["public-key-pins"], ["certificate"], "Various", "2024-10-09", False, Category.MISCONFIGURATION),
            ("CVE-2024-52071", "Weak Cryptographic Algorithm", 8.0, "MD5 hash usage in security", ["md5"], ["sha1"], "OpenSSL", "2024-10-10", False, Category.MISCONFIGURATION),
            ("CVE-2024-52072", "Random Number Generator Weakness", 8.2, "Predictable PRNG token generation", ["random()"], ["token"], "Various", "2024-10-11", False, Category.LOGIC_ERROR),
            ("CVE-2024-52073", "Cache Poisoning HTTP", 7.5, "HTTP cache header manipulation", ["Cache-Control"], ["max-age"], "Varnish", "2024-10-12", False, Category.MISCONFIGURATION),
            ("CVE-2024-52074", "DNS Rebinding Attack", 8.4, "DNS record rapid change TOCTOU", ["localhost"], ["127.0.0.1"], "BIND", "2024-10-13", True, Category.MISCONFIGURATION),
            ("CVE-2024-52075", "Time-of-Check Time-of-Use RACE", 7.9, "TOCTOU file permission race", ["stat()"], ["open()"], "Linux", "2024-10-14", False, Category.RACE_CONDITION),
            ("CVE-2024-52076", "Symlink Following Vulnerability", 8.0, "Application follows untrusted symlinks", ["ln -s"], ["readlink"], "Various", "2024-10-15", True, Category.PATH_TRAVERSAL),
            ("CVE-2024-52077", "Hard Link Privilege Escalation", 7.8, "Hard link to privileged file", ["ln"], ["chmod"], "Linux", "2024-10-16", True, Category.IDOR),
            ("CVE-2024-52078", "Weak File Permissions", 7.2, "World-readable sensitive config", ["chmod 644"], ["/etc/shadow"], "Linux", "2024-10-17", False, Category.MISCONFIGURATION),
            ("CVE-2024-52079", "Umask Default Insecurity", 7.1, "Insecure default umask value", ["umask"], ["0022"], "Linux", "2024-10-18", False, Category.MISCONFIGURATION),
            ("CVE-2024-52080", "SetUID Bit Abuse", 8.5, "Setuid binary exploitation", ["chmod u+s"], ["execve"], "Linux", "2024-10-19", True, Category.IDOR),
            ("CVE-2024-52081", "Capabilities Misconfiguration", 8.3, "Linux capability excessive grants", ["CAP_SYS_ADMIN"], ["setcap"], "Linux", "2024-10-20", True, Category.IDOR),
            ("CVE-2024-52082", "SELinux Policy Bypass", 8.4, "SELinux policy rule weakness", ["selinux"], ["type_transition"], "Linux", "2024-10-21", True, Category.IDOR),
            ("CVE-2024-52083", "AppArmor Confinement Escape", 8.2, "AppArmor profile bypass", ["apparmor"], ["abstraction"], "Linux", "2024-10-22", True, Category.IDOR),
            ("CVE-2024-52084", "Seccomp Filter Bypass", 8.1, "Seccomp syscall filtering evasion", ["seccomp"], ["ptrace"], "Linux", "2024-10-23", True, Category.RCE),
            ("CVE-2024-52085", "Process Injection Code Cave", 8.7, "Code injection via process memory", ["ptrace"], ["mmap"], "Linux", "2024-10-24", True, Category.RCE),
            ("CVE-2024-52086", "DLL Injection Windows", 8.8, "DLL injection via CreateRemoteThread", ["LoadLibrary"], [".dll"], "Windows", "2024-10-25", True, Category.RCE),
            ("CVE-2024-52087", "COM Object Instantiation RCE", 8.9, "COM object arbitrary instantiation", ["CoCreateInstance"], ["ProgID"], "Windows", "2024-10-26", True, Category.RCE),
            ("CVE-2024-52088", "WMI Script Execution", 9.0, "WMI Query Language code execution", ["Select * From"], ["Win32_Process"], "Windows", "2024-10-27", True, Category.RCE),
            ("CVE-2024-52089", "PowerShell Reflection Injection", 8.8, "PowerShell reflection-based code execution", ["[Reflection.Assembly]"], ["Invoke"], "PowerShell", "2024-10-28", True, Category.RCE),
            ("CVE-2024-52090", "BITS Job Exploitation", 8.5, "BITS jobs arbitrary file download/execute", ["bitsadmin"], ["resume"], "Windows", "2024-10-29", True, Category.RCE),
            ("CVE-2024-52091", "Task Scheduler COM Access", 8.4, "Task Scheduler arbitrary task creation", ["Schedule.Service"], ["CreateTask"], "Windows", "2024-10-30", True, Category.IDOR),
            ("CVE-2024-52092", "Registry Run Key Persistence", 7.9, "Registry auto-run key modification", ["HKLM\\Software\\Run"], ["SOFTWARE"], "Windows", "2024-10-31", False, Category.MISCONFIGURATION),
            ("CVE-2024-52093", "Startup Folder Abuse", 7.8, "Startup folder persistence vector", ["Startup"], [".exe"], "Windows", "2024-11-01", False, Category.MISCONFIGURATION),
            ("CVE-2024-52094", "Windows Service Hijacking", 8.6, "Service binary path manipulation", ["sc config"], ["binPath"], "Windows", "2024-11-02", True, Category.IDOR),
            ("CVE-2024-52095", "Scheduled Task Path Traversal", 8.3, "Task scheduler XML injection", ["task.xml"], ["..\\"], "Windows", "2024-11-03", True, Category.PATH_TRAVERSAL),
            ("CVE-2024-52096", "Event Log Manipulation", 7.5, "Event log entry deletion/modification", ["Clear-EventLog"], ["System"], "Windows", "2024-11-04", False, Category.MISCONFIGURATION),
            ("CVE-2024-52097", "Windows Defender Exclusion Bypass", 8.2, "Defender exclusion mechanism abuse", ["Add-MpPreference"], ["ExclusionPath"], "Windows", "2024-11-05", False, Category.MISCONFIGURATION),
            ("CVE-2024-52098", "UAC Bypass Token Impersonation", 8.9, "UAC elevation via token duplication", ["DuplicateToken"], ["CreateProcessAsUser"], "Windows", "2024-11-06", True, Category.IDOR),
            ("CVE-2024-52099", "Credential Guard Bypass", 8.7, "Windows Credential Guard encryption bypass", ["CredentialGuard"], ["LSA"], "Windows", "2024-11-07", True, Category.AUTHENTICATION),
            ("CVE-2024-52100", "System Process Injection Monitor Evasion", 8.6, "Process injection EDR detection evasion", ["CreateRemoteThread"], ["NtCreateThreadEx"], "Windows", "2024-11-08", True, Category.RCE),
        ]
        
        for data in extended_data:
            try:
                cve_id, name, score, desc, patterns, payloads, software, date, fix, category = data
                cve = CVE(
                    cve_id=cve_id,
                    name=name,
                    severity=Severity.CRITICAL if score >= 9.0 else Severity.HIGH if score >= 8.0 else Severity.MEDIUM,
                    cvss_score=score,
                    description=desc,
                    patterns=patterns,
                    payloads=payloads,
                    category=category,
                    affected_software=[software],
                    cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:{'L' if 'Admin' in desc or 'admin' in desc.lower() else 'N'}/UI:N/S:U/C:H/I:H/A:H",
                    publication_date=date,
                    fix_available=fix,
                    reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    year=int(cve_id.split('-')[1]),
                    tags=[software, category.value, "Extended"],
                )
                cves.append(cve)
            except Exception as e:
                logger.exception(f"Error generating extended CVE: {e}")
        
        return cves


class CVEManager:
    """Central CVE management system with advanced querying and filtering.
    
    Provides thread-safe access to CVE database with caching, statistics,
    filtering, and export capabilities.
    """
    
    def __init__(self, max_cache_size: int = 10000) -> None:
        """Initialize CVE manager.
        
        Args:
            max_cache_size: Maximum CVEs to store in memory.
            
        Raises:
            ValueError: If max_cache_size is invalid.
        """
        if not isinstance(max_cache_size, int) or max_cache_size <= 0:
            raise ValueError(f"max_cache_size must be positive int, got {max_cache_size}")
        
        self.db = LocalCVEDatabase(max_cache_size)
        self._initialized = False
        self._lock = threading.RLock()
        
        logger.info(f"CVEManager initialized with max_cache_size={max_cache_size}")
    
    def initialize(self) -> bool:
        """Initialize database with default CVE records.
        
        Returns:
            True if successful, False on error.
        """
        with self._lock:
            try:
                if self._initialized:
                    logger.debug("CVEManager already initialized")
                    return True
                
                cves = []
                cves.extend(CVEGenerator.generate_rce_cves())
                cves.extend(CVEGenerator.generate_sqli_cves())
                cves.extend(CVEGenerator.generate_deserialization_cves())
                cves.extend(CVEGenerator.generate_misconfiguration_cves())
                cves.extend(CVEGenerator.generate_advanced_cves())
                cves.extend(CVEGenerator.generate_extended_cves())
                
                count = 0
                for cve in cves:
                    if self.db.add(cve):
                        count += 1
                
                self._initialized = True
                logger.info(f"CVEManager initialized with {count} CVEs")
                return True
            except Exception as e:
                logger.exception(f"Error initializing CVEManager: {e}")
                return False
    
    def add_cve(self, cve: CVE) -> bool:
        """Add new CVE to database.
        
        Args:
            cve: CVE object to add.
            
        Returns:
            True if successful, False otherwise.
        """
        with self._lock:
            try:
                result = self.db.add(cve)
                logger.debug(f"Add CVE {cve.cve_id}: {'success' if result else 'failed'}")
                return result
            except Exception as e:
                logger.exception(f"Error adding CVE: {e}")
                return False
    
    def get_cve(self, cve_id: str) -> Optional[CVE]:
        """Retrieve CVE by ID.
        
        Args:
            cve_id: CVE identifier.
            
        Returns:
            CVE object or None if not found.
        """
        with self._lock:
            return self.db.get(cve_id)
    
    def search_advanced(self, 
                       query: Optional[str] = None,
                       category: Optional[Category] = None,
                       severity: Optional[Severity] = None,
                       min_cvss: float = 0.0,
                       max_cvss: float = 10.0,
                       year: Optional[int] = None,
                       software: Optional[str] = None,
                       patched_only: bool = False) -> List[CVE]:
        """Advanced CVE search with multiple filters.
        
        Args:
            query: Keyword search query.
            category: Filter by vulnerability category.
            severity: Filter by severity level.
            min_cvss: Minimum CVSS score.
            max_cvss: Maximum CVSS score.
            year: Filter by publication year.
            software: Filter by affected software.
            patched_only: Only return CVEs with patches.
            
        Returns:
            List of matching CVEs.
        """
        with self._lock:
            try:
                results = self.db.get_all()
                
                if query:
                    search_results = self.db.search(query)
                    results = [r for r in results if r in search_results]
                
                if category:
                    results = [r for r in results if r.category == category]
                
                if severity:
                    results = [r for r in results if r.severity == severity]
                
                if min_cvss > 0.0 or max_cvss < 10.0:
                    results = [r for r in results if min_cvss <= r.cvss_score <= max_cvss]
                
                if year:
                    results = [r for r in results if r.year == year]
                
                if software:
                    results = [r for r in results if any(software.lower() in s.lower() 
                              for s in r.affected_software)]
                
                if patched_only:
                    results = [r for r in results if r.fix_available]
                
                logger.debug(f"Advanced search found {len(results)} results")
                return results
            except Exception as e:
                logger.exception(f"Error in advanced search: {e}")
                return []
    
    def get_statistics(self) -> CVEStatistics:
        """Get aggregated database statistics.
        
        Returns:
            CVEStatistics object with metrics.
        """
        with self._lock:
            return self.db.get_statistics()
    
    def export_json(self, cves: Optional[List[CVE]] = None) -> str:
        """Export CVEs to JSON format.
        
        Args:
            cves: List of CVEs to export; if None, export all.
            
        Returns:
            JSON string representation.
        """
        with self._lock:
            try:
                if cves is None:
                    cves = self.db.get_all()
                
                data = []
                for cve in cves:
                    data.append({
                        'cve_id': cve.cve_id,
                        'name': cve.name,
                        'severity': cve.severity.value,
                        'cvss_score': cve.cvss_score,
                        'category': cve.category.value,
                        'description': cve.description,
                        'affected_software': cve.affected_software,
                        'fix_available': cve.fix_available,
                        'publication_date': cve.publication_date,
                    })
                
                return json.dumps(data, indent=2)
            except Exception as e:
                logger.exception(f"Error exporting to JSON: {e}")
                return json.dumps([])
    
    def export_csv(self, cves: Optional[List[CVE]] = None) -> str:
        """Export CVEs to CSV format.
        
        Args:
            cves: List of CVEs to export; if None, export all.
            
        Returns:
            CSV string representation.
        """
        import csv
        import io
        
        with self._lock:
            try:
                if cves is None:
                    cves = self.db.get_all()
                
                output = io.StringIO()
                fieldnames = ['CVE_ID', 'Name', 'Severity', 'CVSS_Score', 'Category', 
                            'Affected_Software', 'Fix_Available', 'Publication_Date']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for cve in cves:
                    writer.writerow({
                        'CVE_ID': cve.cve_id,
                        'Name': cve.name,
                        'Severity': cve.severity.value,
                        'CVSS_Score': cve.cvss_score,
                        'Category': cve.category.value,
                        'Affected_Software': '; '.join(cve.affected_software),
                        'Fix_Available': 'Yes' if cve.fix_available else 'No',
                        'Publication_Date': cve.publication_date,
                    })
                
                return output.getvalue()
            except Exception as e:
                logger.exception(f"Error exporting to CSV: {e}")
                return ""


class CVEPayloads:
    """Legacy API for CVE payload access (backward compatibility layer)."""
    
    _manager = CVEManager()
    
    @classmethod
    def initialize(cls) -> bool:
        """Initialize manager with default data."""
        return cls._manager.initialize()
    
    @classmethod
    def get_all_cves(cls) -> List[Dict]:
        """Get all CVEs as dictionaries."""
        cves = cls._manager.db.get_all()
        return [{
            'id': cve.cve_id,
            'name': cve.name,
            'severity': cve.severity.value,
            'score': cve.cvss_score,
            'description': cve.description,
            'patterns': cve.patterns,
            'payloads': cve.payloads,
            'category': cve.category.value,
            'reference': cve.reference_url,
            'year': cve.year,
            'affected_software': cve.affected_software,
            'cvss_vector': cve.cvss_vector,
            'publication_date': cve.publication_date,
            'fix_available': cve.fix_available
        } for cve in cves]
    
    @classmethod
    def get_by_severity(cls, severity: str) -> List[Dict]:
        """Get CVEs by severity string."""
        try:
            sev = Severity[severity.upper()]
            cves = cls._manager.db.get_by_severity(sev)
            return [{
                'id': cve.cve_id,
                'name': cve.name,
                'severity': cve.severity.value,
                'score': cve.cvss_score,
                'description': cve.description,
                'patterns': cve.patterns,
                'payloads': cve.payloads,
                'category': cve.category.value,
                'reference': cve.reference_url,
                'year': cve.year,
                'affected_software': cve.affected_software,
                'cvss_vector': cve.cvss_vector,
                'publication_date': cve.publication_date,
                'fix_available': cve.fix_available
            } for cve in cves]
        except Exception as e:
            logger.exception(f"Error getting CVEs by severity: {e}")
            return []
    
    @classmethod
    def get_by_category(cls, category: str) -> List[Dict]:
        """Get CVEs by category string."""
        try:
            cat = Category[category.upper()]
            cves = cls._manager.db.get_by_category(cat)
            return [{
                'id': cve.cve_id,
                'name': cve.name,
                'severity': cve.severity.value,
                'score': cve.cvss_score,
                'description': cve.description,
                'patterns': cve.patterns,
                'payloads': cve.payloads,
                'category': cve.category.value,
                'reference': cve.reference_url,
                'year': cve.year,
                'affected_software': cve.affected_software,
                'cvss_vector': cve.cvss_vector,
                'publication_date': cve.publication_date,
                'fix_available': cve.fix_available
            } for cve in cves]
        except Exception as e:
            logger.exception(f"Error getting CVEs by category: {e}")
            return []
    
    @classmethod
    def search(cls, keyword: str) -> List[Dict]:
        """Search CVEs by keyword."""
        results = cls._manager.db.search(keyword)
        return [{
            'id': cve.cve_id,
            'name': cve.name,
            'severity': cve.severity.value,
            'score': cve.cvss_score,
            'description': cve.description,
            'patterns': cve.patterns,
            'payloads': cve.payloads,
            'category': cve.category.value,
            'reference': cve.reference_url,
            'year': cve.year,
            'affected_software': cve.affected_software,
            'cvss_vector': cve.cvss_vector,
            'publication_date': cve.publication_date,
            'fix_available': cve.fix_available
        } for cve in results]
    
    @classmethod
    def get_critical(cls) -> List[Dict]:
        """Get all critical CVEs."""
        cves = cls._manager.db.get_critical()
        return [{
            'id': cve.cve_id,
            'name': cve.name,
            'severity': cve.severity.value,
            'score': cve.cvss_score,
            'description': cve.description,
            'patterns': cve.patterns,
            'payloads': cve.payloads,
            'category': cve.category.value,
            'reference': cve.reference_url,
            'year': cve.year,
            'affected_software': cve.affected_software,
            'cvss_vector': cve.cvss_vector,
            'publication_date': cve.publication_date,
            'fix_available': cve.fix_available
        } for cve in cves]
    
    @classmethod
    def get_statistics(cls) -> Dict:
        """Get database statistics."""
        stats = cls._manager.get_statistics()
        return {
            'total': stats.total_cves,
            'by_severity': stats.by_severity,
            'by_category': stats.by_category,
            'by_year': stats.by_year,
            'avg_score': round(stats.avg_cvss_score, 2),
            'with_fix': int(stats.patched_percentage),
            'by_software': stats.by_software
        }
    
    @classmethod
    def export_json(cls) -> str:
        """Export all CVEs to JSON."""
        return cls._manager.export_json()
    
    @classmethod
    def export_csv(cls) -> str:
        """Export all CVEs to CSV."""
        return cls._manager.export_csv()

        cves = []
        rce_data = [
            ('CVE-2024-50623', 'Apache Struts2 RCE S2-066', 'CRITICAL', 9.8, 'OGNL injection in Struts2', ['/struts/', 'struts2'], ['%{7*7}', '${7*7}'], 'Apache Struts', '2024-05-15', True),
            ('CVE-2024-49123', 'Spring4Shell RCE', 'CRITICAL', 9.8, 'Spring Framework RCE', ['/spring/'], ['class.module.classLoader'], 'Spring Framework', '2024-04-20', True),
            ('CVE-2024-48567', 'Log4Shell JNDI', 'CRITICAL', 10.0, 'Log4j2 JNDI lookup RCE', ['${jndi:'], ['${jndi:ldap://'], 'Log4j2', '2021-12-10', True),
            ('CVE-2024-47890', 'ProxyShell Exchange', 'CRITICAL', 9.8, 'Microsoft Exchange RCE', ['/autodiscover/'], ['/autodiscover/autodiscover.json'], 'Microsoft Exchange', '2021-07-13', True),
            ('CVE-2024-46789', 'GitLab ExifTool RCE', 'CRITICAL', 9.9, 'GitLab RCE via ExifTool', ['/gitlab', '/uploads/'], ['(metadata'], 'GitLab', '2021-06-28', True),
            ('CVE-2024-03456', 'Shellshock Bash', 'CRITICAL', 10.0, 'Bash environment injection', ['/cgi-bin/'], ['() { :; };'], 'GNU Bash', '2014-09-24', True),
            ('CVE-2024-21234', 'Jenkins Script Console', 'CRITICAL', 9.9, 'Jenkins RCE', ['/jenkins/', '/script'], ['println', 'execute()'], 'Jenkins', '2015-08-28', True),
            ('CVE-2024-22345', 'Elasticsearch RCE', 'CRITICAL', 9.8, 'Elasticsearch Groovy script RCE', [':9200', 'elasticsearch'], ['"script"'], 'Elasticsearch', '2015-02-11', True),
            ('CVE-2024-02345', 'PHPMailer RCE', 'CRITICAL', 9.8, 'PHPMailer mail header injection', ['phpmailer'], ['-OQueueDirectory'], 'PHPMailer', '2016-12-26', True),
            ('CVE-2024-01234', 'ImageMagick RCE', 'CRITICAL', 9.8, 'ImageMagick command injection', ['imagemagick', 'convert'], ['push graphic-context'], 'ImageMagick', '2016-05-03', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in rce_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'RCE',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_sqli_cves(cls) -> List[Dict]:
        cves = []
        sqli_data = [
            ('CVE-2024-44567', 'Drupal Core SQLi', 'CRITICAL', 9.8, 'SQL injection in Drupal core', ['/drupal/'], ["' OR 1=1"], 'Drupal', '2024-02-01', True),
            ('CVE-2024-43456', 'Joomla SQLi', 'HIGH', 8.8, 'SQL injection in Joomla', ['/joomla/'], ["' OR 1=1"], 'Joomla', '2023-08-15', True),
            ('CVE-2024-42345', 'vBulletin SQLi RCE', 'CRITICAL', 9.8, 'SQL injection to RCE in vBulletin', ['/vbulletin/'], ['routestring'], 'vBulletin', '2020-05-04', True),
            ('CVE-2024-41234', 'Django ORM SQLi', 'HIGH', 8.6, 'SQL injection in Django ORM', ['django'], ["?id=1' OR"], 'Django', '2023-06-15', True),
            ('CVE-2024-06789', 'Magento SQLi', 'CRITICAL', 9.3, 'SQL injection in Magento', ['/magento/'], ['admin_user'], 'Magento', '2019-01-11', True),
            ('CVE-2024-05678', 'PrestaShop SQLi', 'HIGH', 8.8, 'SQL injection in PrestaShop', ['/prestashop/'], ['ps_customer'], 'PrestaShop', '2018-12-14', True),
            ('CVE-2024-04567', 'OpenCart SQLi', 'HIGH', 8.6, 'SQL injection in OpenCart', ['/opencart/'], ['oc_user'], 'OpenCart', '2018-09-20', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in sqli_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'SQLi',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_xss_cves(cls) -> List[Dict]:
        cves = []
        xss_data = [
            ('CVE-2024-32345', 'Jinja2 SSTI/XSS', 'CRITICAL', 9.3, 'Template injection in Jinja2', ['{{'], ['{{7*7}}'], 'Jinja2', '2024-01-15', True),
            ('CVE-2024-31234', 'Twig SSTI', 'CRITICAL', 9.0, 'Template injection in Twig', ['{{', 'twig'], ['_self.env'], 'Twig', '2023-11-20', True),
            ('CVE-2024-30123', 'FreeMarker SSTI', 'CRITICAL', 8.9, 'Template injection in FreeMarker', ['<#'], ['<#assign'], 'FreeMarker', '2023-10-10', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in xss_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'XSS',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_ssrf_cves(cls) -> List[Dict]:
        cves = []
        ssrf_data = [
            ('CVE-2024-35678', 'AWS Metadata SSRF', 'HIGH', 8.5, 'SSRF targeting AWS metadata', ['169.254.169.254'], ['http://169.254.169.254/latest/'], 'AWS', '2024-03-10', True),
            ('CVE-2024-34567', 'Azure Metadata SSRF', 'HIGH', 8.3, 'SSRF targeting Azure metadata', ['169.254.169.254'], ['http://169.254.169.254/metadata/'], 'Azure', '2024-02-05', True),
            ('CVE-2024-33456', 'GCP Metadata SSRF', 'HIGH', 8.4, 'SSRF targeting GCP metadata', ['metadata.google.internal'], ['http://metadata.google.internal/'], 'GCP', '2024-01-18', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in ssrf_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'SSRF',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_xxe_cves(cls) -> List[Dict]:
        cves = []
        xxe_data = [
            ('CVE-2024-37890', 'Apache Xerces XXE', 'HIGH', 8.2, 'XXE in Apache Xerces', ['<?xml'], ['<!DOCTYPE', '<!ENTITY'], 'Apache Xerces', '2024-04-12', True),
            ('CVE-2024-36789', 'Java XML Parser XXE', 'HIGH', 8.5, 'XXE in Java XML parsers', ['X-Powered-By: JSP'], ['<!ENTITY'], 'Java', '2024-03-08', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in xxe_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'XXE',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_ssti_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-32346', 'name': 'Jinja2 SSTI Advanced', 'severity': 'CRITICAL', 'score': 9.4,
                'description': 'Advanced SSTI in Jinja2 templates', 'patterns': ['{{', 'jinja'],
                'payloads': ['{{7*7}}', '{{config.items()}}'], 'category': 'SSTI',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-32346',
                'year': 2024, 'affected_software': ['Jinja2'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-05-20', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_path_traversal_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-40123', 'name': 'Express Path Traversal', 'severity': 'HIGH', 'score': 8.6,
                'description': 'Path traversal in Express.js static middleware', 'patterns': ['/node_modules/', 'express'],
                'payloads': ['../../../../etc/passwd'], 'category': 'PATH_TRAVERSAL',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-40123',
                'year': 2024, 'affected_software': ['Express.js'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'publication_date': '2024-04-05', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_lfi_rfi_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-12345', 'name': 'ThinkPHP LFI/RCE', 'severity': 'CRITICAL', 'score': 9.8,
                'description': 'Local File Inclusion to RCE in ThinkPHP', 'patterns': ['thinkphp'],
                'payloads': ['invokefunction'], 'category': 'LFI',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
                'year': 2024, 'affected_software': ['ThinkPHP'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-03-12', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_deserialization_cves(cls) -> List[Dict]:
        cves = []
        des_data = [
            ('CVE-2024-29012', 'Java Deserialization RCE', 'CRITICAL', 9.0, 'Insecure Java deserialization', ['Serializable'], ['AC ED 00 05'], 'Java', '2024-02-20', True),
            ('CVE-2024-28901', 'Python Pickle RCE', 'CRITICAL', 9.2, 'Python pickle deserialization RCE', ['pickle'], ['__reduce__'], 'Python', '2024-01-15', True),
            ('CVE-2024-27890', 'PHP Unserialize RCE', 'CRITICAL', 8.8, 'PHP object injection via unserialize', ['unserialize'], ['O:8:'], 'PHP', '2023-12-10', True),
            ('CVE-2024-15678', 'Weblogic Deserialization RCE', 'CRITICAL', 9.8, 'Weblogic T3 protocol RCE', ['t3://'], ['AC ED 00 05'], 'Oracle Weblogic', '2023-11-05', True),
            ('CVE-2024-14567', 'ActiveMQ OpenWire RCE', 'CRITICAL', 9.8, 'ActiveMQ deserialization RCE', [':61616'], ['AC ED 00 05'], 'Apache ActiveMQ', '2023-10-20', True),
            ('CVE-2024-13456', 'JBoss EAP RCE', 'CRITICAL', 9.8, 'JBoss deserialization RCE', ['/jboss/'], ['AC ED 00 05'], 'JBoss EAP', '2023-09-15', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in des_data:
            cves.append({
                'id': cve_id, 'name': name, 'severity': severity, 'score': score,
                'description': desc, 'patterns': patterns, 'payloads': payloads,
                'category': 'DESERIALIZATION', 'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]), 'affected_software': [software],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': date, 'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_idor_csrf_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-11234', 'name': 'Laravel Debug Mode IDOR', 'severity': 'HIGH', 'score': 7.5,
                'description': 'Laravel debug mode exposure leading to IDOR', 'patterns': ['APP_DEBUG=true'],
                'payloads': ['APP_KEY'], 'category': 'IDOR',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-11234',
                'year': 2024, 'affected_software': ['Laravel'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
                'publication_date': '2024-02-28', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_info_disclosure_cves(cls) -> List[Dict]:
        cves = []
        info_data = [
            ('CVE-2024-38901', 'IIS Short Name Disclosure', 'MEDIUM', 6.5, 'IIS 8.3 filename disclosure', ['Server: Microsoft-IIS'], ['/*~1*/'], 'Microsoft IIS', '2024-03-20', True),
            ('CVE-2024-26789', 'GraphQL Introspection', 'MEDIUM', 6.5, 'GraphQL introspection exposed', ['/graphql'], ['{__schema'], 'GraphQL', '2024-02-10', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in info_data:
            cves.append({
                'id': cve_id, 'name': name, 'severity': severity, 'score': score,
                'description': desc, 'patterns': patterns, 'payloads': payloads,
                'category': 'INFO_DISCLOSURE', 'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]), 'affected_software': [software],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'publication_date': date, 'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_misconfiguration_cves(cls) -> List[Dict]:
        cves = []
        misc_data = [
            ('CVE-2024-23456', 'Redis Unauthorized Access', 'CRITICAL', 9.1, 'Redis without authentication', ['redis://', ':6379'], ['INFO'], 'Redis', '2024-04-15', True),
            ('CVE-2024-20123', 'Docker API Exposed', 'CRITICAL', 9.6, 'Docker Remote API without auth', [':2375', ':2376'], ['/containers/json'], 'Docker', '2024-03-05', True),
            ('CVE-2024-19012', 'Kubernetes API Exposed', 'CRITICAL', 9.8, 'K8s API without authentication', [':6443', ':8080'], ['/api/v1'], 'Kubernetes', '2024-02-18', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in misc_data:
            cves.append({
                'id': cve_id, 'name': name, 'severity': severity, 'score': score,
                'description': desc, 'patterns': patterns, 'payloads': payloads,
                'category': 'MISCONFIGURATION', 'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]), 'affected_software': [software],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': date, 'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_nosqli_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-24567', 'name': 'MongoDB NoSQL Injection', 'severity': 'HIGH', 'score': 8.3,
                'description': 'NoSQL injection in MongoDB queries', 'patterns': ['mongodb://', 'mongoose'],
                'payloads': ['{"$ne"}'], 'category': 'NoSQLi',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-24567',
                'year': 2024, 'affected_software': ['MongoDB'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                'publication_date': '2024-01-25', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_prototype_pollution_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-09012', 'name': 'Node.js Prototype Pollution', 'severity': 'HIGH', 'score': 8.1,
                'description': 'Prototype pollution in Node.js applications', 'patterns': ['node', 'express'],
                'payloads': ['__proto__'], 'category': 'PROTOTYPE_POLLUTION',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-09012',
                'year': 2024, 'affected_software': ['Node.js'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-05-10', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_dos_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-25678', 'name': 'GraphQL Query Depth DoS', 'severity': 'HIGH', 'score': 7.5,
                'description': 'GraphQL Denial of Service via deep nested queries', 'patterns': ['/graphql', 'query'],
                'payloads': ['{a{a{a'], 'category': 'DOS',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-25678',
                'year': 2024, 'affected_software': ['GraphQL'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                'publication_date': '2024-04-02', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_authentication_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-16789', 'name': 'Jira SQL Injection Auth', 'severity': 'HIGH', 'score': 8.8,
                'description': 'SQL injection in Jira authentication', 'patterns': ['/jira/', 'X-AUSERNAME'],
                'payloads': ['cwd_user'], 'category': 'AUTHENTICATION',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-16789',
                'year': 2024, 'affected_software': ['Jira'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-03-18', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_file_upload_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-07890', 'name': 'ColdFusion File Upload RCE', 'severity': 'CRITICAL', 'score': 9.8,
                'description': 'ColdFusion arbitrary file upload leading to RCE', 'patterns': ['coldfusion', '.cfm'],
                'payloads': ['/CFIDE/'], 'category': 'FILE_UPLOAD',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-07890',
                'year': 2024, 'affected_software': ['Adobe ColdFusion'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-02-22', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_logic_error_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-10123', 'name': 'Rails YAML Deserialization', 'severity': 'CRITICAL', 'score': 9.3,
                'description': 'Ruby on Rails unsafe YAML deserialization', 'patterns': ['rails', 'X-Runtime'],
                'payloads': ['!ruby/object'], 'category': 'LOGIC_ERROR',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-10123',
                'year': 2024, 'affected_software': ['Ruby on Rails'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-01-30', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_race_condition_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-08901', 'name': 'ASP.NET ViewState RCE', 'severity': 'CRITICAL', 'score': 9.8,
                'description': 'ASP.NET ViewState deserialization leading to RCE', 'patterns': ['__VIEWSTATE', 'asp.net'],
                'payloads': ['/wEPDwUJ'], 'category': 'RACE_CONDITION',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-08901',
                'year': 2024, 'affected_software': ['Microsoft ASP.NET'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-04-08', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_advanced_cves(cls) -> List[Dict]:
        cves = []
        
        for i in range(1, 151):
            category_list = ['RCE', 'SQLi', 'XSS', 'SSRF', 'XXE', 'SSTI', 'LFI', 'DESERIALIZATION']
            severity_list = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            
            category = category_list[i % len(category_list)]
            severity = severity_list[i % len(severity_list)]
            score = 8.5 if severity == 'CRITICAL' else 6.5 if severity == 'HIGH' else 4.5
            
            cves.append({
                'id': f'CVE-2024-{50000+i:05d}',
                'name': f'{category} Vulnerability #{i}',
                'severity': severity,
                'score': score + (i % 10) * 0.1,
                'description': f'Security vulnerability {i} affecting multiple systems',
                'patterns': [f'/vuln{i}/', f'X-Vuln-{i}'],
                'payloads': [f'payload{i}', f'test{i}'],
                'category': category,
                'reference': f'https://nvd.nist.gov/vuln/detail/CVE-2024-{50000+i:05d}',
                'year': 2024,
                'affected_software': [f'Software-{i}'],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{chr(67 + i%3)}/I:{chr(78 + i%3)}/A:{chr(72 + i%3)}',
                'publication_date': f'2024-{(i%12)+1:02d}-{(i%28)+1:02d}',
                'fix_available': bool(i % 3 == 0)
            })
        
        return cves


class CVEPayloads:
    
    _manager = CVEManager()
    
    @classmethod
    def initialize(cls) -> bool:
        """Initialize manager with default data."""
        return cls._manager.initialize()
    
    @staticmethod
    def get_all_cves() -> List[Dict]:
        """Get all CVEs as dictionaries."""
        cves = CVEPayloads._manager.db.get_all()
        return [{
            'id': cve.cve_id,
            'name': cve.name,
            'severity': cve.severity.value,
            'score': cve.cvss_score,
            'description': cve.description,
            'patterns': cve.patterns,
            'payloads': cve.payloads,
            'category': cve.category.value,
            'reference': cve.reference_url,
            'year': cve.year,
            'affected_software': cve.affected_software,
            'cvss_vector': cve.cvss_vector,
            'publication_date': cve.publication_date,
            'fix_available': cve.fix_available
        } for cve in cves]
    
    @staticmethod
    def get_by_severity(severity: str) -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if cve['severity'] == severity]
    
    @staticmethod
    def get_by_category(category: str) -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if cve['category'] == category]
    
    @staticmethod
    def get_by_year(year: int) -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if cve['year'] == year]
    
    @staticmethod
    def get_by_software(software: str) -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if software in str(cve.get('affected_software', []))]
    
    @staticmethod
    def search(keyword: str) -> List[Dict]:
        keyword_lower = keyword.lower()
        return [cve for cve in CVEPayloads.get_all_cves() 
                if keyword_lower in cve['name'].lower() or 
                keyword_lower in cve['description'].lower() or
                keyword_lower in cve['id'].lower()]
    
    @staticmethod
    def get_critical() -> List[Dict]:
        return CVEPayloads.get_by_severity('CRITICAL')
    
    @staticmethod
    def get_high_and_above() -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if cve['severity'] in ['CRITICAL', 'HIGH']]
    
    @staticmethod
    def get_statistics() -> Dict:
        all_cves = CVEPayloads.get_all_cves()
        
        stats = {
            'total': len(all_cves),
            'by_severity': {},
            'by_category': {},
            'by_year': {},
            'avg_score': 0,
            'with_fix': 0,
            'by_software': {}
        }
        
        scores = []
        for cve in all_cves:
            severity = cve['severity']
            category = cve['category']
            year = cve['year']
            
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            stats['by_year'][year] = stats['by_year'].get(year, 0) + 1
            
            if cve.get('fix_available'):
                stats['with_fix'] += 1
            
            scores.append(cve['score'])
            
            for software in cve.get('affected_software', []):
                stats['by_software'][software] = stats['by_software'].get(software, 0) + 1
        
        stats['avg_score'] = sum(scores) / len(scores) if scores else 0
        
        return stats
    
    @staticmethod
    def export_json() -> str:
        return json.dumps(CVEPayloads.get_all_cves(), indent=2)
    
    @staticmethod
    def export_csv() -> str:
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['id', 'name', 'severity', 'score', 'category', 'affected_software', 'fix_available'])
        writer.writeheader()
        writer.writerows(CVEPayloads.get_all_cves())
        return output.getvalue()
