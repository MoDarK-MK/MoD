"""
mod_ai.py

Local AI engine for MoD (Master of Defense) without external APIs.
Provides lightweight heuristic + statistical scoring to prioritize
vulnerability findings using only on-device computation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
import math
import statistics
import time
from collections import deque, defaultdict
import json
import re
from difflib import SequenceMatcher
try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None


# --- Configuration --------------------------------------------------------------------

@dataclass
class ModAIConfig:
    """Tunables for the local AI engine.

    Adjust weights to balance sensitivity vs. false positives.
    All computation is on-device (no external APIs).
    """

    severity_weights: Dict[str, float] = field(default_factory=lambda: {
        "CRITICAL": 1.0,
        "HIGH": 0.88,
        "MEDIUM": 0.68,
        "LOW": 0.48,
        "INFO": 0.25,
    })
    max_pattern_boost: float = 0.20
    pattern_unit_boost: float = 0.045
    entropy_bonus: float = 0.05
    error_bonus: float = 0.07
    status5xx_bonus: float = 0.05
    slow_response_bonus: float = 0.05
    anomaly_bonus_cap: float = 0.22
    fp_penalty_cap: float = 0.32
    fp_penalty_weight: float = 0.42
    payload_risk_bonus: float = 0.06
    keyword_bonus: float = 0.08
    high_confidence_floor: float = 0.62
    response_length_bucket_edges: Tuple[int, int, int] = (800, 4000, 15000)
    long_response_bonus: float = 0.03
    tiny_response_penalty: float = 0.05
    error_token_bonus: float = 0.05
    # Expert system multipliers
    vuln_type_weights: Dict[str, float] = field(default_factory=lambda: {
        "SQL_INJECTION": 1.05,
        "RCE": 1.08,
        "COMMAND_INJECTION": 1.07,
        "SSRF": 1.05,
        "XXE": 1.05,
        "SSTI": 1.06,
        "LDAP_INJECTION": 1.04,
    })
    hard_confirm_bonus: float = 0.12
    multi_indicator_bonus: float = 0.06
    high_risk_keyword_floor: float = 0.65
    per_vuln_floor: Dict[str, float] = field(default_factory=lambda: {
        "SQL_INJECTION": 0.55,
        "RCE": 0.6,
        "COMMAND_INJECTION": 0.58,
        "SSRF": 0.55,
        "XXE": 0.55,
        "SSTI": 0.57,
        "LDAP_INJECTION": 0.54,
    })
    per_vuln_ceiling: Dict[str, float] = field(default_factory=lambda: {
        "SQL_INJECTION": 0.98,
        "RCE": 0.99,
        "COMMAND_INJECTION": 0.98,
        "SSRF": 0.96,
        "XXE": 0.96,
        "SSTI": 0.97,
        "LDAP_INJECTION": 0.95,
    })
    rate_limit_statuses: Tuple[int, ...] = (429, 503, 504)
    noise_length_threshold: int = 200000
    noise_penalty: float = 0.08
    # Sliding window memory
    window_size: int = 30
    memory_decay: float = 0.92
    # Lightweight ML (logistic) weights (optional)
    ml_weights: Dict[str, float] = field(default_factory=lambda: {
        "bias": -0.4,
        "confidence": 1.2,
        "severity": 0.9,
        "patterns": 0.35,
        "fp_risk": -0.8,
        "entropy": 0.25,
        "response_time": 0.15,
        "status_error": 0.3,
        "payload_risk": 0.4,
        "keywords": 0.35,
        "anomaly": 0.25,
    })
    enable_ml: bool = True
    # 1. Response Structure Diffing
    enable_response_diffing: bool = True
    diff_threshold: float = 0.15
    # 2. Confidence Calibrator
    enable_calibration: bool = True
    calibration_window: int = 100
    # 3. Temporal Drift Detection
    enable_temporal: bool = True
    temporal_buckets: Dict[str, Tuple[int, int]] = field(default_factory=lambda: {
        "night": (22, 6),
        "workday": (9, 17),
        "evening": (18, 22),
    })
    # 4. Chain-of-Evidence Graph
    enable_evidence_chain: bool = True
    # 5. Payload Family Clustering
    enable_payload_families: bool = True
    payload_families: Dict[str, List[str]] = field(default_factory=lambda: {
        "timing_sqli": ["sleep", "benchmark", "waitfor", "time"],
        "polyglot_xss": ["<svg", "onerror", "javascript:", "onload"],
        "lfi_patterns": ["../", "..\\", "file://", "etc/passwd"],
        "ssti_markers": ["${{", "{{", "<%", "#{{"],
        "rce_indicators": ["uid=", "gid=", "systeminfo", "bin/"],
    })
    family_boost: float = 0.07
    # 6. Context-Aware HTTP Analysis
    enable_http_context: bool = True
    http_method_weights: Dict[str, float] = field(default_factory=lambda: {
        "GET": 0.8,
        "POST": 1.0,
        "PUT": 0.95,
        "DELETE": 0.85,
        "PATCH": 0.9,
    })
    # 7. Rich Keyword Sets per Vuln Type
    vuln_keywords: Dict[str, List[str]] = field(default_factory=lambda: {
        "SQL_INJECTION": [
            "sql syntax", "mysql error", "ora-", "pgsql", "sqlite",
            "syntax error", "unclosed quotation", "union select", "order by",
        ],
        "RCE": [
            "uid=0", "root:x:0:0", "total", "drwx", "-rw-",
            "systeminfo", "c:\\windows", "bin/bash",
        ],
        "SSRF": [
            "169.254.169.254", "metadata", "aws_session_token",
            "connection refused", "connection timed out",
        ],
        "XXE": [
            "<!entity", "<!doctype", "xxe", "file:///", "system entity",
        ],
        "SSTI": [
            "jinja2", "freemarker", "velocity", "template",
            "expression error", "undefined variable",
        ],
        "LDAP": [
            "ldap error", "invalid dn", "filter", "objectclass",
        ],
        "CSRF": [
            "csrf", "token", "nonce", "samesite", "origin",
        ],
    })
    keyword_weight: float = 0.04
    # 8. False Positive Suppression
    enable_fp_suppression: bool = True
    fp_suppression_keywords: List[str] = field(default_factory=lambda: [
        "404", "not found", "error page", "maintenance",
        "coming soon", "under construction",
    ])
    fp_whitelist: List[str] = field(default_factory=list)
    noise_keywords: List[str] = field(default_factory=lambda: [
        "404", "not found", "error page", "maintenance",
        "coming soon", "under construction",
    ])
    # 9. Rate-Limit & Throttle Awareness
    enable_throttle_awareness: bool = True
    throttle_pattern_size: int = 5
    throttle_threshold: float = 0.7
    # 10. Per-Vuln Score Ranges
    vuln_criticality: Dict[str, float] = field(default_factory=lambda: {
        "RCE": 0.95,
        "SQL_INJECTION": 0.90,
        "COMMAND_INJECTION": 0.88,
        "SSTI": 0.85,
        "XXE": 0.85,
        "SSRF": 0.75,
        "CSRF": 0.65,
        "LDAP_INJECTION": 0.80,
    })
    # 11. Payload Context Matching
    context_types: Dict[str, List[str]] = field(default_factory=lambda: {
        "html_body": [">", "<tag"],
        "javascript": ["alert", "eval", "function"],
        "sql": ["union", "select", "where"],
        "xpath": ["[", "or", "and"],
    })
    # 12. Smart Baseline Learning
    enable_baseline_learning: bool = True
    baseline_window: int = 50
    baseline_decay: float = 0.95
    # 13. Multi-Signal Fusion (Bayesian)
    enable_bayesian_fusion: bool = True
    signal_priors: Dict[str, float] = field(default_factory=lambda: {
        "pattern_match": 0.7,
        "error_indicator": 0.6,
        "timing_anomaly": 0.65,
        "keyword_hit": 0.5,
        "payload_risk": 0.55,
    })
    # 14. Score Audit Trail
    enable_audit_trail: bool = True
    audit_history_size: int = 1000
    # 15. Lightweight Anomaly Detector
    enable_anomaly_detector: bool = True
    anomaly_window: int = 20
    anomaly_threshold: float = 2.5
    # 16. Vendor-Specific Rules
    enable_vendor_rules: bool = True
    vendor_rules: Dict[str, Dict] = field(default_factory=lambda: {
        "apache": {"error_log": "[error]", "config_file": "httpd.conf"},
        "nginx": {"error_log": "error", "config_file": "nginx.conf"},
        "iis": {"error_log": "Event", "config_file": "web.config"},
        "wordpress": {"wp_config": "wp-config.php", "admin": "wp-admin"},
        "django": {"debug_page": "TemplateDoesNotExist", "framework": "django"},
        "spring": {"framework": "spring", "error": "SpringBootException"},
    })
    # 17. Export/Import Config
    enable_config_export: bool = True
    # 18. Performance Metrics
    enable_metrics: bool = True
    metrics_window: int = 500
    # Phase B: Advanced Detection Features (5 new capabilities)
    enable_lateral_movement: bool = True
    enable_time_series: bool = True
    enable_request_correlation: bool = True
    enable_protocol_analysis: bool = True
    enable_historical_context: bool = True


class ModAILabel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ModAIFeatures:
    severity_weight: float
    confidence: float
    matched_patterns: int
    false_positive_risk: float
    response_time: float
    status_code: int
    has_error_indicators: bool
    content_entropy: float
    content_length: int
    payload_length: int
    anomaly_score: float = 0.0
    notes: List[str] = field(default_factory=list)
    keyword_hits: List[str] = field(default_factory=list)
    hard_hits: List[str] = field(default_factory=list)
    payload_risk: float = 0.0
    vuln_type: str = ""
    target_id: str = "global"
    hour_of_day: int = 0
    is_rate_limited: bool = False
    is_noise: bool = False
    baseline_response: str = ""  # For response diffing (Feature 1)
    injected_response: str = ""  # For response diffing (Feature 1)
    response_diff_ratio: float = 0.0  # Structure diff ratio (0-1)


class SlidingMemory:
    """Lightweight sliding window memory for recent scores per target."""

    def __init__(self, window_size: int = 30, decay: float = 0.92) -> None:
        self.window_size = window_size
        self.decay = decay
        self.store: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.window_size))

    def add(self, target: str, value: float) -> None:
        self.store[target].append(value)

    def baseline(self, target: str) -> float:
        items = self.store.get(target)
        if not items:
            return 0.0
        weights = [self.decay ** i for i in range(len(items)-1, -1, -1)]
        num = sum(v * w for v, w in zip(items, weights))
        den = sum(weights)
        return num / den if den else 0.0


class ScoreAuditTrail:
    """Audit trail for score evolution and debugging."""

    def __init__(self, max_size: int = 1000) -> None:
        self.max_size = max_size
        self.entries: deque = deque(maxlen=max_size)

    def record(self, target: str, score: float, label: str, explanations: List[str], timestamp: float = None) -> None:
        if timestamp is None:
            timestamp = time.time()
        self.entries.append({
            "timestamp": timestamp,
            "target": target,
            "score": score,
            "label": label,
            "explanations": explanations,
        })

    def get_history(self, target: str = None) -> List[Dict]:
        if not target:
            return list(self.entries)
        return [e for e in self.entries if e["target"] == target]


class MetricsCollector:
    """Track FP, FN, precision, recall, per-vuln metrics."""

    def __init__(self, window: int = 500) -> None:
        self.window = window
        self.detections: deque = deque(maxlen=window)
        self.per_vuln: Dict[str, List] = defaultdict(list)

    def record(self, vuln_type: str, score: float, label: str, is_confirmed: bool = False) -> None:
        entry = {"vuln_type": vuln_type, "score": score, "label": label, "confirmed": is_confirmed}
        self.detections.append(entry)
        self.per_vuln[vuln_type].append(entry)

    def get_metrics(self) -> Dict:
        if not self.detections:
            return {}
        total = len(self.detections)
        confirmed = sum(1 for d in self.detections if d["confirmed"])
        avg_score = sum(d["score"] for d in self.detections) / total if total else 0
        per_vuln_avg = {k: sum(d["score"] for d in v) / len(v) for k, v in self.per_vuln.items() if v}
        return {
            "total": total,
            "confirmed": confirmed,
            "confirmation_rate": confirmed / total if total else 0,
            "avg_score": avg_score,
            "per_vuln_avg": per_vuln_avg,
        }


class ResponseDiffer:
    """Compare response structures (DOM/JSON/XML) for Boolean/Tautology detection."""

    @staticmethod
    def diff_ratio(s1: str, s2: str) -> float:
        """Levenshtein-like similarity ratio using SequenceMatcher."""
        matcher = SequenceMatcher(None, s1, s2)
        return matcher.ratio()

    @staticmethod
    def parse_json_structure(content: str) -> Optional[Dict]:
        try:
            return json.loads(content)
        except:
            return None

    @staticmethod
    def parse_xml_structure(content: str) -> Optional[object]:
        if not ET:
            return None
        try:
            return ET.fromstring(content)
        except:
            return None

    @staticmethod
    def compare_responses(baseline: str, injected: str, threshold: float = 0.15) -> Tuple[bool, float]:
        """Detect structural changes suggesting Boolean/Tautology SQLi or SSTI."""
        if not baseline or not injected:
            return False, 0.0
        ratio = ResponseDiffer.diff_ratio(baseline, injected)
        diff_percent = 1.0 - ratio
        is_different = diff_percent > threshold
        return is_different, diff_percent

    @staticmethod
    def extract_json_keys(obj: any, keys: set = None) -> set:
        """Recursively extract all keys from JSON object."""
        if keys is None:
            keys = set()
        if isinstance(obj, dict):
            keys.update(obj.keys())
            for v in obj.values():
                ResponseDiffer.extract_json_keys(v, keys)
        elif isinstance(obj, list):
            for item in obj:
                ResponseDiffer.extract_json_keys(item, keys)
        return keys

    @staticmethod
    def json_structure_diff(baseline: Dict, injected: Dict) -> Tuple[bool, float, Dict]:
        """Advanced JSON structure comparison (field additions/removals)."""
        if not baseline or not injected:
            return False, 0.0, {}
        
        base_keys = ResponseDiffer.extract_json_keys(baseline)
        inj_keys = ResponseDiffer.extract_json_keys(injected)
        
        added_keys = inj_keys - base_keys
        removed_keys = base_keys - inj_keys
        common_keys = base_keys & inj_keys
        
        total_keys = len(base_keys) if base_keys else 1
        structure_diff = (len(added_keys) + len(removed_keys)) / total_keys
        
        return structure_diff > 0.1, structure_diff, {
            "added": list(added_keys),
            "removed": list(removed_keys),
            "common": len(common_keys)
        }

    @staticmethod
    def html_table_diff(baseline: str, injected: str) -> float:
        """Detect table cell content changes (SQL injection indicator)."""
        import re
        base_cells = re.findall(r'<t[dh]>([^<]+)</t[dh]>', baseline.lower())
        inj_cells = re.findall(r'<t[dh]>([^<]+)</t[dh]>', injected.lower())
        
        if not base_cells:
            return 0.0
        
        # Calculate row count difference
        base_rows = len(re.findall(r'<tr[^>]*>', baseline))
        inj_rows = len(re.findall(r'<tr[^>]*>', injected))
        row_diff = abs(inj_rows - base_rows) / (base_rows + 1)
        
        # Calculate cell content similarity
        cell_match = sum(1 for c in inj_cells if c in base_cells) / max(len(inj_cells), 1)
        
        return (row_diff + (1.0 - cell_match)) / 2.0


class PayloadComplexityAnalyzer:
    """Analyze payload complexity and sophistication."""

    @staticmethod
    def count_nesting_depth(payload: str) -> int:
        """Count nesting depth (parentheses, brackets, etc.)."""
        depth = 0
        max_depth = 0
        for char in payload:
            if char in '({[':
                depth += 1
                max_depth = max(max_depth, depth)
            elif char in ')}]':
                depth = max(0, depth - 1)
        return max_depth

    @staticmethod
    def detect_encoding(payload: str) -> List[str]:
        """Detect common encodings (base64, hex, URL, etc.)."""
        encodings = []
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', payload):
            encodings.append('base64')
        if re.match(r'^[0-9a-fA-F]+$', payload):
            encodings.append('hex')
        if '%' in payload:
            encodings.append('url')
        if '\\x' in payload or '\\u' in payload:
            encodings.append('escape')
        return encodings

    @staticmethod
    def score_complexity(payload: str) -> float:
        """Score payload complexity (0-1)."""
        nesting = PayloadComplexityAnalyzer.count_nesting_depth(payload)
        encoding_count = len(PayloadComplexityAnalyzer.detect_encoding(payload))
        unique_chars = len(set(payload))
        payload_len = len(payload)
        
        # Normalize and combine
        nesting_score = min(nesting / 10.0, 1.0)
        encoding_score = min(encoding_count / 3.0, 1.0)
        char_diversity = min(unique_chars / 50.0, 1.0)
        length_score = min(payload_len / 500.0, 1.0)
        
        return (nesting_score * 0.3 + encoding_score * 0.25 + char_diversity * 0.25 + length_score * 0.2)


class HTTPContextAnalyzer:
    """Analyze HTTP context for vulnerability scoring."""

    @staticmethod
    def analyze_method(method: str) -> float:
        """Score HTTP method riskiness."""
        risk_scores = {
            "POST": 0.8,
            "GET": 0.6,
            "PUT": 0.75,
            "DELETE": 0.85,
            "PATCH": 0.7,
            "HEAD": 0.3,
            "OPTIONS": 0.2,
        }
        return risk_scores.get(method.upper(), 0.5)

    @staticmethod
    def analyze_headers(headers: Dict[str, str]) -> float:
        """Detect authentication/sensitive headers."""
        risk = 0.0
        sensitive = ["authorization", "cookie", "x-api-key", "x-auth-token"]
        for header in sensitive:
            if header in [h.lower() for h in headers.keys()]:
                risk += 0.15
        return min(risk, 1.0)

    @staticmethod
    def analyze_content_type(content_type: str) -> float:
        """Score content-type riskiness."""
        dangerous = ["application/json", "application/xml", "text/plain"]
        safe = ["image/", "font/", "application/pdf"]
        
        if any(d in content_type.lower() for d in dangerous):
            return 0.7
        if any(s in content_type.lower() for s in safe):
            return 0.1
        return 0.4


class AnomalyDetector:
    """Detect outliers and unusual patterns in response times and scores."""

    def __init__(self, window: int = 20, threshold: float = 2.5) -> None:
        self.window = window
        self.threshold = threshold
        self.history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window))

    def add(self, target: str, value: float) -> None:
        self.history[target].append(value)

    def is_anomaly(self, target: str, value: float) -> Tuple[bool, float]:
        history = self.history.get(target)
        if not history or len(history) < 3:
            return False, 0.0
        mean = statistics.mean(history)
        stdev = statistics.stdev(history) if len(history) > 1 else 0.1
        z = (value - mean) / stdev if stdev else 0
        is_anom = abs(z) > self.threshold
        return is_anom, abs(z)


class BayesianFusion:
    """Bayesian combination of independent signals."""

    @staticmethod
    def combine_signals(signals: Dict[str, float], priors: Dict[str, float]) -> float:
        """Combine P(signal | vulnerable) signals using naive Bayes."""
        if not signals:
            return 0.5
        # Arithmetic mean weighted by priors
        weighted_sum = 0.0
        prior_weight = 0.0
        for signal_name, signal_value in signals.items():
            prior = priors.get(signal_name, 0.5)
            weighted_sum += signal_value * prior
            prior_weight += prior
        result = weighted_sum / (prior_weight + 0.0001) if prior_weight > 0 else 0.5
        return min(max(result, 0.0), 1.0)


class ModAIEngine:
    """Local scoring engine for security findings (no network/API)."""

    VERSION = "2.1"

    def __init__(self, config: Optional[ModAIConfig] = None) -> None:
        self.cfg = config or ModAIConfig()
        self.memory = SlidingMemory(window_size=self.cfg.window_size, decay=self.cfg.memory_decay)
        self.audit_trail = ScoreAuditTrail(max_size=self.cfg.audit_history_size)
        self.metrics = MetricsCollector(window=self.cfg.metrics_window)
        self.anomaly_detector = AnomalyDetector(window=self.cfg.anomaly_window, threshold=self.cfg.anomaly_threshold)
        self.differ = ResponseDiffer()
        self.calibration_history: deque = deque(maxlen=self.cfg.calibration_window)
        self.throttle_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.cfg.throttle_pattern_size))
        # Phase A helpers
        self.payload_complexity = PayloadComplexityAnalyzer()
        self.http_context = HTTPContextAnalyzer()
        self.isolation_forest = IsolationForestAnomalyDetector()
        self.evidence_graph = ChainOfEvidenceGraph()
        self.calibrator = ConfidenceCalibrator(window=100)
        self.fuzzy_matcher = FuzzyMatcher()
        self.score_history: deque = deque(maxlen=100)  # For ML training
        # Phase B helpers
        self.lateral_movement = LateralMovementDetector()
        self.time_series = TimeSeriesAnalyzer(window_size=self.cfg.window_size)
        self.request_correlation = RequestCorrelationEngine()
        self.protocol_analyzer = ProtocolSpecificAnalyzer()
        self.historical_context = HistoricalContextEngine()

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        # Normalize by max entropy (log2(N))
        max_entropy = math.log2(length) if length > 1 else 1.0
        return entropy / max_entropy if max_entropy > 0 else 0.0

    @staticmethod
    def _anomaly_score(response_times: List[float]) -> float:
        if not response_times:
            return 0.0
        if len(response_times) == 1:
            return 0.2 if response_times[0] > 3.5 else 0.0
        mean = statistics.mean(response_times)
        stdev = statistics.stdev(response_times)
        latest = response_times[-1]
        if stdev == 0:
            return 0.3 if latest - mean > 2.5 else 0.0
        z = (latest - mean) / stdev
        return min(max(z / 5.0, 0.0), 1.0)

    @staticmethod
    def _keyword_hits(content: str) -> List[str]:
        if not content:
            return []
        content_lower = content.lower()
        candidates = [
            "sleep(", "benchmark", "load_file", "xp_cmdshell", "union select",
            "<?xml", "<!doctype", "onerror=", "onload=", "alert(",
            "../../", "file://", "win.ini", "etc/passwd", "<?php",
            "system(", "exec(", "curl ", "wget ", "ping ", "127.0.0.1",
            "metadata", "169.254.169.254", "aws_session_token",
        ]
        hits = [kw for kw in candidates if kw in content_lower]
        return hits[:12]

    @staticmethod
    def _hard_confirm_indicators(content: str) -> List[str]:
        if not content:
            return []
        content_lower = content.lower()
        indicators = [
            "uid=", "gid=", "root:x:0:0", "drwx", "-rw-", "systeminfo",  # RCE/command
            "sql syntax", "ora-", "mysql", "psql",                           # SQLi
            "<!entity", "<!doctype", "xxe", "file:///",                      # XXE
            "template", "jinja2", "freemarker", "velocity",                   # SSTI
            "metadata", "169.254.169.254", "aws_access_key_id",                # SSRF cloud
        ]
        return [ind for ind in indicators if ind in content_lower]

    @staticmethod
    def _payload_risk(payload: str) -> float:
        if not payload:
            return 0.0
        p = payload.lower()
        risk = 0.0
        if any(token in p for token in ["union", "select", "sleep", "benchmark", "waitfor", "cmd="]):
            risk += 0.25
        if any(token in p for token in ["<?", "<svg", "onerror", "onload", "script>", "javascript:"]):
            risk += 0.25
        if any(token in p for token in ["../../", "..\\", "file://", "etc/passwd", "win.ini"]):
            risk += 0.2
        if any(token in p for token in ["${", "{{", "<%", "#{", "\n|", "||", "&&"]):
            risk += 0.15
        return min(risk, 0.6)

    def build_features(
        self,
        detection: Dict,
        content: str,
        response_time: float,
        status_code: int,
        matched_patterns: int,
        error_indicators: bool,
        payload: str,
        response_time_window: Optional[List[float]] = None,
    ) -> ModAIFeatures:
        severity = detection.get("severity", "MEDIUM")
        severity_weight = self.cfg.severity_weights.get(str(severity), 0.5)
        confidence = float(detection.get("confidence", 0.5))
        fp_risk = float(detection.get("false_positive_risk", 0.0))
        entropy = self._shannon_entropy(content[:2000])  # limit for performance
        payload_len = len(payload or "")
        anomaly = self._anomaly_score(response_time_window or [response_time])
        keyword_hits = self._keyword_hits(content)
        hard_hits = self._hard_confirm_indicators(content)
        payload_risk = self._payload_risk(payload)
        vuln_type = str(detection.get("type", "")).upper()
        target_id = str(detection.get("target", "global"))
        hour_of_day = time.gmtime().tm_hour
        is_rate_limited = status_code in self.cfg.rate_limit_statuses
        is_noise = len(content) > self.cfg.noise_length_threshold and matched_patterns == 0

        notes: List[str] = []
        if status_code >= 500:
            notes.append("server_error")
        if status_code == 403:
            notes.append("forbidden")
        if status_code == 401:
            notes.append("unauthorized")
        if response_time > 4:
            notes.append("slow_response")
        if matched_patterns >= 3:
            notes.append("multi_pattern_match")
        if fp_risk < 0.1:
            notes.append("low_fp_risk")
        if payload_risk > 0.25:
            notes.append("high_risk_payload")
        if keyword_hits:
            notes.append("keywords:" + ",".join(keyword_hits[:4]))
        if hard_hits:
            notes.append("hard_hits:" + ",".join(hard_hits[:3]))
        if is_rate_limited:
            notes.append("rate_limited")
        if is_noise:
            notes.append("noise_content")
        return ModAIFeatures(
            severity_weight=severity_weight,
            confidence=confidence,
            matched_patterns=matched_patterns,
            false_positive_risk=fp_risk,
            response_time=response_time,
            status_code=status_code,
            has_error_indicators=error_indicators,
            content_entropy=entropy,
            content_length=len(content),
            payload_length=payload_len,
            anomaly_score=anomaly,
            notes=notes,
            keyword_hits=keyword_hits,
            hard_hits=hard_hits,
            payload_risk=payload_risk,
            vuln_type=vuln_type,
            target_id=target_id,
            hour_of_day=hour_of_day,
            is_rate_limited=is_rate_limited,
            is_noise=is_noise,
        )

    def score(self, features: ModAIFeatures, detection: Dict) -> Tuple[float, ModAILabel, List[str]]:
        explanations: List[str] = []
        base = 0.62 * features.confidence + 0.38 * features.severity_weight
        explanations.append(f"base={base:.2f}")

        pattern_boost = min(features.matched_patterns * self.cfg.pattern_unit_boost, self.cfg.max_pattern_boost)
        base += pattern_boost
        if pattern_boost:
            explanations.append(f"patterns+{pattern_boost:.2f}")

        # Content heuristics
        if 0.32 <= features.content_entropy <= 0.82:
            base += self.cfg.entropy_bonus
            explanations.append(f"entropy+{self.cfg.entropy_bonus:.2f}")

        if features.has_error_indicators:
            base += self.cfg.error_bonus
            explanations.append(f"errors+{self.cfg.error_bonus:.2f}")

        if features.status_code >= 500:
            base += self.cfg.status5xx_bonus
            explanations.append(f"status5xx+{self.cfg.status5xx_bonus:.2f}")

        if features.response_time > 4:
            base += self.cfg.slow_response_bonus
            explanations.append(f"slow+{self.cfg.slow_response_bonus:.2f}")

        # Feature 1: Response structure diffing for Boolean/Tautology SQLi/SSTI
        if self.cfg.enable_response_diffing and features.baseline_response and features.injected_response:
            is_diff, diff_ratio = self.differ.compare_responses(features.baseline_response, features.injected_response, threshold=0.15)
            if is_diff and diff_ratio > 0.15:
                base += 0.08  # Boost for detected difference
                explanations.append(f"resp_diff+0.08")
            features.response_diff_ratio = diff_ratio

        # Response length bucketization
        small, medium, large = self.cfg.response_length_bucket_edges
        if features.content_length < small:
            base -= self.cfg.tiny_response_penalty
            explanations.append(f"tiny-{self.cfg.tiny_response_penalty:.2f}")
        elif features.content_length > large:
            base += self.cfg.long_response_bonus
            explanations.append(f"long+{self.cfg.long_response_bonus:.2f}")

        # Penalties
        fp_penalty = min(features.false_positive_risk * self.cfg.fp_penalty_weight, self.cfg.fp_penalty_cap)
        base -= fp_penalty
        if fp_penalty:
            explanations.append(f"fp-{fp_penalty:.2f}")

        anomaly_boost = min(features.anomaly_score * 0.22, self.cfg.anomaly_bonus_cap)
        base += anomaly_boost
        if anomaly_boost:
            explanations.append(f"anomaly+{anomaly_boost:.2f}")

        # Expert signals
        label = ModAILabel.LOW  # provisional
        keyword_push = 0.0
        if "keywords:" in ";".join(features.notes):
            keyword_push += self.cfg.keyword_bonus
        if keyword_push:
            base += keyword_push
            explanations.append(f"keywords+{keyword_push:.2f}")

        if any(note.startswith("hard_hits:") for note in features.notes):
            base += self.cfg.hard_confirm_bonus
            explanations.append(f"hard+{self.cfg.hard_confirm_bonus:.2f}")

        # Feature 5: Payload family clustering boost
        if self.cfg.enable_payload_families and features.payload_length > 5:
            # Simple payload content heuristic (would use actual payload in real scenario)
            payload_preview = ";".join(features.notes)[:100]
            family_matches = PayloadFamilyClusterer.classify_payload(payload_preview, self.cfg.payload_families)
            if family_matches:
                family_boost = min(len(family_matches) * 0.04, 0.12)
                base += family_boost
                explanations.append(f"family[{','.join(family_matches)}]+{family_boost:.2f}")

        if features.matched_patterns >= 2 and features.has_error_indicators:
            base += self.cfg.multi_indicator_bonus
            explanations.append(f"multi+{self.cfg.multi_indicator_bonus:.2f}")

        vuln_type = features.vuln_type or str(detection.get("type", ""))
        if vuln_type in self.cfg.vuln_type_weights:
            w = self.cfg.vuln_type_weights[vuln_type]
            base *= w
            explanations.append(f"vuln_weight*{w:.2f}")

        # Feature 3: Temporal drift adjustment (hour of day)
        if self.cfg.enable_temporal and features.hour_of_day in self.cfg.temporal_buckets:
            hour_weight = self.cfg.temporal_buckets[features.hour_of_day]
            base *= hour_weight
            explanations.append(f"temporal*{hour_weight:.2f}")

        # ===== PHASE A: Advanced Enhancements =====
        
        # Feature 1b: Advanced JSON/XML structural diffing
        if self.cfg.enable_response_diffing and features.injected_response:
            try:
                inj_json = ResponseDiffer.parse_json_structure(features.injected_response)
                base_json = ResponseDiffer.parse_json_structure(features.baseline_response) if features.baseline_response else None
                if inj_json and base_json:
                    is_struct_diff, struct_ratio, diff_info = ResponseDiffer.json_structure_diff(base_json, inj_json)
                    if is_struct_diff:
                        base += 0.12
                        explanations.append(f"json_struct_diff+0.12({len(diff_info['added'])}new)")
            except:
                pass
        
        # Feature 1c: HTML table diffing for SQLi
        if features.baseline_response and features.injected_response and '<table' in features.baseline_response.lower():
            table_diff = ResponseDiffer.html_table_diff(features.baseline_response, features.injected_response)
            if table_diff > 0.2:
                base += min(table_diff * 0.15, 0.10)
                explanations.append(f"table_diff+{min(table_diff * 0.15, 0.10):.2f}")
        
        # Feature 2: Payload complexity analysis
        payload_text = ";".join(features.notes)[:200]
        if payload_text:
            complexity = self.payload_complexity.score_complexity(payload_text)
            encodings = self.payload_complexity.detect_encoding(payload_text)
            
            # Higher complexity + multiple encodings = higher risk
            if complexity > 0.7 and len(encodings) > 1:
                base += 0.08
                explanations.append(f"complex_payload+0.08")
            
            # Nesting depth indicator
            nesting = self.payload_complexity.count_nesting_depth(payload_text)
            if nesting > 5:
                base += min(nesting * 0.02, 0.10)
                explanations.append(f"deep_nesting+{min(nesting * 0.02, 0.10):.2f}")
        
        # Feature 5b: Fuzzy payload matching (better evasion detection)
        if len(features.hard_hits) > 0 and features.payload_length > 0:
            payload_sample = features.hard_hits[0] if features.hard_hits else ""
            # Try fuzzy matching against known signatures
            known_sql_sigs = ["union select", "or 1=1", "; drop table", "benchmark("]
            fuzzy_matches = self.fuzzy_matcher.find_similar(payload_sample, known_sql_sigs, threshold=0.75)
            if fuzzy_matches:
                base += min(len(fuzzy_matches) * 0.05, 0.15)
                explanations.append(f"fuzzy_match+{min(len(fuzzy_matches) * 0.05, 0.15):.2f}")
        
        # Feature 6: HTTP context scoring
        http_risk = 0.0
        http_risk += self.http_context.analyze_method(detection.get("method", "GET")) * 0.1
        http_risk += self.http_context.analyze_content_type(detection.get("content_type", "text/html")) * 0.05
        if http_risk > 0:
            base += min(http_risk, 0.15)
            explanations.append(f"http_context+{min(http_risk, 0.15):.2f}")

        # Feature 15: Lightweight anomaly detector (add score to history, check for outlier)
        if self.cfg.enable_anomaly_detector and features.target_id:
            self.anomaly_detector.add(features.target_id, features.response_time)
            is_anom, z_score = self.anomaly_detector.is_anomaly(features.target_id, features.response_time)
            if is_anom and z_score > 2.5:
                base += 0.06
                explanations.append(f"anom_outlier+0.06")
            
            # Train isolation forest
            self.score_history.append(features.response_time)
            if len(self.score_history) >= 20:
                try:
                    self.isolation_forest.train(list(self.score_history))
                except:
                    pass


        # Feature 8: False positive suppression
        if self.cfg.enable_fp_suppression:
            notes_str = ";".join(features.notes).lower()
            for fp_keyword in self.cfg.fp_suppression_keywords:
                if fp_keyword.lower() in notes_str:
                    base *= 0.75
                    explanations.append(f"fp_suppress*0.75")
                    break

        # Feature 16: Vendor-specific rule matching (if enabled)
        if self.cfg.enable_vendor_rules and self.cfg.vendor_rules:
            # This would need headers/status from detection context
            # For now, add a placeholder that could be enhanced
            pass

        # Feature 12: Bayesian fusion of signals (if enabled)
        if self.cfg.enable_bayesian_fusion:
            signals = {
                "confidence": features.confidence,
                "patterns": min(features.matched_patterns / 5.0, 1.0),
                "errors": float(features.has_error_indicators),
                "entropy": min(features.content_entropy / 0.5, 1.0),
                "payload_risk": features.payload_risk,
            }
            bayes_score = BayesianFusion.combine_signals(signals, self.cfg.signal_priors)
            base = 0.65 * base + 0.35 * bayes_score
            explanations.append("bayesian_blend")

        if base < self.cfg.high_confidence_floor and any("high_risk_payload" in n for n in features.notes):
            base = max(base, self.cfg.high_confidence_floor)
            explanations.append("floor_high_risk_payload")

        # Per-vuln floor/ceiling
        if vuln_type in self.cfg.per_vuln_floor:
            floor = self.cfg.per_vuln_floor[vuln_type]
            if base < floor:
                base = floor
                explanations.append(f"floor:{vuln_type.lower()}={floor:.2f}")
        if vuln_type in self.cfg.per_vuln_ceiling:
            ceiling = self.cfg.per_vuln_ceiling[vuln_type]
            if base > ceiling:
                base = ceiling
                explanations.append(f"ceiling:{vuln_type.lower()}={ceiling:.2f}")

        # Noise and rate-limit handling
        if features.is_noise:
            base -= self.cfg.noise_penalty
            explanations.append(f"noise-{self.cfg.noise_penalty:.2f}")
        if features.is_rate_limited:
            base -= 0.05
            explanations.append("ratelimit-0.05")

        # Sliding memory adjustment (temporal baseline)
        baseline = self.memory.baseline(features.target_id)
        if baseline > 0:
            base = 0.8 * base + 0.2 * baseline
            explanations.append("memory_blend")

        # Optional ML-style logistic refinement
        if self.cfg.enable_ml:
            ml = self.cfg.ml_weights
            z = ml.get("bias", 0.0)
            z += ml.get("confidence", 0.0) * features.confidence
            z += ml.get("severity", 0.0) * features.severity_weight
            z += ml.get("patterns", 0.0) * features.matched_patterns
            z += ml.get("fp_risk", 0.0) * features.false_positive_risk
            z += ml.get("entropy", 0.0) * features.content_entropy
            z += ml.get("response_time", 0.0) * min(features.response_time, 10)
            z += ml.get("status_error", 0.0) * (1 if features.status_code >= 500 else 0)
            z += ml.get("payload_risk", 0.0) * features.payload_risk
            z += ml.get("keywords", 0.0) * (1 if features.keyword_hits else 0)
            z += ml.get("anomaly", 0.0) * features.anomaly_score
            ml_score = 1 / (1 + math.exp(-z))
            base = 0.7 * base + 0.3 * ml_score
            explanations.append("ml_blend")

        score = max(0.0, min(base, 1.0))

        # Update memory after scoring
        try:
            self.memory.add(features.target_id, score)
        except Exception:
            pass

        # Feature 14: Track metrics
        if self.cfg.enable_metrics:
            self.metrics.record(vuln_type, score, str(label))

        # Feature 15: Add to audit trail
        if self.cfg.enable_audit_trail:
            self.audit_trail.record(features.target_id, score, str(label), explanations)

        # ===== PHASE A.4: Chain-of-Evidence Graph Integration =====
        if self.cfg.enable_evidence_chain and score > 0.5:
            try:
                self.evidence_graph.add_signal("confidence", features.confidence)
                self.evidence_graph.add_signal("patterns", min(features.matched_patterns / 5.0, 1.0))
                self.evidence_graph.add_signal("errors", float(features.has_error_indicators))
                self.evidence_graph.add_edge("confidence", "patterns", 0.7)
                self.evidence_graph.add_edge("errors", "patterns", 0.8)
                coe_score = self.evidence_graph.compute_propagation("confidence")
                explanations.append(f"chain_of_evidence={coe_score:.2f}")
            except:
                pass

        # ===== PHASE B.1: Lateral Movement Detection =====
        if self.cfg.enable_lateral_movement and len(features.notes) >= 2:
            try:
                attack_types = [n.split(':')[0] for n in features.notes if ':' in n]
                if len(attack_types) >= 2:
                    correlation = self.lateral_movement.detect_multi_target_correlation([
                        (features.target_id, detection.get("url", ""), attack_types[i % len(attack_types)])
                        for i in range(min(len(features.notes), 3))
                    ])
                    if correlation > 0.5:
                        base += correlation * 0.08
                        explanations.append(f"lateral_movement={correlation:.2f}")
            except:
                pass

        # ===== PHASE B.2: Time-Series Anomaly Detection =====
        if self.cfg.enable_time_series:
            try:
                self.time_series.add_point(score, features.hour_of_day)
                is_anomaly, anomaly_score = self.time_series.detect_change_point()
                if is_anomaly and anomaly_score > 0.5:
                    base = max(base + anomaly_score * 0.1, base)
                    trend = self.time_series.get_trend()
                    explanations.append(f"time_series_anomaly={anomaly_score:.2f}:{trend}")
            except:
                pass

        # ===== PHASE B.3: Request Correlation Analysis =====
        if self.cfg.enable_request_correlation:
            try:
                headers = detection.get("headers", {})
                geo_anomaly = self.request_correlation.detect_geographic_anomaly(
                    [detection.get("source_ip", "127.0.0.1")],
                    [detection.get("url", "")]
                )
                if geo_anomaly > 0.4:
                    base += geo_anomaly * 0.06
                    explanations.append(f"geographic_anomaly={geo_anomaly:.2f}")
            except:
                pass

        # ===== PHASE B.4: Protocol-Specific Analysis =====
        if self.cfg.enable_protocol_analysis:
            try:
                url = detection.get("url", "")
                method = detection.get("method", "GET")
                payload = features.payload_risk > 0.5 and detection.get("url", "") or ""
                response = detection.get("response", "")
                
                graphql_risk = self.protocol_analyzer.detect_graphql_introspection(payload, response)
                soap_risk = self.protocol_analyzer.detect_soap_xxe(payload)
                rest_risk = self.protocol_analyzer.detect_rest_token_manipulation(payload, method)
                ws_risk = self.protocol_analyzer.detect_websocket_evasion(payload, url)
                grpc_risk = self.protocol_analyzer.detect_grpc_exploitation(payload, detection.get("headers", {}))
                
                protocol_risks = [graphql_risk, soap_risk, rest_risk, ws_risk, grpc_risk]
                max_protocol_risk = max(protocol_risks) if protocol_risks else 0.0
                
                if max_protocol_risk > 0.4:
                    base += max_protocol_risk * 0.07
                    explanations.append(f"protocol_risk={max_protocol_risk:.2f}")
            except:
                pass

        # ===== PHASE B.5: Historical Context & CVE Integration =====
        if self.cfg.enable_historical_context:
            try:
                # Check for novel/unknown indicators
                unknown_indicators = [k for k in features.keyword_hits if k not in self.historical_context.threat_intelligence]
                zero_day_score = self.historical_context.detect_zero_day_pattern(unknown_indicators)
                
                if zero_day_score > 0.3:
                    base += zero_day_score * 0.06
                    explanations.append(f"zero_day_pattern={zero_day_score:.2f}")
            except:
                pass

        # ===== PHASE A.5: Confidence Calibration =====
        if self.cfg.enable_calibration:
            # Record for calibration
            self.calibrator.record_detection(score, vuln_type, features.false_positive_risk < 0.3)
            
            # Use calibrated thresholds
            label_str = self.calibrator.get_label(score, vuln_type)
            if label_str == "CRITICAL":
                label = ModAILabel.CRITICAL
            elif label_str == "HIGH":
                label = ModAILabel.HIGH
            elif label_str == "MEDIUM":
                label = ModAILabel.MEDIUM
            else:
                label = ModAILabel.LOW
        else:
            # Default thresholds
            if score >= 0.85:
                label = ModAILabel.CRITICAL
            elif score >= 0.7:
                label = ModAILabel.HIGH
            elif score >= 0.52:
                label = ModAILabel.MEDIUM
            else:
                label = ModAILabel.LOW

        return score, label, explanations

    def enrich_detection(
        self,
        detection: Dict,
        content: str,
        response_time: float,
        status_code: int,
        matched_patterns: int,
        error_indicators: bool,
        payload: str,
        response_time_window: Optional[List[float]] = None,
    ) -> Dict:
        """Add AI score to detection result without external dependencies."""
        features = self.build_features(
            detection,
            content,
            response_time,
            status_code,
            matched_patterns,
            error_indicators,
            payload,
            response_time_window,
        )
        score, label, explanations = self.score(features, detection)

        detection = dict(detection)
        detection["mod_ai"] = {
            "version": self.VERSION,
            "score": round(score, 3),
            "label": label.value,
            "explanations": explanations,
            "features": {
                "severity_weight": features.severity_weight,
                "confidence": features.confidence,
                "matched_patterns": features.matched_patterns,
                "false_positive_risk": features.false_positive_risk,
                "content_entropy": round(features.content_entropy, 3),
                "response_time": features.response_time,
                "status_code": features.status_code,
                "payload_length": features.payload_length,
                "anomaly_score": round(features.anomaly_score, 3),
                "payload_risk": round(features.payload_risk, 3),
                "keyword_hits": features.keyword_hits,
                "hard_hits": features.hard_hits,
                "target_id": features.target_id,
                "vuln_type": features.vuln_type,
                "hour_of_day": features.hour_of_day,
            },
        }
        return detection


class TemporalAnalyzer:
    """Analyze temporal patterns (hour, day) for drift detection."""

    @staticmethod
    def get_hour_bucket(hour: int, buckets: Dict[int, float]) -> float:
        """Map hour to bucket weight."""
        if hour in buckets:
            return buckets[hour]
        # Default to 1.0 for unknown hours
        return 1.0

    @staticmethod
    def detect_temporal_drift(history: List[float], baseline_mean: float, threshold: float = 2.5) -> Tuple[bool, float]:
        """Detect if recent scores drift from baseline (Z-score based)."""
        if len(history) < 2:
            return False, 0.0
        recent_mean = statistics.mean(history[-5:]) if len(history) >= 5 else statistics.mean(history)
        drift = abs(recent_mean - baseline_mean)
        z_drift = drift / (statistics.stdev(history) + 0.01) if len(history) > 1 else 0
        is_drift = z_drift > threshold
        return is_drift, z_drift


class VendorRuleEngine:
    """Match error pages/responses to vendor-specific signatures."""

    @staticmethod
    def detect_vendor(content: str, status_code: int, headers: Dict[str, str], vendor_rules: Dict) -> List[str]:
        """Detect vendor from response characteristics."""
        matches = []
        content_lower = content.lower()
        
        for vendor, rules in vendor_rules.items():
            fingerprints = rules.get("fingerprints", [])
            signatures = rules.get("signatures", [])
            status_codes = rules.get("status_codes", [])
            
            # Check fingerprints in content
            for fp in fingerprints:
                if fp.lower() in content_lower:
                    matches.append(vendor)
                    break
            
            # Check HTTP status codes
            if status_code in status_codes:
                matches.append(vendor)
            
            # Check signatures in headers
            for sig in signatures:
                for header_val in headers.values():
                    if sig.lower() in header_val.lower():
                        matches.append(vendor)
                        break
        
        return list(set(matches))


class IsolationForestAnomalyDetector:
    """Lightweight Isolation Forest implementation for anomaly detection."""

    def __init__(self, n_trees: int = 10, sample_size: int = 256, contamination: float = 0.1) -> None:
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.contamination = contamination
        self.trees: List[Dict] = []
        self.threshold = 0.0
        self.trained = False

    def train(self, X: List[float]) -> None:
        """Train isolation forest on 1D scores."""
        if len(X) < 2:
            return
        
        # Simple threshold-based anomaly detection (approximation)
        mean = statistics.mean(X)
        stdev = statistics.stdev(X) if len(X) > 1 else 0.1
        self.threshold = mean + (3.0 * stdev)  # 3-sigma rule
        self.trained = True

    def predict(self, x: float) -> int:
        """Predict: 1 for anomaly, -1 for normal."""
        if not self.trained:
            return -1
        return 1 if x > self.threshold else -1


class ChainOfEvidenceGraph:
    """Build and traverse DAG of vulnerability signals."""

    def __init__(self) -> None:
        self.edges: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        self.signal_values: Dict[str, float] = {}
        self.evidence_chain: List[str] = []

    def add_signal(self, signal_id: str, value: float) -> None:
        """Add a signal node."""
        self.signal_values[signal_id] = value

    def add_edge(self, from_signal: str, to_signal: str, weight: float) -> None:
        """Add directed edge (from → to with weight)."""
        self.edges[from_signal].append((to_signal, weight))

    def compute_propagation(self, root_signal: str) -> float:
        """Compute final score via signal propagation."""
        visited = set()
        stack = [(root_signal, 1.0)]
        total_score = 0.0
        
        while stack:
            signal, path_weight = stack.pop()
            if signal in visited:
                continue
            visited.add(signal)
            
            signal_value = self.signal_values.get(signal, 0.0)
            contribution = signal_value * path_weight
            total_score += contribution
            self.evidence_chain.append(f"{signal}({contribution:.2f})")
            
            # Propagate to dependent signals
            for next_signal, edge_weight in self.edges.get(signal, []):
                if next_signal not in visited:
                    stack.append((next_signal, path_weight * edge_weight))
        
        return min(total_score, 1.0)

    def get_explanation(self) -> str:
        """Get human-readable explanation."""
        return " -> ".join(self.evidence_chain)


class ConfidenceCalibrator:
    """Self-tuning confidence threshold calibrator."""

    def __init__(self, window: int = 100, learning_rate: float = 0.01) -> None:
        self.window = window
        self.learning_rate = learning_rate
        self.history: deque = deque(maxlen=window)
        self.thresholds = {
            "CRITICAL": 0.85,
            "HIGH": 0.70,
            "MEDIUM": 0.52,
            "LOW": 0.30,
        }
        self.per_vuln_thresholds: Dict[str, Dict[str, float]] = defaultdict(lambda: dict(self.thresholds))

    def record_detection(self, score: float, vuln_type: str, is_confirmed: bool) -> None:
        """Record a detection for calibration."""
        self.history.append({"score": score, "vuln_type": vuln_type, "confirmed": is_confirmed})

    def calibrate(self, vuln_type: str = "global") -> Dict[str, float]:
        """Recalibrate thresholds based on history."""
        if len(self.history) < 10:
            return self.thresholds if vuln_type == "global" else self.per_vuln_thresholds[vuln_type]
        
        # Filter by vuln_type
        relevant = [h for h in self.history if h["vuln_type"] == vuln_type or vuln_type == "global"]
        if not relevant:
            return self.thresholds
        
        confirmed_scores = sorted([h["score"] for h in relevant if h["confirmed"]])
        unconfirmed_scores = sorted([h["score"] for h in relevant if not h["confirmed"]])
        
        # Estimate optimal thresholds
        if confirmed_scores and unconfirmed_scores:
            # Find gap between confirmed and unconfirmed
            new_critical = statistics.median(confirmed_scores[-len(confirmed_scores)//3:]) if confirmed_scores else 0.85
            new_critical = min(max(new_critical, 0.7), 0.98)
            
            threshold_dict = self.thresholds if vuln_type == "global" else self.per_vuln_thresholds[vuln_type]
            threshold_dict["CRITICAL"] = new_critical
            threshold_dict["HIGH"] = new_critical - 0.15
            threshold_dict["MEDIUM"] = new_critical - 0.33
            threshold_dict["LOW"] = new_critical - 0.55
            
            return threshold_dict
        
        return self.thresholds if vuln_type == "global" else self.per_vuln_thresholds[vuln_type]

    def get_label(self, score: float, vuln_type: str = "global") -> str:
        """Get label based on calibrated thresholds."""
        thresholds = self.per_vuln_thresholds.get(vuln_type, self.thresholds)
        
        if score >= thresholds.get("CRITICAL", 0.85):
            return "CRITICAL"
        elif score >= thresholds.get("HIGH", 0.70):
            return "HIGH"
        elif score >= thresholds.get("MEDIUM", 0.52):
            return "MEDIUM"
        else:
            return "LOW"


class FuzzyMatcher:
    """Fuzzy matching for payload signatures."""

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance."""
        if len(s1) < len(s2):
            return FuzzyMatcher.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    @staticmethod
    def similarity_ratio(s1: str, s2: str, threshold: float = 0.85) -> Tuple[bool, float]:
        """Calculate string similarity ratio."""
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return True, 1.0
        
        distance = FuzzyMatcher.levenshtein_distance(s1, s2)
        ratio = 1.0 - (distance / max_len)
        
        return ratio >= threshold, ratio

    @staticmethod
    def find_similar(payload: str, signatures: List[str], threshold: float = 0.85) -> List[Tuple[str, float]]:
        """Find similar signatures."""
        matches = []
        for sig in signatures:
            is_match, ratio = FuzzyMatcher.similarity_ratio(payload, sig, threshold)
            if is_match:
                matches.append((sig, ratio))
        return sorted(matches, key=lambda x: x[1], reverse=True)


# ================================================================================
# PHASE B: Advanced Detection Enhancements (Lateral Movement, Time-Series, etc.)
# ================================================================================

class LateralMovementDetector:
    """Detect multi-target attacks and lateral movement patterns."""
    
    def __init__(self):
        self.target_history = defaultdict(list)  # target -> list of (timestamp, url, type)
        self.attack_chains = []  # chains of related attacks
    
    def record_attack(self, target_id: str, url: str, attack_type: str, timestamp: float = None):
        """Record an attack against a target."""
        if timestamp is None:
            timestamp = time.time()
        self.target_history[target_id].append((timestamp, url, attack_type))
    
    def detect_multi_target_correlation(self, attack_list: List[Tuple[str, str, str]]) -> float:
        """
        Detect if multiple attacks are correlated (same pattern, similar timeframe).
        attack_list: [(target_id, url, attack_type), ...]
        Returns: correlation score 0-1
        """
        if len(attack_list) < 2:
            return 0.0
        
        # Check if targets are similar (same subnet/domain)
        targets = [a[0] for a in attack_list]
        types = [a[2] for a in attack_list]
        
        # Check type consistency
        type_consistency = len(set(types)) / max(len(types), 1)
        
        # Check temporal proximity (all within 5 minutes?)
        urls = [a[1] for a in attack_list]
        url_variance = len(set(urls)) / max(len(urls), 1)
        
        # Multi-target attack score: higher if same type, multiple targets, varied URLs
        correlation = (type_consistency * 0.4) + ((1.0 - url_variance) * 0.3) + (len(targets) / 10.0 * 0.3)
        return min(correlation, 1.0)
    
    def detect_enumeration_pattern(self, payloads: List[str], urls: List[str]) -> float:
        """
        Detect account/resource enumeration (sequential IDs, list attempts).
        Returns: enumeration confidence 0-1
        """
        if len(payloads) < 3 or len(urls) < 3:
            return 0.0
        
        # Check for sequential patterns (id=1, id=2, id=3)
        numeric_payloads = [p for p in payloads if any(c.isdigit() for c in p)]
        if len(numeric_payloads) < 3:
            return 0.0
        
        # Check if URLs are similar (same endpoint, different params)
        url_paths = [u.split('?')[0] for u in urls]
        same_path_ratio = len([1 for p in set(url_paths)]) / max(len(url_paths), 1)
        
        enumeration_score = (same_path_ratio * 0.6) + (len(numeric_payloads) / len(payloads) * 0.4)
        return min(enumeration_score, 1.0)


class TimeSeriesAnalyzer:
    """Detect anomalies using time-series analysis (simple trend + deviation)."""
    
    def __init__(self, window_size: int = 30):
        self.window_size = window_size
        self.scores_history = deque(maxlen=window_size)
        self.timestamps = deque(maxlen=window_size)
    
    def add_point(self, score: float, timestamp: float = None):
        """Add a score to the time series."""
        if timestamp is None:
            timestamp = time.time()
        self.scores_history.append(score)
        self.timestamps.append(timestamp)
    
    def detect_change_point(self) -> Tuple[bool, float]:
        """
        Detect if there's a significant change point using simple 3-sigma.
        Returns: (is_anomaly, anomaly_score)
        """
        if len(self.scores_history) < 5:
            return False, 0.0
        
        scores = list(self.scores_history)
        mean = statistics.mean(scores)
        try:
            stdev = statistics.stdev(scores)
        except:
            return False, 0.0
        
        current = scores[-1]
        z_score = abs((current - mean) / max(stdev, 0.01))
        
        is_anomaly = z_score > 3.0
        anomaly_score = min(z_score / 10.0, 1.0)
        
        return is_anomaly, anomaly_score
    
    def get_trend(self) -> str:
        """Get trend: 'increasing', 'decreasing', 'stable'."""
        if len(self.scores_history) < 3:
            return "stable"
        
        recent = list(self.scores_history)[-3:]
        if recent[-1] > recent[0] + 0.05:
            return "increasing"
        elif recent[-1] < recent[0] - 0.05:
            return "decreasing"
        else:
            return "stable"


class RequestCorrelationEngine:
    """Correlate requests to detect coordinated attacks."""
    
    def __init__(self):
        self.request_sessions = defaultdict(list)  # session_id -> list of requests
        self.request_fingerprints = {}  # fingerprint -> count
    
    def compute_session_fingerprint(self, method: str, url: str, headers: Dict) -> str:
        """Create a fingerprint from request metadata."""
        base = f"{method}:{url.split('?')[0]}"
        user_agent = headers.get("User-Agent", "")
        origin = headers.get("Origin", "")
        return f"{base}:{user_agent}:{origin}"
    
    def detect_geographic_anomaly(self, ips: List[str], urls: List[str]) -> float:
        """
        Detect geographic inconsistency (multiple IPs, same session).
        Returns: anomaly score 0-1
        """
        if len(set(ips)) <= 1:
            return 0.0
        
        # More unique IPs = higher anomaly
        ip_uniqueness = min(len(set(ips)) / max(len(ips), 1), 1.0)
        
        # If same endpoint attacked from many IPs = suspicious
        url_paths = [u.split('?')[0] for u in urls]
        endpoint_consistency = 1.0 - (len(set(url_paths)) / max(len(url_paths), 1))
        
        return (ip_uniqueness * 0.6) + (endpoint_consistency * 0.4)
    
    def detect_request_sequence_anomaly(self, requests: List[Dict]) -> float:
        """
        Detect unusual request sequences (skip steps, repeat patterns).
        Returns: sequence anomaly score 0-1
        """
        if len(requests) < 3:
            return 0.0
        
        # Check for repetitive patterns
        urls = [r.get("url", "") for r in requests]
        url_repeats = sum(1 for i, u in enumerate(urls) if i > 0 and u == urls[i-1])
        repeat_ratio = url_repeats / max(len(urls) - 1, 1)
        
        # Check temporal consistency
        timestamps = [r.get("timestamp", 0) for r in requests if r.get("timestamp")]
        if len(timestamps) >= 2:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            if intervals:
                mean_interval = statistics.mean(intervals)
                variance_ratio = sum(1 for i in intervals if abs(i - mean_interval) > mean_interval * 0.5) / len(intervals)
            else:
                variance_ratio = 0.0
        else:
            variance_ratio = 0.0
        
        anomaly = (repeat_ratio * 0.5) + (variance_ratio * 0.5)
        return min(anomaly, 1.0)


class ProtocolSpecificAnalyzer:
    """Detect protocol-specific exploits (GraphQL, SOAP, gRPC, WebSocket)."""
    
    @staticmethod
    def detect_graphql_introspection(payload: str, response: str) -> float:
        """Detect GraphQL introspection attacks."""
        graphql_indicators = ["__schema", "__type", "introspectionQuery", "__typename", "__field"]
        indicator_count = sum(1 for ind in graphql_indicators if ind in payload or ind in response)
        
        if indicator_count >= 2:
            return min(indicator_count / 5.0, 1.0)
        return 0.0
    
    @staticmethod
    def detect_soap_xxe(payload: str) -> float:
        """Detect SOAP/XML-RPC XXE attacks."""
        xxe_indicators = ["<!DOCTYPE", "SYSTEM", "ENTITY", "&xxe;", "%xxe;"]
        indicator_count = sum(1 for ind in xxe_indicators if ind in payload)
        
        if indicator_count >= 2:
            return min(indicator_count / 5.0, 1.0)
        return 0.0
    
    @staticmethod
    def detect_rest_token_manipulation(payload: str, method: str) -> float:
        """Detect REST API token/auth manipulation."""
        token_patterns = ["Authorization", "bearer", "token=", "api_key", "jwt"]
        manipulation_risk = 0.0
        
        if method in ["PUT", "DELETE", "PATCH"]:  # Dangerous methods
            manipulation_risk += 0.3
        
        if any(pattern.lower() in payload.lower() for pattern in token_patterns):
            manipulation_risk += 0.4
        
        return min(manipulation_risk, 1.0)
    
    @staticmethod
    def detect_websocket_evasion(payload: str, url: str) -> float:
        """Detect WebSocket-based evasion attempts."""
        ws_indicators = ["ws://", "wss://", "WebSocket", "msg:", "cmd:"]
        
        is_ws = "ws://" in url or "wss://" in url
        evasion_risk = 0.3 if is_ws else 0.0
        
        indicator_count = sum(1 for ind in ws_indicators if ind in payload)
        if indicator_count >= 1:
            evasion_risk += 0.4
        
        return min(evasion_risk, 1.0)
    
    @staticmethod
    def detect_grpc_exploitation(payload: str, headers: Dict) -> float:
        """Detect gRPC-specific attacks."""
        grpc_indicators = ["grpc", "proto", "application/grpc", "content-type: application/grpc"]
        
        is_grpc = any(ind.lower() in str(headers).lower() for ind in grpc_indicators)
        exploit_risk = 0.3 if is_grpc else 0.0
        
        if "proto" in payload.lower() or "message" in payload.lower():
            exploit_risk += 0.3
        
        return min(exploit_risk, 1.0)


class HistoricalContextEngine:
    """Integrate CVE timelines and vulnerability lifecycle context."""
    
    def __init__(self):
        self.cve_timeline = {}  # cve_id -> {"released": timestamp, "patch": timestamp}
        self.threat_intelligence = defaultdict(list)  # indicator -> [cves]
    
    def record_cve(self, cve_id: str, released_timestamp: float, patch_timestamp: float = None):
        """Record a CVE's timeline."""
        self.cve_timeline[cve_id] = {
            "released": released_timestamp,
            "patch": patch_timestamp or (released_timestamp + 86400 * 30)  # Assume 30 days
        }
    
    def compute_cve_recency_score(self, cve_id: str, current_timestamp: float = None) -> float:
        """
        Compute exploitation risk based on CVE age.
        Newer CVEs (< 30 days) = higher risk, older = lower risk.
        """
        if current_timestamp is None:
            current_timestamp = time.time()
        
        if cve_id not in self.cve_timeline:
            return 0.5  # Unknown = medium risk
        
        cve_info = self.cve_timeline[cve_id]
        released = cve_info["released"]
        patch = cve_info["patch"]
        
        days_since_release = (current_timestamp - released) / 86400
        days_since_patch = (current_timestamp - patch) / 86400
        
        # Risk is high if recent release, and decreases with patch availability
        if days_since_release < 30:
            risk = 0.9
        elif days_since_release < 90:
            risk = 0.7
        else:
            risk = 0.4
        
        # Reduce if patch is old
        if days_since_patch < 0:
            pass  # Not patched yet
        elif days_since_patch < 30:
            risk *= 0.8
        else:
            risk *= 0.5
        
        return min(risk, 1.0)
    
    def detect_zero_day_pattern(self, unknown_indicators: List[str]) -> float:
        """
        Detect zero-day-like patterns (novel indicators not in threat intel).
        Returns: zero-day risk score 0-1
        """
        novel_count = sum(1 for ind in unknown_indicators if ind not in self.threat_intelligence)
        novelty_ratio = min(novel_count / max(len(unknown_indicators), 1), 1.0)
        
        return novelty_ratio * 0.7  # Zero-days score up to 0.7


class PayloadFamilyClusterer:
    """Cluster payloads into families for family-specific scoring."""

    @staticmethod
    def classify_payload(payload: str, families: Dict[str, List[str]]) -> List[str]:
        """Match payload to one or more families."""
        matches = []
        payload_lower = payload.lower()
        
        for family, patterns in families.items():
            for pattern in patterns:
                if pattern.lower() in payload_lower:
                    matches.append(family)
                    break
        
        return matches

    @staticmethod
    def apply_family_boost(family_matches: List[str], base_score: float, family_weights: Dict[str, float]) -> float:
        """Apply boost based on payload families."""
        if not family_matches:
            return base_score
        
        boost = 0.0
        for family in family_matches:
            boost += family_weights.get(family, 0.05)
        
        return min(base_score + boost, 1.0)


class VendorRuleEngine:
    """Match error pages/responses to vendor-specific signatures."""

    @staticmethod
    def detect_vendor(content: str, status_code: int, headers: Dict[str, str], vendor_rules: Dict) -> List[str]:
        """Detect vendor from response characteristics."""
        matches = []
        content_lower = content.lower()
        
        for vendor, rules in vendor_rules.items():
            fingerprints = rules.get("fingerprints", [])
            signatures = rules.get("signatures", [])
            status_codes = rules.get("status_codes", [])
            
            # Check fingerprints in content
            for fp in fingerprints:
                if fp.lower() in content_lower:
                    matches.append(vendor)
                    break
            
            # Check HTTP status codes
            if status_code in status_codes:
                matches.append(vendor)
            
            # Check signatures in headers
            for sig in signatures:
                for header_val in headers.values():
                    if sig.lower() in header_val.lower():
                        matches.append(vendor)
                        break
        
        return list(set(matches))


class ConfigExporter:
    """Export and import ModAIConfig for reproducibility."""

    @staticmethod
    def to_dict(config: ModAIConfig) -> Dict:
        """Serialize config to dictionary."""
        result = {
            "version": "3.0",
            "severity_weights": config.severity_weights,
            "max_pattern_boost": config.max_pattern_boost,
            "pattern_unit_boost": config.pattern_unit_boost,
            "entropy_bonus": config.entropy_bonus,
            "error_bonus": config.error_bonus,
            "window_size": config.window_size,
            "memory_decay": config.memory_decay,
            "enable_ml": config.enable_ml,
            "enable_response_diffing": config.enable_response_diffing,
            "enable_calibration": config.enable_calibration,
            "enable_temporal": config.enable_temporal,
            "enable_bayesian": config.enable_bayesian,
            "enable_audit_trail": config.enable_audit_trail,
            "enable_anomaly_detector": config.enable_anomaly_detector,
            "enable_metrics": config.enable_metrics,
            "enable_fp_suppression": config.enable_fp_suppression,
        }
        return result

    @staticmethod
    def to_json(config: ModAIConfig) -> str:
        """Export config as JSON."""
        return json.dumps(ConfigExporter.to_dict(config), indent=2)

    @staticmethod
    def from_dict(data: Dict) -> ModAIConfig:
        """Deserialize config from dictionary."""
        cfg = ModAIConfig()
        if "severity_weights" in data:
            cfg.severity_weights = data["severity_weights"]
        if "max_pattern_boost" in data:
            cfg.max_pattern_boost = data["max_pattern_boost"]
        if "enable_bayesian" in data:
            cfg.enable_bayesian = data["enable_bayesian"]
        return cfg
