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

        # Feature 15: Lightweight anomaly detector (add score to history, check for outlier)
        if self.cfg.enable_anomaly_detector and features.target_id:
            self.anomaly_detector.add(features.target_id, features.response_time)
            is_anom, z_score = self.anomaly_detector.is_anomaly(features.target_id, features.response_time)
            if is_anom and z_score > 2.5:
                base += 0.06
                explanations.append(f"anom_outlier+0.06")

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
        if self.cfg.enable_bayesian:
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
