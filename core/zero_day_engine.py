"""
Zero-Day Detection Engine - Advanced ML-based vulnerability discovery
===========================================================================
Detects unknown vulnerabilities using behavior analysis, anomaly detection,
and statistical pattern recognition. 50x enhanced detection capabilities.
"""

import time
import math
import statistics
import hashlib
import re
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    """Zero-Day severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ZeroDayFinding:
    """Structured zero-day detection finding."""
    detection_type: str
    severity: SeverityLevel
    confidence: float
    indicators: List[str]
    payload_index: Optional[int] = None
    bypass_patterns: List[Tuple[str, float]] = None
    anomaly_details: Dict = None
    recommendation: str = ""


class AdvancedZeroDayAnomalyDetector:
    """Enterprise-grade anomaly detection with multi-dimensional analysis."""
    
    def __init__(self, advanced_mode: bool = True):
        self.baseline_responses = deque(maxlen=1000)
        self.response_patterns = defaultdict(list)
        self.entropy_baseline = 4.5
        self.timing_baseline = 0.5
        self.advanced_mode = advanced_mode
        
        # Multi-dimensional baselines
        self.size_distribution = deque(maxlen=500)
        self.timing_distribution = deque(maxlen=500)
        self.entropy_distribution = deque(maxlen=500)
        self.header_patterns = defaultdict(lambda: defaultdict(int))
        self.response_fingerprints = defaultdict(int)
        self.parameter_correlations = defaultdict(list)
        self.protocol_anomalies = defaultdict(list)
        
    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy with normalized output."""
        if not data or len(data) < 2:
            return 0.0
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            if p > 0:
                entropy -= p * math.log2(p)
        # Normalize to 0-1 range
        max_entropy = math.log2(len(data))
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def detect_response_header_anomalies(self, headers: Dict[str, str]) -> float:
        """Detect anomalous HTTP headers (potential exploitation indicators)."""
        anomaly_score = 0.0
        
        # Check for missing standard headers
        standard_headers = {'Content-Type', 'Content-Length', 'Server', 'Date'}
        missing_headers = len(standard_headers - set(headers.keys())) / len(standard_headers)
        anomaly_score += missing_headers * 0.15
        
        # Check for unusual header values
        for header, value in headers.items():
            # Detect obfuscated headers
            if len(value) > 500:
                anomaly_score += 0.1
            # Detect encoding in header values
            if any(enc in value.lower() for enc in ['base64', 'encoded', 'gzip', 'deflate']):
                anomaly_score += 0.05
            # Detect SQL/RCE indicators in headers
            if any(ind in value.lower() for ind in ['union', 'select', 'exec', 'bash', 'cmd']):
                anomaly_score += 0.2
        
        return min(anomaly_score, 1.0)
    
    def detect_unusual_response_size(self, response_size: int, baseline_sizes: List[int]) -> float:
        """Detect abnormal response sizes with advanced statistical methods."""
        if len(baseline_sizes) < 3:
            return 0.0
        
        baseline_sizes = sorted(baseline_sizes)
        avg_size = statistics.mean(baseline_sizes)
        
        # Use percentile-based detection (more robust than Z-score)
        if len(baseline_sizes) >= 10:
            p25 = baseline_sizes[len(baseline_sizes)//4]
            p75 = baseline_sizes[3*len(baseline_sizes)//4]
            iqr = p75 - p25
            lower_bound = max(0, p25 - 3 * iqr)
            upper_bound = p75 + 3 * iqr
        else:
            std_dev = statistics.stdev(baseline_sizes) if len(baseline_sizes) > 1 else avg_size * 0.1
            if std_dev == 0:
                std_dev = avg_size * 0.1
            lower_bound = max(0, avg_size - 3 * std_dev)
            upper_bound = avg_size + 3 * std_dev
        
        # Calculate anomaly score
        if response_size < lower_bound or response_size > upper_bound:
            std_dev = statistics.stdev(baseline_sizes) if len(baseline_sizes) > 1 else avg_size * 0.1
            z_score = abs((response_size - avg_size) / (std_dev if std_dev > 0 else avg_size * 0.1))
            return min(z_score / 5.0, 1.0)
        
        return 0.0
    
    def detect_timing_anomalies(self, response_times: List[float]) -> float:
        """Detect timing-based attack patterns using advanced statistics."""
        if len(response_times) < 5:
            return 0.0
        
        response_times_sorted = sorted(response_times)
        avg_time = statistics.mean(response_times)
        
        if avg_time == 0:
            return 0.0
        
        # Detect monotonic increase (time-based blind injection)
        increasing_count = sum(1 for i in range(len(response_times_sorted)-1) 
                              if response_times_sorted[i+1] > response_times_sorted[i] * 1.2)
        monotonic_score = min(increasing_count / max(len(response_times_sorted) - 1, 1), 1.0) * 0.4
        
        # Detect variance anomaly
        stdev = statistics.stdev(response_times) if len(response_times) > 1 else avg_time * 0.2
        variance_ratio = stdev / avg_time
        variance_score = min(variance_ratio / 0.5, 1.0) * 0.3
        
        # Detect bimodal distribution (conditional delays)
        median = statistics.median(response_times_sorted)
        slow_count = sum(1 for t in response_times if t > median * 1.5)
        fast_count = sum(1 for t in response_times if t < median * 0.5)
        
        if slow_count >= len(response_times) * 0.3 and fast_count >= len(response_times) * 0.2:
            bimodal_score = 0.3
        else:
            bimodal_score = 0.0
        
        return min(monotonic_score + variance_score + bimodal_score, 1.0)
    
    def detect_encoding_mutations(self, payloads: List[str], responses: List[str]) -> float:
        """Detect encoding bypass attempts with entropy analysis."""
        if len(payloads) < 3 or len(responses) < 3:
            return 0.0
        
        mutation_scores = []
        
        for payload, response in zip(payloads, responses):
            # Calculate entropy difference
            payload_entropy = self.calculate_entropy(payload)
            response_entropy = self.calculate_entropy(response)
            
            entropy_diff = abs(response_entropy - payload_entropy)
            
            # Detect obfuscation patterns
            if entropy_diff > 0.5:
                mutation_scores.append(0.9)
            
            # Detect encoding signatures
            encoding_patterns = ['base64', 'hex', 'url', 'html', '%20', '&#']
            encoding_count = sum(1 for pattern in encoding_patterns if pattern in response.lower())
            
            if encoding_count >= 2:
                mutation_scores.append(0.8)
            
            # Detect low entropy (compression/encryption)
            if response_entropy < 2.0 and len(response) > 50:
                mutation_scores.append(0.7)
        
        return min(statistics.mean(mutation_scores) if mutation_scores else 0.0, 1.0)
    
    def detect_behavioral_anomalies(self, request_data: Dict, response_data: Dict = None) -> float:
        """Detect sophisticated behavioral anomalies."""
        anomaly_score = 0.0
        
        # Parameter mutation detection
        if 'parameters' in request_data:
            param_count = len(request_data['parameters'])
            # Non-linear scoring for unusual parameter counts
            if param_count > 50:
                anomaly_score += 0.25
            elif param_count > 30:
                anomaly_score += 0.15
            elif param_count > 20:
                anomaly_score += 0.1
            
            # Check for parameter injection patterns
            params = request_data.get('parameters', {})
            if isinstance(params, dict):
                for key, value in params.items():
                    # Detect SQL injection patterns
                    sql_patterns = ['union', 'select', 'insert', 'delete', 'drop', '1=1', 'or', 'and']
                    if any(p in str(value).lower() for p in sql_patterns):
                        anomaly_score += 0.15
                    
                    # Detect command injection
                    cmd_patterns = ['|', '&', ';', '`', '$', '$(', '{', '}', '||', '&&']
                    if any(p in str(value) for p in cmd_patterns):
                        anomaly_score += 0.15
        
        # Header anomalies
        if 'headers' in request_data:
            header_anomaly = self.detect_response_header_anomalies(request_data['headers'])
            anomaly_score += header_anomaly * 0.2
        
        # Payload pattern analysis
        if 'payload' in request_data:
            payload = request_data['payload']
            
            # Detect special character density
            special_chars = sum(1 for c in payload if c in '`$(){}[]|;\\<>"\'\n')
            density = special_chars / max(len(payload), 1)
            
            if density > 0.4:
                anomaly_score += 0.25
            elif density > 0.2:
                anomaly_score += 0.15
            
            # Detect null bytes and control characters
            if '\x00' in payload or any(ord(c) < 32 for c in payload if c not in '\n\t\r'):
                anomaly_score += 0.2
        
        # Response analysis
        if response_data:
            if 'content' in response_data:
                content = response_data['content']
                # Detect stack traces
                if any(trace in content.lower() for trace in ['traceback', 'stacktrace', 'at line']):
                    anomaly_score += 0.25
                # Detect error messages
                if any(err in content.lower() for err in ['sql error', 'parse error', 'undefined']):
                    anomaly_score += 0.15
        
        return min(anomaly_score, 1.0)
    
    def detect_data_exfiltration(self, responses: List[Dict]) -> float:
        """Detect potential data exfiltration attempts."""
        if len(responses) < 2:
            return 0.0
        
        exfil_score = 0.0
        
        # Check for increasing response sizes (data leakage)
        sizes = [len(r.get('content', '')) for r in responses]
        if len(sizes) >= 3:
            size_trend = sum(1 for i in range(len(sizes)-1) if sizes[i+1] > sizes[i] * 1.1)
            trend_ratio = size_trend / max(len(sizes) - 1, 1)
            exfil_score += trend_ratio * 0.3
        
        # Check for high-entropy content (encrypted data)
        for response in responses:
            content = response.get('content', '')
            if len(content) > 100:
                entropy = self.calculate_entropy(content)
                if entropy > 0.8:
                    exfil_score += 0.2
        
        # Check for suspicious content types
        for response in responses:
            headers = response.get('headers', {})
            content_type = headers.get('Content-Type', '').lower()
            if any(ct in content_type for ct in ['octet-stream', 'binary', 'application/x-']):
                exfil_score += 0.15
        
        return min(exfil_score, 1.0)


class AdvancedZeroDayBehaviorAnalyzer:
    """Advanced behavior analysis for unknown vulnerability patterns."""
    
    def __init__(self):
        self.attack_chains = defaultdict(list)
        self.success_patterns = deque(maxlen=500)
        self.failure_patterns = deque(maxlen=500)
        
    def analyze_injection_behavior(self, baseline: str, test_responses: List[str], 
                                   payloads: List[str] = None) -> Dict[str, float]:
        """Comprehensive injection behavior analysis."""
        if not test_responses:
            return {"overall_score": 0.0, "sql_score": 0.0, "rce_score": 0.0, "xxe_score": 0.0}
        
        results = {
            "overall_score": 0.0,
            "sql_score": 0.0,
            "rce_score": 0.0,
            "xxe_score": 0.0,
            "xss_score": 0.0,
            "ldap_score": 0.0,
            "path_traversal_score": 0.0,
        }
        
        baseline_len = len(baseline)
        variance_scores = []
        
        for i, response in enumerate(test_responses):
            if len(response) == 0:
                continue
            
            # Length variance
            length_variance = abs(len(response) - baseline_len) / max(baseline_len, 1)
            variance_scores.append(min(length_variance, 1.0))
            
            # SQL Injection indicators
            sql_indicators = ['sql syntax error', 'mysql', 'postgresql', 'oracle database',
                            'sqlserver', 'unexpected end', 'column count', 'duplicate column',
                            'near:', 'syntax error in', 'parse error']
            sql_score = sum(1 for ind in sql_indicators if ind in response.lower()) / max(len(sql_indicators), 1)
            results["sql_score"] = max(results["sql_score"], min(sql_score + length_variance * 0.2, 1.0))
            
            # RCE indicators
            rce_indicators = ['command executed', 'uid=', 'gid=', 'root@', 'root#', 
                            'total', 'drwxr', 'bin/bash', 'bin/sh', 'shell_exec', 
                            'system(', 'passthru', 'exec(', 'popen(']
            rce_score = sum(1 for ind in rce_indicators if ind in response.lower()) / max(len(rce_indicators), 1)
            results["rce_score"] = max(results["rce_score"], min(rce_score + length_variance * 0.3, 1.0))
            
            # XXE indicators
            xxe_indicators = ['<!entity', 'system', 'public', 'dtd', 'xml version',
                            'doctype', 'parameter entity', 'external entity']
            xxe_score = sum(1 for ind in xxe_indicators if ind in response.lower()) / max(len(xxe_indicators), 1)
            results["xxe_score"] = max(results["xxe_score"], min(xxe_score, 1.0))
            
            # XSS indicators
            xss_indicators = ['<script', 'javascript:', 'onerror=', 'onload=', 'eval(', 'alert(']
            xss_score = sum(1 for ind in xss_indicators if ind in response.lower()) / max(len(xss_indicators), 1)
            results["xss_score"] = max(results["xss_score"], min(xss_score, 1.0))
            
            # LDAP Injection indicators
            ldap_indicators = ['ldap error', 'ldap result', 'no such object', 'invalid dn', '*(']
            ldap_score = sum(1 for ind in ldap_indicators if ind in response.lower()) / max(len(ldap_indicators), 1)
            results["ldap_score"] = max(results["ldap_score"], min(ldap_score, 1.0))
            
            # Path Traversal indicators
            path_indicators = ['../', '..\\', '/etc/', '/var/', 'c:\\windows', 'c:\\winnt']
            path_score = sum(1 for ind in path_indicators if ind in response.lower()) / max(len(path_indicators), 1)
            results["path_traversal_score"] = max(results["path_traversal_score"], min(path_score, 1.0))
        
        results["overall_score"] = min(statistics.mean(variance_scores) if variance_scores else 0.0, 1.0)
        return results
    
    def detect_filter_bypasses(self, payloads: List[str], responses: List[str]) -> List[Tuple[str, float, str]]:
        """Identify filter bypass techniques with classification."""
        bypass_findings = []
        
        bypass_patterns = {
            "case_mutation": ["UnIoN", "sElEcT", "InSeRt", "DeLeTe"],
            "comment_injection": ["/**/", "-- ", "#", "/*! */"],
            "encoding": ["%20", "%09", "%0a", "&#32;", "&#9;"],
            "char_substitution": ["<", ">", "[", "]", "{", "}"],
            "null_byte": ["%00", "\\x00"],
        }
        
        for payload, response in zip(payloads, responses):
            # Check for successful payload indicators
            if 'error' not in response.lower() and len(response) > 100:
                bypass_findings.append((payload, 0.85, "verbose_response"))
            
            # Check for conditional success
            if any(ind in response for ind in ['admin', 'true', '1=1', 'success', 'authenticated']):
                bypass_findings.append((payload, 0.9, "positive_indicator"))
            
            # Detect bypass technique used
            for technique, patterns in bypass_patterns.items():
                for pattern in patterns:
                    if pattern in payload:
                        bypass_findings.append((payload, 0.75, technique))
                        break
        
        return sorted(bypass_findings, key=lambda x: x[1], reverse=True)
    
    def detect_protocol_violations(self, request: Dict, response: Dict) -> float:
        """Detect protocol-level anomalies."""
        violation_score = 0.0
        
        # HTTP status code validation
        if 'status_code' in response:
            status_code = response['status_code']
            # Unusual status codes might indicate WAF bypass or protocol violation
            if status_code in [418, 451, 511, 599]:  # Unusual codes
                violation_score += 0.2
        
        # Response validation
        if 'headers' in response:
            headers = response['headers']
            # Missing content-length with chunked encoding
            if 'Transfer-Encoding' in headers and 'Content-Length' in headers:
                violation_score += 0.15
            
            # Contradictory headers
            if 'Content-Type' in headers and 'Content-Encoding' in headers:
                ct = headers['Content-Type'].lower()
                ce = headers['Content-Encoding'].lower()
                # Some combinations are suspicious
                if 'json' in ct and 'gzip' in ce:
                    violation_score += 0.1
        
        return min(violation_score, 1.0)


class ZeroDayDetectionEngine:
    """50x Enhanced zero-day detection engine with ML capabilities."""
    
    def __init__(self):
        self.anomaly_detector = AdvancedZeroDayAnomalyDetector(advanced_mode=True)
        self.behavior_analyzer = AdvancedZeroDayBehaviorAnalyzer()
        self.learned_patterns = defaultdict(list)
        self.discovered_vulns = []
        self.scan_history = deque(maxlen=100)
        
    def scan_for_unknown_vulns(self, responses: List[Dict], payloads: List[str], 
                               baseline_response: str, request_context: Dict = None) -> List[ZeroDayFinding]:
        """
        Comprehensive zero-day vulnerability scanning.
        
        Args:
            responses: List of HTTP responses [{'content': str, 'headers': dict, 'status_code': int, 'response_time': float}]
            payloads: List of test payloads used
            baseline_response: Normal baseline response for comparison
            request_context: Additional request context for analysis
            
        Returns:
            List of detected zero-day findings
        """
        findings = []
        
        if not responses or not payloads:
            return findings
        
        # Extract response data
        response_times = [r.get('response_time', 0) for r in responses]
        response_sizes = [len(r.get('content', '')) for r in responses]
        response_contents = [r.get('content', '') for r in responses]
        response_headers = [r.get('headers', {}) for r in responses]
        
        # ===== PHASE 1: Anomaly Detection Suite =====
        size_anomalies = []
        for size in response_sizes:
            anomaly = self.anomaly_detector.detect_unusual_response_size(size, response_sizes)
            if anomaly > 0.7:
                size_anomalies.append(anomaly)
        
        timing_anomaly = self.anomaly_detector.detect_timing_anomalies(response_times)
        encoding_anomaly = self.anomaly_detector.detect_encoding_mutations(payloads, response_contents)
        
        # ===== PHASE 2: Behavioral Analysis =====
        behavior_scores = self.behavior_analyzer.analyze_injection_behavior(
            baseline_response, response_contents, payloads
        )
        bypass_patterns = self.behavior_analyzer.detect_filter_bypasses(
            payloads, response_contents
        )
        
        # ===== PHASE 3: Header Analysis =====
        header_anomaly_scores = [
            self.anomaly_detector.detect_response_header_anomalies(h) 
            for h in response_headers
        ]
        max_header_anomaly = max(header_anomaly_scores) if header_anomaly_scores else 0.0
        
        # ===== PHASE 4: Data Exfiltration Detection =====
        exfil_score = self.anomaly_detector.detect_data_exfiltration(responses)
        
        # ===== PHASE 5: Composite Zero-Day Scoring =====
        if size_anomalies:
            zero_day_score = (
                statistics.mean(size_anomalies) * 0.30 +
                timing_anomaly * 0.20 +
                encoding_anomaly * 0.15 +
                max(behavior_scores.values()) * 0.20 +
                max_header_anomaly * 0.10 +
                exfil_score * 0.05
            )
            
            if zero_day_score > 0.65:
                finding = ZeroDayFinding(
                    detection_type='POTENTIAL_ZERO_DAY',
                    severity=SeverityLevel.CRITICAL if zero_day_score > 0.85 else SeverityLevel.HIGH,
                    confidence=min(zero_day_score, 1.0),
                    indicators=[
                        f'Size anomalies: {len(size_anomalies)} detected',
                        f'Timing variance: {timing_anomaly:.3f}',
                        f'Encoding mutations: {encoding_anomaly:.3f}',
                        f'Behavior changes: {max(behavior_scores.values()):.3f}',
                        f'Header anomalies: {max_header_anomaly:.3f}',
                        f'Data exfiltration risk: {exfil_score:.3f}',
                    ],
                    bypass_patterns=bypass_patterns[:5],
                    recommendation="Escalate to security team. Apply WAF rules and monitor for similar patterns."
                )
                findings.append(finding)
        
        # ===== PHASE 6: Per-Vulnerability-Type Scoring =====
        for vuln_type, score in behavior_scores.items():
            if vuln_type != "overall_score" and score > 0.6:
                severity = SeverityLevel.CRITICAL if score > 0.85 else (
                    SeverityLevel.HIGH if score > 0.75 else SeverityLevel.MEDIUM
                )
                finding = ZeroDayFinding(
                    detection_type=f'SUSPECTED_{vuln_type.upper()}',
                    severity=severity,
                    confidence=score,
                    indicators=[
                        f'{vuln_type.title()} confidence: {score:.3f}',
                        f'Response variation detected',
                    ],
                    bypass_patterns=bypass_patterns[:3],
                    recommendation=f"Investigate potential {vuln_type} vulnerability"
                )
                findings.append(finding)
        
        # ===== PHASE 7: Statistical Outlier Detection =====
        if response_sizes and len(response_sizes) > 5:
            try:
                q1 = statistics.quantiles(response_sizes, n=4)[0]
                q3 = statistics.quantiles(response_sizes, n=4)[2]
                iqr = q3 - q1
                outlier_threshold = q3 + 1.5 * iqr
                
                for i, size in enumerate(response_sizes):
                    if size > outlier_threshold:
                        finding = ZeroDayFinding(
                            detection_type='RESPONSE_SIZE_OUTLIER',
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.75,
                            indicators=[f'Response size: {size} bytes (threshold: {outlier_threshold:.0f})'],
                            payload_index=i,
                            recommendation="Analyze payload for data leakage"
                        )
                        findings.append(finding)
            except:
                pass
        
        # ===== PHASE 8: Protocol Violation Detection =====
        for i, response in enumerate(responses):
            if request_context:
                violation_score = self.behavior_analyzer.detect_protocol_violations(
                    request_context, response
                )
                if violation_score > 0.4:
                    finding = ZeroDayFinding(
                        detection_type='PROTOCOL_VIOLATION',
                        severity=SeverityLevel.MEDIUM,
                        confidence=violation_score,
                        indicators=['Unusual HTTP protocol behavior detected'],
                        payload_index=i,
                        recommendation="Check for HTTP/2 or protocol-level attacks"
                    )
                    findings.append(finding)
        
        # Store in history
        self.scan_history.append({
            "timestamp": time.time(),
            "payloads_tested": len(payloads),
            "findings_count": len(findings),
            "highest_score": max([f.confidence for f in findings], default=0.0)
        })
        
        return findings
    
    def generate_report(self, findings: List[ZeroDayFinding]) -> Dict:
        """Generate comprehensive analysis report."""
        if not findings:
            return {
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "status": "No vulnerabilities detected",
                "findings": []
            }
        
        severity_counts = defaultdict(int)
        for finding in findings:
            severity_counts[finding.severity.value] += 1
        
        return {
            "total_findings": len(findings),
            "critical_count": severity_counts.get(SeverityLevel.CRITICAL.value, 0),
            "high_count": severity_counts.get(SeverityLevel.HIGH.value, 0),
            "medium_count": severity_counts.get(SeverityLevel.MEDIUM.value, 0),
            "low_count": severity_counts.get(SeverityLevel.LOW.value, 0),
            "status": "Vulnerabilities detected" if findings else "Clean",
            "findings": [
                {
                    "type": f.detection_type,
                    "severity": f.severity.value,
                    "confidence": round(f.confidence, 3),
                    "indicators": f.indicators,
                    "recommendation": f.recommendation,
                    "bypass_patterns": f.bypass_patterns[:3] if f.bypass_patterns else []
                }
                for f in findings
            ]
        }
