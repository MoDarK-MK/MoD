"""
Advanced Detection Engine for MoD Scanner
Cutting-edge vulnerability detection techniques with ML-based analysis
"""

from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum
import re
import time
import hashlib
import statistics
import math
from collections import defaultdict, Counter
import logging

logger = logging.getLogger("MoD.advanced_detection")


class DetectionTechnique(Enum):
    """Advanced detection methodologies"""
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    PATTERN_MATCHING = "pattern_matching"
    ENTROPY_ANALYSIS = "entropy_analysis"
    TIME_DIFFERENTIAL = "time_differential"
    RESPONSE_COMPARISON = "response_comparison"
    STATISTICAL_ANALYSIS = "statistical_analysis"
    FUZZY_MATCHING = "fuzzy_matching"
    MACHINE_LEARNING = "machine_learning"
    ANOMALY_DETECTION = "anomaly_detection"
    SIGNATURE_BASED = "signature_based"
    HEURISTIC_ANALYSIS = "heuristic_analysis"
    MUTATION_TESTING = "mutation_testing"


@dataclass
class DetectionResult:
    """Result of advanced detection"""
    technique: DetectionTechnique
    confidence: float
    evidence: List[str]
    indicators: Dict[str, Any]
    severity: str
    false_positive_probability: float
    timestamp: float = field(default_factory=time.time)


class EntropyAnalyzer:
    """Shannon entropy and randomness analysis"""
    
    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of string"""
        if not data:
            return 0.0
        
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def calculate_normalized_entropy(data: str) -> float:
        """Normalized entropy (0-1 scale)"""
        if not data:
            return 0.0
        
        shannon = EntropyAnalyzer.calculate_shannon_entropy(data)
        max_entropy = math.log2(len(data)) if len(data) > 1 else 1
        
        return shannon / max_entropy if max_entropy > 0 else 0.0
    
    @staticmethod
    def detect_randomness(data: str, threshold: float = 0.75) -> Tuple[bool, float]:
        """Detect if data appears random"""
        normalized = EntropyAnalyzer.calculate_normalized_entropy(data)
        is_random = normalized >= threshold
        
        return is_random, normalized
    
    @staticmethod
    def analyze_token_quality(token: str) -> Dict[str, float]:
        """Comprehensive token quality analysis"""
        return {
            'entropy': EntropyAnalyzer.calculate_shannon_entropy(token),
            'normalized_entropy': EntropyAnalyzer.calculate_normalized_entropy(token),
            'character_diversity': len(set(token)) / len(token) if token else 0,
            'length_score': min(len(token) / 32, 1.0),
            'uppercase_ratio': sum(1 for c in token if c.isupper()) / len(token) if token else 0,
            'lowercase_ratio': sum(1 for c in token if c.islower()) / len(token) if token else 0,
            'digit_ratio': sum(1 for c in token if c.isdigit()) / len(token) if token else 0,
            'special_char_ratio': sum(1 for c in token if not c.isalnum()) / len(token) if token else 0,
        }


class BehavioralAnalyzer:
    """Behavioral pattern analysis for vulnerability detection"""
    
    @staticmethod
    def analyze_response_timing(
        baseline_times: List[float],
        injected_times: List[float],
        expected_delay: float = 5.0
    ) -> Tuple[bool, float]:
        """
        Advanced timing attack detection
        Returns: (is_vulnerable, confidence_score)
        """
        if not baseline_times or not injected_times:
            return False, 0.0
        
        baseline_avg = statistics.mean(baseline_times)
        injected_avg = statistics.mean(injected_times)
        
        baseline_std = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.1
        injected_std = statistics.stdev(injected_times) if len(injected_times) > 1 else 0.1
        
        # Time differential
        time_diff = injected_avg - baseline_avg
        
        # Expected range (60% - 150% of expected delay)
        expected_min = expected_delay * 0.6
        expected_max = expected_delay * 1.5
        
        # Check if timing matches expected delay
        if expected_min <= time_diff <= expected_max:
            # High confidence - timing matches expected delay
            confidence = 0.95
            
            # Reduce confidence if high variance
            if injected_std > expected_delay * 0.3:
                confidence -= 0.15
            
            return True, max(confidence, 0.7)
        
        # Partial match (50% - 200% of expected)
        if expected_delay * 0.5 <= time_diff <= expected_delay * 2.0:
            confidence = 0.70
            return True, confidence
        
        return False, 0.0
    
    @staticmethod
    def detect_error_pattern_changes(
        baseline_errors: List[str],
        injected_errors: List[str]
    ) -> Tuple[bool, float, List[str]]:
        """
        Detect changes in error patterns indicating vulnerability
        Returns: (is_different, confidence, new_error_patterns)
        """
        baseline_set = set(baseline_errors)
        injected_set = set(injected_errors)
        
        # New errors that appeared only with injection
        new_errors = injected_set - baseline_set
        
        if not new_errors:
            return False, 0.0, []
        
        # Calculate confidence based on error characteristics
        confidence = 0.5
        
        # Known vulnerability error patterns
        vuln_patterns = [
            r'sql', r'mysql', r'postgresql', r'oracle', r'syntax error',
            r'ldap', r'xpath', r'xml', r'parser', r'unexpected',
            r'exception', r'stack trace', r'warning', r'fatal',
            r'command not found', r'permission denied', r'access denied'
        ]
        
        pattern_matches = 0
        for error in new_errors:
            for pattern in vuln_patterns:
                if re.search(pattern, error, re.IGNORECASE):
                    pattern_matches += 1
                    break
        
        if pattern_matches > 0:
            confidence = min(0.5 + (pattern_matches * 0.15), 0.95)
        
        return True, confidence, list(new_errors)


class ResponseDifferentialAnalyzer:
    """Analyze response differences to detect vulnerabilities"""
    
    @staticmethod
    def calculate_levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate edit distance between two strings"""
        if len(s1) < len(s2):
            return ResponseDifferentialAnalyzer.calculate_levenshtein_distance(s2, s1)
        
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
    def calculate_similarity_ratio(s1: str, s2: str) -> float:
        """Calculate similarity ratio (0-1) between two strings"""
        if not s1 and not s2:
            return 1.0
        
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        
        distance = ResponseDifferentialAnalyzer.calculate_levenshtein_distance(s1, s2)
        return 1.0 - (distance / max_len)
    
    @staticmethod
    def detect_boolean_based_sqli(
        true_response: str,
        false_response: str,
        baseline_response: str
    ) -> Tuple[bool, float]:
        """
        Detect Boolean-based SQL injection using response comparison
        Returns: (is_vulnerable, confidence)
        """
        # Calculate similarities
        true_to_baseline = ResponseDifferentialAnalyzer.calculate_similarity_ratio(
            true_response, baseline_response
        )
        false_to_baseline = ResponseDifferentialAnalyzer.calculate_similarity_ratio(
            false_response, baseline_response
        )
        true_to_false = ResponseDifferentialAnalyzer.calculate_similarity_ratio(
            true_response, false_response
        )
        
        # Boolean SQLi detected if:
        # 1. True condition similar to baseline
        # 2. False condition different from baseline
        # 3. True and False responses are different
        
        if (true_to_baseline > 0.85 and 
            false_to_baseline < 0.70 and 
            true_to_false < 0.75):
            
            confidence = 0.90
            return True, confidence
        
        # Relaxed detection
        if (true_to_baseline > 0.75 and 
            false_to_baseline < 0.80 and 
            true_to_false < 0.85):
            
            confidence = 0.75
            return True, confidence
        
        return False, 0.0


class StatisticalAnalyzer:
    """Statistical analysis for vulnerability detection"""
    
    @staticmethod
    def detect_outliers(values: List[float], threshold: float = 2.0) -> List[int]:
        """
        Detect outliers using Z-score method
        Returns: indices of outliers
        """
        if len(values) < 3:
            return []
        
        mean = statistics.mean(values)
        std = statistics.stdev(values)
        
        if std == 0:
            return []
        
        outliers = []
        for i, value in enumerate(values):
            z_score = abs((value - mean) / std)
            if z_score > threshold:
                outliers.append(i)
        
        return outliers
    
    @staticmethod
    def analyze_response_size_distribution(
        baseline_sizes: List[int],
        injected_sizes: List[int]
    ) -> Tuple[bool, float]:
        """
        Detect anomalies in response size distribution
        Returns: (is_anomalous, confidence)
        """
        if not baseline_sizes or not injected_sizes:
            return False, 0.0
        
        baseline_mean = statistics.mean(baseline_sizes)
        injected_mean = statistics.mean(injected_sizes)
        
        baseline_std = statistics.stdev(baseline_sizes) if len(baseline_sizes) > 1 else 0.1
        
        # Calculate size difference
        size_diff = abs(injected_mean - baseline_mean)
        
        # Significant if difference > 2 standard deviations
        if size_diff > 2 * baseline_std:
            confidence = min(0.7 + (size_diff / (baseline_mean + 1)) * 0.2, 0.95)
            return True, confidence
        
        return False, 0.0


class PatternMatcher:
    """Advanced pattern matching for vulnerability signatures"""
    
    # Comprehensive vulnerability patterns
    ERROR_PATTERNS = {
        'sql_injection': [
            r'SQL syntax.*?error',
            r'mysql_fetch',
            r'ORA-\d{5}',
            r'Microsoft.*?ODBC.*?Driver',
            r'PostgreSQL.*?ERROR',
            r'Warning.*?mysql_',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'com\.mysql\.jdbc',
            r'Zend_Db_Statement',
            r'Pdo[.:].*?SQLException',
            r'org\.postgresql\.util',
            r'SQLServer JDBC Driver',
        ],
        'xss': [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'<img[^>]+onerror',
            r'<svg[^>]+onload',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
        ],
        'command_injection': [
            r'sh:\s+.*?:.*?not found',
            r'command not found',
            r'/bin/(ba)?sh',
            r'root:.*?:0:0:',
            r'uid=\d+.*?gid=\d+',
            r'Unable to fork',
            r'System32',
            r'cmd\.exe',
        ],
        'xxe': [
            r'XML\s+parsing\s+error',
            r'DOCTYPE\s+is\s+not\s+allowed',
            r'Entity.*?not\s+defined',
            r'javax\.xml\.parsers',
            r'org\.xml\.sax',
            r'SAXParseException',
        ],
        'ldap': [
            r'LDAP.*?error',
            r'javax\.naming\.directory',
            r'LDAPException',
            r'com\.sun\.jndi\.ldap',
        ],
    }
    
    @staticmethod
    def match_vulnerability_patterns(
        response: str,
        vulnerability_type: str
    ) -> Tuple[bool, float, List[str]]:
        """
        Match response against known vulnerability patterns
        Returns: (matched, confidence, matched_patterns)
        """
        patterns = PatternMatcher.ERROR_PATTERNS.get(vulnerability_type, [])
        
        matched_patterns = []
        for pattern in patterns:
            if re.search(pattern, response, re.IGNORECASE | re.MULTILINE):
                matched_patterns.append(pattern)
        
        if not matched_patterns:
            return False, 0.0, []
        
        # Calculate confidence based on number of matches
        confidence = min(0.6 + (len(matched_patterns) * 0.1), 0.95)
        
        return True, confidence, matched_patterns


class HeuristicEngine:
    """Heuristic-based vulnerability detection"""
    
    @staticmethod
    def analyze_injection_context(
        url: str,
        parameter: str,
        payload: str,
        response: str,
        response_time: float
    ) -> DetectionResult:
        """
        Comprehensive heuristic analysis
        Returns: DetectionResult with confidence and evidence
        """
        indicators = {}
        evidence = []
        confidence = 0.0
        
        # 1. Pattern matching
        for vuln_type in PatternMatcher.ERROR_PATTERNS.keys():
            matched, pattern_conf, patterns = PatternMatcher.match_vulnerability_patterns(
                response, vuln_type
            )
            if matched:
                indicators[f'{vuln_type}_patterns'] = patterns
                evidence.append(f'Matched {len(patterns)} {vuln_type} patterns')
                confidence = max(confidence, pattern_conf)
        
        # 2. Entropy analysis
        entropy = EntropyAnalyzer.calculate_normalized_entropy(response)
        indicators['response_entropy'] = entropy
        
        # 3. Response characteristics
        indicators['response_length'] = len(response)
        indicators['response_time'] = response_time
        
        # 4. Payload reflection detection
        if payload in response:
            evidence.append('Payload reflected in response')
            indicators['payload_reflected'] = True
            confidence = max(confidence, 0.70)
        
        # Determine severity
        severity = 'Low'
        if confidence >= 0.90:
            severity = 'Critical'
        elif confidence >= 0.75:
            severity = 'High'
        elif confidence >= 0.60:
            severity = 'Medium'
        
        return DetectionResult(
            technique=DetectionTechnique.HEURISTIC_ANALYSIS,
            confidence=confidence,
            evidence=evidence,
            indicators=indicators,
            severity=severity,
            false_positive_probability=1.0 - confidence
        )


class MutationTester:
    """Mutation-based testing for vulnerability confirmation"""
    
    @staticmethod
    def generate_mutations(payload: str, count: int = 10) -> List[str]:
        """Generate payload mutations"""
        mutations = [payload]
        
        # Case variations
        mutations.append(payload.upper())
        mutations.append(payload.lower())
        mutations.append(payload.swapcase())
        
        # Encoding variations
        import urllib.parse
        mutations.append(urllib.parse.quote(payload))
        mutations.append(urllib.parse.quote_plus(payload))
        
        # Space variations
        mutations.append(payload.replace(' ', '+'))
        mutations.append(payload.replace(' ', '%20'))
        mutations.append(payload.replace(' ', '\t'))
        
        # Comment insertions
        mutations.append(payload.replace(' ', '/**/ '))
        
        return list(set(mutations))[:count]
    
    @staticmethod
    def confirm_with_mutations(
        original_result: bool,
        mutation_results: List[bool]
    ) -> Tuple[bool, float]:
        """
        Confirm vulnerability using mutation testing
        Returns: (confirmed, confidence)
        """
        if not original_result:
            return False, 0.0
        
        positive_mutations = sum(1 for r in mutation_results if r)
        total_mutations = len(mutation_results)
        
        if total_mutations == 0:
            return original_result, 0.5
        
        mutation_rate = positive_mutations / total_mutations
        
        # High confidence if >70% mutations also succeed
        if mutation_rate >= 0.7:
            return True, 0.95
        elif mutation_rate >= 0.5:
            return True, 0.80
        elif mutation_rate >= 0.3:
            return True, 0.65
        
        return False, 0.4
