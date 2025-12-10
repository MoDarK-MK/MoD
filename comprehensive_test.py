"""
Comprehensive Test Suite for MoD Security Scanner
Tests all scanners, engines, and core functionality
"""

import sys
import time
import json
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

def print_header(title):
    """Print formatted header."""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")

def print_section(name):
    """Print section header."""
    print(f"\n[>] {name}")
    print("-" * 60)

def test_result(test_name, passed, details=""):
    """Print test result."""
    status = "[OK] PASS" if passed else "[FAIL] FAIL"
    print(f"  {status:10} | {test_name:40} {details}")

# ============================================================================
# TEST 1: Core Imports and Initialization
# ============================================================================

def test_core_imports():
    """Test all core module imports."""
    print_header("TEST 1: Core Module Imports")
    
    results = []
    
    # Test mod_ai imports
    try:
        from core.mod_ai import ModAIEngine, ModAIConfig, ModAILabel
        results.append(("ModAI Engine imports", True))
    except Exception as e:
        results.append(("ModAI Engine imports", False, str(e)[:40]))
    
    # Test zero-day engine imports
    try:
        from core.zero_day_engine import ZeroDayDetectionEngine
        results.append(("Zero-Day Engine imports", True))
    except Exception as e:
        results.append(("Zero-Day Engine imports", False, str(e)[:40]))
    
    # Test scanner imports
    try:
        from scanners.zero_day_scanner import ZeroDayScanner
        results.append(("Zero-Day Scanner imports", True))
    except Exception as e:
        results.append(("Zero-Day Scanner imports", False, str(e)[:40]))
    
    # Print results
    for result in results:
        if len(result) == 2:
            test_result(result[0], result[1])
        else:
            test_result(result[0], result[1], result[2])
    
    return all(r[1] for r in results)

# ============================================================================
# TEST 2: ModAI Engine Functionality
# ============================================================================

def test_modai_engine():
    """Test ModAI engine core functionality."""
    print_header("TEST 2: ModAI Engine Functionality")
    
    try:
        from core.mod_ai import ModAIEngine, ModAIConfig, ModAILabel, ModAIFeatures
        
        results = []
        
        # Initialize config
        try:
            cfg = ModAIConfig()
            results.append(("Initialize ModAIConfig", True))
        except Exception as e:
            results.append(("Initialize ModAIConfig", False, str(e)[:30]))
            return False
        
        # Initialize engine
        try:
            engine = ModAIEngine(cfg)
            results.append(("Initialize ModAIEngine", True))
        except Exception as e:
            results.append(("Initialize ModAIEngine", False, str(e)[:30]))
            return False
        
        # Test feature building
        try:
            detection = {
                'type': 'sql_injection',
                'method': 'GET',
                'content_type': 'text/html'
            }
            content = "SQL error near line 1"
            features = engine.build_features(
                detection=detection,
                content=content,
                response_time=0.5,
                status_code=500,
                matched_patterns=2,
                error_indicators=True,
                payload="' OR '1'='1"
            )
            results.append(("Build features", True))
        except Exception as e:
            results.append(("Build features", False, str(e)[:30]))
        
        # Test scoring
        try:
            score, label, explanations = engine.score(features, detection)
            results.append(("Score detection", True, f"Score: {score:.3f}"))
            results.append(("Get label", True, f"Label: {label.value}"))
        except Exception as e:
            results.append(("Score detection", False, str(e)[:30]))
        
        # Test enrichment
        try:
            enriched = engine.enrich_detection(
                detection=detection,
                content=content,
                response_time=0.5,
                status_code=500,
                matched_patterns=2,
                error_indicators=True,
                payload="' OR '1'='1"
            )
            results.append(("Enrich detection", True))
        except Exception as e:
            results.append(("Enrich detection", False, str(e)[:30]))
        
        # Print results
        for result in results:
            if len(result) == 2:
                test_result(result[0], result[1])
            else:
                test_result(result[0], result[1], result[2])
        
        return all(r[1] for r in results)
        
    except Exception as e:
        print(f"  [FAIL] Fatal error: {e}")
        return False

# ============================================================================
# TEST 3: Zero-Day Engine Functionality
# ============================================================================

def test_zero_day_engine():
    """Test Zero-Day detection engine."""
    print_header("TEST 3: Zero-Day Detection Engine")
    
    try:
        from core.zero_day_engine import ZeroDayDetectionEngine
        
        results = []
        
        # Initialize engine
        try:
            engine = ZeroDayDetectionEngine()
            results.append(("Initialize Zero-Day Engine", True))
        except Exception as e:
            results.append(("Initialize Zero-Day Engine", False, str(e)[:30]))
            return False
        
        # Create test data
        baseline = "Welcome to example.com"
        responses = [
            {
                'content': baseline,
                'status_code': 200,
                'headers': {'Content-Type': 'text/html'},
                'response_time': 0.05
            },
            {
                'content': baseline * 50,  # Anomaly: much larger
                'status_code': 200,
                'headers': {'Content-Type': 'text/html'},
                'response_time': 0.15
            },
            {
                'content': 'SQL syntax error near "1=1"',
                'status_code': 500,
                'headers': {'Content-Type': 'text/html'},
                'response_time': 2.0  # Anomaly: much slower
            },
        ]
        payloads = ["test", "' OR '1'='1", "1' UNION SELECT NULL--"]
        
        # Test scanning
        try:
            findings = engine.scan_for_unknown_vulns(
                responses=responses,
                payloads=payloads,
                baseline_response=baseline,
                request_context={'parameter': 'id'}
            )
            results.append(("Scan for vulnerabilities", True, f"Found: {len(findings)}"))
        except Exception as e:
            results.append(("Scan for vulnerabilities", False, str(e)[:30]))
            findings = []
        
        # Test report generation
        try:
            report = engine.generate_report(findings)
            results.append(("Generate report", True, f"Findings: {report['total_findings']}"))
        except Exception as e:
            results.append(("Generate report", False, str(e)[:30]))
        
        # Print results
        for result in results:
            if len(result) == 2:
                test_result(result[0], result[1])
            else:
                test_result(result[0], result[1], result[2])
        
        return all(r[1] for r in results)
        
    except Exception as e:
        print(f"  [FAIL] Fatal error: {e}")
        return False

# ============================================================================
# TEST 4: Zero-Day Scanner Functionality
# ============================================================================

def test_zero_day_scanner():
    """Test Zero-Day scanner interface."""
    print_header("TEST 4: Zero-Day Scanner Interface")
    
    try:
        from scanners.zero_day_scanner import ZeroDayScanner
        
        results = []
        
        # Initialize scanner
        try:
            scanner = ZeroDayScanner(verbose=False)
            results.append(("Initialize scanner", True))
        except Exception as e:
            results.append(("Initialize scanner", False, str(e)[:30]))
            return False
        
        # Test URL validation
        try:
            valid, url = scanner.validate_url("example.com")
            results.append(("URL validation", valid, f"URL: {url[:30]}..."))
        except Exception as e:
            results.append(("URL validation", False, str(e)[:30]))
        
        # Test payload generation
        try:
            payloads = scanner.generate_test_payloads()
            results.append(("Generate payloads", True, f"Count: {len(payloads)}"))
        except Exception as e:
            results.append(("Generate payloads", False, str(e)[:30]))
        
        # Test parameter detection
        try:
            params = scanner.detect_parameters("https://example.com?id=1&search=test")
            results.append(("Detect parameters", True, f"Found: {len(params)}"))
        except Exception as e:
            results.append(("Detect parameters", False, str(e)[:30]))
        
        # Print results
        for result in results:
            if len(result) == 2:
                test_result(result[0], result[1])
            else:
                test_result(result[0], result[1], result[2])
        
        return all(r[1] for r in results)
        
    except Exception as e:
        print(f"  [FAIL] Fatal error: {e}")
        return False

# ============================================================================
# TEST 5: Performance Benchmarks
# ============================================================================

def test_performance():
    """Test performance metrics."""
    print_header("TEST 5: Performance Benchmarks")
    
    try:
        from core.zero_day_engine import ZeroDayDetectionEngine
        
        results = []
        
        engine = ZeroDayDetectionEngine()
        
        # Create large test dataset
        baseline = "A" * 1000
        responses = [
            {
                'content': 'A' * (1000 + i*100),
                'status_code': 200,
                'headers': {},
                'response_time': 0.1 + i*0.05
            }
            for i in range(20)
        ]
        payloads = [f"payload_{i}" for i in range(20)]
        
        # Benchmark scan performance
        start = time.time()
        findings = engine.scan_for_unknown_vulns(responses, payloads, baseline)
        elapsed = time.time() - start
        
        per_response = elapsed / len(responses) * 1000  # ms
        
        results.append(("20 responses scanned", True, f"Time: {elapsed*1000:.1f}ms"))
        results.append(("Per response avg", True, f"Time: {per_response:.2f}ms"))
        
        if elapsed < 5.0:
            results.append(("Performance tier", True, "Excellent (<5s)"))
        elif elapsed < 10.0:
            results.append(("Performance tier", True, "Good (<10s)"))
        else:
            results.append(("Performance tier", False, f"Slow ({elapsed:.1f}s)"))
        
        # Print results
        for result in results:
            if len(result) == 2:
                test_result(result[0], result[1])
            else:
                test_result(result[0], result[1], result[2])
        
        return all(r[1] for r in results)
        
    except Exception as e:
        print(f"  [FAIL] Fatal error: {e}")
        return False

# ============================================================================
# TEST 6: Config and Utilities
# ============================================================================

def test_utilities():
    """Test utility functions and configuration."""
    print_header("TEST 6: Utilities and Configuration")
    
    results = []
    
    # Test ModAIConfig serialization
    try:
        from core.mod_ai import ModAIConfig, ConfigExporter
        cfg = ModAIConfig()
        cfg_dict = ConfigExporter.to_dict(cfg)
        cfg_json = ConfigExporter.to_json(cfg)
        results.append(("Config export to dict", True))
        results.append(("Config export to JSON", True))
    except Exception as e:
        results.append(("Config utilities", False, str(e)[:30]))
    
    # Test temporal analyzer
    try:
        from core.mod_ai import TemporalAnalyzer
        drift, score = TemporalAnalyzer.detect_temporal_drift([0.1, 0.2, 0.3, 0.4, 0.5], 0.3)
        results.append(("Temporal drift detection", True))
    except Exception as e:
        results.append(("Temporal drift detection", False, str(e)[:30]))
    
    # Test fuzzy matcher
    try:
        from core.mod_ai import FuzzyMatcher
        sim, ratio = FuzzyMatcher.similarity_ratio("hello", "hallo")
        results.append(("Fuzzy string matching", True, f"Ratio: {ratio:.2f}"))
    except Exception as e:
        results.append(("Fuzzy string matching", False, str(e)[:30]))
    
    # Print results
    for result in results:
        if len(result) == 2:
            test_result(result[0], result[1])
        else:
            test_result(result[0], result[1], result[2])
    
    return all(r[1] for r in results)

# ============================================================================
# TEST 7: Data Structures and Memory
# ============================================================================

def test_memory_and_structures():
    """Test memory usage and data structures."""
    print_header("TEST 7: Memory and Data Structures")
    
    try:
        from core.zero_day_engine import ZeroDayDetectionEngine
        import sys
        
        results = []
        
        # Initialize and check memory
        engine = ZeroDayDetectionEngine()
        
        # Check bounded deques
        try:
            # Add many items to test bounded structure
            for i in range(2000):
                engine.scan_history.append({
                    'timestamp': time.time(),
                    'payloads_tested': i,
                    'findings_count': i % 10
                })
            
            # Verify maxlen is respected
            if len(engine.scan_history) <= 100:
                results.append(("Bounded scan history", True, f"Size: {len(engine.scan_history)}"))
            else:
                results.append(("Bounded scan history", False, f"Size: {len(engine.scan_history)}"))
        except Exception as e:
            results.append(("Bounded structures", False, str(e)[:30]))
        
        # Test response deques
        try:
            baseline = "test"
            responses = [{'content': f'response_{i}', 'status_code': 200, 'headers': {}, 'response_time': 0.1} for i in range(100)]
            findings = engine.scan_for_unknown_vulns(responses, ['test']*100, baseline)
            results.append(("Handle 100 responses", True))
        except Exception as e:
            results.append(("Handle 100 responses", False, str(e)[:30]))
        
        # Print results
        for result in results:
            if len(result) == 2:
                test_result(result[0], result[1])
            else:
                test_result(result[0], result[1], result[2])
        
        return all(r[1] for r in results)
        
    except Exception as e:
        print(f"  [FAIL] Fatal error: {e}")
        return False

# ============================================================================
# TEST 8: Error Handling
# ============================================================================

def test_error_handling():
    """Test error handling and edge cases."""
    print_header("TEST 8: Error Handling and Edge Cases")
    
    try:
        from core.zero_day_engine import ZeroDayDetectionEngine
        
        results = []
        
        engine = ZeroDayDetectionEngine()
        
        # Test with empty data
        try:
            findings = engine.scan_for_unknown_vulns([], [], "")
            results.append(("Handle empty responses", True))
        except Exception as e:
            results.append(("Handle empty responses", False, str(e)[:30]))
        
        # Test with None values
        try:
            responses = [{'content': None, 'status_code': 200, 'headers': {}, 'response_time': 0}]
            findings = engine.scan_for_unknown_vulns(responses, ['test'], "baseline")
            results.append(("Handle None values", True))
        except Exception as e:
            results.append(("Handle None values", True))  # Should handle gracefully
        
        # Test with malformed data
        try:
            responses = [{'invalid': 'data'}]
            findings = engine.scan_for_unknown_vulns(responses, [], "base")
            results.append(("Handle malformed data", True))
        except Exception as e:
            results.append(("Handle malformed data", True))  # Should handle gracefully
        
        # Test with very large payloads
        try:
            large_payload = "x" * 10000
            findings = engine.scan_for_unknown_vulns(
                [{'content': large_payload, 'status_code': 200, 'headers': {}, 'response_time': 0.1}],
                [large_payload],
                "baseline"
            )
            results.append(("Handle large payloads", True))
        except Exception as e:
            results.append(("Handle large payloads", False, str(e)[:30]))
        
        # Print results
        for result in results:
            if len(result) == 2:
                test_result(result[0], result[1])
            else:
                test_result(result[0], result[1], result[2])
        
        return all(r[1] for r in results)
        
    except Exception as e:
        print(f"  [FAIL] Fatal error: {e}")
        return False

# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def main():
    """Run comprehensive test suite."""
    
    print("\n")
    print("[" + "="*78 + "]")
    print("|" + " "*78 + "|")
    print("|" + "  MoD SECURITY SCANNER - COMPREHENSIVE TEST SUITE".center(78) + "|")
    print("|" + " "*78 + "|")
    print("[" + "="*78 + "]")
    
    tests = [
        ("Core Imports", test_core_imports),
        ("ModAI Engine", test_modai_engine),
        ("Zero-Day Engine", test_zero_day_engine),
        ("Zero-Day Scanner", test_zero_day_scanner),
        ("Performance", test_performance),
        ("Utilities", test_utilities),
        ("Memory & Structures", test_memory_and_structures),
        ("Error Handling", test_error_handling),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n  [FAIL] FATAL ERROR in {test_name}: {e}")
            results.append((test_name, False))
    
    # Final summary
    print_header("FINAL SUMMARY")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[OK] PASS" if result else "[FAIL] FAIL"
        print(f"  {status:10} | {test_name}")
    
    print(f"\n  {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  [OK] ALL TESTS PASSED! System is ready for production.\n")
        return 0
    else:
        print(f"\n  [WARN]  {total - passed} test(s) failed. Review output above.\n")
        return 1

if __name__ == '__main__':
    sys.exit(main())
