"""
Test Phase A-D new features (v4.0 enhancement)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.mod_ai import (
    ModAIEngine,
    ModAIConfig,
    ModAIFeatures,
    ResponseDiffer,
    PayloadComplexityAnalyzer,
    HTTPContextAnalyzer,
    IsolationForestAnomalyDetector,
    ChainOfEvidenceGraph,
    ConfidenceCalibrator,
    FuzzyMatcher,
)


def test_phase_a_features():
    print("\n" + "="*70)
    print("PHASE A: Advanced Enhancements Test Suite")
    print("="*70)
    
    # Test 1: Advanced Response Diffing
    print("\n[TEST 1] Advanced Response Diffing")
    baseline_json = '{"id": 1, "status": "ok"}'
    injected_json = '{"id": 1, "status": "ok", "admin": true}'
    is_diff, ratio, diff_info = ResponseDiffer.json_structure_diff(
        ResponseDiffer.parse_json_structure(baseline_json),
        ResponseDiffer.parse_json_structure(injected_json)
    )
    assert is_diff, "Should detect JSON structure diff"
    assert len(diff_info['added']) > 0, "Should detect added keys"
    print(f"  [OK] Detected JSON diff: {diff_info}")
    
    # Test 2: HTML Table Diffing
    print("\n[TEST 2] HTML Table Diffing")
    baseline_html = '<table><tr><td>user1</td></tr><tr><td>user2</td></tr></table>'
    injected_html = '<table><tr><td>user1</td></tr></table>'
    diff = ResponseDiffer.html_table_diff(baseline_html, injected_html)
    assert 0 <= diff <= 1, "Diff ratio should be 0-1"
    print(f"  [OK] HTML table diff: {diff:.2f}")
    
    # Test 3: Payload Complexity Analyzer
    print("\n[TEST 3] Payload Complexity Analysis")
    simple_payload = "test"
    complex_payload = "union select 1,2,3; sleep(5); or 1=1"
    simple_score = PayloadComplexityAnalyzer.score_complexity(simple_payload)
    complex_score = PayloadComplexityAnalyzer.score_complexity(complex_payload)
    assert complex_score > simple_score, "Complex payload should score higher"
    
    nesting = PayloadComplexityAnalyzer.count_nesting_depth(complex_payload)
    assert nesting >= 0, "Nesting depth should be non-negative"
    print(f"  [OK] Simple: {simple_score:.2f}, Complex: {complex_score:.2f}, Nesting: {nesting}")
    
    # Test 4: Payload Encoding Detection
    print("\n[TEST 4] Encoding Detection")
    base64_payload = "dW5pb24gc2VsZWN0"
    hex_payload = "48656c6c6f"
    url_payload = "%75%6e%69%6f%6e"
    
    base64_enc = PayloadComplexityAnalyzer.detect_encoding(base64_payload)
    hex_enc = PayloadComplexityAnalyzer.detect_encoding(hex_payload)
    url_enc = PayloadComplexityAnalyzer.detect_encoding(url_payload)
    
    assert 'base64' in base64_enc, "Should detect base64"
    assert 'hex' in hex_enc, "Should detect hex"
    assert 'url' in url_enc, "Should detect URL encoding"
    print(f"  [OK] Base64: {base64_enc}, Hex: {hex_enc}, URL: {url_enc}")
    
    # Test 5: HTTP Context Analyzer
    print("\n[TEST 5] HTTP Context Analysis")
    method_risk = HTTPContextAnalyzer.analyze_method("DELETE")
    ct_risk = HTTPContextAnalyzer.analyze_content_type("application/json")
    assert method_risk > 0, "Should score method risk"
    assert ct_risk > 0, "Should score content-type risk"
    print(f"  [OK] DELETE risk: {method_risk:.2f}, JSON risk: {ct_risk:.2f}")
    
    # Test 6: Isolation Forest Anomaly Detector
    print("\n[TEST 6] Isolation Forest Anomaly Detector")
    if_detector = IsolationForestAnomalyDetector()
    normal_scores = [2.0, 2.1, 2.05, 1.95, 2.02, 1.98, 2.03] * 3
    if_detector.train(normal_scores)
    
    normal_pred = if_detector.predict(2.0)
    anomaly_pred = if_detector.predict(20.0)
    assert normal_pred == -1, "Normal should be -1"
    assert anomaly_pred == 1, "Anomaly should be 1"
    print(f"  [OK] Normal: {normal_pred}, Anomaly: {anomaly_pred}")
    
    # Test 7: Chain-of-Evidence Graph
    print("\n[TEST 7] Chain-of-Evidence Graph")
    coe = ChainOfEvidenceGraph()
    coe.add_signal("confidence", 0.85)
    coe.add_signal("patterns", 0.7)
    coe.add_signal("errors", 1.0)
    coe.add_edge("confidence", "patterns", 0.8)
    coe.add_edge("patterns", "errors", 0.9)
    
    final_score = coe.compute_propagation("confidence")
    explanation = coe.get_explanation()
    assert 0 <= final_score <= 1, "Score should be 0-1"
    assert len(explanation) > 0, "Should have explanation"
    print(f"  [OK] COE score: {final_score:.2f}, chain: {explanation}")
    
    # Test 8: Confidence Calibrator
    print("\n[TEST 8] Confidence Calibrator")
    calibrator = ConfidenceCalibrator()
    
    # Record some detections
    for score in [0.9, 0.88, 0.92, 0.85]:
        calibrator.record_detection(score, "SQLi", True)
    for score in [0.4, 0.35, 0.45]:
        calibrator.record_detection(score, "SQLi", False)
    
    thresholds = calibrator.calibrate("SQLi")
    label = calibrator.get_label(0.88, "SQLi")
    assert isinstance(label, str), "Should return label string"
    print(f"  [OK] Calibrated thresholds: {thresholds}, Label for 0.88: {label}")
    
    # Test 9: Fuzzy Matcher
    print("\n[TEST 9] Fuzzy Matcher")
    payload = "union select 1,2,3"
    signatures = ["union select 1,2,3", "union select 1,2", "select * from"]
    
    distance = FuzzyMatcher.levenshtein_distance(payload, signatures[0])
    assert distance == 0, "Identical strings should have distance 0"
    
    is_match, ratio = FuzzyMatcher.similarity_ratio(payload, signatures[0])
    assert is_match and ratio == 1.0, "Identical should match"
    
    similar = FuzzyMatcher.find_similar(payload, signatures, threshold=0.8)
    assert len(similar) > 0, "Should find similar signatures"
    print(f"  [OK] Distance to sig1: {distance}, Similar found: {len(similar)}")
    
    # Test 10: Integration Test (Full Scoring with Phase A)
    print("\n[TEST 10] Integration: Full Scoring with Phase A Features")
    cfg = ModAIConfig()
    cfg.enable_response_diffing = True
    cfg.enable_calibration = True
    cfg.enable_evidence_chain = True
    cfg.enable_payload_families = True
    
    engine = ModAIEngine(config=cfg)
    
    features = ModAIFeatures(
        severity_weight=0.88,
        confidence=0.82,
        matched_patterns=3,
        false_positive_risk=0.15,
        response_time=2.5,
        status_code=200,
        has_error_indicators=True,
        content_entropy=0.65,
        content_length=5000,
        payload_length=150,
        anomaly_score=0.1,
        notes=["keywords:union", "pattern:sql_inject"],
        keyword_hits=["union", "select"],
        hard_hits=["uid="],
        payload_risk=0.75,
        vuln_type="SQLi",
        target_id="target_456",
        hour_of_day=14,
        baseline_response='{"status": "ok"}',
        injected_response='{"status": "ok", "admin": true}',
    )
    
    detection = {"type": "SQLi", "url": "http://example.com?id=1", "method": "GET"}
    
    score, label, explanations = engine.score(features, detection)
    
    assert 0.0 <= score <= 1.0, f"Score should be 0-1, got {score}"
    assert len(explanations) > 5, f"Should have multiple explanations, got {len(explanations)}"
    assert any("json_struct" in e or "table_diff" in e or "complex" in e for e in explanations), \
        "Should have Phase A feature in explanations"
    
    print(f"  [OK] Score: {score:.3f}, Label: {label.value}")
    print(f"  [OK] Explanation count: {len(explanations)}")
    print(f"  [OK] Sample explanations: {explanations[:3]}")
    
    print("\n" + "="*70)
    print("ALL PHASE A TESTS PASSED (10/10)")
    print("="*70)
    return True


if __name__ == "__main__":
    try:
        success = test_phase_a_features()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
