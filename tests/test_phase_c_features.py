"""
Test Phase C: System Integration Features (v4.0 enhancement)
"""

import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.mod_ai import (
    ModAIEngine,
    ModAIConfig,
    ModAIFeatures,
    DistributedScoringFederation,
    FeedbackLoopEngine,
    RealTimeAlertingEngine,
    PerformanceOptimizer,
    PrivacyComplianceEngine,
)


def test_phase_c_features():
    print("\n" + "="*70)
    print("PHASE C: System Integration Features Test Suite")
    print("="*70)
    
    # Test 1: Distributed Scoring Federation
    print("\n[TEST 1] Distributed Scoring Federation")
    dsf = DistributedScoringFederation()
    
    # Record scores from multiple peers
    dsf.record_peer_score("det_001", "node_1", 0.85, 0.9)
    dsf.record_peer_score("det_001", "node_2", 0.82, 0.88)
    dsf.record_peer_score("det_001", "node_3", 0.88, 0.92)
    
    consensus, level = dsf.compute_consensus_score("det_001", local_score=0.83)
    assert 0 <= consensus <= 1, "Consensus should be 0-1"
    assert level in ["unanimous_high", "unanimous_low", "majority_high", "majority_low", "split", "local"], "Invalid consensus level"
    print(f"  [OK] Consensus: {consensus:.2f}, Level: {level}")
    
    # Test 2: Feedback Loop Engine
    print("\n[TEST 2] Feedback Loop Engine")
    fle = FeedbackLoopEngine()
    
    # Record some true positives
    for i in range(5):
        fle.record_detection(f"det_{i}", "SQLi", 0.85 + i*0.01, True, 0.9)
    
    # Record some false positives
    for i in range(2):
        fle.record_detection(f"det_{i+5}", "SQLi", 0.75 + i*0.05, False, 0.7)
    
    fp_rate = fle.compute_false_positive_rate("SQLi")
    assert 0 <= fp_rate <= 1, "FP rate should be 0-1"
    
    learning_adj = fle.get_learning_adjustment("SQLi")
    assert 0.8 <= learning_adj <= 1.0, "Learning adjustment should be 0.8-1.0"
    print(f"  [OK] False Positive Rate: {fp_rate:.2f}, Learning Adjustment: {learning_adj:.2f}")
    
    # Test 3: Real-Time Alerting Engine
    print("\n[TEST 3] Real-Time Alerting Engine")
    rtae = RealTimeAlertingEngine()
    
    # Test should_alert with cooldown
    alert1 = rtae.should_alert("CRITICAL", 0.95)
    assert alert1 == True, "First alert should be sent"
    
    alert2 = rtae.should_alert("CRITICAL", 0.95)
    assert alert2 == False, "Second alert within cooldown should not be sent"
    
    # Create an alert
    alert = rtae.create_alert("det_001", "SQLi", 0.92, "HIGH", ["high_fp_risk", "timing_indicator"])
    assert "alert_id" in alert, "Alert should have ID"
    assert alert["score"] == 0.92, "Alert should contain score"
    print(f"  [OK] Alert created: {alert['alert_id']}, Counters: {dict(rtae.alert_counters)}")
    
    # Test 4: Performance Optimizer
    print("\n[TEST 4] Performance Optimizer")
    po = PerformanceOptimizer()
    
    # Test caching
    po.cache_score("payload_hash_001", 0.87)
    cached = po.get_cached_score("payload_hash_001")
    assert cached == 0.87, "Should return cached score"
    
    # Test batch operations
    po.add_to_batch("det_1", "payload_1")
    po.add_to_batch("det_2", "payload_2")
    po.add_to_batch("det_3", "payload_3")
    
    batch = po.get_batch(2)
    assert len(batch) == 2, "Should get 2 items in batch"
    
    remaining_batch = po.get_batch(5)
    assert len(remaining_batch) == 1, "Should have 1 item remaining"
    print(f"  [OK] Cache hit, Batch ops working, Remaining queue: {len(po.batch_queue)}")
    
    # Test 5: Privacy Compliance Engine
    print("\n[TEST 5] Privacy Compliance Engine")
    pce = PrivacyComplianceEngine()
    
    # Test PII detection
    content = "User john@example.com called from 555-123-4567 with SSN 123-45-6789"
    pii_found = pce.detect_pii(content)
    assert len(pii_found) > 0, "Should detect PII"
    assert any(p[0] == "email" for p in pii_found), "Should detect email"
    
    # Test PII redaction
    redacted = pce.redact_pii(content)
    assert "@" not in redacted or "[EMAIL]" in redacted, "Email should be redacted"
    
    # Test audit logging
    pce.log_data_access("read", 1024, "user_123")
    pce.log_data_access("write", 2048, "user_456")
    
    audit_summary = pce.get_audit_summary()
    assert audit_summary["total_accesses"] == 2, "Should have 2 accesses logged"
    assert audit_summary["total_data_accessed_bytes"] == 3072, "Should sum data sizes"
    print(f"  [OK] PII detected: {len(pii_found)}, Redacted text length: {len(redacted)}, Audit: {audit_summary['total_accesses']} accesses")
    
    # Test 6: Full Integration with ModAIEngine
    print("\n[TEST 6] Integration: Phase C with ModAIEngine")
    cfg = ModAIConfig()
    cfg.enable_federation = False  # Disabled by default
    cfg.enable_feedback_loops = True
    cfg.enable_real_time_alerts = True
    cfg.enable_performance_optimization = True
    cfg.enable_privacy_compliance = True
    
    engine = ModAIEngine(config=cfg)
    
    features = ModAIFeatures(
        severity_weight=0.88,
        confidence=0.75,
        matched_patterns=3,
        false_positive_risk=0.15,
        response_time=2.5,
        status_code=200,
        has_error_indicators=True,
        content_entropy=0.65,
        content_length=5000,
        payload_length=150,
        anomaly_score=0.2,
        notes=["timing_attack", "high_entropy"],
        keyword_hits=["sleep", "benchmark", "union"],
        hard_hits=["uid="],
        payload_risk=0.75,
        vuln_type="SQLi",
        target_id="target_789",
        hour_of_day=14,
    )
    
    detection = {
        "id": "det_phase_c_1",
        "type": "SQLi",
        "url": "http://example.com?id=1",
        "method": "GET",
    }
    
    score, label, explanations = engine.score(features, detection)
    
    assert 0 <= score <= 1, f"Score should be 0-1, got {score}"
    assert len(explanations) > 5, f"Should have multiple explanations, got {len(explanations)}"
    
    # Check for Phase C features in explanations
    phase_c_indicators = [e for e in explanations if any(
        indicator in e for indicator in ["feedback", "alert", "cache", "pii"]
    )]
    
    print(f"  [OK] Score: {score:.3f}, Label: {label.value}")
    print(f"  [OK] Total explanations: {len(explanations)}")
    print(f"  [OK] Phase C indicators: {len(phase_c_indicators)}")
    if phase_c_indicators:
        print(f"       {phase_c_indicators[:3]}")
    print(f"  [OK] Sample explanations: {explanations[:5]}")
    
    print("\n" + "="*70)
    print("ALL PHASE C TESTS PASSED (6/6)")
    print("="*70)
    return True


if __name__ == "__main__":
    try:
        success = test_phase_c_features()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
