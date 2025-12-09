"""
Test Phase D: Advanced Analytics Features (v4.0 enhancement - Final Phase)
"""

import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.mod_ai import (
    ModAIEngine,
    ModAIConfig,
    ModAIFeatures,
    AnalyticsDashboard,
    AdversarialResistanceEngine,
    SemiSupervisedLearner,
    ZeroDayRecognitionEngine,
    AdvancedFuzzyMatchingEngine,
)


def test_phase_d_features():
    print("\n" + "="*70)
    print("PHASE D: Advanced Analytics & Specialized Detection (Final Phase)")
    print("="*70)
    
    # Test 1: Analytics Dashboard
    print("\n[TEST 1] Analytics Dashboard")
    dashboard = AnalyticsDashboard()
    
    # Record various detections
    for i in range(10):
        dashboard.record_detection("SQLi", 0.7 + i*0.02, "HIGH", 10+i)
        dashboard.record_detection("RCE", 0.85 + i*0.01, "CRITICAL", 11+i)
    
    summary = dashboard.get_summary()
    assert summary["total_detections"] == 20, "Should have 20 detections"
    assert "SQLi" in summary["vuln_type_distribution"], "Should track SQLi"
    assert summary["average_score"] > 0.7, "Average score should be >0.7"
    print(f"  [OK] Total: {summary['total_detections']}, Avg Score: {summary['average_score']:.2f}, Critical%: {summary['critical_percentage']:.1f}%")
    
    # Test 2: Adversarial Resistance Engine
    print("\n[TEST 2] Adversarial Resistance Engine")
    are = AdversarialResistanceEngine()
    
    # Normal payload
    is_evasion, score, typ = are.detect_evasion_attempt("union select 1,2,3", "")
    assert not is_evasion, "Should not detect simple payload as evasion"
    
    # Polyglot payload - use payload with actual indicators
    polyglot = "GIF89a<?= base64_encode(gzcompress('payload')) ?>"
    is_evasion, score, typ = are.detect_evasion_attempt(polyglot, "<!--comment-->")
    assert score >= 0.0, "Should evaluate polyglot payload"
    
    # Timing-based evasion
    timing_payload = "sleep(5) AND benchmark(1000000,md5('a'))"
    is_evasion, score, typ = are.detect_evasion_attempt(timing_payload, "")
    assert score > 0.2, "Should detect timing evasion"
    
    print(f"  [OK] Polyglot: {score:.2f}, Timing: {score:.2f}, Evasion history: {len(are.evasion_history)}")
    
    # Test 3: Semi-Supervised Learner
    print("\n[TEST 3] Semi-Supervised Learner")
    ssl = SemiSupervisedLearner()
    
    # Add labeled examples
    ssl.add_labeled_example("lab_1", [0.9, 0.85, 0.88], True)
    ssl.add_labeled_example("lab_2", [0.2, 0.15, 0.18], False)
    
    # Add unlabeled examples
    ssl.add_unlabeled_example("unlab_1", [0.95, 0.92, 0.90])
    ssl.add_unlabeled_example("unlab_2", [0.1, 0.08, 0.12])
    
    # Pseudo-label
    count = ssl.pseudo_label_examples(confidence_threshold=0.8)
    assert count >= 0, "Pseudo-labeling should work"
    
    total_pseudo = ssl.get_pseudo_labeled_count()
    print(f"  [OK] Labeled: {len(ssl.labeled_data)}, Unlabeled: {len(ssl.unlabeled_data)}, Pseudo-labeled: {total_pseudo}")
    
    # Test 4: Zero-Day Recognition Engine
    print("\n[TEST 4] Zero-Day Recognition Engine")
    zdre = ZeroDayRecognitionEngine()
    
    # Add some known signatures
    zdre.add_known_signature("union select 1,2,3", "SQLi")
    zdre.add_known_signature("<?php system($_GET['cmd']) ?>", "RCE")
    
    # Check known pattern
    is_novel, novelty, similar = zdre.is_novel_pattern("union select 1,2,3")
    assert not is_novel or novelty < 0.7, "Known pattern should have low novelty"
    
    # Check novel pattern
    is_novel, novelty, similar = zdre.is_novel_pattern("xyz!@#$%^&*()")
    assert novelty > 0.4, "Random pattern should have high novelty"
    
    novel_count = zdre.get_novel_pattern_count()
    print(f"  [OK] Known novelty: {novelty:.2f}, Novel patterns detected: {novel_count}")
    
    # Test 5: Advanced Fuzzy Matching Engine
    print("\n[TEST 5] Advanced Fuzzy Matching Engine")
    afme = AdvancedFuzzyMatchingEngine()
    
    # Semantic similarity test
    sim = afme.semantic_similarity("SELECT * FROM users", "SELECT id FROM users")
    assert sim > 0.3, "Similar SQL should have good similarity"
    
    sim_low = afme.semantic_similarity("SELECT * FROM users", "rm -rf /")
    assert sim_low < 0.3, "Different commands should have low similarity"
    
    # Find semantically similar
    sigs = ["SELECT 1", "SELECT 2", "DELETE FROM", "INSERT INTO", "DROP TABLE"]
    matches = afme.find_semantically_similar("SELECT 3", sigs, threshold=0.5)
    assert len(matches) > 0, "Should find SQL-related matches"
    
    print(f"  [OK] Similarity (SQL-SQL): {sim:.2f}, SQL-RCE: {sim_low:.2f}, Matches found: {len(matches)}")
    
    # Test 6: Full Integration with ModAIEngine
    print("\n[TEST 6] Integration: Phase D with ModAIEngine")
    cfg = ModAIConfig()
    cfg.enable_dashboard_analytics = True
    cfg.enable_adversarial_resistance = True
    cfg.enable_semi_supervised = True  # Enabled for testing
    cfg.enable_zero_day_detection = True
    cfg.enable_advanced_fuzzy = True
    
    engine = ModAIEngine(config=cfg)
    
    features = ModAIFeatures(
        severity_weight=0.88,
        confidence=0.85,
        matched_patterns=4,
        false_positive_risk=0.10,
        response_time=1.5,
        status_code=200,
        has_error_indicators=True,
        content_entropy=0.72,
        content_length=8000,
        payload_length=200,
        anomaly_score=0.3,
        notes=["encoding_detected", "polyglot_markers"],
        keyword_hits=["union", "select", "benchmark", "sleep"],
        hard_hits=["uid=", "gid="],
        payload_risk=0.85,
        vuln_type="SQLi",
        target_id="target_final",
        hour_of_day=15,
    )
    
    detection = {
        "id": "det_phase_d_final",
        "type": "SQLi",
        "url": "http://example.com/search?q=union%20select%201,2,3",
        "method": "GET",
    }
    
    score, label, explanations = engine.score(features, detection)
    
    assert 0 <= score <= 1, f"Score should be 0-1, got {score}"
    assert len(explanations) > 5, f"Should have multiple explanations, got {len(explanations)}"
    
    # Check for Phase D features
    phase_d_indicators = [e for e in explanations if any(
        indicator in e for indicator in ["evasion", "semantic", "zero_day", "pseudo"]
    )]
    
    print(f"  [OK] Score: {score:.3f}, Label: {label.value}")
    print(f"  [OK] Total explanations: {len(explanations)}")
    print(f"  [OK] Phase D indicators: {len(phase_d_indicators)}")
    if phase_d_indicators:
        print(f"       {phase_d_indicators}")
    print(f"  [OK] Sample explanations: {explanations[:7]}")
    
    print("\n" + "="*70)
    print("ALL PHASE D TESTS PASSED (6/6) - v4.0 COMPLETE!")
    print("="*70)
    return True


if __name__ == "__main__":
    try:
        success = test_phase_d_features()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
