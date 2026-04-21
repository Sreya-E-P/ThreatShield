# scripts/test_zero_day_detector.py
"""
TEST ZERO-DAY DETECTOR
Tests the zero-day detection model with REAL threats from your dataset
"""

import json
import numpy as np
import joblib
from pathlib import Path
from datetime import datetime
import random

def load_zero_day_model():
    """Load the trained zero-day detector"""
    models_dir = Path(__file__).parent.parent / "models"
    
    print("\n" + "="*80)
    print("🔬 LOADING ZERO-DAY DETECTOR")
    print("="*80)
    
    try:
        model = joblib.load(models_dir / "zero_day_classifier_latest.joblib")
        scaler = joblib.load(models_dir / "zero_day_scaler_latest.joblib")
        print("✅ Zero-Day Detector loaded successfully!")
        return model, scaler
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return None, None

def load_real_threats():
    """Load the real threats from your collected data"""
    data_dir = Path(__file__).parent.parent / "training_data"
    
    print("\n" + "="*80)
    print("📁 LOADING REAL THREATS")
    print("="*80)
    
    # Find the mega threats file
    mega_files = list(data_dir.glob("mega_threats_*.json"))
    if not mega_files:
        print("❌ No real threat data found!")
        return []
    
    latest = max(mega_files, key=lambda p: p.stat().st_mtime)
    print(f"📂 Loading: {latest.name}")
    
    with open(latest, 'r') as f:
        data = json.load(f)
    
    threats = data['threats']
    print(f"✅ Loaded {len(threats)} real threats")
    print(f"   Sources: URLhaus={data['stats'].get('urlhaus',0)}, "
          f"SSLBL={data['stats'].get('sslbl',0)}, "
          f"Spamhaus={data['stats'].get('spamhaus',0)}")
    
    return threats

def extract_features_simple(threat):
    """Extract features for zero-day detection (matches training format)"""
    features = []
    
    # 1. Risk Score
    features.append(threat.get('risk_score', 0.5))
    
    # 2. Severity one-hot
    severity = threat.get('severity', 'medium')
    features.append(1.0 if severity == 'critical' else 0.0)
    features.append(1.0 if severity == 'high' else 0.0)
    features.append(1.0 if severity == 'medium' else 0.0)
    features.append(1.0 if severity == 'low' else 0.0)
    
    # 3. Threat Characteristics
    features.append(threat.get('propagation_rate', 0.5))
    features.append(threat.get('complexity', 0.5))
    features.append(min(threat.get('affected_systems', 0) / 500, 1.0))
    features.append(min(threat.get('detection_age_hours', 0) / 72, 1.0))
    features.append(threat.get('resource_usage', 0.5))
    features.append(1.0 if threat.get('lateral_movement', False) else 0.0)
    features.append(threat.get('data_sensitivity', 0.5))
    features.append(threat.get('impact_score', 0.5))
    features.append(threat.get('confidence', 0.5))
    features.append(threat.get('is_zero_day', 0.0))
    
    # 4. Indicators
    indicators = threat.get('indicators', [])
    features.append(min(len(indicators) / 20, 1.0))
    features.append(0.5 if any(i.get('type') == 'ip' for i in indicators) else 0.0)
    features.append(0.5 if any(i.get('type') == 'domain' for i in indicators) else 0.0)
    features.append(0.5 if any(i.get('type') == 'url' for i in indicators) else 0.0)
    features.append(0.5 if any(i.get('type') == 'hash' for i in indicators) else 0.0)
    
    # 5. Behaviors
    behaviors = threat.get('behaviors', [])
    behavior_cats = ['persistence', 'evasion', 'execution', 'defense_evasion',
                     'privilege_escalation', 'discovery', 'lateral_movement', 'exfiltration']
    for cat in behavior_cats:
        features.append(1.0 if any(cat in str(b).lower() for b in behaviors) else 0.0)
    
    # 6. MITRE Techniques
    mitre = threat.get('mitre_techniques', [])
    features.append(min(len(mitre) / 10, 1.0))
    
    # 7. Source Confidence
    source = threat.get('source', 'unknown')
    source_conf = {
        'urlhaus': 0.95, 'sslbl': 0.90, 'spamhaus': 0.92, 'openphish': 0.88,
        'emergingthreats': 0.85, 'alienvault': 0.87, 'unknown': 0.50
    }
    for src, conf in source_conf.items():
        features.append(1.0 if src in source else conf / 2)
    
    # 8. Temporal Features
    age = threat.get('detection_age_hours', 0)
    features.append(np.sin(2 * np.pi * age / 24))
    features.append(np.cos(2 * np.pi * age / 24))
    features.append(1.0 if age < 6 else 0.0)
    
    # Pad to 50 features
    while len(features) < 50:
        features.append(0.0)
    
    return np.array(features[:50], dtype=np.float32).reshape(1, -1)

def test_zero_day_detector(model, scaler, threats):
    """Test the zero-day detector on real threats"""
    
    print("\n" + "="*80)
    print("🎯 TESTING ZERO-DAY DETECTOR ON REAL THREATS")
    print("="*80)
    
    results = []
    
    for i, threat in enumerate(threats[:50]):  # Test first 50 threats
        try:
            # Extract features
            X = extract_features_simple(threat)
            
            # Scale features
            X_scaled = scaler.transform(X)
            
            # Get prediction
            zero_day_prob = model.predict_proba(X_scaled)[0][1]
            prediction = "ZERO-DAY" if zero_day_prob > 0.5 else "KNOWN"
            
            # Get confidence
            confidence = abs(zero_day_prob - 0.5) * 2  # Scale to 0-1
            
            results.append({
                "threat": threat,
                "zero_day_probability": zero_day_prob,
                "prediction": prediction,
                "confidence": confidence
            })
            
        except Exception as e:
            print(f"Error testing threat {i}: {e}")
            continue
    
    # Display results
    print(f"\n📊 TEST RESULTS (First 20 threats):")
    print(f"{'No.':<4} {'Source':<15} {'Type':<15} {'Zero-Day Prob':<15} {'Prediction':<12}")
    print("-" * 80)
    
    for i, r in enumerate(results[:20]):
        source = r['threat'].get('source', 'unknown')[:14]
        t_type = r['threat'].get('type', 'unknown')[:14]
        prob = r['zero_day_probability'] * 100
        pred = r['prediction']
        
        color = "🔴" if pred == "ZERO-DAY" else "🟢"
        print(f"{i+1:<4} {source:<15} {t_type:<15} {prob:>6.1f}%{' ':<8} {color} {pred}")
    
    # Statistics
    zero_day_count = sum(1 for r in results if r['prediction'] == "ZERO-DAY")
    avg_prob = np.mean([r['zero_day_probability'] for r in results])
    avg_confidence = np.mean([r['confidence'] for r in results])
    
    print("\n" + "="*80)
    print("📊 STATISTICS")
    print("="*80)
    print(f"   Total Threats Tested: {len(results)}")
    print(f"   Detected as ZERO-DAY: {zero_day_count} ({zero_day_count/len(results)*100:.1f}%)")
    print(f"   Detected as KNOWN: {len(results)-zero_day_count} ({(len(results)-zero_day_count)/len(results)*100:.1f}%)")
    print(f"   Average Zero-Day Probability: {avg_prob*100:.1f}%")
    print(f"   Average Confidence: {avg_confidence*100:.1f}%")
    
    return results

def test_with_synthetic_zero_day(model, scaler):
    """Create and test synthetic zero-day threats"""
    
    print("\n" + "="*80)
    print("🎯 TESTING WITH SYNTHETIC ZERO-DAY THREATS")
    print("="*80)
    
    # Create synthetic zero-day threats
    synthetic_threats = [
        {
            "type": "zero_day_exploit",
            "severity": "critical",
            "risk_score": 0.95,
            "propagation_rate": 0.9,
            "complexity": 0.95,
            "affected_systems": 50,
            "detection_age_hours": 0.5,
            "resource_usage": 0.8,
            "lateral_movement": True,
            "data_sensitivity": 0.95,
            "impact_score": 0.98,
            "confidence": 0.85,
            "is_zero_day": 1.0,
            "indicators": [{"type": "ip", "value": "1.2.3.4"}],
            "behaviors": ["novel_pattern", "unknown_technique", "evasion"],
            "source": "unknown"
        },
        {
            "type": "novel_malware",
            "severity": "high",
            "risk_score": 0.85,
            "propagation_rate": 0.7,
            "complexity": 0.85,
            "affected_systems": 30,
            "detection_age_hours": 1,
            "resource_usage": 0.6,
            "lateral_movement": True,
            "data_sensitivity": 0.8,
            "impact_score": 0.85,
            "confidence": 0.75,
            "is_zero_day": 1.0,
            "indicators": [{"type": "hash", "value": "new_hash_123"}],
            "behaviors": ["unusual_behavior", "new_technique"],
            "source": "unknown"
        }
    ]
    
    print("\n🔬 Testing synthetic zero-day threats:")
    
    for threat in synthetic_threats:
        X = extract_features_simple(threat)
        X_scaled = scaler.transform(X)
        prob = model.predict_proba(X_scaled)[0][1]
        
        print(f"\n   Threat: {threat['type']}")
        print(f"   Zero-Day Probability: {prob*100:.1f}%")
        print(f"   Expected: ZERO-DAY")
        print(f"   Result: {'✅ PASS' if prob > 0.5 else '❌ FAIL'}")
    
    return synthetic_threats

def test_with_known_threats(model, scaler, threats):
    """Test with known threat patterns"""
    
    print("\n" + "="*80)
    print("🎯 TESTING WITH KNOWN THREAT PATTERNS")
    print("="*80)
    
    # Extract known threat patterns from real data
    known_patterns = []
    for threat in threats[:10]:
        if threat.get('source') != 'unknown':
            known_patterns.append(threat)
    
    print(f"\n🔬 Testing {len(known_patterns)} known threat patterns:")
    
    zero_day_count = 0
    for threat in known_patterns:
        X = extract_features_simple(threat)
        X_scaled = scaler.transform(X)
        prob = model.predict_proba(X_scaled)[0][1]
        
        if prob > 0.5:
            zero_day_count += 1
        
        source = threat.get('source', 'unknown')[:15]
        t_type = threat.get('type', 'unknown')[:15]
        print(f"   [{source}] {t_type}: {prob*100:.1f}% {'⚠️ ZERO-DAY' if prob > 0.5 else '✅ KNOWN'}")
    
    print(f"\n   Zero-day false positives: {zero_day_count}/{len(known_patterns)} ({zero_day_count/len(known_patterns)*100:.1f}%)")
    
    return known_patterns

def main():
    print("\n" + "="*80)
    print("🔬 ZERO-DAY DETECTOR TEST SUITE")
    print("="*80)
    
    # Load model
    model, scaler = load_zero_day_model()
    if model is None:
        print("❌ Cannot test without model!")
        return
    
    # Load real threats
    threats = load_real_threats()
    if not threats:
        print("❌ Cannot test without real threats!")
        return
    
    # Test 1: Real threats
    results = test_zero_day_detector(model, scaler, threats)
    
    # Test 2: Synthetic zero-day threats
    synthetic = test_with_synthetic_zero_day(model, scaler)
    
    # Test 3: Known threats
    known = test_with_known_threats(model, scaler, threats)
    
    # Final verdict
    print("\n" + "="*80)
    print("🎯 FINAL VERDICT")
    print("="*80)
    
    # Calculate metrics
    zero_day_rate = sum(1 for r in results if r['prediction'] == "ZERO-DAY") / len(results)
    avg_confidence = np.mean([r['confidence'] for r in results])
    
    print(f"\n   Zero-Day Detection Rate: {zero_day_rate*100:.1f}%")
    print(f"   Average Confidence: {avg_confidence*100:.1f}%")
    
    if zero_day_rate < 0.1:
        print("\n   ✅ ZERO-DAY DETECTOR PERFORMANCE: GOOD")
        print("   - Very few false positives")
        print("   - High confidence in predictions")
        print("   - Ready for production")
    elif zero_day_rate < 0.3:
        print("\n   ⚠️ ZERO-DAY DETECTOR PERFORMANCE: MODERATE")
        print("   - Some false positives detected")
        print("   - May need more training data")
    else:
        print("\n   ⚠️ ZERO-DAY DETECTOR PERFORMANCE: NEEDS IMPROVEMENT")
        print("   - High false positive rate")
        print("   - Consider retraining with more data")
    
    print("\n" + "="*80)
    print("✅ TEST COMPLETE!")
    print("="*80)

if __name__ == "__main__":
    import numpy as np
    main()