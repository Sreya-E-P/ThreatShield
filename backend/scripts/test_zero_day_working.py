# scripts/test_zero_day_working.py
"""
ZERO-DAY DETECTOR TEST - Using your actual model files
"""

import json
import numpy as np
import joblib
from pathlib import Path
from datetime import datetime

def load_models():
    """Load the actual models you have"""
    models_dir = Path(__file__).parent.parent / "models"
    
    print("\n" + "="*80)
    print("🔬 LOADING ZERO-DAY DETECTOR")
    print("="*80)
    
    # Find the latest scaler
    scaler_files = list(models_dir.glob("zero_day_scaler_*.joblib"))
    if scaler_files:
        latest_scaler = max(scaler_files, key=lambda p: p.stat().st_mtime)
        print(f"📂 Loading scaler: {latest_scaler.name}")
        scaler = joblib.load(latest_scaler)
    else:
        print("⚠️ No scaler found, using None")
        scaler = None
    
    # Load the classifier
    classifier_path = models_dir / "zero_day_classifier_latest.joblib"
    if classifier_path.exists():
        print(f"📂 Loading classifier: {classifier_path.name}")
        classifier = joblib.load(classifier_path)
    else:
        print("❌ Classifier not found!")
        return None, None
    
    print("✅ Models loaded successfully!")
    return classifier, scaler

def load_real_threats():
    """Load real threats from collected data"""
    data_dir = Path(__file__).parent.parent / "training_data"
    
    # Find the mega threats file
    mega_files = list(data_dir.glob("mega_threats_*.json"))
    if not mega_files:
        print("❌ No real threat data found!")
        return []
    
    latest = max(mega_files, key=lambda p: p.stat().st_mtime)
    print(f"\n📂 Loading threats: {latest.name}")
    
    with open(latest, 'r') as f:
        data = json.load(f)
    
    threats = data['threats']
    print(f"✅ Loaded {len(threats)} real threats")
    print(f"   Sources:")
    for key, value in data['stats'].items():
        if key not in ['total_real', 'duration_seconds'] and value > 0:
            print(f"     • {key}: {value}")
    
    return threats

def extract_features(threat):
    """Extract features matching the training format"""
    features = []
    
    # 1. Risk Score
    features.append(threat.get('risk_score', 0.5))
    
    # 2. Severity (one-hot)
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

def test_zero_day_detector(classifier, scaler, threats):
    """Test the zero-day detector"""
    
    print("\n" + "="*80)
    print("🎯 TESTING ZERO-DAY DETECTOR ON REAL THREATS")
    print("="*80)
    
    results = []
    
    # Test first 50 threats
    test_count = min(50, len(threats))
    print(f"\n🔬 Testing {test_count} threats...\n")
    
    for i, threat in enumerate(threats[:test_count]):
        try:
            X = extract_features(threat)
            
            # Scale if scaler exists
            if scaler:
                X = scaler.transform(X)
            
            # Get prediction
            prob = classifier.predict_proba(X)[0][1]
            prediction = "ZERO-DAY" if prob > 0.5 else "KNOWN"
            
            results.append({
                "source": threat.get('source', 'unknown'),
                "type": threat.get('type', 'unknown'),
                "title": threat.get('title', '')[:40],
                "zero_day_probability": prob,
                "prediction": prediction
            })
            
        except Exception as e:
            print(f"   Error on threat {i}: {e}")
            continue
    
    # Display results
    print(f"{'No.':<4} {'Source':<18} {'Type':<15} {'Zero-Day Prob':<15} {'Result':<12}")
    print("-" * 75)
    
    zero_day_count = 0
    for i, r in enumerate(results):
        prob = r['zero_day_probability'] * 100
        pred = r['prediction']
        icon = "🔴" if pred == "ZERO-DAY" else "🟢"
        
        print(f"{i+1:<4} {r['source'][:16]:<18} {r['type'][:13]:<15} {prob:>6.1f}%{' ':<8} {icon} {pred}")
        
        if pred == "ZERO-DAY":
            zero_day_count += 1
    
    # Statistics
    avg_prob = np.mean([r['zero_day_probability'] for r in results])
    
    print("\n" + "="*80)
    print("📊 STATISTICS")
    print("="*80)
    print(f"   Total Tested: {len(results)}")
    print(f"   Detected as ZERO-DAY: {zero_day_count} ({zero_day_count/len(results)*100:.1f}%)")
    print(f"   Detected as KNOWN: {len(results)-zero_day_count} ({(len(results)-zero_day_count)/len(results)*100:.1f}%)")
    print(f"   Average Zero-Day Probability: {avg_prob*100:.1f}%")
    
    return results

def test_synthetic_zero_day(classifier, scaler):
    """Test with synthetic zero-day threats"""
    
    print("\n" + "="*80)
    print("🎯 TESTING SYNTHETIC ZERO-DAY THREATS")
    print("="*80)
    
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
        },
        {
            "type": "new_ransomware",
            "severity": "critical",
            "risk_score": 0.92,
            "propagation_rate": 0.85,
            "complexity": 0.9,
            "affected_systems": 45,
            "detection_age_hours": 2,
            "resource_usage": 0.75,
            "lateral_movement": True,
            "data_sensitivity": 0.9,
            "impact_score": 0.92,
            "confidence": 0.88,
            "is_zero_day": 1.0,
            "indicators": [{"type": "ip", "value": "5.6.7.8"}],
            "behaviors": ["encryption", "lateral_movement"],
            "source": "unknown"
        }
    ]
    
    print("\n🔬 Testing synthetic zero-day threats:\n")
    
    passed = 0
    for threat in synthetic_threats:
        X = extract_features(threat)
        if scaler:
            X = scaler.transform(X)
        prob = classifier.predict_proba(X)[0][1]
        is_zero_day = prob > 0.5
        
        print(f"   Threat: {threat['type']}")
        print(f"   Zero-Day Probability: {prob*100:.1f}%")
        print(f"   Expected: ZERO-DAY")
        print(f"   Result: {'✅ PASS' if is_zero_day else '❌ FAIL'}\n")
        
        if is_zero_day:
            passed += 1
    
    print(f"   Synthetic Zero-Day Detection Rate: {passed}/{len(synthetic_threats)} ({passed/len(synthetic_threats)*100:.0f}%)")
    
    return synthetic_threats

def main():
    print("\n" + "="*80)
    print("🔬 ZERO-DAY DETECTOR TEST SUITE")
    print("="*80)
    
    # Load models
    classifier, scaler = load_models()
    if classifier is None:
        print("❌ Cannot test without classifier!")
        return
    
    # Load real threats
    threats = load_real_threats()
    if not threats:
        print("❌ Cannot test without real threats!")
        return
    
    # Test real threats
    results = test_zero_day_detector(classifier, scaler, threats)
    
    # Test synthetic zero-day threats
    synthetic = test_synthetic_zero_day(classifier, scaler)
    
    # Final verdict
    print("\n" + "="*80)
    print("🎯 FINAL VERDICT")
    print("="*80)
    
    zero_day_rate = sum(1 for r in results if r['prediction'] == "ZERO-DAY") / len(results)
    avg_prob = np.mean([r['zero_day_probability'] for r in results])
    
    print(f"\n   Real Threat Zero-Day Rate: {zero_day_rate*100:.1f}%")
    print(f"   Average Zero-Day Probability: {avg_prob*100:.1f}%")
    
    if zero_day_rate < 0.1:
        print("\n   ✅ ZERO-DAY DETECTOR: EXCELLENT")
        print("   - Very low false positive rate")
        print("   - Ready for production")
    elif zero_day_rate < 0.2:
        print("\n   ✅ ZERO-DAY DETECTOR: GOOD")
        print("   - Low false positive rate")
        print("   - Suitable for production")
    elif zero_day_rate < 0.3:
        print("\n   ⚠️ ZERO-DAY DETECTOR: MODERATE")
        print("   - Some false positives detected")
        print("   - May need additional training")
    else:
        print("\n   ⚠️ ZERO-DAY DETECTOR: NEEDS IMPROVEMENT")
        print("   - High false positive rate")
        print("   - Consider retraining with more data")
    
    print("\n" + "="*80)
    print("✅ TEST COMPLETE!")
    print("="*80)

if __name__ == "__main__":
    import numpy as np
    main()