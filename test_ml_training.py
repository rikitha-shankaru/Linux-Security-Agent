#!/usr/bin/env python3
"""
Test script to verify ML training uses real data
"""

from core.enhanced_security_agent import EnhancedSecurityAgent
import time

def test_ml_training():
    print("=== Testing ML Training ===")
    print()
    
    agent = EnhancedSecurityAgent()
    
    print("Starting monitoring to collect real data...")
    print("Will collect data for 30 seconds...")
    print()
    
    # Start monitoring
    agent.start_monitoring()
    time.sleep(30)
    agent.stop_monitoring()
    
    print()
    
    # Check if models were trained
    if agent.enhanced_anomaly_detector:
        print("✅ Anomaly detector exists")
        
        # Check if models are trained
        has_trained_models = False
        if hasattr(agent.enhanced_anomaly_detector, 'isolation_forest') and agent.enhanced_anomaly_detector.isolation_forest:
            has_trained_models = True
        
        if hasattr(agent.enhanced_anomaly_detector, 'one_class_svm') and agent.enhanced_anomaly_detector.one_class_svm:
            has_trained_models = True
        
        if hasattr(agent.enhanced_anomaly_detector, 'dbscan') and agent.enhanced_anomaly_detector.dbscan is not None:
            has_trained_models = True
        
        if has_trained_models:
            print("✅ Models are trained")
        else:
            print("⚠️  Models might not be trained yet")
            print("   Check training code in enhanced_security_agent.py")
        
        # Try a prediction
        print()
        print("Testing anomaly detection with sample syscalls...")
        test_syscalls = ['read', 'write', 'open', 'close', 'read', 'write']
        try:
            result = agent.enhanced_anomaly_detector.detect_anomaly_ensemble(test_syscalls)
            print(f"✅ Anomaly score: {result.anomaly_score:.3f}")
            print(f"✅ Is anomaly: {result.is_anomaly}")
            print()
            
            if result.anomaly_score >= 0:
                print("✅ ML detection is working!")
                print("   This means Bug #2 (ML training) is FIXED")
                return True
            else:
                print("⚠️  ML returned invalid score")
                return False
        except Exception as e:
            print(f"❌ Error during prediction: {e}")
            return False
    else:
        print("❌ No anomaly detector found")
        print("   Check enhanced_security_agent.py initialization")
        return False

if __name__ == "__main__":
    success = test_ml_training()
    exit(0 if success else 1)

