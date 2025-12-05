#!/usr/bin/env python3
"""
Verification Script: Does Detection Actually Work?
===================================================

This script verifies that:
1. eBPF captures syscalls
2. ML models load
3. Anomaly detection runs
4. Risk scoring works
5. Detections are visible

Author: Likitha Shankar
"""

import sys
import os
import time
import subprocess

# Add project to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

print("="*60)
print("DETECTION VERIFICATION TEST")
print("="*60)
print()

# Test 1: Can we import?
print("Test 1: Imports...")
try:
    from enhanced_ebpf_monitor import StatefulEBPFMonitor
    from enhanced_anomaly_detector import EnhancedAnomalyDetector
    from detection.risk_scorer import EnhancedRiskScorer
    print("✅ All imports successful")
except Exception as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

# Test 2: Do models load?
print("\nTest 2: ML Model Loading...")
detector = EnhancedAnomalyDetector()
if detector._load_models():
    print(f"✅ Models loaded successfully")
    print(f"   - is_fitted: {detector.is_fitted}")
    print(f"   - Isolation Forest: {detector.isolation_forest is not None}")
    print(f"   - One-Class SVM: {detector.one_class_svm is not None}")
else:
    print(f"❌ Models failed to load")
    print(f"   - Check if trained: python3 scripts/train_with_dataset.py")
    sys.exit(1)

# Test 3: Does eBPF capture work?
print("\nTest 3: eBPF Capture (5 seconds)...")
from collections import deque
events = deque(maxlen=100)

def callback(pid, syscall, info):
    events.append((pid, syscall, info.get('comm', '?')))

try:
    monitor = StatefulEBPFMonitor({})
    monitor.start_monitoring(callback)
    time.sleep(5)
    monitor.stop_monitoring()
    
    if len(events) >= 50:
        print(f"✅ eBPF captured {len(events)} events")
        print(f"   Sample: {list(events)[:3]}")
    else:
        print(f"⚠️  Only captured {len(events)} events (expected 50+)")
except Exception as e:
    print(f"❌ eBPF failed: {e}")
    sys.exit(1)

# Test 4: Does ML detection work?
print("\nTest 4: ML Anomaly Detection...")

# Create normal pattern
normal_syscalls = ['read', 'write', 'open', 'close'] * 5
result_normal = detector.detect_anomaly_ensemble(normal_syscalls, None, 1000)
print(f"   Normal pattern: score={result_normal.anomaly_score:.1f}, anomaly={result_normal.is_anomaly}")

# Create suspicious pattern
suspicious_syscalls = ['setuid', 'setgid', 'execve', 'ptrace', 'chmod'] * 10
result_suspicious = detector.detect_anomaly_ensemble(suspicious_syscalls, None, 9999)
print(f"   Suspicious pattern: score={result_suspicious.anomaly_score:.1f}, anomaly={result_suspicious.is_anomaly}")

if result_suspicious.anomaly_score > result_normal.anomaly_score:
    print(f"✅ ML detection differentiates patterns")
else:
    print(f"⚠️  ML scores similar (might need more training data)")

# Test 5: Does risk scoring work?
print("\nTest 5: Risk Scoring...")
scorer = EnhancedRiskScorer()

# Normal process
risk_normal = scorer.update_risk_score(1000, normal_syscalls, {'comm': 'python3'}, result_normal.anomaly_score)
print(f"   Normal risk: {risk_normal:.1f}")

# Suspicious process
risk_suspicious = scorer.update_risk_score(9999, suspicious_syscalls, {'comm': 'malware', 'uid': 0}, result_suspicious.anomaly_score)
print(f"   Suspicious risk: {risk_suspicious:.1f}")

if risk_suspicious > risk_normal + 20:
    print(f"✅ Risk scoring differentiates threats")
else:
    print(f"⚠️  Risk scores similar")

# Test 6: Live agent test with attack
print("\nTest 6: Live Agent with Attack Simulation...")
print("   Starting agent in background...")

agent_cmd = "sudo timeout 15 python3 core/simple_agent.py --collector ebpf --threshold 20 2>&1"
agent_proc = subprocess.Popen(agent_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

time.sleep(8)  # Let agent start

print("   Simulating privilege escalation attack...")
for i in range(10):
    try:
        subprocess.run(['sudo', 'id'], capture_output=True, timeout=1)
        subprocess.run(['sudo', 'chmod', '777', f'/tmp/test_{i}'], capture_output=True, timeout=1)
        time.sleep(0.3)
    except:
        pass

time.sleep(3)  # Let agent process

# Check agent output
agent_proc.terminate()
output = agent_proc.stdout.read().decode()

high_risk_count = output.count('HIGH RISK') + output.count('🔴')
anomaly_count = output.count('ANOMALY') + output.count('⚠️')

print(f"\n   Agent detected:")
print(f"   - High risk alerts: {high_risk_count}")
print(f"   - Anomaly alerts: {anomaly_count}")

if high_risk_count > 0 or anomaly_count > 0:
    print(f"✅ Agent is detecting threats!")
else:
    print(f"⚠️  No detections logged (check output below)")
    print(f"\n--- Agent Output (last 20 lines) ---")
    print('\n'.join(output.split('\n')[-20:]))

# Final summary
print("\n" + "="*60)
print("VERIFICATION SUMMARY")
print("="*60)

tests_passed = 0
tests_total = 6

if detector.is_fitted:
    tests_passed += 1
if len(events) >= 50:
    tests_passed += 1
if result_suspicious.anomaly_score > result_normal.anomaly_score:
    tests_passed += 1
if risk_suspicious > risk_normal + 20:
    tests_passed += 1
if high_risk_count > 0 or anomaly_count > 0:
    tests_passed += 1
    
# Always pass imports
tests_passed += 1  

print(f"\nTests Passed: {tests_passed}/{tests_total}")
print(f"Success Rate: {tests_passed/tests_total*100:.0f}%")

if tests_passed >= 5:
    print("\n✅ DETECTION IS WORKING")
    print("   Your agent is functional and detecting threats!")
elif tests_passed >= 3:
    print("\n⚠️  PARTIALLY WORKING")
    print("   Core components work but needs tuning")
else:
    print("\n❌ NEEDS FIXES")
    print("   Multiple components failing")

print("\n" + "="*60)

