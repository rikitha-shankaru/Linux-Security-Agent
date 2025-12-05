#!/usr/bin/env python3
"""
Test Connection Pattern Detection
==================================

Tests the new C2 beaconing and port scanning detection features.

Author: Likitha Shankar
"""

import sys
import os
import time
import subprocess
import socket

sys.path.insert(0, 'core')

from connection_pattern_analyzer import ConnectionPatternAnalyzer

print("="*60)
print("CONNECTION PATTERN DETECTION TEST")
print("="*60)

analyzer = ConnectionPatternAnalyzer()

# Test 1: C2 Beaconing Detection
print("\n1️⃣  Testing C2 Beaconing Detection...")
print("   Simulating regular connections every 10 seconds...")

beacon_pid = 12345
base_time = time.time()

for i in range(6):
    result = analyzer.analyze_connection(
        pid=beacon_pid,
        dest_ip="192.168.1.100",
        dest_port=8080,
        timestamp=base_time + (i * 10.0)  # Regular 10-second intervals
    )
    
    if result and result['type'] == 'C2_BEACONING':
        print(f"   ✅ DETECTED: C2 Beaconing after {i+1} connections")
        print(f"      Mean interval: {result['mean_interval']:.1f}s")
        print(f"      Variance: {result['stdev']:.2f}s")
        print(f"      Risk score: {result['risk_score']}")
        break
else:
    print("   ⚠️  No beaconing detected (may need more connections)")

# Test 2: Port Scanning Detection  
print("\n2️⃣  Testing Port Scanning Detection...")
print("   Simulating rapid connections to multiple ports...")

scan_pid = 23456
scan_time = time.time()

for port in range(1000, 1020):  # 20 different ports
    result = analyzer.analyze_connection(
        pid=scan_pid,
        dest_ip="192.168.1.200",
        dest_port=port,
        timestamp=scan_time + (port - 1000) * 0.1  # Very fast (0.1s apart)
    )
    
    if result and result['type'] == 'PORT_SCANNING':
        print(f"   ✅ DETECTED: Port scanning after {port-999} connections")
        print(f"      Unique ports: {result['unique_ports']}")
        print(f"      Timeframe: {result['timeframe']:.1f}s")
        print(f"      Risk score: {result['risk_score']}")
        break
else:
    print("   ⚠️  No port scanning detected")

# Test 3: Normal Behavior (should NOT detect)
print("\n3️⃣  Testing Normal Behavior...")
print("   Simulating normal HTTP connections (varied timing)...")

normal_pid = 34567
normal_time = time.time()

detections = 0
for i in range(10):
    result = analyzer.analyze_connection(
        pid=normal_pid,
        dest_ip="example.com",
        dest_port=443,
        timestamp=normal_time + i * (5.0 + i * 2.0)  # Irregular intervals
    )
    if result:
        detections += 1

if detections == 0:
    print("   ✅ CORRECT: Normal behavior not flagged")
else:
    print(f"   ⚠️  WARNING: {detections} false positives on normal behavior")

# Stats
print("\n" + "="*60)
print("SUMMARY")
print("="*60)
stats = analyzer.get_stats()
print(f"Total connections analyzed: {stats['total_connections_analyzed']}")
print(f"C2 beacons detected: {stats['beacons_detected']}")
print(f"Port scans detected: {stats['port_scans_detected']}")
print(f"Exfiltrations detected: {stats['exfiltrations_detected']}")

if stats['beacons_detected'] > 0 or stats['port_scans_detected'] > 0:
    print("\n✅ CONNECTION PATTERN DETECTION WORKING!")
else:
    print("\n⚠️  No patterns detected (may need tuning)")

print("\n" + "="*60)

