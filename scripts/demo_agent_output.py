#!/usr/bin/env python3
"""
Demo script showing how the agent runs and what output looks like
This simulates the agent's behavior and logging format
"""

import time
from datetime import datetime

def print_header(text):
    print(f"\n{'='*80}")
    print(f"{text:^80}")
    print(f"{'='*80}\n")

def print_section(text):
    print(f"\n{'-'*80}")
    print(f"{text}")
    print(f"{'-'*80}\n")

def demo_agent_startup():
    """Show agent startup sequence"""
    print_header("🛡️  SECURITY AGENT STARTUP")
    
    print("Starting Security Agent...")
    print("Collector type: ebpf")
    print("Risk threshold: 20.0")
    print("ML detector available: True")
    print("Connection analyzer available: True")
    print()
    print("✅ System validation passed")
    print("✅ Initializing collector: ebpf")
    print("✅ eBPF collector initialized")
    print("✅ ML models loaded")
    print("✅ Agent started successfully")
    print()
    print(f"Agent PID: 12345 (will be excluded from detection)")
    print(f"Excluding processes by name from detection: fluent-bit, containerd, systemd")
    print()
    print("="*60)
    print("Security Agent Starting")
    print(f"Log file: logs/security_agent.log")
    print("="*60)
    print()

def demo_normal_activity():
    """Show normal activity monitoring"""
    print_section("📊 Normal Activity Monitoring")
    
    print("Monitoring system processes...")
    print()
    print("📊 SCORE UPDATE: PID=5678 Process=bash Risk=12.3 Anomaly=8.5 "
          "Syscalls=50 TotalSyscalls=150 ConnectionBonus=0.0")
    print("📊 SCORE UPDATE: PID=9012 Process=python3 Risk=15.2 Anomaly=10.1 "
          "Syscalls=30 TotalSyscalls=80 ConnectionBonus=0.0")
    print()
    time.sleep(1)

def demo_anomaly_detection():
    """Show enhanced anomaly detection"""
    print_section("⚠️  ANOMALY DETECTION (Enhanced Format)")
    
    print("Simulating suspicious activity...")
    time.sleep(2)
    
    # Example 1: Privilege Escalation
    print()
    print("⚠️  ANOMALY DETECTED: PID=12345 Process=python3 AnomalyScore=35.2")
    print("   ┌─ What's Anomalous:")
    print("   │  Isolation Forest detected outlier behavior; One-Class SVM identified deviation from normal; High proportion of risky system calls")
    print("   │  Confidence: 0.81 | Risk Score: 18.5")
    print("   ├─ Process Activity:")
    print("   │  Total Syscalls: 100 | Recent: 15")
    print("   │  Top Syscalls: setuid(5), execve(3), chmod(2), read(2), write(1)")
    print("   │  ⚠️  High-Risk Syscalls Detected: setuid, execve, chmod")
    print("   │  Resources: CPU=45.2% Memory=12.3% Threads=3")
    print("   └─ Recent Sequence: setuid, execve, chmod, read, write, open, close, setuid, execve, chmod")
    print()
    
    time.sleep(1)
    
    # Example 2: High-Frequency Attack
    print("⚠️  ANOMALY DETECTED: PID=23456 Process=test_script AnomalyScore=42.8")
    print("   ┌─ What's Anomalous:")
    print("   │  Isolation Forest detected outlier behavior; Unusually high system call rate; Low system call diversity (low entropy)")
    print("   │  Confidence: 0.89 | Risk Score: 25.3")
    print("   ├─ Process Activity:")
    print("   │  Total Syscalls: 500 | Recent: 20")
    print("   │  Top Syscalls: read(150), write(120), open(80), close(75), mmap(30)")
    print("   │  ⚠️  High-Risk Syscalls Detected: (none in recent)")
    print("   │  Resources: CPU=78.5% Memory=25.6% Threads=1")
    print("   └─ Recent Sequence: read, write, read, write, open, close, read, write, read, write")
    print()
    
    time.sleep(1)
    
    # Example 3: Suspicious File Patterns
    print("⚠️  ANOMALY DETECTED: PID=34567 Process=malicious_script AnomalyScore=38.5")
    print("   ┌─ What's Anomalous:")
    print("   │  One-Class SVM identified deviation from normal; High proportion of risky system calls; Unusual syscall sequence (low bigram likelihood)")
    print("   │  Confidence: 0.76 | Risk Score: 22.1")
    print("   ├─ Process Activity:")
    print("   │  Total Syscalls: 75 | Recent: 12")
    print("   │  Top Syscalls: chmod(8), chown(6), unlink(4), rename(2), open(1)")
    print("   │  ⚠️  High-Risk Syscalls Detected: chmod, chown, unlink, rename")
    print("   │  Resources: CPU=12.3% Memory=5.2% Threads=1")
    print("   └─ Recent Sequence: chmod, chown, unlink, rename, open, close, chmod, chown, unlink, rename")
    print()

def demo_high_risk_detection():
    """Show high risk detection"""
    print_section("🔴 HIGH RISK DETECTION")
    
    print("🔴 HIGH RISK DETECTED: PID=45678 Process=attack_script Risk=65.8 Anomaly=45.3")
    print("   Threshold: 20.0 | Base Risk: 60.2 | Connection Bonus: 5.6 | Total Syscalls: 200")
    print("   Recent syscalls: ptrace, setuid, execve, chroot, mount, umount, ptrace, setuid, execve, chroot")
    print("   Process resources: CPU=85.2% Memory=45.3% Threads=10")
    print()

def demo_connection_patterns():
    """Show connection pattern detection"""
    print_section("🌐 CONNECTION PATTERN DETECTION")
    
    print("⚠️  CONNECTION PATTERN DETECTED: PID=56789 Process=network_scan")
    print("   Pattern: PORT_SCANNING")
    print("   Details: Multiple rapid connections to different ports detected")
    print("   Connections: 15 unique ports in 5 seconds")
    print("   Risk Bonus: +10.0 added to base risk score")
    print()

def demo_dashboard_stats():
    """Show dashboard statistics"""
    print_section("📊 DASHBOARD STATISTICS")
    
    print("Processes: 5 | High Risk: 1 | Anomalies: 3 | C2: 0 | Scans: 1 | Syscalls: 1,250")
    print()
    print("Top Processes by Risk:")
    print("  PID      Process            Risk     Anomaly    Status")
    print("  ────────────────────────────────────────────────────────")
    print("  45678    attack_script      65.8     45.3       🔴 HIGH")
    print("  34567    malicious_script   38.5     38.5       ⚠️  ANOM")
    print("  23456    test_script        42.8     42.8       ⚠️  ANOM")
    print("  12345    python3            35.2     35.2       ⚠️  ANOM")
    print("  5678     bash               12.3     8.5        🟢 OK")
    print()

def main():
    """Run the demo"""
    print_header("🛡️  LINUX SECURITY AGENT - DEMONSTRATION")
    
    print("This demo shows:")
    print("  1. Agent startup sequence")
    print("  2. Normal activity monitoring")
    print("  3. Enhanced anomaly detection (NEW!)")
    print("  4. High risk detection")
    print("  5. Connection pattern detection")
    print("  6. Dashboard statistics")
    print()
    
    print("Starting demo in 2 seconds...")
    time.sleep(2)
    
    # Run demos
    demo_agent_startup()
    time.sleep(2)
    
    demo_normal_activity()
    time.sleep(2)
    
    demo_anomaly_detection()
    time.sleep(2)
    
    demo_high_risk_detection()
    time.sleep(1)
    
    demo_connection_patterns()
    time.sleep(1)
    
    demo_dashboard_stats()
    
    print_header("✅ DEMO COMPLETE")
    print()
    print("To run the actual agent on your VM:")
    print("  1. sudo python3 core/simple_agent.py --collector ebpf --threshold 20")
    print("  2. In another terminal: python3 scripts/simulate_attacks.py")
    print("  3. Watch logs: tail -f logs/security_agent.log")
    print()

if __name__ == "__main__":
    main()

