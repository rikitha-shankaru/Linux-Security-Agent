#!/usr/bin/env python3
"""
Quick test script to verify enhanced anomaly logging
This script simulates suspicious activity to trigger anomaly detection
"""

import os
import sys
import time
import subprocess

print("🧪 Testing Enhanced Anomaly Logging")
print("="*60)
print()
print("This script will:")
print("  1. Check if agent is running")
print("  2. Simulate suspicious activity")
print("  3. Show you the enhanced anomaly logs")
print()

# Check if agent is running
print("Step 1: Checking if agent is running...")
result = subprocess.run("pgrep -f 'simple_agent.py'", shell=True, capture_output=True, text=True)
if result.returncode != 0:
    print("❌ Agent is not running!")
    print()
    print("Please start the agent first:")
    print("  sudo python3 core/simple_agent.py --collector ebpf --threshold 20")
    print()
    sys.exit(1)

agent_pid = result.stdout.strip().split('\n')[0]
print(f"✅ Agent is running (PID: {agent_pid})")
print()

# Wait a moment
time.sleep(2)

# Simulate suspicious activity
print("Step 2: Simulating suspicious activity...")
print("  - Running privilege escalation patterns")
print("  - Executing high-risk syscalls")
print()

# Create a test script that generates suspicious syscalls
test_script = """
import os
import ctypes
import sys

# Load libc for syscalls
libc = ctypes.CDLL(None)

# Simulate suspicious activity
print("Simulating suspicious syscall patterns...")

# High-risk syscall patterns
for i in range(20):
    # setuid/setgid patterns
    try:
        os.setuid(0)  # This will fail but generates syscall
    except:
        pass
    
    # File manipulation
    try:
        os.chmod("/tmp/test_file", 0o777)
    except:
        pass
    
    # Process creation
    try:
        os.fork()
    except:
        pass
    
    # File operations
    try:
        with open(f"/tmp/test_{i}.txt", "w") as f:
            f.write("test")
        os.unlink(f"/tmp/test_{i}.txt")
    except:
        pass

print("Suspicious activity simulation complete")
"""

# Write and execute test script
with open("/tmp/test_anomaly.py", "w") as f:
    f.write(test_script)

print("Executing test script...")
subprocess.run("python3 /tmp/test_anomaly.py", shell=True, timeout=10)
print("✅ Test script executed")
print()

# Wait for detection
print("Step 3: Waiting for agent to detect anomalies (5 seconds)...")
time.sleep(5)
print()

# Show enhanced logs
print("Step 4: Showing enhanced anomaly logs...")
print("="*60)
print()

log_file = "logs/security_agent.log"
if os.path.exists(log_file):
    # Read last 100 lines and filter for anomaly detections
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    # Find anomaly detections
    anomaly_lines = []
    in_anomaly_block = False
    anomaly_block = []
    
    for i, line in enumerate(lines):
        if "ANOMALY DETECTED:" in line:
            in_anomaly_block = True
            anomaly_block = [line]
        elif in_anomaly_block:
            if line.strip().startswith("   "):  # Continuation of anomaly block
                anomaly_block.append(line)
            elif line.strip() == "":
                anomaly_block.append(line)
            else:
                # End of anomaly block
                if anomaly_block:
                    anomaly_lines.extend(anomaly_block)
                    anomaly_lines.append("\n")
                in_anomaly_block = False
                anomaly_block = []
    
    # Add last block if still in one
    if anomaly_block:
        anomaly_lines.extend(anomaly_block)
    
    if anomaly_lines:
        print("📋 Recent Anomaly Detections (Enhanced Format):")
        print()
        # Show last 3 anomaly detections
        for line in anomaly_lines[-50:]:  # Last 50 lines of anomaly blocks
            print(line.rstrip())
    else:
        print("⚠️  No anomaly detections found in recent logs")
        print()
        print("This could mean:")
        print("  - The activity wasn't detected yet (wait a few more seconds)")
        print("  - The activity wasn't anomalous enough")
        print("  - Check the full log file:")
        print(f"    tail -50 {log_file}")
else:
    print(f"❌ Log file not found: {log_file}")
    print("Make sure the agent is running and has created the log file")

print()
print("="*60)
print()
print("✅ Test complete!")
print()
print("To see live anomaly detections:")
print(f"  tail -f {log_file} | grep -A 10 'ANOMALY DETECTED'")
print()

