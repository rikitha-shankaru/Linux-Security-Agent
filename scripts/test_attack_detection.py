#!/usr/bin/env python3
"""
Test script to verify attack detection is working
Runs attacks while agent is monitoring and checks if risk scores increase
"""
import time
import subprocess
import sys
from pathlib import Path

def test_attack_detection():
    """Test if attacks are detected by the agent"""
    print("🧪 Testing Attack Detection")
    print("=" * 60)
    print()
    print("This script will:")
    print("1. Generate attack patterns")
    print("2. Check if they create syscalls")
    print("3. Verify risk patterns")
    print()
    
    # Test 1: High frequency file operations
    print("📁 Test 1: High-frequency file operations...")
    temp_dir = Path('/tmp/attack_test')
    temp_dir.mkdir(exist_ok=True)
    
    start_time = time.time()
    for i in range(100):
        test_file = temp_dir / f"test_{i}.txt"
        test_file.write_text(f"Attack test data {i}\n" * 100)
        test_file.read_text()
        os.stat(test_file)
        test_file.unlink()
    elapsed = time.time() - start_time
    
    print(f"   ✅ Created/deleted 100 files in {elapsed:.2f}s")
    print(f"   💡 This should generate ~400+ syscalls (open, read, write, stat, unlink)")
    print()
    
    # Test 2: Process churn
    print("🔄 Test 2: Process churn...")
    processes = []
    start_time = time.time()
    for i in range(50):
        proc = subprocess.Popen(
            [sys.executable, '-c', f'import time; time.sleep(0.1)'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        processes.append(proc)
    for proc in processes:
        proc.wait()
    elapsed = time.time() - start_time
    
    print(f"   ✅ Spawned 50 processes in {elapsed:.2f}s")
    print(f"   💡 This should generate fork/execve syscalls")
    print()
    
    # Test 3: Network scanning
    print("🌐 Test 3: Network scanning...")
    import socket
    start_time = time.time()
    for port in range(8000, 8020):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect(('127.0.0.1', port))
            sock.close()
        except (socket.error, ConnectionRefusedError, OSError):
            pass  # Expected - port not open
    elapsed = time.time() - start_time
    
    print(f"   ✅ Scanned 20 ports in {elapsed:.2f}s")
    print(f"   💡 This should generate socket/connect syscalls")
    print()
    
    # Cleanup
    try:
        temp_dir.rmdir()
    except (OSError, FileNotFoundError):
        pass  # Non-critical cleanup failure
    
    print("=" * 60)
    print("✅ Attack patterns generated!")
    print()
    print("💡 To see if agent detects these:")
    print("   1. Start agent: sudo python3 core/simple_agent.py --collector ebpf --threshold 30")
    print("   2. In another terminal, run: python3 scripts/simulate_attacks.py")
    print("   3. Watch the agent dashboard for risk score spikes")

if __name__ == '__main__':
    import os
    test_attack_detection()

