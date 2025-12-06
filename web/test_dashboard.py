#!/usr/bin/env python3
"""
Test script to verify dashboard is working correctly
"""

import requests
import subprocess
import time
import sys
from pathlib import Path

def test_dashboard():
    """Test all dashboard components"""
    print("🧪 Testing Web Dashboard")
    print("="*60)
    print()
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: Check if server is running
    print("Test 1: Dashboard server status...")
    try:
        response = requests.get("http://localhost:5001", timeout=5)
        if response.status_code == 200:
            print("   ✅ Dashboard server is running")
            tests_passed += 1
        else:
            print(f"   ❌ Server returned status {response.status_code}")
            tests_failed += 1
    except requests.exceptions.ConnectionError:
        print("   ❌ Dashboard server is NOT running")
        print("   💡 Start it with: cd web && python3 app.py")
        tests_failed += 1
    except Exception as e:
        print(f"   ❌ Error: {e}")
        tests_failed += 1
    
    print()
    
    # Test 2: Check API status endpoint
    print("Test 2: API status endpoint...")
    try:
        response = requests.get("http://localhost:5001/api/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ API responding: {data}")
            tests_passed += 1
        else:
            print(f"   ❌ API returned status {response.status_code}")
            tests_failed += 1
    except Exception as e:
        print(f"   ❌ Error: {e}")
        tests_failed += 1
    
    print()
    
    # Test 3: Check if agent log file exists
    print("Test 3: Agent log file...")
    log_file = Path(__file__).parent.parent / 'logs' / 'security_agent.log'
    if log_file.exists():
        size = log_file.stat().st_size
        mtime = log_file.stat().st_mtime
        age = time.time() - mtime
        
        print(f"   ✅ Log file exists ({size} bytes)")
        if age < 10:
            print(f"   ✅ Log file is recent ({age:.1f}s ago) - agent is running")
            tests_passed += 1
        else:
            print(f"   ⚠️  Log file is old ({age:.1f}s ago) - agent may not be running")
            tests_failed += 1
    else:
        print("   ⚠️  Log file not found - agent may not be started")
        print("   💡 Start agent with: sudo python3 core/simple_agent.py --collector ebpf --threshold 20")
        tests_failed += 1
    
    print()
    
    # Test 4: Check if agent process is running
    print("Test 4: Agent process...")
    try:
        result = subprocess.run(['pgrep', '-f', 'simple_agent.py'], 
                              capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            print(f"   ✅ Agent process running (PIDs: {', '.join(pids)})")
            tests_passed += 1
        else:
            print("   ⚠️  Agent process not found")
            print("   💡 Start agent with: sudo python3 core/simple_agent.py --collector ebpf --threshold 20")
            tests_failed += 1
    except Exception as e:
        print(f"   ⚠️  Could not check process: {e}")
        tests_failed += 1
    
    print()
    
    # Test 5: Check recent log entries
    print("Test 5: Recent log entries...")
    if log_file.exists():
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-10:] if len(lines) > 10 else lines
                
                if recent_lines:
                    print(f"   ✅ Found {len(recent_lines)} recent log entries")
                    print("   Recent entries:")
                    for line in recent_lines[-3:]:
                        print(f"      {line.strip()[:80]}")
                    tests_passed += 1
                else:
                    print("   ⚠️  No log entries found")
                    tests_failed += 1
        except Exception as e:
            print(f"   ❌ Error reading log: {e}")
            tests_failed += 1
    else:
        print("   ⚠️  Log file not found")
        tests_failed += 1
    
    print()
    
    # Test 6: Check WebSocket endpoint (basic check)
    print("Test 6: WebSocket endpoint...")
    try:
        # Just check if the page loads with socket.io
        response = requests.get("http://localhost:5001/monitor", timeout=5)
        if response.status_code == 200 and 'socket.io' in response.text:
            print("   ✅ Monitor page loads with WebSocket support")
            tests_passed += 1
        else:
            print("   ⚠️  Monitor page may not have WebSocket")
            tests_failed += 1
    except Exception as e:
        print(f"   ❌ Error: {e}")
        tests_failed += 1
    
    print()
    print("="*60)
    print(f"Results: {tests_passed} passed, {tests_failed} failed")
    print()
    
    if tests_failed == 0:
        print("✅ All tests passed! Dashboard is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the messages above.")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(test_dashboard())
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted")
        sys.exit(1)

