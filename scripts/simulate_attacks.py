#!/usr/bin/env python3
"""
Safe Attack Simulation Script
Safely simulates attack patterns to test the security agent
DO NOT RUN ON PRODUCTION SYSTEMS - Use in VM only!
"""

import os
import sys
import time
import subprocess
import signal
import random
from pathlib import Path

# Colors for output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_header(text):
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{text}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")

def print_attack(name, description):
    print(f"{YELLOW}🔴 Attack: {name}{RESET}")
    print(f"   {description}")
    print()

def simulate_privilege_escalation():
    """Simulate privilege escalation attack pattern"""
    print_attack(
        "Privilege Escalation",
        "Attempts setuid, setgid, execve patterns (safe - will fail)"
    )
    
    # Create a test script that attempts privilege operations
    test_script = """
import os
import sys

# Attempt setuid (will fail - safe)
try:
    os.setuid(0)  # Will fail unless root
except PermissionError:
    pass

# Attempt setgid (will fail - safe)
try:
    os.setgid(0)  # Will fail unless root
except PermissionError:
    pass

# Execute commands (normal execve pattern)
os.system('echo "test" > /tmp/test_attack.txt')
os.system('cat /tmp/test_attack.txt')
os.system('rm /tmp/test_attack.txt')
"""
    
    # Run the script multiple times to create pattern
    for i in range(10):
        try:
            result = subprocess.run([sys.executable, '-c', test_script], 
                          capture_output=True, timeout=5, check=False)
            time.sleep(0.1)
        except subprocess.TimeoutExpired:
            # Expected - some operations may hang, that's fine
            pass
        except Exception as e:
            # Ignore other errors
            pass
    
    print(f"{GREEN}✅ Privilege escalation pattern executed (10 iterations){RESET}")

def simulate_high_frequency_attack():
    """Simulate high-frequency attack (DoS pattern)"""
    print_attack(
        "High-Frequency Attack",
        "Rapid syscall bursts to trigger rate-based detection"
    )
    
    # Rapid file operations - MORE AGGRESSIVE
    temp_dir = Path('/tmp/attack_sim')
    temp_dir.mkdir(exist_ok=True)
    
    try:
        # Create MANY files rapidly (increased from 100 to 500)
        for i in range(500):
            test_file = temp_dir / f"test_{i}.txt"
            test_file.write_text(f"Attack simulation data {i}\n" * 100)  # Larger files
            test_file.read_text()
            # Also do stat, chmod, etc. to generate more syscalls
            test_file.chmod(0o755)
            os.stat(test_file)
            if i % 50 == 0:
                time.sleep(0.001)  # Minimal delay
        
        # Rapid cleanup
        for file in temp_dir.glob("test_*.txt"):
            file.unlink()
        temp_dir.rmdir()
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
    
    print(f"{GREEN}✅ High-frequency pattern executed (500 file ops){RESET}")

def simulate_suspicious_file_patterns():
    """Simulate suspicious file access patterns"""
    print_attack(
        "Suspicious File Patterns",
        "Bursty file I/O with unusual patterns"
    )
    
    temp_dir = Path('/tmp/suspicious_pattern')
    temp_dir.mkdir(exist_ok=True)
    
    try:
        # Create and delete files in rapid succession (increased from 50 to 200)
        for i in range(200):
            # Create file
            test_file = temp_dir / f"suspicious_{i}.dat"
            # Larger files to generate more I/O
            test_file.write_bytes(b'x' * 10240)  # 10KB file
            
            # Read it back multiple times
            for _ in range(3):
                test_file.read_bytes()
            
            # Also do stat, chmod, etc.
            os.stat(test_file)
            os.chmod(test_file, 0o755)
            
            # Delete it
            test_file.unlink()
            
            # Minimal delay for bursty pattern
            if i % 20 == 0:
                time.sleep(0.001)
        
        temp_dir.rmdir()
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
    
    print(f"{GREEN}✅ Suspicious file pattern executed (200 files){RESET}")

def simulate_process_churn():
    """Simulate rapid process creation/termination"""
    print_attack(
        "Process Churn",
        "Rapid fork/exec patterns"
    )
    
    # Spawn MANY short-lived processes (increased from 20 to 100)
    processes = []
    for i in range(100):
        # Each process does file I/O to generate more syscalls
        # Fix: Use string formatting that works correctly
        script_code = f'''
import os
import time
# Generate syscalls
for j in range(10):
    filename = "/tmp/churn_{i}_" + str(j) + ".tmp"
    with open(filename, "w") as f:
        f.write("test")
    os.remove(filename)
time.sleep(0.01)
'''
        proc = subprocess.Popen(
            [sys.executable, '-c', script_code],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        processes.append(proc)
        if i % 10 == 0:
            time.sleep(0.01)  # Small delay every 10 processes
    
    # Wait for all to complete
    for proc in processes:
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    
    print(f"{GREEN}✅ Process churn pattern executed (100 processes){RESET}")

def simulate_network_scanning():
    """Simulate network scanning pattern"""
    print_attack(
        "Network Scanning",
        "Rapid socket operations (safe - localhost only)"
    )
    
    import socket
    
    # Attempt to connect to multiple ports (will fail - safe)
    for port in range(8000, 8020):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect(('127.0.0.1', port))
            sock.close()
        except (socket.error, ConnectionRefusedError):
            pass  # Expected - port not open
        time.sleep(0.01)
    
    print(f"{GREEN}✅ Network scanning pattern executed (20 ports){RESET}")

def simulate_ptrace_attempts():
    """Simulate ptrace attempts (safe - will fail)"""
    print_attack(
        "Ptrace Attempts",
        "Attempts to ptrace other processes (safe - will fail)"
    )
    
    # Try to ptrace our own process (will fail - safe)
    try:
        # This would require ptrace syscall - simulate by attempting
        # In real attack, this would be: ptrace(PTRACE_ATTACH, target_pid)
        # We simulate by just creating the pattern
        for i in range(5):
            # Create a child process
            child = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(0.5)'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(0.1)
            child.terminate()
            child.wait()
    except Exception as e:
        pass
    
    print(f"{GREEN}✅ Ptrace pattern simulated{RESET}")

def run_all_attacks():
    """Run all attack simulations"""
    print_header("🔴 SAFE ATTACK SIMULATION - Testing Security Agent")
    print(f"{YELLOW}⚠️  WARNING: This script simulates attack patterns{RESET}")
    print(f"{YELLOW}⚠️  Only run in a VM or isolated environment{RESET}")
    print(f"{YELLOW}⚠️  All operations are safe and non-destructive{RESET}")
    print()
    
    input(f"{GREEN}Press Enter to start attack simulation...{RESET}")
    
    attacks = [
        ("Privilege Escalation", simulate_privilege_escalation),
        ("High-Frequency Attack", simulate_high_frequency_attack),
        ("Suspicious File Patterns", simulate_suspicious_file_patterns),
        ("Process Churn", simulate_process_churn),
        ("Network Scanning", simulate_network_scanning),
        ("Ptrace Attempts", simulate_ptrace_attempts),
    ]
    
    for name, attack_func in attacks:
        try:
            attack_func()
            time.sleep(1)  # Pause between attacks
        except KeyboardInterrupt:
            print(f"\n{YELLOW}⚠️  Attack simulation interrupted{RESET}")
            break
        except Exception as e:
            print(f"{RED}❌ Error in {name}: {e}{RESET}")
    
    print_header("✅ Attack Simulation Complete")
    print(f"{GREEN}Check your security agent dashboard for detection results!{RESET}")
    print()
    print("Expected results:")
    print("  - Risk scores should spike to 50-100")
    print("  - ML anomaly detection should flag these patterns")
    print("  - Dashboard should show high-risk processes")
    print()

if __name__ == "__main__":
    # Safety check - warn if not in VM
    if os.path.exists('/.dockerenv') or 'VM' in os.environ.get('HOSTNAME', ''):
        print(f"{GREEN}✅ Running in container/VM - safe to proceed{RESET}\n")
    else:
        print(f"{YELLOW}⚠️  Not detected as VM/container - proceed with caution{RESET}\n")
    
    run_all_attacks()

