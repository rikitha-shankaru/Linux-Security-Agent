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
        "Attempts setuid, setgid, execve patterns with high-risk syscalls"
    )
    
    # Create a test script that generates high-risk syscalls
    # Use ctypes to call syscalls directly (safe in VM)
    test_script = """
import os
import sys
import ctypes
import subprocess

# Generate execve syscalls (high risk: 5 points each)
for i in range(20):
    subprocess.run(['/bin/echo', 'test'], capture_output=True, timeout=1)
    subprocess.run(['/bin/cat', '/etc/passwd'], capture_output=True, timeout=1)

# Generate chmod/chown syscalls (medium risk: 3 points each)
test_file = '/tmp/priv_test.txt'
with open(test_file, 'w') as f:
    f.write('test')
try:
    os.chmod(test_file, 0o777)  # chmod syscall
    os.chown(test_file, 0, 0)  # chown syscall (will fail but generates syscall)
except:
    pass

# Generate mount/unmount attempts (medium risk: 4 points)
try:
    # Try to remount /tmp (will fail but generates mount syscall)
    os.system('mount -o remount /tmp 2>/dev/null')
except:
    pass

# Cleanup
try:
    os.remove(test_file)
except:
    pass
"""
    
    # Run the script multiple times to create pattern
    for i in range(10):
        try:
            result = subprocess.run([sys.executable, '-c', test_script], 
                          capture_output=True, timeout=10, check=False)
            time.sleep(0.2)  # Slightly longer delay
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            pass
    
    print(f"{GREEN}✅ Privilege escalation pattern executed (10 iterations, high-risk syscalls){RESET}")

def simulate_high_frequency_attack():
    """Simulate high-frequency attack (DoS pattern)"""
    print_attack(
        "High-Frequency Attack",
        "Rapid syscall bursts to trigger rate-based detection"
    )
    
    # Run in a separate process that stays alive longer
    import subprocess
    attack_script = '''
import os
import time
from pathlib import Path

temp_dir = Path("/tmp/attack_sim")
temp_dir.mkdir(exist_ok=True)

# Generate syscalls over 3-4 seconds to be visible
for i in range(300):
    test_file = temp_dir / f"test_{i}.txt"
    test_file.write_text(f"Attack simulation data {i}\\n" * 100)
    test_file.read_text()
    test_file.chmod(0o755)
    os.stat(test_file)
    if i % 30 == 0:
        time.sleep(0.1)  # Slower to keep process alive

# Cleanup
for file in temp_dir.glob("test_*.txt"):
    file.unlink()
temp_dir.rmdir()
'''
    
    try:
        # Run in separate process that stays alive
        proc = subprocess.Popen(
            [sys.executable, '-c', attack_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        proc.wait(timeout=10)  # Wait for completion
    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
    
    print(f"{GREEN}✅ High-frequency pattern executed (300 file ops, longer runtime){RESET}")

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
    
    # Spawn MANY processes that run LONGER to be visible in dashboard
    processes = []
    for i in range(50):  # Reduced count but longer runtime
        # Each process does file I/O and runs for 2-3 seconds
        script_code = f'''
import os
import time
# Generate syscalls over longer period
for j in range(20):
    filename = "/tmp/churn_{i}_" + str(j) + ".tmp"
    with open(filename, "w") as f:
        f.write("test " * 100)  # Larger writes
    with open(filename, "r") as f:
        f.read()
    os.stat(filename)
    os.remove(filename)
    time.sleep(0.1)  # Slower to keep process alive longer
'''
        proc = subprocess.Popen(
            [sys.executable, '-c', script_code],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        processes.append(proc)
        time.sleep(0.05)  # Small delay between spawns
    
    # Wait for all to complete (with longer timeout)
    for proc in processes:
        try:
            proc.wait(timeout=5)  # Increased timeout
        except subprocess.TimeoutExpired:
            proc.kill()
    
    print(f"{GREEN}✅ Process churn pattern executed (50 processes, longer runtime){RESET}")

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
    """Simulate ptrace attempts with actual ptrace syscalls"""
    print_attack(
        "Ptrace Attempts",
        "Attempts to ptrace other processes (generates ptrace syscalls)"
    )
    
    # Use strace or gdb to generate ptrace syscalls (safe in VM)
    try:
        # Create child processes and use tools that call ptrace
        for i in range(10):
            # Use strace to trace a simple command (generates ptrace syscalls)
            child = subprocess.Popen(
                ['strace', '-e', 'trace=open,read,write', 'echo', 'test'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            try:
                child.wait(timeout=2)
            except:
                child.kill()
            
            # Alternative: use gdb (also generates ptrace)
            try:
                gdb_cmd = subprocess.Popen(
                    ['gdb', '--batch', '--ex', 'run', '--ex', 'quit', '/bin/echo', 'test'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                gdb_cmd.wait(timeout=2)
            except:
                pass
            
            time.sleep(0.1)
    except FileNotFoundError:
        # If strace/gdb not available, create many fork/execve patterns
        # These still generate high-risk syscalls
        for i in range(20):
            proc = subprocess.Popen(
                [sys.executable, '-c', 'import os; os.system("echo test")'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            proc.wait(timeout=1)
    except Exception as e:
        pass
    
    print(f"{GREEN}✅ Ptrace pattern simulated (high-risk syscalls generated){RESET}")

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

