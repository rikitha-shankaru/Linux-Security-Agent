#!/usr/bin/env python3
"""
Find what syscalls actually exist on this system
"""

import os
import subprocess

def find_available_syscalls():
    print("🔍 Finding available syscalls on your system...")
    
    # Check available tracepoints
    print("\n📊 Available syscall tracepoints:")
    try:
        result = subprocess.run(['find', '/sys/kernel/debug/tracing/events/syscalls', '-name', 'sys_enter_*'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            tracepoints = result.stdout.strip().split('\n')
            for tp in tracepoints[:20]:  # Show first 20
                if tp:
                    print(f"   {tp}")
            print(f"   ... and {len(tracepoints)-20} more" if len(tracepoints) > 20 else "")
        else:
            print("   ❌ No tracepoints found")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Check available kprobes
    print("\n🔧 Available kprobe targets (syscall-related):")
    try:
        result = subprocess.run(['grep', '-r', 'do_sys', '/proc/kallsyms'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            kprobes = result.stdout.strip().split('\n')
            for kp in kprobes[:10]:  # Show first 10
                if kp:
                    print(f"   {kp}")
        else:
            print("   ❌ No kprobes found")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Check kernel version
    print("\n🐧 System info:")
    try:
        with open('/proc/version', 'r') as f:
            print(f"   Kernel: {f.read().strip()}")
    except:
        print("   ❌ Cannot read kernel version")
    
    # Check architecture
    try:
        result = subprocess.run(['uname', '-m'], capture_output=True, text=True)
        print(f"   Architecture: {result.stdout.strip()}")
    except:
        print("   ❌ Cannot determine architecture")

if __name__ == "__main__":
    find_available_syscalls()
