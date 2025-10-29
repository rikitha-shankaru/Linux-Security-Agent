#!/usr/bin/env python3
"""
Test script to verify syscall capture is working
"""

from core.enhanced_ebpf_monitor import StatefulEBPFMonitor
import time

def test_syscall_capture():
    print("=== Testing Syscall Capture ===")
    print()
    
    monitor = StatefulEBPFMonitor()
    
    # Track captured syscalls
    captured_syscalls = []
    
    def callback(pid, syscall_name, info):
        captured_syscalls.append({
            'pid': pid,
            'syscall': syscall_name,
            'timestamp': info.get('timestamp', 0)
        })
    
    print("Starting monitoring...")
    monitor.start_monitoring(event_callback=callback)
    
    print("📊 Capturing syscalls for 10 seconds...")
    print("   (Do some normal work - browse files, open terminal, etc.)")
    time.sleep(10)
    
    print("Stopping monitoring...")
    monitor.stop_monitoring()
    
    # Analyze results
    unique_syscalls = set([s['syscall'] for s in captured_syscalls])
    syscall_counts = {}
    for s in captured_syscalls:
        syscall_counts[s['syscall']] = syscall_counts.get(s['syscall'], 0) + 1
    
    print()
    print(f"✅ Captured {len(captured_syscalls)} total syscalls")
    print(f"✅ Found {len(unique_syscalls)} unique syscall types")
    print()
    
    # Show most common syscalls
    sorted_syscalls = sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)
    print("Top 10 most common syscalls:")
    for syscall, count in sorted_syscalls[:10]:
        print(f"  {syscall:20} → {count}")
    
    print()
    
    # Verify we got real syscalls
    expected_syscalls = ['read', 'write', 'open', 'close', 'mmap']
    found_expected = [s for s in expected_syscalls if s in unique_syscalls]
    
    print(f"Looking for common syscalls: {expected_syscalls}")
    print(f"Found: {found_expected}")
    print()
    
    if len(found_expected) >= 3:
        print("✅ SUCCESS: Real syscalls are being captured!")
        print("   This means Bug #1 (eBPF capture) is FIXED")
        return True
    elif len(captured_syscalls) > 0:
        print("⚠️  Partial success: Got syscalls but not the expected ones")
        print("   Check if running on Linux with proper BCC")
        return False
    else:
        print("❌ FAILURE: No syscalls captured")
        print("   This might mean:")
        print("   - Not running on Linux")
        print("   - BCC not installed")
        print("   - Permission issues")
        return False

if __name__ == "__main__":
    success = test_syscall_capture()
    exit(0 if success else 1)

