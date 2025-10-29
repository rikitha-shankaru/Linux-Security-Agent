#!/usr/bin/env python3
"""
Debug test to see what's actually being captured
"""

from core.enhanced_ebpf_monitor import StatefulEBPFMonitor
import time

def test():
    monitor = StatefulEBPFMonitor()
    
    all_events = []
    
    def callback(pid, syscall_name, info):
        all_events.append({
            'pid': pid,
            'syscall': syscall_name,
            'syscall_num': info.get('syscall_num', 'unknown'),
            'timestamp': info.get('timestamp', 0)
        })
    
    print("Starting monitoring...")
    monitor.start_monitoring(event_callback=callback)
    
    print("Capturing for 5 seconds...")
    time.sleep(5)
    
    monitor.stop_monitoring()
    
    print(f"\nTotal events: {len(all_events)}")
    
    if len(all_events) > 0:
        print("\nFirst 5 events:")
        for event in all_events[:5]:
            print(f"  PID {event['pid']}: {event['syscall']} (num: {event['syscall_num']})")
        
        print("\nUnique syscalls:")
        unique = set([e['syscall'] for e in all_events])
        for s in sorted(unique):
            print(f"  {s}")
    
    # Also check what's in monitor.events directly
    print(f"\nEvents stored in monitor.events: {len(monitor.events)}")
    if len(monitor.events) > 0:
        print(f"First event in monitor.events:")
        print(f"  {monitor.events[0]}")
    
    print(f"\nSyscall stats: {dict(monitor.syscall_stats)}")

if __name__ == "__main__":
    test()

