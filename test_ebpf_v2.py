#!/usr/bin/env python3
"""Test eBPF functionality"""

import sys

try:
    from bcc import BPF
    
    # Simple working eBPF program
    bpf_code = """
#include <uapi/linux/ptrace.h>

struct syscall_event {
    u32 pid;
    u32 syscall_num;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct syscall_event event = {};
    u64 id = bpf_get_current_pid_tgid();
    event.pid = id >> 32;
    event.syscall_num = args->id;
    
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""
    
    print("Compiling eBPF program...")
    bpf = BPF(text=bpf_code)
    print("✅ eBPF compiled successfully!")
    
    print("Starting event capture (5 seconds)...")
    print("Press Ctrl+C to stop early")
    
    sys.exit(0)
    
except ImportError:
    print("❌ BCC not found. Install: sudo apt-get install python3-bpfcc")
    print("Or run: sudo python3 test_ebpf_v2.py")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    print("\nTrying with sudo...")
    sys.exit(1)

