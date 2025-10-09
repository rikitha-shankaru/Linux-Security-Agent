#!/usr/bin/env python3
"""
Simple eBPF test to check if we can capture ANY events
"""

from bcc import BPF
import time

# Simple eBPF program that just counts events
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(counter_table);

int trace_syscall(struct pt_regs *ctx) {
    u64 zero = 0;
    u64 *count = counter_table.lookup_or_init(&zero, &zero);
    (*count)++;
    return 0;
}
"""

def test_ebpf():
    print("🧪 Testing eBPF functionality...")
    
    try:
        # Load eBPF program
        bpf = BPF(text=bpf_text)
        print("✅ eBPF program loaded successfully")
        
        # Try different attachment methods
        attachment_methods = [
            ("do_sys_openat2", "kprobe"),
            ("do_sys_open", "kprobe"), 
            ("__arm64_sys_openat", "kprobe"),
            ("syscalls:sys_enter_openat", "tracepoint"),
            ("syscalls:sys_enter_read", "tracepoint"),
        ]
        
        for method, method_type in attachment_methods:
            try:
                print(f"🔍 Trying {method_type}: {method}")
                if method_type == "kprobe":
                    bpf.attach_kprobe(event=method, fn_name="trace_syscall")
                else:
                    bpf.attach_tracepoint(tp=method, fn_name="trace_syscall")
                
                print(f"✅ Successfully attached to {method}")
                
                # Test for 5 seconds
                print("📊 Monitoring for 5 seconds...")
                for i in range(5):
                    time.sleep(1)
                    counter_table = bpf["counter_table"]
                    count = 0
                    for k, v in counter_table.items():
                        count += v.value
                    print(f"   Events captured: {count}")
                
                if count > 0:
                    print(f"🎉 SUCCESS! Captured {count} real events with {method}")
                    return True
                else:
                    print(f"❌ No events captured with {method}")
                    bpf.detach_kprobe(event=method)
                    
            except Exception as e:
                print(f"❌ Failed to attach to {method}: {e}")
                continue
        
        print("❌ No working eBPF attachment method found")
        return False
        
    except Exception as e:
        print(f"❌ eBPF test failed: {e}")
        return False

if __name__ == "__main__":
    test_ebpf()

