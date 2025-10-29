#!/usr/bin/env python3
try:
    from bcc import BPF
    print("✅ eBPF ready!")
except ImportError as e:
    print(f"❌ eBPF not available: {e}")
    print("Install with: sudo apt-get install bpfcc-tools python3-bpfcc")
