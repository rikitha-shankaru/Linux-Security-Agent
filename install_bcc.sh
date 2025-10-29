#!/bin/bash

echo "=== Installing BCC (eBPF Tools) ==="
echo
echo "Installing bpfcc-tools and python3-bpfcc..."
echo

# For Ubuntu/Debian
if [ -f /etc/debian_version ]; then
    sudo apt-get update
    sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
else
    echo "This script is for Ubuntu/Debian. For other distros, install bcc manually."
    exit 1
fi

echo
echo "Verifying BCC installation..."
python3 -c "
try:
    from bcc import BPF
    print('✅ BCC installed successfully')
except ImportError as e:
    print(f'❌ BCC import failed: {e}')
"

echo
echo "=== Done ==="

