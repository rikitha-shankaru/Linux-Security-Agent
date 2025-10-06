#!/bin/bash

echo "🐧 Linux VM Setup Script for Security Agent"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (sudo)"
    exit 1
fi

echo "✅ Running as root"
echo ""

# Update system
echo "📦 Updating system packages..."
apt-get update

# Install dependencies
echo "🔧 Installing dependencies..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    bpfcc-tools \
    python3-bpfcc \
    build-essential \
    linux-headers-$(uname -r) \
    git \
    curl

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
pip3 install psutil scikit-learn numpy pandas colorama rich click requests

# Test eBPF
echo "🧪 Testing eBPF..."
python3 -c "
try:
    from bcc import BPF
    print('✅ eBPF is working!')
except ImportError as e:
    print('❌ eBPF not available:', e)
"

echo ""
echo "🎉 Setup complete!"
echo ""
echo "🚀 To run the security agent:"
echo "   sudo python3 security_agent.py --dashboard --threshold 30"
echo ""
echo "📊 Expected output:"
echo "   - Real eBPF system call monitoring"
echo "   - Kernel-level security monitoring"
echo "   - No fallback messages"
echo "   - Full enterprise capabilities"
