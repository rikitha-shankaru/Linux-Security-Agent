#!/bin/bash
# Complete setup script to run IN your Linux VM SSH session
# Copy and paste this entire script into your Linux VM terminal

set -e

echo "🚀 Linux Security Agent - Setup and Training"
echo "============================================="
echo ""

# Check if we're in the right directory
if [ ! -f "core/enhanced_security_agent.py" ]; then
    echo "❌ Project files not found in current directory"
    echo ""
    echo "Please transfer files from your Mac first:"
    echo ""
    echo "On your MAC terminal (not SSH), run:"
    echo "  cd /Users/likithashankar/linux_security_agent"
    echo "  scp -r core/ config/ docs/ scripts/ tests/ requirements.txt agent@192.168.64.4:~/linux_security_agent/"
    echo ""
    exit 1
fi

echo "✅ Project files found"
echo ""

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Install Python dependencies
echo ""
echo "📦 Installing Python dependencies..."
pip install --upgrade pip -q
pip install -q numpy pandas scikit-learn psutil rich click requests
echo "✅ Python dependencies installed"

# Check for BCC tools
echo ""
echo "🔍 Checking for BCC tools (eBPF support)..."
if command -v python3-bpfcc >/dev/null 2>&1; then
    echo "✅ BCC tools already installed"
else
    echo "⚠️  BCC tools not found. Installing..."
    sudo apt-get update -qq
    sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) 2>&1 | grep -E "(Setting up|Unpacking|done)" || true
    echo "✅ BCC tools installed"
fi

# Train models
echo ""
echo "🧠 Training anomaly detection models..."
echo "========================================="
echo "This will collect REAL syscall data for 60 seconds"
echo ""
echo "💡 TIP: Open another terminal and generate activity:"
echo "   ls -R /"
echo "   ps aux"
echo "   cat /etc/passwd"
echo "   find /usr -name '*.py' | head -20"
echo ""
echo "Starting training in 3 seconds..."
sleep 3

# Train models
sudo -E env PATH=$PATH python3 core/enhanced_security_agent.py --train-models

# Verify models
echo ""
echo "🔍 Verifying trained models..."
if [ -d ~/.cache/security_agent ]; then
    echo ""
    echo "✅ Models saved to ~/.cache/security_agent/:"
    ls -lh ~/.cache/security_agent/ | grep -E '\.pkl|\.npy|\.json' || true
    echo ""
    echo "🎉 Training complete!"
    echo ""
    echo "You can now run the agent:"
    echo "  sudo python3 core/enhanced_security_agent.py --dashboard"
else
    echo "⚠️  Model directory not found"
fi

