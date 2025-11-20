#!/bin/bash
# Commands to run in your Linux VM after git pull

echo "🚀 Setting up and training on Linux VM"
echo "======================================"
echo ""

# 1. Pull latest changes
echo "📥 Pulling latest changes from git..."
git pull origin main
echo "✅ Git pull complete"
echo ""

# 2. Navigate to project
cd ~/linux_security_agent

# 3. Create virtual environment if needed
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment exists"
fi

# 4. Activate virtual environment
echo ""
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# 5. Install/upgrade Python dependencies
echo ""
echo "📦 Installing Python dependencies..."
pip install --upgrade pip -q
pip install -q numpy pandas scikit-learn psutil rich click requests
echo "✅ Python dependencies installed"

# 6. Check for BCC tools
echo ""
echo "🔍 Checking for BCC tools (eBPF support)..."
if command -v python3-bpfcc >/dev/null 2>&1; then
    echo "✅ BCC tools already installed"
else
    echo "⚠️  Installing BCC tools..."
    sudo apt-get update -qq
    sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) 2>&1 | tail -3
    echo "✅ BCC tools installed"
fi

# 7. Train models
echo ""
echo "🧠 Training anomaly detection models..."
echo "========================================="
echo "This will collect REAL syscall data for 60 seconds"
echo ""
echo "💡 TIP: Open another terminal and generate activity:"
echo "   ls -R /"
echo "   ps aux"
echo "   cat /etc/passwd"
echo ""
echo "Starting training in 3 seconds..."
sleep 3

# Train models with real syscall data
sudo -E env PATH=$PATH python3 core/enhanced_security_agent.py --train-models

# Verify models
echo ""
echo "🔍 Verifying trained models..."
if [ -d ~/.cache/security_agent ]; then
    echo ""
    echo "✅ Models saved to ~/.cache/security_agent/:"
    ls -lh ~/.cache/security_agent/ | grep -E '\.pkl|\.npy|\.json'
    echo ""
    echo "🎉 Training complete!"
    echo ""
    echo "You can now run the agent:"
    echo "  sudo python3 core/enhanced_security_agent.py --dashboard"
else
    echo "⚠️  Model directory not found"
fi

