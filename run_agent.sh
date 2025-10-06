#!/bin/bash
# Linux Security Agent - Local Run Script

echo "🛡️  Starting Linux Security Agent (macOS version)"
echo "================================================"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup first."
    echo "   Run: python3 setup_macos.py"
    exit 1
fi

# Check if security_agent_mac.py exists
if [ ! -f "security_agent_mac.py" ]; then
    echo "❌ security_agent_mac.py not found."
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Check if .local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "⚠️  Adding ~/.local/bin to PATH for this session"
    export PATH="$HOME/.local/bin:$PATH"
fi

echo "Starting security agent with timeout (30 seconds)..."
echo "Press Ctrl+C to stop early"
echo ""

# Run the security agent with timeout
python3 security_agent_mac.py --dashboard --threshold 30 --timeout 30
