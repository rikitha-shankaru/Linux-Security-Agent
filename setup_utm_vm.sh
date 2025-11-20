#!/bin/bash
# Setup script for UTM Linux VM
# Connects to VM and sets up the Linux Security Agent

VM_USER="agent"
VM_HOST="192.168.64.4"
VM_SSH="${VM_USER}@${VM_HOST}"

echo "🚀 Setting up Linux Security Agent on UTM VM"
echo "=============================================="
echo ""

# Test SSH connection
echo "📡 Testing SSH connection to ${VM_SSH}..."
if ssh -o ConnectTimeout=5 -o BatchMode=yes ${VM_SSH} "echo 'Connection successful'" 2>/dev/null; then
    echo "✅ SSH connection successful!"
else
    echo "❌ SSH connection failed!"
    echo ""
    echo "Please ensure:"
    echo "  1. VM is running"
    echo "  2. SSH is enabled on the VM"
    echo "  3. You have SSH keys set up (or use password authentication)"
    echo ""
    echo "To connect manually:"
    echo "  ssh ${VM_SSH}"
    echo ""
    read -p "Press Enter to continue anyway or Ctrl+C to exit..."
fi

echo ""
echo "📦 Step 1: Installing system dependencies on VM..."
ssh ${VM_SSH} << 'ENDSSH'
    echo "Updating package list..."
    sudo apt-get update -qq
    
    echo "Installing Python and build tools..."
    sudo apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-dev \
        build-essential \
        git \
        curl
    
    echo "Installing BCC tools for eBPF..."
    sudo apt-get install -y -qq \
        bpfcc-tools \
        python3-bpfcc \
        linux-headers-$(uname -r) || \
    echo "⚠️  BCC installation may have failed - will try alternative method"
    
    echo "✅ System dependencies installed"
ENDSSH

echo ""
echo "📂 Step 2: Setting up project directory on VM..."
ssh ${VM_SSH} << 'ENDSSH'
    # Create project directory
    mkdir -p ~/linux_security_agent
    cd ~/linux_security_agent
    
    # Check if git repo exists
    if [ -d .git ]; then
        echo "Git repository found, pulling latest changes..."
        git pull
    else
        echo "No git repository found - will need to copy files"
    fi
    
    echo "✅ Project directory ready"
ENDSSH

echo ""
echo "📤 Step 3: Copying project files to VM..."
# Use rsync if available, otherwise scp
if command -v rsync &> /dev/null; then
    echo "Using rsync for efficient file transfer..."
    rsync -avz --exclude 'venv*' --exclude '__pycache__' --exclude '*.pyc' \
        --exclude '.git' --exclude '*.log' \
        ./ ${VM_SSH}:~/linux_security_agent/
else
    echo "Using scp for file transfer..."
    scp -r \
        --exclude='venv*' --exclude='__pycache__' --exclude='*.pyc' \
        ./ ${VM_SSH}:~/linux_security_agent/
fi

echo ""
echo "📥 Step 4: Installing Python dependencies on VM..."
ssh ${VM_SSH} << 'ENDSSH'
    cd ~/linux_security_agent
    
    echo "Installing Python packages..."
    pip3 install --user -q -r requirements.txt || {
        echo "⚠️  Some packages may have failed - checking..."
        pip3 install --user -q psutil scikit-learn numpy pandas colorama rich click requests || true
    }
    
    echo "✅ Python dependencies installed"
ENDSSH

echo ""
echo "✅ Step 5: Verifying installation..."
ssh ${VM_SSH} << 'ENDSSH'
    cd ~/linux_security_agent
    
    echo "Testing Python imports..."
    python3 -c "
import sys
try:
    from bcc import BPF
    print('✅ BCC/eBPF available')
except ImportError:
    print('⚠️  BCC not available - will use auditd fallback')

try:
    import psutil
    print('✅ psutil available')
except ImportError:
    print('❌ psutil not available')

try:
    import sklearn
    print('✅ scikit-learn available')
except ImportError:
    print('⚠️  scikit-learn not available - ML features limited')
"
    
    echo ""
    echo "Testing agent import..."
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from core.enhanced_security_agent import EnhancedSecurityAgent
    print('✅ Security agent module loads successfully')
except Exception as e:
    print(f'❌ Error loading agent: {e}')
"
ENDSSH

echo ""
echo "🎉 Setup complete!"
echo ""
echo "To run the agent on the VM:"
echo "  ssh ${VM_SSH}"
echo "  cd ~/linux_security_agent"
echo "  sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30"
echo ""
echo "Or use the quick connect script:"
echo "  ./connect_and_run.sh"

