#!/bin/bash
# Deploy and setup Linux Security Agent on UTM VM
# Handles password authentication

VM_USER="agent"
VM_HOST="192.168.64.4"
VM_SSH="${VM_USER}@${VM_HOST}"
VM_PASS="rrot"

echo "🚀 Deploying Linux Security Agent to UTM VM"
echo "============================================"
echo ""

# Check if sshpass is available
if command -v sshpass &> /dev/null; then
    SSH_CMD="sshpass -p '${VM_PASS}' ssh -o StrictHostKeyChecking=no"
    SCP_CMD="sshpass -p '${VM_PASS}' scp -o StrictHostKeyChecking=no"
    RSYNC_CMD="sshpass -p '${VM_PASS}' rsync"
    echo "✅ Using sshpass for password authentication"
else
    echo "⚠️  sshpass not found - will prompt for password"
    echo "   Install with: brew install hudochenkov/sshpass/sshpass (on Mac)"
    SSH_CMD="ssh -o StrictHostKeyChecking=no"
    SCP_CMD="scp -o StrictHostKeyChecking=no"
    RSYNC_CMD="rsync"
fi

echo ""
echo "📡 Step 1: Testing SSH connection..."
${SSH_CMD} ${VM_SSH} "echo '✅ Connection successful'" || {
    echo "❌ Connection failed!"
    exit 1
}

echo ""
echo "📦 Step 2: Installing system dependencies..."
${SSH_CMD} ${VM_SSH} << 'ENDSSH'
    echo "Updating package list..."
    sudo apt-get update -qq
    
    echo "Installing Python and build tools..."
    sudo apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-dev \
        build-essential \
        git \
        curl \
        openssh-server
    
    echo "Installing BCC tools for eBPF..."
    sudo apt-get install -y -qq \
        bpfcc-tools \
        python3-bpfcc \
        linux-headers-$(uname -r) 2>&1 | grep -v "^$" || echo "⚠️  BCC install may need attention"
    
    echo "✅ System dependencies installed"
ENDSSH

echo ""
echo "📂 Step 3: Setting up project directory..."
${SSH_CMD} ${VM_SSH} << 'ENDSSH'
    mkdir -p ~/linux_security_agent
    cd ~/linux_security_agent
    echo "✅ Project directory ready at ~/linux_security_agent"
ENDSSH

echo ""
echo "📤 Step 4: Copying project files to VM..."
# Use rsync if available, otherwise scp
if command -v rsync &> /dev/null; then
    echo "Using rsync for efficient transfer..."
    ${RSYNC_CMD} -avz --exclude 'venv*' --exclude '__pycache__' --exclude '*.pyc' \
        --exclude '.git' --exclude '*.log' --exclude '.DS_Store' \
        ./ ${VM_SSH}:~/linux_security_agent/ || {
        echo "⚠️  rsync failed, trying scp..."
        ${SCP_CMD} -r ./ ${VM_SSH}:~/linux_security_agent/
    }
else
    echo "Using scp for transfer..."
    ${SCP_CMD} -r ./ ${VM_SSH}:~/linux_security_agent/
fi

echo ""
echo "📥 Step 5: Installing Python dependencies..."
${SSH_CMD} ${VM_SSH} << 'ENDSSH'
    cd ~/linux_security_agent
    
    echo "Installing Python packages..."
    pip3 install --user -q -r requirements.txt 2>&1 | tail -5 || {
        echo "Installing packages individually..."
        pip3 install --user -q psutil scikit-learn numpy pandas colorama rich click requests
    }
    
    echo "✅ Python dependencies installed"
ENDSSH

echo ""
echo "✅ Step 6: Verifying installation..."
${SSH_CMD} ${VM_SSH} << 'ENDSSH'
    cd ~/linux_security_agent
    
    echo "Testing imports..."
    python3 -c "
import sys
sys.path.insert(0, '.')
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
    print('⚠️  scikit-learn not available')
"
    
    echo ""
    echo "Testing agent module..."
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from core.enhanced_security_agent import EnhancedSecurityAgent
    print('✅ Security agent module loads successfully')
except Exception as e:
    print(f'❌ Error: {e}')
"
ENDSSH

echo ""
echo "🎉 Deployment complete!"
echo ""
echo "To run the agent, use:"
echo "  ./run_on_vm.sh"
echo ""
echo "Or connect manually:"
echo "  ssh ${VM_SSH}"
echo "  cd ~/linux_security_agent"
echo "  sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30"

