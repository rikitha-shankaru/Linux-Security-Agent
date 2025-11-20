#!/bin/bash
# Run security agent on UTM VM

VM_USER="agent"
VM_HOST="192.168.64.4"
VM_SSH="${VM_USER}@${VM_HOST}"
VM_PASS="rrot"

# Check if sshpass is available
if command -v sshpass &> /dev/null; then
    SSH_CMD="sshpass -p '${VM_PASS}' ssh -o StrictHostKeyChecking=no -t"
else
    SSH_CMD="ssh -o StrictHostKeyChecking=no -t"
fi

echo "🚀 Running Linux Security Agent on VM..."
echo ""

# Check if training is requested
if [ "$1" == "train" ]; then
    echo "🧠 Training models first..."
    ${SSH_CMD} ${VM_SSH} << 'ENDSSH'
        cd ~/linux_security_agent
        echo "Training models (this will take ~60 seconds)..."
        echo "💡 TIP: Open another terminal and generate activity for better training data"
        sudo python3 core/enhanced_security_agent.py --train-models
ENDSSH
    echo ""
    echo "✅ Training complete!"
    echo ""
fi

echo "Starting security agent..."
${SSH_CMD} ${VM_SSH} << 'ENDSSH'
    cd ~/linux_security_agent
    
    if [ ! -f "core/enhanced_security_agent.py" ]; then
        echo "❌ Agent not found! Please run deploy_to_vm.sh first"
        exit 1
    fi
    
    echo "🚀 Starting security agent with dashboard..."
    echo "   Press Ctrl+C to stop"
    echo ""
    
    sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30
ENDSSH

