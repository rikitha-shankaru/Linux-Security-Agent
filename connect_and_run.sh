#!/bin/bash
# Quick connect and run script for UTM VM

VM_USER="agent"
VM_HOST="192.168.64.4"
VM_SSH="${VM_USER}@${VM_HOST}"

echo "🔌 Connecting to UTM VM and running security agent..."
echo ""

# Check if we should just connect or run the agent
if [ "$1" == "run" ]; then
    echo "🚀 Running security agent on VM..."
    ssh -t ${VM_SSH} << 'ENDSSH'
        cd ~/linux_security_agent
        if [ ! -d "~/linux_security_agent" ]; then
            echo "❌ Project directory not found!"
            echo "Please run setup_utm_vm.sh first"
            exit 1
        fi
        
        echo "Starting security agent..."
        sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30
ENDSSH
else
    echo "📡 Connecting to VM..."
    echo "Once connected, run:"
    echo "  cd ~/linux_security_agent"
    echo "  sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30"
    echo ""
    ssh ${VM_SSH}
fi

