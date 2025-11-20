#!/bin/bash
# Quick script to run agent on VM after training

echo "🚀 Starting security agent on VM..."
echo ""
echo "This will connect to your VM and start the dashboard."
echo ""

VM_USER="agent"
VM_HOST="192.168.64.4"
VM_PASS="rrot"

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    echo "❌ sshpass not found. Install it with:"
    echo "   brew install hudochenkov/sshpass/sshpass"
    exit 1
fi

echo "📡 Connecting to VM and starting agent..."
echo ""

# Run agent with dashboard
sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no "$VM_USER@$VM_HOST" << 'ENDSSH'
cd ~/linux_security_agent
echo "✅ Starting security agent dashboard..."
echo ""
echo "💡 TIP: Open another terminal and generate activity:"
echo "   while true; do ls -R /home > /dev/null 2>&1; ps aux > /dev/null 2>&1; sleep 0.5; done"
echo ""
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30
ENDSSH

