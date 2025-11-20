#!/bin/bash
# Test script for Linux VM - Sets up auditd and runs security agent

echo "🚀 Testing Security Agent on Linux VM with Auditd"
echo "=================================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run with sudo"
    exit 1
fi

# Step 1: Update and install auditd
echo "📦 Step 1: Installing auditd..."
apt-get update -qq > /dev/null 2>&1
if ! command -v auditd &> /dev/null; then
    apt-get install -y auditd > /dev/null 2>&1
    echo "✅ Auditd installed"
else
    echo "✅ Auditd already installed"
fi

# Step 2: Start auditd service
echo ""
echo "🚀 Step 2: Starting auditd service..."
systemctl start auditd 2>/dev/null
systemctl enable auditd > /dev/null 2>&1

if systemctl is-active --quiet auditd; then
    echo "✅ Auditd is running"
else
    echo "❌ Failed to start auditd"
    exit 1
fi

# Step 3: Configure auditd rules
echo ""
echo "⚙️  Step 3: Configuring auditd to capture all syscalls..."
auditctl -a always,exit -S all > /dev/null 2>&1

# Verify rules
echo "📋 Current audit rules:"
auditctl -l

# Step 4: Check audit log
echo ""
echo "📁 Step 4: Checking audit log..."
if [ -f /var/log/audit/audit.log ]; then
    echo "✅ Audit log exists: /var/log/audit/audit.log"
    echo "   Size: $(du -h /var/log/audit/audit.log | cut -f1)"
else
    echo "⚠️  Audit log not found (will be created on first event)"
    mkdir -p /var/log/audit
    touch /var/log/audit/audit.log
    chmod 600 /var/log/audit/audit.log
fi

# Step 5: Test auditd is capturing
echo ""
echo "🧪 Step 5: Testing auditd capture..."
echo "   Generating test activity..."
ls -R /home > /dev/null 2>&1 &
ps aux > /dev/null 2>&1 &
sleep 2

# Check if events were logged
if [ -f /var/log/audit/audit.log ]; then
    EVENT_COUNT=$(grep -c "type=SYSCALL" /var/log/audit/audit.log 2>/dev/null || echo "0")
    if [ "$EVENT_COUNT" -gt "0" ]; then
        echo "✅ Auditd is capturing events! ($EVENT_COUNT syscall events found)"
    else
        echo "⚠️  No events yet (may need more activity)"
    fi
fi

# Step 6: Run security agent
echo ""
echo "=================================================="
echo "🎯 Step 6: Starting Security Agent with Auditd"
echo "=================================================="
echo ""
echo "💡 TIP: Open another terminal and generate activity:"
echo "   while true; do ls -R /home > /dev/null 2>&1; ps aux > /dev/null 2>&1; sleep 0.5; done"
echo ""
echo "Starting agent in 3 seconds..."
sleep 3

# Change to project directory
cd ~/linux_security_agent 2>/dev/null || cd /home/agent/linux_security_agent 2>/dev/null || {
    echo "❌ Cannot find project directory"
    exit 1
}

# Run the agent
python3 core/enhanced_security_agent.py --collector auditd --train-models --dashboard --threshold 30

