#!/bin/bash
# Quick setup script for auditd collector

echo "🔧 Setting up auditd collector..."
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run with sudo"
    exit 1
fi

# Install auditd
echo "📦 Installing auditd..."
apt-get update -qq
apt-get install -y auditd > /dev/null 2>&1

# Start auditd service
echo "🚀 Starting auditd service..."
systemctl start auditd
systemctl enable auditd > /dev/null 2>&1

# Configure auditd to capture all syscalls
echo "⚙️  Configuring auditd to capture all syscalls..."
auditctl -a always,exit -S all > /dev/null 2>&1

# Verify auditd is running
if systemctl is-active --quiet auditd; then
    echo "✅ Auditd is running"
else
    echo "❌ Auditd failed to start"
    exit 1
fi

# Check if audit log exists
if [ -f /var/log/audit/audit.log ]; then
    echo "✅ Audit log file exists"
else
    echo "⚠️  Audit log file not found (may be created on first event)"
fi

# Show current audit rules
echo ""
echo "📋 Current audit rules:"
auditctl -l

echo ""
echo "✅ Setup complete!"
echo ""
echo "Now run:"
echo "  sudo python3 core/enhanced_security_agent.py --collector auditd --train-models --dashboard --threshold 30"
echo ""

