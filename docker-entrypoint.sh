#!/bin/bash
# Docker entrypoint script for security agent with auditd

set -e

echo "🐳 Starting Security Agent in Docker container..."
echo ""

# Start auditd service (if not already running)
if [ ! -f /var/run/auditd.pid ]; then
    echo "🚀 Starting auditd service..."
    # Start auditd in foreground mode for container
    auditd -f &
    sleep 2
fi

# Configure auditd to capture all syscalls
echo "⚙️  Configuring auditd rules..."
auditctl -a always,exit -S all 2>/dev/null || echo "⚠️  Could not set audit rules (may need host auditd)"

# Verify auditd is working
if [ -f /var/log/audit/audit.log ]; then
    echo "✅ Audit log file exists"
else
    echo "⚠️  Creating audit log directory..."
    mkdir -p /var/log/audit
    touch /var/log/audit/audit.log
    chmod 600 /var/log/audit/audit.log
fi

# Show audit rules
echo ""
echo "📋 Current audit rules:"
auditctl -l 2>/dev/null || echo "⚠️  Cannot show rules (may need host auditd)"

echo ""
echo "✅ Starting security agent..."
echo ""

# Run the security agent with provided arguments
exec python3 core/enhanced_security_agent.py "$@"

