#!/bin/bash
# Debug script - checks what's wrong

echo "🔍 Debugging Security Agent Setup"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Not running as root (use sudo)"
else
    echo "✅ Running as root"
fi

echo ""
echo "📦 Checking dependencies..."

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "✅ Python3: $PYTHON_VERSION"
else
    echo "❌ Python3 not found"
fi

# Check auditd
if command -v auditd &> /dev/null; then
    echo "✅ Auditd installed"
else
    echo "❌ Auditd not installed"
fi

# Check auditd service
echo ""
echo "🔧 Checking auditd service..."
if systemctl is-active --quiet auditd 2>/dev/null; then
    echo "✅ Auditd service is running"
else
    echo "❌ Auditd service is NOT running"
    echo "   Try: sudo systemctl start auditd"
fi

# Check audit rules
echo ""
echo "📋 Checking audit rules..."
RULES=$(auditctl -l 2>/dev/null)
if [ -n "$RULES" ]; then
    echo "✅ Audit rules configured:"
    echo "$RULES" | head -5
else
    echo "❌ No audit rules configured"
    echo "   Try: sudo auditctl -a always,exit -S all"
fi

# Check audit log
echo ""
echo "📁 Checking audit log..."
if [ -f /var/log/audit/audit.log ]; then
    LOG_SIZE=$(du -h /var/log/audit/audit.log | cut -f1)
    EVENT_COUNT=$(grep -c "type=SYSCALL" /var/log/audit/audit.log 2>/dev/null || echo "0")
    echo "✅ Audit log exists: $LOG_SIZE"
    echo "   Events: $EVENT_COUNT syscall events"
    
    if [ "$EVENT_COUNT" -eq "0" ]; then
        echo "   ⚠️  No events yet - generate some activity"
    fi
else
    echo "❌ Audit log not found: /var/log/audit/audit.log"
    echo "   Try: sudo mkdir -p /var/log/audit && sudo touch /var/log/audit/audit.log"
fi

# Check project directory
echo ""
echo "📂 Checking project..."
if [ -d ~/linux_security_agent ]; then
    echo "✅ Project directory exists: ~/linux_security_agent"
    cd ~/linux_security_agent
    
    if [ -f "core/enhanced_security_agent.py" ]; then
        echo "✅ Main script exists"
    else
        echo "❌ Main script not found"
    fi
    
    if [ -f "core/collector_auditd.py" ]; then
        echo "✅ Auditd collector exists"
    else
        echo "❌ Auditd collector not found"
    fi
else
    echo "❌ Project directory not found: ~/linux_security_agent"
fi

# Check Python dependencies
echo ""
echo "🐍 Checking Python dependencies..."
cd ~/linux_security_agent 2>/dev/null || exit 1

python3 -c "import psutil" 2>/dev/null && echo "✅ psutil installed" || echo "❌ psutil missing"
python3 -c "import sklearn" 2>/dev/null && echo "✅ scikit-learn installed" || echo "❌ scikit-learn missing"
python3 -c "import pandas" 2>/dev/null && echo "✅ pandas installed" || echo "❌ pandas missing"
python3 -c "from rich.console import Console" 2>/dev/null && echo "✅ rich installed" || echo "❌ rich missing"

# Test import
echo ""
echo "🧪 Testing imports..."
python3 -c "
try:
    from core.collector_auditd import AuditdCollector
    print('✅ AuditdCollector imports successfully')
except Exception as e:
    print(f'❌ AuditdCollector import failed: {e}')

try:
    from core.enhanced_security_agent import EnhancedSecurityAgent
    print('✅ EnhancedSecurityAgent imports successfully')
except Exception as e:
    print(f'❌ EnhancedSecurityAgent import failed: {e}')
" 2>&1

echo ""
echo "=================================="
echo "🔍 Debug complete!"
echo ""
echo "If you see errors above, fix them first."
echo "Then try running the agent again."

