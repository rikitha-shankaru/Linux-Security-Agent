#!/bin/bash
# Comprehensive Agent Test - Run on VM
# This script will test the agent with all attack types

set -e

echo "=========================================="
echo "🛡️  COMPREHENSIVE AGENT TEST"
echo "=========================================="
echo ""

# Change to project directory
cd ~/Linux-Security-Agent

# Pull latest code
echo "📥 Pulling latest code..."
git pull origin main || echo "⚠️  Git pull failed (may already be up to date)"

# Kill any existing agents
echo "🧹 Cleaning up existing agents..."
sudo pkill -9 -f 'simple_agent.py' 2>/dev/null || true
sleep 2

# Check if log directory exists
mkdir -p logs

# Run comprehensive test
echo ""
echo "🚀 Starting comprehensive test..."
echo "This will:"
echo "  1. Start the agent"
echo "  2. Run all 6 attack types"
echo "  3. Monitor for detections"
echo "  4. Generate test report"
echo ""
echo "Press Ctrl+C to stop early"
echo ""

sudo python3 scripts/comprehensive_agent_test.py

echo ""
echo "=========================================="
echo "✅ Test Complete!"
echo "=========================================="
echo ""
echo "📊 View results:"
echo "  - Test report: comprehensive_test_results.json"
echo "  - Log file: logs/security_agent.log"
echo ""
echo "📝 View recent detections:"
echo "  grep 'HIGH RISK DETECTED' logs/security_agent.log | tail -10"
echo "  grep 'ANOMALY DETECTED' logs/security_agent.log | tail -10"
echo "  grep 'CONNECTION PATTERN' logs/security_agent.log | tail -10"
echo ""

