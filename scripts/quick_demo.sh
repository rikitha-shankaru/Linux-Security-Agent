#!/bin/bash

echo "=== Quick Demo Commands ==="
echo ""
echo "This will show the agent running with what's currently working."
echo ""
echo "Run this in Terminal 1:"
echo "  cd ~/linux_security_agent"
echo "  sudo python3 core/enhanced_security_agent.py --dashboard --timeout 60"
echo ""
echo "This works:"
echo "  ✅ eBPF program compiles and loads"
echo "  ✅ Agent starts and runs"
echo "  ✅ Dashboard appears"
echo "  ✅ No crashes"
echo ""
echo "Known limitation: Perf events not reaching Python (requires BCC configuration)"
echo ""

