#!/bin/bash

echo "=== Testing Linux Security Agent ==="
echo

# Check Python
echo "1. Checking Python..."
python3 --version || exit 1
echo "   ✅ Python OK"
echo

# Check dependencies
echo "2. Checking Python dependencies..."
python3 -c "import psutil; print('   ✅ psutil')" 2>/dev/null || echo "   ⚠️  psutil missing"
python3 -c "import docker; print('   ✅ docker')" 2>/dev/null || echo "   ⚠️  docker missing"
python3 -c "import rich; print('   ✅ rich')" 2>/dev/null || echo "   ⚠️  rich missing"
python3 -c "import numpy; print('   ✅ numpy')" 2>/dev/null || echo "   ⚠️  numpy missing"
python3 -c "import sklearn; print('   ✅ sklearn')" 2>/dev/null || echo "   ⚠️  sklearn missing"
echo

# Check eBPF
echo "3. Checking eBPF monitor..."
python3 -c "from core.enhanced_ebpf_monitor import StatefulEBPFMonitor; print('   ✅ eBPF monitor imports')" 2>/dev/null || echo "   ⚠️  eBPF monitor import failed"
echo

# Check other modules
echo "4. Checking other modules..."
python3 -c "from core.enhanced_security_agent import EnhancedSecurityAgent; print('   ✅ Security agent imports')" 2>/dev/null || echo "   ⚠️  Security agent import failed"
python3 -c "from core.enhanced_anomaly_detector import EnhancedAnomalyDetector; print('   ✅ Anomaly detector imports')" 2>/dev/null || echo "   ⚠️  Anomaly detector import failed"
echo

# Quick functionality test (needs sudo)
echo "5. Quick functionality test (requires sudo)..."
echo "   Running: sudo timeout 5 python3 core/enhanced_security_agent.py --dashboard --timeout 5"
sudo timeout 5 python3 core/enhanced_security_agent.py --dashboard --timeout 5 2>&1 | grep -q "Security Dashboard" && echo "   ✅ Agent runs successfully" || echo "   ⚠️  Agent test had issues (this is OK if just timeout)"
echo

echo "=== Quick Test Complete ==="
echo
echo "If all checks pass, you can run:"
echo "  sudo python3 tests/test_ebpf.py        # Test eBPF functionality"
echo "  sudo python3 tests/run_tests.py         # Run all tests"

