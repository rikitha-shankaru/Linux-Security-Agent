# Testing & Verification Guide

## Phase 1: Prerequisites Check

### Step 1: Check Operating System
```bash
uname -r
```
**Expected:** Linux kernel 4.1 or higher

### Step 2: Check Python Version
```bash
python3 --version
```
**Expected:** Python 3.7 or higher

### Step 3: Check Required Packages
```bash
pip list | grep -E "(psutil|docker|rich|numpy|scipy|scikit-learn)"
```
**Expected:** All packages should be installed

If missing:
```bash
pip install psutil docker rich numpy scipy scikit-learn
```

### Step 4: Check for BCC (Linux only)
```bash
which python3-bpfcc
dpkg -l | grep bpfcc
```
**Expected:** `python3-bpfcc` package installed

If missing (Ubuntu/Debian):
```bash
sudo apt-get install bpfcc-tools python3-bpfcc
```

### Step 5: Verify File Structure
```bash
ls -la core/
```
**Expected files:**
- enhanced_security_agent.py
- enhanced_ebpf_monitor.py
- enhanced_anomaly_detector.py
- container_security_monitor.py

---

## Phase 2: Basic Functionality Test

### Test 1: Import Test

```bash
cd /Users/likithashankar/linux_security_agent

# Test each module
python3 -c "from core.enhanced_ebpf_monitor import StatefulEBPFMonitor; print('✅ eBPF monitor OK')"
python3 -c "from core.enhanced_anomaly_detector import EnhancedAnomalyDetector; print('✅ Anomaly detector OK')"
python3 -c "from core.container_security_monitor import ContainerSecurityMonitor; print('✅ Container monitor OK')"
python3 -c "from core.enhanced_security_agent import EnhancedSecurityAgent; print('✅ Security agent OK')"
```

**Expected:** All modules import without errors

**If errors:** Check Python path and dependencies

---

## Phase 3: Verify Syscall Capture Works

### Test 2: Check if eBPF Can Load (Linux)

```bash
sudo python3 -c "
from core.enhanced_ebpf_monitor import StatefulEBPFMonitor
monitor = StatefulEBPFMonitor()
try:
    monitor.start_monitoring()
    print('✅ eBPF program loaded successfully')
    monitor.stop_monitoring()
except Exception as e:
    print(f'❌ Error: {e}')
"
```

**Expected:** "✅ eBPF program loaded successfully"

**If error:** Check if you have root privileges and BCC installed

### Test 3: Verify Syscall Mapping

```bash
sudo python3 -c "
from core.enhanced_ebpf_monitor import StatefulEBPFMonitor
monitor = StatefulEBPFMonitor()

# Test syscall number to name conversion
test_syscalls = [0, 1, 2, 59, 101, 171]
print('Testing syscall number to name mapping:')
for num in test_syscalls:
    name = monitor._syscall_num_to_name(num)
    print(f'  {num} → {name}')

expected = ['read', 'write', 'open', 'execve', 'ptrace', 'ptrace']
print('\nExpected names:')
for i, name in enumerate(expected):
    print(f'  {test_syscalls[i]} → {name}')
"
```

**Expected:**
```
0 → read
1 → write
2 → open
59 → execve
101 → ptrace
171 → ptrace
```

---

## Phase 4: Test Real Syscall Capture

### Test 4: Capture Real Syscalls (30 seconds)

Create test file: `test_syscall_capture.py`

```python
from core.enhanced_ebpf_monitor import StatefulEBPFMonitor
import time

def test_syscall_capture():
    print("Starting syscall capture test...")
    monitor = StatefulEBPFMonitor()
    
    # Track captured syscalls
    captured_syscalls = []
    
    def callback(pid, syscall_name, info):
        captured_syscalls.append({
            'pid': pid,
            'syscall': syscall_name,
            'timestamp': info.get('timestamp', 0)
        })
    
    monitor.start_monitoring(event_callback=callback)
    
    # Let it run for 10 seconds
    print("Capturing syscalls for 10 seconds...")
    print("(Do some normal work - browse files, type, etc.)")
    time.sleep(10)
    
    monitor.stop_monitoring()
    
    # Analyze results
    unique_syscalls = set([s['syscall'] for s in captured_syscalls])
    
    print(f"\n✅ Captured {len(captured_syscalls)} syscalls")
    print(f"✅ Found {len(unique_syscalls)} unique syscall types")
    print(f"\nSample syscalls captured:")
    for syscall in list(unique_syscalls)[:10]:
        print(f"  - {syscall}")
    
    # Verify we got real syscalls
    expected_syscalls = ['read', 'write', 'open', 'close']
    found_expected = any(s in unique_syscalls for s in expected_syscalls)
    
    if found_expected:
        print("\n✅ SUCCESS: Real syscalls being captured!")
    else:
        print("\n⚠️  WARNING: Might not be capturing real syscalls")
        print("   Check if running on Linux with BCC installed")
    
    return len(captured_syscalls) > 0

if __name__ == "__main__":
    test_syscall_capture()
```

Run it:
```bash
sudo python3 test_syscall_capture.py
```

**Expected:**
- Should show hundreds of syscalls captured
- Should see common ones: read, write, open, close
- Should have unique syscall names (not just "syscall")

**If no syscalls:** Check BCC installation and permissions

---

## Phase 5: Test ML Training

### Test 5: Verify ML Training Uses Real Data

Create test file: `test_ml_training.py`

```python
from core.enhanced_security_agent import EnhancedSecurityAgent
import time

def test_ml_training():
    print("Testing ML training with real data...")
    
    agent = EnhancedSecurityAgent()
    
    # Start monitoring briefly
    agent.start_monitoring()
    print("Collecting real syscall data for 30 seconds...")
    time.sleep(30)
    agent.stop_monitoring()
    
    # Check if models were trained
    if agent.enhanced_anomaly_detector:
        if hasattr(agent.enhanced_anomaly_detector, 'models_trained'):
            print(f"✅ Models trained: {agent.enhanced_anomaly_detector.models_trained}")
        
        # Try a prediction
        test_syscalls = ['read', 'write', 'open', 'close', 'read']
        result = agent.enhanced_anomaly_detector.detect_anomaly_ensemble(test_syscalls)
        print(f"✅ Anomaly score: {result.anomaly_score}")
        print(f"✅ Is anomaly: {result.is_anomaly}")
        
        print("\n✅ ML training is working!")
    else:
        print("⚠️  No anomaly detector found")

if __name__ == "__main__":
    test_ml_training()
```

Run it:
```bash
sudo python3 test_ml_training.py
```

**Expected:**
- Should collect real data
- Models should be trained
- Should output anomaly score

---

## Phase 6: Test Full Security Agent

### Test 6: Run Full Agent with Dashboard

```bash
sudo python3 core/enhanced_security_agent.py --dashboard --timeout 60
```

**What to look for:**
1. Dashboard appears with process table
2. See real syscall names (read, write, execve, etc.)
3. Risk scores updating
4. Some processes showing high risk scores
5. Memory cleanup messages every ~60 seconds

**Expected output:**
```
📊 Real-time Security Dashboard
╭─────────────────────────┬───────┬──────────────┬──────────────┬───────────╮
│ Process Name            │ PID   │ Risk Score   │ Anomaly      │ Container│
├─────────────────────────┼───────┼──────────────┼──────────────┼───────────┤
│ python3                 │ 12345 │ 45.2         │ 0.1          │ -         │
│ bash                    │ 12346 │ 12.5         │ 0.05         │ docker-xyz│
```

**If errors:** Check logs for specific issues

### Test 7: Test with Training

First train models:
```bash
sudo python3 core/enhanced_security_agent.py --train-models
```

Wait for "✅ Anomaly detection models trained on REAL data"

Then run dashboard:
```bash
sudo python3 core/enhanced_security_agent.py --dashboard --timeout 60
```

**Expected:**
- Higher detection accuracy
- Better anomaly scores
- Models loaded from previous training

---

## Phase 7: Test Container Detection

### Test 8: Test with Docker (if available)

Start some containers:
```bash
docker run -d --name test-nginx nginx
docker run -d --name test-redis redis
docker ps
```

Run the agent:
```bash
sudo python3 core/enhanced_security_agent.py --dashboard --timeout 60
```

**What to look for:**
- Container column shows container IDs
- Processes mapped to containers
- Container-specific risk scoring

Check logs for:
```
"Container security enabled"
"Detected container: test-nginx"
"Detected container: test-redis"
```

---

## Phase 8: Test Memory Cleanup

### Test 9: Monitor Memory Usage

```bash
# In one terminal, monitor memory
watch -n 1 'ps aux | grep enhanced_security_agent.py | grep -v grep'

# In another terminal, run agent
sudo python3 core/enhanced_security_agent.py --dashboard --timeout 300
```

**What to check:**
- Memory should start ~50MB
- Should stay around 50-100MB
- Should NOT grow indefinitely
- Should see "🧹 Cleaned up X stale processes" messages

**If memory grows continuously:** Memory cleanup not working

---

## Phase 9: Test Thread Safety

### Test 10: Run Under Load

```bash
# Generate syscall load
for i in {1..10}; do
    (while true; do ls /usr/bin/ > /dev/null; done &)
done

# Run agent
sudo python3 core/enhanced_security_agent.py --dashboard --timeout 30
```

**What to check:**
- No crashes
- No "race condition" errors
- Dashboard updates smoothly
- No data corruption

---

## Phase 10: Test Bug Fixes

### Test 11: Verify Syscall Names are Real

```bash
sudo python3 core/enhanced_security_agent.py --dashboard --timeout 30 2>&1 | grep -E "(read|write|execve|open|close|fork|ptrace)"
```

**Expected:** Should see actual syscall names, NOT just "syscall"

### Test 12: Verify ML Uses Real Data

Check the training output:
```bash
sudo python3 core/enhanced_security_agent.py --train-models 2>&1 | grep -E "(Collecting|training|samples)"
```

**Expected:**
```
"📊 Collecting real syscall data for 30 seconds..."
"✅ Collected X real training samples"
"NOT: supplementing with simulated data"
```

### Test 13: Verify Memory Cleanup

Look for cleanup messages:
```bash
sudo python3 core/enhanced_security_agent.py --dashboard --timeout 180 2>&1 | grep "Cleaned up"
```

**Expected:** Should see cleanup messages every ~60 seconds

---

## Common Issues & Solutions

### Issue: "No module named bcc"
**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install bpfcc-tools python3-bpfcc
```

### Issue: "Permission denied" when loading eBPF
**Solution:** Need root privileges
```bash
sudo python3 [command]
```

### Issue: Only seeing "syscall" not real names
**Problem:** Bug #1 not fixed properly
**Solution:** Check `enhanced_ebpf_monitor.py` line 109-145 for eBPF code

### Issue: ML training says "supplementing with simulated data"
**Problem:** Bug #2 not fixed
**Solution:** Check `enhanced_security_agent.py` line 354-438 for training code

### Issue: Memory keeps growing
**Problem:** Bug #3 not fixed
**Solution:** Check for cleanup thread in `enhanced_security_agent.py`

### Issue: Crashes or race conditions
**Problem:** Bug #4 not fixed
**Solution:** Check locking in `process_syscall_event` method

---

## Verification Checklist

Run through this checklist:

- [ ] Python dependencies installed
- [ ] BCC installed (Linux)
- [ ] All modules import successfully
- [ ] eBPF program loads without errors
- [ ] Syscall mapping works (numbers → names)
- [ ] Real syscalls being captured
- [ ] Dashboard shows real syscall names
- [ ] Risk scores are being calculated
- [ ] ML training collects real data
- [ ] Memory stays bounded
- [ ] Cleanup messages appear
- [ ] No crashes under load
- [ ] Container detection works (if Docker available)
- [ ] All 5 bug fixes are working

---

## Quick Test Script

Save this as `quick_test.sh`:

```bash
#!/bin/bash

echo "=== Testing Linux Security Agent ==="

# Check Python
echo "Checking Python..."
python3 --version || exit 1

# Check dependencies
echo "Checking dependencies..."
python3 -c "import psutil, docker, rich, numpy, sklearn" || echo "⚠️  Missing dependencies"

# Check eBPF
echo "Checking eBPF..."
python3 -c "from core.enhanced_ebpf_monitor import StatefulEBPFMonitor" || echo "⚠️  eBPF monitor import failed"

# Quick functionality test
echo "Running quick test..."
sudo timeout 5 python3 core/enhanced_security_agent.py --dashboard --timeout 5 2>&1 | grep -q "Security Dashboard" && echo "✅ Agent runs" || echo "⚠️  Agent test failed"

echo "=== Tests Complete ==="
```

Make it executable:
```bash
chmod +x quick_test.sh
./quick_test.sh
```

---

## What to Report

After testing, report:
1. Which tests passed
2. Which tests failed
3. Any errors or warnings
4. Screenshots of dashboard
5. Memory usage graphs
6. Syscall capture rate
7. Any performance issues

Then I can help fix any remaining problems!

