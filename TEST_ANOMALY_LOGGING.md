# Testing Enhanced Anomaly Logging

## Quick Test Steps

### Option 1: Automated Test Script

```bash
# 1. Start the agent (in one terminal)
sudo python3 core/simple_agent.py --collector ebpf --threshold 20

# 2. Run the test script (in another terminal)
python3 scripts/test_anomaly_logging.py
```

The test script will:
- Check if agent is running
- Simulate suspicious activity
- Show you the enhanced anomaly logs

### Option 2: Manual Testing

#### Step 1: Start the Agent

```bash
# Start agent in headless mode (for background)
sudo python3 core/simple_agent.py --collector ebpf --threshold 20 --headless

# OR start with dashboard (to see live updates)
sudo python3 core/simple_agent.py --collector ebpf --threshold 20
```

#### Step 2: Simulate Attacks

```bash
# Run attack simulations
python3 scripts/simulate_attacks.py

# OR run specific attack
python3 -c "
import sys
sys.path.insert(0, 'scripts')
from simulate_attacks import simulate_privilege_escalation
simulate_privilege_escalation()
"
```

#### Step 3: View Enhanced Logs

```bash
# Watch live anomaly detections with enhanced format
tail -f logs/security_agent.log | grep -A 15 'ANOMALY DETECTED'

# OR view recent anomalies
tail -100 logs/security_agent.log | grep -A 15 'ANOMALY DETECTED'
```

### Option 3: Quick Suspicious Activity

```bash
# Create a script that generates suspicious syscalls
cat > /tmp/test_anomaly.sh << 'EOF'
#!/bin/bash
# Generate suspicious activity
for i in {1..50}; do
    sudo chmod 777 /tmp/test_$i 2>/dev/null
    sudo chown root:root /tmp/test_$i 2>/dev/null
    /bin/ls -la /tmp/test_$i 2>/dev/null
    rm -f /tmp/test_$i 2>/dev/null
done
EOF

chmod +x /tmp/test_anomaly.sh
/tmp/test_anomaly.sh
```

Then check logs:
```bash
tail -50 logs/security_agent.log | grep -A 15 'ANOMALY DETECTED'
```

## What to Look For

The enhanced anomaly logging will show:

```
⚠️  ANOMALY DETECTED: PID=12345 Process=python3 AnomalyScore=35.2
   ┌─ What's Anomalous:
   │  Isolation Forest detected outlier behavior; High proportion of risky system calls
   │  Confidence: 0.81 | Risk Score: 18.5
   ├─ Process Activity:
   │  Total Syscalls: 100 | Recent: 15
   │  Top Syscalls: setuid(5), execve(3), chmod(2), read(2), write(1)
   │  ⚠️  High-Risk Syscalls Detected: setuid, execve, chmod
   │  Resources: CPU=45.2% Memory=12.3% Threads=3
   └─ Recent Sequence: setuid, execve, chmod, read, write, open, close, setuid, execve, chmod
```

## Expected Output

You should see:
- ✅ **What's Anomalous**: ML explanation of why it's flagged
- ✅ **Process Activity**: Total and recent syscall counts
- ✅ **Top Syscalls**: Most frequent syscalls with counts
- ✅ **High-Risk Syscalls**: Specific risky syscalls detected
- ✅ **Resources**: CPU, memory, thread usage
- ✅ **Recent Sequence**: Last 10 syscalls in order

## Troubleshooting

**No anomalies detected?**
- Make sure agent is running: `pgrep -f simple_agent.py`
- Check log file exists: `ls -la logs/security_agent.log`
- Lower the threshold: `--threshold 10` (instead of 20)
- Wait a few seconds for detection

**Logs not showing enhanced format?**
- Make sure you pulled the latest code: `git pull origin main`
- Restart the agent after pulling
- Check you're looking at the right log file

**Agent not starting?**
- Check eBPF support: `lsmod | grep bpf`
- Check permissions: `sudo python3 ...`
- Check ML models: `ls -la ~/.cache/security_agent/`

