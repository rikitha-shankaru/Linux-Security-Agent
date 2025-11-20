# Testing with Attacks - Complete Guide

## 🎯 Overview

This guide shows how to test your security agent implementation with actual attack patterns to verify it works correctly.

---

## 🔴 Safe Attack Simulation

### **Quick Start**

```bash
# Terminal 1: Run the security agent
cd ~/linux_security_agent
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30

# Terminal 2: Run attack simulation
python3 scripts/simulate_attacks.py
```

### **What the Script Does**

The `simulate_attacks.py` script safely simulates:

1. **Privilege Escalation** - Attempts `setuid`, `setgid`, `execve` patterns
2. **High-Frequency Attack** - Rapid syscall bursts (DoS pattern)
3. **Suspicious File Patterns** - Bursty file I/O operations
4. **Process Churn** - Rapid fork/exec patterns
5. **Network Scanning** - Multiple socket connection attempts
6. **Ptrace Attempts** - Process tracing attempts

**All operations are SAFE:**
- ✅ No actual privilege escalation (attempts fail)
- ✅ No destructive operations
- ✅ Only uses `/tmp` directory
- ✅ Limited duration and scope
- ✅ Safe to run in VM

---

## 📊 What to Look For

### **During Attack Simulation**

1. **Risk Scores Should Spike**
   - Normal processes: Risk < 30
   - Attack patterns: Risk **50-100**

2. **ML Anomaly Detection**
   - Should flag attacks as anomalous
   - Confidence scores should be high

3. **Dashboard Updates**
   - Real-time risk score updates
   - High-risk processes highlighted
   - Explanations shown (e.g., "High proportion of risky system calls")

4. **Syscall Patterns**
   - Dashboard should show suspicious syscalls
   - High frequency of `execve`, `setuid`, `fork`, etc.

### **Expected Results**

```
High Risk Processes (>30.0):
  PID 12345: python3 (Risk: 85.5)  ← Attack simulation
  PID 12346: python3 (Risk: 72.3)  ← Attack simulation
  
Anomaly Detected:
  PID 12345: python3
  Score: 85.5
  Explanation: "High proportion of risky system calls; Isolation Forest detected outlier behavior"
```

---

## 🧪 Integration Tests with Attacks

### **Run Automated Tests**

```bash
# Run integration tests that include attack simulations
python3 tests/test_integration_full.py

# Specifically test attack detection
python3 -m pytest tests/test_integration_full.py::TestAttackSimulation -v
```

### **Test Coverage**

The test suite includes:
- ✅ Privilege escalation simulation
- ✅ Container escape simulation  
- ✅ High-frequency attack simulation
- ✅ Risk score validation
- ✅ ML anomaly detection validation

---

## 📈 Training with Public Datasets

### **Supported Datasets**

You can train with publicly available datasets:

1. **ADFA-LD** (UNSW) - Linux syscall traces
2. **CIC-IDS2017** - Network and system data
3. **Custom JSON datasets** - Any properly formatted dataset

### **Dataset Format**

```json
{
  "samples": [
    {
      "syscalls": ["read", "write", "open", "close", "execve"],
      "process_info": {
        "cpu_percent": 10.0,
        "memory_percent": 5.0,
        "num_threads": 2
      }
    }
  ]
}
```

### **Training from Dataset**

```bash
# Train from JSON file
python3 scripts/train_with_dataset.py --file dataset.json

# Train from URL
python3 scripts/train_with_dataset.py --url https://example.com/dataset.json

# Train from directory of JSON files
python3 scripts/train_with_dataset.py --directory ./datasets/

# Append to existing models
python3 scripts/train_with_dataset.py --file dataset.json --append
```

---

## 🔍 Validation Checklist

### **Before Demo**

- [ ] Agent runs without errors
- [ ] Dashboard displays correctly
- [ ] Normal processes show low risk (< 30)
- [ ] Attack simulation script runs successfully
- [ ] Attacks trigger high risk scores (50-100)
- [ ] ML models flag attacks as anomalous
- [ ] Explanations are clear and accurate

### **During Demo**

1. **Show Normal Behavior**
   ```bash
   # Run normal commands
   ls -R /home
   cat /etc/passwd
   ps aux
   ```
   - Should show low risk scores

2. **Run Attack Simulation**
   ```bash
   python3 scripts/simulate_attacks.py
   ```
   - Should show high risk scores
   - Should trigger anomaly detection

3. **Show Dashboard**
   - Point out risk score differences
   - Show anomaly explanations
   - Demonstrate real-time updates

---

## 🎓 For Professor Presentation

### **Demo Script**

```bash
# 1. Start agent
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30

# 2. Show normal behavior (low risk)
# Run: ls, cat, ps in another terminal

# 3. Run attack simulation
python3 scripts/simulate_attacks.py

# 4. Point out:
#    - Risk scores spiked to 50-100
#    - ML anomaly detection flagged attacks
#    - Real-time dashboard updates
#    - Clear explanations
```

### **Talking Points**

1. **"Why eBPF?"**
   - "10-100x faster than auditd through zero-copy architecture"
   - "Real-time detection with < 5% CPU overhead"
   - "Industry standard for modern security monitoring"

2. **"How Training Works?"**
   - "Unsupervised learning: collects 500+ real syscall samples"
   - "Extracts 50-D features, trains ensemble of 3 ML models"
   - "Learns normal behavior, flags deviations as anomalies"

3. **"How We Test?"**
   - "Safe attack simulation scripts trigger suspicious patterns"
   - "Agent detects in real-time with risk scores 50-100"
   - "ML models correctly flag attacks with high confidence"

---

## 📝 Example Output

### **Normal Process**
```
PID 1000: bash
Risk Score: 15.2
Syscalls: read, write, open, close
Status: Normal
```

### **Attack Pattern**
```
PID 12345: python3 (attack simulation)
Risk Score: 87.5
Syscalls: execve, setuid, setgid, fork, execve
Anomaly: ✅ DETECTED
Explanation: "High proportion of risky system calls; Isolation Forest detected outlier behavior"
```

---

## 🔧 Troubleshooting

### **Attacks Not Detected?**

1. **Check if agent is running**: `ps aux | grep security_agent`
2. **Check risk threshold**: Lower threshold (e.g., `--threshold 20`)
3. **Verify eBPF is working**: Check for syscall events in dashboard
4. **Check ML models**: Ensure models are trained (`ls ~/.cache/security_agent/*.pkl`)

### **False Positives?**

1. **Retrain models**: Collect more normal data
2. **Adjust threshold**: Increase threshold value
3. **Check baseline**: Ensure training data represents normal behavior

---

**Last Updated:** January 2025

