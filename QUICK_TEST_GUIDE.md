# 🚀 Quick Test Guide - Linux Security Agent

## ✅ Pre-Test Checklist (In VM)

1. **Activate virtual environment:**
   ```bash
   source venv/bin/activate  # or: source venv_new/bin/activate
   ```

2. **Pull latest code:**
   ```bash
   cd ~/linux_security_agent
   git pull
   ```

3. **Verify eBPF/BCC is available:**
   ```bash
   python3 -c "from bcc import BPF; print('✅ eBPF ready!')"
   ```

## 🎯 Main Test Command

```bash
# Run with dashboard (RECOMMENDED for demo)
sudo $(which python3) core/enhanced_security_agent.py --dashboard --timeout 60

# Or simpler (if python3 is in venv):
sudo ./venv/bin/python3 core/enhanced_security_agent.py --dashboard --timeout 60
```

## 📊 What to Expect

### Initial Output:
- ✅ eBPF program loaded successfully
- ✅ Enhanced eBPF monitor initialized
- ✅ Enhanced anomaly detector initialized
- ⚠️ Container monitoring disabled (Docker not running) - **This is OK**
- 🧠 Training anomaly detection models...
- 📊 Collecting real syscall data for 60 seconds...

### During Training (First 60 seconds):
- 💡 **Tip:** Run commands in another terminal to generate syscalls!
- Try: `ls`, `ps`, `cat /etc/passwd`, `top`, etc.

### Dashboard Shows:
- **Live Process Monitoring Table:**
  - PID, Process Name, Risk (🟢🟡🔴), Anomaly (✓/⚠️), Syscalls, CPU%
- **Statistics Panel** with explanations:
  - Processes Monitored
  - High Risk Processes
  - Anomalies Detected
  - Policy Violations

## 🐛 Troubleshooting

### If eBPF fails to load:
```bash
# Check BCC installation
dpkg -l | grep bpfcc

# Reinstall if needed
sudo apt update && sudo apt install -y python3-bpfcc
```

### If you see "ModuleNotFoundError":
```bash
# Make sure venv has system site packages
deactivate
rm -rf venv
python3 -m venv venv --system-site-packages
source venv/bin/activate
```

### If dashboard is blank:
- Wait for training to complete (60 seconds)
- Generate system activity in another terminal
- Processes will appear as syscalls are captured

## 🎤 Demo Tips

### For Professor Presentation:

1. **Start the agent FIRST:**
   ```bash
   sudo ./venv/bin/python3 core/enhanced_security_agent.py --dashboard --timeout 300
   ```

2. **While it's training, explain:**
   - "The agent is collecting real syscall data from the kernel using eBPF"
   - "ML models are being trained on actual system behavior"

3. **Generate activity in another terminal:**
   ```bash
   # Normal activity
   ls -la
   cat /etc/passwd
   
   # More interesting
   find /home -name "*.py" 2>/dev/null
   ```

4. **Point out the dashboard:**
   - **Risk Scores:** How processes are scored
   - **Anomaly Detection:** ML ensemble working
   - **Real-time Updates:** Live syscall capture

5. **Explain the metrics:**
   - **🟢 Green (0-30):** Normal activity
   - **🟡 Yellow (30-50):** Potentially suspicious
   - **🔴 Red (50+):** High risk, investigate immediately

## ✅ Success Indicators

- Dashboard updates every 0.5 seconds
- Processes appear in the table
- Risk scores change dynamically
- Statistics panel shows increasing counts
- No crashes or errors

## 📝 Post-Test Commands

```bash
# List all monitored processes
sudo ./venv/bin/python3 core/enhanced_security_agent.py --list-processes

# Show detected anomalies
sudo ./venv/bin/python3 core/enhanced_security_agent.py --list-anomalies

# Get statistics
sudo ./venv/bin/python3 core/enhanced_security_agent.py --stats
```

