# Quick Run Guide

## On Linux VM (Recommended)

```bash
# 1. Connect to your VM
ssh agent@192.168.64.4
# Password: rrot

# 2. Navigate to project
cd ~/linux_security_agent
git pull origin main

# 3. Install dependencies (if not already installed)
pip3 install -r requirements.txt

# 4. Setup auditd (if not already running)
sudo systemctl start auditd
sudo auditctl -a always,exit -S all

# 5. Run simple agent
sudo python3 core/simple_agent.py --collector auditd --threshold 30
```

## What to Expect

1. **System Validation** - Checks if auditd is available
2. **Collector Selection** - Auto-selects auditd (or eBPF if available)
3. **Live Dashboard** - Shows processes with risk scores
4. **Press Ctrl+C** - To stop

## Troubleshooting

### "Audit log not found"
```bash
sudo systemctl start auditd
sudo auditctl -a always,exit -S all
```

### "No collector available"
```bash
# Check auditd
sudo systemctl status auditd

# Check audit log
ls -la /var/log/audit/audit.log
```

### "Module not found"
```bash
pip3 install -r requirements.txt
```

## Alternative: Enhanced Agent

```bash
# Train models first (optional)
python3 core/enhanced_security_agent.py --train-models

# Run with dashboard
sudo python3 core/enhanced_security_agent.py --collector auditd --dashboard --threshold 30
```

