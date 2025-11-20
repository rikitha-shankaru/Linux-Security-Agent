# 🔧 Troubleshooting Guide - Linux VM

## Quick Debug

**Run this on your VM to see what's wrong:**

```bash
cd ~/linux_security_agent
git pull origin main
bash debug_vm.sh
```

This will check:
- ✅ Python installation
- ✅ Auditd installation and service
- ✅ Audit rules configuration
- ✅ Audit log file
- ✅ Project files
- ✅ Python dependencies
- ✅ Code imports

---

## Common Issues & Fixes

### Issue 1: "Auditd not installed"

**Fix:**
```bash
sudo apt-get update
sudo apt-get install -y auditd
```

### Issue 2: "Auditd service not running"

**Fix:**
```bash
sudo systemctl start auditd
sudo systemctl enable auditd
sudo systemctl status auditd
```

### Issue 3: "No audit rules"

**Fix:**
```bash
sudo auditctl -a always,exit -S all
sudo auditctl -l  # Verify
```

### Issue 4: "Audit log not found"

**Fix:**
```bash
sudo mkdir -p /var/log/audit
sudo touch /var/log/audit/audit.log
sudo chmod 600 /var/log/audit/audit.log
sudo systemctl restart auditd
```

### Issue 5: "Python dependencies missing"

**Fix:**
```bash
cd ~/linux_security_agent
pip3 install -r requirements.txt
# Or
python3 -m pip install --user -r requirements.txt
```

### Issue 6: "Import errors"

**Fix:**
```bash
cd ~/linux_security_agent
# Make sure you're in the right directory
pwd
# Should show: /home/agent/linux_security_agent

# Try importing
python3 -c "from core.collector_auditd import AuditdCollector; print('OK')"
```

### Issue 7: "Permission denied"

**Fix:**
```bash
# Make sure you're using sudo
sudo python3 core/enhanced_security_agent.py --collector auditd ...
```

### Issue 8: "0 samples collected"

**Possible causes:**
1. Auditd not capturing events
2. Audit log not readable
3. No system activity

**Fix:**
```bash
# 1. Check auditd is running
sudo systemctl status auditd

# 2. Check audit rules
sudo auditctl -l

# 3. Generate activity
ls -R /home > /dev/null 2>&1
ps aux > /dev/null 2>&1

# 4. Check if events are logged
sudo tail -20 /var/log/audit/audit.log | grep SYSCALL

# 5. Check log permissions
ls -la /var/log/audit/audit.log
```

---

## Step-by-Step Manual Setup

If the script doesn't work, do it manually:

### 1. Check Python
```bash
python3 --version
# Should show Python 3.x
```

### 2. Install Auditd
```bash
sudo apt-get update
sudo apt-get install -y auditd
```

### 3. Start Auditd
```bash
sudo systemctl start auditd
sudo systemctl enable auditd
```

### 4. Configure Rules
```bash
sudo auditctl -a always,exit -S all
sudo auditctl -l
# Should show: -a always,exit -S all
```

### 5. Test Auditd
```bash
# Generate activity
ls -R /home > /dev/null 2>&1

# Check log
sudo tail -5 /var/log/audit/audit.log
# Should see SYSCALL events
```

### 6. Install Dependencies
```bash
cd ~/linux_security_agent
pip3 install -r requirements.txt
```

### 7. Test Import
```bash
python3 -c "from core.collector_auditd import AuditdCollector; print('OK')"
```

### 8. Run Agent
```bash
sudo python3 core/enhanced_security_agent.py --collector auditd --dashboard --threshold 30
```

---

## What Error Are You Seeing?

**Please share:**
1. The exact error message
2. What command you ran
3. Output of: `bash debug_vm.sh`

This will help me fix the specific issue!

---

## Alternative: Skip Training, Just Test Dashboard

If training is the issue, test the dashboard first:

```bash
# Just run dashboard (no training)
sudo python3 core/enhanced_security_agent.py --collector auditd --dashboard --threshold 30
```

Then generate activity in another terminal to see if processes appear.

