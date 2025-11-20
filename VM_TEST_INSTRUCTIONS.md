# 🧪 Testing on Linux VM - Quick Guide

## Quick Test (One Command)

**On your Linux VM, run:**

```bash
cd ~/linux_security_agent
git pull origin main
sudo bash test_on_vm.sh
```

This script will:
1. ✅ Install auditd (if needed)
2. ✅ Start auditd service
3. ✅ Configure audit rules
4. ✅ Test that auditd is capturing
5. ✅ Run the security agent with auditd

---

## Manual Test (Step by Step)

If you prefer to do it manually:

### 1. Pull Latest Code
```bash
cd ~/linux_security_agent
git pull origin main
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

### 4. Configure Audit Rules
```bash
sudo auditctl -a always,exit -S all
```

### 5. Verify Auditd is Working
```bash
# Generate some activity
ls -R /home > /dev/null 2>&1
ps aux > /dev/null 2>&1

# Check if events were logged
sudo tail -20 /var/log/audit/audit.log | grep SYSCALL
# Should see syscall events
```

### 6. Run Security Agent
```bash
cd ~/linux_security_agent
sudo python3 core/enhanced_security_agent.py --collector auditd --train-models --dashboard --threshold 30
```

---

## What to Expect

### During Training:
- ✅ Should collect **50+ samples** (not 0!)
- ✅ Real syscall data being captured
- ✅ Models training on actual behavior

### Dashboard:
- ✅ Processes appearing in table
- ✅ Real-time updates
- ✅ Risk scores calculated
- ✅ Syscall counts increasing

### If You See "0 samples":
1. Check auditd is running: `sudo systemctl status auditd`
2. Check audit rules: `sudo auditctl -l`
3. Generate activity in another terminal
4. Check audit log: `sudo tail -f /var/log/audit/audit.log`

---

## Generate Test Activity

**In another terminal while agent is running:**

```bash
# Generate lots of syscalls
while true; do
    ls -R /home > /dev/null 2>&1
    ps aux > /dev/null 2>&1
    cat /etc/passwd > /dev/null 2>&1
    find /tmp -type f 2>/dev/null | head -10 > /dev/null
    sleep 0.3
done
```

You should see processes appearing in the dashboard!

---

## Troubleshooting

### Auditd Not Running
```bash
sudo systemctl restart auditd
sudo systemctl status auditd
```

### No Events Being Captured
```bash
# Check rules
sudo auditctl -l
# Should show: -a always,exit -S all

# If not, add rule:
sudo auditctl -a always,exit -S all
```

### Permission Errors
```bash
# Make sure you're using sudo
sudo python3 core/enhanced_security_agent.py --collector auditd ...
```

### Can't Read Audit Log
```bash
# Check permissions
ls -la /var/log/audit/audit.log
# Should be readable

# If not:
sudo chmod 644 /var/log/audit/audit.log
```

---

## Success Indicators

✅ **Training collects 50+ samples** (not 0!)
✅ **Dashboard shows processes** (not just "Waiting...")
✅ **Syscall counts increasing** in real-time
✅ **Risk scores being calculated**
✅ **No errors in output**

---

## Next Steps After Testing

Once it's working:
1. Test threat intelligence features
2. Test response handler (carefully!)
3. Test with different workloads
4. Performance testing
5. Scale testing

