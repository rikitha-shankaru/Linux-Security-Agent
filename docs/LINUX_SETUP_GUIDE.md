# 🐧 Linux Security Agent - Complete Setup Guide
# ================================================

## 📋 Table of Contents
1. Initial Ubuntu VM Setup (First Time)
2. Daily SSH Access from macOS
3. Running the Security Agent
4. Troubleshooting
5. Demo Commands

## 🚀 PART 1: Initial Ubuntu VM Setup (First Time)

### Step 1: Install Ubuntu 24.04 in VirtualBox
1. Download Ubuntu 24.04 LTS ISO from ubuntu.com
2. Create new VM in VirtualBox:
   - Name: LinuxSecurityAgent
   - Type: Linux
   - Version: Ubuntu (64-bit)
   - Memory: 4GB RAM
   - Hard disk: 25GB
   - Enable EFI
3. Attach Ubuntu ISO and install
4. Create user: agent (password: your choice)

### Step 2: Install System Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    build-essential \
    linux-headers-$(uname -r) \
    bpfcc-tools \
    python3-bpfcc \
    openssh-server \
    htop \
    tree

# Verify eBPF installation
python3 -c "from bcc import BPF; print('✅ eBPF working!')"
```

### Step 3: Clone Project from GitHub
```bash
# Clone your repository
git clone https://github.com/rikitha-shankaru/Linux-Security-Agent.git
cd Linux-Security-Agent

# Make setup script executable
chmod +x setup_linux_vm.sh

# Run automated setup
./setup_linux_vm.sh
```

### Step 4: Configure SSH Server
```bash
# Start SSH service
sudo systemctl start ssh
sudo systemctl enable ssh

# Check SSH status
sudo systemctl status ssh

# Find VM IP address
ip addr show | grep inet
```

### Step 5: Set Up VirtualBox Port Forwarding
1. In VirtualBox Manager:
   - Right-click Ubuntu VM → Settings
   - Network → Adapter 1 → Advanced → Port Forwarding
   - Add rule:
     - Name: SSH
     - Protocol: TCP
     - Host IP: 127.0.0.1
     - Host Port: 2222
     - Guest IP: (leave blank)
     - Guest Port: 22

### Step 6: Test Initial Setup
```bash
# Activate virtual environment
source venv/bin/activate

# Test the security agent
sudo python3 security_agent.py --dashboard --threshold 30

# Press Ctrl+C to stop
```

## 🔗 PART 2: Daily SSH Access from macOS

### Step 1: Connect via SSH from macOS
```bash
# Connect to Ubuntu VM
ssh -p 2222 agent@127.0.0.1

# If host key error, remove old key:
ssh-keygen -R "[127.0.0.1]:2222"

# Then try again:
ssh -p 2222 agent@127.0.0.1
```

### Step 2: Navigate to Project Directory
```bash
# Once connected via SSH
cd Linux-Security-Agent

# Activate virtual environment
source venv/bin/activate

# Check you're in the right place
pwd
ls -la
```

### Step 3: Start the Security Agent
```bash
# Run with dashboard
sudo python3 security_agent.py --dashboard --threshold 30

# Or run with timeout (e.g., 60 seconds)
sudo python3 security_agent.py --dashboard --threshold 30 --timeout 60

# Or run in background
sudo python3 security_agent.py --dashboard --threshold 30 &
```

## 🎯 PART 3: Running the Security Agent

### Basic Commands
```bash
# Dashboard mode (real-time monitoring)
sudo python3 security_agent.py --dashboard --threshold 30

# JSON output mode
sudo python3 security_agent.py --output json

# With anomaly detection
sudo python3 security_agent.py --dashboard --anomaly-detection --threshold 30

# With specific timeout
sudo python3 security_agent.py --dashboard --threshold 30 --timeout 300
```

### Demo Scripts
```bash
# Run normal behavior demo
python3 demo/normal_behavior.py

# Run suspicious behavior demo
python3 demo/suspicious_behavior.py

# Run full demo
python3 demo/run_demo.py
```

### Expected Output
```
🛡️  Linux Security Agent - Process Risk Dashboard (eBPF Events: XXX)
================================================================
┌─────┬──────────────┬────────────┬──────────┬─────────────┐
│ PID │ Process Name │ Risk Score │ Syscalls │ Last Update │
├─────┼──────────────┼────────────┼──────────┼─────────────┤
│ 1   │ systemd      │ 1.9        │ 2        │ 14:30:25    │
│ 2   │ python3      │ 20.0       │ 172      │ 14:30:26    │
└─────┴──────────────┴────────────┴──────────┴─────────────┘

Total Processes: 150+ | Total Syscalls: 1000+ | High Risk: 0
eBPF Monitoring: Active (Real system calls)
```

## 🔧 PART 4: Troubleshooting

### SSH Connection Issues
```bash
# Remove old host keys
ssh-keygen -R "[127.0.0.1]:2222"

# Check SSH service status
sudo systemctl status ssh

# Restart SSH service
sudo systemctl restart ssh

# Check port forwarding in VirtualBox
# VM Settings → Network → Port Forwarding
```

### eBPF Issues
```bash
# Reinstall eBPF tools
sudo apt install --reinstall bpfcc-tools python3-bpfcc

# Check kernel headers
sudo apt install linux-headers-$(uname -r)

# Verify eBPF
python3 -c "from bcc import BPF; print('✅ eBPF working!')"
```

### Permission Issues
```bash
# Fix virtual environment permissions
sudo chown -R agent:agent venv/

# Fix project permissions
sudo chown -R agent:agent Linux-Security-Agent/
```

### Agent Not Starting
```bash
# Check if already running
ps aux | grep security_agent

# Kill existing processes
sudo pkill -f security_agent

# Check dependencies
pip3 list | grep -E "(bcc|psutil|rich)"

# Reinstall dependencies
pip3 install -r requirements.txt
```

## 🎓 PART 5: Demo Commands for Professor

### Quick Demo Sequence
```bash
# 1. Connect via SSH
ssh -p 2222 agent@127.0.0.1

# 2. Navigate to project
cd Linux-Security-Agent
source venv/bin/activate

# 3. Start agent
sudo python3 security_agent.py --dashboard --threshold 30

# 4. In another terminal, run demo
python3 demo/suspicious_behavior.py

# 5. Show risk scores changing in real-time
# 6. Stop agent with Ctrl+C
```

### Talking Points
- "This is real eBPF system call monitoring"
- "Live risk scoring based on process behavior"
- "Production-ready Linux security agent"
- "Enterprise-grade threat detection"
- "Real-time dashboard with dynamic updates"

## 📊 PART 6: Performance Monitoring

### System Resources
```bash
# Check system resources
htop

# Check eBPF events
sudo python3 security_agent.py --output json | head -20

# Monitor disk usage
df -h

# Check memory usage
free -h
```

### Log Files
```bash
# Check system logs
sudo journalctl -f

# Check security agent logs
tail -f /var/log/syslog | grep security_agent
```

## 🚀 PART 7: Advanced Usage

### Custom Risk Thresholds
```bash
# Low threshold (more sensitive)
sudo python3 security_agent.py --dashboard --threshold 10

# High threshold (less sensitive)
sudo python3 security_agent.py --dashboard --threshold 50
```

### Export Data
```bash
# Export to JSON file
sudo python3 security_agent.py --output json > security_data.json

# Export with timestamp
sudo python3 security_agent.py --output json > security_$(date +%Y%m%d_%H%M%S).json
```

### Background Operation
```bash
# Run in background
nohup sudo python3 security_agent.py --dashboard --threshold 30 > agent.log 2>&1 &

# Check background process
ps aux | grep security_agent

# Stop background process
sudo pkill -f security_agent
```

## 📝 PART 8: Daily Workflow Summary

### Morning Routine
1. Start VirtualBox VM
2. SSH from macOS: `ssh -p 2222 agent@127.0.0.1`
3. Navigate: `cd Linux-Security-Agent && source venv/bin/activate`
4. Start agent: `sudo python3 security_agent.py --dashboard --threshold 30`

### Evening Routine
1. Stop agent: `Ctrl+C`
2. Disconnect SSH: `exit`
3. Shutdown VM: `sudo shutdown -h now`

### Weekly Maintenance
1. Update system: `sudo apt update && sudo apt upgrade -y`
2. Update project: `git pull origin main`
3. Reinstall dependencies: `pip3 install -r requirements.txt`

## 🎯 PART 9: Success Indicators

### ✅ Everything Working Correctly
- SSH connection successful
- eBPF events counting up (e.g., "eBPF Events: 421")
- Dashboard showing live processes
- Risk scores updating in real-time
- No error messages about eBPF failures

### ❌ Common Issues
- "eBPF monitoring failed" → Check eBPF installation
- "Permission denied" → Use sudo for security_agent.py
- "No such file or directory" → Check you're in correct directory
- SSH connection refused → Check port forwarding and SSH service

## 📞 Support Commands

### Quick Health Check
```bash
# Check VM status
ip addr show | grep inet
sudo systemctl status ssh

# Check project status
cd Linux-Security-Agent
ls -la
source venv/bin/activate
python3 -c "from bcc import BPF; print('✅ eBPF OK')"

# Test agent
sudo python3 security_agent.py --help
```

### Reset Everything
```bash
# Stop all processes
sudo pkill -f security_agent

# Reset virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

# Test again
sudo python3 security_agent.py --dashboard --threshold 30
```

## 🎉 Conclusion

This guide covers everything you need to:
- Set up Ubuntu VM from scratch
- Configure SSH access from macOS
- Run the Linux Security Agent
- Troubleshoot common issues
- Prepare for professor demos

Your Linux Security Agent is now ready for production use! 🚀

---
Last Updated: $(date)
Project: Linux Security Agent
Repository: https://github.com/rikitha-shankaru/Linux-Security-Agent
