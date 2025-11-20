# Quick Deploy to UTM VM

## 🚀 Fastest Method (Recommended)

### Option 1: Install sshpass (Easiest)

```bash
# Install sshpass on Mac
brew install hudochenkov/sshpass/sshpass

# Then run deployment
./deploy_to_vm.sh
```

### Option 2: Use Expect Script

```bash
# Make sure expect is installed
brew install expect

# Run deployment
chmod +x deploy_with_expect.sh
./deploy_with_expect.sh
```

### Option 3: Manual Steps (If scripts don't work)

#### Step 1: Copy files to VM

```bash
# From your Mac terminal
cd /Users/likithashankar/linux_security_agent
scp -r ./ agent@192.168.64.4:~/linux_security_agent/
# Password: root
```

#### Step 2: Install dependencies on VM

```bash
ssh agent@192.168.64.4
# Password: root

# Once connected, run:
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev build-essential git curl
sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
# Password: root (for sudo)
```

#### Step 3: Install Python packages

```bash
# Still on VM
cd ~/linux_security_agent
pip3 install --user -r requirements.txt
```

#### Step 4: Test installation

```bash
# On VM
python3 -c "from core.enhanced_security_agent import EnhancedSecurityAgent; print('✅ Works!')"
```

#### Step 5: Run the agent

```bash
# On VM
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30
# Password: root (for sudo)
```

## 🎯 One-Line Commands (Copy-Paste)

### Deploy Everything

```bash
# Install sshpass first, then:
sshpass -p 'root' ssh agent@192.168.64.4 "sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-dev build-essential bpfcc-tools python3-bpfcc linux-headers-\$(uname -r)" && \
sshpass -p 'root' scp -r ./ agent@192.168.64.4:~/linux_security_agent/ && \
sshpass -p 'root' ssh agent@192.168.64.4 "cd ~/linux_security_agent && pip3 install --user -r requirements.txt"
```

### Run Agent

```bash
sshpass -p 'root' ssh -t agent@192.168.64.4 "cd ~/linux_security_agent && sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30"
```

## 📝 Quick Reference

- **VM IP:** 192.168.64.4
- **User:** agent
- **Password:** root
- **Project Path:** ~/linux_security_agent

## 🔧 Troubleshooting

### If sshpass not available:
```bash
brew install hudochenkov/sshpass/sshpass
```

### If connection fails:
```bash
# Test connection
ping 192.168.64.4
ssh -v agent@192.168.64.4
```

### If BCC installation fails:
```bash
# On VM, try:
sudo apt-get install -y bcc-tools python3-bcc
```

### Use auditd fallback if eBPF doesn't work:
```bash
# On VM:
sudo apt-get install -y auditd
sudo systemctl start auditd
sudo python3 core/enhanced_security_agent.py --collector auditd --dashboard
```

