# UTM VM Setup Guide

## 🎯 Quick Start

You have a Linux VM running in UTM at `192.168.64.4`. Here's how to set up the security agent.

## 📋 Prerequisites

1. **SSH access** to the VM (already configured: `agent@192.168.64.4`)
2. **VM is running** and accessible
3. **SSH keys set up** (or password authentication enabled)

## 🚀 Setup Steps

### Option 1: Automated Setup (Recommended)

```bash
# Make scripts executable
chmod +x setup_utm_vm.sh connect_and_run.sh

# Run automated setup
./setup_utm_vm.sh
```

This script will:
1. ✅ Test SSH connection
2. ✅ Install system dependencies (Python, BCC tools)
3. ✅ Copy project files to VM
4. ✅ Install Python packages
5. ✅ Verify installation

### Option 2: Manual Setup

#### Step 1: Test SSH Connection

```bash
ssh agent@192.168.64.4
```

If this works, you're good to go!

#### Step 2: Install Dependencies on VM

```bash
ssh agent@192.168.64.4 << 'EOF'
    # Update package list
    sudo apt-get update
    
    # Install Python and build tools
    sudo apt-get install -y \
        python3 python3-pip python3-dev \
        build-essential git curl
    
    # Install BCC tools for eBPF
    sudo apt-get install -y \
        bpfcc-tools python3-bpfcc \
        linux-headers-$(uname -r)
EOF
```

#### Step 3: Copy Project to VM

```bash
# From your Mac, in the project directory
rsync -avz --exclude 'venv*' --exclude '__pycache__' \
    --exclude '.git' \
    ./ agent@192.168.64.4:~/linux_security_agent/
```

Or use scp:
```bash
scp -r ./ agent@192.168.64.4:~/linux_security_agent/
```

#### Step 4: Install Python Packages on VM

```bash
ssh agent@192.168.64.4 << 'EOF'
    cd ~/linux_security_agent
    pip3 install --user -r requirements.txt
EOF
```

#### Step 5: Verify Installation

```bash
ssh agent@192.168.64.4 << 'EOF'
    cd ~/linux_security_agent
    
    # Test BCC
    python3 -c "from bcc import BPF; print('✅ eBPF working')"
    
    # Test agent
    python3 -c "from core.enhanced_security_agent import EnhancedSecurityAgent; print('✅ Agent loads')"
EOF
```

## 🏃 Running the Agent

### Quick Run

```bash
# Connect and run in one command
./connect_and_run.sh run
```

### Manual Run

```bash
# Connect to VM
ssh agent@192.168.64.4

# Navigate to project
cd ~/linux_security_agent

# Run the agent (requires sudo for eBPF)
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30
```

### Training Models First

```bash
ssh agent@192.168.64.4 << 'EOF'
    cd ~/linux_security_agent
    
    # Train models (no sudo needed)
    python3 core/enhanced_security_agent.py --train-models
    
    # Then run monitoring
    sudo python3 core/enhanced_security_agent.py --dashboard
EOF
```

## 🔧 Troubleshooting

### SSH Connection Issues

**Problem:** Can't connect via SSH

**Solutions:**
```bash
# Test connection
ping 192.168.64.4

# Check if SSH is running on VM
ssh -v agent@192.168.64.4

# If password auth needed, use:
ssh -o PreferredAuthentications=password agent@192.168.64.4
```

### BCC Installation Fails

**Problem:** `bpfcc-tools` not available

**Solutions:**
```bash
# Try alternative package name
sudo apt-get install -y bcc-tools python3-bcc

# Or compile from source (advanced)
# See: https://github.com/iovisor/bcc
```

### Permission Denied

**Problem:** Need sudo for eBPF

**Solution:** This is normal - eBPF requires root access
```bash
# Always use sudo for running the agent
sudo python3 core/enhanced_security_agent.py --dashboard
```

### Use auditd Fallback

If eBPF doesn't work, use auditd:
```bash
# On VM, enable auditd
sudo apt-get install -y auditd
sudo systemctl start auditd
sudo systemctl enable auditd

# Run with auditd collector
sudo python3 core/enhanced_security_agent.py --collector auditd --dashboard
```

## 📝 Useful Commands

### Quick Connect
```bash
./connect_and_run.sh        # Just connect
./connect_and_run.sh run    # Connect and run agent
```

### Copy Files to VM
```bash
# Single file
scp file.py agent@192.168.64.4:~/linux_security_agent/

# Entire directory (exclude venv)
rsync -avz --exclude 'venv*' ./ agent@192.168.64.4:~/linux_security_agent/
```

### Run Commands on VM
```bash
# Single command
ssh agent@192.168.64.4 "cd ~/linux_security_agent && ls -la"

# Multiple commands
ssh agent@192.168.64.4 << 'EOF'
    cd ~/linux_security_agent
    git pull
    pip3 install --user -r requirements.txt
EOF
```

## 🎯 Recommended Workflow

1. **Develop on Mac** - Edit code locally
2. **Sync to VM** - Use rsync or git
3. **Test on VM** - Run agent with sudo
4. **Iterate** - Repeat as needed

### Git Workflow (Recommended)

```bash
# On Mac: Make changes and commit
git add .
git commit -m "Your changes"
git push

# On VM: Pull changes
ssh agent@192.168.64.4 << 'EOF'
    cd ~/linux_security_agent
    git pull
    pip3 install --user -r requirements.txt
EOF
```

## 🔐 Security Notes

- **SSH Keys:** Set up SSH keys for passwordless login
- **Sudo Access:** Agent needs sudo for eBPF (normal)
- **Firewall:** Ensure VM firewall allows your connection
- **Network:** UTM VMs typically use NAT networking

## 📊 VM Configuration Tips

For best performance in UTM:
- **RAM:** Allocate at least 2GB (4GB recommended)
- **CPU:** 2+ cores if available
- **Disk:** 20GB+ for Ubuntu
- **Network:** NAT or Bridged (for SSH access)

---

**Quick Reference:**
- **VM IP:** `192.168.64.4`
- **User:** `agent`
- **SSH:** `ssh agent@192.168.64.4`
- **Project Path:** `~/linux_security_agent`

**Last Updated:** January 2025

