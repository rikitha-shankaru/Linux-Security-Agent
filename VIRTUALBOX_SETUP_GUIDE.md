# 🐧 VirtualBox Linux Setup Guide

## 📋 **Prerequisites**

### **Downloads Required:**
1. **VirtualBox**: https://www.virtualbox.org/wiki/Downloads
   - Download "VirtualBox 7.0.x platform packages" for macOS
   - Install the .dmg file

2. **Ubuntu 22.04 LTS**: https://ubuntu.com/download/desktop
   - Download "Ubuntu 22.04.3 LTS" (Long Term Support)
   - File size: ~4.7GB

---

## 🚀 **Step-by-Step VM Setup**

### **Step 1: Install VirtualBox**
1. Open the downloaded VirtualBox .dmg file
2. Run the installer
3. Follow the installation wizard
4. Grant necessary permissions when prompted

### **Step 2: Create New Virtual Machine**

1. **Open VirtualBox**
2. **Click "New"**
3. **Configure VM Settings:**
   - **Name**: `Linux Security Agent`
   - **Type**: Linux
   - **Version**: Ubuntu (64-bit)
   - **Memory**: 4096 MB (4GB) - **Important for eBPF**
   - **Hard Disk**: Create a virtual hard disk now
   - **Hard Disk Type**: VDI (VirtualBox Disk Image)
   - **Storage**: Dynamically allocated
   - **Size**: 25 GB (minimum for Ubuntu + your project)

### **Step 3: Configure VM Settings**

**Before starting the VM, configure these settings:**

1. **Right-click VM → Settings**
2. **System → Processor:**
   - Enable "Enable PAE/NX"
   - Processors: 2 (if available)
3. **Display → Screen:**
   - Video Memory: 128 MB
   - Enable "Enable 3D Acceleration"
4. **Network → Adapter 1:**
   - Attached to: NAT (default is fine)
5. **Storage → Controller IDE:**
   - Click the CD icon → Choose a disk file
   - Select your downloaded Ubuntu 22.04 ISO

### **Step 4: Install Ubuntu**

1. **Start the VM**
2. **Ubuntu Installation:**
   - Select "Install Ubuntu"
   - Choose "Normal installation"
   - Enable "Install third-party software"
   - Choose "Erase disk and install Ubuntu"
   - Set up your user account (remember the password!)
   - Wait for installation to complete (~20-30 minutes)
   - Restart when prompted

### **Step 5: Install Guest Additions**

**After Ubuntu is installed:**

1. **In the VM menu**: Devices → Insert Guest Additions CD
2. **Open Terminal** in Ubuntu
3. **Run these commands:**
   ```bash
   sudo apt update
   sudo apt install -y build-essential dkms linux-headers-$(uname -r)
   sudo mount /dev/cdrom /mnt
   cd /mnt
   sudo ./VBoxLinuxAdditions.run
   sudo reboot
   ```

---

## 🔧 **Step 6: Transfer Your Project**

### **Method 1: Using Shared Folder (Recommended)**

1. **In VirtualBox**: Devices → Shared Folders → Shared Folder Settings
2. **Add new shared folder:**
   - Folder Path: `/Users/likithashankar/linux_security_agent`
   - Folder Name: `security_agent`
   - Enable "Auto-mount" and "Make Permanent"
3. **In Ubuntu VM:**
   ```bash
   sudo usermod -a -G vboxsf $USER
   sudo reboot
   ```
4. **After reboot, access your project:**
   ```bash
   cd /media/sf_security_agent
   ls -la
   ```

### **Method 2: Using Git (Alternative)**

```bash
# In Ubuntu VM
sudo apt install -y git
git clone <your-github-repo>
cd linux_security_agent
```

### **Method 3: Using SCP (Alternative)**

```bash
# From your Mac terminal
scp -r /Users/likithashankar/linux_security_agent username@vm-ip:/home/username/
```

---

## 🛡️ **Step 7: Install Security Agent Dependencies**

**In the Ubuntu VM:**

```bash
# Navigate to your project
cd /media/sf_security_agent  # or wherever you placed it

# Make setup script executable
chmod +x setup_linux_vm.sh

# Run the setup script
sudo ./setup_linux_vm.sh
```

**Or manually install:**
```bash
# Update system
sudo apt update

# Install system dependencies
sudo apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    bpfcc-tools \
    python3-bpfcc \
    build-essential \
    linux-headers-$(uname -r) \
    git

# Install Python dependencies
pip3 install psutil scikit-learn numpy pandas colorama rich click requests
```

---

## 🚀 **Step 8: Test Your Security Agent**

**In the Ubuntu VM:**

```bash
# Navigate to project directory
cd /media/sf_security_agent

# Test eBPF is working
python3 -c "
try:
    from bcc import BPF
    print('✅ eBPF is working!')
except ImportError as e:
    print('❌ eBPF not available:', e)
"

# Run the security agent with full eBPF support
sudo python3 security_agent.py --dashboard --threshold 30
```

---

## 🎯 **Expected Results**

**You should see:**
```
🛡️  Linux Security Agent - Real-Time Dashboard
===============================================
┌─────┬──────────────┬────────────┬──────────┬─────────────┐
│ PID │ Process Name │ Risk Score │ Syscalls │ Last Update │
├─────┼──────────────┼────────────┼──────────┼─────────────┤
│ 1   │ systemd      │ 4.0        │ 4        │ 14:30:25    │
│ 2   │ kthreadd     │ 2.0        │ 2        │ 14:30:24    │
│ 3   │ rcu_gp       │ 1.0        │ 1        │ 14:30:23    │
└─────┴──────────────┴────────────┴──────────┴─────────────┘

Total Processes: 150+ | Total Syscalls: 1000+ | High Risk: 0
eBPF Monitoring: Active (Real system calls)
```

**No fallback messages!** 🎉

---

## 🔧 **Troubleshooting**

### **Common Issues:**

1. **"eBPF not available"**
   ```bash
   sudo apt install -y bpfcc-tools python3-bpfcc
   sudo reboot
   ```

2. **"Permission denied"**
   ```bash
   sudo python3 security_agent.py --dashboard
   ```

3. **"Shared folder not accessible"**
   ```bash
   sudo usermod -a -G vboxsf $USER
   sudo reboot
   ```

4. **VM runs slowly**
   - Increase RAM to 4GB+
   - Enable hardware acceleration
   - Install Guest Additions

---

## 🎓 **For Your Professor Demo**

**Perfect setup for maximum impact:**
- ✅ Real Linux environment
- ✅ Full eBPF system call monitoring
- ✅ No Docker limitations
- ✅ Authentic enterprise experience
- ✅ Professional presentation

**Demo script:**
```bash
# In Ubuntu VM
sudo python3 security_agent.py --dashboard --threshold 30
# In another terminal:
python3 demo/run_demo.py
```

---

## 🚀 **Next Steps**

1. **Download VirtualBox and Ubuntu**
2. **Follow this guide step by step**
3. **Test your security agent**
4. **Practice your demo**
5. **Impress your professor!** 🎉

**Estimated setup time: 1-2 hours**
**Demo preparation: 30 minutes**
**Total time to success: 2-3 hours**
