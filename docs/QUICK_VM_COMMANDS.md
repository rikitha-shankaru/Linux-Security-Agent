# 🚀 Quick VM Commands Reference

## 🐧 **Ubuntu VM Commands**

### **System Updates**
```bash
sudo apt update
sudo apt upgrade -y
```

### **Install Dependencies**
```bash
sudo apt install -y python3 python3-pip bpfcc-tools python3-bpfcc build-essential linux-headers-$(uname -r)
```

### **Test eBPF**
```bash
python3 -c "from bcc import BPF; print('✅ eBPF working!')"
```

### **Run Security Agent**
```bash
cd /media/sf_security_agent
sudo python3 security_agent.py --dashboard --threshold 30
```

### **Run Demo**
```bash
python3 demo/run_demo.py
```

### **Check System Info**
```bash
uname -a
lsb_release -a
```

## 🔧 **Troubleshooting Commands**

### **Fix eBPF Issues**
```bash
sudo apt install --reinstall bpfcc-tools python3-bpfcc
sudo reboot
```

### **Fix Shared Folder**
```bash
sudo usermod -a -G vboxsf $USER
sudo reboot
```

### **Check Processes**
```bash
ps aux | grep python
```

### **Check Kernel Modules**
```bash
lsmod | grep bpf
```

## 🎯 **Demo Commands**

### **Start Agent**
```bash
sudo python3 security_agent.py --dashboard --threshold 30
```

### **Run Normal Demo**
```bash
python3 demo/normal_behavior.py
```

### **Run Suspicious Demo**
```bash
python3 demo/suspicious_behavior.py
```

### **JSON Output**
```bash
sudo python3 security_agent.py --output json
```

## 📊 **Expected Output**
```
🛡️  Linux Security Agent - Real-Time Dashboard
===============================================
┌─────┬──────────────┬────────────┬──────────┬─────────────┐
│ PID │ Process Name │ Risk Score │ Syscalls │ Last Update │
├─────┼──────────────┼────────────┼──────────┼─────────────┤
│ 1   │ systemd      │ 4.0        │ 4        │ 14:30:25    │
│ 2   │ kthreadd     │ 2.0        │ 2        │ 14:30:24    │
└─────┴──────────────┴────────────┴──────────┴─────────────┘

Total Processes: 150+ | Total Syscalls: 1000+ | High Risk: 0
eBPF Monitoring: Active (Real system calls)
```

## 🎓 **Professor Demo Talking Points**
- "This is real eBPF system call monitoring"
- "No fallback messages - full kernel access"
- "Enterprise-grade Linux security agent"
- "Real-time threat detection and response"
- "Production-ready EDR system"
