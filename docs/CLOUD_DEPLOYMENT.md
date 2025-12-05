# Cloud VM Deployment Guide

> **Author**: Likitha Shankar  
> **Updated**: December 5, 2024  
> **Verified**: Google Cloud VM (Ubuntu 22.04 LTS)

This project **requires a Linux VM with full kernel access** for eBPF functionality. This guide covers deployment on major cloud providers.

---

## ✅ Verified Working Configuration

**Successfully tested on:**
- **Provider**: Google Cloud Platform
- **OS**: Ubuntu 22.04 LTS
- **Kernel**: 6.8.0-1044-gcp
- **Instance**: e2-medium (2 vCPU, 4 GB RAM)
- **eBPF**: Fully functional at kernel level
- **Performance**: 26,270 syscalls/second capture rate

---

## 🚀 Quick Start (Google Cloud)

### 1. Create VM Instance

```bash
# Via Google Cloud Console:
# - Compute Engine > VM Instances > Create Instance
# - Machine type: e2-medium or higher
# - Boot disk: Ubuntu 22.04 LTS
# - Firewall: Allow SSH (port 22)

# Via gcloud CLI:
gcloud compute instances create security-agent-vm \
  --zone=us-east1-b \
  --machine-type=e2-medium \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB
```

### 2. Connect to VM

```bash
# Get external IP
gcloud compute instances list

# SSH into VM
gcloud compute ssh security-agent-vm --zone=us-east1-b

# Or use SSH key
ssh username@EXTERNAL_IP
```

### 3. Install Dependencies

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install eBPF/BCC tools
sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

# Install Docker (optional, for container monitoring)
sudo apt-get install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker

# Install Python dependencies
sudo apt-get install -y python3-pip git
```

### 4. Clone and Setup Project

```bash
# Clone repository
git clone https://github.com/likitha-shankar/Linux-Security-Agent.git
cd Linux-Security-Agent

# Install Python packages
pip3 install --user -r requirements.txt

# Or install system-wide (for sudo use)
sudo pip3 install -r requirements.txt
```

### 5. Verify eBPF Working

```bash
# Test eBPF import
python3 -c "from bcc import BPF; print('✅ eBPF/BCC working!')"

# Test simple eBPF program
sudo python3 << 'EOF'
from bcc import BPF
prog = """
int hello(void *ctx) {
    bpf_trace_printk("eBPF working!\\n");
    return 0;
}
"""
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
print("✅ eBPF loaded into kernel successfully!")
EOF
```

### 6. Train ML Models

```bash
# Train models with provided dataset
python3 scripts/train_with_dataset.py --file datasets/normal_behavior_dataset.json

# Verify models saved
ls -lh ~/.cache/security_agent/
```

### 7. Run the Agent

```bash
# Simple agent with eBPF
sudo python3 core/simple_agent.py --collector ebpf --threshold 30

# Enhanced agent with all features
sudo python3 core/enhanced_security_agent.py --collector ebpf --dashboard
```

---

## 🔧 Other Cloud Providers

### AWS EC2

```bash
# Launch instance:
# - AMI: Ubuntu Server 22.04 LTS
# - Instance type: t3.medium or higher
# - Security group: Allow SSH (port 22)
# - Key pair: Create or use existing

# Connect:
ssh -i your-key.pem ubuntu@ec2-instance-ip

# Follow steps 3-7 above
```

### Oracle Cloud (Free Tier)

```bash
# Create instance:
# - Image: Canonical Ubuntu 22.04
# - Shape: VM.Standard.E2.1.Micro (free tier)
# - VCN: Allow SSH ingress

# Connect:
ssh -i ~/.ssh/id_rsa ubuntu@instance-ip

# Follow steps 3-7 above
```

### Azure VM

```bash
# Create VM:
az vm create \
  --resource-group myResourceGroup \
  --name security-agent-vm \
  --image Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest \
  --size Standard_B2s \
  --admin-username azureuser \
  --generate-ssh-keys

# Connect:
ssh azureuser@vm-public-ip

# Follow steps 3-7 above
```

---

## 📊 Performance Verification

Test your deployment:

```bash
# Simple eBPF test (10 seconds)
sudo python3 core/test_ebpf.py

# Full monitoring test (30 seconds)
sudo python3 << 'EOF'
from core.collectors.ebpf_collector import EBPFCollector
from collections import defaultdict
import time

processes = defaultdict(int)

def count_event(event):
    processes[event.pid] += 1

collector = EBPFCollector()
collector.start_monitoring(count_event)

print("Monitoring for 30 seconds...")
time.sleep(30)
collector.stop_monitoring()

total = sum(processes.values())
print(f"\n✅ Captured {total:,} syscalls in 30 seconds")
print(f"✅ Rate: {total/30:,.0f} syscalls/second")
print(f"✅ Processes monitored: {len(processes)}")
EOF
```

**Expected results:**
- Syscall capture rate: 20K-30K syscalls/second (depending on VM activity)
- Processes monitored: 10-20 concurrent processes
- Zero errors from eBPF loading

---

## 🔒 Security Considerations

### For Cloud VMs:

1. **Firewall Rules**
   ```bash
   # Restrict SSH to your IP only
   # Don't expose agent ports publicly
   ```

2. **User Permissions**
   ```bash
   # Create dedicated user for agent
   sudo useradd -m -s /bin/bash secagent
   sudo usermod -aG docker secagent
   
   # Configure passwordless sudo for agent only
   echo "secagent ALL=(ALL) NOPASSWD: /usr/bin/python3 /path/to/agent" | sudo tee /etc/sudoers.d/secagent
   ```

3. **Data Storage**
   ```bash
   # Agent stores data in ~/.cache/security_agent/
   # Ensure secure permissions (already set to 0o700)
   ls -la ~/.cache/security_agent/
   ```

---

## 🐛 Troubleshooting

### eBPF Not Loading

```bash
# Check kernel version (need 4.9+)
uname -r

# Install kernel headers
sudo apt-get install linux-headers-$(uname -r)

# Check BCC installation
python3 -c "import bcc; print(bcc.__version__)"

# Try loading simple eBPF program
sudo python3 -c "from bcc import BPF; BPF(text='int hello() { return 0; }')"
```

### Permission Denied

```bash
# Ensure running with sudo
sudo python3 core/simple_agent.py --collector ebpf

# Check capabilities
sudo getcap /usr/bin/python3

# Run with explicit capabilities (alternative to sudo)
sudo setcap cap_sys_admin,cap_bpf+ep /usr/bin/python3.10
```

### Module Not Found

```bash
# Install dependencies system-wide
sudo pip3 install -r requirements.txt

# Or use --user but run without sudo
pip3 install --user -r requirements.txt
python3 core/enhanced_security_agent.py --train-models
```

---

## 📝 Maintenance

### Update Code

```bash
cd ~/Linux-Security-Agent
git pull origin main
sudo pip3 install -r requirements.txt  # If dependencies changed
```

### Retrain Models

```bash
# Retrain with new data
python3 scripts/train_with_dataset.py --file datasets/normal_behavior_dataset.json --append

# Or collect live data and retrain
python3 core/enhanced_security_agent.py --train-models
```

### Monitor Logs

```bash
# Check agent logs (if logging enabled)
tail -f ~/.cache/security_agent/agent.log

# Check system logs
sudo journalctl -f | grep python3
```

---

## 🎓 Academic Use

**For demonstrating to professors:**

1. Share VM IP (with restricted access)
2. Provide SSH key for temporary access
3. Run live demo:
   ```bash
   sudo python3 core/simple_agent.py --collector ebpf --threshold 30
   ```
4. Show verification:
   ```bash
   cat BRUTAL_REVIEW_FINDINGS.md
   python3 tests/test_ml_anomaly_detector.py
   ```

---

## 📊 Verified Metrics

**On Google Cloud VM (e2-medium, Ubuntu 22.04):**

| Metric | Value | Verified |
|--------|-------|----------|
| Syscall capture rate | 26,270/sec | ✅ |
| Process monitoring | 15+ concurrent | ✅ |
| ML detection | 50-D features, 3 models | ✅ |
| eBPF kernel loading | Success | ✅ |
| All tests passing | 5/5 | ✅ |

---

## 🔗 References

- [Google Cloud Compute Engine](https://cloud.google.com/compute)
- [AWS EC2](https://aws.amazon.com/ec2/)
- [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/)
- [eBPF Documentation](https://ebpf.io/)
- [BCC Tools](https://github.com/iovisor/bcc)

---

**Last Updated**: December 5, 2024  
**Verified By**: Likitha Shankar  
**VM**: 136.112.137.224 (Google Cloud, Ubuntu 22.04)

