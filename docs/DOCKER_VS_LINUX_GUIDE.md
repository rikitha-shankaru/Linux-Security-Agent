# Docker vs Linux Setup Guide

## 🎯 Quick Answer

**Docker works, but you need a Linux host** (or Docker Desktop which uses a Linux VM).

## 📋 Options Comparison

### Option 1: Native Linux (Recommended for Best Performance)
✅ **Best for:** Production, development, full eBPF features  
✅ **Pros:**
- Full eBPF support with best performance
- Direct kernel access
- No container overhead
- Easier debugging

❌ **Cons:**
- Requires Linux machine or VM
- Need root/sudo access

### Option 2: Docker on Linux Host
✅ **Best for:** Containerized deployments, isolation  
✅ **Pros:**
- Isolated environment
- Easy to deploy
- Reproducible setup
- Works on any Linux host

❌ **Cons:**
- Requires `--privileged` mode (security consideration)
- Slightly more overhead
- Must run on Linux host

### Option 3: Docker Desktop (Mac/Windows)
⚠️ **Best for:** Development/testing only  
✅ **Pros:**
- Works on Mac/Windows
- No need for separate Linux VM

❌ **Cons:**
- Uses Linux VM under the hood anyway
- Performance overhead
- May have limitations with eBPF
- Not ideal for production

### Option 4: Linux VM (VirtualBox, VMware, etc.)
✅ **Best for:** Development, learning, testing  
✅ **Pros:**
- Full Linux environment
- Isolated from host
- Can test without affecting host system

❌ **Cons:**
- Requires VM software
- More resource usage
- Setup overhead

---

## 🐳 Docker Setup (If You Choose Docker)

### Prerequisites
- **Linux host** OR Docker Desktop (Mac/Windows)
- Docker installed
- Kernel 4.1+ (on Linux host)

### Quick Start with Docker

```bash
# 1. Build the image
cd /path/to/linux_security_agent
docker build -f config/Dockerfile -t security-agent .

# 2. Run with privileged mode (required for eBPF)
docker run --privileged --rm -it \
  -v /var/log:/var/log:rw \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  security-agent \
  python3 core/enhanced_security_agent.py --dashboard --threshold 30

# OR use docker-compose
cd config
docker-compose up
```

### Important Docker Notes

1. **`--privileged` is REQUIRED** for eBPF to work
   - This gives the container full kernel access
   - Security consideration: only use on trusted systems

2. **Volume Mounts:**
   - `/proc` - Process information
   - `/sys` - System information
   - `/var/log` - Logs (optional)

3. **Alternative: Use auditd collector** (less privileged)
   ```bash
   # Run with auditd instead of eBPF (no --privileged needed)
   docker run --rm -it \
     -v /var/log/audit:/var/log/audit:ro \
     security-agent \
     python3 core/enhanced_security_agent.py --collector auditd --dashboard
   ```

---

## 🐧 Native Linux Setup (Recommended)

### Quick Start on Linux

```bash
# 1. Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y \
  python3 python3-pip python3-dev \
  bpfcc-tools python3-bpfcc \
  build-essential linux-headers-$(uname -r)

# 2. Install Python packages
pip3 install -r requirements.txt

# 3. Run the agent
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30
```

### Why Native Linux is Better

1. **Performance:** Direct kernel access, no container overhead
2. **Features:** Full eBPF capabilities
3. **Debugging:** Easier to troubleshoot
4. **Security:** No need for `--privileged` containers

---

## 🖥️ Linux VM Setup (If You Don't Have Linux)

### Option A: VirtualBox + Ubuntu

1. **Install VirtualBox:**
   - Download from: https://www.virtualbox.org/
   - Install on your Mac/Windows

2. **Create Ubuntu VM:**
   - Download Ubuntu 20.04+ ISO
   - Create VM with 4GB RAM, 25GB disk
   - Install Ubuntu

3. **Install in VM:**
   ```bash
   # In the Ubuntu VM
   sudo apt-get update
   sudo apt-get install -y python3 python3-pip python3-dev \
     bpfcc-tools python3-bpfcc build-essential linux-headers-$(uname -r)
   
   # Clone your project or use shared folder
   git clone <your-repo>
   cd linux_security_agent
   pip3 install -r requirements.txt
   
   # Run
   sudo python3 core/enhanced_security_agent.py --dashboard
   ```

### Option B: WSL2 (Windows Only)

```bash
# In WSL2 Ubuntu
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev \
  bpfcc-tools python3-bpfcc build-essential linux-headers-$(uname -r)

# Note: WSL2 has some eBPF limitations, may need to use auditd fallback
```

---

## 🔍 Which Should You Choose?

### Choose **Native Linux** if:
- ✅ You have a Linux machine
- ✅ You want best performance
- ✅ You're doing production work
- ✅ You need full eBPF features

### Choose **Docker** if:
- ✅ You have a Linux host
- ✅ You want containerized deployment
- ✅ You need isolation
- ✅ You're deploying to Kubernetes

### Choose **Linux VM** if:
- ✅ You're on Mac/Windows
- ✅ You want full Linux experience
- ✅ You're learning/developing
- ✅ You don't want Docker overhead

### Choose **Docker Desktop** if:
- ✅ You're on Mac/Windows
- ✅ You just want to test quickly
- ✅ You don't need production performance
- ⚠️ Note: May have eBPF limitations

---

## 🚀 Recommended Setup for Different Scenarios

### For Development/Testing
1. **Mac/Windows:** Use Linux VM (VirtualBox) → Native Linux setup
2. **Linux:** Use native Linux setup directly

### For Production
1. **Linux Server:** Native Linux setup (best performance)
2. **Containerized:** Docker on Linux host with `--privileged`

### For Quick Testing
1. **Any OS:** Docker Desktop (if available)
2. **Linux:** Native setup (fastest)

---

## ⚠️ Important Notes

### eBPF Requirements
- **Kernel 4.1+** required
- **Root/privileged access** required
- **Linux kernel** (not available on macOS/Windows natively)

### Security Considerations
- `--privileged` Docker containers have full host access
- Only use on trusted systems
- Consider using auditd collector for less privileged operation

### Performance
- Native Linux: Best performance
- Docker on Linux: Slight overhead (~5-10%)
- Docker Desktop: More overhead (~10-20%)
- VM: Depends on resources allocated

---

## 📝 Quick Commands Reference

### Docker (Linux Host)
```bash
docker build -f config/Dockerfile -t security-agent .
docker run --privileged --rm -it security-agent \
  python3 core/enhanced_security_agent.py --dashboard
```

### Native Linux
```bash
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30
```

### Docker with auditd (less privileged)
```bash
docker run --rm -it \
  -v /var/log/audit:/var/log/audit:ro \
  security-agent \
  python3 core/enhanced_security_agent.py --collector auditd --dashboard
```

---

## 🎓 My Recommendation

**For your use case (research/academic project):**

1. **If you have a Linux machine:** Use native Linux setup
2. **If you're on Mac/Windows:** 
   - **Best:** Set up a Linux VM (VirtualBox) → then native Linux
   - **Quick test:** Docker Desktop (but may have limitations)
3. **If deploying:** Docker on Linux host with `--privileged`

**Bottom line:** Docker works, but you still need a Linux kernel underneath. For best results, use native Linux (either directly or in a VM).

---

**Last Updated:** January 2025

