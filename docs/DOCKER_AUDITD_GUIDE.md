# 🐳 Docker + Auditd Setup Guide

## Why Auditd Instead of eBPF?

**eBPF Issues:**
- Requires kernel headers and BCC tools
- May not work in all environments (VMs, containers)
- Can have permission/security restrictions
- Complex setup

**Auditd Advantages:**
- ✅ Works in Docker containers
- ✅ No kernel headers needed
- ✅ More reliable syscall capture
- ✅ Better for production environments
- ✅ Works in restricted environments

---

## Quick Start: Run with Auditd (No Docker)

```bash
# Install auditd
sudo apt-get install -y auditd

# Start auditd service
sudo systemctl start auditd
sudo systemctl enable auditd

# Run agent with auditd collector
sudo python3 core/enhanced_security_agent.py --collector auditd --dashboard --threshold 30
```

---

## Docker Setup with Auditd

### Option 1: Docker Compose (Recommended)

**1. Create `docker-compose.auditd.yml`:**

```yaml
version: '3.8'

services:
  security-agent:
    build:
      context: .
      dockerfile: Dockerfile.auditd
    privileged: true  # Still needed for some features
    volumes:
      - /var/log/audit:/var/log/audit:ro  # Read audit logs
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - ./config:/app/config:ro
    environment:
      - PYTHONUNBUFFERED=1
      - COLLECTOR=auditd
    command: ["--collector", "auditd", "--dashboard", "--threshold", "30"]
    restart: unless-stopped
    network_mode: "host"  # May need host network for auditd
```

**2. Create `Dockerfile.auditd`:**

```dockerfile
FROM ubuntu:22.04

# Install system dependencies (NO BCC - just auditd)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    auditd \
    procps \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app
WORKDIR /app

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Set entrypoint
ENTRYPOINT ["python3", "core/enhanced_security_agent.py"]
```

**3. Run:**

```bash
docker-compose -f docker-compose.auditd.yml up
```

---

### Option 2: Docker Run (Simple)

```bash
# Build image
docker build -f Dockerfile.auditd -t security-agent:auditd .

# Run container
docker run -it --rm \
  --privileged \
  -v /var/log/audit:/var/log/audit:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -e COLLECTOR=auditd \
  security-agent:auditd \
  --collector auditd --dashboard --threshold 30
```

---

## Setup Auditd on Host (For Docker)

**On your Linux VM/host:**

```bash
# Install auditd
sudo apt-get install -y auditd

# Configure auditd to log syscalls
sudo auditctl -a always,exit -S all

# Or add to /etc/audit/rules.d/audit.rules:
# -a always,exit -S all

# Restart auditd
sudo systemctl restart auditd

# Verify it's working
sudo tail -f /var/log/audit/audit.log
# Should see syscall events
```

---

## Testing Auditd Collector

**1. Check if auditd is running:**
```bash
sudo systemctl status auditd
```

**2. Check if audit logs exist:**
```bash
ls -la /var/log/audit/audit.log
```

**3. Generate test activity:**
```bash
# In one terminal
sudo python3 core/enhanced_security_agent.py --collector auditd --dashboard --threshold 30

# In another terminal
ls -R /home
ps aux
cat /etc/passwd
```

**4. Verify syscalls are being captured:**
```bash
# Should see processes appearing in dashboard
```

---

## Comparison: eBPF vs Auditd

| Feature | eBPF | Auditd |
|---------|------|--------|
| **Setup Complexity** | High (kernel headers, BCC) | Low (just install package) |
| **Docker Support** | Limited (needs privileged) | ✅ Works well |
| **Performance** | Very low overhead | Low overhead |
| **Syscall Coverage** | All syscalls | All syscalls |
| **Reliability** | Can fail in VMs | ✅ More reliable |
| **Production Ready** | ⚠️ Depends on env | ✅ Yes |

---

## Troubleshooting

### Auditd Not Capturing Events

**1. Check auditd is running:**
```bash
sudo systemctl status auditd
```

**2. Check audit rules:**
```bash
sudo auditctl -l
# Should show: -a always,exit -S all
```

**3. Check log file permissions:**
```bash
ls -la /var/log/audit/audit.log
# Should be readable
```

**4. Test auditd directly:**
```bash
# Generate activity
ls -R /home

# Check logs
sudo tail -20 /var/log/audit/audit.log | grep SYSCALL
# Should see syscall events
```

### Docker Issues

**If auditd logs aren't accessible:**
```bash
# Make sure volume mount is correct
docker run -v /var/log/audit:/var/log/audit:ro ...

# Check inside container
docker exec -it <container> ls -la /var/log/audit/
```

---

## Recommended Approach

**For your VM setup:**
1. ✅ Use auditd instead of eBPF (more reliable)
2. ✅ Run directly on VM (not Docker) for simplicity
3. ✅ Or use Docker with auditd if you prefer containerization

**Commands:**
```bash
# On VM - Simple approach
sudo apt-get install -y auditd
sudo systemctl start auditd
sudo systemctl enable auditd
sudo python3 core/enhanced_security_agent.py --collector auditd --dashboard --threshold 30
```

This should capture syscalls much more reliably than eBPF!

