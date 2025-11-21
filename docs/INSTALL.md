# Linux Security Agent - Installation Guide

> **Author**: Master's Student Research Project  
> **Note**: This installation guide was prepared for a Master's research project.

## System Requirements

### Operating System
- **Linux**: Kernel 4.1 or higher (Ubuntu 18.04+, CentOS 7+, RHEL 7+, Debian 9+)
- **macOS**: macOS 10.14 or higher (with simulation mode)
- Root privileges required for eBPF monitoring on Linux (not required on macOS)

### Hardware Requirements
- CPU: x86_64 architecture
- RAM: 512MB minimum, 2GB recommended
- Disk: 100MB for installation, additional space for logs

### Software Dependencies
- Python 3.7 or higher
- **Linux**: BCC (Berkeley Packet Capture) tools
- **macOS**: psutil library (no eBPF support)
- Standard development tools

## Installation Methods

### Method 1: Manual Installation

#### Step 1: Install System Dependencies

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev
sudo apt-get install -y bpfcc-tools python3-bpfcc
sudo apt-get install -y build-essential linux-headers-$(uname -r)
```

**Linux (CentOS/RHEL):**
```bash
sudo yum update
sudo yum install -y python3 python3-pip python3-devel
sudo yum install -y bcc-tools python3-bcc
sudo yum install -y gcc kernel-devel
```

**Linux (Fedora):**
```bash
sudo dnf update
sudo dnf install -y python3 python3-pip python3-devel
sudo dnf install -y bcc-tools python3-bcc
sudo dnf install -y gcc kernel-devel
```

**macOS:**
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and dependencies
brew install python3
```

#### Step 2: Install Python Dependencies

```bash
# Clone or download the project
git clone <repository-url>
cd linux_security_agent

# Install Python dependencies
pip3 install -r requirements.txt
```

#### Step 3: Verify Installation

**Linux:**
```bash
# Test BCC installation
sudo python3 -c "from bcc import BPF; print('BCC is working')"

# Test the security agent
sudo python3 core/simple_agent.py --help
```

**macOS:**
```bash
# Test psutil installation
python3 -c "import psutil; print('psutil is working')"

# Test the security agent (Linux only - no macOS version)
sudo python3 core/simple_agent.py --help
```

### Method 2: Docker Installation

#### Step 1: Create Dockerfile

```dockerfile
FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev \
    bpfcc-tools python3-bpfcc \
    build-essential linux-headers-$(uname -r) \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app
WORKDIR /app

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Set entrypoint
ENTRYPOINT ["python3", "core/simple_agent.py"]
```

#### Step 2: Build and Run

```bash
# Build Docker image
docker build -t security-agent .

# Run with privileged mode (required for eBPF)
docker run --privileged --rm -it security-agent --dashboard
```

### Method 3: Package Installation

#### Create DEB Package

```bash
# Create package structure
mkdir -p security-agent-1.0/usr/local/bin
mkdir -p security-agent-1.0/usr/local/lib/python3.8/site-packages
mkdir -p security-agent-1.0/etc/security-agent
mkdir -p security-agent-1.0/var/log

# Copy files
cp core/simple_agent.py security-agent-1.0/usr/local/bin/core/simple_agent.py
cp *.py security-agent-1.0/usr/local/lib/python3.8/site-packages/
cp requirements.txt security-agent-1.0/etc/security-agent/

# Create control file
cat > security-agent-1.0/DEBIAN/control << EOF
Package: security-agent
Version: 1.0
Section: security
Priority: optional
Architecture: amd64
Depends: python3, bpfcc-tools, python3-bpfcc
Maintainer: Your Name <your.email@example.com>
Description: Linux Security Agent for system call monitoring
EOF

# Build package
dpkg-deb --build security-agent-1.0
```

#### Install DEB Package

```bash
sudo dpkg -i security-agent_1.0_amd64.deb
```

## Configuration

### Environment Variables

```bash
# Set default configuration
export SECURITY_AGENT_THRESHOLD=50
export SECURITY_AGENT_LOG_FILE=/var/log/security_agent.log
export SECURITY_AGENT_ENABLE_KILL=false
```

### Configuration File

Create `/etc/security-agent/config.json`:

```json
{
    "threshold": 50.0,
    "warn_threshold": 30.0,
    "freeze_threshold": 70.0,
    "kill_threshold": 90.0,
    "enable_warnings": true,
    "enable_freeze": true,
    "enable_kill": false,
    "log_file": "/var/log/security_agent.log",
    "anomaly_detection": true,
    "dashboard": true
}
```

### Systemd Service

Create `/etc/systemd/system/security-agent.service`:

```ini
[Unit]
Description=Linux Security Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/core/simple_agent.py --collector ebpf --dashboard --threshold 30
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable security-agent
sudo systemctl start security-agent
```

## Verification

### Test Installation

**Linux:**
```bash
# Test basic functionality
sudo python3 core/simple_agent.py --help

# Test with demo scripts
cd demo
python3 normal_behavior.py
python3 suspicious_behavior.py

# Test monitoring
sudo python3 core/simple_agent.py --dashboard --threshold 10
```

**macOS:**
```bash
# Test basic functionality
python3 core/simple_agent.py --help

# Test with demo scripts
cd demo
python3 normal_behavior.py
python3 suspicious_behavior.py

# Test monitoring with timeout
python3 core/simple_agent.py --dashboard --threshold 10 --timeout 30
```

### Check Logs

```bash
# Check system logs
sudo journalctl -u security-agent -f

# Check action logs
sudo tail -f /var/log/security_agent.log
```

### Verify eBPF

```bash
# Check if eBPF is working
sudo python3 -c "
from bcc import BPF
import time

# Simple eBPF program
prog = '''
int hello(void *ctx) {
    bpf_trace_printk(\"Hello, World!\\n\");
    return 0;
}
'''

b = BPF(text=prog)
b.attach_kprobe(event='sys_open', fn_name='hello')
print('eBPF is working!')
time.sleep(1)
b.detach_kprobe(event='sys_open')
"
```

## Troubleshooting

### Common Installation Issues

#### 1. BCC Installation Fails

**Problem**: BCC tools not available or installation fails

**Solution**:
```bash
# Try alternative installation methods
sudo apt-get install -y bpfcc-tools python3-bpfcc

# Or compile from source
git clone https://github.com/iovisor/bcc.git
cd bcc
mkdir build && cd build
cmake ..
make
sudo make install
```

#### 2. Kernel Headers Missing

**Problem**: `linux-headers-$(uname -r)` not found

**Solution**:
```bash
# Install kernel headers
sudo apt-get install -y linux-headers-$(uname -r)

# Or install generic headers
sudo apt-get install -y linux-headers-generic
```

#### 3. Python Dependencies Fail

**Problem**: pip install fails for some packages

**Solution**:
```bash
# Upgrade pip
pip3 install --upgrade pip

# Install dependencies one by one
pip3 install bcc
pip3 install psutil
pip3 install scikit-learn
pip3 install numpy
pip3 install pandas
pip3 install colorama
pip3 install rich
pip3 install click
```

#### 4. Permission Denied

**Problem**: Cannot access eBPF or system files

**Solution (Linux):**
```bash
# Ensure running as root
sudo python3 core/simple_agent.py

# Check capabilities
sudo setcap cap_sys_admin+ep /usr/bin/python3

# Or use sudoers
echo "security-agent ALL=(ALL) NOPASSWD: /usr/local/bin/core/simple_agent.py" | sudo tee /etc/sudoers.d/security-agent
```

**Solution (macOS):**
```bash
# macOS version doesn't require root privileges
python3 core/simple_agent.py --dashboard

# If you get permission errors, check file permissions
chmod +x core/simple_agent.py
```

### Performance Issues

#### 1. High CPU Usage

**Problem**: Agent consumes too much CPU

**Solution**:
```bash
# Use eBPF instead of fallback mode
sudo python3 core/simple_agent.py --use-ebpf

# Reduce monitoring frequency
# Edit the code to increase sleep intervals
```

#### 2. Memory Usage

**Problem**: High memory consumption

**Solution**:
```bash
# Limit process history
# Edit the code to reduce maxlen in deque

# Use JSON output instead of dashboard
sudo python3 core/simple_agent.py --output json
```

### Security Issues

#### 1. Log File Permissions

**Problem**: Log files not accessible

**Solution**:
```bash
# Set proper permissions
sudo chown root:root /var/log/security_agent.log
sudo chmod 600 /var/log/security_agent.log

# Or use syslog
sudo python3 core/simple_agent.py --action-log /dev/log
```

#### 2. Action Permissions

**Problem**: Cannot take actions on processes

**Solution**:
```bash
# Check if running as root
whoami

# Check process permissions
ps aux | grep security_agent

# Test action manually
sudo kill -USR1 <pid>
```

## Uninstallation

### Remove Manual Installation

```bash
# Stop service if running
sudo systemctl stop security-agent
sudo systemctl disable security-agent

# Remove files
sudo rm -rf /usr/local/bin/core/simple_agent.py
sudo rm -rf /usr/local/lib/python3.8/site-packages/security_agent*
sudo rm -rf /etc/security-agent
sudo rm -rf /var/log/security_agent.log

# Remove systemd service
sudo rm -f /etc/systemd/system/security-agent.service
sudo systemctl daemon-reload
```

### Remove Package Installation

```bash
# Remove DEB package
sudo dpkg -r security-agent

# Remove dependencies (optional)
sudo apt-get autoremove
```

### Remove Docker Installation

```bash
# Remove Docker image
docker rmi security-agent

# Remove containers
docker rm $(docker ps -aq --filter ancestor=security-agent)
```

## Support
---

## VM Quick Setup Tips (VirtualBox + Ubuntu)

- Allocate 4GB RAM, 25GB disk; enable PAE/NX; 2 CPUs if available.
- Install Guest Additions; set a shared folder to your project path and add user to `vboxsf`.
- Fast commands:
  ```bash
  sudo apt update && sudo apt install -y \
    python3 python3-pip python3-dev \
    bpfcc-tools python3-bpfcc \
    build-essential linux-headers-$(uname -r)
  python3 -c "from bcc import BPF; print('✅ eBPF working')"
  ```
-
 Common fixes:
  - Shared folder: `sudo usermod -a -G vboxsf $USER && sudo reboot`
  - eBPF missing: `sudo apt install -y bpfcc-tools python3-bpfcc && sudo reboot`

### Getting Help

1. Check the logs: `/var/log/security_agent.log`
2. Review the documentation: `README.md`, `USAGE.md`
3. Test with demo scripts: `demo/` directory
4. Check system requirements and dependencies

### Reporting Issues

When reporting issues, include:
- Operating system and version
- Kernel version (`uname -r`)
- Python version (`python3 --version`)
- BCC version (`dpkg -l | grep bcc`)
- Error messages and logs
- Steps to reproduce the issue
