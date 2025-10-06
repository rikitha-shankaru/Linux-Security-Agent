# 🍎 Running Linux Security Agent on macOS

Since you're on macOS, here are the best ways to run the Linux Security Agent:

## Option 1: Native macOS Version (Recommended)

The easiest way is to use the macOS-compatible version I created:

### Quick Start
```bash
# Activate virtual environment
source venv/bin/activate

# Run the macOS version
python3 security_agent_mac.py --dashboard

# Or with custom threshold
python3 security_agent_mac.py --dashboard --threshold 30
```

### Features Available on macOS
- ✅ Process monitoring using psutil
- ✅ Risk scoring based on simulated system calls
- ✅ Real-time dashboard
- ✅ JSON output
- ✅ Process risk assessment
- ❌ eBPF monitoring (Linux only)
- ❌ Actual system call interception (Linux only)

## Option 2: Docker (Full Linux Experience)

For the complete Linux experience with eBPF support:

### Prerequisites
1. Install Docker Desktop for Mac: https://www.docker.com/products/docker-desktop/
2. Start Docker Desktop

### Run with Docker
```bash
# Build and run the security agent
./run_on_mac.sh

# Or manually:
docker build -t security-agent .
docker run --rm -it --privileged security-agent --dashboard
```

### Docker Compose (Alternative)
```bash
# Run with docker-compose
docker-compose up

# Run in background
docker-compose up -d
```

## Option 3: Virtual Machine

For the most authentic Linux experience:

### Using VirtualBox
1. Install VirtualBox: https://www.virtualbox.org/
2. Download Ubuntu 22.04 LTS
3. Create a new VM with at least 2GB RAM
4. Install Ubuntu in the VM
5. Transfer the project files to the VM
6. Run the full Linux version with eBPF support

### Using UTM (Apple Silicon Macs)
1. Install UTM: https://mac.getutm.app/
2. Create a Linux VM
3. Install Ubuntu or your preferred Linux distribution
4. Run the security agent with full eBPF support

## 🚀 Quick Demo on macOS

Let's test the macOS version right now:

```bash
# 1. Start the macOS security agent
source venv/bin/activate
python3 security_agent_mac.py --dashboard --threshold 10

# 2. In another terminal, run the demo scripts
python3 demo/normal_behavior.py
python3 demo/suspicious_behavior.py
```

## 📊 What You'll See

### Normal Behavior Demo
- Low risk scores (0-20)
- Basic file operations
- Standard system commands

### Suspicious Behavior Demo
- High risk scores (50-100)
- Privilege escalation attempts
- Suspicious system calls

### Dashboard Output
```
┌─────┬──────────────┬────────────┬──────────┬─────────────┐
│ PID │ Process Name │ Risk Score │ Syscalls │ Last Update │
├─────┼──────────────┼────────────┼──────────┼─────────────┤
│1234 │ python3      │ 75.2       │ 45       │ 15:30:25    │
│5678 │ bash         │ 82.1       │ 38       │ 15:30:24    │
│9012 │ ls           │ 5.1        │ 12       │ 15:30:23    │
└─────┴──────────────┴────────────┴──────────┴─────────────┘
```

## 🔧 macOS-Specific Features

### Process Monitoring
- Monitors all running processes
- Simulates system calls based on process behavior
- Tracks resource usage (CPU, memory)
- Identifies suspicious process patterns

### Risk Assessment
- Same risk scoring algorithm as Linux version
- Categorizes processes by risk level
- Real-time risk score updates
- Anomaly detection (if scikit-learn is available)

### Safety Features
- No actual system call interception (safer for macOS)
- Process monitoring only
- No kernel-level modifications
- Safe to run without root privileges

## 🆚 Comparison: macOS vs Linux

| Feature | macOS Version | Linux Version |
|---------|---------------|---------------|
| Process Monitoring | ✅ | ✅ |
| Risk Scoring | ✅ | ✅ |
| Dashboard | ✅ | ✅ |
| JSON Output | ✅ | ✅ |
| eBPF Monitoring | ❌ | ✅ |
| Real Syscalls | ❌ | ✅ |
| Root Required | ❌ | ✅ |
| Kernel Access | ❌ | ✅ |
| Performance | Good | Excellent |

## 🎯 Recommendations

### For Learning and Testing
Use the **macOS version** - it's perfect for understanding how the security agent works without needing Linux.

### For Production Security
Use **Docker** or **Virtual Machine** to get the full Linux experience with eBPF monitoring.

### For Development
Use the **macOS version** for development and testing, then deploy the **Linux version** in production.

## 🚀 Getting Started Now

```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Run the macOS security agent
python3 security_agent_mac.py --dashboard

# 3. In another terminal, test with demos
python3 demo/run_demo.py
```

## 🔍 Troubleshooting

### Common Issues

1. **Import errors**: Make sure virtual environment is activated
2. **Permission errors**: macOS version doesn't need root privileges
3. **Performance issues**: macOS version is less efficient than Linux version
4. **Missing features**: Some advanced features require Linux

### Getting Help

- Check the logs for error messages
- Verify all dependencies are installed
- Try the demo scripts to test functionality
- Use the test suite: `python3 run_tests.py`

## 🎉 Next Steps

1. **Try the macOS version** to understand the concepts
2. **Run the demo scripts** to see risk scoring in action
3. **Explore the dashboard** to see real-time monitoring
4. **Consider Docker** for the full Linux experience
5. **Deploy on Linux** for production use

The macOS version gives you a great understanding of how the security agent works, even without the full Linux eBPF capabilities!
