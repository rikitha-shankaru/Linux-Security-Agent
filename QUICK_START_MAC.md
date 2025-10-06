# 🚀 Quick Start Guide for macOS

## You're on macOS - Here's How to Run the Security Agent

### Option 1: Native macOS Version (Easiest)

```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Run the macOS security agent with timeout (auto-stop after 30 seconds)
python3 security_agent_mac.py --dashboard --timeout 30

# 3. In another terminal, test with demos
python3 demo/run_demo.py
```

### Option 2: Docker (Full Linux Experience)

```bash
# 1. Install Docker Desktop for Mac
# 2. Run the security agent in Docker
./run_on_mac.sh
```

### Option 3: Virtual Machine

1. Install VirtualBox or UTM
2. Create Ubuntu VM
3. Transfer project files
4. Run full Linux version with eBPF

## 🎯 What You'll See

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

### Demo Results
- **Normal behavior**: Low risk scores (0-20)
- **Suspicious behavior**: High risk scores (50-100)

## 🔧 Available Commands

```bash
# Basic monitoring
python3 security_agent_mac.py --dashboard

# Custom threshold
python3 security_agent_mac.py --dashboard --threshold 30

# With timeout (auto-stop after 30 seconds)
python3 security_agent_mac.py --dashboard --threshold 30 --timeout 30

# JSON output
python3 security_agent_mac.py --output json

# Help
python3 security_agent_mac.py --help
```

## 📊 Features Available on macOS

- ✅ Process monitoring
- ✅ Risk scoring
- ✅ Real-time dashboard
- ✅ JSON output
- ✅ Demo scripts
- ✅ Timeout support (auto-stop)
- ✅ Graceful exit (Ctrl+C)
- ❌ eBPF monitoring (Linux only)
- ❌ Real system call interception (Linux only)

## 🎉 Ready to Go!

The macOS version gives you a great understanding of how the security agent works. For the full Linux experience with eBPF, use Docker or a virtual machine.

**Start now:**
```bash
source venv/bin/activate
python3 security_agent_mac.py --dashboard --timeout 30
```

## 🆕 Recent Improvements

- ✅ **Fixed NoneType errors** - No more comparison errors
- ✅ **Added timeout support** - Auto-stop after specified seconds
- ✅ **Graceful exit** - Clean shutdown with Ctrl+C
- ✅ **Better error handling** - Robust error recovery
- ✅ **Updated documentation** - Comprehensive guides
