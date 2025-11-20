# ⚠️ Mac Docker Limitation

## Issue

**Auditd doesn't work in Docker Desktop on Mac** because:
- Auditd requires kernel-level access to the Linux audit subsystem
- Docker Desktop runs Linux containers in a VM, but auditd needs direct kernel access
- The error: `Operation not permitted` when trying to set audit rules

## Solutions

### Option 1: Test on Linux VM (Recommended)
Your Linux VM (`agent@192.168.64.4`) is the best place to test:
- Native Linux kernel
- Full auditd support
- Real syscall capture

```bash
# On your Linux VM
sudo apt-get install -y auditd
sudo systemctl start auditd
sudo auditctl -a always,exit -S all
sudo python3 core/enhanced_security_agent.py --collector auditd --dashboard --threshold 30
```

### Option 2: Test Code Without Auditd
The Docker container can still test:
- Code execution
- ML models
- Dashboard rendering
- Configuration

But **won't capture real syscalls** without auditd.

### Option 3: Use Docker on Linux
If you have access to a Linux machine:
- Full auditd support
- Real syscall capture
- Production-like environment

## What Works on Mac Docker

✅ **Code runs** - Python code executes
✅ **ML models** - Training and inference work
✅ **Dashboard** - UI renders correctly
✅ **Configuration** - All config options work

❌ **Auditd** - Can't capture syscalls (kernel limitation)
❌ **eBPF** - Also needs kernel access (same issue)

## Recommendation

**For testing the full implementation:**
1. Use your Linux VM (`agent@192.168.64.4`)
2. Install auditd on the VM
3. Run directly on the VM (not Docker)

**For testing code/Docker setup:**
1. Mac Docker is fine
2. Can verify code runs
3. Can test configuration
4. Can't test syscall capture

## Next Steps

1. **On Linux VM:** Test with auditd (full functionality)
2. **On Mac Docker:** Test code execution (limited functionality)

The Docker setup is correct - it just needs a Linux host for auditd to work!

