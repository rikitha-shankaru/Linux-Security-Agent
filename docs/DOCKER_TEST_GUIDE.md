# 🐳 Docker Testing Guide

## Quick Start: Test in Docker Container

### Option 1: Docker Compose (Easiest)

```bash
# Build and run
docker-compose -f docker-compose.auditd.yml up --build

# Or run in background
docker-compose -f docker-compose.auditd.yml up -d --build

# View logs
docker-compose -f docker-compose.auditd.yml logs -f

# Stop
docker-compose -f docker-compose.auditd.yml down
```

### Option 2: Docker Run (More Control)

```bash
# Build image
docker build -f Dockerfile.auditd -t security-agent:auditd .

# Run container
docker run -it --rm \
  --name security-agent \
  --privileged \
  -v /var/log/audit:/var/log/audit:rw \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  --network host \
  security-agent:auditd \
  --collector auditd --train-models --dashboard --threshold 30
```

---

## Setup Auditd on Host (Recommended)

**For best results, run auditd on the host and mount logs:**

```bash
# On host (your VM)
sudo apt-get install -y auditd
sudo systemctl start auditd
sudo auditctl -a always,exit -S all

# Then run Docker container
docker-compose -f docker-compose.auditd.yml up --build
```

The container will read audit logs from the host.

---

## Testing the Implementation

### 1. Start Container

```bash
docker-compose -f docker-compose.auditd.yml up --build
```

### 2. Generate Test Activity

**In another terminal on the host:**

```bash
# Generate syscalls
while true; do
    ls -R /home > /dev/null 2>&1
    ps aux > /dev/null 2>&1
    cat /etc/passwd > /dev/null 2>&1
    sleep 0.5
done
```

### 3. Check Dashboard

The dashboard should show:
- Processes being captured
- Risk scores
- Syscall counts
- Real-time updates

### 4. Verify Audit Logs

```bash
# Check if audit logs are being written
sudo tail -f /var/log/audit/audit.log | grep SYSCALL

# Or from inside container
docker exec -it security-agent tail -f /var/log/audit/audit.log | grep SYSCALL
```

---

## Troubleshooting

### Container Can't Access Audit Logs

**Solution:** Make sure auditd is running on host and logs are accessible:

```bash
# On host
sudo chmod 644 /var/log/audit/audit.log
sudo systemctl restart auditd
```

### No Syscalls Being Captured

**Check:**
1. Is auditd running on host?
   ```bash
   sudo systemctl status auditd
   ```

2. Are audit rules set?
   ```bash
   sudo auditctl -l
   # Should show: -a always,exit -S all
   ```

3. Are logs being written?
   ```bash
   sudo tail -20 /var/log/audit/audit.log
   ```

### Container Exits Immediately

**Check logs:**
```bash
docker-compose -f docker-compose.auditd.yml logs
```

**Common issues:**
- Missing dependencies → Check Dockerfile
- Permission errors → Use `--privileged` flag
- Auditd not starting → Check entrypoint script

---

## Alternative: Run Auditd Inside Container

If you want auditd to run inside the container:

```bash
# Run with auditd service
docker run -it --rm \
  --name security-agent \
  --privileged \
  --cap-add AUDIT_CONTROL \
  --cap-add AUDIT_WRITE \
  -v /var/log/audit:/var/log/audit:rw \
  security-agent:auditd \
  --collector auditd --dashboard --threshold 30
```

**Note:** This is less reliable than using host auditd.

---

## Quick Test Commands

```bash
# Build and test
docker-compose -f docker-compose.auditd.yml build
docker-compose -f docker-compose.auditd.yml up

# Test without training
docker-compose -f docker-compose.auditd.yml run --rm security-agent \
  --collector auditd --dashboard --threshold 30

# Test with stats only
docker-compose -f docker-compose.auditd.yml run --rm security-agent \
  --collector auditd --stats

# Interactive shell for debugging
docker-compose -f docker-compose.auditd.yml run --rm security-agent /bin/bash
```

---

## Expected Results

**When working correctly, you should see:**

1. ✅ Container starts successfully
2. ✅ Auditd service running (or using host auditd)
3. ✅ Training collects 50+ samples (not 0)
4. ✅ Dashboard shows processes
5. ✅ Real-time updates working
6. ✅ Syscalls being captured and displayed

---

## Next Steps

Once Docker setup works:
1. Test with different workloads
2. Test threat intelligence features
3. Test response handler
4. Performance testing
5. Scale testing

