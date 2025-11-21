# SSH Connection Troubleshooting

**Author:** Likitha Shankar  
**Last Updated:** November 2024

## Quick Troubleshooting Steps

### 1. Test Network Connectivity

From your Mac, test if you can reach the VM:

```bash
# Ping the VM
ping 192.168.64.4

# If ping works, try telnet to port 22
telnet 192.168.64.4 22
# or
nc -zv 192.168.64.4 22
```

**If ping fails:**
- Check UTM network settings
- Verify VM IP address hasn't changed
- Check if VM is running

### 2. Check Firewall on VM

```bash
# On VM, check firewall status
sudo ufw status

# If firewall is active, allow SSH
sudo ufw allow ssh
sudo ufw allow 22/tcp

# Or temporarily disable firewall to test
sudo ufw disable
# (Remember to re-enable after testing!)
```

### 3. Check SSH Configuration

```bash
# On VM, check SSH config
sudo nano /etc/ssh/sshd_config

# Make sure these are set:
# PermitRootLogin yes (or no, depending on preference)
# PasswordAuthentication yes
# PubkeyAuthentication yes
# Port 22

# After editing, restart SSH
sudo systemctl restart ssh
```

### 4. Check SSH Logs

```bash
# On VM, watch SSH logs in real-time
sudo tail -f /var/log/auth.log

# Then try connecting from Mac - you'll see what's happening
```

### 5. Verify SSH is Actually Running

```bash
# On VM
sudo systemctl status ssh
sudo ss -tlnp | grep :22
ps aux | grep sshd
```

### 6. Test SSH Connection with Verbose Output

From your Mac:

```bash
# Connect with verbose output to see what's happening
ssh -v agent@192.168.64.4

# Or even more verbose
ssh -vvv agent@192.168.64.4
```

This will show you exactly where the connection is failing.

### 7. Check UTM Network Settings

If using UTM on Mac:

1. Open UTM
2. Select your VM
3. Go to Settings → Network
4. Make sure:
   - Network Mode is "Shared Network" or "Bridged"
   - Network is enabled
5. Restart the VM

### 8. Find Current VM IP Address

```bash
# On VM, check current IP
ip addr show
# or
hostname -I

# The IP might have changed!
```

### 9. Common Error Messages and Fixes

#### "Connection refused"
```bash
# SSH service might not be running
sudo systemctl start ssh
sudo systemctl enable ssh
```

#### "Connection timed out"
```bash
# Firewall might be blocking
sudo ufw allow ssh
# Or check if VM IP changed
```

#### "Permission denied (publickey)"
```bash
# Try with password authentication
ssh -o PreferredAuthentications=password agent@192.168.64.4
```

#### "Host key verification failed"
```bash
# Remove old host key from Mac
ssh-keygen -R 192.168.64.4
# Then try connecting again
```

### 10. Alternative: Use UTM's Built-in Terminal

If SSH still doesn't work:
1. Open UTM
2. Click on your VM window
3. Use the VM's built-in terminal directly
4. No SSH needed for local access

## Quick Test Script

Save this as `test_ssh.sh` on your Mac:

```bash
#!/bin/bash
VM_IP="192.168.64.4"
VM_USER="agent"

echo "Testing connectivity to $VM_IP..."
ping -c 3 $VM_IP

echo -e "\nTesting SSH port..."
nc -zv $VM_IP 22

echo -e "\nAttempting SSH connection..."
ssh -v $VM_USER@$VM_IP "echo 'SSH connection successful!'"
```

Make it executable and run:
```bash
chmod +x test_ssh.sh
./test_ssh.sh
```

## Still Not Working?

1. **Check if VM IP changed:**
   ```bash
   # On VM
   hostname -I
   ```

2. **Try connecting from VM to itself:**
   ```bash
   # On VM
   ssh localhost
   # If this works, SSH is fine, issue is network
   ```

3. **Check Mac's firewall:**
   ```bash
   # On Mac
   # System Settings → Network → Firewall
   # Make sure it's not blocking outbound connections
   ```

4. **Try different network mode in UTM:**
   - Switch from "Shared Network" to "Bridged" or vice versa
   - Restart VM

---

**Note:** If you're using UTM and the IP keeps changing, consider setting a static IP or using the VM's hostname instead of IP.

