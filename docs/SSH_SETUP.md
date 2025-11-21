# SSH Connection Setup Guide

**Author:** Likitha Shankar  
**Last Updated:** November 2024

This guide explains how to enable and configure SSH connections for the Linux Security Agent project.

## Enable SSH on Linux VM

### 1. Install SSH Server (if not already installed)

```bash
# On Ubuntu/Debian
sudo apt update
sudo apt install openssh-server

# On CentOS/RHEL
sudo yum install openssh-server
# or for newer versions
sudo dnf install openssh-server
```

### 2. Start SSH Service

```bash
# Start SSH service
sudo systemctl start ssh

# Enable SSH to start on boot
sudo systemctl enable ssh

# Check SSH status
sudo systemctl status ssh
```

### 3. Configure SSH (Optional)

Edit the SSH configuration file:

```bash
sudo nano /etc/ssh/sshd_config
```

Common settings to check:
- `Port 22` - SSH port (default is 22)
- `PermitRootLogin no` - Security best practice
- `PasswordAuthentication yes` - Allow password login
- `PubkeyAuthentication yes` - Allow SSH key authentication

After editing, restart SSH:

```bash
sudo systemctl restart ssh
```

### 4. Check Firewall

If you have a firewall enabled, allow SSH:

```bash
# UFW (Ubuntu)
sudo ufw allow ssh
sudo ufw allow 22/tcp

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

### 5. Find Your IP Address

```bash
# Get IP address
ip addr show
# or
hostname -I
```

## Connect from Mac/Windows to Linux VM

### Using SSH Command

```bash
# Basic connection
ssh username@ip_address

# Example (for your VM)
ssh agent@192.168.64.4

# With specific port
ssh -p 22 agent@192.168.64.4

# With verbose output (for debugging)
ssh -v agent@192.168.64.4
```

### Using SSH Keys (Passwordless Login)

1. **Generate SSH Key Pair** (on your local machine):

```bash
# Generate key pair
ssh-keygen -t ed25519 -C "your_email@example.com"

# Or use RSA (older systems)
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

2. **Copy Public Key to VM**:

```bash
# Method 1: Using ssh-copy-id
ssh-copy-id agent@192.168.64.4

# Method 2: Manual copy
cat ~/.ssh/id_ed25519.pub | ssh agent@192.168.64.4 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

# Method 3: Copy and paste manually
cat ~/.ssh/id_ed25519.pub
# Then on VM:
mkdir -p ~/.ssh
nano ~/.ssh/authorized_keys
# Paste the public key, save and exit
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

3. **Test Passwordless Login**:

```bash
ssh agent@192.168.64.4
# Should connect without password prompt
```

## Troubleshooting

### SSH Connection Refused

```bash
# Check if SSH is running
sudo systemctl status ssh

# Check if port 22 is listening
sudo netstat -tlnp | grep :22
# or
sudo ss -tlnp | grep :22

# Check firewall
sudo ufw status
```

### Permission Denied

```bash
# Check SSH logs
sudo tail -f /var/log/auth.log
# or
sudo journalctl -u ssh -f

# Verify permissions on ~/.ssh
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

### Connection Timeout

```bash
# Check if VM is reachable
ping 192.168.64.4

# Check if port is open
telnet 192.168.64.4 22
# or
nc -zv 192.168.64.4 22
```

## Quick Setup Script

Save this as `setup_ssh.sh` on your VM:

```bash
#!/bin/bash
# Enable SSH on Linux VM

echo "Installing SSH server..."
sudo apt update
sudo apt install -y openssh-server

echo "Starting SSH service..."
sudo systemctl start ssh
sudo systemctl enable ssh

echo "Configuring firewall..."
sudo ufw allow ssh

echo "Checking SSH status..."
sudo systemctl status ssh

echo "SSH setup complete!"
echo "Your IP address: $(hostname -I | awk '{print $1}')"
```

Make it executable and run:

```bash
chmod +x setup_ssh.sh
./setup_ssh.sh
```

## For UTM VM (macOS)

If you're using UTM to run your Linux VM:

1. **Network Settings in UTM:**
   - Go to VM Settings → Network
   - Enable "Network Mode" (usually "Shared Network" or "Bridged")
   - This allows the VM to get an IP on your network

2. **Find VM IP:**
   ```bash
   # Inside the VM
   ip addr show
   # Look for inet address (usually 192.168.64.x for UTM)
   ```

3. **Connect from Mac:**
   ```bash
   ssh agent@192.168.64.4
   ```

## Security Best Practices

1. **Disable root login:**
   ```bash
   sudo nano /etc/ssh/sshd_config
   # Set: PermitRootLogin no
   sudo systemctl restart ssh
   ```

2. **Use SSH keys instead of passwords:**
   - More secure
   - Passwordless login

3. **Change default port (optional):**
   ```bash
   sudo nano /etc/ssh/sshd_config
   # Change: Port 22 to Port 2222 (or another port)
   sudo systemctl restart ssh
   ```

4. **Keep SSH updated:**
   ```bash
   sudo apt update && sudo apt upgrade openssh-server
   ```

## Common Commands

```bash
# Connect to VM
ssh agent@192.168.64.4

# Copy file to VM
scp file.txt agent@192.168.64.4:/home/agent/

# Copy file from VM
scp agent@192.168.64.4:/home/agent/file.txt ./

# Run command on VM
ssh agent@192.168.64.4 "ls -la"

# Port forwarding
ssh -L 8080:localhost:80 agent@192.168.64.4
```

---

**Note:** This guide is for setting up SSH access to your Linux VM for development and testing of the Linux Security Agent project.

