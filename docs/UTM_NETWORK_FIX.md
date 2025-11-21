# Fix UTM Network Connection Issue

**Problem:** Mac can't reach VM at 192.168.64.4

## Quick Fix Steps

### Step 1: Check VM's Actual IP Address

**On your VM** (use UTM's built-in terminal/console):

```bash
# Get current IP
hostname -I

# Or more detailed
ip addr show | grep "inet "
```

**The IP might be different!** It could be:
- `192.168.64.5`
- `192.168.64.3`
- `10.0.2.15` (if using NAT mode)
- Something else entirely

### Step 2: Fix UTM Network Settings

1. **Open UTM**
2. **Select your Linux VM**
3. **Click "Edit" or right-click → "Edit"**
4. **Go to "Network" tab**
5. **Change settings:**
   - **Network Mode:** Select "Shared Network" (NOT "NAT" or "Isolated")
   - **Enable:** Make sure network is checked/enabled
6. **Click "Save"**
7. **Shut down VM completely** (not just suspend)
8. **Start VM again**
9. **Wait for full boot**
10. **Check IP again:** `hostname -I` on VM

### Step 3: Test Connection with New IP

**From your Mac:**

```bash
# Replace with the IP you found
ping <NEW_IP>

# If ping works, try SSH
ssh agent@<NEW_IP>
```

## Alternative: Use UTM's Built-in Terminal

If network still doesn't work:

1. **In UTM, click on your VM window**
2. **Use the VM's built-in terminal directly**
3. **No SSH needed** - you can work directly in UTM

## If IP Keeps Changing

Set a static IP on the VM:

```bash
# On VM
sudo nano /etc/netplan/01-netcfg.yaml

# Add (adjust for your network):
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: false
      addresses:
        - 192.168.64.4/24
      gateway4: 192.168.64.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]

# Apply
sudo netplan apply
```

## Check UTM Network Status

In UTM:
- **VM Settings → Network**
- Should show: "Shared Network" or "Bridged"
- Should NOT show: "NAT" or "Isolated"

## Still Not Working?

1. **Check if VM network interface is up:**
   ```bash
   # On VM
   ip link show
   # Look for "UP" status
   ```

2. **Restart network on VM:**
   ```bash
   # On VM
   sudo systemctl restart networking
   # or
   sudo ifdown eth0 && sudo ifup eth0
   ```

3. **Check UTM's network adapter:**
   - In UTM settings, make sure network adapter is enabled
   - Try removing and re-adding the network adapter

---

**Most Common Fix:** Change UTM network mode from "NAT" to "Shared Network" and restart VM.

