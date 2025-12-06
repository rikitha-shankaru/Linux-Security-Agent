#!/bin/bash
# Setup script to run web dashboard on VM with SSH port forwarding

echo "🛡️  Linux Security Agent - VM Dashboard Setup"
echo "=============================================="
echo ""

echo "This script will help you access the web dashboard from your VM"
echo ""
echo "Option 1: SSH Port Forwarding (Recommended)"
echo "  Run this on your LOCAL machine:"
echo "    ssh -L 5001:localhost:5001 -i /path/to/key likithashankar14@YOUR_VM_IP"
echo ""
echo "  Then open: http://localhost:5001"
echo ""
echo "Option 2: Direct Access (if VM has public IP)"
echo "  Run dashboard on VM, then access:"
echo "    http://YOUR_VM_IP:5001"
echo ""
echo "Option 3: Cloud Console Browser"
echo "  If your VM provider has browser SSH, you can access it there"
echo ""

