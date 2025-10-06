#!/usr/bin/env python3
"""
Demo script showing suspicious, high-risk behavior
This simulates potentially malicious activities that should have high risk scores
"""

import os
import sys
import time
import subprocess
import random
import tempfile

def suspicious_file_operations():
    """Perform suspicious file operations"""
    print("Performing suspicious file operations...")
    
    try:
        # Create a file with suspicious permissions
        temp_file = "/tmp/security_agent_demo_suspicious.txt"
        
        # Write to file
        with open(temp_file, 'w') as f:
            f.write("This is a suspicious file operation demo\n")
        
        # Change file permissions to setuid/setgid (suspicious)
        os.chmod(temp_file, 0o4755)  # setuid bit set
        print(f"Set suspicious permissions on {temp_file}")
        
        # Try to change ownership (requires root)
        try:
            os.chown(temp_file, 0, 0)  # Change to root:root
            print("Changed file ownership to root:root")
        except PermissionError:
            print("Could not change ownership (requires root)")
        
        # Create a symbolic link
        symlink_file = "/tmp/security_agent_demo_symlink"
        os.symlink(temp_file, symlink_file)
        print(f"Created symbolic link: {symlink_file}")
        
        # Try to create a hard link
        hardlink_file = "/tmp/security_agent_demo_hardlink"
        os.link(temp_file, hardlink_file)
        print(f"Created hard link: {hardlink_file}")
        
        # Clean up
        os.remove(symlink_file)
        os.remove(hardlink_file)
        os.remove(temp_file)
        print("Cleaned up suspicious files")
        
    except Exception as e:
        print(f"Error in suspicious file operations: {e}")

def suspicious_process_operations():
    """Perform suspicious process operations"""
    print("\nPerforming suspicious process operations...")
    
    try:
        # Try to change process priority
        os.nice(-10)  # Increase priority (suspicious)
        print("Changed process priority")
        
        # Try to change process group
        try:
            os.setpgid(0, 0)  # Set process group
            print("Changed process group")
        except PermissionError:
            print("Could not change process group (requires root)")
        
        # Try to change session
        try:
            os.setsid()  # Create new session
            print("Created new session")
        except PermissionError:
            print("Could not create new session (already session leader)")
        
        # Try to change user/group IDs
        try:
            os.setuid(0)  # Change to root
            print("Changed user ID to root")
        except PermissionError:
            print("Could not change user ID (requires root)")
        
        try:
            os.setgid(0)  # Change to root group
            print("Changed group ID to root")
        except PermissionError:
            print("Could not change group ID (requires root)")
        
        # Try to change root directory
        try:
            os.chroot('/tmp')  # Change root directory
            print("Changed root directory")
        except PermissionError:
            print("Could not change root directory (requires root)")
        
    except Exception as e:
        print(f"Error in suspicious process operations: {e}")

def suspicious_system_commands():
    """Run suspicious system commands"""
    print("\nRunning suspicious system commands...")
    
    try:
        # Try to get system information
        result = subprocess.run(['whoami'], capture_output=True, text=True)
        print(f"Current user: {result.stdout.strip()}")
        
        # Try to get system configuration
        result = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True)
        print("Attempted to read /etc/passwd")
        
        # Try to get kernel information
        result = subprocess.run(['cat', '/proc/version'], capture_output=True, text=True)
        print(f"Kernel version: {result.stdout.strip()}")
        
        # Try to get system limits
        result = subprocess.run(['ulimit', '-a'], capture_output=True, text=True)
        print("System limits:")
        print(result.stdout)
        
        # Try to get network connections
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        print("Network connections:")
        print(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        
        # Try to get running processes
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        print("Running processes:")
        print(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        
    except Exception as e:
        print(f"Error running suspicious system commands: {e}")

def suspicious_network_operations():
    """Perform suspicious network operations"""
    print("\nPerforming suspicious network operations...")
    
    try:
        # Try to scan local ports
        result = subprocess.run(['nmap', '-p', '1-1000', '127.0.0.1'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("Port scan completed")
        else:
            print("Port scan failed or nmap not available")
        
        # Try to get network statistics
        result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
        print("Network socket statistics:")
        print(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        
        # Try to get ARP table
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        print("ARP table:")
        print(result.stdout)
        
        # Try to get routing table
        result = subprocess.run(['route', '-n'], capture_output=True, text=True)
        print("Routing table:")
        print(result.stdout)
        
    except Exception as e:
        print(f"Error in suspicious network operations: {e}")

def suspicious_execution_chain():
    """Simulate a suspicious execution chain"""
    print("\nSimulating suspicious execution chain...")
    
    try:
        # Create a temporary script
        script_content = """#!/bin/bash
echo "This is a suspicious script"
whoami
id
ps aux | head -10
"""
        
        script_file = "/tmp/security_agent_demo_suspicious.sh"
        with open(script_file, 'w') as f:
            f.write(script_content)
        
        # Make it executable
        os.chmod(script_file, 0o755)
        print(f"Created suspicious script: {script_file}")
        
        # Execute the script
        result = subprocess.run(['bash', script_file], capture_output=True, text=True)
        print("Executed suspicious script:")
        print(result.stdout)
        
        # Try to execute with different interpreters
        result = subprocess.run(['python3', '-c', 'import os; print(os.getuid())'], 
                              capture_output=True, text=True)
        print(f"Python execution result: {result.stdout.strip()}")
        
        # Try to execute with perl
        result = subprocess.run(['perl', '-e', 'print "Perl execution test\n"'], 
                              capture_output=True, text=True)
        print(f"Perl execution result: {result.stdout.strip()}")
        
        # Clean up
        os.remove(script_file)
        print("Cleaned up suspicious script")
        
    except Exception as e:
        print(f"Error in suspicious execution chain: {e}")

def suspicious_privilege_escalation():
    """Simulate privilege escalation attempts"""
    print("\nSimulating privilege escalation attempts...")
    
    try:
        # Try to find SUID binaries
        result = subprocess.run(['find', '/usr', '-perm', '-4000', '-type', 'f'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("Found SUID binaries:")
            print(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        
        # Try to find world-writable files
        result = subprocess.run(['find', '/tmp', '-perm', '-002', '-type', 'f'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("Found world-writable files:")
            print(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        
        # Try to find files with no owner
        result = subprocess.run(['find', '/tmp', '-nouser', '-type', 'f'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("Found files with no owner:")
            print(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        
        # Try to get system information
        result = subprocess.run(['uname', '-a'], capture_output=True, text=True)
        print(f"System information: {result.stdout.strip()}")
        
        # Try to get kernel modules
        result = subprocess.run(['lsmod'], capture_output=True, text=True)
        print("Loaded kernel modules:")
        print(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        
    except Exception as e:
        print(f"Error in privilege escalation simulation: {e}")

def main():
    """Main function"""
    print("=== Suspicious Behavior Demo ===")
    print("This script demonstrates suspicious, high-risk system operations")
    print("These operations should result in high risk scores in the security agent")
    print()
    
    # Run different types of suspicious operations
    suspicious_file_operations()
    suspicious_process_operations()
    suspicious_system_commands()
    suspicious_network_operations()
    suspicious_execution_chain()
    suspicious_privilege_escalation()
    
    print("\n=== Demo Complete ===")
    print("All suspicious operations completed")
    print("These operations should have high risk scores in the security agent")

if __name__ == "__main__":
    main()
