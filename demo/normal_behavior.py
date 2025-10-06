#!/usr/bin/env python3
"""
Demo script showing normal, low-risk behavior
This simulates typical system operations that should have low risk scores
"""

import os
import sys
import time
import subprocess
import random

def normal_file_operations():
    """Perform normal file operations"""
    print("Performing normal file operations...")
    
    # Create a temporary file
    temp_file = "/tmp/security_agent_demo_normal.txt"
    
    try:
        # Write to file
        with open(temp_file, 'w') as f:
            f.write("This is a normal file operation demo\n")
        
        # Read from file
        with open(temp_file, 'r') as f:
            content = f.read()
            print(f"Read content: {content.strip()}")
        
        # Get file stats
        stat_info = os.stat(temp_file)
        print(f"File size: {stat_info.st_size} bytes")
        
        # List directory
        files = os.listdir('/tmp')
        print(f"Found {len(files)} files in /tmp")
        
        # Change directory
        original_dir = os.getcwd()
        os.chdir('/tmp')
        print(f"Changed to directory: {os.getcwd()}")
        os.chdir(original_dir)
        
        # Get current working directory
        cwd = os.getcwd()
        print(f"Current working directory: {cwd}")
        
        # Get process info
        pid = os.getpid()
        print(f"Process ID: {pid}")
        
        # Get user info
        uid = os.getuid()
        gid = os.getgid()
        print(f"User ID: {uid}, Group ID: {gid}")
        
        # Sleep for a bit
        time.sleep(1)
        
        # Clean up
        os.remove(temp_file)
        print("Cleaned up temporary file")
        
    except Exception as e:
        print(f"Error in normal operations: {e}")

def normal_system_commands():
    """Run normal system commands"""
    print("\nRunning normal system commands...")
    
    try:
        # List files
        result = subprocess.run(['ls', '-la'], capture_output=True, text=True)
        print("ls command output:")
        print(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        
        # Get system info
        result = subprocess.run(['uname', '-a'], capture_output=True, text=True)
        print(f"System info: {result.stdout.strip()}")
        
        # Get current date
        result = subprocess.run(['date'], capture_output=True, text=True)
        print(f"Current date: {result.stdout.strip()}")
        
        # Get process list
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        lines = result.stdout.split('\n')[:5]  # First 5 lines
        print("Process list (first 5 lines):")
        for line in lines:
            print(f"  {line}")
        
        # Get memory info
        result = subprocess.run(['free', '-h'], capture_output=True, text=True)
        print("Memory info:")
        print(result.stdout)
        
    except Exception as e:
        print(f"Error running system commands: {e}")

def normal_network_operations():
    """Perform normal network operations"""
    print("\nPerforming normal network operations...")
    
    try:
        # Get network interfaces
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
        print("Network interfaces:")
        print(result.stdout[:300] + "..." if len(result.stdout) > 300 else result.stdout)
        
        # Get routing table
        result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
        print("Routing table:")
        print(result.stdout)
        
        # Test connectivity
        result = subprocess.run(['ping', '-c', '1', '127.0.0.1'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("Localhost ping successful")
        else:
            print("Localhost ping failed")
        
    except Exception as e:
        print(f"Error in network operations: {e}")

def normal_process_operations():
    """Perform normal process operations"""
    print("\nPerforming normal process operations...")
    
    try:
        # Get current process info
        pid = os.getpid()
        print(f"Current process PID: {pid}")
        
        # Get parent process info
        ppid = os.getppid()
        print(f"Parent process PID: {ppid}")
        
        # Get process group
        pgid = os.getpgid(pid)
        print(f"Process group ID: {pgid}")
        
        # Get session ID
        sid = os.getsid(pid)
        print(f"Session ID: {sid}")
        
        # Get process limits
        import resource
        limits = resource.getrlimit(resource.RLIMIT_CPU)
        print(f"CPU time limit: {limits}")
        
        # Get process times
        times = os.times()
        print(f"Process times: {times}")
        
        # Get environment variables
        env_vars = list(os.environ.keys())[:5]  # First 5 env vars
        print(f"Environment variables (first 5): {env_vars}")
        
    except Exception as e:
        print(f"Error in process operations: {e}")

def main():
    """Main function"""
    print("=== Normal Behavior Demo ===")
    print("This script demonstrates normal, low-risk system operations")
    print("These operations should result in low risk scores in the security agent")
    print()
    
    # Run different types of normal operations
    normal_file_operations()
    normal_system_commands()
    normal_network_operations()
    normal_process_operations()
    
    print("\n=== Demo Complete ===")
    print("All operations completed successfully")
    print("These operations should have low risk scores in the security agent")

if __name__ == "__main__":
    main()
