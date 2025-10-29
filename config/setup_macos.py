#!/usr/bin/env python3
"""
macOS setup script for Linux Security Agent
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path

def create_launchd_service():
    """Create launchd plist file for macOS"""
    plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.security-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/security-agent</string>
        <string>--config</string>
        <string>/usr/local/etc/security-agent/config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/security-agent/security-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/security-agent/security-agent.error.log</string>
    <key>WorkingDirectory</key>
    <string>/usr/local/var/lib/security-agent</string>
</dict>
</plist>
"""
    
    # Create LaunchAgents directory
    launchagents_dir = os.path.expanduser("~/Library/LaunchAgents")
    os.makedirs(launchagents_dir, exist_ok=True)
    
    with open(os.path.join(launchagents_dir, 'com.security-agent.plist'), 'w') as f:
        f.write(plist_content)
    
    print("✅ Created launchd service file")

def create_config_file():
    """Create default configuration file"""
    config = {
        "use_ebpf": False,  # eBPF not available on macOS
        "use_anomaly_detection": True,
        "use_actions": True,
        "show_dashboard": True,
        "warn_threshold": 30.0,
        "freeze_threshold": 70.0,
        "kill_threshold": 90.0,
        "enable_warnings": True,
        "enable_freeze": True,
        "enable_kill": False,
        "batch_size": 1000,
        "update_interval": 1.0,
        "log_level": "INFO",
        "data_retention_days": 30,
        "max_log_size_mb": 100,
        "cloud_endpoint": "",
        "api_key": "",
        "tls_cert": "",
        "tls_key": ""
    }
    
    try:
        os.makedirs('/usr/local/etc/security-agent', exist_ok=True)
        with open('/usr/local/etc/security-agent/config.json', 'w') as f:
            json.dump(config, f, indent=2)
        print("✅ Created configuration file")
    except PermissionError:
        # Try with sudo
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            json.dump(config, tmp, indent=2)
            tmp_path = tmp.name
        
        cmd = ['sudo', 'mkdir', '-p', '/usr/local/etc/security-agent']
        subprocess.run(cmd, check=True)
        
        cmd = ['sudo', 'cp', tmp_path, '/usr/local/etc/security-agent/config.json']
        subprocess.run(cmd, check=True)
        
        os.unlink(tmp_path)
        print("✅ Created configuration file (with sudo)")

def create_directories():
    """Create necessary directories"""
    directories = [
        '/usr/local/bin',
        '/usr/local/etc/security-agent',
        '/usr/local/var/lib/security-agent',
        '/usr/local/var/log/security-agent'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✅ Created directory: {directory}")
        except PermissionError:
            # Try with sudo
            cmd = ['sudo', 'mkdir', '-p', directory]
            subprocess.run(cmd, check=True)
            print(f"✅ Created directory: {directory} (with sudo)")

def install_dependencies():
    """Install system dependencies"""
    print("📦 Installing system dependencies...")
    
    # Check if Homebrew is installed
    if not shutil.which('brew'):
        print("❌ Homebrew not found. Please install Homebrew first:")
        print("   /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
        sys.exit(1)
    
    # Install Python and development tools
    packages = [
        'python@3.11',
        'python-tk'
    ]
    
    for package in packages:
        cmd = ['brew', 'install', package]
        subprocess.run(cmd, check=True)
    
    print("✅ System dependencies installed")

def install_python_dependencies():
    """Install Python dependencies"""
    print("🐍 Installing Python dependencies...")
    
    requirements = [
        'psutil>=5.9.0',
        'scikit-learn>=1.3.0',
        'numpy>=1.24.0',
        'pandas>=2.0.0',
        'colorama>=0.4.0',
        'rich>=13.0.0',
        'click>=8.0.0',
        'requests>=2.28.0',
        'cryptography>=3.4.8'
    ]
    
    for requirement in requirements:
        cmd = ['pip3', 'install', requirement]
        subprocess.run(cmd, check=True)
    
    print("✅ Python dependencies installed")

def copy_files():
    """Copy agent files to system locations"""
    print("📁 Copying agent files...")
    
    files_to_copy = [
        ('production_agent.py', '/usr/local/bin/security-agent'),
        ('ebpf_monitor.py', '/usr/local/bin/ebpf_monitor.py'),
        ('advanced_risk_engine.py', '/usr/local/bin/advanced_risk_engine.py'),
        ('mitre_attack_detector.py', '/usr/local/bin/mitre_attack_detector.py'),
        ('anomaly_detector.py', '/usr/local/bin/anomaly_detector.py'),
        ('action_handler.py', '/usr/local/bin/action_handler.py'),
        ('security_agent_mac.py', '/usr/local/bin/security-agent-mac')
    ]
    
    for src, dst in files_to_copy:
        if os.path.exists(src):
            try:
                shutil.copy2(src, dst)
                os.chmod(dst, 0o755)
                print(f"✅ Copied {src} to {dst}")
            except PermissionError:
                # Try with sudo
                cmd = ['sudo', 'cp', src, dst]
                subprocess.run(cmd, check=True)
                cmd = ['sudo', 'chmod', '755', dst]
                subprocess.run(cmd, check=True)
                print(f"✅ Copied {src} to {dst} (with sudo)")
        else:
            print(f"⚠️  File not found: {src}")

def create_macos_agent():
    """Create macOS-specific agent wrapper"""
    macos_agent_content = """#!/usr/bin/env python3
'''
macOS Security Agent Wrapper
Uses the macOS-compatible version of the security agent
'''

import sys
import os

# Add the agent directory to Python path
sys.path.insert(0, '/usr/local/bin')

# Import and run the macOS agent
from security_agent_mac import main

if __name__ == "__main__":
    main()
"""
    
    with open('/usr/local/bin/security-agent-mac', 'w') as f:
        f.write(macos_agent_content)
    
    os.chmod('/usr/local/bin/security-agent-mac', 0o755)
    print("✅ Created macOS agent wrapper")

def create_uninstall_script():
    """Create uninstall script"""
    uninstall_content = """#!/bin/bash
echo "Uninstalling Linux Security Agent from macOS..."

# Stop and unload service
launchctl unload ~/Library/LaunchAgents/com.security-agent.plist 2>/dev/null || true

# Remove service file
rm -f ~/Library/LaunchAgents/com.security-agent.plist

# Remove files
rm -rf /usr/local/etc/security-agent
rm -rf /usr/local/var/lib/security-agent
rm -rf /usr/local/var/log/security-agent
rm -f /usr/local/bin/security-agent
rm -f /usr/local/bin/security-agent-mac
rm -f /usr/local/bin/ebpf_monitor.py
rm -f /usr/local/bin/advanced_risk_engine.py
rm -f /usr/local/bin/mitre_attack_detector.py
rm -f /usr/local/bin/anomaly_detector.py
rm -f /usr/local/bin/action_handler.py

echo "✅ Linux Security Agent uninstalled from macOS"
"""
    
    with open('uninstall_macos.sh', 'w') as f:
        f.write(uninstall_content)
    
    os.chmod('uninstall_macos.sh', 0o755)
    print("✅ Created macOS uninstall script")

def main():
    """Main installation function"""
    print("🍎 Linux Security Agent - macOS Installation")
    print("=" * 50)
    
    # Check if running as root (not required on macOS)
    if os.geteuid() == 0:
        print("⚠️  Running as root on macOS. This is not recommended.")
        print("   The installation will use sudo for system directories only.")
    
    try:
        # Installation steps
        create_directories()
        install_dependencies()
        install_python_dependencies()
        copy_files()
        create_macos_agent()
        create_config_file()
        create_launchd_service()
        create_uninstall_script()
        
        print("\n🎉 Installation completed successfully!")
        print("\nNext steps:")
        print("1. Edit configuration: /usr/local/etc/security-agent/config.json")
        print("2. Start the service: launchctl load ~/Library/LaunchAgents/com.security-agent.plist")
        print("3. Check status: launchctl list | grep security-agent")
        print("4. View logs: tail -f /usr/local/var/log/security-agent/security-agent.log")
        print("5. Run manually: /usr/local/bin/security-agent-mac --dashboard")
        
        print("\nNote: This is the macOS version with limited eBPF support.")
        print("For full functionality, run on a Linux system.")
        
    except Exception as e:
        print(f"❌ Installation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
