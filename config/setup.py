#!/usr/bin/env python3
"""
Production setup script for Linux Security Agent
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path

def create_systemd_service():
    """Create systemd service file"""
    service_content = """[Unit]
Description=Linux Security Agent - Enterprise EDR
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/security-agent --config /etc/security-agent/config.json
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=security-agent

# Security settings
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /var/lib/security-agent /tmp

# Resource limits
LimitNOFILE=65536
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
"""
    
    with open('/etc/systemd/system/security-agent.service', 'w') as f:
        f.write(service_content)
    
    print("✅ Created systemd service file")

def create_config_file():
    """Create default configuration file"""
    config = {
        "use_ebpf": True,
        "use_anomaly_detection": True,
        "use_actions": True,
        "show_dashboard": False,
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
    
    os.makedirs('/etc/security-agent', exist_ok=True)
    with open('/etc/security-agent/config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("✅ Created configuration file")

def create_directories():
    """Create necessary directories"""
    directories = [
        '/usr/local/bin',
        '/etc/security-agent',
        '/var/lib/security-agent',
        '/var/log/security-agent'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def install_dependencies():
    """Install system dependencies"""
    print("📦 Installing system dependencies...")
    
    # Detect package manager
    if shutil.which('apt-get'):
        cmd = ['apt-get', 'update']
        subprocess.run(cmd, check=True)
        
        cmd = ['apt-get', 'install', '-y', 
               'python3', 'python3-pip', 'python3-dev',
               'bpfcc-tools', 'python3-bpfcc',
               'build-essential', 'linux-headers-generic']
        subprocess.run(cmd, check=True)
        
    elif shutil.which('yum'):
        cmd = ['yum', 'install', '-y',
               'python3', 'python3-pip', 'python3-devel',
               'bcc-tools', 'python3-bcc',
               'gcc', 'kernel-devel']
        subprocess.run(cmd, check=True)
        
    elif shutil.which('dnf'):
        cmd = ['dnf', 'install', '-y',
               'python3', 'python3-pip', 'python3-devel',
               'bcc-tools', 'python3-bcc',
               'gcc', 'kernel-devel']
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
        ('action_handler.py', '/usr/local/bin/action_handler.py')
    ]
    
    for src, dst in files_to_copy:
        if os.path.exists(src):
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
            print(f"✅ Copied {src} to {dst}")
        else:
            print(f"⚠️  File not found: {src}")

def setup_logrotate():
    """Setup log rotation"""
    logrotate_content = """/var/log/security-agent/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload security-agent > /dev/null 2>&1 || true
    endscript
}
"""
    
    with open('/etc/logrotate.d/security-agent', 'w') as f:
        f.write(logrotate_content)
    
    print("✅ Created logrotate configuration")

def setup_firewall():
    """Setup firewall rules if needed"""
    print("🔥 Setting up firewall rules...")
    
    # This would be customized based on the environment
    # For now, just create a placeholder
    firewall_rules = """# Security Agent Firewall Rules
# Allow outbound HTTPS for cloud communication
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Allow outbound DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
"""
    
    with open('/etc/security-agent/firewall-rules.sh', 'w') as f:
        f.write(firewall_rules)
    
    os.chmod('/etc/security-agent/firewall-rules.sh', 0o755)
    print("✅ Created firewall rules")

def create_uninstall_script():
    """Create uninstall script"""
    uninstall_content = """#!/bin/bash
echo "Uninstalling Linux Security Agent..."

# Stop and disable service
systemctl stop security-agent
systemctl disable security-agent

# Remove service file
rm -f /etc/systemd/system/security-agent.service

# Remove files
rm -rf /etc/security-agent
rm -rf /var/lib/security-agent
rm -rf /var/log/security-agent
rm -f /usr/local/bin/security-agent
rm -f /usr/local/bin/ebpf_monitor.py
rm -f /usr/local/bin/advanced_risk_engine.py
rm -f /usr/local/bin/mitre_attack_detector.py
rm -f /usr/local/bin/anomaly_detector.py
rm -f /usr/local/bin/action_handler.py

# Remove logrotate
rm -f /etc/logrotate.d/security-agent

# Remove firewall rules
rm -f /etc/security-agent/firewall-rules.sh

# Reload systemd
systemctl daemon-reload

echo "✅ Linux Security Agent uninstalled"
"""
    
    with open('uninstall.sh', 'w') as f:
        f.write(uninstall_content)
    
    os.chmod('uninstall.sh', 0o755)
    print("✅ Created uninstall script")

def main():
    """Main installation function"""
    print("🛡️  Linux Security Agent - Production Installation")
    print("=" * 50)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script must be run as root")
        sys.exit(1)
    
    try:
        # Installation steps
        create_directories()
        install_dependencies()
        install_python_dependencies()
        copy_files()
        create_config_file()
        create_systemd_service()
        setup_logrotate()
        setup_firewall()
        create_uninstall_script()
        
        # Reload systemd
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        
        print("\n🎉 Installation completed successfully!")
        print("\nNext steps:")
        print("1. Edit configuration: /etc/security-agent/config.json")
        print("2. Start the service: systemctl start security-agent")
        print("3. Enable auto-start: systemctl enable security-agent")
        print("4. Check status: systemctl status security-agent")
        print("5. View logs: journalctl -u security-agent -f")
        
    except Exception as e:
        print(f"❌ Installation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
