#!/usr/bin/env python3
"""
Local setup script for Linux Security Agent (no sudo required)
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path

def create_local_directories():
    """Create local directories"""
    home_dir = Path.home()
    local_dirs = [
        home_dir / '.security-agent',
        home_dir / '.security-agent' / 'config',
        home_dir / '.security-agent' / 'data',
        home_dir / '.security-agent' / 'logs'
    ]
    
    for directory in local_dirs:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def create_local_config():
    """Create local configuration file"""
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
        "config_file": str(Path.home() / '.security-agent' / 'config' / 'config.json'),
        "log_file": str(Path.home() / '.security-agent' / 'logs' / 'security-agent.log'),
        "data_dir": str(Path.home() / '.security-agent' / 'data')
    }
    
    config_file = Path.home() / '.security-agent' / 'config' / 'config.json'
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print("✅ Created local configuration file")

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
    
    # Check if we're in a virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Virtual environment detected, installing packages...")
        for requirement in requirements:
            cmd = ['pip', 'install', requirement]
            subprocess.run(cmd, check=True)
    else:
        print("⚠️  No virtual environment detected. Skipping package installation.")
        print("   Please run: pip install -r requirements.txt")
        print("   Or activate your virtual environment first.")
    
    print("✅ Python dependencies handled")

def create_local_scripts():
    """Create local executable scripts"""
    home_dir = Path.home()
    bin_dir = home_dir / '.local' / 'bin'
    bin_dir.mkdir(parents=True, exist_ok=True)
    
    # Create security agent script
    agent_script = f"""#!/usr/bin/env python3
import sys
import os

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(current_dir)
sys.path.insert(0, project_dir)

# Import and run the macOS agent
from security_agent_mac import main

if __name__ == "__main__":
    main()
"""
    
    agent_path = bin_dir / 'security-agent'
    with open(agent_path, 'w') as f:
        f.write(agent_script)
    agent_path.chmod(0o755)
    
    # Create production agent script
    prod_script = f"""#!/usr/bin/env python3
import sys
import os

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(current_dir)
sys.path.insert(0, project_dir)

# Import and run the production agent
from production_agent import main

if __name__ == "__main__":
    main()
"""
    
    prod_path = bin_dir / 'security-agent-prod'
    with open(prod_path, 'w') as f:
        f.write(prod_script)
    prod_path.chmod(0o755)
    
    print("✅ Created local executable scripts")
    print(f"   {agent_path}")
    print(f"   {prod_path}")

def create_run_script():
    """Create a simple run script"""
    run_script = f"""#!/bin/bash
# Linux Security Agent - Local Run Script

echo "🛡️  Starting Linux Security Agent (macOS version)"
echo "================================================"

# Check if .local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "⚠️  Adding ~/.local/bin to PATH for this session"
    export PATH="$HOME/.local/bin:$PATH"
fi

# Run the security agent
python3 security_agent_mac.py --dashboard --threshold 30
"""
    
    with open('run_agent.sh', 'w') as f:
        f.write(run_script)
    os.chmod('run_agent.sh', 0o755)
    
    print("✅ Created run script: run_agent.sh")

def create_demo_script():
    """Create demo script"""
    demo_script = f"""#!/bin/bash
# Linux Security Agent - Demo Script

echo "🧪 Running Security Agent Demo"
echo "=============================="

# Terminal 1: Start the agent
echo "Starting security agent in background..."
python3 security_agent_mac.py --dashboard --threshold 30 &
AGENT_PID=$!

# Wait a moment for agent to start
sleep 3

# Terminal 2: Run demo scripts
echo "Running demo scripts..."
cd demo
python3 run_demo.py

# Stop the agent
echo "Stopping security agent..."
kill $AGENT_PID 2>/dev/null

echo "Demo complete!"
"""
    
    with open('run_demo.sh', 'w') as f:
        f.write(demo_script)
    os.chmod('run_demo.sh', 0o755)
    
    print("✅ Created demo script: run_demo.sh")

def main():
    """Main installation function"""
    print("🍎 Linux Security Agent - Local Installation (No Sudo)")
    print("=" * 60)
    
    try:
        # Installation steps
        create_local_directories()
        create_local_config()
        install_python_dependencies()
        create_local_scripts()
        create_run_script()
        create_demo_script()
        
        print("\n🎉 Local installation completed successfully!")
        print("\nNext steps:")
        print("1. Add ~/.local/bin to your PATH (add to ~/.zshrc or ~/.bash_profile):")
        print("   export PATH=\"$HOME/.local/bin:$PATH\"")
        print("2. Run the agent:")
        print("   ./run_agent.sh")
        print("   OR")
        print("   python3 security_agent_mac.py --dashboard")
        print("3. Run the demo:")
        print("   ./run_demo.sh")
        print("4. Edit configuration:")
        print(f"   nano {Path.home() / '.security-agent' / 'config' / 'config.json'}")
        
        print("\nNote: This is the macOS version with limited eBPF support.")
        print("For full functionality, run on a Linux system.")
        
    except Exception as e:
        print(f"❌ Installation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
