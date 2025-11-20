#!/usr/bin/env python3
"""Check and install missing dependencies for the security agent"""

import sys
import subprocess

def check_and_install(package, import_name=None):
    """Check if package is installed, install if missing"""
    if import_name is None:
        import_name = package
    
    try:
        __import__(import_name)
        print(f"✅ {package} is installed")
        return True
    except ImportError:
        print(f"❌ {package} is missing - installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✅ {package} installed successfully")
            return True
        except subprocess.CalledProcessError:
            print(f"⚠️  Failed to install {package}")
            return False

if __name__ == "__main__":
    print("Checking dependencies for Enhanced Security Agent...\n")
    
    # Core dependencies (required)
    check_and_install("psutil", "psutil")
    check_and_install("rich", "rich")
    
    # ML dependencies (for anomaly detector)
    check_and_install("numpy", "numpy")
    check_and_install("pandas", "pandas")
    check_and_install("scikit-learn", "sklearn")
    
    # Docker (optional - for container monitoring)
    check_and_install("docker", "docker")
    
    print("\n✅ Dependency check complete!")

