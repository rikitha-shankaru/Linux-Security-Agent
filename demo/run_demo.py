#!/usr/bin/env python3
"""
Demo runner script that demonstrates both normal and suspicious behavior
"""

import os
import sys
import time
import subprocess
import threading

def run_normal_behavior():
    """Run normal behavior demo"""
    print("Starting normal behavior demo...")
    try:
        result = subprocess.run([sys.executable, 'normal_behavior.py'], 
                              capture_output=True, text=True, cwd=os.path.dirname(__file__))
        print("Normal behavior demo output:")
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
    except Exception as e:
        print(f"Error running normal behavior demo: {e}")

def run_suspicious_behavior():
    """Run suspicious behavior demo"""
    print("\nStarting suspicious behavior demo...")
    try:
        result = subprocess.run([sys.executable, 'suspicious_behavior.py'], 
                              capture_output=True, text=True, cwd=os.path.dirname(__file__))
        print("Suspicious behavior demo output:")
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
    except Exception as e:
        print(f"Error running suspicious behavior demo: {e}")

def main():
    """Main function"""
    print("=== Security Agent Demo Runner ===")
    print("This script will run both normal and suspicious behavior demos")
    print("Start the security agent in another terminal to see the risk scores")
    print()
    
    # Run normal behavior first
    run_normal_behavior()
    
    # Wait a bit
    print("\nWaiting 5 seconds before running suspicious behavior...")
    time.sleep(5)
    
    # Run suspicious behavior
    run_suspicious_behavior()
    
    print("\n=== Demo Complete ===")
    print("Check the security agent output to see the risk scores")

if __name__ == "__main__":
    main()
