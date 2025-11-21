#!/usr/bin/env python3
"""
Automated Attack Test Runner
Runs attack simulations and verifies agent detection
"""

import sys
import os
import time
import subprocess
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tests.test_automated_attacks import AutomatedAttackTestRunner

def main():
    """Main entry point"""
    print(f"{'='*70}")
    print("🚀 Starting Automated Attack Test Suite")
    print(f"{'='*70}")
    print("\nThis will:")
    print("  1. Start the security agent in the background")
    print("  2. Execute various attack patterns")
    print("  3. Verify agent detection")
    print("  4. Generate comprehensive test report")
    print("\n⚠️  Note: Requires sudo for eBPF collector")
    print(f"{'='*70}\n")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("\n❌ Error: This script requires root privileges (sudo)")
        print("   Please run: sudo python3 scripts/run_attack_tests.py")
        sys.exit(1)
    
    # Run tests
    runner = AutomatedAttackTestRunner()
    report = runner.run_all_tests()
    
    # Print final summary with proper alignment
    print(f"\n{'='*70}")
    print("✅ AUTOMATED ATTACK TESTS COMPLETE")
    print(f"{'='*70}")
    print(f"\n📊 Results:")
    print(f"  {'Tests Run:':<18} {report['tests_run']:>3}")
    print(f"  {'Failures:':<18} {report['failures']:>3}")
    print(f"  {'Errors:':<18} {report['errors']:>3}")
    print(f"  {'Success:':<18} {'✅ YES' if report['success'] else '❌ NO'}")
    print(f"\n💾 Full report: attack_test_report.json")
    print(f"{'='*70}")
    
    return 0 if report['success'] else 1

if __name__ == '__main__':
    sys.exit(main())

