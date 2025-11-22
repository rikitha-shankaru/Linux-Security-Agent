#!/usr/bin/env python3
"""
Run Thread Safety Stress Tests
Author: Likitha Shankar

NOTE: These tests require psutil and rich packages.
      Run on Linux VM where dependencies are installed.
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Check for required dependencies
missing_deps = []
try:
    import psutil
except ImportError:
    missing_deps.append("psutil")

try:
    import rich
except ImportError:
    missing_deps.append("rich")

if missing_deps:
    print("❌ Missing required dependencies:")
    for dep in missing_deps:
        print(f"   - {dep}")
    print("\n💡 Install dependencies:")
    print("   sudo apt install python3-psutil python3-rich")
    print("   OR")
    print("   pip3 install psutil rich")
    print("\n⚠️  These tests should be run on Linux VM where dependencies are available.")
    sys.exit(1)

from tests.test_thread_safety import ThreadSafetyTester

if __name__ == "__main__":
    print("🧪 Thread Safety Stress Test Runner")
    print("=" * 70)
    print()
    
    tester = ThreadSafetyTester()
    success = tester.run_all_tests()
    
    if success:
        print("\n✅ All thread safety tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some thread safety tests failed. Review errors above.")
        sys.exit(1)

