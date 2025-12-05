#!/bin/bash
# Quick wrapper script to run automated tests

cd "$(dirname "$0")"

echo "🛡️  Linux Security Agent - Automated Testing"
echo "=============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  This script needs sudo privileges"
    echo "Running with sudo..."
    sudo python3 scripts/automate_all_tests.py "$@"
else
    python3 scripts/automate_all_tests.py "$@"
fi

