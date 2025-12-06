#!/bin/bash
# Simple start script for dashboard

cd "$(dirname "$0")"

echo "🛡️  Starting Linux Security Agent Dashboard"
echo "=========================================="
echo ""
echo "Dashboard will be available at:"
echo "  - http://localhost:5001 (from VM)"
echo "  - http://136.112.137.224:5001 (from your browser, if firewall allows)"
echo ""
echo "Press Ctrl+C to stop"
echo ""

python3 app.py

