#!/bin/bash
# Quick start script for web dashboard

cd "$(dirname "$0")"

echo "🛡️  Starting Linux Security Agent Web Dashboard"
echo "================================================"
echo ""

# Check if dependencies are installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "⚠️  Flask not found. Installing dependencies..."
    pip3 install -r requirements.txt
    echo ""
fi

# Check if port 5000 is in use
if lsof -Pi :5000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Port 5000 is already in use"
    echo "   Killing existing process..."
    lsof -ti:5000 | xargs kill -9 2>/dev/null
    sleep 2
fi

echo "✅ Starting web server..."
echo ""
echo "🌐 Dashboard will be available at: http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo "================================================"
echo ""

python3 app.py

