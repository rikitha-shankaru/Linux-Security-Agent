#!/bin/bash
# Linux Security Agent - Demo Script

echo "🧪 Running Security Agent Demo"
echo "=============================="

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup first."
    exit 1
fi

# Terminal 1: Start the agent with timeout
echo "Starting security agent in background (30 second timeout)..."
source venv/bin/activate
python3 security_agent_mac.py --dashboard --threshold 30 --timeout 30 &
AGENT_PID=$!

# Wait a moment for agent to start
sleep 3

# Terminal 2: Run demo scripts
echo "Running demo scripts..."
cd demo
python3 run_demo.py

# Wait for agent to finish or stop it
echo "Waiting for agent to finish..."
wait $AGENT_PID 2>/dev/null || echo "Agent stopped"

echo "Demo complete!"
