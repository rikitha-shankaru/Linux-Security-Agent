#!/bin/bash
# Kill any running security agent processes

echo "Killing any running security agent processes..."

# Kill simple_agent.py processes
sudo pkill -f simple_agent.py

# Kill enhanced_security_agent.py processes
sudo pkill -f enhanced_security_agent.py

# Wait a moment
sleep 2

# Force kill if still running
sudo pkill -9 -f simple_agent.py
sudo pkill -9 -f enhanced_security_agent.py

echo "Done. All agent processes killed."

