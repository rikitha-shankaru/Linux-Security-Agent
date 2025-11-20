#!/bin/bash
# Trigger some syscalls to test the agent

echo "Triggering syscalls for testing..."

# File operations (read syscalls)
ls -la /etc
cat /etc/passwd | head -5

# Network operations
hostname

# Process operations
ps aux | grep python | wc -l

# File writes
echo "test" > /tmp/test_agent.txt
cat /tmp/test_agent.txt
rm /tmp/test_agent.txt

echo "Activity triggered!"

