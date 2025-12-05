#!/bin/bash
# Quick Test Runner - Copy this to your VM and run

cd ~/Linux-Security-Agent
git pull origin main
sudo python3 scripts/comprehensive_agent_test.py

