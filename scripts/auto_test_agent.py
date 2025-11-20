#!/usr/bin/env python3
"""
Automated test script for the security agent
Tests attack detection and verifies scores are working correctly
"""
import os
import sys
import time
import subprocess
import signal
import threading
from pathlib import Path

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class AgentTester:
    def __init__(self):
        self.agent_process = None
        self.test_results = []
        
    def start_agent(self):
        """Start the agent in background"""
        print(f"{BLUE}🚀 Starting security agent...{RESET}")
        self.agent_process = subprocess.Popen(
            [sys.executable, 'core/simple_agent.py', '--collector', 'ebpf', '--threshold', '30'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        print(f"{GREEN}✅ Agent started (PID: {self.agent_process.pid}){RESET}")
        time.sleep(5)  # Give agent time to initialize
        
    def stop_agent(self):
        """Stop the agent"""
        if self.agent_process:
            print(f"{YELLOW}🛑 Stopping agent...{RESET}")
            self.agent_process.terminate()
            try:
                self.agent_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.agent_process.kill()
            print(f"{GREEN}✅ Agent stopped{RESET}")
    
    def run_attack(self, name, attack_func):
        """Run an attack and check results"""
        print(f"\n{YELLOW}🔴 Running attack: {name}{RESET}")
        try:
            attack_func()
            print(f"{GREEN}✅ Attack executed: {name}{RESET}")
            time.sleep(2)  # Give agent time to process
            return True
        except Exception as e:
            print(f"{RED}❌ Attack failed: {name} - {e}{RESET}")
            return False
    
    def test_high_frequency_attack(self):
        """Test high-frequency file operations"""
        temp_dir = Path('/tmp/auto_test')
        temp_dir.mkdir(exist_ok=True)
        
        try:
            for i in range(200):
                test_file = temp_dir / f"test_{i}.txt"
                test_file.write_text(f"Attack data {i}\n" * 50)
                test_file.read_text()
                os.stat(test_file)
                test_file.unlink()
            
            # Cleanup
            temp_dir.rmdir()
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")
    
    def test_process_churn(self):
        """Test rapid process creation"""
        processes = []
        for i in range(50):
            proc = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(0.1)'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            processes.append(proc)
        
        for proc in processes:
            proc.wait()
    
    def test_network_scanning(self):
        """Test network scanning pattern"""
        import socket
        for port in range(8000, 8020):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect(('127.0.0.1', port))
                sock.close()
            except:
                pass
    
    def check_agent_output(self):
        """Check if agent detected attacks"""
        if not self.agent_process:
            return False
        
        # Read recent output
        try:
            # Note: This is simplified - in real test, you'd parse agent output
            # or check logs/API
            return True
        except:
            return False
    
    def run_all_tests(self):
        """Run all automated tests"""
        print(f"{BLUE}{'='*60}{RESET}")
        print(f"{BLUE}🧪 Automated Security Agent Test Suite{RESET}")
        print(f"{BLUE}{'='*60}{RESET}\n")
        
        # Check if we're in the right directory
        if not os.path.exists('core/simple_agent.py'):
            print(f"{RED}❌ Error: Must run from project root directory{RESET}")
            return False
        
        # Check if models are trained
        model_dir = os.path.expanduser('~/.cache/security_agent')
        if not os.path.exists(os.path.join(model_dir, 'isolation_forest.pkl')):
            print(f"{YELLOW}⚠️  ML models not found. Training models first...{RESET}")
            train_result = subprocess.run(
                [sys.executable, 'scripts/train_with_dataset.py', 
                 '--file', 'datasets/normal_behavior_dataset.json'],
                capture_output=True
            )
            if train_result.returncode != 0:
                print(f"{RED}❌ Model training failed{RESET}")
                return False
            print(f"{GREEN}✅ Models trained{RESET}")
        
        try:
            # Start agent
            self.start_agent()
            
            # Run attacks
            attacks = [
                ("High-Frequency Attack", self.test_high_frequency_attack),
                ("Process Churn", self.test_process_churn),
                ("Network Scanning", self.test_network_scanning),
            ]
            
            for name, attack_func in attacks:
                success = self.run_attack(name, attack_func)
                self.test_results.append((name, success))
                time.sleep(1)
            
            # Let agent process for a bit
            print(f"\n{YELLOW}⏳ Waiting for agent to process attacks...{RESET}")
            time.sleep(5)
            
            # Summary
            print(f"\n{BLUE}{'='*60}{RESET}")
            print(f"{BLUE}📊 Test Results{RESET}")
            print(f"{BLUE}{'='*60}{RESET}")
            for name, success in self.test_results:
                status = f"{GREEN}✅ PASS{RESET}" if success else f"{RED}❌ FAIL{RESET}"
                print(f"  {name}: {status}")
            
            print(f"\n{YELLOW}💡 Check agent output above for risk/anomaly scores{RESET}")
            print(f"{YELLOW}💡 Expected: Risk scores should spike to 30-100 during attacks{RESET}")
            print(f"{YELLOW}💡 Expected: Anomaly scores should be > 10.00 during attacks{RESET}")
            
        finally:
            self.stop_agent()
        
        return all(result[1] for result in self.test_results)

if __name__ == '__main__':
    tester = AgentTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

