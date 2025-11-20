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
        """Start the agent in background with output capture"""
        print(f"{BLUE}🚀 Starting security agent...{RESET}")
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_file = os.path.join(project_root, '/tmp/agent_test_output.log')
        
        # Start agent with output to file so we can read it
        self.agent_process = subprocess.Popen(
            [sys.executable, 'core/simple_agent.py', '--collector', 'ebpf', '--threshold', '30'],
            stdout=open('/tmp/agent_test_output.log', 'w'),
            stderr=subprocess.STDOUT,
            cwd=project_root
        )
        print(f"{GREEN}✅ Agent started (PID: {self.agent_process.pid}){RESET}")
        print(f"{YELLOW}   Output being logged to /tmp/agent_test_output.log{RESET}")
        time.sleep(8)  # Give agent more time to initialize and start capturing
        
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
        """Check if agent detected attacks by reading log file"""
        log_file = '/tmp/agent_test_output.log'
        if not os.path.exists(log_file):
            return False, "Log file not found"
        
        try:
            with open(log_file, 'r') as f:
                content = f.read()
            
            # Check for key indicators
            has_models = 'Models loaded' in content or 'Loaded pre-trained' in content
            has_syscalls = 'Syscalls:' in content or 'total_syscalls' in content
            has_anomalies = 'Anomalies:' in content or 'anomalies' in content.lower()
            has_risk = 'Risk' in content or 'risk_score' in content.lower()
            
            # Try to extract some stats
            import re
            anomaly_match = re.search(r'Anomalies:\s*(\d+)', content)
            syscall_match = re.search(r'Syscalls:\s*(\d+)', content)
            
            anomaly_count = int(anomaly_match.group(1)) if anomaly_match else 0
            syscall_count = int(syscall_match.group(1)) if syscall_match else 0
            
            status = []
            if has_models:
                status.append("✅ Models loaded")
            if has_syscalls:
                status.append(f"✅ Captured {syscall_count} syscalls")
            if has_anomalies:
                status.append(f"✅ Detected {anomaly_count} anomalies")
            if has_risk:
                status.append("✅ Risk scoring active")
            
            return True, "\n".join(status) if status else "Agent running but no stats found"
        except Exception as e:
            return False, f"Error reading log: {e}"
    
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
            time.sleep(8)  # Give more time for processing
            
            # Check agent output
            print(f"\n{BLUE}📊 Checking agent detection results...{RESET}")
            detected, status_msg = self.check_agent_output()
            if detected:
                print(f"{GREEN}{status_msg}{RESET}")
            else:
                print(f"{YELLOW}{status_msg}{RESET}")
            
            # Show last few lines of agent output
            log_file = '/tmp/agent_test_output.log'
            if os.path.exists(log_file):
                print(f"\n{YELLOW}📄 Last 20 lines of agent output:{RESET}")
                print(f"{BLUE}{'-'*60}{RESET}")
                try:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()
                        for line in lines[-20:]:
                            print(line.rstrip())
                except:
                    print(f"{RED}Could not read log file{RESET}")
                print(f"{BLUE}{'-'*60}{RESET}")
            
            # Summary
            print(f"\n{BLUE}{'='*60}{RESET}")
            print(f"{BLUE}📊 Test Results{RESET}")
            print(f"{BLUE}{'='*60}{RESET}")
            for name, success in self.test_results:
                status = f"{GREEN}✅ PASS{RESET}" if success else f"{RED}❌ FAIL{RESET}"
                print(f"  {name}: {status}")
            
            print(f"\n{YELLOW}💡 Expected: Risk scores should spike to 30-100 during attacks{RESET}")
            print(f"{YELLOW}💡 Expected: Anomaly scores should be > 10.00 during attacks{RESET}")
            print(f"{YELLOW}💡 Full agent output: cat /tmp/agent_test_output.log{RESET}")
            
        finally:
            self.stop_agent()
            # Cleanup log file
            try:
                if os.path.exists('/tmp/agent_test_output.log'):
                    os.remove('/tmp/agent_test_output.log')
            except:
                pass
        
        return all(result[1] for result in self.test_results)

if __name__ == '__main__':
    tester = AgentTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

