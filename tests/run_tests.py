#!/usr/bin/env python3
"""
Test suite for Linux Security Agent
"""

import os
import sys
import time
import subprocess
import threading
import json
import unittest
from unittest.mock import patch, MagicMock

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from security_agent import SecurityAgent, SyscallRiskScorer, ProcessMonitor
    from anomaly_detector import AnomalyDetector
    from action_handler import ActionHandler, ActionType
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure all dependencies are installed")
    sys.exit(1)

class TestSyscallRiskScorer(unittest.TestCase):
    """Test the system call risk scorer"""
    
    def setUp(self):
        self.scorer = SyscallRiskScorer()
    
    def test_syscall_risk_levels(self):
        """Test that syscalls have appropriate risk levels"""
        # Low risk syscalls
        self.assertEqual(self.scorer.get_syscall_risk('read'), 1)
        self.assertEqual(self.scorer.get_syscall_risk('write'), 1)
        self.assertEqual(self.scorer.get_syscall_risk('open'), 1)
        
        # Medium risk syscalls
        self.assertEqual(self.scorer.get_syscall_risk('fork'), 3)
        self.assertEqual(self.scorer.get_syscall_risk('execve'), 5)
        self.assertEqual(self.scorer.get_syscall_risk('chmod'), 3)
        
        # High risk syscalls
        self.assertEqual(self.scorer.get_syscall_risk('ptrace'), 8)
        self.assertEqual(self.scorer.get_syscall_risk('setuid'), 8)
        self.assertEqual(self.scorer.get_syscall_risk('setgid'), 8)
        
        # Unknown syscall
        self.assertEqual(self.scorer.get_syscall_risk('unknown_syscall'), 2)
    
    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        # Test with low risk syscalls
        low_risk_syscalls = ['read', 'write', 'open', 'close']
        score = self.scorer.calculate_risk_score(low_risk_syscalls)
        self.assertLess(score, 20)  # Should be low
        
        # Test with high risk syscalls
        high_risk_syscalls = ['execve', 'setuid', 'ptrace', 'chmod']
        score = self.scorer.calculate_risk_score(high_risk_syscalls)
        self.assertGreater(score, 30)  # Should be high
    
    def test_risk_score_update(self):
        """Test risk score updates"""
        current_score = 10.0
        new_syscalls = ['execve', 'setuid']
        updated_score = self.scorer.update_risk_score(current_score, new_syscalls)
        
        # Score should increase
        self.assertGreater(updated_score, current_score)
        
        # Test with empty syscalls (decay)
        decayed_score = self.scorer.update_risk_score(updated_score, [])
        self.assertLess(decayed_score, updated_score)

class TestProcessMonitor(unittest.TestCase):
    """Test the process monitor"""
    
    def setUp(self):
        self.scorer = SyscallRiskScorer()
        self.monitor = ProcessMonitor(self.scorer)
    
    def test_process_risk_update(self):
        """Test process risk updates"""
        pid = 12345
        syscalls = ['read', 'write', 'execve']
        
        # Update process risk
        self.monitor.update_process_risk(pid, syscalls)
        
        # Check if process was added
        self.assertIn(pid, self.monitor.processes)
        
        # Check process data
        process = self.monitor.processes[pid]
        self.assertEqual(process['syscall_count'], len(syscalls))
        self.assertGreater(process['risk_score'], 0)
    
    def test_high_risk_processes(self):
        """Test high risk process detection"""
        # Add some processes with different risk levels
        self.monitor.update_process_risk(1001, ['read', 'write'])  # Low risk
        self.monitor.update_process_risk(1002, ['execve', 'setuid', 'ptrace'])  # High risk
        
        # Get high risk processes
        high_risk = self.monitor.get_high_risk_processes(threshold=50.0)
        
        # Should find the high risk process
        self.assertGreater(len(high_risk), 0)
        
        # Check that high risk process is in the list
        pids = [pid for pid, _, _, _ in high_risk]
        self.assertIn(1002, pids)

class TestAnomalyDetector(unittest.TestCase):
    """Test the anomaly detector"""
    
    def setUp(self):
        self.detector = AnomalyDetector()
    
    def test_feature_extraction(self):
        """Test feature extraction from syscalls"""
        syscalls = ['read', 'write', 'execve', 'setuid', 'ptrace']
        features = self.detector.extract_features(syscalls)
        
        # Should return a numpy array
        self.assertIsNotNone(features)
        self.assertGreater(len(features), 0)
    
    def test_anomaly_detection(self):
        """Test anomaly detection"""
        # Generate training data
        training_data = self.detector.generate_training_data(100)
        
        # Train the model
        self.detector.fit(training_data)
        
        # Test with normal syscalls
        normal_syscalls = ['read', 'write', 'open', 'close']
        is_anomaly, score = self.detector.predict(normal_syscalls)
        
        # Test with suspicious syscalls
        suspicious_syscalls = ['execve', 'setuid', 'ptrace', 'chmod']
        is_anomaly_suspicious, score_suspicious = self.detector.predict(suspicious_syscalls)
        
        # Suspicious syscalls should have different scores
        self.assertNotEqual(score, score_suspicious)

class TestActionHandler(unittest.TestCase):
    """Test the action handler"""
    
    def setUp(self):
        self.config = {
            'warn_threshold': 30.0,
            'freeze_threshold': 70.0,
            'kill_threshold': 90.0,
            'enable_warnings': True,
            'enable_freeze': True,
            'enable_kill': False,  # Safety first
            'log_file': '/tmp/test_security_agent.log'
        }
        self.handler = ActionHandler(self.config)
    
    def test_action_thresholds(self):
        """Test action threshold determination"""
        # Test warning threshold
        action = self.handler.should_take_action(12345, 35.0)
        self.assertEqual(action, ActionType.WARN)
        
        # Test freeze threshold
        action = self.handler.should_take_action(12345, 75.0)
        self.assertEqual(action, ActionType.FREEZE)
        
        # Test kill threshold (if enabled)
        self.handler.enable_kill = True
        action = self.handler.should_take_action(12345, 95.0)
        self.assertEqual(action, ActionType.KILL)
        
        # Test no action
        action = self.handler.should_take_action(12345, 20.0)
        self.assertEqual(action, ActionType.LOG)
    
    def test_action_history(self):
        """Test action history tracking"""
        # Take some actions
        self.handler.take_action(12345, "test_process", 35.0, 0.1, ActionType.WARN)
        self.handler.take_action(12346, "test_process2", 75.0, 0.2, ActionType.FREEZE)
        
        # Check history
        history = self.handler.get_action_history()
        self.assertGreaterEqual(len(history), 2)
        
        # Check that actions are recorded
        pids = [action['pid'] for action in history]
        self.assertIn(12345, pids)
        self.assertIn(12346, pids)

class TestSecurityAgent(unittest.TestCase):
    """Test the main security agent"""
    
    def setUp(self):
        # Mock arguments
        self.args = MagicMock()
        self.args.threshold = 50.0
        self.args.output = 'console'
        self.args.dashboard = False
        self.args.use_ebpf = False  # Use fallback mode for testing
        self.args.anomaly_detection = False
        self.args.enable_kill = False
        self.args.action_log = '/tmp/test_security_agent.log'
        
        self.agent = SecurityAgent(self.args)
    
    def test_agent_initialization(self):
        """Test agent initialization"""
        self.assertIsNotNone(self.agent.risk_scorer)
        self.assertIsNotNone(self.agent.monitor)
        self.assertIsNotNone(self.agent.console)
        self.assertFalse(self.agent.running)
    
    def test_syscall_simulation(self):
        """Test syscall simulation for processes"""
        # Create a mock process
        mock_proc = MagicMock()
        mock_proc.info = {'pid': 12345, 'name': 'python3', 'create_time': time.time()}
        
        # Test syscall simulation
        syscalls = self.agent._simulate_syscalls_for_process(mock_proc)
        
        # Should return some syscalls
        self.assertIsInstance(syscalls, list)
        self.assertGreater(len(syscalls), 0)
    
    def test_process_monitoring(self):
        """Test process monitoring"""
        # Test process name retrieval
        name = self.agent.monitor.get_process_name(os.getpid())
        self.assertIsNotNone(name)
        self.assertIsInstance(name, str)

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_demo_scripts(self):
        """Test that demo scripts can be imported and run"""
        try:
            # Test normal behavior script
            result = subprocess.run([
                sys.executable, 'demo/normal_behavior.py'
            ], capture_output=True, text=True, timeout=30)
            
            # Should complete successfully
            self.assertEqual(result.returncode, 0)
            
            # Test suspicious behavior script
            result = subprocess.run([
                sys.executable, 'demo/suspicious_behavior.py'
            ], capture_output=True, text=True, timeout=30)
            
            # Should complete successfully
            self.assertEqual(result.returncode, 0)
            
        except subprocess.TimeoutExpired:
            self.fail("Demo scripts took too long to run")
        except FileNotFoundError:
            self.skipTest("Demo scripts not found")

def run_performance_test():
    """Run performance tests"""
    print("\n=== Performance Tests ===")
    
    # Test risk scorer performance
    scorer = SyscallRiskScorer()
    syscalls = ['read', 'write', 'execve', 'setuid', 'ptrace'] * 1000
    
    start_time = time.time()
    for _ in range(1000):
        scorer.calculate_risk_score(syscalls)
    end_time = time.time()
    
    print(f"Risk scorer: {end_time - start_time:.3f}s for 1000 calculations")
    
    # Test anomaly detector performance
    detector = AnomalyDetector()
    training_data = detector.generate_training_data(1000)
    
    start_time = time.time()
    detector.fit(training_data)
    end_time = time.time()
    
    print(f"Anomaly detector training: {end_time - start_time:.3f}s")
    
    # Test prediction performance
    start_time = time.time()
    for _ in range(1000):
        detector.predict(syscalls)
    end_time = time.time()
    
    print(f"Anomaly detector prediction: {end_time - start_time:.3f}s for 1000 predictions")

def run_demo_test():
    """Run demo tests"""
    print("\n=== Demo Tests ===")
    
    try:
        # Run normal behavior demo
        print("Running normal behavior demo...")
        result = subprocess.run([
            sys.executable, 'demo/normal_behavior.py'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✓ Normal behavior demo completed successfully")
        else:
            print(f"✗ Normal behavior demo failed: {result.stderr}")
        
        # Run suspicious behavior demo
        print("Running suspicious behavior demo...")
        result = subprocess.run([
            sys.executable, 'demo/suspicious_behavior.py'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✓ Suspicious behavior demo completed successfully")
        else:
            print(f"✗ Suspicious behavior demo failed: {result.stderr}")
        
    except subprocess.TimeoutExpired:
        print("✗ Demo tests timed out")
    except FileNotFoundError:
        print("✗ Demo scripts not found")

def run_attack_tests():
    """Run automated attack detection tests"""
    print("\n=== Automated Attack Tests ===")
    try:
        from tests.test_automated_attacks import AutomatedAttackTestRunner
        runner = AutomatedAttackTestRunner()
        report = runner.run_all_tests()
        return report['success']
    except ImportError as e:
        print(f"⚠️  Attack tests not available: {e}")
        return False
    except Exception as e:
        print(f"❌ Attack tests failed: {e}")
        return False

def main():
    """Main test function"""
    print("Linux Security Agent - Test Suite")
    print("=" * 50)
    
    # Run unit tests
    print("\n=== Unit Tests ===")
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run performance tests
    run_performance_test()
    
    # Run demo tests
    run_demo_test()
    
    print("\n=== Test Summary ===")
    print("All tests completed!")
    print("\nTo run the security agent:")
    print("sudo python3 security_agent.py --dashboard")
    print("\nTo run demos:")
    print("python3 demo/run_demo.py")

if __name__ == "__main__":
    main()
