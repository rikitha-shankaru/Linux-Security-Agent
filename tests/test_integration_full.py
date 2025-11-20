#!/usr/bin/env python3
"""
Comprehensive Integration Tests for Linux Security Agent
Tests the full pipeline from syscall capture to anomaly detection
"""

import unittest
import time
import threading
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.enhanced_security_agent import EnhancedSecurityAgent
    from core.enhanced_anomaly_detector import EnhancedAnomalyDetector
    from core.enhanced_ebpf_monitor import StatefulEBPFMonitor
    IMPORTS_AVAILABLE = True
except ImportError as e:
    IMPORTS_AVAILABLE = False
    IMPORT_ERROR = str(e)


@unittest.skipIf(not IMPORTS_AVAILABLE, f"Imports not available: {IMPORT_ERROR}")
class TestFullPipelineIntegration(unittest.TestCase):
    """Test the complete pipeline from syscall capture to risk scoring"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            'risk_threshold': 30.0,
            'anomaly_weight': 0.3,
            'collector': 'ebpf',
            'debug': False
        }
        self.agent = None
    
    def tearDown(self):
        """Clean up after tests"""
        if self.agent:
            try:
                self.agent.stop_monitoring()
            except:
                pass
    
    def test_agent_initialization(self):
        """Test that agent initializes correctly"""
        self.agent = EnhancedSecurityAgent(self.config)
        self.assertIsNotNone(self.agent)
        self.assertIsNotNone(self.agent.enhanced_risk_scorer)
    
    def test_syscall_event_processing(self):
        """Test that syscall events are processed correctly"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        # Simulate syscall event
        test_pid = 1234
        test_syscall = 'execve'
        test_event = {
            'pid': test_pid,
            'syscall_num': 59,
            'syscall_name': test_syscall,
            'timestamp': time.time()
        }
        
        # Process event
        self.agent._handle_syscall_event(test_pid, test_syscall, test_event)
        
        # Verify process was tracked
        with self.agent.processes_lock:
            self.assertIn(test_pid, self.agent.processes)
            self.assertGreater(self.agent.processes[test_pid].get('syscall_count', 0), 0)
    
    def test_risk_score_calculation(self):
        """Test risk score calculation for different syscalls"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        # Low risk syscall
        self.agent._handle_syscall_event(1001, 'read', {'pid': 1001, 'syscall_name': 'read'})
        with self.agent.processes_lock:
            low_risk = self.agent.processes.get(1001, {}).get('risk_score', 0)
        
        # High risk syscall
        self.agent._handle_syscall_event(1002, 'ptrace', {'pid': 1002, 'syscall_name': 'ptrace'})
        with self.agent.processes_lock:
            high_risk = self.agent.processes.get(1002, {}).get('risk_score', 0)
        
        # High risk should be higher than low risk
        self.assertGreater(high_risk, low_risk)
    
    def test_anomaly_detection_integration(self):
        """Test ML anomaly detection integration"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        # Train models first (with mock data)
        if self.agent.enhanced_anomaly_detector:
            training_data = [
                (['read', 'write', 'open', 'close'] * 10, {'cpu_percent': 10, 'memory_percent': 5}),
                (['read', 'write', 'mmap', 'munmap'] * 10, {'cpu_percent': 15, 'memory_percent': 8}),
            ] * 50  # 100 samples
            
            self.agent.enhanced_anomaly_detector.train_models(training_data)
            
            # Test normal behavior
            normal_result = self.agent.enhanced_anomaly_detector.detect_anomaly_ensemble(
                ['read', 'write', 'open', 'close'],
                {'cpu_percent': 10, 'memory_percent': 5},
                pid=2001
            )
            self.assertIsNotNone(normal_result)
            
            # Test anomalous behavior
            anomalous_result = self.agent.enhanced_anomaly_detector.detect_anomaly_ensemble(
                ['ptrace', 'mount', 'setuid', 'setgid'] * 5,
                {'cpu_percent': 90, 'memory_percent': 80},
                pid=2002
            )
            self.assertIsNotNone(anomalous_result)
            # Anomalous should have higher score
            self.assertGreater(anomalous_result.anomaly_score, normal_result.anomaly_score)
    
    def test_container_detection_integration(self):
        """Test container detection integration"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        if self.agent.container_security_monitor:
            # Mock container detection
            with patch.object(self.agent.container_security_monitor, 'get_container_info') as mock_get:
                mock_get.return_value = None  # No container
                
                # Process event
                self.agent._handle_syscall_event(3001, 'execve', {'pid': 3001, 'syscall_name': 'execve'})
                
                # Verify it was processed
                with self.agent.processes_lock:
                    self.assertIn(3001, self.agent.processes)
    
    def test_memory_cleanup(self):
        """Test that memory cleanup works correctly"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        # Create many processes
        for i in range(100):
            self.agent._handle_syscall_event(4000 + i, 'read', {'pid': 4000 + i, 'syscall_name': 'read'})
        
        # Wait for cleanup
        time.sleep(2)
        
        # Verify cleanup happened (processes should be cleaned up if stale)
        # Note: This test may need adjustment based on cleanup logic
        with self.agent.processes_lock:
            # At least some processes should still be tracked
            self.assertGreater(len(self.agent.processes), 0)
    
    def test_statistics_tracking(self):
        """Test that statistics are tracked correctly"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        # Process multiple events
        for i in range(10):
            self.agent._handle_syscall_event(5000 + i, 'read', {'pid': 5000 + i, 'syscall_name': 'read'})
        
        # Check statistics
        with self.agent.stats_lock:
            self.assertGreater(self.agent.stats['total_processes'], 0)


@unittest.skipIf(not IMPORTS_AVAILABLE, f"Imports not available: {IMPORT_ERROR}")
class TestAttackSimulation(unittest.TestCase):
    """Simulate attack patterns and verify detection"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            'risk_threshold': 50.0,
            'anomaly_weight': 0.3,
            'collector': 'ebpf',
            'debug': False
        }
        self.agent = None
    
    def tearDown(self):
        """Clean up after tests"""
        if self.agent:
            try:
                self.agent.stop_monitoring()
            except:
                pass
    
    def test_privilege_escalation_simulation(self):
        """Simulate privilege escalation attack pattern"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        # Simulate attack: setuid, setgid, execve
        attack_pid = 6001
        attack_syscalls = ['setuid', 'setgid', 'execve', 'chroot']
        
        for syscall in attack_syscalls:
            self.agent._handle_syscall_event(
                attack_pid, 
                syscall, 
                {'pid': attack_pid, 'syscall_name': syscall}
            )
        
        # Check risk score
        with self.agent.processes_lock:
            risk_score = self.agent.processes.get(attack_pid, {}).get('risk_score', 0)
            # Should be high risk
            self.assertGreater(risk_score, 30.0)
    
    def test_container_escape_simulation(self):
        """Simulate container escape attempt"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        if self.agent.container_security_monitor:
            # Simulate cross-container access
            source_pid = 7001
            target_pid = 7002
            
            # Mock container detection
            with patch.object(self.agent.container_security_monitor, '_get_process_container') as mock_get:
                mock_get.side_effect = lambda pid: 'container-1' if pid == source_pid else 'container-2'
                
                # Simulate cross-container syscall
                detected = self.agent.container_security_monitor.detect_cross_container_attempt(
                    source_pid, target_pid, 'ptrace'
                )
                
                # Should detect cross-container attempt
                self.assertTrue(detected)
    
    def test_high_frequency_attack_simulation(self):
        """Simulate high-frequency attack (DoS pattern)"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        attack_pid = 8001
        
        # Rapid syscalls
        for _ in range(100):
            self.agent._handle_syscall_event(
                attack_pid,
                'fork',
                {'pid': attack_pid, 'syscall_name': 'fork'}
            )
        
        # Check that high frequency was detected
        with self.agent.processes_lock:
            risk_score = self.agent.processes.get(attack_pid, {}).get('risk_score', 0)
            # High frequency should increase risk
            self.assertGreater(risk_score, 20.0)


@unittest.skipIf(not IMPORTS_AVAILABLE, f"Imports not available: {IMPORT_ERROR}")
class TestPerformanceBenchmarks(unittest.TestCase):
    """Performance and scalability tests"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            'risk_threshold': 30.0,
            'collector': 'ebpf',
            'debug': False
        }
        self.agent = None
    
    def tearDown(self):
        """Clean up after tests"""
        if self.agent:
            try:
                self.agent.stop_monitoring()
            except:
                pass
    
    def test_event_processing_performance(self):
        """Test event processing performance"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        # Measure time to process many events
        num_events = 1000
        start_time = time.time()
        
        for i in range(num_events):
            self.agent._handle_syscall_event(
                i % 100,  # 100 different PIDs
                'read',
                {'pid': i % 100, 'syscall_name': 'read'}
            )
        
        elapsed = time.time() - start_time
        events_per_second = num_events / elapsed
        
        # Should process at least 1000 events per second
        self.assertGreater(events_per_second, 1000)
        print(f"Event processing: {events_per_second:.0f} events/sec")
    
    def test_memory_usage(self):
        """Test memory usage with many processes"""
        self.agent = EnhancedSecurityAgent(self.config)
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create many processes
        for i in range(500):
            self.agent._handle_syscall_event(
                i,
                'read',
                {'pid': i, 'syscall_name': 'read'}
            )
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (< 100MB for 500 processes)
        self.assertLess(memory_increase, 100)
        print(f"Memory increase: {memory_increase:.2f} MB for 500 processes")


if __name__ == '__main__':
    unittest.main(verbosity=2)

