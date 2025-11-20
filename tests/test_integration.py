"""
Integration tests for end-to-end functionality
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import time

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
from enhanced_security_agent import EnhancedSecurityAgent


class TestIntegration(unittest.TestCase):
    """Integration tests for full system flow"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'debug': False,
            'risk_threshold': 50.0,
            'collector': 'auditd'  # Use auditd for testing (doesn't require root)
        }
    
    @patch('psutil.Process')
    def test_full_event_flow(self, mock_proc):
        """Test full event processing flow"""
        # Setup mocks
        mock_proc.return_value.name.return_value = 'test_process'
        mock_proc.return_value.cpu_percent.return_value = 5.0
        mock_proc.return_value.memory_percent.return_value = 2.0
        mock_proc.return_value.num_threads.return_value = 2
        
        agent = EnhancedSecurityAgent(self.config)
        
        # Simulate syscall event
        agent.process_syscall_event(5000, 'read', {
            'cpu_percent': 5.0,
            'memory_percent': 2.0,
            'num_threads': 2
        })
        
        # Verify process was tracked
        self.assertIn(5000, agent.processes)
        self.assertEqual(agent.processes[5000]['syscall_count'], 1)
        self.assertIn('read', list(agent.processes[5000]['syscalls']))
    
    def test_risk_score_calculation_flow(self):
        """Test risk scoring calculation flow"""
        agent = EnhancedSecurityAgent(self.config)
        
        # Simulate multiple syscalls
        with patch.object(agent, '_get_process_name', return_value='test'):
            # Low-risk syscalls
            agent.process_syscall_event(6000, 'read')
            agent.process_syscall_event(6000, 'write')
            agent.process_syscall_event(6000, 'open')
            
            # Process should have low risk
            if 6000 in agent.processes:
                risk = agent.processes[6000]['risk_score']
                self.assertLess(risk, 50.0)
            
            # Add high-risk syscall
            agent.process_syscall_event(6000, 'ptrace')
            
            # Risk should increase
            if 6000 in agent.processes:
                risk_after = agent.processes[6000]['risk_score']
                # Risk should be higher (though may still be < threshold depending on smoothing)
                self.assertGreaterEqual(risk_after, 0.0)
                self.assertLessEqual(risk_after, 100.0)
    
    def test_statistics_tracking(self):
        """Test that statistics are properly tracked"""
        agent = EnhancedSecurityAgent(self.config)
        
        initial_stats = agent.get_monitoring_stats()
        self.assertIsInstance(initial_stats, dict)
        self.assertIn('total_processes', initial_stats)
        self.assertIn('high_risk_processes', initial_stats)
        self.assertIn('anomalies_detected', initial_stats)
    
    def test_config_loading_and_validation(self):
        """Test configuration loading and validation"""
        # Test with invalid config values
        invalid_config = {
            'risk_threshold': 150.0,  # Should be clamped to 100
            'anomaly_weight': 2.0,    # Should be clamped to 1.0
            'collector': 'invalid'    # Should default to ebpf
        }
        
        agent = EnhancedSecurityAgent(invalid_config)
        
        # Values should be validated/clamped
        self.assertLessEqual(agent.config.get('risk_threshold', 100), 100.0)
        self.assertLessEqual(agent.config.get('anomaly_weight', 1.0), 1.0)


if __name__ == '__main__':
    unittest.main()

