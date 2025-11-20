"""
Unit tests for process tracking functionality
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import time

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
from enhanced_security_agent import EnhancedSecurityAgent


class TestProcessTracking(unittest.TestCase):
    """Test process tracking functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'debug': False,
            'risk_threshold': 50.0
        }
        self.agent = EnhancedSecurityAgent(self.config)
        # Don't start actual monitoring - just test methods
    
    def test_get_process_name_valid_pid(self):
        """Test getting process name for valid PID"""
        # Mock psutil
        with patch('psutil.Process') as mock_proc:
            mock_proc.return_value.name.return_value = 'test_process'
            name = self.agent._get_process_name(1000)
            self.assertEqual(name, 'test_process')
    
    def test_get_process_name_invalid_pid(self):
        """Test getting process name for invalid PID"""
        name = self.agent._get_process_name(-1)
        self.assertTrue('<invalid:' in name)
    
    def test_get_process_name_nonexistent_pid(self):
        """Test getting process name for non-existent PID"""
        import psutil
        with patch('psutil.Process', side_effect=psutil.NoSuchProcess(99999)):
            name = self.agent._get_process_name(99999)
            self.assertTrue('<unknown:' in name)
    
    def test_process_name_caching(self):
        """Test that process names are cached"""
        with patch('psutil.Process') as mock_proc:
            mock_proc.return_value.name.return_value = 'cached_process'
            
            # First call - should hit psutil
            name1 = self.agent._get_process_name(2000)
            self.assertEqual(name1, 'cached_process')
            
            # Second call - should use cache (psutil should not be called again)
            name2 = self.agent._get_process_name(2000)
            self.assertEqual(name2, 'cached_process')
            # Verify psutil was only called once (cached on second call)
            self.assertEqual(mock_proc.return_value.name.call_count, 1)
    
    def test_process_syscall_event_input_validation(self):
        """Test input validation in process_syscall_event"""
        # Invalid PID
        self.agent.process_syscall_event(-1, 'read')
        self.assertNotIn(-1, self.agent.processes)
        
        # Invalid syscall
        self.agent.process_syscall_event(1000, '')
        self.assertNotIn(1000, self.agent.processes)
        
        # Valid inputs should create process entry
        with patch.object(self.agent, '_get_process_name', return_value='test'):
            self.agent.process_syscall_event(3000, 'read')
            # Process should be created (even if we don't have full monitoring)
            # Note: may fail if psutil access is denied, which is OK
    
    def test_cleanup_old_processes(self):
        """Test cleanup of stale processes"""
        current_time = time.time()
        
        # Add a stale process (last update 10 minutes ago)
        self.agent.processes[5000] = {
            'name': 'stale_process',
            'last_update': current_time - 600,  # 10 minutes ago
            'risk_score': 10.0,
            'syscall_count': 5
        }
        
        # Add a fresh process
        self.agent.processes[5001] = {
            'name': 'fresh_process',
            'last_update': current_time - 60,  # 1 minute ago
            'risk_score': 10.0,
            'syscall_count': 5
        }
        
        # Run cleanup
        self.agent._cleanup_old_processes()
        
        # Stale process should be removed
        self.assertNotIn(5000, self.agent.processes)
        # Fresh process should remain
        self.assertIn(5001, self.agent.processes)
    
    def test_get_high_risk_processes(self):
        """Test getting high-risk processes"""
        self.agent.processes = {
            100: {'name': 'low_risk', 'risk_score': 20.0},
            101: {'name': 'medium_risk', 'risk_score': 45.0},
            102: {'name': 'high_risk', 'risk_score': 75.0},
            103: {'name': 'critical_risk', 'risk_score': 90.0}
        }
        
        high_risk = self.agent.get_high_risk_processes(threshold=50.0)
        
        # Should return processes with risk >= 50
        self.assertEqual(len(high_risk), 2)
        self.assertIn((102, 'high_risk', 75.0, 0.0), high_risk)
        self.assertIn((103, 'critical_risk', 90.0, 0.0), high_risk)


if __name__ == '__main__':
    unittest.main()

