"""
Unit tests for container security monitoring
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))


class TestContainerSecurityMonitor(unittest.TestCase):
    """Test container security monitoring"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock Docker to avoid requiring actual Docker
        with patch.dict('sys.modules', {'docker': MagicMock()}):
            from container_security_monitor import ContainerSecurityMonitor
            self.config = {}
            # Create monitor without Docker dependency
            self.monitor = ContainerSecurityMonitor(self.config)
            # Set docker_available to False for testing
            self.monitor.docker_available = False
    
    def test_init_no_docker(self):
        """Test initialization without Docker"""
        self.assertFalse(self.monitor.docker_available)
        self.assertIsNotNone(self.monitor.default_policy)
    
    def test_validate_syscall_no_policy(self):
        """Test syscall validation when no policy exists"""
        # No container, no policy - should allow
        result = self.monitor.validate_syscall(1000, 'read')
        self.assertTrue(result)
    
    def test_get_process_container_invalid_pid(self):
        """Test getting container for invalid PID"""
        container_id = self.monitor._get_process_container(-1)
        self.assertIsNone(container_id)
    
    def test_get_process_container_no_docker(self):
        """Test getting container when Docker not available"""
        self.monitor.docker_available = False
        container_id = self.monitor._get_process_container(1000)
        # Should return None or handle gracefully
        self.assertIsNone(container_id)
    
    def test_detect_cross_container_attempt_no_containers(self):
        """Test cross-container detection with no containers"""
        result = self.monitor.detect_cross_container_attempt(1000, 2000, 'read')
        self.assertFalse(result)
    
    def test_container_policy_creation(self):
        """Test container policy creation"""
        # Mock container info
        self.monitor.containers['test_container'] = MagicMock()
        self.monitor.containers['test_container'].name = 'test'
        self.monitor.containers['test_container'].privileged = False
        
        self.monitor._create_container_policy('test_container')
        self.assertIn('test_container', self.monitor.container_policies)


if __name__ == '__main__':
    unittest.main()

