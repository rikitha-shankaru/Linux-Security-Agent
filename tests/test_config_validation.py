"""
Unit tests for configuration validation
"""
import unittest
import sys
import os
import tempfile
import json
import yaml

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))


class TestConfigValidation(unittest.TestCase):
    """Test configuration validation logic"""
    
    def test_validate_risk_threshold(self):
        """Test risk threshold validation"""
        from enhanced_security_agent import EnhancedSecurityAgent
        
        # Test valid threshold
        config = {'risk_threshold': 75.0}
        agent = EnhancedSecurityAgent(config)
        self.assertEqual(agent.config.get('risk_threshold'), 75.0)
        
        # Test threshold clamping (should be 0-100)
        config_high = {'risk_threshold': 150.0}
        agent_high = EnhancedSecurityAgent(config_high)
        self.assertLessEqual(agent_high.config.get('risk_threshold'), 100.0)
        
        config_low = {'risk_threshold': -10.0}
        agent_low = EnhancedSecurityAgent(config_low)
        self.assertGreaterEqual(agent_low.config.get('risk_threshold'), 0.0)
    
    def test_validate_anomaly_weight(self):
        """Test anomaly weight validation"""
        from enhanced_security_agent import EnhancedSecurityAgent
        
        config = {'anomaly_weight': 0.5}
        agent = EnhancedSecurityAgent(config)
        # Should be clamped to 0-1
        self.assertGreaterEqual(agent.config.get('anomaly_weight'), 0.0)
        self.assertLessEqual(agent.config.get('anomaly_weight'), 1.0)
    
    def test_validate_collector(self):
        """Test collector validation"""
        from enhanced_security_agent import EnhancedSecurityAgent
        
        # Valid collectors
        for collector in ['ebpf', 'auditd']:
            config = {'collector': collector}
            agent = EnhancedSecurityAgent(config)
            self.assertEqual(agent.config.get('collector'), collector)
        
        # Invalid collector should default to ebpf
        config = {'collector': 'invalid'}
        agent = EnhancedSecurityAgent(config)
        self.assertEqual(agent.config.get('collector'), 'ebpf')


if __name__ == '__main__':
    unittest.main()

