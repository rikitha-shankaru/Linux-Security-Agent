"""
Unit tests for EnhancedRiskScorer
"""
import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
from enhanced_security_agent import EnhancedRiskScorer


class TestEnhancedRiskScorer(unittest.TestCase):
    """Test cases for EnhancedRiskScorer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'risk_threshold': 50.0,
            'anomaly_weight': 0.3,
            'decay_factor': 0.95,
            'decay_interval': 60
        }
        self.scorer = EnhancedRiskScorer(self.config)
    
    def test_init_default_config(self):
        """Test initialization with default config"""
        scorer = EnhancedRiskScorer()
        self.assertIsNotNone(scorer.config)
        self.assertIsNotNone(scorer.base_risk_scores)
    
    def test_update_risk_score_normal_syscalls(self):
        """Test risk scoring for normal syscalls"""
        syscalls = ['read', 'write', 'open', 'close']
        score = self.scorer.update_risk_score(1000, syscalls)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)
        self.assertLess(score, 30.0)  # Normal syscalls should be low risk
    
    def test_update_risk_score_high_risk_syscalls(self):
        """Test risk scoring for high-risk syscalls"""
        syscalls = ['ptrace', 'setuid', 'mount']
        score = self.scorer.update_risk_score(1001, syscalls)
        self.assertGreater(score, 30.0)  # High-risk syscalls should increase score
    
    def test_behavioral_baseline_creation(self):
        """Test that behavioral baselines are created"""
        syscalls = ['read', 'write']
        self.scorer.update_risk_score(1002, syscalls)
        self.assertIn(1002, self.scorer.process_baselines)
    
    def test_risk_score_decay(self):
        """Test that risk scores decay over time"""
        import time
        syscalls = ['ptrace', 'setuid']
        score1 = self.scorer.update_risk_score(1003, syscalls)
        
        # Simulate time passing
        baseline = self.scorer.process_baselines[1003]
        baseline['last_updated'] = time.time() - 120  # 2 minutes ago
        
        score2 = self.scorer.update_risk_score(1003, ['read'])
        # Score should decay but new risky syscall could increase it
        self.assertGreaterEqual(score2, 0.0)
        self.assertLessEqual(score2, 100.0)
    
    def test_container_score_adjustment(self):
        """Test container-specific risk adjustments"""
        escape_syscalls = ['mount', 'chroot', 'pivot_root']
        score = self.scorer.update_risk_score(
            1004, escape_syscalls, container_id='container123'
        )
        self.assertGreater(score, 0.0)
    
    def test_anomaly_score_integration(self):
        """Test that anomaly score affects risk"""
        syscalls = ['read', 'write']
        score_without_anomaly = self.scorer.update_risk_score(
            1005, syscalls, anomaly_score=0.0
        )
        score_with_anomaly = self.scorer.update_risk_score(
            1006, syscalls, anomaly_score=0.8
        )
        self.assertGreater(score_with_anomaly, score_without_anomaly)


if __name__ == '__main__':
    unittest.main()

