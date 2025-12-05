"""
Unit tests for ML anomaly detection
"""
import unittest
from unittest.mock import Mock, patch
import sys
import os
import numpy as np

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))


class TestMLAnomalyDetector(unittest.TestCase):
    """Test ML anomaly detection"""
    
    def setUp(self):
        """Set up test fixtures"""
        try:
            from enhanced_anomaly_detector import EnhancedAnomalyDetector
            self.config = {
                'contamination': 0.1,
                'nu': 0.1
            }
            self.detector = EnhancedAnomalyDetector(self.config)
        except ImportError:
            self.skipTest("ML dependencies not available")
    
    def test_extract_features_empty_syscalls(self):
        """Test feature extraction with empty syscall list"""
        features = self.detector.extract_advanced_features([], None)
        self.assertEqual(len(features), 50)
        self.assertTrue(np.all(features == 0))
    
    def test_extract_features_normal_syscalls(self):
        """Test feature extraction with normal syscalls"""
        syscalls = ['read', 'write', 'open', 'close', 'read', 'write']
        features = self.detector.extract_advanced_features(syscalls, None)
        self.assertEqual(len(features), 50)
        self.assertTrue(np.any(features > 0))  # Should have non-zero features
    
    def test_extract_features_high_risk_syscalls(self):
        """Test feature extraction with high-risk syscalls"""
        syscalls = ['ptrace', 'setuid', 'mount', 'chroot']
        features = self.detector.extract_advanced_features(syscalls, None)
        self.assertEqual(len(features), 50)
        # High-risk ratio feature should be > 0
        self.assertGreater(features[10], 0)  # High-risk ratio is at index 10
    
    def test_detect_anomaly_not_fitted(self):
        """Test anomaly detection when models not fitted"""
        result = self.detector.detect_anomaly_ensemble(['read', 'write'], None, 1000)
        self.assertFalse(result.is_anomaly)
        self.assertEqual(result.anomaly_score, 0.0)
        self.assertEqual(result.model_used, "none")
    
    def test_feature_extraction_with_process_info(self):
        """Test feature extraction with process info"""
        syscalls = ['read', 'write']
        process_info = {
            'cpu_percent': 10.5,
            'memory_percent': 5.2,
            'num_threads': 3
        }
        features = self.detector.extract_advanced_features(syscalls, process_info)
        self.assertEqual(len(features), 50)
        # Resource features should be non-zero (cpu_percent, memory_percent, num_threads at indices 17-19)
        self.assertTrue(any(features[15:20] > 0))  # Resource features are at indices 17-19


if __name__ == '__main__':
    unittest.main()

