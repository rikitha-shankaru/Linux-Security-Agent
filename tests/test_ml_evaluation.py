#!/usr/bin/env python3
"""
ML Model Evaluation Tests
Tests model performance, metrics, and validation
"""

import unittest
import numpy as np
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.enhanced_anomaly_detector import EnhancedAnomalyDetector, AnomalyResult
    IMPORTS_AVAILABLE = True
except ImportError as e:
    IMPORTS_AVAILABLE = False
    IMPORT_ERROR = str(e)


@unittest.skipIf(not IMPORTS_AVAILABLE, f"Imports not available: {IMPORT_ERROR}")
class TestMLEvaluation(unittest.TestCase):
    """Test ML model evaluation and metrics"""
    
    def setUp(self):
        """Set up test environment"""
        self.detector = EnhancedAnomalyDetector({
            'contamination': 0.1,
            'nu': 0.1,
            'feature_window': 100
        })
        
        # Generate training data (normal behavior)
        self.training_data = []
        normal_syscalls = ['read', 'write', 'open', 'close', 'mmap', 'munmap']
        for i in range(200):
            syscalls = np.random.choice(normal_syscalls, size=50, replace=True).tolist()
            process_info = {
                'cpu_percent': np.random.uniform(0, 30),
                'memory_percent': np.random.uniform(0, 20),
                'num_threads': np.random.randint(1, 10)
            }
            self.training_data.append((syscalls, process_info))
    
    def test_model_training(self):
        """Test that models train successfully"""
        self.detector.train_models(self.training_data)
        self.assertTrue(self.detector.is_fitted)
        self.assertTrue(any(self.detector.models_trained.values()))
    
    def test_feature_extraction_consistency(self):
        """Test that feature extraction is consistent"""
        syscalls = ['read', 'write', 'open', 'close'] * 10
        
        features1 = self.detector.extract_advanced_features(syscalls)
        features2 = self.detector.extract_advanced_features(syscalls)
        
        # Should be identical for same input
        np.testing.assert_array_almost_equal(features1, features2)
    
    def test_feature_dimensions(self):
        """Test that features have correct dimensions"""
        syscalls = ['read', 'write', 'open', 'close'] * 10
        features = self.detector.extract_advanced_features(syscalls)
        
        # Should be 50-D feature vector
        self.assertEqual(len(features), 50)
        self.assertEqual(features.shape, (50,))
    
    def test_anomaly_detection_normal_vs_anomalous(self):
        """Test that normal and anomalous behavior are distinguished"""
        self.detector.train_models(self.training_data)
        
        # Normal behavior
        normal_syscalls = ['read', 'write', 'open', 'close', 'mmap']
        normal_result = self.detector.detect_anomaly_ensemble(
            normal_syscalls,
            {'cpu_percent': 10, 'memory_percent': 5, 'num_threads': 2}
        )
        
        # Anomalous behavior
        anomalous_syscalls = ['ptrace', 'mount', 'setuid', 'setgid', 'chroot'] * 5
        anomalous_result = self.detector.detect_anomaly_ensemble(
            anomalous_syscalls,
            {'cpu_percent': 90, 'memory_percent': 80, 'num_threads': 50}
        )
        
        # Anomalous should have higher score
        self.assertGreater(anomalous_result.anomaly_score, normal_result.anomaly_score)
    
    def test_model_persistence(self):
        """Test that models can be saved and loaded"""
        self.detector.train_models(self.training_data)
        
        # Save models
        self.detector._save_models()
        
        # Create new detector and load
        new_detector = EnhancedAnomalyDetector({
            'contamination': 0.1,
            'nu': 0.1
        })
        new_detector._load_models()
        
        # Should be fitted
        self.assertTrue(new_detector.is_fitted)
        
        # Should produce similar results
        test_syscalls = ['read', 'write', 'open', 'close']
        result1 = self.detector.detect_anomaly_ensemble(test_syscalls, {})
        result2 = new_detector.detect_anomaly_ensemble(test_syscalls, {})
        
        # Scores should be similar (within 10%)
        self.assertAlmostEqual(result1.anomaly_score, result2.anomaly_score, delta=10.0)
    
    def test_ensemble_consensus(self):
        """Test that ensemble models agree on clear cases"""
        self.detector.train_models(self.training_data)
        
        # Very normal behavior
        normal_syscalls = ['read', 'write', 'open', 'close'] * 20
        normal_result = self.detector.detect_anomaly_ensemble(normal_syscalls, {})
        
        # Very anomalous behavior
        anomalous_syscalls = ['ptrace', 'mount', 'setuid'] * 20
        anomalous_result = self.detector.detect_anomaly_ensemble(anomalous_syscalls, {})
        
        # Clear distinction
        score_diff = anomalous_result.anomaly_score - normal_result.anomaly_score
        self.assertGreater(score_diff, 20.0)  # At least 20 point difference
    
    def test_empty_syscall_handling(self):
        """Test handling of empty syscall lists"""
        self.detector.train_models(self.training_data)
        
        result = self.detector.detect_anomaly_ensemble([], {})
        self.assertIsNotNone(result)
        # Empty should have low score (no activity)
        self.assertLess(result.anomaly_score, 50.0)
    
    def test_feature_extraction_edge_cases(self):
        """Test feature extraction with edge cases"""
        # Single syscall
        features = self.detector.extract_advanced_features(['read'])
        self.assertEqual(len(features), 50)
        
        # Very long sequence
        long_seq = ['read'] * 1000
        features = self.detector.extract_advanced_features(long_seq)
        self.assertEqual(len(features), 50)
        
        # Mixed case
        mixed = ['read', 'READ', 'Write', 'write']
        features = self.detector.extract_advanced_features(mixed)
        self.assertEqual(len(features), 50)


@unittest.skipIf(not IMPORTS_AVAILABLE, f"Imports not available: {IMPORT_ERROR}")
class TestMLMetrics(unittest.TestCase):
    """Test ML evaluation metrics"""
    
    def setUp(self):
        """Set up test environment"""
        self.detector = EnhancedAnomalyDetector()
        
        # Generate labeled test data
        self.normal_data = []
        self.anomalous_data = []
        
        # Normal samples
        for i in range(100):
            syscalls = np.random.choice(['read', 'write', 'open', 'close'], size=30).tolist()
            self.normal_data.append((syscalls, {'cpu_percent': 10, 'memory_percent': 5}))
        
        # Anomalous samples
        for i in range(20):
            syscalls = np.random.choice(['ptrace', 'mount', 'setuid', 'setgid'], size=30).tolist()
            self.anomalous_data.append((syscalls, {'cpu_percent': 90, 'memory_percent': 80}))
    
    def test_precision_recall_calculation(self):
        """Calculate precision and recall metrics"""
        # Train on normal data only (unsupervised)
        self.detector.train_models(self.normal_data)
        
        # Test on both normal and anomalous
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        
        threshold = 50.0  # Risk score threshold
        
        # Test normal samples (should be negative)
        for syscalls, process_info in self.normal_data[:50]:
            result = self.detector.detect_anomaly_ensemble(syscalls, process_info)
            if result.anomaly_score >= threshold:
                false_positives += 1
        
        # Test anomalous samples (should be positive)
        for syscalls, process_info in self.anomalous_data:
            result = self.detector.detect_anomaly_ensemble(syscalls, process_info)
            if result.anomaly_score >= threshold:
                true_positives += 1
            else:
                false_negatives += 1
        
        # Calculate metrics
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        
        print(f"Precision: {precision:.2f}, Recall: {recall:.2f}")
        print(f"TP: {true_positives}, FP: {false_positives}, FN: {false_negatives}")
        
        # Should have reasonable performance
        self.assertGreater(precision, 0.0)
        self.assertGreater(recall, 0.0)
    
    def test_confusion_matrix(self):
        """Generate confusion matrix"""
        self.detector.train_models(self.normal_data)
        
        threshold = 50.0
        confusion_matrix = {
            'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0
        }
        
        # Test normal samples
        for syscalls, process_info in self.normal_data:
            result = self.detector.detect_anomaly_ensemble(syscalls, process_info)
            if result.anomaly_score >= threshold:
                confusion_matrix['FP'] += 1
            else:
                confusion_matrix['TN'] += 1
        
        # Test anomalous samples
        for syscalls, process_info in self.anomalous_data:
            result = self.detector.detect_anomaly_ensemble(syscalls, process_info)
            if result.anomaly_score >= threshold:
                confusion_matrix['TP'] += 1
            else:
                confusion_matrix['FN'] += 1
        
        print("Confusion Matrix:")
        print(f"  TP: {confusion_matrix['TP']}, FP: {confusion_matrix['FP']}")
        print(f"  FN: {confusion_matrix['FN']}, TN: {confusion_matrix['TN']}")
        
        # Should have some true positives
        self.assertGreater(confusion_matrix['TP'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)

