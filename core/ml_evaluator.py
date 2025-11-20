#!/usr/bin/env python3
"""
ML Model Evaluation Module
Provides metrics and evaluation tools for anomaly detection models
"""

import numpy as np
from typing import List, Tuple, Dict, Any, Optional
from collections import defaultdict
import json
import os
from dataclasses import dataclass, asdict


@dataclass
class EvaluationMetrics:
    """Structured evaluation metrics"""
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    threshold: float
    total_samples: int


class MLEvaluator:
    """ML model evaluation and metrics calculation"""
    
    def __init__(self, detector):
        """
        Initialize evaluator with detector
        
        Args:
            detector: EnhancedAnomalyDetector instance
        """
        self.detector = detector
    
    def evaluate_on_dataset(self, 
                           normal_samples: List[Tuple[List[str], Dict]],
                           anomalous_samples: List[Tuple[List[str], Dict]],
                           threshold: float = 50.0) -> EvaluationMetrics:
        """
        Evaluate model on labeled dataset
        
        Args:
            normal_samples: List of (syscalls, process_info) tuples - should be negative
            anomalous_samples: List of (syscalls, process_info) tuples - should be positive
            threshold: Risk score threshold for classification
        
        Returns:
            EvaluationMetrics object with all metrics
        """
        if not self.detector.is_fitted:
            raise ValueError("Detector must be trained before evaluation")
        
        tp = 0  # True positives: anomalous correctly identified
        fp = 0  # False positives: normal incorrectly flagged as anomalous
        tn = 0  # True negatives: normal correctly identified as normal
        fn = 0  # False negatives: anomalous incorrectly identified as normal
        
        # Evaluate normal samples (should be negative)
        for syscalls, process_info in normal_samples:
            result = self.detector.detect_anomaly_ensemble(syscalls, process_info)
            if result.anomaly_score >= threshold:
                fp += 1  # False positive
            else:
                tn += 1  # True negative
        
        # Evaluate anomalous samples (should be positive)
        for syscalls, process_info in anomalous_samples:
            result = self.detector.detect_anomaly_ensemble(syscalls, process_info)
            if result.anomaly_score >= threshold:
                tp += 1  # True positive
            else:
                fn += 1  # False negative
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0
        
        return EvaluationMetrics(
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            accuracy=accuracy,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            threshold=threshold,
            total_samples=len(normal_samples) + len(anomalous_samples)
        )
    
    def find_optimal_threshold(self,
                              normal_samples: List[Tuple[List[str], Dict]],
                              anomalous_samples: List[Tuple[List[str], Dict]],
                              threshold_range: Tuple[float, float] = (0.0, 100.0),
                              step: float = 1.0) -> Dict[str, Any]:
        """
        Find optimal threshold that maximizes F1 score
        
        Args:
            normal_samples: Normal behavior samples
            anomalous_samples: Anomalous behavior samples
            threshold_range: (min, max) threshold range to search
            step: Step size for threshold search
        
        Returns:
            Dict with optimal threshold and metrics
        """
        best_threshold = threshold_range[0]
        best_f1 = 0.0
        best_metrics = None
        
        thresholds = []
        f1_scores = []
        
        for threshold in np.arange(threshold_range[0], threshold_range[1] + step, step):
            metrics = self.evaluate_on_dataset(normal_samples, anomalous_samples, threshold)
            thresholds.append(threshold)
            f1_scores.append(metrics.f1_score)
            
            if metrics.f1_score > best_f1:
                best_f1 = metrics.f1_score
                best_threshold = threshold
                best_metrics = metrics
        
        return {
            'optimal_threshold': best_threshold,
            'optimal_f1': best_f1,
            'metrics_at_optimal': asdict(best_metrics) if best_metrics else None,
            'threshold_curve': {
                'thresholds': thresholds,
                'f1_scores': f1_scores
            }
        }
    
    def generate_confusion_matrix(self,
                                 normal_samples: List[Tuple[List[str], Dict]],
                                 anomalous_samples: List[Tuple[List[str], Dict]],
                                 threshold: float = 50.0) -> Dict[str, int]:
        """
        Generate confusion matrix
        
        Returns:
            Dict with TP, FP, TN, FN counts
        """
        metrics = self.evaluate_on_dataset(normal_samples, anomalous_samples, threshold)
        
        return {
            'true_positives': metrics.true_positives,
            'false_positives': metrics.false_positives,
            'true_negatives': metrics.true_negatives,
            'false_negatives': metrics.false_negatives
        }
    
    def calculate_roc_curve(self,
                           normal_samples: List[Tuple[List[str], Dict]],
                           anomalous_samples: List[Tuple[List[str], Dict]],
                           num_thresholds: int = 100) -> Dict[str, Any]:
        """
        Calculate ROC curve
        
        Returns:
            Dict with TPR, FPR, thresholds, and AUC
        """
        # Get scores for all samples
        normal_scores = []
        anomalous_scores = []
        
        for syscalls, process_info in normal_samples:
            result = self.detector.detect_anomaly_ensemble(syscalls, process_info)
            normal_scores.append(result.anomaly_score)
        
        for syscalls, process_info in anomalous_samples:
            result = self.detector.detect_anomaly_ensemble(syscalls, process_info)
            anomalous_scores.append(result.anomaly_score)
        
        # Calculate thresholds
        all_scores = normal_scores + anomalous_scores
        min_score = min(all_scores)
        max_score = max(all_scores)
        thresholds = np.linspace(min_score, max_score, num_thresholds)
        
        tpr = []  # True Positive Rate (Recall)
        fpr = []  # False Positive Rate
        
        for threshold in thresholds:
            metrics = self.evaluate_on_dataset(normal_samples, anomalous_samples, threshold)
            tpr.append(metrics.recall)  # TPR = Recall
            fpr.append(metrics.false_positives / len(normal_samples) if len(normal_samples) > 0 else 0.0)
        
        # Calculate AUC (Area Under Curve) using trapezoidal rule
        auc = np.trapz(tpr, fpr)
        
        return {
            'true_positive_rates': tpr,
            'false_positive_rates': fpr,
            'thresholds': thresholds.tolist(),
            'auc': float(auc)
        }
    
    def export_evaluation_report(self,
                                normal_samples: List[Tuple[List[str], Dict]],
                                anomalous_samples: List[Tuple[List[str], Dict]],
                                output_path: str,
                                threshold: float = 50.0) -> bool:
        """
        Export comprehensive evaluation report to JSON
        
        Args:
            normal_samples: Normal behavior samples
            anomalous_samples: Anomalous behavior samples
            output_path: Path to output JSON file
            threshold: Classification threshold
        
        Returns:
            True if successful
        """
        try:
            # Calculate all metrics
            metrics = self.evaluate_on_dataset(normal_samples, anomalous_samples, threshold)
            confusion_matrix = self.generate_confusion_matrix(normal_samples, anomalous_samples, threshold)
            optimal_threshold = self.find_optimal_threshold(normal_samples, anomalous_samples)
            roc_curve = self.calculate_roc_curve(normal_samples, anomalous_samples)
            
            report = {
                'evaluation_timestamp': str(np.datetime64('now')),
                'threshold_used': threshold,
                'metrics': asdict(metrics),
                'confusion_matrix': confusion_matrix,
                'optimal_threshold': optimal_threshold,
                'roc_curve': roc_curve,
                'dataset_info': {
                    'normal_samples': len(normal_samples),
                    'anomalous_samples': len(anomalous_samples),
                    'total_samples': len(normal_samples) + len(anomalous_samples)
                }
            }
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error exporting evaluation report: {e}")
            return False
    
    def print_evaluation_summary(self,
                                normal_samples: List[Tuple[List[str], Dict]],
                                anomalous_samples: List[Tuple[List[str], Dict]],
                                threshold: float = 50.0):
        """
        Print human-readable evaluation summary
        """
        metrics = self.evaluate_on_dataset(normal_samples, anomalous_samples, threshold)
        confusion_matrix = self.generate_confusion_matrix(normal_samples, anomalous_samples, threshold)
        
        print("\n" + "=" * 60)
        print("ML Model Evaluation Summary")
        print("=" * 60)
        print(f"\nThreshold: {threshold:.2f}")
        print(f"\nConfusion Matrix:")
        print(f"  True Positives (TP):  {confusion_matrix['true_positives']}")
        print(f"  False Positives (FP): {confusion_matrix['false_positives']}")
        print(f"  True Negatives (TN):  {confusion_matrix['true_negatives']}")
        print(f"  False Negatives (FN): {confusion_matrix['false_negatives']}")
        print(f"\nMetrics:")
        print(f"  Precision: {metrics.precision:.4f}")
        print(f"  Recall:    {metrics.recall:.4f}")
        print(f"  F1 Score:  {metrics.f1_score:.4f}")
        print(f"  Accuracy:  {metrics.accuracy:.4f}")
        print(f"\nTotal Samples: {metrics.total_samples}")
        print("=" * 60)

