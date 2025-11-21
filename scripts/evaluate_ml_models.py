#!/usr/bin/env python3
"""
ML Model Evaluation Script
Generates comprehensive evaluation report with metrics for academic submission
"""

import sys
import os
import json
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any
import numpy as np

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.enhanced_anomaly_detector import EnhancedAnomalyDetector
from core.ml_evaluator import MLEvaluator, EvaluationMetrics

def generate_normal_samples(count: int = 500) -> List[Tuple[List[str], Dict]]:
    """Generate normal behavior samples"""
    normal_syscalls = ['read', 'write', 'open', 'close', 'stat', 'fstat', 
                       'getpid', 'getppid', 'getuid', 'getgid', 'mmap', 
                       'munmap', 'brk', 'access', 'lseek']
    
    samples = []
    for _ in range(count):
        # Generate random sequence of normal syscalls
        syscall_seq = np.random.choice(normal_syscalls, size=50, replace=True).tolist()
        process_info = {
            'cpu_percent': np.random.uniform(0, 30),
            'memory_percent': np.random.uniform(0, 20),
            'num_threads': np.random.randint(1, 10)
        }
        samples.append((syscall_seq, process_info))
    
    return samples

def generate_anomalous_samples(count: int = 100) -> List[Tuple[List[str], Dict]]:
    """Generate anomalous behavior samples (attack patterns)"""
    # High-risk syscalls that indicate attacks
    high_risk_syscalls = ['ptrace', 'setuid', 'setgid', 'execve', 'fork', 
                          'chmod', 'chown', 'mount', 'umount', 'reboot']
    
    # Mix of normal and high-risk for realistic attack patterns
    normal_syscalls = ['read', 'write', 'open', 'close']
    
    samples = []
    for _ in range(count):
        # Generate attack-like pattern: mostly normal with bursts of high-risk
        syscall_seq = []
        for _ in range(50):
            if np.random.random() < 0.3:  # 30% chance of high-risk syscall
                syscall_seq.append(np.random.choice(high_risk_syscalls))
            else:
                syscall_seq.append(np.random.choice(normal_syscalls))
        
        process_info = {
            'cpu_percent': np.random.uniform(50, 95),  # High CPU
            'memory_percent': np.random.uniform(40, 90),  # High memory
            'num_threads': np.random.randint(10, 50)  # Many threads
        }
        samples.append((syscall_seq, process_info))
    
    return samples

def evaluate_models(detector: EnhancedAnomalyDetector, 
                   normal_samples: List[Tuple[List[str], Dict]],
                   anomalous_samples: List[Tuple[List[str], Dict]]) -> Dict[str, Any]:
    """Run comprehensive model evaluation"""
    
    evaluator = MLEvaluator(detector)
    
    print("🔍 Running Model Evaluation...")
    print("=" * 70)
    
    # Evaluate at different thresholds
    thresholds = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0]
    results = []
    
    for threshold in thresholds:
        metrics = evaluator.evaluate_on_dataset(
            normal_samples, 
            anomalous_samples, 
            threshold=threshold
        )
        results.append({
            'threshold': threshold,
            'precision': metrics.precision,
            'recall': metrics.recall,
            'f1_score': metrics.f1_score,
            'accuracy': metrics.accuracy,
            'true_positives': metrics.true_positives,
            'false_positives': metrics.false_positives,
            'true_negatives': metrics.true_negatives,
            'false_negatives': metrics.false_negatives
        })
    
    # Find optimal threshold
    optimal = evaluator.find_optimal_threshold(
        normal_samples,
        anomalous_samples,
        threshold_range=(10.0, 80.0),
        step=5.0
    )
    
    # Generate confusion matrix at optimal threshold
    confusion_matrix = evaluator.generate_confusion_matrix(
        normal_samples,
        anomalous_samples,
        threshold=optimal['optimal_threshold']
    )
    
    # Generate ROC curve data
    roc_data = evaluator.calculate_roc_curve(
        normal_samples,
        anomalous_samples,
        num_thresholds=50
    )
    
    # Calculate AUC (simplified - using trapezoidal rule)
    auc = 0.0
    if len(roc_data['fpr']) > 1:
        for i in range(1, len(roc_data['fpr'])):
            auc += (roc_data['fpr'][i] - roc_data['fpr'][i-1]) * roc_data['tpr'][i]
    
    return {
        'threshold_results': results,
        'optimal_threshold': optimal,
        'confusion_matrix': confusion_matrix,
        'roc_curve': roc_data,
        'auc': auc,
        'evaluation_timestamp': time.time()
    }

def print_evaluation_report(eval_results: Dict[str, Any]):
    """Print formatted evaluation report"""
    
    print("\n" + "=" * 70)
    print("📊 ML MODEL EVALUATION REPORT")
    print("=" * 70)
    
    # Optimal threshold results
    optimal = eval_results['optimal_threshold']
    print(f"\n🎯 Optimal Threshold: {optimal['optimal_threshold']:.2f}")
    print(f"   Optimal F1 Score: {optimal['optimal_f1']:.4f}")
    
    # Best threshold metrics
    best_threshold = optimal['optimal_threshold']
    threshold_results = eval_results['threshold_results']
    best_result = next((r for r in threshold_results if abs(r['threshold'] - best_threshold) < 1.0), None)
    
    if best_result:
        print(f"\n📈 Metrics at Optimal Threshold ({best_threshold:.1f}):")
        print(f"   Precision:  {best_result['precision']:.4f} ({best_result['precision']*100:.2f}%)")
        print(f"   Recall:     {best_result['recall']:.4f} ({best_result['recall']*100:.2f}%)")
        print(f"   F1 Score:   {best_result['f1_score']:.4f}")
        print(f"   Accuracy:   {best_result['accuracy']:.4f} ({best_result['accuracy']*100:.2f}%)")
    
    # Confusion Matrix
    cm = eval_results['confusion_matrix']
    print(f"\n📋 Confusion Matrix (Threshold: {best_threshold:.1f}):")
    print(f"   True Positives (TP):  {cm['true_positives']:4d}  |  Anomalies correctly detected")
    print(f"   False Positives (FP): {cm['false_positives']:4d}  |  Normal flagged as anomaly")
    print(f"   True Negatives (TN):  {cm['true_negatives']:4d}  |  Normal correctly identified")
    print(f"   False Negatives (FN): {cm['false_negatives']:4d}  |  Anomalies missed")
    
    # ROC AUC
    print(f"\n📉 ROC AUC: {eval_results['auc']:.4f}")
    if eval_results['auc'] >= 0.9:
        print("   ✅ Excellent discrimination (AUC ≥ 0.9)")
    elif eval_results['auc'] >= 0.8:
        print("   ✅ Good discrimination (AUC ≥ 0.8)")
    elif eval_results['auc'] >= 0.7:
        print("   ⚠️  Acceptable discrimination (AUC ≥ 0.7)")
    else:
        print("   ⚠️  Poor discrimination (AUC < 0.7)")
    
    # Threshold comparison table
    print(f"\n📊 Performance Across Thresholds:")
    print(f"{'Threshold':<12} {'Precision':<12} {'Recall':<12} {'F1 Score':<12} {'Accuracy':<12}")
    print("-" * 60)
    for result in eval_results['threshold_results']:
        print(f"{result['threshold']:>10.1f}  {result['precision']:>10.4f}  {result['recall']:>10.4f}  "
              f"{result['f1_score']:>10.4f}  {result['accuracy']:>10.4f}")
    
    print("\n" + "=" * 70)

def save_evaluation_report(eval_results: Dict[str, Any], output_file: str = "ml_evaluation_report.json"):
    """Save evaluation results to JSON file"""
    output_path = project_root / output_file
    
    # Convert numpy types to native Python types for JSON
    def convert_to_json(obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, dict):
            return {k: convert_to_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_to_json(item) for item in obj]
        return obj
    
    json_data = convert_to_json(eval_results)
    
    with open(output_path, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"\n💾 Evaluation report saved to: {output_path}")

def main():
    """Main evaluation script"""
    print("🧠 ML Model Evaluation for Linux Security Agent")
    print("=" * 70)
    print("This script will:")
    print("  1. Train models on normal behavior")
    print("  2. Evaluate on normal and anomalous samples")
    print("  3. Generate comprehensive metrics report")
    print("=" * 70)
    
    # Initialize detector
    config = {
        'contamination': 0.1,
        'nu': 0.1,
        'eps': 0.5,
        'min_samples': 5,
        'pca_components': 10,
        'feature_window': 100
    }
    
    detector = EnhancedAnomalyDetector(config)
    
    # Generate training data (normal behavior)
    print("\n📊 Generating training data (normal behavior)...")
    training_data = generate_normal_samples(500)
    print(f"   Generated {len(training_data)} normal samples")
    
    # Train models
    print("\n🔧 Training ML models...")
    detector.train_models(training_data)
    print("   ✅ Models trained successfully")
    
    # Generate test data
    print("\n📊 Generating test data...")
    normal_test = generate_normal_samples(200)
    anomalous_test = generate_anomalous_samples(100)
    print(f"   Normal test samples: {len(normal_test)}")
    print(f"   Anomalous test samples: {len(anomalous_test)}")
    
    # Run evaluation
    eval_results = evaluate_models(detector, normal_test, anomalous_test)
    
    # Print report
    print_evaluation_report(eval_results)
    
    # Save report
    save_evaluation_report(eval_results)
    
    print("\n✅ Evaluation complete!")
    print("\n💡 Next steps:")
    print("   - Review ml_evaluation_report.json for detailed results")
    print("   - Use these metrics in your academic submission")
    print("   - Include confusion matrix and ROC AUC in documentation")

if __name__ == "__main__":
    main()

