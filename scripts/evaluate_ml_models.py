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
    
    # OPTIMIZATION: Pre-compute all anomaly scores once
    print("\n📊 Computing anomaly scores for all samples...")
    print("   (This may take a minute - computing scores for 300 samples)")
    
    normal_scores = []
    total_normal = len(normal_samples)
    for i, (syscalls, process_info) in enumerate(normal_samples):
        if (i + 1) % 50 == 0:
            print(f"   Normal samples: {i+1}/{total_normal} ({((i+1)/total_normal)*100:.1f}%)")
        result = detector.detect_anomaly_ensemble(syscalls, process_info)
        normal_scores.append(result.anomaly_score)
    
    anomalous_scores = []
    total_anomalous = len(anomalous_samples)
    for i, (syscalls, process_info) in enumerate(anomalous_samples):
        if (i + 1) % 25 == 0:
            print(f"   Anomalous samples: {i+1}/{total_anomalous} ({((i+1)/total_anomalous)*100:.1f}%)")
        result = detector.detect_anomaly_ensemble(syscalls, process_info)
        anomalous_scores.append(result.anomaly_score)
    
    print("   ✅ All scores computed!")
    
    # Now evaluate at different thresholds using pre-computed scores
    print("\n📈 Evaluating at different thresholds...")
    thresholds = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0]
    results = []
    
    for threshold in thresholds:
        # Calculate metrics using pre-computed scores
        tp = sum(1 for score in anomalous_scores if score >= threshold)
        fn = len(anomalous_scores) - tp
        fp = sum(1 for score in normal_scores if score >= threshold)
        tn = len(normal_scores) - fp
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0
        
        results.append({
            'threshold': threshold,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'accuracy': accuracy,
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn
        })
        print(f"   Threshold {threshold:.1f}: F1={f1_score:.3f}, Precision={precision:.3f}, Recall={recall:.3f}")
    
    # Find optimal threshold
    print("\n🎯 Finding optimal threshold...")
    best_threshold = 50.0
    best_f1 = 0.0
    threshold_range = np.arange(10.0, 80.0, 5.0)
    
    for threshold in threshold_range:
        tp = sum(1 for score in anomalous_scores if score >= threshold)
        fn = len(anomalous_scores) - tp
        fp = sum(1 for score in normal_scores if score >= threshold)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        if f1_score > best_f1:
            best_f1 = f1_score
            best_threshold = threshold
    
    print(f"   ✅ Optimal threshold: {best_threshold:.1f} (F1={best_f1:.3f})")
    
    # Generate confusion matrix at optimal threshold
    print("\n📋 Generating confusion matrix...")
    tp = sum(1 for score in anomalous_scores if score >= best_threshold)
    fn = len(anomalous_scores) - tp
    fp = sum(1 for score in normal_scores if score >= best_threshold)
    tn = len(normal_scores) - fp
    
    confusion_matrix = {
        'true_positives': tp,
        'false_positives': fp,
        'true_negatives': tn,
        'false_negatives': fn
    }
    
    # Generate ROC curve data (using pre-computed scores)
    print("\n📉 Generating ROC curve...")
    all_scores = normal_scores + anomalous_scores
    min_score = min(all_scores)
    max_score = max(all_scores)
    
    # Use unique thresholds from actual scores for more accurate ROC
    unique_thresholds = sorted(set(normal_scores + anomalous_scores), reverse=True)
    if len(unique_thresholds) > 50:
        # Sample if too many
        indices = np.linspace(0, len(unique_thresholds)-1, 50, dtype=int)
        roc_thresholds = [unique_thresholds[i] for i in indices]
    else:
        roc_thresholds = unique_thresholds
    
    # Add boundary points
    roc_thresholds = [max_score + 1] + roc_thresholds + [min_score - 1]
    
    tpr = []
    fpr = []
    
    for threshold in roc_thresholds:
        tp = sum(1 for score in anomalous_scores if score >= threshold)
        fn = len(anomalous_scores) - tp
        fp = sum(1 for score in normal_scores if score >= threshold)
        
        tpr_val = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr_val = fp / len(normal_scores) if len(normal_scores) > 0 else 0.0
        
        tpr.append(tpr_val)
        fpr.append(fpr_val)
    
    # Sort by FPR for proper ROC curve (ascending FPR)
    fpr_array = np.array(fpr)
    tpr_array = np.array(tpr)
    sort_indices = np.argsort(fpr_array)
    fpr_sorted = fpr_array[sort_indices]
    tpr_sorted = tpr_array[sort_indices]
    
    # Ensure we start at (0,0) and end at (1,1)
    if fpr_sorted[0] > 0:
        fpr_sorted = np.concatenate([[0.0], fpr_sorted])
        tpr_sorted = np.concatenate([[0.0], tpr_sorted])
    if fpr_sorted[-1] < 1.0:
        fpr_sorted = np.concatenate([fpr_sorted, [1.0]])
        tpr_sorted = np.concatenate([tpr_sorted, [1.0]])
    
    # Calculate AUC using trapezoidal rule (integrate TPR with respect to FPR)
    auc = np.trapz(tpr_sorted, fpr_sorted)
    auc = max(0.0, min(1.0, auc))  # Clamp to [0, 1]
    
    print(f"   ✅ ROC AUC: {auc:.4f}")
    
    optimal = {
        'optimal_threshold': best_threshold,
        'optimal_f1': best_f1
    }
    
    roc_data = {
        'true_positive_rates': tpr_sorted.tolist(),
        'false_positive_rates': fpr_sorted.tolist(),
        'thresholds': roc_thresholds,
        'auc': float(auc)
    }
    
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

