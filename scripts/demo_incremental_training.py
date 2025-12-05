#!/usr/bin/env python3
"""
Demonstration of Incremental Model Retraining
Shows how models automatically improve over time with new normal behavior samples
"""

import sys
import os
import time
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.enhanced_anomaly_detector import EnhancedAnomalyDetector
from core.incremental_trainer import IncrementalTrainer, AdaptiveThresholdManager


def generate_sample_data(count=100, pattern='normal'):
    """Generate sample syscall data"""
    import random
    
    if pattern == 'normal':
        syscalls_pool = ['read', 'write', 'open', 'close', 'stat', 'fstat', 'mmap', 'munmap']
        samples = []
        for _ in range(count):
            syscalls = random.choices(syscalls_pool, k=random.randint(10, 30))
            process_info = {
                'cpu_percent': random.uniform(5, 30),
                'memory_percent': random.uniform(5, 20),
                'num_threads': random.randint(1, 5)
            }
            samples.append((syscalls, process_info))
        return samples
    
    elif pattern == 'anomalous':
        high_risk = ['ptrace', 'setuid', 'setgid', 'mount', 'umount', 'chmod']
        samples = []
        for _ in range(count):
            syscalls = random.choices(high_risk, k=random.randint(10, 20))
            process_info = {
                'cpu_percent': random.uniform(60, 95),
                'memory_percent': random.uniform(50, 90),
                'num_threads': random.randint(10, 30)
            }
            samples.append((syscalls, process_info))
        return samples


def demo_basic_incremental_training():
    """Demonstrate basic incremental training"""
    print("=" * 70)
    print("DEMO 1: Basic Incremental Training")
    print("=" * 70)
    print()
    
    # Initialize detector
    print("🔧 Step 1: Initialize anomaly detector...")
    config = {
        'contamination': 0.1,
        'nu': 0.1,
        'eps': 0.5,
        'min_samples': 5
    }
    detector = EnhancedAnomalyDetector(config)
    print("   ✅ Detector initialized")
    print()
    
    # Initial training
    print("🧠 Step 2: Initial model training with 200 normal samples...")
    initial_data = generate_sample_data(200, 'normal')
    detector.train_models(initial_data)
    print("   ✅ Initial training complete")
    print()
    
    # Test detection before retraining
    print("📊 Step 3: Test anomaly detection (before retraining)...")
    test_normal = generate_sample_data(10, 'normal')
    test_anomalous = generate_sample_data(10, 'anomalous')
    
    normal_scores = []
    anomalous_scores = []
    
    for syscalls, process_info in test_normal:
        result = detector.detect_anomaly_ensemble(syscalls, process_info, pid=1000)
        normal_scores.append(result.anomaly_score)
    
    for syscalls, process_info in test_anomalous:
        result = detector.detect_anomaly_ensemble(syscalls, process_info, pid=2000)
        anomalous_scores.append(result.anomaly_score)
    
    print(f"   Normal samples avg score: {sum(normal_scores)/len(normal_scores):.2f}")
    print(f"   Anomalous samples avg score: {sum(anomalous_scores)/len(anomalous_scores):.2f}")
    print()
    
    # Incremental retraining
    print("🔄 Step 4: Incremental retraining with 150 new normal samples...")
    new_data = generate_sample_data(150, 'normal')
    detector.train_models(new_data, append=True)  # append=True for incremental
    print("   ✅ Incremental retraining complete")
    print()
    
    # Test detection after retraining
    print("📊 Step 5: Test anomaly detection (after retraining)...")
    normal_scores_after = []
    anomalous_scores_after = []
    
    for syscalls, process_info in test_normal:
        result = detector.detect_anomaly_ensemble(syscalls, process_info, pid=1000)
        normal_scores_after.append(result.anomaly_score)
    
    for syscalls, process_info in test_anomalous:
        result = detector.detect_anomaly_ensemble(syscalls, process_info, pid=2000)
        anomalous_scores_after.append(result.anomaly_score)
    
    print(f"   Normal samples avg score: {sum(normal_scores_after)/len(normal_scores_after):.2f}")
    print(f"   Anomalous samples avg score: {sum(anomalous_scores_after)/len(anomalous_scores_after):.2f}")
    print()
    
    print("✅ Demo 1 complete! Models improved with additional data.")
    print()


def demo_automatic_incremental_training():
    """Demonstrate automatic background incremental training"""
    print("=" * 70)
    print("DEMO 2: Automatic Background Incremental Training")
    print("=" * 70)
    print()
    
    # Initialize detector and trainer
    print("🔧 Step 1: Initialize detector and incremental trainer...")
    config = {
        'contamination': 0.1,
        'retrain_interval': 10,  # Short interval for demo (10 seconds)
        'min_samples_for_retrain': 20,
        'anomaly_score_threshold': 30.0
    }
    detector = EnhancedAnomalyDetector(config)
    trainer = IncrementalTrainer(detector, config)
    print("   ✅ Initialized")
    print()
    
    # Initial training
    print("🧠 Step 2: Initial training...")
    initial_data = generate_sample_data(100, 'normal')
    detector.train_models(initial_data)
    print("   ✅ Initial training complete")
    print()
    
    # Start automatic trainer
    print("🚀 Step 3: Start automatic incremental trainer...")
    trainer.start()
    print("   ✅ Trainer started (will retrain every 10 seconds)")
    print()
    
    # Simulate continuous operation
    print("📡 Step 4: Simulate continuous operation (collecting samples)...")
    print("   Feeding normal behavior samples to the trainer...")
    print()
    
    for i in range(30):
        syscalls, process_info = generate_sample_data(1, 'normal')[0]
        result = detector.detect_anomaly_ensemble(syscalls, process_info, pid=3000)
        
        # Add sample to trainer
        trainer.add_sample(syscalls, process_info, result.anomaly_score)
        
        # Print stats every 5 samples
        if (i + 1) % 5 == 0:
            stats = trainer.get_stats()
            print(f"   [{i+1}/30] Samples collected: {stats['samples_in_buffer']}, "
                  f"Retrainings: {stats['retraining_count']}")
        
        time.sleep(0.5)  # Simulate real-time collection
    
    print()
    print("⏳ Step 5: Waiting for automatic retraining...")
    time.sleep(12)  # Wait for retrain interval
    
    # Check final stats
    final_stats = trainer.get_stats()
    print()
    print("📊 Final Statistics:")
    print(f"   Total samples collected: {final_stats['total_samples_collected']}")
    print(f"   Retraining count: {final_stats['retraining_count']}")
    print(f"   Last retrain: {final_stats['time_since_last_retrain']:.1f}s ago")
    print()
    
    # Stop trainer
    trainer.stop()
    print("🛑 Trainer stopped")
    print()
    
    print("✅ Demo 2 complete! Models automatically retrained in background.")
    print()


def demo_adaptive_thresholds():
    """Demonstrate adaptive threshold management"""
    print("=" * 70)
    print("DEMO 3: Adaptive Threshold Management")
    print("=" * 70)
    print()
    
    print("🎯 Step 1: Initialize adaptive threshold manager...")
    threshold_manager = AdaptiveThresholdManager(initial_threshold=30.0, config={
        'target_fp_rate': 0.05,  # Target 5% false positive rate
        'adaptation_rate': 2.0
    })
    print(f"   Initial threshold: {threshold_manager.get_threshold():.2f}")
    print()
    
    print("📊 Step 2: Simulate detections with feedback...")
    print()
    
    # Simulate some detections
    import random
    
    for round_num in range(5):
        print(f"   Round {round_num + 1}:")
        
        for _ in range(10):
            # Generate a mix of normal and anomalous scores
            if random.random() < 0.3:
                # Anomalous sample
                score = random.uniform(40, 90)
                is_fp = random.random() < 0.1  # 10% are false positives
            else:
                # Normal sample
                score = random.uniform(10, 30)
                is_fp = False
            
            threshold_manager.update(score, is_fp)
        
        stats = threshold_manager.get_stats()
        print(f"     Threshold: {stats['current_threshold']:.2f}")
        print(f"     FP Rate: {stats['false_positive_rate']:.2%}")
        print(f"     Detections: {stats['total_detections']}")
        print()
    
    print("✅ Demo 3 complete! Threshold adapted based on false positive rate.")
    print()


def main():
    """Run all demos"""
    print()
    print("🎓 Incremental Model Retraining Demonstration")
    print("=" * 70)
    print()
    print("This demo shows three aspects of incremental learning:")
    print("1. Manual incremental retraining with append=True")
    print("2. Automatic background retraining")
    print("3. Adaptive threshold adjustment")
    print()
    input("Press Enter to start Demo 1...")
    print()
    
    # Demo 1
    demo_basic_incremental_training()
    
    input("Press Enter to start Demo 2...")
    print()
    
    # Demo 2
    demo_automatic_incremental_training()
    
    input("Press Enter to start Demo 3...")
    print()
    
    # Demo 3
    demo_adaptive_thresholds()
    
    print("=" * 70)
    print("🎉 All demos complete!")
    print("=" * 70)
    print()
    print("💡 To enable incremental training in the agent:")
    print("   1. Set 'enable_incremental_training: true' in config/config.yml")
    print("   2. Run: sudo python3 core/enhanced_security_agent.py --dashboard")
    print("   3. Models will automatically retrain every hour with new normal samples")
    print()


if __name__ == "__main__":
    main()

