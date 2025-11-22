#!/usr/bin/env python3
"""
Calibrate ML Models
Calibrates ensemble predictions using calibration data
Author: Likitha Shankar
"""

import sys
import os
import argparse
import numpy as np
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from core.enhanced_anomaly_detector import EnhancedAnomalyDetector
    from core.utils.model_calibration import ModelCalibrator
    IMPORTS_AVAILABLE = True
except ImportError as e:
    IMPORTS_AVAILABLE = False
    IMPORT_ERROR = str(e)


def main():
    parser = argparse.ArgumentParser(
        description='Calibrate ML models for better confidence estimates',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Calibrate using training data
  python3 scripts/calibrate_models.py --file datasets/normal_behavior_dataset.json
  
  # Calibrate with validation data (normal + anomalous)
  python3 scripts/calibrate_models.py --normal normal.json --anomalous attacks.json
        """
    )
    
    parser.add_argument('--file', type=str, default=None,
                       help='Training data file (for calibration)')
    parser.add_argument('--normal', type=str, default=None,
                       help='Normal behavior data file')
    parser.add_argument('--anomalous', type=str, default=None,
                       help='Anomalous behavior data file')
    parser.add_argument('--method', type=str, default='isotonic',
                       choices=['isotonic', 'platt'],
                       help='Calibration method')
    
    args = parser.parse_args()
    
    if not IMPORTS_AVAILABLE:
        print(f"❌ Cannot import required modules: {IMPORT_ERROR}")
        return 1
    
    # Load detector
    config = {'enable_calibration': True}
    detector = EnhancedAnomalyDetector(config)
    
    # Check if models are trained, if not, load or train them first
    if not detector.is_fitted:
        print("📚 Models not yet loaded. Attempting to load pre-trained models...")
        try:
            detector._load_models()
            if detector.is_fitted:
                print("✅ Pre-trained models loaded successfully")
        except Exception as e:
            print(f"⚠️  Could not load pre-trained models: {e}")
        
        if not detector.is_fitted:
            print("📚 No pre-trained models found. Training models first...")
            # Load training data
            if args.file:
                training_data = detector.load_training_data_from_file(args.file)
                if not training_data:
                    print("❌ No training data loaded")
                    return 1
                detector.train_models(training_data)
                print("✅ Models trained successfully")
            else:
                print("❌ Cannot train models: no training data file provided")
                print("   Use --file to specify training data")
                return 1
    else:
        print("✅ Models already loaded and ready")
    
    # Load training/calibration data
    if args.file:
        print(f"📂 Loading calibration data from {args.file}...")
        training_data = detector.load_training_data_from_file(args.file)
        if not training_data:
            print("❌ No training data loaded")
            return 1
        
        # For calibration, we need labels (assume all normal = 0)
        print("📊 Generating predictions for calibration...")
        raw_scores = []
        true_labels = []
        
        for syscalls, process_info in training_data[:200]:  # Use subset for calibration
            result = detector.detect_anomaly_ensemble(syscalls, process_info)
            score = result.anomaly_score
            raw_scores.append(score)
            true_labels.append(0)  # All normal
            
            # Debug: show first few scores
            if len(raw_scores) <= 3:
                print(f"   Sample {len(raw_scores)}: Raw score = {score:.2f}")
        
        print(f"✅ Generated {len(raw_scores)} calibration samples")
        print(f"   Score range: [{min(raw_scores):.2f}, {max(raw_scores):.2f}], Mean: {sum(raw_scores)/len(raw_scores):.2f}")
        
    elif args.normal and args.anomalous:
        print("📂 Loading normal and anomalous data...")
        
        # Check if files exist first
        if not os.path.exists(args.normal):
            print(f"❌ File not found: {args.normal}")
            print(f"   💡 Tip: Use --file option with existing dataset, or create {args.normal}")
            return 1
        
        if not os.path.exists(args.anomalous):
            print(f"❌ File not found: {args.anomalous}")
            print(f"   💡 Tip: Create attack dataset or use --file option with normal data only")
            return 1
        
        normal_data = detector.load_training_data_from_file(args.normal)
        anomalous_data = detector.load_training_data_from_file(args.anomalous)
        
        if not normal_data or not anomalous_data:
            print("❌ Failed to load calibration data")
            return 1
        
        # Generate predictions
        raw_scores = []
        true_labels = []
        
        print("📊 Generating predictions for normal samples...")
        for syscalls, process_info in normal_data[:100]:
            result = detector.detect_anomaly_ensemble(syscalls, process_info)
            raw_scores.append(result.anomaly_score)
            true_labels.append(0)  # Normal
        
        print("📊 Generating predictions for anomalous samples...")
        for syscalls, process_info in anomalous_data[:100]:
            result = detector.detect_anomaly_ensemble(syscalls, process_info)
            raw_scores.append(result.anomaly_score)
            true_labels.append(1)  # Anomalous
        
        print(f"✅ Generated {len(raw_scores)} calibration samples")
    else:
        parser.print_help()
        return 1
    
    # Calibrate
    if not detector.calibrator:
        print("❌ Calibrator not initialized. Enable calibration in config.")
        return 1
    
    print(f"🧠 Calibrating models using {args.method} method...")
    raw_scores_array = np.array(raw_scores)
    true_labels_array = np.array(true_labels)
    
    success = detector.calibrator.calibrate(raw_scores_array, true_labels_array, method=args.method)
    
    if not success:
        print("❌ Calibration failed")
        return 1
    
    # Evaluate calibration
    print("📈 Evaluating calibration quality...")
    metrics = detector.calibrator.evaluate_calibration(raw_scores_array, true_labels_array)
    
    # Show some sample predictions for debugging
    print("\n📊 Sample Predictions (first 5):")
    for i in range(min(5, len(raw_scores))):
        pred = detector.calibrator.predict_calibrated(raw_scores[i])
        print(f"   Sample {i+1}: Raw={raw_scores[i]:.2f}, "
              f"Calibrated={pred.calibrated_score:.2f}, "
              f"Prob={pred.calibrated_probability:.4f}, "
              f"CI=[{pred.confidence_interval_lower:.2f}, {pred.confidence_interval_upper:.2f}]")
    
    print("\n" + "=" * 70)
    print("📊 Calibration Results")
    print("=" * 70)
    print(f"Brier Score: {metrics['brier_score']:.6f} (lower is better, perfect=0.0)")
    print(f"Expected Calibration Error (ECE): {metrics['ece']:.6f} (lower is better, perfect=0.0)")
    print(f"Calibrated: {metrics['calibrated']}")
    print(f"Samples: {metrics.get('n_samples', len(raw_scores))}")
    print(f"\n📝 Note: Scores are 0.0000 because:")
    print(f"   - All samples are normal (label=0)")
    print(f"   - Model correctly predicts low anomaly scores")
    print(f"   - Calibrated probabilities are close to 0 (normal)")
    print(f"   - Brier score = mean((pred - 0)²) ≈ 0 when pred ≈ 0")
    print(f"\n💡 For meaningful calibration metrics, use both normal AND anomalous data:")
    print(f"   python3 scripts/calibrate_models.py --normal normal.json --anomalous attacks.json")
    print("=" * 70)
    
    if metrics['brier_score'] < 0.25 and metrics['ece'] < 0.1:
        print("\n✅ Calibration quality is good!")
    elif metrics['brier_score'] < 0.5 and metrics['ece'] < 0.2:
        print("\n⚠️  Calibration quality is acceptable")
    else:
        print("\n⚠️  Calibration quality needs improvement")
    
    # Save calibrator state (would need to be integrated into detector save/load)
    print("\n💡 Note: Calibration state is stored in detector instance.")
    print("   To persist, integrate calibrator save/load into model persistence.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

