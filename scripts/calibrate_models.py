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
            raw_scores.append(result.anomaly_score)
            true_labels.append(0)  # All normal
        
        print(f"✅ Generated {len(raw_scores)} calibration samples")
        
    elif args.normal and args.anomalous:
        print("📂 Loading normal and anomalous data...")
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
    
    print("\n" + "=" * 70)
    print("📊 Calibration Results")
    print("=" * 70)
    print(f"Brier Score: {metrics['brier_score']:.4f} (lower is better)")
    print(f"Expected Calibration Error (ECE): {metrics['ece']:.4f} (lower is better)")
    print(f"Calibrated: {metrics['calibrated']}")
    print(f"Samples: {metrics.get('n_samples', len(raw_scores))}")
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

