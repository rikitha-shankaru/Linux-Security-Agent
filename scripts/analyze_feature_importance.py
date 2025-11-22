#!/usr/bin/env python3
"""
Analyze Feature Importance for 50-D Feature Engineering
Validates if 50 dimensions is optimal and identifies most important features
Author: Likitha Shankar
"""

import sys
import os
import argparse
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from core.utils.feature_importance_analyzer import FeatureImportanceAnalyzer
    from core.enhanced_anomaly_detector import EnhancedAnomalyDetector
    IMPORTS_AVAILABLE = True
except ImportError as e:
    IMPORTS_AVAILABLE = False
    IMPORT_ERROR = str(e)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze feature importance for 50-D feature engineering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze from training data file
  python3 scripts/analyze_feature_importance.py --file datasets/normal_behavior_dataset.json
  
  # Export report
  python3 scripts/analyze_feature_importance.py --file dataset.json --export report.json
        """
    )
    
    parser.add_argument('--file', type=str, required=True,
                       help='Path to JSON training data file')
    parser.add_argument('--export', type=str, default=None,
                       help='Export analysis report to JSON file')
    
    args = parser.parse_args()
    
    if not IMPORTS_AVAILABLE:
        print(f"❌ Cannot import required modules: {IMPORT_ERROR}")
        print("   Make sure scikit-learn, pandas, and numpy are installed")
        return 1
    
    # Check if file exists
    if not os.path.exists(args.file):
        print(f"❌ File not found: {args.file}")
        return 1
    
    # Load training data
    print(f"📂 Loading training data from {args.file}...")
    detector = EnhancedAnomalyDetector()
    training_data = detector.load_training_data_from_file(args.file)
    
    if not training_data:
        print("❌ No training data loaded")
        return 1
    
    print(f"✅ Loaded {len(training_data)} samples")
    
    # Analyze features
    analyzer = FeatureImportanceAnalyzer()
    report = analyzer.analyze_features(training_data, detector)
    
    # Print report
    analyzer.print_report(report)
    
    # Export if requested
    if args.export:
        analyzer.export_report(report, args.export)
    
    # Summary
    dim_analysis = report.dimensionality_analysis
    if dim_analysis.get('is_optimal'):
        print("\n✅ 50-D feature engineering is optimal!")
        return 0
    else:
        optimal_n = dim_analysis.get('optimal_components_95pct')
        if optimal_n:
            print(f"\n⚠️  Consider adjusting to {optimal_n} dimensions for optimal performance")
        return 0


if __name__ == "__main__":
    sys.exit(main())

