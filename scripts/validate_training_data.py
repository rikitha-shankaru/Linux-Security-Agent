#!/usr/bin/env python3
"""
Validate Training Data Quality
Checks training data for quality issues, outliers, and generates quality reports
Author: Likitha Shankar
"""

import sys
import os
import argparse
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.utils.training_data_validator import TrainingDataValidator


def main():
    parser = argparse.ArgumentParser(
        description='Validate training data quality',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate a single file
  python3 scripts/validate_training_data.py --file datasets/normal_behavior_dataset.json
  
  # Validate and export report
  python3 scripts/validate_training_data.py --file dataset.json --export report.json
        """
    )
    
    parser.add_argument('--file', type=str, required=True,
                       help='Path to JSON training data file')
    parser.add_argument('--export', type=str, default=None,
                       help='Export quality report to JSON file')
    parser.add_argument('--quiet', action='store_true',
                       help='Only show quality score and errors')
    
    args = parser.parse_args()
    
    # Check if file exists
    if not os.path.exists(args.file):
        print(f"❌ File not found: {args.file}")
        return 1
    
    # Validate
    validator = TrainingDataValidator()
    report = validator.validate_file(args.file)
    
    if args.quiet:
        print(f"Quality Score: {report.quality_score:.2%}")
        if report.errors:
            for error in report.errors:
                print(f"ERROR: {error}")
        return 0 if report.quality_score >= 0.7 and not report.errors else 1
    else:
        validator.print_report(report)
    
    # Export if requested
    if args.export:
        validator.export_report(report, args.export)
    
    # Return exit code based on quality
    if report.quality_score >= 0.7 and not report.errors:
        print("\n✅ Data quality is acceptable for training")
        return 0
    elif report.quality_score >= 0.5 and not report.errors:
        print("\n⚠️  Data quality is marginal - review recommendations")
        return 0
    else:
        print("\n❌ Data quality is poor - fix issues before training")
        return 1


if __name__ == "__main__":
    sys.exit(main())

