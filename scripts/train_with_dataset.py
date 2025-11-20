#!/usr/bin/env python3
"""
Train ML Models with Public Dataset
Loads training data from JSON file or URL and trains models
"""

import sys
import os
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.enhanced_anomaly_detector import EnhancedAnomalyDetector
    IMPORTS_AVAILABLE = True
except ImportError as e:
    IMPORTS_AVAILABLE = False
    IMPORT_ERROR = str(e)

def train_from_file(file_path: str, append: bool = False):
    """Train models from JSON file"""
    if not IMPORTS_AVAILABLE:
        print(f"❌ Cannot import detector: {IMPORT_ERROR}")
        return False
    
    detector = EnhancedAnomalyDetector()
    
    print(f"📂 Loading training data from {file_path}...")
    training_data = detector.load_training_data_from_file(file_path)
    
    if not training_data:
        print("❌ No training data loaded")
        return False
    
    print(f"✅ Loaded {len(training_data)} samples")
    print(f"🧠 Training models (append={append})...")
    
    detector.train_models(training_data, append=append)
    
    print("✅ Training complete!")
    print(f"📁 Models saved to: {detector.model_dir}")
    return True

def train_from_url(url: str, append: bool = False):
    """Train models from URL"""
    if not IMPORTS_AVAILABLE:
        print(f"❌ Cannot import detector: {IMPORT_ERROR}")
        return False
    
    detector = EnhancedAnomalyDetector()
    
    print(f"🌐 Loading training data from {url}...")
    training_data = detector.load_training_data_from_url(url)
    
    if not training_data:
        print("❌ No training data loaded")
        return False
    
    print(f"✅ Loaded {len(training_data)} samples")
    print(f"🧠 Training models (append={append})...")
    
    detector.train_models(training_data, append=append)
    
    print("✅ Training complete!")
    print(f"📁 Models saved to: {detector.model_dir}")
    return True

def train_from_directory(directory: str, append: bool = False):
    """Train models from directory of JSON files"""
    if not IMPORTS_AVAILABLE:
        print(f"❌ Cannot import detector: {IMPORT_ERROR}")
        return False
    
    detector = EnhancedAnomalyDetector()
    
    print(f"📂 Loading training data from {directory}...")
    training_data = detector.load_training_data_from_directory(directory)
    
    if not training_data:
        print("❌ No training data loaded")
        return False
    
    print(f"✅ Loaded {len(training_data)} samples")
    print(f"🧠 Training models (append={append})...")
    
    detector.train_models(training_data, append=append)
    
    print("✅ Training complete!")
    print(f"📁 Models saved to: {detector.model_dir}")
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Train ML models with public dataset',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train from JSON file
  python3 scripts/train_with_dataset.py --file dataset.json
  
  # Train from URL
  python3 scripts/train_with_dataset.py --url https://example.com/dataset.json
  
  # Train from directory
  python3 scripts/train_with_dataset.py --directory ./datasets/
  
  # Append to existing models
  python3 scripts/train_with_dataset.py --file dataset.json --append
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', type=str, help='Path to JSON training data file')
    group.add_argument('--url', type=str, help='URL to JSON training data')
    group.add_argument('--directory', type=str, help='Directory containing JSON training data files')
    
    parser.add_argument('--append', action='store_true', 
                       help='Append to existing feature store (incremental learning)')
    
    args = parser.parse_args()
    
    if args.file:
        success = train_from_file(args.file, append=args.append)
    elif args.url:
        success = train_from_url(args.url, append=args.append)
    elif args.directory:
        success = train_from_directory(args.directory, append=args.append)
    else:
        parser.print_help()
        return 1
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())

