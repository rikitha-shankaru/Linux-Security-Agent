#!/usr/bin/env python3
"""
Generate Anomalous Data for Calibration
Creates synthetic anomalous syscall patterns for calibration purposes
Author: Likitha Shankar
"""

import sys
import os
import json
import random
from pathlib import Path
from typing import List, Dict, Tuple

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from core.enhanced_anomaly_detector import EnhancedAnomalyDetector
    IMPORTS_AVAILABLE = True
except ImportError as e:
    IMPORTS_AVAILABLE = False
    IMPORT_ERROR = str(e)


def generate_anomalous_patterns(num_samples: int = 200) -> List[Tuple[List[str], Dict]]:
    """
    Generate synthetic anomalous syscall patterns
    
    Returns:
        List of (syscalls, process_info) tuples representing anomalous behavior
    """
    anomalous_data = []
    
    # High-risk syscall patterns
    high_risk_patterns = [
        # Privilege escalation
        ['setuid', 'setgid', 'chmod', 'chown', 'execve', 'execve', 'execve'],
        ['ptrace', 'ptrace', 'ptrace', 'clone', 'execve'],
        ['mount', 'umount', 'mount', 'chroot', 'pivot_root'],
        
        # Process injection
        ['ptrace', 'ptrace', 'ptrace', 'ptrace', 'ptrace', 'clone', 'execve'],
        ['clone', 'clone', 'clone', 'execve', 'execve', 'execve'],
        
        # Suspicious file operations
        ['open', 'chmod', 'chown', 'write', 'write', 'write', 'close'],
        ['openat', 'fchmod', 'fchown', 'write', 'write'],
        
        # Network scanning
        ['socket', 'socket', 'socket', 'socket', 'socket', 'connect', 'connect', 'connect'],
        ['socket', 'bind', 'listen', 'accept', 'accept', 'accept'],
        
        # Resource exhaustion
        ['fork', 'fork', 'fork', 'fork', 'fork', 'fork', 'fork', 'fork'],
        ['mmap', 'mmap', 'mmap', 'mmap', 'mmap', 'mmap'],
        
        # Unusual sequences
        ['reboot', 'sync', 'sync'],
        ['ioperm', 'iopl', 'iopl'],
        ['keyctl', 'add_key', 'request_key'],
    ]
    
    # Generate samples
    for i in range(num_samples):
        # Pick a pattern and add variation
        base_pattern = random.choice(high_risk_patterns)
        
        # Add some variation
        syscalls = base_pattern.copy()
        # Repeat some syscalls to create bursts
        for _ in range(random.randint(0, 5)):
            syscalls.append(random.choice(base_pattern))
        
        # Shuffle slightly to add variation
        if random.random() < 0.3:
            random.shuffle(syscalls)
        
        # Add some normal syscalls mixed in (more realistic)
        normal_syscalls = ['read', 'write', 'open', 'close']
        for _ in range(random.randint(0, 3)):
            syscalls.insert(random.randint(0, len(syscalls)), random.choice(normal_syscalls))
        
        # Generate process info with suspicious characteristics
        process_info = {
            'cpu_percent': random.uniform(50.0, 95.0),  # High CPU
            'memory_percent': random.uniform(30.0, 80.0),  # High memory
            'num_threads': random.randint(10, 50)  # Many threads
        }
        
        anomalous_data.append((syscalls, process_info))
    
    return anomalous_data


def save_anomalous_dataset(data: List[Tuple[List[str], Dict]], output_path: str):
    """Save anomalous data to JSON file"""
    samples = []
    for syscalls, process_info in data:
        samples.append({
            'syscalls': syscalls,
            'process_info': process_info
        })
    
    dataset = {
        'metadata': {
            'source': 'synthetic_anomalous_behavior',
            'collection_date': '2025-11-22',
            'description': 'Synthetic anomalous syscall patterns for calibration',
            'sample_count': len(samples)
        },
        'samples': samples
    }
    
    with open(output_path, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"✅ Saved {len(samples)} anomalous samples to {output_path}")


def main():
    import argparse
    
    if not IMPORTS_AVAILABLE:
        print(f"❌ Cannot import required modules: {IMPORT_ERROR}")
        return 1
    
    parser = argparse.ArgumentParser(
        description='Generate anomalous data for calibration',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--samples', type=int, default=200,
                       help='Number of anomalous samples to generate (default: 200)')
    parser.add_argument('--output', type=str, default='datasets/anomalous_behavior_dataset.json',
                       help='Output file path (default: datasets/anomalous_behavior_dataset.json)')
    
    args = parser.parse_args()
    
    print("🔴 Generating anomalous syscall patterns...")
    print(f"   Samples: {args.samples}")
    
    anomalous_data = generate_anomalous_patterns(args.samples)
    
    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    save_anomalous_dataset(anomalous_data, str(output_path))
    
    print(f"\n✅ Anomalous dataset generated successfully!")
    print(f"\n💡 Next steps:")
    print(f"   1. Use this for calibration:")
    print(f"      python3 scripts/calibrate_models.py --normal datasets/normal_behavior_dataset.json --anomalous {args.output}")
    print(f"   2. Or combine with normal data for training")
    
    return 0


if __name__ == "__main__":
    import argparse
    sys.exit(main())

