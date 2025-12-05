#!/usr/bin/env python3
"""
Generate Diverse Training Data
===============================

Creates comprehensive training datasets with various normal behavior patterns:
- Different user types (developer, sys admin, regular user)
- Various applications (web servers, databases, compilers)
- Different times of day and usage patterns
- Resource-intensive vs lightweight activities
- Interactive vs batch processing

This improves ML model accuracy by training on realistic, diverse data.

Author: Likitha Shankar
"""

import sys
import os
import json
import random
import time
from datetime import datetime
from collections import defaultdict

# Add project to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# Syscall patterns for different user behaviors
BEHAVIOR_PATTERNS = {
    'developer': {
        'common_syscalls': ['read', 'write', 'open', 'close', 'stat', 'fstat', 'lseek', 
                           'mmap', 'munmap', 'brk', 'access', 'execve', 'wait4', 'pipe'],
        'processes': ['python3', 'gcc', 'make', 'git', 'vim', 'bash', 'node', 'npm'],
        'file_patterns': ['.py', '.c', '.h', '.js', '.json', '.md', '.txt', '.sh'],
        'intensity': 'high',
        'burst_patterns': True
    },
    'sysadmin': {
        'common_syscalls': ['open', 'read', 'write', 'close', 'stat', 'execve', 'fork',
                           'socket', 'connect', 'sendto', 'recvfrom', 'ioctl', 'fcntl'],
        'processes': ['systemctl', 'journalctl', 'ps', 'top', 'netstat', 'ss', 'iptables', 
                     'ssh', 'scp', 'rsync', 'tar', 'grep'],
        'file_patterns': ['.conf', '.log', '.service', '.socket', '.timer'],
        'intensity': 'medium',
        'burst_patterns': False
    },
    'webserver': {
        'common_syscalls': ['accept', 'read', 'write', 'send', 'recv', 'socket', 'bind',
                           'listen', 'epoll_wait', 'epoll_ctl', 'close', 'open', 'stat'],
        'processes': ['nginx', 'apache2', 'node', 'gunicorn', 'uwsgi'],
        'file_patterns': ['.html', '.css', '.js', '.php', '.py'],
        'intensity': 'very_high',
        'burst_patterns': True
    },
    'database': {
        'common_syscalls': ['read', 'write', 'fsync', 'fdatasync', 'open', 'close', 'lseek',
                           'pread', 'pwrite', 'flock', 'fcntl', 'mmap', 'munmap'],
        'processes': ['postgres', 'mysqld', 'mongod', 'redis-server'],
        'file_patterns': ['.db', '.sql', '.mdb', '.ibd'],
        'intensity': 'very_high',
        'burst_patterns': False
    },
    'regular_user': {
        'common_syscalls': ['read', 'write', 'open', 'close', 'stat', 'access', 'execve',
                           'wait4', 'select', 'poll'],
        'processes': ['firefox', 'chrome', 'libreoffice', 'evince', 'gedit', 'nautilus'],
        'file_patterns': ['.txt', '.pdf', '.doc', '.jpg', '.png', '.mp3', '.mp4'],
        'intensity': 'low',
        'burst_patterns': False
    },
    'batch_processing': {
        'common_syscalls': ['read', 'write', 'open', 'close', 'stat', 'lseek', 'fork',
                           'execve', 'wait4', 'pipe', 'dup2'],
        'processes': ['python3', 'bash', 'perl', 'awk', 'sed', 'sort', 'uniq'],
        'file_patterns': ['.csv', '.json', '.xml', '.log', '.dat'],
        'intensity': 'medium',
        'burst_patterns': True
    },
    'container_workload': {
        'common_syscalls': ['clone', 'unshare', 'setns', 'mount', 'umount', 'pivot_root',
                           'read', 'write', 'socket', 'connect'],
        'processes': ['docker', 'containerd', 'runc', 'podman'],
        'file_patterns': ['.yaml', '.yml', '.json', '.conf'],
        'intensity': 'high',
        'burst_patterns': True
    }
}


def generate_syscall_sequence(behavior_type, length=100):
    """Generate a realistic syscall sequence for a behavior type"""
    pattern = BEHAVIOR_PATTERNS[behavior_type]
    syscalls = []
    
    for _ in range(length):
        # Weight common syscalls higher
        if random.random() < 0.8:
            syscall = random.choice(pattern['common_syscalls'])
        else:
            # Occasionally include other syscalls
            all_syscalls = ['getpid', 'getuid', 'geteuid', 'getgid', 'getegid',
                          'time', 'gettimeofday', 'clock_gettime', 'nanosleep']
            syscall = random.choice(all_syscalls)
        
        syscalls.append(syscall)
    
    # Add burst patterns if applicable
    if pattern.get('burst_patterns') and len(syscalls) > 30:
        # Insert a burst of similar syscalls
        burst_syscall = random.choice(pattern['common_syscalls'])
        burst_length = min(random.randint(10, 30), len(syscalls) // 2)
        burst_position = random.randint(0, max(0, len(syscalls) - burst_length))
        syscalls[burst_position:burst_position] = [burst_syscall] * burst_length
    
    return syscalls


def generate_process_info(behavior_type):
    """Generate realistic process information"""
    pattern = BEHAVIOR_PATTERNS[behavior_type]
    process = random.choice(pattern['processes'])
    
    return {
        'pid': random.randint(1000, 65535),
        'comm': process,
        'exe': f'/usr/bin/{process}',
        'uid': 1000 if behavior_type != 'sysadmin' else random.choice([0, 1000]),
        'gid': 1000,
        'ppid': random.randint(1, 1000)
    }


def generate_sample(behavior_type, sample_id):
    """Generate a complete training sample"""
    syscalls = generate_syscall_sequence(behavior_type, length=random.randint(50, 200))
    process_info = generate_process_info(behavior_type)
    
    return {
        'id': sample_id,
        'behavior_type': behavior_type,
        'syscalls': syscalls,
        'process_info': process_info,
        'timestamp': datetime.now().isoformat(),
        'is_malicious': False,
        'label': 'normal'
    }


def generate_mixed_workload_sample(sample_id):
    """Generate a sample that mixes multiple behavior types"""
    # Pick 2-3 behavior types
    behaviors = random.sample(list(BEHAVIOR_PATTERNS.keys()), k=random.randint(2, 3))
    
    all_syscalls = []
    for behavior in behaviors:
        syscalls = generate_syscall_sequence(behavior, length=random.randint(20, 50))
        all_syscalls.extend(syscalls)
    
    # Shuffle to mix them
    random.shuffle(all_syscalls)
    
    return {
        'id': sample_id,
        'behavior_type': 'mixed_workload',
        'behavior_components': behaviors,
        'syscalls': all_syscalls,
        'process_info': generate_process_info(random.choice(behaviors)),
        'timestamp': datetime.now().isoformat(),
        'is_malicious': False,
        'label': 'normal'
    }


def generate_time_based_sample(behavior_type, time_of_day, sample_id):
    """Generate sample with time-of-day characteristics"""
    # Adjust intensity based on time
    intensity_multipliers = {
        'morning': 0.7,    # Lower activity
        'midday': 1.0,     # Normal activity
        'evening': 0.8,    # Moderate activity
        'night': 0.3       # Low activity
    }
    
    multiplier = intensity_multipliers.get(time_of_day, 1.0)
    base_length = random.randint(50, 200)
    adjusted_length = int(base_length * multiplier)
    
    syscalls = generate_syscall_sequence(behavior_type, length=adjusted_length)
    
    return {
        'id': sample_id,
        'behavior_type': behavior_type,
        'time_of_day': time_of_day,
        'syscalls': syscalls,
        'process_info': generate_process_info(behavior_type),
        'timestamp': datetime.now().isoformat(),
        'is_malicious': False,
        'label': 'normal'
    }


def generate_diverse_dataset(
    samples_per_behavior=100,
    include_mixed=True,
    include_time_based=True,
    output_file='diverse_training_dataset.json'
):
    """Generate a comprehensive diverse training dataset"""
    
    print("="*60)
    print("GENERATING DIVERSE TRAINING DATA")
    print("="*60)
    
    dataset = {
        'metadata': {
            'created': datetime.now().isoformat(),
            'total_samples': 0,
            'behavior_types': list(BEHAVIOR_PATTERNS.keys()),
            'samples_per_behavior': samples_per_behavior,
            'includes_mixed_workloads': include_mixed,
            'includes_time_based': include_time_based
        },
        'samples': []
    }
    
    sample_id = 0
    
    # Generate samples for each behavior type
    print(f"\n📊 Generating {samples_per_behavior} samples per behavior type...")
    for behavior in BEHAVIOR_PATTERNS.keys():
        print(f"   Generating {behavior}...", end=' ')
        for _ in range(samples_per_behavior):
            sample = generate_sample(behavior, sample_id)
            dataset['samples'].append(sample)
            sample_id += 1
        print(f"✅ ({sample_id} total)")
    
    # Generate mixed workload samples
    if include_mixed:
        mixed_count = samples_per_behavior // 2
        print(f"\n📊 Generating {mixed_count} mixed workload samples...")
        for _ in range(mixed_count):
            sample = generate_mixed_workload_sample(sample_id)
            dataset['samples'].append(sample)
            sample_id += 1
        print(f"   ✅ ({sample_id} total)")
    
    # Generate time-based samples
    if include_time_based:
        times = ['morning', 'midday', 'evening', 'night']
        time_samples = samples_per_behavior // 4
        print(f"\n📊 Generating time-based samples ({time_samples} per time period)...")
        for time_of_day in times:
            print(f"   Generating {time_of_day}...", end=' ')
            for _ in range(time_samples):
                behavior = random.choice(list(BEHAVIOR_PATTERNS.keys()))
                sample = generate_time_based_sample(behavior, time_of_day, sample_id)
                dataset['samples'].append(sample)
                sample_id += 1
            print(f"✅")
        print(f"   Total: {sample_id}")
    
    dataset['metadata']['total_samples'] = len(dataset['samples'])
    
    # Shuffle samples
    random.shuffle(dataset['samples'])
    
    # Save dataset
    output_path = os.path.join(os.path.dirname(__file__), '..', 'datasets', output_file)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"\n💾 Dataset saved to: datasets/{output_file}")
    
    # Print statistics
    print(f"\n📊 DATASET STATISTICS:")
    print(f"   Total samples: {dataset['metadata']['total_samples']}")
    print(f"   Behavior types: {len(BEHAVIOR_PATTERNS)}")
    print(f"   Mixed workloads: {include_mixed}")
    print(f"   Time-based samples: {include_time_based}")
    
    # Distribution
    behavior_counts = defaultdict(int)
    for sample in dataset['samples']:
        behavior_counts[sample['behavior_type']] += 1
    
    print(f"\n📈 Distribution:")
    for behavior, count in sorted(behavior_counts.items()):
        percentage = (count / dataset['metadata']['total_samples']) * 100
        print(f"   {behavior}: {count} ({percentage:.1f}%)")
    
    return dataset


def generate_lightweight_dataset(output_file='lightweight_training_dataset.json'):
    """Generate a smaller, lightweight dataset for quick training"""
    print("\n📦 Generating lightweight dataset (20 samples per behavior)...")
    return generate_diverse_dataset(
        samples_per_behavior=20,
        include_mixed=True,
        include_time_based=False,
        output_file=output_file
    )


def generate_comprehensive_dataset(output_file='comprehensive_training_dataset.json'):
    """Generate a large, comprehensive dataset for thorough training"""
    print("\n📚 Generating comprehensive dataset (500 samples per behavior)...")
    return generate_diverse_dataset(
        samples_per_behavior=500,
        include_mixed=True,
        include_time_based=True,
        output_file=output_file
    )


def main():
    """Main execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate diverse training data')
    parser.add_argument('--size', choices=['lightweight', 'standard', 'comprehensive'],
                        default='standard',
                        help='Dataset size (lightweight=20, standard=100, comprehensive=500 per behavior)')
    parser.add_argument('--output', type=str,
                        help='Output filename (default: based on size)')
    
    args = parser.parse_args()
    
    if args.size == 'lightweight':
        output = args.output or 'lightweight_training_dataset.json'
        generate_lightweight_dataset(output)
    elif args.size == 'comprehensive':
        output = args.output or 'comprehensive_training_dataset.json'
        generate_comprehensive_dataset(output)
    else:  # standard
        output = args.output or 'diverse_training_dataset.json'
        generate_diverse_dataset(
            samples_per_behavior=100,
            include_mixed=True,
            include_time_based=True,
            output_file=output
        )
    
    print(f"\n✅ Dataset generation complete!")
    print(f"\n📝 Next steps:")
    print(f"   1. Train models: python3 scripts/train_with_dataset.py --file datasets/{output}")
    print(f"   2. Evaluate: python3 scripts/evaluate_ml_models.py")
    print(f"   3. Test: python3 core/simple_agent.py --collector ebpf")


if __name__ == "__main__":
    main()

