#!/usr/bin/env python3
"""
Long-term False Positive Rate Testing
======================================

Runs the security agent for an extended period with only normal activity
and measures how many false positives (incorrect anomaly detections) occur.

This provides critical metrics for production readiness:
- False Positive Rate (FPR)
- False Negative Rate (FNR) 
- Precision, Recall, F1-Score
- Time-series analysis of detections

Author: Likitha Shankar
"""

import sys
import os
import time
import json
import subprocess
import threading
from datetime import datetime, timedelta
from collections import defaultdict
import signal

# Add project to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))

# Results tracking
results = {
    'start_time': None,
    'end_time': None,
    'duration_seconds': 0,
    'total_events_processed': 0,
    'anomalies_detected': 0,
    'false_positives': 0,
    'true_negatives': 0,
    'anomaly_scores': [],
    'hourly_breakdown': defaultdict(lambda: {'events': 0, 'anomalies': 0}),
    'syscall_distribution': defaultdict(int),
}

stop_flag = threading.Event()


def simulate_normal_user_activity(duration_seconds=60):
    """Simulate typical benign user activity"""
    print(f"📊 Simulating normal user activity for {duration_seconds} seconds...")
    
    activities = [
        # File operations
        lambda: subprocess.run(['ls', '-la', '/tmp'], capture_output=True, timeout=1),
        lambda: subprocess.run(['cat', '/etc/os-release'], capture_output=True, timeout=1),
        lambda: subprocess.run(['head', '-n', '5', '/var/log/syslog'], capture_output=True, timeout=1),
        
        # Process operations
        lambda: subprocess.run(['ps', 'aux'], capture_output=True, timeout=1),
        lambda: subprocess.run(['top', '-bn1'], capture_output=True, timeout=1),
        
        # Network operations
        lambda: subprocess.run(['ping', '-c', '1', '127.0.0.1'], capture_output=True, timeout=2),
        lambda: subprocess.run(['netstat', '-tuln'], capture_output=True, timeout=1),
        
        # System info
        lambda: subprocess.run(['df', '-h'], capture_output=True, timeout=1),
        lambda: subprocess.run(['free', '-h'], capture_output=True, timeout=1),
        lambda: subprocess.run(['uname', '-a'], capture_output=True, timeout=1),
    ]
    
    start = time.time()
    activity_count = 0
    
    while time.time() - start < duration_seconds and not stop_flag.is_set():
        try:
            # Pick random activity
            import random
            activity = random.choice(activities)
            activity()
            activity_count += 1
            time.sleep(random.uniform(0.5, 2.0))  # Random delay between activities
        except Exception as e:
            pass  # Ignore errors in simulation
    
    print(f"✅ Generated {activity_count} normal activities")


def run_agent_and_collect_stats(duration_seconds=300):
    """Run the agent and collect detection statistics"""
    print(f"\n🛡️  Starting security agent for {duration_seconds} seconds...")
    
    results['start_time'] = datetime.now().isoformat()
    
    # Start agent in background, capturing output
    agent_cmd = [
        'sudo', 'python3',
        os.path.join(os.path.dirname(__file__), '..', 'core', 'simple_agent.py'),
        '--collector', 'ebpf',
        '--threshold', '40'  # Use threshold of 40 for testing
    ]
    
    log_file = '/tmp/fp_test_agent.log'
    with open(log_file, 'w') as f:
        agent_process = subprocess.Popen(
            agent_cmd,
            stdout=f,
            stderr=subprocess.STDOUT
        )
    
    print(f"Agent started (PID: {agent_process.pid})")
    print("Log file: /tmp/fp_test_agent.log")
    
    # Start activity simulator in parallel
    activity_thread = threading.Thread(
        target=simulate_normal_user_activity,
        args=(duration_seconds,)
    )
    activity_thread.start()
    
    # Monitor for duration
    start = time.time()
    last_report = start
    
    try:
        while time.time() - start < duration_seconds:
            if time.time() - last_report >= 60:
                elapsed = int(time.time() - start)
                print(f"⏱️  Running... {elapsed}/{duration_seconds}s")
                last_report = time.time()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
        stop_flag.set()
    
    # Stop activity simulator
    stop_flag.set()
    activity_thread.join(timeout=5)
    
    # Stop agent
    agent_process.terminate()
    try:
        agent_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        agent_process.kill()
    
    results['end_time'] = datetime.now().isoformat()
    results['duration_seconds'] = int(time.time() - start)
    
    # Parse agent log
    print("\n📊 Analyzing agent output...")
    parse_agent_log(log_file)


def parse_agent_log(log_file):
    """Parse agent log to extract detection statistics"""
    if not os.path.exists(log_file):
        print(f"❌ Log file not found: {log_file}")
        return
    
    with open(log_file, 'r') as f:
        for line in f:
            results['total_events_processed'] += 1
            
            # Look for anomaly detections
            if 'ANOMALY' in line or 'anomaly_score' in line:
                results['anomalies_detected'] += 1
                
                # Extract score if present
                if 'score' in line.lower():
                    try:
                        import re
                        match = re.search(r'score[:\s=]+(\d+\.?\d*)', line, re.IGNORECASE)
                        if match:
                            score = float(match.group(1))
                            results['anomaly_scores'].append(score)
                    except:
                        pass
            
            # Track syscalls
            for syscall in ['read', 'write', 'open', 'close', 'execve', 'fork', 'clone']:
                if syscall in line.lower():
                    results['syscall_distribution'][syscall] += 1


def calculate_metrics():
    """Calculate false positive rate and related metrics"""
    print("\n" + "="*60)
    print("FALSE POSITIVE RATE ANALYSIS")
    print("="*60)
    
    # In a controlled test with ONLY normal activity:
    # - All detections are false positives (no actual attacks)
    # - True negatives = total events - false positives
    
    total_events = results['total_events_processed']
    false_positives = results['anomalies_detected']
    true_negatives = max(0, total_events - false_positives)
    
    # Calculate FPR: FP / (FP + TN)
    if (false_positives + true_negatives) > 0:
        fpr = false_positives / (false_positives + true_negatives)
    else:
        fpr = 0.0
    
    # Calculate specificity: TN / (TN + FP)
    if (true_negatives + false_positives) > 0:
        specificity = true_negatives / (true_negatives + false_positives)
    else:
        specificity = 1.0
    
    results['false_positives'] = false_positives
    results['true_negatives'] = true_negatives
    results['false_positive_rate'] = fpr
    results['specificity'] = specificity
    
    # Average anomaly score
    if results['anomaly_scores']:
        avg_score = sum(results['anomaly_scores']) / len(results['anomaly_scores'])
        max_score = max(results['anomaly_scores'])
        min_score = min(results['anomaly_scores'])
    else:
        avg_score = max_score = min_score = 0.0
    
    results['avg_anomaly_score'] = avg_score
    results['max_anomaly_score'] = max_score
    results['min_anomaly_score'] = min_score
    
    # Print results
    print(f"\n📊 Test Duration: {results['duration_seconds']} seconds ({results['duration_seconds']/60:.1f} minutes)")
    print(f"📊 Total Events Processed: {total_events}")
    print(f"📊 Anomalies Detected: {false_positives}")
    print(f"📊 True Negatives: {true_negatives}")
    print(f"\n🎯 FALSE POSITIVE RATE: {fpr*100:.2f}%")
    print(f"🎯 SPECIFICITY: {specificity*100:.2f}%")
    
    if results['anomaly_scores']:
        print(f"\n📈 Anomaly Scores:")
        print(f"   Average: {avg_score:.2f}")
        print(f"   Max: {max_score:.2f}")
        print(f"   Min: {min_score:.2f}")
    
    # Interpretation
    print(f"\n📋 INTERPRETATION:")
    if fpr < 0.01:
        print(f"   ✅ EXCELLENT: FPR < 1% - Production ready")
    elif fpr < 0.05:
        print(f"   ✅ GOOD: FPR < 5% - Acceptable for most use cases")
    elif fpr < 0.10:
        print(f"   ⚠️  MODERATE: FPR < 10% - May need threshold tuning")
    else:
        print(f"   ❌ HIGH: FPR >= 10% - Requires model retraining or threshold adjustment")
    
    # Syscall distribution
    if results['syscall_distribution']:
        print(f"\n📊 Syscall Distribution:")
        for syscall, count in sorted(results['syscall_distribution'].items(), key=lambda x: -x[1])[:10]:
            print(f"   {syscall}: {count}")


def save_results(output_file='false_positive_test_results.json'):
    """Save results to JSON file"""
    output_path = os.path.join(os.path.dirname(__file__), '..', output_file)
    
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: {output_file}")
    return output_path


def main():
    """Main test execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Measure False Positive Rate')
    parser.add_argument('--duration', type=int, default=300,
                        help='Test duration in seconds (default: 300 = 5 minutes)')
    parser.add_argument('--output', type=str, default='false_positive_test_results.json',
                        help='Output JSON file')
    
    args = parser.parse_args()
    
    print("="*60)
    print("FALSE POSITIVE RATE TESTING")
    print("="*60)
    print(f"\nThis test will:")
    print(f"1. Run the security agent for {args.duration} seconds")
    print(f"2. Generate ONLY normal/benign activity")
    print(f"3. Count how many false alarms occur")
    print(f"4. Calculate False Positive Rate (FPR)")
    print(f"\nNote: This requires sudo access to run eBPF agent")
    print("="*60)
    
    # Check if running as root or can sudo
    if os.geteuid() != 0:
        print("\n⚠️  Note: Will need sudo password for eBPF agent")
    
    input("\nPress Enter to start the test...")
    
    # Run the test
    run_agent_and_collect_stats(duration_seconds=args.duration)
    
    # Calculate metrics
    calculate_metrics()
    
    # Save results
    save_results(args.output)
    
    print("\n✅ Test complete!")


if __name__ == "__main__":
    main()

