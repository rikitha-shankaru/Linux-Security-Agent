#!/usr/bin/env python3
"""
Performance Benchmarking Under Heavy Load
==========================================

Measures agent performance under various load conditions:
- CPU usage under different syscall rates
- Memory consumption over time
- Event processing throughput
- Detection latency
- System overhead impact

Provides production readiness metrics.

Author: Likitha Shankar
"""

import sys
import os
import time
import json
import psutil
import subprocess
import threading
from datetime import datetime
from collections import deque

# Add project to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Results storage
benchmark_results = {
    'test_start': None,
    'test_end': None,
    'scenarios': []
}


def get_process_stats(pid):
    """Get CPU and memory stats for a process"""
    try:
        proc = psutil.Process(pid)
        return {
            'cpu_percent': proc.cpu_percent(interval=0.1),
            'memory_mb': proc.memory_info().rss / (1024 * 1024),
            'num_threads': proc.num_threads(),
            'io_counters': proc.io_counters() if hasattr(proc, 'io_counters') else None
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def generate_load(intensity='medium', duration=60):
    """Generate various load patterns
    
    Args:
        intensity: 'light', 'medium', 'heavy', 'extreme'
        duration: seconds to run
    """
    print(f"🔥 Generating {intensity} load for {duration} seconds...")
    
    load_configs = {
        'light': {
            'num_threads': 2,
            'ops_per_second': 10,
            'file_operations': True,
            'network_operations': False,
            'process_spawning': False
        },
        'medium': {
            'num_threads': 5,
            'ops_per_second': 50,
            'file_operations': True,
            'network_operations': True,
            'process_spawning': False
        },
        'heavy': {
            'num_threads': 10,
            'ops_per_second': 200,
            'file_operations': True,
            'network_operations': True,
            'process_spawning': True
        },
        'extreme': {
            'num_threads': 20,
            'ops_per_second': 1000,
            'file_operations': True,
            'network_operations': True,
            'process_spawning': True
        }
    }
    
    config = load_configs.get(intensity, load_configs['medium'])
    
    def worker():
        """Worker thread generating load"""
        start = time.time()
        ops = 0
        
        while time.time() - start < duration:
            try:
                # File operations
                if config['file_operations']:
                    with open('/tmp/bench_test.txt', 'w') as f:
                        f.write('test' * 100)
                    with open('/tmp/bench_test.txt', 'r') as f:
                        _ = f.read()
                    os.remove('/tmp/bench_test.txt')
                    ops += 3
                
                # Network operations
                if config['network_operations']:
                    subprocess.run(
                        ['ping', '-c', '1', '-W', '1', '127.0.0.1'],
                        capture_output=True,
                        timeout=2
                    )
                    ops += 1
                
                # Process spawning
                if config['process_spawning']:
                    subprocess.run(
                        ['ls', '/tmp'],
                        capture_output=True,
                        timeout=1
                    )
                    ops += 1
                
                # Control rate
                sleep_time = config['num_threads'] / config['ops_per_second']
                time.sleep(max(0.001, sleep_time))
                
            except Exception:
                pass
        
        return ops
    
    # Start worker threads
    threads = []
    for _ in range(config['num_threads']):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    
    # Wait for completion
    for t in threads:
        t.join()
    
    print(f"✅ Load generation complete")


def benchmark_scenario(name, intensity, duration=60):
    """Run a single benchmark scenario"""
    print(f"\n{'='*60}")
    print(f"SCENARIO: {name}")
    print(f"{'='*60}")
    
    scenario = {
        'name': name,
        'intensity': intensity,
        'duration': duration,
        'start_time': datetime.now().isoformat(),
        'agent_stats': [],
        'system_stats': [],
        'baseline_cpu': None,
        'baseline_memory': None,
        'agent_overhead_cpu': None,
        'agent_overhead_memory': None
    }
    
    # Get baseline system stats (no agent)
    print(f"\n1️⃣  Measuring baseline (no agent)...")
    baseline_cpu_samples = []
    baseline_mem_samples = []
    
    # Start load generator
    load_thread = threading.Thread(target=generate_load, args=(intensity, 15))
    load_thread.start()
    
    start = time.time()
    while time.time() - start < 15:
        baseline_cpu_samples.append(psutil.cpu_percent(interval=1))
        baseline_mem_samples.append(psutil.virtual_memory().percent)
    
    load_thread.join()
    
    scenario['baseline_cpu'] = sum(baseline_cpu_samples) / len(baseline_cpu_samples)
    scenario['baseline_memory'] = sum(baseline_mem_samples) / len(baseline_mem_samples)
    
    print(f"   Baseline CPU: {scenario['baseline_cpu']:.1f}%")
    print(f"   Baseline Memory: {scenario['baseline_memory']:.1f}%")
    
    # Run with agent
    print(f"\n2️⃣  Running with security agent...")
    
    # Start agent
    agent_cmd = [
        'sudo', 'python3',
        os.path.join(os.path.dirname(__file__), '..', 'core', 'simple_agent.py'),
        '--collector', 'ebpf',
        '--threshold', '30'
    ]
    
    log_file = f'/tmp/bench_{name.replace(" ", "_")}.log'
    with open(log_file, 'w') as f:
        agent_process = subprocess.Popen(
            agent_cmd,
            stdout=f,
            stderr=subprocess.STDOUT
        )
    
    agent_pid = agent_process.pid
    print(f"   Agent PID: {agent_pid}")
    
    # Wait for agent to initialize
    time.sleep(5)
    
    # Start load generator
    load_thread = threading.Thread(target=generate_load, args=(intensity, duration))
    load_thread.start()
    
    # Monitor performance
    start = time.time()
    sample_count = 0
    
    while time.time() - start < duration:
        # Get agent stats
        agent_stats = get_process_stats(agent_pid)
        if agent_stats:
            scenario['agent_stats'].append({
                'timestamp': time.time() - start,
                **agent_stats
            })
        
        # Get system stats
        scenario['system_stats'].append({
            'timestamp': time.time() - start,
            'cpu_percent': psutil.cpu_percent(interval=0),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters()._asdict() if hasattr(psutil.disk_io_counters(), '_asdict') else {}
        })
        
        sample_count += 1
        
        # Progress indicator
        if sample_count % 10 == 0:
            elapsed = int(time.time() - start)
            print(f"   Progress: {elapsed}/{duration}s", end='\r')
        
        time.sleep(1)
    
    print(f"\n   ✅ Monitoring complete ({sample_count} samples)")
    
    # Stop load generator
    load_thread.join(timeout=10)
    
    # Stop agent
    agent_process.terminate()
    try:
        agent_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        agent_process.kill()
    
    # Calculate overhead
    if scenario['agent_stats']:
        avg_agent_cpu = sum(s['cpu_percent'] for s in scenario['agent_stats']) / len(scenario['agent_stats'])
        avg_agent_mem = sum(s['memory_mb'] for s in scenario['agent_stats']) / len(scenario['agent_stats'])
        max_agent_cpu = max(s['cpu_percent'] for s in scenario['agent_stats'])
        max_agent_mem = max(s['memory_mb'] for s in scenario['agent_stats'])
        
        scenario['avg_agent_cpu'] = avg_agent_cpu
        scenario['avg_agent_memory_mb'] = avg_agent_mem
        scenario['max_agent_cpu'] = max_agent_cpu
        scenario['max_agent_memory_mb'] = max_agent_mem
    
    if scenario['system_stats']:
        avg_sys_cpu = sum(s['cpu_percent'] for s in scenario['system_stats']) / len(scenario['system_stats'])
        avg_sys_mem = sum(s['memory_percent'] for s in scenario['system_stats']) / len(scenario['system_stats'])
        
        scenario['avg_system_cpu'] = avg_sys_cpu
        scenario['avg_system_memory'] = avg_sys_mem
        
        scenario['agent_overhead_cpu'] = avg_sys_cpu - scenario['baseline_cpu']
        scenario['agent_overhead_memory'] = avg_sys_mem - scenario['baseline_memory']
    
    scenario['end_time'] = datetime.now().isoformat()
    
    # Print results
    print(f"\n📊 RESULTS:")
    print(f"   Agent CPU Usage: {scenario.get('avg_agent_cpu', 0):.1f}% (avg), {scenario.get('max_agent_cpu', 0):.1f}% (max)")
    print(f"   Agent Memory: {scenario.get('avg_agent_memory_mb', 0):.1f} MB (avg), {scenario.get('max_agent_memory_mb', 0):.1f} MB (max)")
    print(f"   System CPU: {scenario.get('avg_system_cpu', 0):.1f}% (with agent) vs {scenario['baseline_cpu']:.1f}% (baseline)")
    print(f"   CPU Overhead: {scenario.get('agent_overhead_cpu', 0):.1f}%")
    
    return scenario


def run_all_benchmarks():
    """Run all benchmark scenarios"""
    print("\n" + "="*60)
    print("PERFORMANCE BENCHMARK SUITE")
    print("="*60)
    
    benchmark_results['test_start'] = datetime.now().isoformat()
    
    scenarios = [
        ("Light Load", "light", 30),
        ("Medium Load", "medium", 45),
        ("Heavy Load", "heavy", 60),
    ]
    
    for name, intensity, duration in scenarios:
        scenario_result = benchmark_scenario(name, intensity, duration)
        benchmark_results['scenarios'].append(scenario_result)
        
        # Cleanup
        time.sleep(5)
    
    benchmark_results['test_end'] = datetime.now().isoformat()


def generate_report():
    """Generate comprehensive performance report"""
    print("\n" + "="*60)
    print("PERFORMANCE BENCHMARK REPORT")
    print("="*60)
    
    for scenario in benchmark_results['scenarios']:
        print(f"\n📊 {scenario['name'].upper()}:")
        print(f"   Duration: {scenario['duration']}s")
        print(f"   Agent CPU: {scenario.get('avg_agent_cpu', 0):.2f}% avg, {scenario.get('max_agent_cpu', 0):.2f}% max")
        print(f"   Agent Memory: {scenario.get('avg_agent_memory_mb', 0):.1f} MB avg, {scenario.get('max_agent_memory_mb', 0):.1f} MB max")
        print(f"   CPU Overhead: {scenario.get('agent_overhead_cpu', 0):.2f}%")
        print(f"   Memory Overhead: {scenario.get('agent_overhead_memory', 0):.2f}%")
    
    # Overall assessment
    print(f"\n📋 OVERALL ASSESSMENT:")
    
    avg_cpu_overhead = sum(s.get('agent_overhead_cpu', 0) for s in benchmark_results['scenarios']) / len(benchmark_results['scenarios'])
    avg_memory = sum(s.get('avg_agent_memory_mb', 0) for s in benchmark_results['scenarios']) / len(benchmark_results['scenarios'])
    
    print(f"   Average CPU Overhead: {avg_cpu_overhead:.2f}%")
    print(f"   Average Memory Usage: {avg_memory:.1f} MB")
    
    if avg_cpu_overhead < 5:
        print(f"   ✅ EXCELLENT: CPU overhead < 5% - Minimal performance impact")
    elif avg_cpu_overhead < 10:
        print(f"   ✅ GOOD: CPU overhead < 10% - Acceptable for production")
    elif avg_cpu_overhead < 20:
        print(f"   ⚠️  MODERATE: CPU overhead < 20% - May impact performance")
    else:
        print(f"   ❌ HIGH: CPU overhead >= 20% - Significant performance impact")
    
    if avg_memory < 100:
        print(f"   ✅ EXCELLENT: Memory < 100 MB - Very efficient")
    elif avg_memory < 500:
        print(f"   ✅ GOOD: Memory < 500 MB - Acceptable")
    else:
        print(f"   ⚠️  HIGH: Memory >= 500 MB - Consider optimization")


def save_results(output_file='performance_benchmark_results.json'):
    """Save benchmark results"""
    output_path = os.path.join(os.path.dirname(__file__), '..', output_file)
    
    with open(output_path, 'w') as f:
        json.dump(benchmark_results, f, indent=2)
    
    print(f"\n💾 Results saved to: {output_file}")


def main():
    """Main benchmark execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Benchmark agent performance under load')
    parser.add_argument('--quick', action='store_true',
                        help='Run quick test (shorter durations)')
    parser.add_argument('--output', type=str, default='performance_benchmark_results.json',
                        help='Output JSON file')
    
    args = parser.parse_args()
    
    print("="*60)
    print("PERFORMANCE BENCHMARKING UNDER LOAD")
    print("="*60)
    print("\nThis will test agent performance under:")
    print("  • Light load (10 ops/sec)")
    print("  • Medium load (50 ops/sec)")
    print("  • Heavy load (200 ops/sec)")
    print("\nMetrics measured:")
    print("  • CPU usage")
    print("  • Memory consumption")
    print("  • System overhead")
    print("\nNote: Requires sudo for eBPF agent")
    print("="*60)
    
    input("\nPress Enter to start benchmarking...")
    
    # Run benchmarks
    run_all_benchmarks()
    
    # Generate report
    generate_report()
    
    # Save results
    save_results(args.output)
    
    print("\n✅ Benchmarking complete!")


if __name__ == "__main__":
    main()

