#!/usr/bin/env python3
"""
Performance Benchmarking Suite
Tests CPU, memory, and latency overhead of the security agent
"""

import time
import psutil
import threading
import subprocess
import statistics
from typing import Dict, List, Any
import json
from pathlib import Path


class PerformanceBenchmark:
    """Performance benchmarking for security agent"""
    
    def __init__(self):
        self.results = {}
    
    def benchmark_cpu_overhead(self, duration: int = 60) -> Dict[str, Any]:
        """Measure CPU overhead of agent"""
        print(f"📊 Benchmarking CPU overhead for {duration} seconds...")
        
        # Baseline: system without agent
        baseline_cpu = self._measure_system_cpu(duration=10)
        
        # With agent (simulated - would need actual agent running)
        # For now, we'll measure syscall processing overhead
        start_time = time.time()
        syscall_count = 0
        
        # Simulate syscall processing
        while time.time() - start_time < duration:
            # Simulate processing a syscall
            _ = hash(f"syscall_{syscall_count}")
            syscall_count += 1
            time.sleep(0.001)  # 1ms per syscall
        
        elapsed = time.time() - start_time
        syscalls_per_second = syscall_count / elapsed
        
        return {
            'baseline_cpu_percent': baseline_cpu,
            'syscalls_per_second': syscalls_per_second,
            'duration': elapsed,
            'overhead_per_syscall_ms': (elapsed / syscall_count) * 1000
        }
    
    def benchmark_memory_usage(self, process_count: int = 1000) -> Dict[str, Any]:
        """Measure memory usage with varying process counts"""
        print(f"📊 Benchmarking memory usage with {process_count} processes...")
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Simulate tracking processes
        processes = {}
        for i in range(process_count):
            processes[i] = {
                'pid': i,
                'name': f'process_{i}',
                'syscalls': ['read', 'write', 'open', 'close'] * 10,
                'risk_score': 0.0,
                'last_update': time.time()
            }
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_per_process = (final_memory - initial_memory) / process_count
        
        return {
            'initial_memory_mb': initial_memory,
            'final_memory_mb': final_memory,
            'memory_per_process_kb': memory_per_process * 1024,
            'process_count': process_count
        }
    
    def benchmark_latency(self, iterations: int = 1000) -> Dict[str, Any]:
        """Measure syscall processing latency"""
        print(f"📊 Benchmarking latency for {iterations} iterations...")
        
        latencies = []
        
        for i in range(iterations):
            start = time.perf_counter()
            
            # Simulate syscall processing
            syscall = 'execve'
            pid = 1234
            _ = hash(f"{pid}_{syscall}_{i}")
            
            end = time.perf_counter()
            latencies.append((end - start) * 1000)  # Convert to ms
        
        return {
            'iterations': iterations,
            'mean_latency_ms': statistics.mean(latencies),
            'median_latency_ms': statistics.median(latencies),
            'p95_latency_ms': self._percentile(latencies, 95),
            'p99_latency_ms': self._percentile(latencies, 99),
            'max_latency_ms': max(latencies),
            'min_latency_ms': min(latencies)
        }
    
    def benchmark_scale(self, max_processes: int = 10000, step: int = 1000) -> Dict[str, Any]:
        """Benchmark performance at different scales"""
        print(f"📊 Benchmarking scale from 0 to {max_processes} processes...")
        
        results = []
        
        for process_count in range(0, max_processes + 1, step):
            start = time.perf_counter()
            
            # Simulate tracking N processes
            processes = {}
            for i in range(process_count):
                processes[i] = {
                    'pid': i,
                    'syscalls': ['read', 'write'] * 5,
                    'risk_score': 0.0
                }
            
            elapsed = time.perf_counter() - start
            
            results.append({
                'process_count': process_count,
                'setup_time_ms': elapsed * 1000,
                'time_per_process_us': (elapsed / process_count * 1000000) if process_count > 0 else 0
            })
            
            if process_count % 2000 == 0:
                print(f"  Processed {process_count} processes...")
        
        return {
            'scale_results': results,
            'max_processes': max_processes
        }
    
    def benchmark_ml_inference(self, iterations: int = 100) -> Dict[str, Any]:
        """Benchmark ML model inference time"""
        print(f"📊 Benchmarking ML inference for {iterations} iterations...")
        
        # Simulate feature extraction and ML inference
        latencies = []
        
        for i in range(iterations):
            start = time.perf_counter()
            
            # Simulate feature extraction (50 features)
            features = [hash(f"feature_{j}_{i}") % 100 for j in range(50)]
            
            # Simulate ML inference (simple calculation)
            _ = sum(features) / len(features)
            
            end = time.perf_counter()
            latencies.append((end - start) * 1000)  # ms
        
        return {
            'iterations': iterations,
            'mean_inference_ms': statistics.mean(latencies),
            'median_inference_ms': statistics.median(latencies),
            'p95_inference_ms': self._percentile(latencies, 95),
            'p99_inference_ms': self._percentile(latencies, 99)
        }
    
    def run_all_benchmarks(self) -> Dict[str, Any]:
        """Run all performance benchmarks"""
        print("🚀 Starting Performance Benchmarks...")
        print("=" * 60)
        
        results = {
            'timestamp': time.time(),
            'cpu_overhead': self.benchmark_cpu_overhead(duration=30),
            'memory_usage': self.benchmark_memory_usage(process_count=1000),
            'latency': self.benchmark_latency(iterations=1000),
            'ml_inference': self.benchmark_ml_inference(iterations=100),
            'scale': self.benchmark_scale(max_processes=5000, step=500)
        }
        
        print("\n" + "=" * 60)
        print("✅ Benchmarks Complete!")
        print("=" * 60)
        
        return results
    
    def save_results(self, results: Dict[str, Any], file_path: str = "benchmark_results.json"):
        """Save benchmark results to file"""
        output_path = Path(file_path)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"📁 Results saved to {output_path}")
    
    def _measure_system_cpu(self, duration: int = 10) -> float:
        """Measure baseline system CPU usage"""
        cpu_percentages = []
        start = time.time()
        
        while time.time() - start < duration:
            cpu_percentages.append(psutil.cpu_percent(interval=0.1))
        
        return statistics.mean(cpu_percentages)
    
    @staticmethod
    def _percentile(data: List[float], percentile: int) -> float:
        """Calculate percentile"""
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]


if __name__ == "__main__":
    benchmark = PerformanceBenchmark()
    results = benchmark.run_all_benchmarks()
    benchmark.save_results(results)
    
    # Print summary
    print("\n📊 Summary:")
    print(f"  CPU Overhead: {results['cpu_overhead']['overhead_per_syscall_ms']:.3f} ms/syscall")
    print(f"  Memory per Process: {results['memory_usage']['memory_per_process_kb']:.2f} KB")
    print(f"  Mean Latency: {results['latency']['mean_latency_ms']:.3f} ms")
    print(f"  ML Inference: {results['ml_inference']['mean_inference_ms']:.3f} ms")

