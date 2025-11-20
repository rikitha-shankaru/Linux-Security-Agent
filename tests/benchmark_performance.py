#!/usr/bin/env python3
"""
Performance Benchmarking Script
Measures actual performance metrics for the security agent
"""

import time
import sys
import os
import psutil
import statistics
from collections import defaultdict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.enhanced_security_agent import EnhancedSecurityAgent
    IMPORTS_AVAILABLE = True
except ImportError as e:
    IMPORTS_AVAILABLE = False
    IMPORT_ERROR = str(e)
    print(f"Warning: Could not import agent: {IMPORT_ERROR}")
    print("Running in simulation mode...")


class PerformanceBenchmark:
    """Performance benchmarking suite"""
    
    def __init__(self):
        self.config = {
            'risk_threshold': 30.0,
            'anomaly_weight': 0.3,
            'collector': 'ebpf',
            'debug': False
        }
        self.results = defaultdict(list)
    
    def benchmark_event_processing(self, num_events=10000, num_processes=100):
        """Benchmark event processing speed"""
        print(f"\n📊 Benchmarking Event Processing ({num_events} events, {num_processes} processes)...")
        
        if not IMPORTS_AVAILABLE:
            print("⚠️  Skipping - imports not available")
            return
        
        agent = EnhancedSecurityAgent(self.config)
        
        # Warm up
        for i in range(100):
            agent._handle_syscall_event(i % 10, 'read', {'pid': i % 10, 'syscall_name': 'read'})
        
        # Benchmark
        start_time = time.time()
        start_cpu = psutil.Process().cpu_percent()
        
        for i in range(num_events):
            pid = i % num_processes
            syscall = 'read' if i % 2 == 0 else 'write'
            agent._handle_syscall_event(pid, syscall, {'pid': pid, 'syscall_name': syscall})
        
        elapsed = time.time() - start_time
        end_cpu = psutil.Process().cpu_percent()
        
        events_per_second = num_events / elapsed
        cpu_usage = end_cpu - start_cpu
        
        self.results['event_processing'].append({
            'events_per_second': events_per_second,
            'cpu_usage': cpu_usage,
            'elapsed_time': elapsed
        })
        
        print(f"  ✅ Events/sec: {events_per_second:,.0f}")
        print(f"  ✅ CPU usage: {cpu_usage:.2f}%")
        print(f"  ✅ Elapsed: {elapsed:.2f}s")
        
        agent.stop_monitoring()
    
    def benchmark_memory_usage(self, num_processes=1000):
        """Benchmark memory usage with many processes"""
        print(f"\n💾 Benchmarking Memory Usage ({num_processes} processes)...")
        
        if not IMPORTS_AVAILABLE:
            print("⚠️  Skipping - imports not available")
            return
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        agent = EnhancedSecurityAgent(self.config)
        
        # Create processes
        for i in range(num_processes):
            agent._handle_syscall_event(i, 'read', {'pid': i, 'syscall_name': 'read'})
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_per_process = (final_memory - initial_memory) / num_processes
        
        self.results['memory_usage'].append({
            'initial_mb': initial_memory,
            'final_mb': final_memory,
            'increase_mb': final_memory - initial_memory,
            'per_process_kb': memory_per_process * 1024
        })
        
        print(f"  ✅ Initial memory: {initial_memory:.2f} MB")
        print(f"  ✅ Final memory: {final_memory:.2f} MB")
        print(f"  ✅ Increase: {final_memory - initial_memory:.2f} MB")
        print(f"  ✅ Per process: {memory_per_process * 1024:.2f} KB")
        
        agent.stop_monitoring()
    
    def benchmark_risk_scoring(self, num_calculations=10000):
        """Benchmark risk score calculation speed"""
        print(f"\n⚡ Benchmarking Risk Scoring ({num_calculations} calculations)...")
        
        if not IMPORTS_AVAILABLE:
            print("⚠️  Skipping - imports not available")
            return
        
        agent = EnhancedSecurityAgent(self.config)
        
        # Warm up
        agent.enhanced_risk_scorer.update_risk_score(1, ['read', 'write'])
        
        # Benchmark
        start_time = time.time()
        
        for i in range(num_calculations):
            syscalls = ['read', 'write', 'open', 'close'] if i % 2 == 0 else ['ptrace', 'setuid']
            agent.enhanced_risk_scorer.update_risk_score(i % 100, syscalls)
        
        elapsed = time.time() - start_time
        calculations_per_second = num_calculations / elapsed
        
        self.results['risk_scoring'].append({
            'calculations_per_second': calculations_per_second,
            'elapsed_time': elapsed
        })
        
        print(f"  ✅ Calculations/sec: {calculations_per_second:,.0f}")
        print(f"  ✅ Elapsed: {elapsed:.2f}s")
    
    def benchmark_ml_inference(self, num_inferences=1000):
        """Benchmark ML inference speed"""
        print(f"\n🧠 Benchmarking ML Inference ({num_inferences} inferences)...")
        
        if not IMPORTS_AVAILABLE:
            print("⚠️  Skipping - imports not available")
            return
        
        agent = EnhancedSecurityAgent(self.config)
        
        # Train models first
        if agent.enhanced_anomaly_detector:
            print("  Training models...")
            training_data = [
                (['read', 'write', 'open', 'close'] * 10, {'cpu_percent': 10, 'memory_percent': 5})
            ] * 200
            agent.enhanced_anomaly_detector.train_models(training_data)
            print("  ✅ Models trained")
        
        # Warm up
        if agent.enhanced_anomaly_detector and agent.enhanced_anomaly_detector.is_fitted:
            agent.enhanced_anomaly_detector.detect_anomaly_ensemble(['read', 'write'], {})
        
        # Benchmark
        start_time = time.time()
        
        for i in range(num_inferences):
            syscalls = ['read', 'write', 'open', 'close'] if i % 2 == 0 else ['ptrace', 'mount']
            if agent.enhanced_anomaly_detector and agent.enhanced_anomaly_detector.is_fitted:
                agent.enhanced_anomaly_detector.detect_anomaly_ensemble(syscalls, {})
        
        elapsed = time.time() - start_time
        inferences_per_second = num_inferences / elapsed if elapsed > 0 else 0
        
        self.results['ml_inference'].append({
            'inferences_per_second': inferences_per_second,
            'elapsed_time': elapsed
        })
        
        print(f"  ✅ Inferences/sec: {inferences_per_second:,.0f}")
        print(f"  ✅ Elapsed: {elapsed:.2f}s")
        
        agent.stop_monitoring()
    
    def run_all_benchmarks(self):
        """Run all benchmarks"""
        print("=" * 60)
        print("🚀 Performance Benchmark Suite")
        print("=" * 60)
        
        self.benchmark_event_processing(num_events=10000, num_processes=100)
        self.benchmark_memory_usage(num_processes=1000)
        self.benchmark_risk_scoring(num_calculations=10000)
        self.benchmark_ml_inference(num_inferences=1000)
        
        self.print_summary()
    
    def print_summary(self):
        """Print summary of all benchmarks"""
        print("\n" + "=" * 60)
        print("📊 Benchmark Summary")
        print("=" * 60)
        
        if self.results.get('event_processing'):
            r = self.results['event_processing'][0]
            print(f"\nEvent Processing:")
            print(f"  Events/sec: {r['events_per_second']:,.0f}")
            print(f"  CPU usage: {r['cpu_usage']:.2f}%")
        
        if self.results.get('memory_usage'):
            r = self.results['memory_usage'][0]
            print(f"\nMemory Usage:")
            print(f"  Per process: {r['per_process_kb']:.2f} KB")
            print(f"  Total increase: {r['increase_mb']:.2f} MB")
        
        if self.results.get('risk_scoring'):
            r = self.results['risk_scoring'][0]
            print(f"\nRisk Scoring:")
            print(f"  Calculations/sec: {r['calculations_per_second']:,.0f}")
        
        if self.results.get('ml_inference'):
            r = self.results['ml_inference'][0]
            print(f"\nML Inference:")
            print(f"  Inferences/sec: {r['inferences_per_second']:,.0f}")
        
        print("\n" + "=" * 60)
        print("⚠️  Note: These are benchmark results, not production metrics.")
        print("    Real-world performance may vary based on system load,")
        print("    syscall frequency, and other factors.")
        print("=" * 60)


if __name__ == '__main__':
    benchmark = PerformanceBenchmark()
    benchmark.run_all_benchmarks()

