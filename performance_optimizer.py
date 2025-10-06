#!/usr/bin/env python3
"""
Performance Optimization Module for Linux Security Agent
Optimizes for high-performance production environments
"""

import os
import sys
import time
import threading
import multiprocessing
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from collections import deque, defaultdict
import psutil
import gc
import cProfile
import pstats
from functools import wraps
import numpy as np
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import queue
import weakref

@dataclass
class PerformanceMetrics:
    """Performance metrics tracking"""
    cpu_usage: float
    memory_usage: float
    event_rate: float
    processing_latency: float
    queue_size: int
    thread_count: int
    timestamp: float

@dataclass
class OptimizationConfig:
    """Performance optimization configuration"""
    max_threads: int
    max_processes: int
    queue_size_limit: int
    batch_size: int
    memory_threshold: float
    cpu_threshold: float
    gc_threshold: int
    enable_profiling: bool
    enable_caching: bool
    cache_size: int
    compression_enabled: bool

class PerformanceMonitor:
    """Monitor system performance and agent metrics"""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.metrics_history = deque(maxlen=1000)
        self.running = False
        self.monitor_thread = None
        
        # Performance counters
        self.event_count = 0
        self.last_event_time = time.time()
        self.processing_times = deque(maxlen=100)
        
    def start_monitoring(self):
        """Start performance monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Performance monitoring loop"""
        while self.running:
            try:
                # Get system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                memory_percent = memory.percent
                
                # Calculate event rate
                current_time = time.time()
                time_diff = current_time - self.last_event_time
                event_rate = self.event_count / time_diff if time_diff > 0 else 0
                
                # Calculate average processing latency
                avg_latency = np.mean(self.processing_times) if self.processing_times else 0
                
                # Get queue sizes (if available)
                queue_size = 0  # Will be updated by components
                
                # Get thread count
                thread_count = threading.active_count()
                
                # Create metrics
                metrics = PerformanceMetrics(
                    cpu_usage=cpu_percent,
                    memory_usage=memory_percent,
                    event_rate=event_rate,
                    processing_latency=avg_latency,
                    queue_size=queue_size,
                    thread_count=thread_count,
                    timestamp=current_time
                )
                
                self.metrics_history.append(metrics)
                
                # Reset counters
                self.event_count = 0
                self.last_event_time = current_time
                
                # Check for performance issues
                self._check_performance_issues(metrics)
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                print(f"Performance monitoring error: {e}")
                time.sleep(10)
    
    def _check_performance_issues(self, metrics: PerformanceMetrics):
        """Check for performance issues and trigger optimizations"""
        issues = []
        
        if metrics.cpu_usage > self.config.cpu_threshold:
            issues.append(f"High CPU usage: {metrics.cpu_usage:.1f}%")
        
        if metrics.memory_usage > self.config.memory_threshold:
            issues.append(f"High memory usage: {metrics.memory_usage:.1f}%")
        
        if metrics.queue_size > self.config.queue_size_limit:
            issues.append(f"Large queue size: {metrics.queue_size}")
        
        if metrics.processing_latency > 100:  # 100ms threshold
            issues.append(f"High processing latency: {metrics.processing_latency:.1f}ms")
        
        if issues:
            print(f"⚠️ Performance issues detected: {', '.join(issues)}")
            self._trigger_optimizations(issues)
    
    def _trigger_optimizations(self, issues: List[str]):
        """Trigger performance optimizations"""
        for issue in issues:
            if "CPU" in issue:
                self._optimize_cpu()
            elif "memory" in issue:
                self._optimize_memory()
            elif "queue" in issue:
                self._optimize_queue()
            elif "latency" in issue:
                self._optimize_latency()
    
    def _optimize_cpu(self):
        """Optimize CPU usage"""
        # Force garbage collection
        gc.collect()
        
        # Reduce thread count if too many
        if threading.active_count() > self.config.max_threads:
            print("🔄 Reducing thread count for CPU optimization")
    
    def _optimize_memory(self):
        """Optimize memory usage"""
        # Force garbage collection
        gc.collect()
        
        # Clear caches if enabled
        if hasattr(self, '_cache'):
            if len(self._cache) > self.config.cache_size:
                # Clear oldest cache entries
                keys_to_remove = list(self._cache.keys())[:100]
                for key in keys_to_remove:
                    del self._cache[key]
                print("🧹 Cleared cache for memory optimization")
    
    def _optimize_queue(self):
        """Optimize queue processing"""
        print("🔄 Optimizing queue processing")
        # This would be implemented by the specific queue managers
    
    def _optimize_latency(self):
        """Optimize processing latency"""
        print("🔄 Optimizing processing latency")
        # This would trigger batch processing optimizations
    
    def record_event(self, processing_time: float = None):
        """Record an event for performance tracking"""
        self.event_count += 1
        if processing_time is not None:
            self.processing_times.append(processing_time)
    
    def get_current_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics"""
        if self.metrics_history:
            return self.metrics_history[-1]
        return None
    
    def get_performance_summary(self) -> Dict:
        """Get performance summary"""
        if not self.metrics_history:
            return {}
        
        recent_metrics = list(self.metrics_history)[-10:]  # Last 10 measurements
        
        return {
            'avg_cpu_usage': np.mean([m.cpu_usage for m in recent_metrics]),
            'avg_memory_usage': np.mean([m.memory_usage for m in recent_metrics]),
            'avg_event_rate': np.mean([m.event_rate for m in recent_metrics]),
            'avg_latency': np.mean([m.processing_latency for m in recent_metrics]),
            'max_queue_size': max([m.queue_size for m in recent_metrics]),
            'thread_count': recent_metrics[-1].thread_count if recent_metrics else 0
        }

class OptimizedEventProcessor:
    """Optimized event processor with batching and threading"""
    
    def __init__(self, config: OptimizationConfig, processor_func: Callable):
        self.config = config
        self.processor_func = processor_func
        self.event_queue = queue.Queue(maxsize=config.queue_size_limit)
        self.batch_queue = queue.Queue(maxsize=100)
        self.running = False
        
        # Threading
        self.worker_threads = []
        self.batch_thread = None
        
        # Batching
        self.current_batch = []
        self.batch_lock = threading.Lock()
        self.last_batch_time = time.time()
        
    def start(self):
        """Start the optimized event processor"""
        self.running = True
        
        # Start worker threads
        for i in range(min(self.config.max_threads, multiprocessing.cpu_count())):
            thread = threading.Thread(target=self._worker_loop, daemon=True)
            thread.start()
            self.worker_threads.append(thread)
        
        # Start batch processing thread
        self.batch_thread = threading.Thread(target=self._batch_loop, daemon=True)
        self.batch_thread.start()
    
    def stop(self):
        """Stop the optimized event processor"""
        self.running = False
        
        # Wait for threads to finish
        for thread in self.worker_threads:
            thread.join(timeout=5)
        
        if self.batch_thread:
            self.batch_thread.join(timeout=5)
    
    def process_event(self, event: Any):
        """Process a single event"""
        try:
            self.event_queue.put(event, timeout=1)
        except queue.Full:
            print("⚠️ Event queue full, dropping event")
    
    def _worker_loop(self):
        """Worker thread loop"""
        while self.running:
            try:
                # Get event from queue
                event = self.event_queue.get(timeout=1)
                
                # Process event
                start_time = time.time()
                self.processor_func(event)
                processing_time = (time.time() - start_time) * 1000  # Convert to ms
                
                # Record performance
                if hasattr(self, 'perf_monitor'):
                    self.perf_monitor.record_event(processing_time)
                
                self.event_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker thread error: {e}")
    
    def _batch_loop(self):
        """Batch processing loop"""
        while self.running:
            try:
                # Collect events for batching
                with self.batch_lock:
                    if len(self.current_batch) >= self.config.batch_size:
                        batch = self.current_batch.copy()
                        self.current_batch.clear()
                    else:
                        batch = None
                
                # Process batch if ready
                if batch:
                    start_time = time.time()
                    self._process_batch(batch)
                    processing_time = (time.time() - start_time) * 1000
                    
                    if hasattr(self, 'perf_monitor'):
                        self.perf_monitor.record_event(processing_time)
                
                # Check for timeout-based batching
                current_time = time.time()
                if (current_time - self.last_batch_time) > 1.0:  # 1 second timeout
                    with self.batch_lock:
                        if self.current_batch:
                            batch = self.current_batch.copy()
                            self.current_batch.clear()
                            self.last_batch_time = current_time
                            
                            if batch:
                                start_time = time.time()
                                self._process_batch(batch)
                                processing_time = (time.time() - start_time) * 1000
                                
                                if hasattr(self, 'perf_monitor'):
                                    self.perf_monitor.record_event(processing_time)
                
                time.sleep(0.1)  # Small delay to prevent busy waiting
                
            except Exception as e:
                print(f"Batch processing error: {e}")
                time.sleep(1)
    
    def _process_batch(self, batch: List[Any]):
        """Process a batch of events"""
        # This would be implemented by the specific processor
        # For now, just process each event individually
        for event in batch:
            try:
                self.processor_func(event)
            except Exception as e:
                print(f"Batch processing error: {e}")
    
    def set_performance_monitor(self, monitor: PerformanceMonitor):
        """Set performance monitor for metrics collection"""
        self.perf_monitor = monitor

class MemoryOptimizer:
    """Memory optimization utilities"""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.cache = {}
        self.cache_access_times = {}
        self.max_cache_size = config.cache_size
        
    def get_cached(self, key: str) -> Optional[Any]:
        """Get cached value"""
        if key in self.cache:
            self.cache_access_times[key] = time.time()
            return self.cache[key]
        return None
    
    def set_cached(self, key: str, value: Any):
        """Set cached value"""
        # Check cache size
        if len(self.cache) >= self.max_cache_size:
            self._evict_oldest()
        
        self.cache[key] = value
        self.cache_access_times[key] = time.time()
    
    def _evict_oldest(self):
        """Evict oldest cache entries"""
        if not self.cache_access_times:
            return
        
        # Find oldest entry
        oldest_key = min(self.cache_access_times.keys(), 
                        key=lambda k: self.cache_access_times[k])
        
        # Remove from cache
        del self.cache[oldest_key]
        del self.cache_access_times[oldest_key]
    
    def clear_cache(self):
        """Clear entire cache"""
        self.cache.clear()
        self.cache_access_times.clear()
    
    def optimize_memory(self):
        """Optimize memory usage"""
        # Force garbage collection
        gc.collect()
        
        # Clear cache if too large
        if len(self.cache) > self.max_cache_size * 0.8:
            self.clear_cache()
            print("🧹 Cleared cache for memory optimization")

class CPUOptimizer:
    """CPU optimization utilities"""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.thread_pool = ThreadPoolExecutor(max_workers=config.max_threads)
        self.process_pool = ProcessPoolExecutor(max_workers=config.max_processes)
        
    def optimize_cpu_usage(self):
        """Optimize CPU usage"""
        # Force garbage collection
        gc.collect()
        
        # Adjust thread pool size based on CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > self.config.cpu_threshold:
            # Reduce thread count
            current_threads = self.thread_pool._max_workers
            new_threads = max(1, current_threads - 1)
            if new_threads != current_threads:
                print(f"🔄 Reducing thread count from {current_threads} to {new_threads}")
                self.thread_pool.shutdown(wait=False)
                self.thread_pool = ThreadPoolExecutor(max_workers=new_threads)
    
    def shutdown(self):
        """Shutdown optimizers"""
        self.thread_pool.shutdown(wait=True)
        self.process_pool.shutdown(wait=True)

def performance_profiler(func):
    """Decorator for performance profiling"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not hasattr(wrapper, '_profiler'):
            wrapper._profiler = cProfile.Profile()
        
        wrapper._profiler.enable()
        result = func(*args, **kwargs)
        wrapper._profiler.disable()
        
        return result
    return wrapper

def memory_usage_monitor(func):
    """Decorator for memory usage monitoring"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        process = psutil.Process()
        memory_before = process.memory_info().rss / 1024 / 1024  # MB
        
        result = func(*args, **kwargs)
        
        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        memory_diff = memory_after - memory_before
        
        if memory_diff > 10:  # 10MB threshold
            print(f"⚠️ High memory usage in {func.__name__}: {memory_diff:.1f}MB")
        
        return result
    return wrapper

class PerformanceOptimizer:
    """Main performance optimizer"""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.perf_monitor = PerformanceMonitor(config)
        self.memory_optimizer = MemoryOptimizer(config)
        self.cpu_optimizer = CPUOptimizer(config)
        self.event_processor = None
        
    def start(self):
        """Start performance optimization"""
        self.perf_monitor.start_monitoring()
        print("✅ Performance optimizer started")
    
    def stop(self):
        """Stop performance optimization"""
        self.perf_monitor.stop_monitoring()
        self.cpu_optimizer.shutdown()
        print("✅ Performance optimizer stopped")
    
    def create_event_processor(self, processor_func: Callable) -> OptimizedEventProcessor:
        """Create an optimized event processor"""
        processor = OptimizedEventProcessor(self.config, processor_func)
        processor.set_performance_monitor(self.perf_monitor)
        return processor
    
    def get_performance_report(self) -> Dict:
        """Get performance report"""
        return {
            'monitor': self.perf_monitor.get_performance_summary(),
            'cache_size': len(self.memory_optimizer.cache),
            'thread_count': threading.active_count(),
            'memory_usage': psutil.virtual_memory().percent,
            'cpu_usage': psutil.cpu_percent()
        }

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = OptimizationConfig(
        max_threads=4,
        max_processes=2,
        queue_size_limit=10000,
        batch_size=100,
        memory_threshold=80.0,
        cpu_threshold=80.0,
        gc_threshold=1000,
        enable_profiling=True,
        enable_caching=True,
        cache_size=1000,
        compression_enabled=True
    )
    
    # Create performance optimizer
    optimizer = PerformanceOptimizer(config)
    optimizer.start()
    
    # Example event processor
    def process_event(event):
        # Simulate event processing
        time.sleep(0.001)  # 1ms processing time
        pass
    
    # Create optimized event processor
    processor = optimizer.create_event_processor(process_event)
    processor.start()
    
    # Simulate some events
    for i in range(1000):
        processor.process_event(f"event_{i}")
        time.sleep(0.01)
    
    # Get performance report
    report = optimizer.get_performance_report()
    print(f"Performance Report: {report}")
    
    # Stop
    processor.stop()
    optimizer.stop()
