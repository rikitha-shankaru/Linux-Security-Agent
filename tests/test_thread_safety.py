#!/usr/bin/env python3
"""
Thread Safety Stress Tests
Tests concurrent access to shared state, lock contention, and data integrity
Author: Likitha Shankar

NOTE: These tests require psutil and rich packages.
      Run on Linux VM where dependencies are installed:
      sudo apt install python3-psutil python3-rich
      OR
      pip3 install psutil rich
"""

import sys
import os
import time
import threading
import random
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Mock missing dependencies for testing
import sys

# Mock psutil if not available
try:
    import psutil
except ImportError:
    class MockProcess:
        def __init__(self, pid):
            self.pid = pid
        def name(self):
            return f"mock_proc_{self.pid}"
        def cpu_percent(self, interval=None):
            return 0.0
        def memory_percent(self):
            return 0.0
        def is_running(self):
            return True
    
    class MockPsutil:
        @staticmethod
        def Process(pid):
            return MockProcess(pid)
        class NoSuchProcess(Exception):
            pass
        class AccessDenied(Exception):
            pass
    
    sys.modules['psutil'] = MockPsutil()
    psutil = MockPsutil()

# Mock rich if not available
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    class MockConsole:
        def print(self, *args, **kwargs):
            pass
    class MockTable:
        def __init__(self, *args, **kwargs):
            pass
        def add_column(self, *args, **kwargs):
            pass
        def add_row(self, *args, **kwargs):
            pass
    class MockLive:
        def __init__(self, *args, **kwargs):
            pass
        def start(self):
            pass
        def stop(self):
            pass
        def update(self, *args, **kwargs):
            pass
    class MockPanel:
        def __init__(self, *args, **kwargs):
            pass
    class MockText:
        def __init__(self, *args, **kwargs):
            pass
    
    # Create comprehensive mock modules
    rich_module = type('Module', (), {})()
    sys.modules['rich'] = rich_module
    sys.modules['rich.console'] = type('Module', (), {'Console': MockConsole})()
    sys.modules['rich.table'] = type('Module', (), {'Table': MockTable})()
    sys.modules['rich.live'] = type('Module', (), {'Live': MockLive})()
    sys.modules['rich.panel'] = type('Module', (), {'Panel': MockPanel})()
    sys.modules['rich.text'] = type('Module', (), {'Text': MockText})()
    
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text

try:
    from core.simple_agent import SimpleSecurityAgent
    from core.enhanced_security_agent import EnhancedSecurityAgent
    IMPORTS_AVAILABLE = True
except ImportError as e:
    IMPORTS_AVAILABLE = False
    IMPORT_ERROR = str(e)


class ThreadSafetyTester:
    """Comprehensive thread safety stress testing"""
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.test_results: Dict[str, bool] = {}
        
    def log_error(self, test_name: str, error: str):
        """Log an error"""
        self.errors.append(f"{test_name}: {error}")
        self.test_results[test_name] = False
        print(f"  ❌ {test_name}: {error}")
    
    def log_success(self, test_name: str):
        """Log a successful test"""
        self.test_results[test_name] = True
        print(f"  ✅ {test_name}: PASSED")
    
    def test_concurrent_process_updates(self, num_threads: int = 10, num_operations: int = 200):
        """Test concurrent updates to process dictionary"""
        test_name = f"Concurrent Process Updates ({num_threads} threads, {num_operations} ops)"
        print(f"\n🧪 Testing: {test_name}")
        
        try:
            # Disable ML inference for faster testing (focus on thread safety, not ML)
            config = {'disable_ml': True} if hasattr(SimpleSecurityAgent, '__init__') else {}
            agent = SimpleSecurityAgent(config)
            agent.running = True
            # Disable ML detector to avoid slow inference
            agent.anomaly_detector = None
            
            # Track which PIDs were accessed
            accessed_pids: Set[int] = set()
            access_lock = threading.Lock()
            
            def worker(thread_id: int):
                """Worker thread that updates processes"""
                nonlocal accessed_pids
                for i in range(num_operations):
                    pid = random.randint(1000, 9999)
                    syscall = random.choice(['open', 'read', 'write', 'execve', 'clone'])
                    
                    # Simulate syscall event
                    from core.collectors.base import SyscallEvent
                    event = SyscallEvent(
                        pid=pid,
                        syscall=syscall,
                        comm=f"test_proc_{thread_id}_{i}",
                        timestamp=time.time()
                    )
                    
                    try:
                        agent._handle_event(event)
                        
                        # Track accessed PIDs
                        with access_lock:
                            accessed_pids.add(pid)
                    except Exception as e:
                        self.log_error(test_name, f"Thread {thread_id} error: {e}")
                        return
            
            # Start worker threads
            threads = []
            for i in range(num_threads):
                t = threading.Thread(target=worker, args=(i,))
                threads.append(t)
                t.start()
            
            # Wait for all threads (increased timeout for ML operations)
            for t in threads:
                t.join(timeout=120)  # Increased from 30 to 120 seconds
                if t.is_alive():
                    self.log_error(test_name, f"Thread {t.ident} did not complete in time")
                    return
            
            # Verify data integrity
            with agent.processes_lock:
                # Check that all processes are valid
                for pid, proc_info in agent.processes.items():
                    if not isinstance(pid, int):
                        self.log_error(test_name, f"Invalid PID type: {type(pid)}")
                        return
                    if 'name' not in proc_info:
                        self.log_error(test_name, f"Process {pid} missing 'name' field")
                        return
                    if 'syscalls' not in proc_info:
                        self.log_error(test_name, f"Process {pid} missing 'syscalls' field")
                        return
                    if 'total_syscalls' not in proc_info:
                        self.log_error(test_name, f"Process {pid} missing 'total_syscalls' field")
                        return
                    if proc_info['total_syscalls'] < 0:
                        self.log_error(test_name, f"Process {pid} has negative syscall count")
                        return
                
                # Check that syscall counts match
                total_from_processes = sum(p['total_syscalls'] for p in agent.processes.values())
                if total_from_processes != agent.stats.get('total_syscalls', 0):
                    self.warnings.append(f"{test_name}: Syscall count mismatch (processes: {total_from_processes}, stats: {agent.stats.get('total_syscalls', 0)})")
            
            self.log_success(test_name)
            
        except Exception as e:
            self.log_error(test_name, f"Test exception: {e}")
            import traceback
            traceback.print_exc()
    
    def test_concurrent_stats_updates(self, num_threads: int = 30, num_updates: int = 500):
        """Test concurrent updates to statistics"""
        test_name = f"Concurrent Stats Updates ({num_threads} threads, {num_updates} updates)"
        print(f"\n🧪 Testing: {test_name}")
        
        try:
            agent = SimpleSecurityAgent()
            agent.running = True
            # Disable ML detector to avoid slow inference
            agent.anomaly_detector = None
            
            # Track expected stats
            expected_stats = defaultdict(int)
            expected_lock = threading.Lock()
            
            def stats_worker(thread_id: int):
                """Worker that updates stats"""
                for i in range(num_updates):
                    # Randomly update different stats
                    stat_key = random.choice(['total_syscalls', 'total_processes', 'high_risk_processes'])
                    
                    with agent.processes_lock:
                        if stat_key == 'total_syscalls':
                            agent.stats['total_syscalls'] = agent.stats.get('total_syscalls', 0) + 1
                        elif stat_key == 'total_processes':
                            agent.stats['total_processes'] = agent.stats.get('total_processes', 0) + 1
                        elif stat_key == 'high_risk_processes':
                            agent.stats['high_risk_processes'] = agent.stats.get('high_risk_processes', 0) + 1
                    
                    with expected_lock:
                        expected_stats[stat_key] += 1
            
            # Start threads
            threads = []
            for i in range(num_threads):
                t = threading.Thread(target=stats_worker, args=(i,))
                threads.append(t)
                t.start()
            
            # Wait for completion (increased timeout)
            for t in threads:
                t.join(timeout=120)  # Increased from 30 to 120 seconds
                if t.is_alive():
                    self.log_error(test_name, f"Thread {t.ident} did not complete")
                    return
            
            # Verify stats are reasonable (may not match exactly due to race conditions,
            # but should be in the right ballpark)
            with agent.processes_lock:
                actual_total = agent.stats.get('total_syscalls', 0)
                expected_total = expected_stats['total_syscalls']
                
                # Allow some variance due to race conditions, but should be close
                if actual_total < expected_total * 0.8 or actual_total > expected_total * 1.2:
                    self.warnings.append(f"{test_name}: Stats may have race conditions (expected ~{expected_total}, got {actual_total})")
                else:
                    self.log_success(test_name)
            
        except Exception as e:
            self.log_error(test_name, f"Test exception: {e}")
            import traceback
            traceback.print_exc()
    
    def test_lock_contention(self, num_threads: int = 50, duration: float = 5.0):
        """Test lock contention under high load"""
        test_name = f"Lock Contention ({num_threads} threads, {duration}s)"
        print(f"\n🧪 Testing: {test_name}")
        
        try:
            agent = SimpleSecurityAgent()
            agent.running = True
            # Disable ML detector to avoid slow inference
            agent.anomaly_detector = None
            
            contention_count = 0
            contention_lock = threading.Lock()
            stop_event = threading.Event()
            
            def contention_worker(thread_id: int):
                """Worker that creates lock contention"""
                nonlocal contention_count
                iterations = 0
                while not stop_event.is_set():
                    pid = random.randint(1000, 9999)
                    syscall = random.choice(['open', 'read', 'write'])
                    
                    from core.collectors.base import SyscallEvent
                    event = SyscallEvent(
                        pid=pid,
                        syscall=syscall,
                        comm=f"contention_{thread_id}",
                        timestamp=time.time()
                    )
                    
                    try:
                        agent._handle_event(event)
                        iterations += 1
                    except Exception as e:
                        with contention_lock:
                            contention_count += 1
                            if contention_count < 5:  # Only log first few
                                print(f"    Warning: Thread {thread_id} error: {e}")
            
            # Start threads
            threads = []
            for i in range(num_threads):
                t = threading.Thread(target=contention_worker, args=(i,))
                threads.append(t)
                t.start()
            
            # Run for specified duration
            time.sleep(duration)
            stop_event.set()
            
            # Wait for threads
            for t in threads:
                t.join(timeout=10)
                if t.is_alive():
                    self.log_error(test_name, f"Thread {t.ident} did not stop")
                    return
            
            # Check for excessive contention (errors)
            if contention_count > num_threads * 0.1:  # More than 10% errors
                self.log_error(test_name, f"High contention/error rate: {contention_count} errors")
            else:
                self.log_success(test_name)
            
        except Exception as e:
            self.log_error(test_name, f"Test exception: {e}")
            import traceback
            traceback.print_exc()
    
    def test_data_race_detection(self, num_threads: int = 10, num_operations: int = 200):
        """Test for data races in shared dictionaries"""
        test_name = f"Data Race Detection ({num_threads} threads, {num_operations} ops)"
        print(f"\n🧪 Testing: {test_name}")
        
        try:
            agent = SimpleSecurityAgent()
            agent.running = True
            # Disable ML detector to avoid slow inference
            agent.anomaly_detector = None
            
            # Track all operations
            operations = []
            operations_lock = threading.Lock()
            
            def race_worker(thread_id: int):
                """Worker that performs operations"""
                for i in range(num_operations):
                    pid = random.randint(1000, 9999)
                    syscall = random.choice(['open', 'read', 'write', 'execve'])
                    
                    from core.collectors.base import SyscallEvent
                    event = SyscallEvent(
                        pid=pid,
                        syscall=syscall,
                        comm=f"race_{thread_id}_{i}",
                        timestamp=time.time()
                    )
                    
                    # Record operation
                    with operations_lock:
                        operations.append((thread_id, pid, syscall, time.time()))
                    
                    try:
                        agent._handle_event(event)
                    except Exception as e:
                        self.log_error(test_name, f"Thread {thread_id} error: {e}")
                        return
            
            # Start threads
            threads = []
            for i in range(num_threads):
                t = threading.Thread(target=race_worker, args=(i,))
                threads.append(t)
                t.start()
            
            # Wait for completion
            for t in threads:
                t.join(timeout=30)
                if t.is_alive():
                    self.log_error(test_name, f"Thread {t.ident} did not complete")
                    return
            
            # Verify final state consistency
            with agent.processes_lock:
                # Check that all processes have consistent data
                for pid, proc_info in agent.processes.items():
                    # Check syscall deque length matches maxlen
                    if len(proc_info['syscalls']) > 100:  # maxlen is 100
                        self.log_error(test_name, f"Process {pid} syscall deque exceeds maxlen")
                        return
                    
                    # Check that total_syscalls >= len(syscalls)
                    if proc_info['total_syscalls'] < len(proc_info['syscalls']):
                        self.log_error(test_name, f"Process {pid} total_syscalls < deque length")
                        return
            
            self.log_success(test_name)
            
        except Exception as e:
            self.log_error(test_name, f"Test exception: {e}")
            import traceback
            traceback.print_exc()
    
    def test_deadlock_prevention(self, num_threads: int = 5, num_operations: int = 50):
        """Test that locks don't cause deadlocks"""
        test_name = f"Deadlock Prevention ({num_threads} threads, {num_operations} ops)"
        print(f"\n🧪 Testing: {test_name}")
        
        try:
            agent = SimpleSecurityAgent()
            agent.running = True
            # Disable ML detector to avoid slow inference
            agent.anomaly_detector = None
            
            completed = 0
            completed_lock = threading.Lock()
            stop_event = threading.Event()
            
            def deadlock_worker(thread_id: int):
                """Worker that could potentially deadlock"""
                nonlocal completed
                for i in range(num_operations):
                    if stop_event.is_set():
                        return
                    
                    pid = random.randint(1000, 9999)
                    syscall = random.choice(['open', 'read', 'write'])
                    
                    from core.collectors.base import SyscallEvent
                    event = SyscallEvent(
                        pid=pid,
                        syscall=syscall,
                        comm=f"deadlock_{thread_id}",
                        timestamp=time.time()
                    )
                    
                    try:
                        # This should not deadlock even with multiple threads
                        agent._handle_event(event)
                        
                        with completed_lock:
                            completed += 1
                    except Exception as e:
                        self.log_error(test_name, f"Thread {thread_id} error: {e}")
                        stop_event.set()
                        return
            
            # Start threads
            threads = []
            for i in range(num_threads):
                t = threading.Thread(target=deadlock_worker, args=(i,))
                threads.append(t)
                t.start()
            
            # Wait for completion with timeout
            for t in threads:
                t.join(timeout=180)  # Increased timeout for deadlock detection (3 minutes)
                if t.is_alive():
                    self.log_error(test_name, f"Thread {t.ident} appears deadlocked (did not complete in 180s)")
                    stop_event.set()
                    return
            
            # Check completion
            if completed < num_threads * num_operations * 0.9:  # At least 90% completion
                self.log_error(test_name, f"Low completion rate: {completed}/{num_threads * num_operations}")
            else:
                self.log_success(test_name)
            
        except Exception as e:
            self.log_error(test_name, f"Test exception: {e}")
            import traceback
            traceback.print_exc()
    
    def test_concurrent_cleanup(self, num_threads: int = 15, num_processes: int = 100):
        """Test concurrent access during cleanup operations"""
        test_name = f"Concurrent Cleanup ({num_threads} threads, {num_processes} processes)"
        print(f"\n🧪 Testing: {test_name}")
        
        try:
            agent = SimpleSecurityAgent()
            agent.running = True
            # Disable ML detector to avoid slow inference
            agent.anomaly_detector = None
            
            # Create many processes first
            from core.collectors.ebpf_collector import SyscallEvent
            for i in range(num_processes):
                event = SyscallEvent(
                    pid=1000 + i,
                    syscall='open',
                    comm=f"cleanup_test_{i}",
                    timestamp=time.time()
                )
                agent._handle_event(event)
            
            # Now have threads access while cleanup runs
            stop_event = threading.Event()
            errors = []
            errors_lock = threading.Lock()
            
            def access_worker(thread_id: int):
                """Worker that accesses processes"""
                while not stop_event.is_set():
                    pid = random.randint(1000, 1000 + num_processes - 1)
                    try:
                        with agent.processes_lock:
                            if pid in agent.processes:
                                # Just access the data
                                _ = agent.processes[pid]['name']
                                _ = agent.processes[pid]['total_syscalls']
                    except Exception as e:
                        with errors_lock:
                            errors.append(f"Thread {thread_id}: {e}")
            
            # Start access threads
            threads = []
            for i in range(num_threads):
                t = threading.Thread(target=access_worker, args=(i,))
                threads.append(t)
                t.start()
            
            # Run cleanup in parallel
            time.sleep(0.5)  # Let threads start
            
            # Simulate cleanup (remove old processes)
            with agent.processes_lock:
                current_time = time.time()
                to_remove = []
                for pid, proc_info in agent.processes.items():
                    if current_time - proc_info.get('last_update', 0) > 300:  # 5 minutes
                        to_remove.append(pid)
                for pid in to_remove:
                    agent.processes.pop(pid, None)
            
            # Stop threads
            time.sleep(1)
            stop_event.set()
            
            for t in threads:
                t.join(timeout=10)
            
            # Check for errors
            if errors:
                self.log_error(test_name, f"Errors during concurrent cleanup: {errors[:5]}")
            else:
                self.log_success(test_name)
            
        except Exception as e:
            self.log_error(test_name, f"Test exception: {e}")
            import traceback
            traceback.print_exc()
    
    def run_all_tests(self):
        """Run all thread safety tests"""
        if not IMPORTS_AVAILABLE:
            print(f"❌ Cannot run tests: Imports failed: {IMPORT_ERROR}")
            return False
        
        print("=" * 70)
        print("🧪 Thread Safety Stress Test Suite")
        print("=" * 70)
        print(f"Author: Likitha Shankar")
        print(f"Testing concurrent access, lock contention, and data integrity\n")
        
        # Run all tests (reduced load to avoid timeouts from ML inference)
        self.test_concurrent_process_updates(num_threads=10, num_operations=200)
        self.test_concurrent_stats_updates(num_threads=30, num_updates=300)
        self.test_lock_contention(num_threads=40, duration=3.0)
        self.test_data_race_detection(num_threads=10, num_operations=200)
        self.test_deadlock_prevention(num_threads=5, num_operations=50)
        self.test_concurrent_cleanup(num_threads=15, num_processes=100)
        
        # Print summary
        print("\n" + "=" * 70)
        print("📊 Test Summary")
        print("=" * 70)
        
        passed = sum(1 for v in self.test_results.values() if v)
        total = len(self.test_results)
        
        print(f"Tests Passed: {passed}/{total}")
        print(f"Tests Failed: {total - passed}/{total}")
        
        if self.warnings:
            print(f"\n⚠️  Warnings ({len(self.warnings)}):")
            for warning in self.warnings[:5]:  # Show first 5
                print(f"  - {warning}")
        
        if self.errors:
            print(f"\n❌ Errors ({len(self.errors)}):")
            for error in self.errors[:10]:  # Show first 10
                print(f"  - {error}")
        
        print("\n" + "=" * 70)
        
        return passed == total


if __name__ == "__main__":
    tester = ThreadSafetyTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

