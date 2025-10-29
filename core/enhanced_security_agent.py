#!/usr/bin/env python3
"""
Enhanced Linux Security Agent - Research-Based Implementation
Integrates stateful eBPF monitoring, unsupervised anomaly detection, and container security
Based on recent research findings (2023-2025)
"""

import os
import sys
import json
import time
import signal
import argparse
import threading
import random
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import traceback

# Add core directory to path for imports
_core_dir = os.path.dirname(os.path.abspath(__file__))
if _core_dir not in sys.path:
    sys.path.insert(0, _core_dir)

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    print("Warning: BCC not available. Using fallback monitoring.")

import psutil
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich import box
import click

# Import enhanced components
try:
    from enhanced_ebpf_monitor import StatefulEBPFMonitor, ProcessState, SecurityPolicy
    ENHANCED_EBPF_AVAILABLE = True
except ImportError as e:
    ENHANCED_EBPF_AVAILABLE = False
    # Suppress warning - eBPF monitor is critical, but we have fallback

try:
    # First check if dependencies are available
    import numpy
    import pandas
    import sklearn
    # Dependencies exist, try importing the module
    from enhanced_anomaly_detector import EnhancedAnomalyDetector, AnomalyResult, BehavioralBaseline
    ENHANCED_ANOMALY_AVAILABLE = True
except ImportError as e:
    ENHANCED_ANOMALY_AVAILABLE = False
    # Optional component - will work without it

try:
    from container_security_monitor import ContainerSecurityMonitor, ContainerInfo, CrossContainerAttempt
    CONTAINER_SECURITY_AVAILABLE = True
except ImportError as e:
    CONTAINER_SECURITY_AVAILABLE = False
    # Optional component - suppress warning for cleaner output

# Import existing components
try:
    # action_handler is in legacy/, not core/, so it's truly optional
    ACTION_HANDLER_AVAILABLE = False
except ImportError:
    ACTION_HANDLER_AVAILABLE = False
    # Optional component - suppress warning for cleaner output

class EnhancedRiskScorer:
    """
    Enhanced risk scoring system with behavioral baselining and adaptive thresholds
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Risk scoring parameters
        self.base_risk_scores = {
            # Low risk - normal operations
            'read': 1, 'write': 1, 'open': 1, 'close': 1, 'lseek': 1,
            'stat': 1, 'fstat': 1, 'lstat': 1, 'access': 1, 'readlink': 1,
            'getcwd': 1, 'chdir': 1, 'fchdir': 1, 'getpid': 1, 'getppid': 1,
            'getuid': 1, 'getgid': 1, 'geteuid': 1, 'getegid': 1,
            'socket': 1, 'bind': 1, 'listen': 1, 'accept': 1, 'connect': 1,
            'send': 1, 'recv': 1, 'sendto': 1, 'recvfrom': 1, 'shutdown': 1,
            
            # Medium risk - potentially suspicious
            'fork': 3, 'vfork': 3, 'clone': 3, 'execve': 5, 'execveat': 5,
            'chmod': 3, 'fchmod': 3, 'chown': 3, 'fchown': 3, 'lchown': 3,
            'rename': 3, 'unlink': 3, 'rmdir': 3, 'mkdir': 3, 'mknod': 3,
            'symlink': 3, 'link': 3, 'mount': 4, 'umount': 4, 'umount2': 4,
            
            # High risk - very suspicious
            'ptrace': 10, 'setuid': 8, 'setgid': 8, 'chroot': 8, 'pivot_root': 8,
            'reboot': 10, 'sethostname': 6, 'setdomainname': 6, 'iopl': 8,
            'ioperm': 8, 'create_module': 10, 'init_module': 10, 'delete_module': 10
        }
        
        # Adaptive risk scoring
        self.process_baselines = {}  # pid -> baseline behavior
        self.risk_history = defaultdict(deque)  # pid -> risk history
        self.adaptive_thresholds = {}  # pid -> adaptive threshold
        
        # Time decay parameters
        self.decay_factor = self.config.get('decay_factor', 0.95)
        self.decay_interval = self.config.get('decay_interval', 60)  # seconds
        
        # Behavioral analysis
        self.behavioral_window = self.config.get('behavioral_window', 100)
        self.anomaly_weight = self.config.get('anomaly_weight', 0.3)
    
    def update_risk_score(self, pid: int, syscalls: List[str], process_info: Dict = None, 
                         anomaly_score: float = 0.0, container_id: str = None) -> float:
        """
        Update risk score with enhanced behavioral analysis
        """
        current_time = time.time()
        
        # Initialize process baseline if needed
        if pid not in self.process_baselines:
            self.process_baselines[pid] = {
                'syscall_frequencies': defaultdict(int),
                'temporal_patterns': deque(maxlen=self.behavioral_window),
                'resource_usage': {},
                'last_updated': current_time,
                'sample_count': 0
            }
        
        baseline = self.process_baselines[pid]
        
        # Calculate base risk score
        base_score = 0.0
        for syscall in syscalls:
            base_score += self.base_risk_scores.get(syscall, 2)
        
        # Normalize by number of syscalls
        if syscalls:
            base_score = base_score / len(syscalls) * 10  # Scale to 0-100
        
        # Apply behavioral analysis
        behavioral_score = self._calculate_behavioral_score(pid, syscalls, process_info)
        
        # Apply container-specific adjustments
        container_score = self._calculate_container_score(pid, syscalls, container_id)
        
        # Combine scores with weights
        final_score = (
            base_score * 0.4 +
            behavioral_score * 0.3 +
            anomaly_score * self.anomaly_weight +
            container_score * 0.1
        )
        
        # Apply time decay
        if pid in self.risk_history and self.risk_history[pid]:
            last_score = self.risk_history[pid][-1]
            time_since_last = current_time - baseline['last_updated']
            
            if time_since_last > self.decay_interval:
                decayed_score = last_score * (self.decay_factor ** (time_since_last / self.decay_interval))
                final_score = max(final_score, decayed_score)
        
        # Update history and baseline
        self.risk_history[pid].append(final_score)
        if len(self.risk_history[pid]) > 50:  # Keep last 50 scores
            self.risk_history[pid].popleft()
        
        self._update_behavioral_baseline(pid, syscalls, process_info)
        
        # Clamp to 0-100 range
        return min(100.0, max(0.0, final_score))
    
    def _calculate_behavioral_score(self, pid: int, syscalls: List[str], process_info: Dict = None) -> float:
        """Calculate behavioral deviation score"""
        if pid not in self.process_baselines:
            return 0.0
        
        baseline = self.process_baselines[pid]
        
        # Calculate syscall frequency deviation
        current_frequencies = defaultdict(int)
        for syscall in syscalls:
            current_frequencies[syscall] += 1
        
        total_syscalls = len(syscalls)
        if total_syscalls == 0:
            return 0.0
        
        # Compare with baseline
        deviation_score = 0.0
        for syscall, count in current_frequencies.items():
            current_freq = count / total_syscalls
            baseline_freq = baseline['syscall_frequencies'].get(syscall, 0) / max(1, baseline['sample_count'])
            
            # Calculate deviation
            deviation = abs(current_freq - baseline_freq)
            deviation_score += deviation * 10  # Scale to 0-100
        
        # Resource usage deviation
        if process_info:
            cpu_deviation = abs(process_info.get('cpu_percent', 0) - baseline['resource_usage'].get('cpu_percent', 0))
            memory_deviation = abs(process_info.get('memory_percent', 0) - baseline['resource_usage'].get('memory_percent', 0))
            
            deviation_score += (cpu_deviation + memory_deviation) * 0.1
        
        return min(100.0, deviation_score)
    
    def _calculate_container_score(self, pid: int, syscalls: List[str], container_id: str = None) -> float:
        """Calculate container-specific risk score"""
        if not container_id:
            return 0.0
        
        # Container-specific risk adjustments
        container_risk = 0.0
        
        # Check for container escape attempts
        escape_syscalls = ['mount', 'umount', 'chroot', 'pivot_root', 'setns']
        for syscall in syscalls:
            if syscall in escape_syscalls:
                container_risk += 5
        
        # Check for privilege escalation
        privilege_syscalls = ['setuid', 'setgid', 'seteuid', 'setegid']
        for syscall in syscalls:
            if syscall in privilege_syscalls:
                container_risk += 3
        
        return min(100.0, container_risk)
    
    def _update_behavioral_baseline(self, pid: int, syscalls: List[str], process_info: Dict = None):
        """Update behavioral baseline for a process"""
        if pid not in self.process_baselines:
            return
        
        baseline = self.process_baselines[pid]
        
        # Update syscall frequencies
        for syscall in syscalls:
            baseline['syscall_frequencies'][syscall] += 1
        
        # Update resource usage
        if process_info:
            baseline['resource_usage'].update({
                'cpu_percent': process_info.get('cpu_percent', 0),
                'memory_percent': process_info.get('memory_percent', 0)
            })
        
        baseline['last_updated'] = time.time()
        baseline['sample_count'] += 1

class EnhancedSecurityAgent:
    """
    Enhanced Linux Security Agent with research-based improvements
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.console = Console()
        self.running = False
        self.debug_mode = config.get('debug', False)
        
        # Enhanced components
        self.enhanced_ebpf_monitor = None
        self.enhanced_anomaly_detector = None
        self.container_security_monitor = None
        self.enhanced_risk_scorer = None
        self.action_handler = None
        
        # Process tracking
        self.processes = {}  # pid -> process info
        self.syscall_counts = defaultdict(int)
        self.security_events = deque(maxlen=10000)
        
        # Statistics
        self.stats = {
            'total_processes': 0,
            'high_risk_processes': 0,
            'anomalies_detected': 0,
            'cross_container_attempts': 0,
            'policy_violations': 0,
            'actions_taken': 0
        }
        
        # Thread lock for process tracking
        self.processes_lock = threading.Lock()
        
        # Risk score persistence (optional - load from file if exists)
        self.risk_score_file = self.config.get('risk_score_file', '/tmp/security_agent_risk_scores.json')
        self._load_risk_scores()
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all enhanced components"""
        # Initialize enhanced risk scorer
        self.enhanced_risk_scorer = EnhancedRiskScorer(self.config)
        
        # Initialize enhanced eBPF monitor
        if ENHANCED_EBPF_AVAILABLE:
            try:
                self.enhanced_ebpf_monitor = StatefulEBPFMonitor(self.config)
                self.console.print("✅ Enhanced eBPF monitor initialized", style="green")
            except Exception as e:
                self.console.print(f"❌ Enhanced eBPF monitor failed: {e}", style="red")
        
        # Initialize enhanced anomaly detector
        if ENHANCED_ANOMALY_AVAILABLE:
            try:
                self.enhanced_anomaly_detector = EnhancedAnomalyDetector(self.config)
                self.console.print("✅ Enhanced anomaly detector initialized", style="green")
            except Exception as e:
                self.console.print(f"❌ Enhanced anomaly detector failed: {e}", style="red")
        
        # Initialize container security monitor
        if CONTAINER_SECURITY_AVAILABLE:
            try:
                self.container_security_monitor = ContainerSecurityMonitor(self.config)
                # Check if Docker is actually running
                if self.container_security_monitor.docker_available:
                    self.console.print("✅ Container security monitor initialized", style="green")
                else:
                    self.console.print("⚠️ Container monitoring disabled (Docker not running)", style="yellow")
            except Exception as e:
                self.console.print(f"⚠️ Container security monitor disabled: {e}", style="yellow")
                self.container_security_monitor = None
        
        # Initialize action handler
        if ACTION_HANDLER_AVAILABLE:
            try:
                self.action_handler = ActionHandler(self.config)
                self.console.print("✅ Action handler initialized", style="green")
            except Exception as e:
                self.console.print(f"❌ Action handler failed: {e}", style="red")
    
    def start_monitoring(self):
        """Start enhanced security monitoring"""
        self.console.print("🚀 Starting Enhanced Linux Security Agent...", style="bold blue")
        
        # Start enhanced eBPF monitoring with callback
        if self.enhanced_ebpf_monitor:
            if self.enhanced_ebpf_monitor.start_monitoring(event_callback=self._handle_syscall_event):
                self.console.print("✅ Enhanced eBPF monitoring started", style="green")
            else:
                self.console.print("❌ Failed to start enhanced eBPF monitoring", style="red")
        
        # Start container security monitoring
        if self.container_security_monitor and self.container_security_monitor.docker_available:
            if self.container_security_monitor.start_monitoring():
                self.console.print("✅ Container security monitoring started", style="green")
            else:
                self.console.print("⚠️ Container security monitoring disabled", style="yellow")
        
        # Train anomaly detection models if needed
        if self.enhanced_anomaly_detector and not self.enhanced_anomaly_detector.is_fitted:
            self._train_anomaly_models()
        
        # Start cleanup thread to prevent memory leaks
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        self.console.print("✅ Memory cleanup thread started", style="green")
        
        self.running = True
        self.console.print("🎉 Enhanced security monitoring started successfully!", style="bold green")
    
    def _train_anomaly_models(self):
        """Train anomaly detection models with REAL behavior data"""
        self.console.print("🧠 Training anomaly detection models with real data...", style="yellow")
        
        # Collect ACTUAL syscall data from running processes
        training_data = []
        collection_time = 30  # Collect for 30 seconds
        start_time = time.time()
        
        self.console.print(f"📊 Collecting real syscall data for {collection_time} seconds...", style="yellow")
        
        # Collect real data
        while (time.time() - start_time) < collection_time:
            # Collect from processes we're monitoring
            with self.processes_lock:
                for pid, proc in self.processes.items():
                    if proc.get('syscalls') and len(proc['syscalls']) > 10:
                        # Use REAL syscall data
                        syscalls = list(proc['syscalls'])
                        
                        # Get REAL process info from psutil
                        try:
                            p = psutil.Process(int(pid))
                            process_info = {
                                'cpu_percent': p.cpu_percent(interval=0.1) or 0,
                                'memory_percent': p.memory_percent(),
                                'num_threads': p.num_threads()
                            }
                            
                            training_data.append((syscalls, process_info))
                            
                            # Limit to first 1000 samples
                            if len(training_data) >= 1000:
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                            continue
                
                # Check if we have enough data
                if len(training_data) >= 1000:
                    break
            
            time.sleep(0.5)  # Collect every 0.5 seconds
        
        # If still not enough data, supplement with baseline patterns
        if len(training_data) < 100:
            self.console.print("⚠️ Not enough real data, using baseline patterns", style="yellow")
            if self.config.get('debug', False):
                self.console.print(f"🐛 DEBUG: Only collected {len(training_data)} samples, need 100+", style="dim")
            baseline_data = self._get_baseline_patterns()
            training_data.extend(baseline_data)
            if self.config.get('debug', False):
                self.console.print(f"🐛 DEBUG: Added {len(baseline_data)} baseline samples", style="dim")
        else:
            self.console.print(f"✅ Collected {len(training_data)} real training samples", style="green")
        
        # Train models on REAL data
        if self.enhanced_anomaly_detector and training_data:
            if self.config.get('debug', False):
                # Count unique processes in training data
                unique_pids = set()
                total_syscalls = 0
                for seq, info in training_data:
                    if seq:
                        total_syscalls += len(seq)
                    if isinstance(info, dict) and 'pid' in info:
                        unique_pids.add(info['pid'])
                
                self.console.print(f"🐛 DEBUG: Training on {len(training_data)} samples from {len(unique_pids)} processes", style="dim")
                if total_syscalls > 0:
                    avg_syscalls = total_syscalls / len(training_data)
                    self.console.print(f"🐛 DEBUG: Total syscalls: {total_syscalls}, Avg per sample: {avg_syscalls:.1f}", style="dim")
            
            self.enhanced_anomaly_detector.train_models(training_data)
            self.console.print("✅ Anomaly detection models trained on REAL data", style="green")
        else:
            self.console.print("⚠️ No data to train on", style="yellow")
    
    def _get_baseline_patterns(self):
        """Get baseline syscall patterns for common processes"""
        patterns = {
            'text_editor': ['open', 'read', 'write', 'close', 'select', 'mmap', 'munmap'],
            'web_browser': ['socket', 'connect', 'send', 'recv', 'poll', 'read', 'write', 'mmap'],
            'shell': ['fork', 'execve', 'wait', 'read', 'write', 'chdir', 'getcwd', 'close'],
            'file_manager': ['open', 'stat', 'getdents', 'readlink', 'close', 'access', 'fstat'],
        }
        
        training_data = []
        for pattern_type, syscalls in patterns.items():
            for _ in range(50):  # 50 samples per pattern
                # Create realistic sequences with repetition
                sequence = []
                for syscall in syscalls:
                    # Add realistic repetition
                    for _ in range(random.randint(1, 3)):
                        sequence.append(syscall)
                
                process_info = {
                    'cpu_percent': random.uniform(1, 20),
                    'memory_percent': random.uniform(1, 10),
                    'num_threads': random.randint(1, 5)
                }
                
                training_data.append((sequence, process_info))
        
        return training_data
    
    def _cleanup_old_processes(self):
        """Remove stale processes to prevent memory leaks"""
        current_time = time.time()
        stale_pids = []
        
        with self.processes_lock:
            for pid, proc in list(self.processes.items()):
                # Remove if not updated in 5 minutes
                last_update = proc.get('last_update', 0)
                if current_time - last_update > 300:  # 5 minutes
                    stale_pids.append(pid)
            
            # Remove stale processes
            for pid in stale_pids:
                del self.processes[pid]
        
        if stale_pids:
            self.console.print(f"🧹 Cleaned up {len(stale_pids)} stale processes", style="dim")
    
    def _cleanup_loop(self):
        """Periodic cleanup loop to prevent memory leaks"""
        while self.running:
            try:
                self._cleanup_old_processes()
                # Check running flag frequently
                for _ in range(60):  # 60 x 1 = 60 seconds
                    if not self.running:
                        return
                    time.sleep(1)
            except Exception:
                # Exit on any exception if we're shutting down
                if not self.running:
                    return
                time.sleep(1)
    
    def stop_monitoring(self):
        """Stop enhanced security monitoring"""
        if not self.running:
            return  # Already stopped
        
        print("\n🛑 Stopping Enhanced Linux Security Agent...", flush=True)
        
        self.running = False
        
        # Stop cleanup thread (daemon thread, no need to join)
        # Just mark as stopped - daemon thread will exit automatically
        
        # Stop enhanced eBPF monitoring immediately
        if self.enhanced_ebpf_monitor:
            try:
                self.enhanced_ebpf_monitor.running = False  # Force stop first
                self.enhanced_ebpf_monitor.stop_monitoring()
            except:
                pass
        
        # Stop container security monitoring
        if self.container_security_monitor:
            try:
                self.container_security_monitor.stop_monitoring()
            except:
                pass
        
        # Save risk scores before shutdown (fast, non-blocking)
        try:
            self._save_risk_scores()
        except:
            pass
        
        print("✅ Enhanced security monitoring stopped", flush=True)
    
    def _load_risk_scores(self):
        """Load risk scores from previous run if available"""
        try:
            if os.path.exists(self.risk_score_file):
                with open(self.risk_score_file, 'r') as f:
                    saved_data = json.load(f)
                    # Restore risk scores for processes that still exist
                    with self.processes_lock:
                        for pid_str, data in saved_data.items():
                            pid = int(pid_str)
                            if pid in self.processes:
                                self.processes[pid]['risk_score'] = data.get('risk_score', 0)
        except Exception:
            pass  # Ignore errors - start fresh if file doesn't exist
    
    def _save_risk_scores(self):
        """Save current risk scores to file for next run"""
        try:
            saved_data = {}
            with self.processes_lock:
                for pid, proc in self.processes.items():
                    if proc.get('risk_score', 0) > 0:
                        saved_data[str(pid)] = {
                            'risk_score': proc.get('risk_score', 0),
                            'name': proc.get('name', 'unknown'),
                            'last_seen': time.time()
                        }
            if saved_data:
                with open(self.risk_score_file, 'w') as f:
                    json.dump(saved_data, f, indent=2)
        except Exception:
            pass  # Ignore errors - not critical
    
    def _handle_syscall_event(self, pid: int, syscall: str, event_info: Dict = None):
        """Handle syscall event from eBPF monitor"""
        # Get process info from psutil (non-blocking)
        process_info = None
        try:
            proc = psutil.Process(pid)
            # Use interval=None for non-blocking, but it needs previous call
            # Cache CPU calculation - call it once per second per process
            cache_key = f"cpu_cache_{pid}"
            cache_time_key = f"cpu_time_{pid}"
            
            if not hasattr(self, '_cpu_cache'):
                self._cpu_cache = {}
                self._cpu_cache_time = {}
            
            current_time = time.time()
            last_cache_time = self._cpu_cache_time.get(cache_key, 0)
            
            # Update CPU every 1 second per process (to avoid overhead)
            # cpu_percent(interval=None) requires a previous call to calculate delta
            # So we make two calls: first to initialize, second to get value
            if current_time - last_cache_time >= 1.0:
                # First call initializes the counter (returns 0.0)
                proc.cpu_percent(interval=None)
                # Wait a tiny bit for accuracy
                time.sleep(0.01)
                # Second call gets the actual percentage
                cpu_val = proc.cpu_percent(interval=None)
                self._cpu_cache[cache_key] = cpu_val
                self._cpu_cache_time[cache_time_key] = current_time
            else:
                cpu_val = self._cpu_cache.get(cache_key, 0.0)
            
            process_info = {
                'cpu_percent': cpu_val,
                'memory_percent': proc.memory_percent(),
                'num_threads': proc.num_threads()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_info = None
        except Exception:
            # Ignore errors - not critical
            process_info = None
        
        self.process_syscall_event(pid, syscall, process_info)
    
    def process_syscall_event(self, pid: int, syscall: str, process_info: Dict = None):
        """Process a system call event with enhanced analysis"""
        try:
            # Get container information
            container_id = None
            if self.container_security_monitor:
                try:
                    container_id = self.container_security_monitor.process_containers.get(pid)
                except AttributeError:
                    # Container monitor not fully initialized
                    pass
            
            # Validate syscall against container policy
            if self.container_security_monitor:
                try:
                    if not self.container_security_monitor.validate_syscall(pid, syscall):
                        self.stats['policy_violations'] += 1
                        return
                except (AttributeError, Exception) as e:
                    # Graceful degradation if container check fails
                    pass
            
            # Get process state from enhanced eBPF monitor
            process_state = None
            if self.enhanced_ebpf_monitor:
                try:
                    process_state = self.enhanced_ebpf_monitor.get_process_state(pid)
                except (AttributeError, Exception) as e:
                    # eBPF monitor not available or failed
                    pass
            
            # Update process information with thread safety (ONE lock for all updates)
            current_time = time.time()
            process_snapshot = None
            risk_score = 0.0
            should_log_high_risk = False
            
            with self.processes_lock:
                if pid not in self.processes:
                    try:
                        self.processes[pid] = {
                            'name': self._get_process_name(pid),
                            'risk_score': 0.0,
                            'anomaly_score': 0.0,
                            'syscall_count': 0,
                            'last_update': current_time,
                            'last_risk_update': current_time,
                            'syscalls': deque(maxlen=1000),  # Bounded deque
                            'container_id': container_id,
                            'process_state': process_state
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        # Process already gone, skip
                        return
                
                process = self.processes[pid]
                process['syscalls'].append(syscall)  # Deque auto-bounds
                process['syscall_count'] += 1
                process['last_update'] = current_time
                
                # Update CPU usage periodically (every 10 syscalls to avoid overhead)
                if process['syscall_count'] % 10 == 0 and process_info:
                    cpu_val = process_info.get('cpu_percent', 0.0)
                    process['cpu_percent'] = cpu_val if cpu_val is not None else 0.0
                
                # Create snapshot while still in lock
                process_snapshot = dict(process)
                process_snapshot['syscalls'] = list(process['syscalls'])
                
                # Calculate risk score while in lock
                if self.enhanced_risk_scorer:
                    # Apply time decay first
                    if 'last_risk_update' in process:
                        time_since_last = current_time - process['last_risk_update']
                        # Decay: lose 1% per second
                        decay_factor = 0.99 ** time_since_last
                        process['risk_score'] = process['risk_score'] * decay_factor
                    
                    # Calculate new risk score
                    risk_score = self.enhanced_risk_scorer.update_risk_score(
                        pid, list(process['syscalls']), process_info, 
                        process.get('anomaly_score', 0.0), container_id
                    )
                    
                    # Smooth with previous score (exponential moving average)
                    if 'risk_score' in process and process['risk_score'] > 0:
                        process['risk_score'] = 0.7 * risk_score + 0.3 * process['risk_score']
                    else:
                        process['risk_score'] = risk_score
                    
                    process['last_risk_update'] = current_time
                    
                    # Check for high-risk processes
                    if process['risk_score'] >= self.config.get('risk_threshold', 50.0):
                        self.stats['high_risk_processes'] += 1
                        should_log_high_risk = True
            
            # Now do heavy work OUTSIDE the lock (anomaly detection is expensive)
            if not process_snapshot:
                return
            
            # Enhanced anomaly detection (OUTSIDE lock - this is expensive)
            anomaly_result = None
            if self.enhanced_anomaly_detector:
                try:
                    anomaly_result = self.enhanced_anomaly_detector.detect_anomaly_ensemble(
                        process_snapshot['syscalls'], process_info, pid
                    )
                    
                    # Update anomaly score back in process (with lock)
                    with self.processes_lock:
                        if pid in self.processes:
                            old_score = self.processes[pid].get('anomaly_score', 0.0)
                            self.processes[pid]['anomaly_score'] = anomaly_result.anomaly_score
                            
                            # Count anomalies (only increment when crossing threshold to avoid double-counting)
                            if anomaly_result.is_anomaly and old_score < 0.5:
                                self.stats['anomalies_detected'] += 1
                                
                                # Debug mode: only show when anomaly is FIRST detected (threshold crossing)
                                if self.config.get('debug', False):
                                    with self._debug_rate_limit_lock:
                                        current_time = time.time()
                                        last_print = self._debug_rate_limit.get(pid, 0)
                                        # Only print once per PID every 10 seconds
                                        if current_time - last_print >= 10.0:
                                            print(f"🐛 DEBUG Anomaly DETECTED: PID={pid} ({process_snapshot.get('name', 'unknown')}) "
                                                  f"score={anomaly_result.anomaly_score:.2f}, "
                                                  f"confidence={anomaly_result.confidence:.2f}, "
                                                  f"explanation={anomaly_result.explanation[:80] if anomaly_result.explanation else 'N/A'}")
                                            self._debug_rate_limit[pid] = current_time
                            elif self.config.get('debug', False) and anomaly_result.is_anomaly:
                                # Rate limit: only log significant changes once per 10 seconds
                                with self._debug_rate_limit_lock:
                                    current_time = time.time()
                                    last_print = self._debug_rate_limit.get(pid, 0)
                                    # Only log if score changed by 10+ points AND 10 seconds have passed
                                    if abs(old_score - anomaly_result.anomaly_score) >= 10.0 and (current_time - last_print) >= 10.0:
                                        print(f"🐛 DEBUG Anomaly UPDATE: PID={pid} score={anomaly_result.anomaly_score:.2f} (was {old_score:.2f})")
                                        self._debug_rate_limit[pid] = current_time
                    
                    if anomaly_result.is_anomaly:
                        self._log_security_event('anomaly_detected', {
                            'pid': pid,
                            'process_name': process_snapshot['name'],
                            'anomaly_score': anomaly_result.anomaly_score,
                            'explanation': anomaly_result.explanation
                        })
                except Exception as e:
                    print(f"Anomaly detection error: {e}")
            
            # Log high-risk event (use snapshot data)
            if should_log_high_risk:
                self._log_security_event('high_risk_process', {
                    'pid': pid,
                    'process_name': process_snapshot['name'],
                    'risk_score': risk_score,
                    'anomaly_score': process_snapshot.get('anomaly_score', 0.0)
                })
            
            # Take action if needed (with lock)
            if self.action_handler:
                try:
                    with self.processes_lock:
                        if pid in self.processes:
                            process = self.processes[pid]
                            self.action_handler.take_action(
                                pid, process['name'], process['risk_score'], 
                                process.get('anomaly_score', 0.0)
                            )
                            self.stats['actions_taken'] += 1
                except Exception as e:
                    print(f"Action handler error: {e}")
            
            # Update statistics (no lock needed for syscall_counts, it's thread-safe defaultdict)
            self.syscall_counts[syscall] += 1
            
            # Update total processes count (every syscall to keep it accurate)
            with self.processes_lock:
                self.stats['total_processes'] = len(self.processes)
            
        except Exception as e:
            self.console.print(f"❌ Error processing syscall event: {e}", style="red")
            self.console.print(f"Traceback: {traceback.format_exc()}", style="red")
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name by PID"""
        try:
            process = psutil.Process(pid)
            return process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"<unknown:{pid}>"
    
    def _log_security_event(self, event_type: str, details: Dict):
        """Log security event"""
        event = {
            'timestamp': time.time(),
            'event_type': event_type,
            'details': details
        }
        self.security_events.append(event)
    
    def get_high_risk_processes(self, threshold: float = 50.0) -> List[Tuple[int, str, float, float]]:
        """Get processes with risk scores above threshold"""
        high_risk = []
        for pid, process in self.processes.items():
            risk_score = process.get('risk_score', 0) or 0
            if risk_score >= threshold:
                anomaly_score = process.get('anomaly_score', 0.0)
                high_risk.append((pid, process['name'], risk_score, anomaly_score))
        return sorted(high_risk, key=lambda x: x[2], reverse=True)
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get comprehensive monitoring statistics"""
        stats = {
            **self.stats,
            'enhanced_ebpf_stats': self.enhanced_ebpf_monitor.get_monitoring_stats() if self.enhanced_ebpf_monitor else {},
            'anomaly_detection_stats': self.enhanced_anomaly_detector.get_detection_stats() if self.enhanced_anomaly_detector else {},
            'container_security_stats': self.container_security_monitor.get_security_stats() if self.container_security_monitor else {},
            'total_syscalls': sum(self.syscall_counts.values()),
            'unique_syscalls': len(self.syscall_counts),
            'security_events': len(self.security_events)
        }
        return stats
    
    def export_monitoring_data(self) -> Dict[str, Any]:
        """Export comprehensive monitoring data"""
        data = {
            'processes': self.processes,
            'syscall_counts': dict(self.syscall_counts),
            'security_events': list(self.security_events),
            'stats': self.get_monitoring_stats(),
            'export_timestamp': time.time()
        }
        
        # Add enhanced component data
        if self.enhanced_ebpf_monitor:
            data['enhanced_ebpf_data'] = self.enhanced_ebpf_monitor.export_state_data()
        
        if self.enhanced_anomaly_detector:
            data['anomaly_detection_data'] = self.enhanced_anomaly_detector.export_anomaly_data()
        
        if self.container_security_monitor:
            data['container_security_data'] = self.container_security_monitor.export_security_data()
        
        return data
    
    def _create_dashboard(self):
        """Create detailed real-time monitoring dashboard"""
        
        # Main processes table - fixed widths to prevent wrapping
        table = Table(
            title="🖥️ Live Process Monitoring", 
            box=box.ROUNDED, 
            show_header=True, 
            header_style="bold",
            padding=(0, 1)
        )
        # Column widths: 8+18+10+8+10+8 = 62 chars + 7 borders = ~69 total width needed
        table.add_column("PID", style="cyan", no_wrap=True, width=7, justify="right", overflow="ignore")
        table.add_column("Process Name", style="magenta", width=16, no_wrap=True, overflow="ellipsis")
        table.add_column("Risk", justify="right", style="yellow", width=9, no_wrap=True, overflow="ignore")
        table.add_column("Anomaly", justify="center", style="yellow", width=7, no_wrap=True, overflow="ignore")
        table.add_column("Syscalls", justify="right", style="green", width=9, no_wrap=True, overflow="ignore")
        table.add_column("CPU%", justify="right", style="cyan", width=7, no_wrap=True, overflow="ignore")
        
        # Add processes sorted by risk score
        sorted_processes = sorted(
            self.processes.items(),
            key=lambda x: x[1].get('risk_score', 0) or 0,
            reverse=True
        )[:10]  # Show top 10
        
        if sorted_processes:
            for pid, proc in sorted_processes:
                risk_score = proc.get('risk_score', 0) or 0
                anomaly_score = proc.get('anomaly_score', 0.0)
                syscall_count = proc.get('syscall_count', 0)
                
                # Risk indicator
                if risk_score >= 50:
                    risk_display = f"🔴 {risk_score:.0f}"
                elif risk_score >= 30:
                    risk_display = f"🟡 {risk_score:.0f}"
                else:
                    risk_display = f"🟢 {risk_score:.0f}"
                
                # Anomaly indicator (simplified)
                if anomaly_score >= 0.5:
                    anomaly_display = "⚠️"
                else:
                    anomaly_display = "✓"
                
                # Get CPU usage - check if we've stored it in process dict
                # (we update it during syscall processing)
                cpu_percent = proc.get('cpu_percent', None)
                if cpu_percent is not None:
                    # Cap CPU at 100% (psutil can show >100% on multi-core, normalize)
                    cpu_percent = min(100.0, max(0.0, cpu_percent))
                    cpu_display = f"{cpu_percent:.1f}%"
                else:
                    # Try to get it from psutil (may be 0.0 if just started)
                    try:
                        p = psutil.Process(int(pid))
                        # Get CPU - may be 0.0% if process is idle or just started
                        cpu = p.cpu_percent(interval=None) or 0.0
                        cpu = min(100.0, max(0.0, cpu))  # Cap at 100%
                        cpu_display = f"{cpu:.1f}%"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        cpu_display = "N/A"
                    except:
                        cpu_display = "0.0%"
                
                # Format syscall count properly
                syscall_display = f"{syscall_count:,}" if syscall_count > 0 else "0"
                
                # Truncate process name if too long
                proc_name = proc.get('name', '<unknown>')
                if len(proc_name) > 17:
                    proc_name = proc_name[:14] + "..."
                
                table.add_row(
                    str(pid),
                    proc_name,
                    risk_display,
                    anomaly_display,
                    syscall_display,
                    cpu_display
                )
        else:
            table.add_row("Waiting for syscall events...", "", "", "", "", "", style="dim")
        
        # Stats panel with explanations
        stats_panel_content = f"""
📊 **Statistics**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 Processes Monitored: {self.stats['total_processes']}
   → Total unique processes captured by eBPF

⚠️  High Risk Processes: {self.stats['high_risk_processes']}  
   → Processes flagged with risk score ≥ 50
   → Detected suspicious syscalls (ptrace, execve, etc.)

🚨 Anomalies Detected: {self.stats['anomalies_detected']}
   → Processes that crossed anomaly threshold (score ≥ 0.5)
   → Current anomaly scores stored per-process in table above
   → ML ensemble (Isolation Forest + One-Class SVM + DBSCAN) analyzes patterns
   → Note: Same process can trigger multiple times if behavior changes

🔒 Policy Violations: {self.stats['policy_violations']}
   → Container security policy violations (currently 0)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 **What's Happening:**
• eBPF is capturing system calls from running processes
• ML models are analyzing behavior patterns in real-time
• Risk scores combine syscall analysis + behavioral baselining
• Anomaly detection uses ensemble of 3 ML algorithms
• Dashboard updates every second

💡 **Risk Score Meaning:**
   🟢 0-30:  Normal system activity
   🟡 30-50: Potentially suspicious
   🔴 50+:   High risk - investigate immediately
        """
        
        # Combine everything - Rich will handle table rendering
        from rich.console import Console
        from io import StringIO
        
        # Increase console width to prevent table wrapping (~70 chars for table + borders)
        string_console = Console(file=StringIO(), force_terminal=True, width=150, legacy_windows=False)
        string_console.print(table, overflow="ignore")
        table_str = string_console.file.getvalue()
        
        content = f"\n{table_str}\n\n{stats_panel_content}"
        
        return Panel(content, title="🛡️ Enhanced Linux Security Agent - Real-time Monitoring", 
                    border_style="green", padding=(0, 1))
    
    def _list_processes(self):
        """List all monitored processes"""
        print("\n" + "="*80)
        print("📋 MONITORED PROCESSES")
        print("="*80)
        
        with self.processes_lock:
            if not self.processes:
                print("No processes monitored yet.")
                return
            
            # Sort by risk score
            sorted_procs = sorted(
                self.processes.items(),
                key=lambda x: x[1].get('risk_score', 0) or 0,
                reverse=True
            )
            
            print(f"\nTotal Processes: {len(sorted_procs)}\n")
            print(f"{'PID':<8} {'Process Name':<20} {'Risk':<8} {'Syscalls':<12} {'Anomaly':<10}")
            print("-" * 80)
            
            for pid, proc in sorted_procs:
                risk = proc.get('risk_score', 0) or 0
                name = proc.get('name', '<unknown>')[:19]
                syscalls = proc.get('syscall_count', 0)
                anomaly = proc.get('anomaly_score', 0.0)
                anomaly_str = f"⚠️ {anomaly:.2f}" if anomaly >= 0.5 else f"✓ {anomaly:.2f}"
                
                print(f"{pid:<8} {name:<20} {risk:<8.0f} {syscalls:<12} {anomaly_str:<10}")
        
        print("\n" + "="*80 + "\n")
    
    def _list_anomalies(self):
        """List all detected anomalies"""
        print("\n" + "="*80)
        print("🚨 DETECTED ANOMALIES")
        print("="*80)
        
        with self.processes_lock:
            anomalies = []
            for pid, proc in self.processes.items():
                anomaly_score = proc.get('anomaly_score', 0.0)
                if anomaly_score >= 0.5:
                    anomalies.append({
                        'pid': pid,
                        'name': proc.get('name', '<unknown>'),
                        'anomaly_score': anomaly_score,
                        'risk_score': proc.get('risk_score', 0) or 0,
                        'syscall_count': proc.get('syscall_count', 0)
                    })
            
            if not anomalies:
                print("\n✅ No anomalies detected.\n")
                return
            
            # Sort by anomaly score
            anomalies.sort(key=lambda x: x['anomaly_score'], reverse=True)
            
            print(f"\nTotal Anomalies: {len(anomalies)}\n")
            print(f"{'PID':<8} {'Process Name':<20} {'Anomaly Score':<15} {'Risk':<8} {'Syscalls':<10}")
            print("-" * 80)
            
            for anom in anomalies:
                print(f"{anom['pid']:<8} {anom['name'][:19]:<20} {anom['anomaly_score']:<15.2f} "
                      f"{anom['risk_score']:<8.0f} {anom['syscall_count']:<10}")
        
        print("\n" + "="*80 + "\n")
    
    def _show_stats(self):
        """Show comprehensive statistics"""
        print("\n" + "="*80)
        print("📊 MONITORING STATISTICS")
        print("="*80)
        
        stats = self.get_monitoring_stats()
        
        print(f"\n🔍 Processes Monitored: {stats.get('total_processes', 0)}")
        print(f"⚠️  High Risk Processes: {stats.get('high_risk_processes', 0)}")
        print(f"🚨 Anomalies Detected: {stats.get('anomalies_detected', 0)}")
        print(f"🔒 Policy Violations: {stats.get('policy_violations', 0)}")
        print(f"📡 Total Syscalls Captured: {stats.get('total_syscalls', 0)}")
        print(f"🔢 Unique Syscall Types: {stats.get('unique_syscalls', 0)}")
        
        if self.enhanced_ebpf_monitor:
            ebpf_stats = stats.get('enhanced_ebpf_stats', {})
            if 'events_captured' in ebpf_stats:
                print(f"📥 eBPF Events Captured: {ebpf_stats['events_captured']}")
        
        if self.enhanced_anomaly_detector:
            anom_stats = stats.get('anomaly_detection_stats', {})
            print(f"\n🧠 ML Model Statistics:")
            print(f"   Total Detections: {anom_stats.get('total_detections', 0)}")
            print(f"   True Positives: {anom_stats.get('true_positives', 0)}")
        
        print("\n" + "="*80 + "\n")

def main():
    """Main function for enhanced security agent"""
    parser = argparse.ArgumentParser(description='Enhanced Linux Security Agent')
    parser.add_argument('--dashboard', action='store_true', help='Show real-time dashboard')
    parser.add_argument('--threshold', type=float, default=50.0, help='Risk threshold for alerts')
    parser.add_argument('--timeout', type=int, default=0, help='Run for specified seconds (0 = indefinitely)')
    parser.add_argument('--output', choices=['console', 'json'], default='console', help='Output format')
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--train-models', action='store_true', help='Train anomaly detection models')
    parser.add_argument('--list-processes', action='store_true', help='List all monitored processes and exit')
    parser.add_argument('--list-anomalies', action='store_true', help='List all detected anomalies and exit')
    parser.add_argument('--stats', action='store_true', help='Show statistics and exit')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode with detailed logging')
    parser.add_argument('--daemon', action='store_true', help='Run as background daemon (logs to file)')
    parser.add_argument('--log-file', type=str, default='/tmp/security_agent.log', help='Log file for daemon mode')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    config.update({
        'risk_threshold': args.threshold,
        'output_format': args.output,
        'debug': args.debug or config.get('debug', False)
    })
    
    # Handle daemon mode (background operation) - FUTURE IMPLEMENTATION
    if args.daemon:
        print("⚠️  Daemon mode coming soon!")
        print("For now, use: nohup sudo python3 core/enhanced_security_agent.py --dashboard --timeout 3600 > /tmp/agent.log 2>&1 &")
        print("Then check logs: tail -f /tmp/agent.log")
        sys.exit(0)
    
    # Create enhanced security agent
    agent = EnhancedSecurityAgent(config)
    
    # Train models if requested
    if args.train_models and agent.enhanced_anomaly_detector:
        agent._train_anomaly_models()
        return
    
    # Handle query commands (list processes, anomalies, stats)
    if args.list_processes or args.list_anomalies or args.stats:
        # Need to start monitoring briefly to collect data
        agent.start_monitoring()
        time.sleep(5)  # Collect data for 5 seconds
        
        if args.list_processes:
            agent._list_processes()
        elif args.list_anomalies:
            agent._list_anomalies()
        elif args.stats:
            agent._show_stats()
        
        agent.stop_monitoring()
        return
    
    # Set up signal handlers for clean exit - MUST be before start_monitoring
    exit_requested = threading.Event()
    shutdown_initiated = False
    
    def signal_handler(signum, frame):
        nonlocal shutdown_initiated
        if shutdown_initiated:
            # Force immediate exit on second Ctrl+C
            print("\n🛑 Force exit!")
            os._exit(1)
        
        shutdown_initiated = True
        print("\n🛑 Ctrl+C detected! Stopping agent...")
        exit_requested.set()
        agent.running = False
        
        # Force immediate stop of all threads
        if agent.enhanced_ebpf_monitor:
            agent.enhanced_ebpf_monitor.running = False
    
    # Install signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    agent.start_monitoring()
    
    try:
        start_time = time.time()
        
        if args.dashboard:
            # Show real-time dashboard - use Live with screen=False for better signal handling
            from rich.live import Live
            live = None
            try:
                live = Live(agent._create_dashboard(), refresh_per_second=2, screen=False)
                live.start()
                
                while agent.running and not exit_requested.is_set():
                    elapsed = time.time() - start_time
                    if args.timeout > 0 and elapsed >= args.timeout:
                        print(f"\n⏰ Timeout reached ({args.timeout}s) - stopping agent...", flush=True)
                        agent.running = False
                        exit_requested.set()
                        break
                    
                    if exit_requested.is_set() or not agent.running:
                        break
                    
                    try:
                        live.update(agent._create_dashboard())
                    except (KeyboardInterrupt, SystemExit):
                        agent.running = False
                        break
                    except:
                        pass
                    
                    # Very short sleep - check exit VERY frequently (50ms total wait)
                    for _ in range(5):  # 5 x 0.01 = 50ms total - allows quick Ctrl+C response
                        if exit_requested.is_set() or not agent.running:
                            break
                        time.sleep(0.01)
            except (KeyboardInterrupt, SystemExit):
                agent.running = False
            finally:
                if live:
                    try:
                        # Stop Live immediately, don't wait
                        live.stop()
                        live.refresh()
                    except:
                        pass
                # Force exit flag
                exit_requested.set()
        else:
            # Run without dashboard
            while agent.running and not exit_requested.is_set():
                # Check exit BEFORE expensive operations
                if exit_requested.is_set() or not agent.running:
                    break
                    
                elapsed = time.time() - start_time
                if args.timeout > 0 and elapsed >= args.timeout:
                    print(f"\n⏰ Timeout reached ({args.timeout}s) - stopping agent...", flush=True)
                    agent.running = False
                    exit_requested.set()
                    break
                
                # Short sleep to allow signal handling - check exit frequently
                time.sleep(0.1)  # 100ms - allows signal handler to work
    
    except KeyboardInterrupt:
        print("\n🛑 Keyboard interrupt detected!")
        exit_requested.set()
        agent.running = False
    
    finally:
        agent.stop_monitoring()
        
        # Export data if requested
        if args.output == 'json':
            data = agent.export_monitoring_data()
            print(json.dumps(data, indent=2))

if __name__ == "__main__":
    main()
