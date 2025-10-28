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
except ImportError:
    ENHANCED_EBPF_AVAILABLE = False
    print("Warning: Enhanced eBPF monitor not available.")

try:
    from enhanced_anomaly_detector import EnhancedAnomalyDetector, AnomalyResult, BehavioralBaseline
    ENHANCED_ANOMALY_AVAILABLE = True
except ImportError:
    ENHANCED_ANOMALY_AVAILABLE = False
    print("Warning: Enhanced anomaly detector not available.")

try:
    from container_security_monitor import ContainerSecurityMonitor, ContainerInfo, CrossContainerAttempt
    CONTAINER_SECURITY_AVAILABLE = True
except ImportError:
    CONTAINER_SECURITY_AVAILABLE = False
    print("Warning: Container security monitor not available.")

# Import existing components
try:
    from action_handler import ActionHandler, ActionType
    ACTION_HANDLER_AVAILABLE = True
except ImportError:
    ACTION_HANDLER_AVAILABLE = False
    print("Warning: Action handler not available.")

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
                self.console.print("✅ Container security monitor initialized", style="green")
            except Exception as e:
                self.console.print(f"❌ Container security monitor failed: {e}", style="red")
        
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
        if self.container_security_monitor:
            if self.container_security_monitor.start_monitoring():
                self.console.print("✅ Container security monitoring started", style="green")
            else:
                self.console.print("❌ Failed to start container security monitoring", style="red")
        
        # Train anomaly detection models if needed
        if self.enhanced_anomaly_detector and not self.enhanced_anomaly_detector.is_fitted:
            self._train_anomaly_models()
        
        self.running = True
        self.console.print("🎉 Enhanced security monitoring started successfully!", style="bold green")
    
    def _train_anomaly_models(self):
        """Train anomaly detection models with normal behavior data"""
        self.console.print("🧠 Training anomaly detection models...", style="yellow")
        
        # Generate training data - try to use real data if available, otherwise simulate
        training_data = []
        
        # If we have actual syscall data from monitoring, use it
        if self.processes and self.syscall_counts:
            for pid, proc in list(self.processes.items())[:100]:  # Use up to 100 processes
                if proc.get('syscalls'):
                    training_data.append((
                        proc['syscalls'][-100:],  # Use last 100 syscalls
                        {
                            'cpu_percent': random.uniform(0, 30),
                            'memory_percent': random.uniform(0, 15),
                            'num_threads': random.randint(1, 5)
                        }
                    ))
        
        # If not enough real data, supplement with simulated data
        if len(training_data) < 1000:
            self.console.print(f"📊 Using {len(training_data)} real samples, supplementing with simulated data...", style="yellow")
            for i in range(1000 - len(training_data)):
                # Simulate normal syscall patterns
                normal_syscalls = ['read', 'write', 'open', 'close', 'mmap', 'munmap']
                syscalls = [random.choice(normal_syscalls) for _ in range(random.randint(10, 50))]
                
                process_info = {
                    'cpu_percent': random.uniform(0, 30),
                    'memory_percent': random.uniform(0, 15),
                    'num_threads': random.randint(1, 5)
                }
                
                training_data.append((syscalls, process_info))
        
        # Train models
        self.enhanced_anomaly_detector.train_models(training_data)
        self.console.print("✅ Anomaly detection models trained", style="green")
    
    def stop_monitoring(self):
        """Stop enhanced security monitoring"""
        self.console.print("🛑 Stopping Enhanced Linux Security Agent...", style="yellow")
        
        self.running = False
        
        # Stop enhanced eBPF monitoring
        if self.enhanced_ebpf_monitor:
            self.enhanced_ebpf_monitor.stop_monitoring()
        
        # Stop container security monitoring
        if self.container_security_monitor:
            self.container_security_monitor.stop_monitoring()
        
        self.console.print("✅ Enhanced security monitoring stopped", style="green")
    
    def _handle_syscall_event(self, pid: int, syscall: str, event_info: Dict = None):
        """Handle syscall event from eBPF monitor"""
        # Get process info from psutil
        try:
            proc = psutil.Process(pid)
            process_info = {
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent(),
                'num_threads': proc.num_threads()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
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
            
            # Update process information with thread safety
            with self.processes_lock:
                if pid not in self.processes:
                    try:
                        self.processes[pid] = {
                            'name': self._get_process_name(pid),
                            'risk_score': 0.0,
                            'anomaly_score': 0.0,
                            'syscall_count': 0,
                            'last_update': time.time(),
                            'syscalls': [],
                            'container_id': container_id,
                            'process_state': process_state
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        # Process already gone, skip
                        return
                
                process = self.processes[pid]
                process['syscalls'].append(syscall)
                process['syscall_count'] += 1
                process['last_update'] = time.time()
                
                # Prune syscalls list to prevent memory leak
                if len(process['syscalls']) > 10000:
                    # Keep last 1000 syscalls
                    process['syscalls'] = process['syscalls'][-1000:]
                
                # Get safe reference to process for later use
                process_ref = dict(process)  # Copy for use outside lock
            
            # Enhanced anomaly detection
            anomaly_result = None
            if self.enhanced_anomaly_detector:
                try:
                    anomaly_result = self.enhanced_anomaly_detector.detect_anomaly_ensemble(
                        process_ref['syscalls'], process_info, pid
                    )
                    with self.processes_lock:
                        if pid in self.processes:
                            self.processes[pid]['anomaly_score'] = anomaly_result.anomaly_score
                
                    if anomaly_result.is_anomaly:
                        self.stats['anomalies_detected'] += 1
                        self._log_security_event('anomaly_detected', {
                            'pid': pid,
                            'process_name': process_ref['name'],
                            'anomaly_score': anomaly_result.anomaly_score,
                            'explanation': anomaly_result.explanation
                        })
                except Exception as e:
                    print(f"Anomaly detection error: {e}")
            
            # Enhanced risk scoring
            if self.enhanced_risk_scorer:
                try:
                    with self.processes_lock:
                        if pid in self.processes:
                            process = self.processes[pid]
                            risk_score = self.enhanced_risk_scorer.update_risk_score(
                                pid, process['syscalls'], process_info, 
                                process.get('anomaly_score', 0.0), container_id
                            )
                            process['risk_score'] = risk_score
                            
                            # Check for high-risk processes
                            if risk_score >= self.config.get('risk_threshold', 50.0):
                                self.stats['high_risk_processes'] += 1
                                self._log_security_event('high_risk_process', {
                                    'pid': pid,
                                    'process_name': process['name'],
                                    'risk_score': risk_score,
                                    'anomaly_score': process.get('anomaly_score', 0.0)
                                })
                except Exception as e:
                    print(f"Risk scoring error: {e}")
            
            # Take action if needed
            if self.action_handler:
                try:
                    with self.processes_lock:
                        if pid in self.processes:
                            process = self.processes[pid]
                            self.action_handler.take_action(
                                pid, process['name'], process['risk_score'], process.get('anomaly_score', 0.0)
                            )
                            self.stats['actions_taken'] += 1
                except Exception as e:
                    print(f"Action handler error: {e}")
            
            # Update statistics
            self.syscall_counts[syscall] += 1
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
        """Create real-time monitoring dashboard"""
        # Create table for process monitoring
        table = Table(title="Enhanced Linux Security Agent - Process Monitoring", box=box.ROUNDED)
        table.add_column("PID", style="cyan", no_wrap=True)
        table.add_column("Process Name", style="magenta")
        table.add_column("Risk Score", justify="right", style="red")
        table.add_column("Anomaly", justify="right", style="yellow")
        table.add_column("Syscalls", justify="right")
        table.add_column("Last Update", style="blue")
        
        # Add processes sorted by risk score
        sorted_processes = sorted(
            self.processes.items(),
            key=lambda x: x[1].get('risk_score', 0) or 0,
            reverse=True
        )[:20]  # Show top 20
        
        for pid, proc in sorted_processes:
            risk_score = proc.get('risk_score', 0) or 0
            anomaly_score = proc.get('anomaly_score', 0.0)
            
            table.add_row(
                str(pid),
                proc.get('name', '<unknown>'),
                f"{risk_score:.1f}",
                f"{anomaly_score:.1f}" if anomaly_score else "0.0",
                str(proc.get('syscall_count', 0)),
                datetime.fromtimestamp(proc.get('last_update', 0)).strftime("%H:%M:%S")
            )
        
        # Create stats panel
        stats_text = Text()
        stats_text.append(f"Processes Monitored: {self.stats['total_processes']}\n", style="cyan")
        stats_text.append(f"High Risk Processes: {self.stats['high_risk_processes']}\n", style="red")
        stats_text.append(f"Anomalies Detected: {self.stats['anomalies_detected']}\n", style="yellow")
        stats_text.append(f"Policy Violations: {self.stats['policy_violations']}\n", style="magenta")
        
        # Combine into panel
        content = f"{table}\n\n{stats_text}"
        
        return Panel(content, title="Enhanced Linux Security Agent", border_style="green")

def main():
    """Main function for enhanced security agent"""
    parser = argparse.ArgumentParser(description='Enhanced Linux Security Agent')
    parser.add_argument('--dashboard', action='store_true', help='Show real-time dashboard')
    parser.add_argument('--threshold', type=float, default=50.0, help='Risk threshold for alerts')
    parser.add_argument('--timeout', type=int, default=0, help='Run for specified seconds (0 = indefinitely)')
    parser.add_argument('--output', choices=['console', 'json'], default='console', help='Output format')
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--train-models', action='store_true', help='Train anomaly detection models')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    config.update({
        'risk_threshold': args.threshold,
        'output_format': args.output
    })
    
    # Create enhanced security agent
    agent = EnhancedSecurityAgent(config)
    
    # Train models if requested
    if args.train_models and agent.enhanced_anomaly_detector:
        agent._train_anomaly_models()
        return
    
    # Start monitoring
    agent.start_monitoring()
    
    try:
        start_time = time.time()
        
        if args.dashboard:
            # Show real-time dashboard
            with Live(agent._create_dashboard(), refresh_per_second=2) as live:
                while agent.running:
                    if args.timeout > 0 and (time.time() - start_time) >= args.timeout:
                        break
                    
                    live.update(agent._create_dashboard())
                    time.sleep(0.5)
        else:
            # Run without dashboard
            while agent.running:
                if args.timeout > 0 and (time.time() - start_time) >= args.timeout:
                    break
                
                time.sleep(1)
    
    except KeyboardInterrupt:
        agent.console.print("\n🛑 Stopping enhanced security agent...", style="yellow")
    
    finally:
        agent.stop_monitoring()
        
        # Export data if requested
        if args.output == 'json':
            data = agent.export_monitoring_data()
            print(json.dumps(data, indent=2))

if __name__ == "__main__":
    main()
