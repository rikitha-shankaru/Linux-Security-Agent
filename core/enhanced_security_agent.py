#!/usr/bin/env python3
"""
Enhanced Linux Security Agent - Research-Based Implementation
==============================================================

Main orchestrator for the security monitoring system. Integrates stateful 
eBPF monitoring, unsupervised ML anomaly detection, container security, and 
automatic incremental retraining.

Key Components:
- Enhanced eBPF Monitor: Kernel-level syscall tracking
- Anomaly Detector: Ensemble ML models (IF, OCSVM, DBSCAN)
- Incremental Trainer: Automatic model retraining
- Container Monitor: Docker security tracking
- Risk Scorer: Threat prioritization
- TUI Dashboard: Real-time visualization

Usage:
    sudo python3 enhanced_security_agent.py --collector ebpf --threshold 30

Author: Likitha Shankar
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
import logging
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Callable
import traceback

# Constants to replace magic numbers
MAX_VALID_PID = 2147483647  # Maximum valid PID on Linux
STALE_PROCESS_TIMEOUT = 300  # 5 minutes in seconds
PROCESS_NAME_CACHE_TTL = 300  # 5 minutes cache TTL
SYSCALL_NAME_MAX_LENGTH = 64  # Maximum syscall name length
DASHBOARD_REFRESH_RATE = 2  # Dashboard updates per second
CLEANUP_CHECK_INTERVAL = 0.1  # Seconds between cleanup checks
DEFAULT_RISK_THRESHOLD = 50.0  # Default risk threshold
DEFAULT_ANOMALY_WEIGHT = 0.3  # Default anomaly weight in risk calculation
DEFAULT_DECAY_FACTOR = 0.95  # Default risk decay factor
DEFAULT_DECAY_INTERVAL = 60  # Default decay interval in seconds

# Performance optimization constants
ML_INFERENCE_INTERVAL = 10  # Run ML inference every N syscalls per process
ML_INFERENCE_TIME_INTERVAL = 2.0  # Minimum seconds between ML inferences per process
RISK_SCORE_CACHE_TTL = 0.5  # Cache risk scores for 0.5 seconds to avoid recalculation
MIN_SYSCALLS_FOR_ML = 5  # Minimum syscalls before running ML inference

# Add core directory and project root to path for imports
_core_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_core_dir)
if _core_dir not in sys.path:
    sys.path.insert(0, _core_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('security_agent')

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    logger.warning("BCC not available. Using fallback monitoring.")

import psutil
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich import box
import click
from pathlib import Path

try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False

# Import enhanced components - use relative imports from core/
try:
    from core.enhanced_ebpf_monitor import StatefulEBPFMonitor, ProcessState, SecurityPolicy
    ENHANCED_EBPF_AVAILABLE = True
except ImportError:
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
    try:
        from core.enhanced_anomaly_detector import EnhancedAnomalyDetector, AnomalyResult, BehavioralBaseline
        ENHANCED_ANOMALY_AVAILABLE = True
    except ImportError:
        from enhanced_anomaly_detector import EnhancedAnomalyDetector, AnomalyResult, BehavioralBaseline
        ENHANCED_ANOMALY_AVAILABLE = True
except ImportError as e:
    ENHANCED_ANOMALY_AVAILABLE = False
    # Optional component - will work without it

try:
    try:
        from core.container_security_monitor import ContainerSecurityMonitor, ContainerInfo, CrossContainerAttempt
        CONTAINER_SECURITY_AVAILABLE = True
    except ImportError:
        from container_security_monitor import ContainerSecurityMonitor, ContainerInfo, CrossContainerAttempt
        CONTAINER_SECURITY_AVAILABLE = True
except ImportError as e:
    CONTAINER_SECURITY_AVAILABLE = False
    # Optional component - suppress warning for cleaner output

# Optional auditd collector (fallback)
try:
    try:
        from core.collectors.auditd_collector import AuditdCollector
        AUDITD_AVAILABLE = True
    except ImportError:
        try:
            from collectors.auditd_collector import AuditdCollector
            AUDITD_AVAILABLE = True
        except ImportError:
            AUDITD_AVAILABLE = False
except ImportError:
    AUDITD_AVAILABLE = False

# Import new response and threat intelligence modules
try:
    try:
        from core.response_handler import ResponseHandler, ResponseAction
        from core.threat_intelligence import ThreatIntelligence, IOCFeed
        RESPONSE_HANDLER_AVAILABLE = True
        THREAT_INTEL_AVAILABLE = True
    except ImportError:
        from response_handler import ResponseHandler, ResponseAction
        from threat_intelligence import ThreatIntelligence, IOCFeed
        RESPONSE_HANDLER_AVAILABLE = True
        THREAT_INTEL_AVAILABLE = True
except ImportError as e:
    RESPONSE_HANDLER_AVAILABLE = False
    THREAT_INTEL_AVAILABLE = False
    ResponseHandler = None
    ThreatIntelligence = None
    logger.debug(f"Response handler and threat intelligence not available: {e}")

# Import existing components
# ActionHandler is optional and in legacy/, so it's disabled
ACTION_HANDLER_AVAILABLE = False
ActionHandler = None  # Type stub to avoid NameError

class EnhancedRiskScorer:
    """
    Enhanced risk scoring system with behavioral baselining and adaptive thresholds
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        
        # Risk scoring parameters (allow overrides from config)
        default_base = {
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
        self.base_risk_scores = dict(default_base)
        if isinstance(self.config.get('base_risk_scores'), dict):
            try:
                # Shallow merge: override provided keys
                self.base_risk_scores.update(self.config['base_risk_scores'])
            except Exception:
                pass
        
        # Adaptive risk scoring
        self.process_baselines = {}  # pid -> baseline behavior
        # FIXED: Use deque with maxlen to prevent unbounded growth
        self.risk_history = defaultdict(lambda: deque(maxlen=50))  # pid -> risk history (max 50 entries)
        self.adaptive_thresholds = {}  # pid -> adaptive threshold
        
        # Time decay parameters
        self.decay_factor = self.config.get('decay_factor', 0.95)
        self.decay_interval = self.config.get('decay_interval', 60)  # seconds
        
        # Behavioral analysis
        self.behavioral_window = self.config.get('behavioral_window', 100)
        self.anomaly_weight = self.config.get('anomaly_weight', 0.3)
    
    def update_risk_score(self, pid: int, syscalls: List[str], 
                         process_info: Optional[Dict[str, Any]] = None, 
                         anomaly_score: float = 0.0, 
                         container_id: Optional[str] = None) -> float:
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
        
        # Apply time decay (relative to last update if available)
        if pid in self.risk_history and self.risk_history[pid]:
            last_score = self.risk_history[pid][-1]
            time_since_last = current_time - baseline['last_updated']
            if time_since_last > self.decay_interval:
                decayed_score = last_score * (self.decay_factor ** (time_since_last / self.decay_interval))
                final_score = max(final_score, decayed_score)
        
        # Update history and baseline
        # FIXED: deque with maxlen automatically handles size limit, no need to check/pop
        self.risk_history[pid].append(final_score)
        
        self._update_behavioral_baseline(pid, syscalls, process_info)
        
        # Clamp to 0-100 range
        return min(100.0, max(0.0, final_score))
    
    def _calculate_behavioral_score(self, pid: int, syscalls: List[str], 
                                    process_info: Optional[Dict[str, Any]] = None) -> float:
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
        # Total baseline counts
        baseline_total = sum(baseline['syscall_frequencies'].values()) or 1
        for syscall, count in current_frequencies.items():
            current_freq = count / total_syscalls
            baseline_freq = baseline['syscall_frequencies'].get(syscall, 0) / baseline_total
            
            # Calculate deviation
            deviation = abs(current_freq - baseline_freq)
            deviation_score += deviation * 10  # Scale to 0-100
        
        # Resource usage deviation
        if process_info:
            cpu_deviation = abs(process_info.get('cpu_percent', 0) - baseline['resource_usage'].get('cpu_percent', 0))
            memory_deviation = abs(process_info.get('memory_percent', 0) - baseline['resource_usage'].get('memory_percent', 0))
            
            deviation_score += (cpu_deviation + memory_deviation) * 0.1
        
        return min(100.0, deviation_score)
    
    def _calculate_container_score(self, pid: int, syscalls: List[str], 
                                   container_id: Optional[str] = None) -> float:
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
    
    def _update_behavioral_baseline(self, pid: int, syscalls: List[str], 
                                    process_info: Optional[Dict[str, Any]] = None) -> None:
        """Update behavioral baseline for a process"""
        if pid not in self.process_baselines:
            return
        
        baseline = self.process_baselines[pid]
        
        # Update syscall frequencies (cap size to avoid unbounded growth)
        for syscall in syscalls:
            baseline['syscall_frequencies'][syscall] += 1
        # Cap to top-N most frequent entries
        max_keys = int(self.config.get('baseline_max_keys', 500))
        if len(baseline['syscall_frequencies']) > max_keys:
            # Keep top-N by count
            top_items = sorted(baseline['syscall_frequencies'].items(), key=lambda x: x[1], reverse=True)[:max_keys]
            baseline['syscall_frequencies'].clear()
            baseline['syscall_frequencies'].update(top_items)
        
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
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.console = Console()
        self.running = False
        self.debug_mode = self.config.get('debug', False)
        
        # Setup logger for this instance
        self.logger = logging.getLogger(f'{logger.name}.agent')
        if self.debug_mode:
            self.logger.setLevel(logging.DEBUG)
        
        # Enhanced components
        self.enhanced_ebpf_monitor = None
        self.enhanced_anomaly_detector = None
        self.incremental_trainer = None  # NEW: Automatic retraining
        self.container_security_monitor = None
        self.enhanced_risk_scorer = None
        self.action_handler = None
        self.response_handler = None
        self.threat_intelligence = None
        
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
        
        # Thread lock for statistics (FIXED: Make stats updates thread-safe)
        self.stats_lock = threading.Lock()
        
        # Rate limiting for debug output (PID -> last print time)
        self._debug_rate_limit = {}  # {pid: last_print_time}
        self._debug_rate_limit_lock = threading.Lock()
        
        # Risk score persistence (optional - load from file if exists)
        # SECURITY FIX: Use secure user cache directory instead of /tmp
        default_cache_dir = os.path.join(os.path.expanduser('~'), '.cache', 'security_agent')
        os.makedirs(default_cache_dir, mode=0o700, exist_ok=True)  # Secure permissions (user-only)
        default_risk_file = os.path.join(default_cache_dir, 'risk_scores.json')
        self.risk_score_file = self.config.get('risk_score_file', default_risk_file)
        self._saved_risk_scores = {}  # Initialize for deferred restoration
        self._load_risk_scores()
        
        # Initialize components
        self._initialize_components()

        # Initialize CPU cache structures early to avoid races
        self._cpu_cache = {}
        self._cpu_cache_time = {}
        self._cpu_cache_lock = threading.Lock()
        
        # Process name cache to reduce overhead (PID -> name, with TTL)
        self._process_name_cache = {}
        self._process_name_cache_time = {}
        self._process_name_cache_lock = threading.Lock()
        # Load from config, fallback to constant
        system_config = self.config.get('system', {})
        self._process_name_cache_ttl = system_config.get('process_name_cache_ttl', PROCESS_NAME_CACHE_TTL)
        
        # ML inference rate limiting (PID -> (last_inference_time, syscall_count))
        self._ml_inference_tracking = {}  # pid -> (last_time, count)
        self._ml_inference_lock = threading.Lock()
        # Load from config, fallback to constants
        perf_config = self.config.get('performance', {})
        self._ml_inference_interval = perf_config.get('ml_inference_interval', ML_INFERENCE_INTERVAL)
        self._ml_inference_time_interval = perf_config.get('ml_inference_time_interval', ML_INFERENCE_TIME_INTERVAL)
        
        # Risk score cache (PID -> (score, timestamp)) to avoid recalculation
        self._risk_score_cache = {}
        self._risk_score_cache_lock = threading.Lock()
        self._risk_score_cache_ttl = perf_config.get('risk_score_cache_ttl', RISK_SCORE_CACHE_TTL)
        
        # Incremental retraining: collect samples during monitoring for automatic retraining
        self._enable_incremental_training = self.config.get('enable_incremental_training', True)
        self._training_samples = deque(maxlen=self.config.get('max_training_samples', 10000))  # Store up to 10K samples
        self._training_samples_lock = threading.Lock()
        self._last_retrain_time = 0.0
        self._retrain_interval = self.config.get('retrain_interval', 3600)  # Retrain every hour by default
        self._min_samples_for_retrain = self.config.get('min_samples_for_retrain', 100)  # Need 100 new samples
        self._retrain_thread = None
    
    def _initialize_components(self):
        """Initialize all enhanced components"""
        # Initialize enhanced risk scorer
        self.enhanced_risk_scorer = EnhancedRiskScorer(self.config)
        
        # Initialize collectors based on config
        collector_choice = str(self.config.get('collector', 'ebpf')).lower()

        if collector_choice == 'ebpf' and ENHANCED_EBPF_AVAILABLE:
            try:
                self.enhanced_ebpf_monitor = StatefulEBPFMonitor(self.config)
                self.console.print("✅ Enhanced eBPF monitor initialized", style="green")
            except Exception as e:
                self.console.print(f"❌ Enhanced eBPF monitor failed: {e}", style="red")
                # Fallback to auditd if available
                if AUDITD_AVAILABLE:
                    try:
                        self.enhanced_ebpf_monitor = None
                        self.auditd_collector = AuditdCollector(self.config)
                        self.console.print("⚠️ Falling back to auditd collector", style="yellow")
                    except Exception as ex:
                        self.console.print(f"❌ Auditd fallback failed: {ex}", style="red")
                else:
                    self.auditd_collector = None
        elif collector_choice == 'auditd' and AUDITD_AVAILABLE:
            try:
                self.auditd_collector = AuditdCollector(self.config)
                self.console.print("✅ Auditd collector initialized", style="green")
            except Exception as e:
                self.console.print(f"❌ Auditd collector failed: {e}", style="red")
        else:
            # No collector available
            self.enhanced_ebpf_monitor = None
            self.auditd_collector = None
        
        # Initialize enhanced anomaly detector
        if ENHANCED_ANOMALY_AVAILABLE:
            try:
                self.enhanced_anomaly_detector = EnhancedAnomalyDetector(self.config)
                self.console.print("✅ Enhanced anomaly detector initialized", style="green")
                
                # Initialize incremental trainer if enabled
                if self.config.get('enable_incremental_training', False):
                    try:
                        from core.incremental_trainer import IncrementalTrainer
                        self.incremental_trainer = IncrementalTrainer(
                            self.enhanced_anomaly_detector, 
                            self.config
                        )
                        self.incremental_trainer.start()
                        self.console.print("✅ Incremental trainer started", style="green")
                    except Exception as e:
                        self.console.print(f"⚠️  Incremental trainer initialization failed: {e}", style="yellow")
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
        
        # Initialize threat intelligence
        if THREAT_INTEL_AVAILABLE:
            try:
                self.threat_intelligence = ThreatIntelligence()
                self.console.print("✅ Threat intelligence initialized", style="green")
            except Exception as e:
                self.console.print(f"❌ Threat intelligence failed: {e}", style="red")
                self.threat_intelligence = None
        
        # Initialize response handler
        if RESPONSE_HANDLER_AVAILABLE:
            try:
                self.response_handler = ResponseHandler(self.config)
                self.console.print("✅ Response handler initialized", style="green")
            except Exception as e:
                self.console.print(f"❌ Response handler failed: {e}", style="red")
                self.response_handler = None
        
        # Initialize action handler (legacy - disabled)
        if ACTION_HANDLER_AVAILABLE:
            try:
                self.action_handler = ActionHandler(self.config)
                self.console.print("✅ Action handler initialized", style="green")
            except Exception as e:
                self.console.print(f"❌ Action handler failed: {e}", style="red")
    
    def start_monitoring(self):
        """Start enhanced security monitoring"""
        self.console.print("🚀 Starting Enhanced Linux Security Agent...", style="bold blue")
        
        # Start selected collector with callback
        if getattr(self, 'enhanced_ebpf_monitor', None):
            if self.enhanced_ebpf_monitor.start_monitoring(event_callback=self._handle_syscall_event):
                self.console.print("✅ Enhanced eBPF monitoring started", style="green")
                self.collector_started = True
            else:
                self.console.print("❌ Failed to start enhanced eBPF monitoring", style="red")
                self.collector_started = False
        elif getattr(self, 'auditd_collector', None):
            if self.auditd_collector.start_monitoring(event_callback=self._handle_syscall_event):
                self.console.print("✅ Auditd monitoring started", style="green")
                self.collector_started = True
            else:
                self.console.print("❌ Failed to start auditd monitoring", style="red")
                self.collector_started = False
        
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
        
        # Start incremental retraining thread if enabled
        if self._enable_incremental_training and self.enhanced_anomaly_detector:
            self._last_retrain_time = time.time()  # Initialize retrain timer
            self._retrain_thread = threading.Thread(target=self._incremental_retrain_loop, daemon=True)
            self._retrain_thread.start()
            retrain_hours = self._retrain_interval / 3600
            self.console.print(f"✅ Incremental retraining enabled (auto-retrains every {retrain_hours:.1f}h, needs {self._min_samples_for_retrain}+ samples)", style="green")
        
        self.running = True
        self.console.print("🎉 Enhanced security monitoring started successfully!", style="bold green")

        # Warn if no collector is active
        if not getattr(self, 'collector_started', False):
            self.console.print("❌ No event collector active. Exiting.", style="bold red")
            self.running = False
    
    def _train_anomaly_models(self):
        """Train anomaly detection models with REAL behavior data"""
        self.console.print("🧠 Training anomaly detection models with real data...", style="yellow")
        
        # CRITICAL: Ensure monitoring is started BEFORE collecting data
        if not getattr(self, 'collector_started', False):
            self.console.print("⚠️ Monitoring not started. Starting monitoring first...", style="yellow")
            self.start_monitoring()
            # Give monitoring more time to initialize and start capturing events
            self.console.print("⏳ Waiting for monitoring to initialize...", style="dim")
            time.sleep(3)  # Increased wait time
            
            # Check if we're actually getting events
            time.sleep(1)  # Give eBPF a moment to start capturing
            with self.processes_lock:
                initial_processes = len(self.processes)
                initial_syscalls = sum(len(p.get('syscalls', [])) for p in self.processes.values())
            
            # Also check eBPF monitor's event count
            ebpf_events = 0
            ebpf_callback_set = False
            if self.enhanced_ebpf_monitor:
                ebpf_events = len(self.enhanced_ebpf_monitor.events)
                ebpf_callback_set = self.enhanced_ebpf_monitor.event_callback is not None
            
            # BRUTAL VERIFICATION: Check everything
            self.console.print(f"🔍 VERIFICATION:", style="yellow")
            self.console.print(f"   eBPF monitor exists: {self.enhanced_ebpf_monitor is not None}", style="dim")
            self.console.print(f"   eBPF callback set: {ebpf_callback_set}", style="dim")
            self.console.print(f"   eBPF events captured: {ebpf_events}", style="dim")
            self.console.print(f"   Processes in dict: {initial_processes}", style="dim")
            self.console.print(f"   Total syscalls in processes: {initial_syscalls}", style="dim")
            self.console.print(f"   Monitoring started: {getattr(self, 'collector_started', False)}", style="dim")
            
            if initial_processes == 0 and initial_syscalls == 0 and ebpf_events == 0:
                self.console.print("⚠️ No events captured yet. Testing eBPF by generating test activity...", style="yellow")
                # Generate some test syscalls to verify eBPF is working
                import subprocess
                try:
                    # Run multiple commands to generate syscalls
                    subprocess.run(['ls', '/'], capture_output=True, timeout=1)
                    subprocess.run(['ps', 'aux'], capture_output=True, timeout=1)
                    subprocess.run(['cat', '/etc/passwd'], capture_output=True, timeout=1)
                    time.sleep(2)  # Give eBPF more time to capture events
                    
                    # Check again
                    with self.processes_lock:
                        test_processes = len(self.processes)
                        test_syscalls = sum(len(p.get('syscalls', [])) for p in self.processes.values())
                    
                    # Check eBPF events
                    if self.enhanced_ebpf_monitor:
                        test_ebpf_events = len(self.enhanced_ebpf_monitor.events)
                        self.console.print(f"📊 eBPF events captured: {test_ebpf_events}", style="dim")
                    
                    if test_processes > 0 or test_syscalls > 0:
                        self.console.print(f"✅ eBPF is working! Captured {test_processes} processes, {test_syscalls} syscalls", style="green")
                    else:
                        self.console.print("⚠️ Still no events. Debugging...", style="yellow")
                        # Check if callback is set
                        if self.enhanced_ebpf_monitor and not self.enhanced_ebpf_monitor.event_callback:
                            self.console.print("❌ ERROR: Event callback not set!", style="red")
                            self.console.print("❌ This is a CRITICAL BUG - callback should be set!", style="bold red")
                        elif ebpf_events > 0:
                            self.console.print(f"⚠️ eBPF captured {test_ebpf_events} events but callback didn't populate processes!", style="yellow")
                            self.console.print("❌ This suggests callback is failing or processes aren't being created", style="red")
                        else:
                            self.console.print("⚠️ eBPF not capturing ANY events - tracepoint may not be working", style="yellow")
                            self.console.print("💡 Try running commands manually in another terminal", style="dim")
                            # Force some test syscalls
                            self.console.print("💡 Generating test syscalls to verify eBPF...", style="dim")
                            import subprocess
                            for _ in range(10):
                                subprocess.run(['ls', '/'], capture_output=True, timeout=0.5)
                                subprocess.run(['ps', 'aux'], capture_output=True, timeout=0.5)
                            time.sleep(2)
                            # Check again
                            if self.enhanced_ebpf_monitor:
                                final_events = len(self.enhanced_ebpf_monitor.events)
                                self.console.print(f"📊 After test: eBPF events = {final_events}", style="dim")
                                if final_events == 0:
                                    self.console.print("❌ CRITICAL: eBPF tracepoint is NOT working!", style="bold red")
                                    self.console.print("   The tracepoint may not be attached or kernel doesn't support it", style="dim")
                except Exception as e:
                    self.console.print(f"⚠️ Could not test eBPF: {e}", style="yellow")
            elif ebpf_events > 0 and initial_syscalls == 0:
                self.console.print(f"⚠️ eBPF captured {ebpf_events} events but processes dict is empty", style="yellow")
                self.console.print("💡 This suggests callback may not be working properly", style="dim")
        
        # Verify monitoring is actually running
        if not getattr(self, 'collector_started', False):
            self.console.print("❌ Monitoring failed to start. Cannot collect real data.", style="red")
            self.console.print("⚠️ Will use baseline patterns only", style="yellow")
            training_data = []
        else:
            # Collect ACTUAL syscall data from running processes
            training_data = []
            collection_time = 60  # Collect for 60 seconds (increased from 30)
            start_time = time.time()
            
            self.console.print(f"📊 Collecting real syscall data for {collection_time} seconds...", style="yellow")
            self.console.print("💡 Tip: Run commands (ls, ps, cat, etc.) in another terminal to generate syscalls!", style="dim")
            
            # Track which processes we've already sampled to avoid duplicates
            sampled_pids = set()
            
            # Collect real data - OPTIMIZED: batch operations, reduce lock time
            iteration = 0
            last_progress_time = start_time
            candidates = []  # Collect candidates first, then batch psutil calls
            total_processes_seen = 0
            
            try:
                last_iteration_log = 0
                while (time.time() - start_time) < collection_time:
                    iteration += 1
                    
                    # Log every 20 iterations to show progress (every ~10 seconds)
                    if iteration - last_iteration_log >= 20:
                        elapsed = time.time() - start_time
                        self.console.print(f"⏳ Iteration {iteration}, elapsed: {int(elapsed)}s...", style="dim")
                        last_iteration_log = iteration
                    
                    # Quick pass to collect candidate PIDs (minimize lock time)
                    # Use context manager but with timeout to avoid blocking on interrupt
                    processes_snapshot = {}
                    try:
                        # Try to acquire lock with timeout - allows interrupt to work
                        if self.processes_lock.acquire(timeout=0.1):
                            try:
                                processes_snapshot = {pid: dict(proc) for pid, proc in self.processes.items()}
                                total_processes_seen = len(processes_snapshot)
                                
                                # DEBUG: Log if we're seeing processes but no syscalls
                                if iteration % 20 == 0 and total_processes_seen > 0:
                                    total_sys = sum(len(p.get('syscalls', [])) for p in processes_snapshot.values())
                                    if total_sys == 0:
                                        self.console.print(f"⚠️ Found {total_processes_seen} processes but 0 syscalls - callback may not be working", style="yellow")
                            finally:
                                self.processes_lock.release()
                        else:
                            # Lock timeout - skip this iteration
                            time.sleep(0.1)
                            continue
                    except KeyboardInterrupt:
                        # Release lock if held
                        try:
                            if self.processes_lock.locked():
                                self.processes_lock.release()
                        except Exception:
                            # Lock release failed - log but continue with raise
                            self.logger.debug("Error releasing lock during exception handling")
                        raise
                    
                    # Process snapshot outside lock
                    for pid, proc in processes_snapshot.items():
                        syscalls_list = proc.get('syscalls', [])
                        if len(syscalls_list) >= 5:
                            pid_key = f"{pid}_{iteration // 10}"
                            if pid_key not in sampled_pids:
                                syscalls = list(syscalls_list)[-50:]  # Take last 50
                                candidates.append((pid, syscalls, pid_key))
                                sampled_pids.add(pid_key)
                                
                                if len(candidates) >= 20 or len(training_data) + len(candidates) >= 500:
                                    break
                    
                    # Batch psutil calls (outside lock, faster)
                    for pid, syscalls, pid_key in candidates:
                        if len(training_data) >= 500:
                            break
                        try:
                            p = psutil.Process(pid)
                            # Batch all psutil calls at once
                            with p.oneshot():  # Context manager optimizes multiple calls
                                cpu_val = p.cpu_percent(interval=None) or 0
                                mem_val = p.memory_percent()
                                threads = p.num_threads()
                            
                            process_info = {
                                'cpu_percent': cpu_val,
                                'memory_percent': mem_val,
                                'num_threads': threads,
                                'pid': pid
                            }
                            training_data.append((syscalls, process_info))
                        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                            sampled_pids.discard(pid_key)  # Allow retry
                            continue
                    
                    candidates.clear()  # Reset for next iteration
                    
                    # Check if we have enough data
                    if len(training_data) >= 500:
                        self.console.print(f"✅ Collected enough data ({len(training_data)} samples)!", style="green")
                        break
                    
                    # Show progress every 10 seconds (optimized timing)
                    elapsed = time.time() - start_time
                    if elapsed - (last_progress_time - start_time) >= 10.0:
                        # Show more informative progress
                        total_syscalls = 0
                        try:
                            if self.processes_lock.acquire(timeout=0.1):
                                try:
                                    total_syscalls = sum(len(p.get('syscalls', [])) for p in self.processes.values())
                                finally:
                                    self.processes_lock.release()
                        except Exception:
                            # Lock release failed - log but continue
                            self.logger.debug("Error releasing lock during cleanup")
                        
                        self.console.print(
                            f"📊 Real data: {len(training_data)} samples | "
                            f"Processes: {total_processes_seen} | "
                            f"Syscalls captured: {total_syscalls} | "
                            f"({int(elapsed)}/{collection_time}s) | "
                            f"Press Ctrl+C to stop early", 
                            style="dim"
                        )
                        last_progress_time = time.time()
                    
                    # Use interruptible sleep - check for interrupt frequently
                    try:
                        # Sleep in small chunks to allow interrupt and show progress
                        for i in range(5):  # 5 * 0.1 = 0.5 seconds total
                            time.sleep(0.1)
                            # Show a dot every second to indicate progress
                            if iteration % 10 == 0 and i == 0:
                                elapsed = time.time() - start_time
                                if int(elapsed) % 5 == 0:  # Every 5 seconds
                                    self.console.print(".", end="", style="dim")
                    except KeyboardInterrupt:
                        self.console.print("\n⚠️ Training interrupted by user", style="yellow")
                        raise
            except KeyboardInterrupt:
                self.console.print("\n⚠️ Training interrupted. Saving collected data...", style="yellow")
                # Don't re-raise - continue with what we have
            
            # Show final collection stats
            elapsed_total = time.time() - start_time
            self.console.print(f"\n📊 Collection complete: {len(training_data)} samples collected in {int(elapsed_total)}s", style="dim")
        
        # If still not enough data, supplement with baseline patterns
        real_samples = len(training_data)
        if real_samples < 50:  # Lower threshold from 100 to 50
            self.console.print(f"⚠️ Only collected {real_samples} real samples (need 50+), adding baseline patterns", style="yellow")
            self.console.print("💡 For better results, generate system activity during training!", style="dim")
            if self.config.get('debug', False):
                self.console.print(f"🐛 DEBUG: Only collected {real_samples} samples, need 50+", style="dim")
            baseline_data = self._get_baseline_patterns()
            training_data.extend(baseline_data)
            self.console.print(f"✅ Added {len(baseline_data)} baseline samples (total: {len(training_data)} samples)", style="green")
        elif real_samples < 100:
            self.console.print(f"✅ Collected {real_samples} real training samples (supplementing with baseline)", style="green")
            # Add some baseline data but keep real data primary
            baseline_data = self._get_baseline_patterns()[:100]  # Add 100 baseline samples
            training_data.extend(baseline_data)
            self.console.print(f"✅ Total: {len(training_data)} samples ({real_samples} real + {len(baseline_data)} baseline)", style="green")
        else:
            self.console.print(f"✅ Collected {real_samples} real training samples", style="green")
        
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
            
            # Use append mode if requested via config
            append = bool(self.config.get('append_training', False))
            self.console.print("🧠 Starting model training...", style="yellow")
            self.enhanced_anomaly_detector.train_models(training_data, append=append)
            self.console.print("✅ Anomaly detection models trained successfully!", style="green")
            self.console.print(f"✅ Models saved to: ~/.cache/security_agent/", style="green")
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
    
    def _collect_training_sample(self, pid: int, process_snapshot: Dict[str, Any], 
                                process_info: Optional[Dict[str, Any]]) -> None:
        """Collect a training sample from normal process behavior for incremental retraining"""
        try:
            # FIXED: Use fresh data from process dict instead of stale snapshot
            # Get current syscalls directly from process dict to avoid stale snapshot
            with self.processes_lock:
                if pid not in self.processes:
                    return  # Process no longer exists
                current_process = self.processes[pid]
                # Create fresh snapshot of syscalls
                syscalls = list(current_process.get('syscalls', []))
                # Use current process info from snapshot or fetch fresh
                if not process_info:
                    process_info = {
                        'cpu_percent': current_process.get('cpu_percent', 0.0),
                        'memory_percent': 0.0,  # Will fetch if needed
                        'num_threads': 1,
                        'pid': pid
                    }
            
            if len(syscalls) < 10:  # Need at least 10 syscalls
                return
            
            # Get current process info if not provided or incomplete
            if not process_info or process_info.get('memory_percent', 0) == 0:
                try:
                    p = psutil.Process(pid)
                    with p.oneshot():  # Optimized batch call
                        fresh_info = {
                            'cpu_percent': p.cpu_percent(interval=None) or 0,
                            'memory_percent': p.memory_percent(),
                            'num_threads': p.num_threads(),
                            'pid': pid
                        }
                        if process_info:
                            process_info.update(fresh_info)
                        else:
                            process_info = fresh_info
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return
            
            # Store sample for incremental training (thread-safe)
            with self._training_samples_lock:
                # Take last 50 syscalls for training (consistent with manual training)
                training_syscalls = syscalls[-50:] if len(syscalls) > 50 else syscalls
                self._training_samples.append((training_syscalls, process_info))
            
            if self.debug_mode:
                self.logger.debug(f"Collected training sample from PID {pid} ({len(training_syscalls)} syscalls, {len(self._training_samples)} total)")
        except Exception as e:
            if self.debug_mode:
                self.logger.debug(f"Error collecting training sample: {e}")
    
    def _incremental_retrain_loop(self) -> None:
        """Background thread for automatic incremental retraining using accumulated samples"""
        self.logger.info(f"Incremental retraining thread started (interval: {self._retrain_interval/3600:.1f}h, min_samples: {self._min_samples_for_retrain})")
        
        while self.running:
            try:
                current_time = time.time()
                
                # Check if it's time to retrain
                time_since_retrain = current_time - self._last_retrain_time
                should_retrain = (
                    time_since_retrain >= self._retrain_interval and
                    self.enhanced_anomaly_detector is not None and
                    self.enhanced_anomaly_detector.is_fitted  # Only retrain if models exist
                )
                
                if should_retrain:
                    # Collect samples for retraining (thread-safe)
                    samples = None
                    sample_count = 0
                    # Capture sample_count inside lock to avoid stale data
                    with self._training_samples_lock:
                        sample_count = len(self._training_samples)
                        if sample_count >= self._min_samples_for_retrain:
                            samples = list(self._training_samples)  # Copy list
                            self._training_samples.clear()  # Clear after collecting
                    
                    if samples:
                        self.logger.info(f"🔄 Automatic incremental retraining: {len(samples)} new samples + previous training data")
                        try:
                            # Retrain with append mode (automatically combines with old feature store)
                            self.enhanced_anomaly_detector.train_models(samples, append=True)
                            self._last_retrain_time = current_time
                            self.logger.info(f"✅ Incremental retraining completed successfully with {len(samples)} new samples")
                        except Exception as e:
                            self.logger.error(f"Error during incremental retraining: {e}", exc_info=True)
                            # Put samples back if retraining failed (so they can be retried)
                            with self._training_samples_lock:
                                # Only add back if we haven't exceeded max
                                if len(self._training_samples) + len(samples) <= self._training_samples.maxlen:
                                    self._training_samples.extend(samples)
                    else:
                        # Not enough samples yet, but reset timer to check again soon
                        if self.debug_mode:
                            # Re-read current count for accurate debug info (may be stale, but better than using old sample_count)
                            current_count = len(self._training_samples) if hasattr(self, '_training_samples') else 0
                            self.logger.debug(f"Not enough samples for retraining ({current_count}/{self._min_samples_for_retrain}), waiting...")
                
                # Sleep for 60 seconds before checking again (check every minute)
                for _ in range(60):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Error in incremental retrain loop: {e}", exc_info=True)
                # Sleep longer on error
                for _ in range(60):
                    if not self.running:
                        break
                    time.sleep(1)
    
    def _cleanup_old_processes(self):
        """Remove stale processes to prevent memory leaks - also clean CPU cache and process name cache"""
        current_time = time.time()
        stale_pids = []
        
        with self.processes_lock:
            for pid, proc in list(self.processes.items()):
                # Remove if not updated in configured timeout
                last_update = proc.get('last_update', 0)
                # Load timeout from config, fallback to constant
                system_config = self.config.get('system', {})
                stale_timeout = system_config.get('stale_process_timeout', STALE_PROCESS_TIMEOUT)
                if current_time - last_update > stale_timeout:
                    stale_pids.append(pid)
            
            # Remove stale processes
            for pid in stale_pids:
                if pid in self.processes:
                    del self.processes[pid]
        
        # Clean up CPU cache for stale processes
        # FIXED: Ensure lock exists before use to avoid creating new locks each time
        if stale_pids and hasattr(self, '_cpu_cache'):
            if not hasattr(self, '_cpu_cache_lock'):
                self._cpu_cache_lock = threading.Lock()
            with self._cpu_cache_lock:
                for pid in stale_pids:
                    cache_key = f"cpu_cache_{pid}"
                    cache_time_key = f"cpu_time_{pid}"
                    self._cpu_cache.pop(cache_key, None)
                    self._cpu_cache_time.pop(cache_time_key, None)
        
        # Clean up process name cache for stale processes
        # FIXED: Ensure lock exists before use to avoid creating new locks each time
        if stale_pids and hasattr(self, '_process_name_cache'):
            if not hasattr(self, '_process_name_cache_lock'):
                self._process_name_cache_lock = threading.Lock()
            with self._process_name_cache_lock:
                for pid in stale_pids:
                    self._process_name_cache.pop(pid, None)
                    self._process_name_cache_time.pop(pid, None)
        
        # Clean up ML inference tracking for stale processes
        # FIXED: Ensure lock exists before use
        if stale_pids and hasattr(self, '_ml_inference_tracking'):
            if not hasattr(self, '_ml_inference_lock'):
                self._ml_inference_lock = threading.Lock()
            with self._ml_inference_lock:
                for pid in stale_pids:
                    self._ml_inference_tracking.pop(pid, None)
        
        # Clean up risk score cache for stale processes
        # FIXED: Ensure lock exists before use
        if stale_pids and hasattr(self, '_risk_score_cache'):
            if not hasattr(self, '_risk_score_cache_lock'):
                self._risk_score_cache_lock = threading.Lock()
            with self._risk_score_cache_lock:
                for pid in stale_pids:
                    self._risk_score_cache.pop(pid, None)
        
        # Also clean up expired cache entries (older than TTL)
        # FIXED: Ensure lock exists before use
        if hasattr(self, '_process_name_cache'):
            if not hasattr(self, '_process_name_cache_lock'):
                self._process_name_cache_lock = threading.Lock()
            with self._process_name_cache_lock:
                expired_keys = [
                    pid for pid, cache_time in self._process_name_cache_time.items()
                    if current_time - cache_time > self._process_name_cache_ttl
                ]
                for pid in expired_keys:
                    self._process_name_cache.pop(pid, None)
                    self._process_name_cache_time.pop(pid, None)
        
        if stale_pids:
            self.console.print(f"🧹 Cleaned up {len(stale_pids)} stale processes", style="dim")
    
    def _cleanup_loop(self):
        """Periodic cleanup loop to prevent memory leaks"""
        while self.running:
            try:
                self._cleanup_old_processes()
                # Check running flag VERY frequently (every 0.1s for fast exit)
                for _ in range(600):  # 600 x 0.1 = 60 seconds total
                    if not self.running:
                        return
                    time.sleep(0.1)  # Check every 100ms instead of 1s
            except Exception:
                # Exit on any exception if we're shutting down
                if not self.running:
                    return
                # Check again before sleeping
                if not self.running:
                    return
                time.sleep(0.1)  # Check more frequently
    
    def stop_monitoring(self):
        """Stop enhanced security monitoring - NON-BLOCKING"""
        if not self.running:
            return  # Already stopped
        
        self.logger.info("Stopping Enhanced Linux Security Agent...")
        
        # Set running=False FIRST before any other operations
        self.running = False
        
        # Stop incremental trainer (if running)
        if self.incremental_trainer:
            try:
                self.incremental_trainer.stop()
            except Exception as e:
                self.logger.debug(f"Error stopping incremental trainer during shutdown: {e}")
                pass
        
        # Stop enhanced eBPF monitoring immediately (non-blocking)
        if self.enhanced_ebpf_monitor:
            try:
                self.enhanced_ebpf_monitor.running = False  # Force stop first
                self.enhanced_ebpf_monitor.stop_monitoring()
            except (AttributeError, RuntimeError, OSError) as e:
                # Ignore errors during shutdown - component may already be stopped
                self.logger.debug(f"Error stopping eBPF monitor during shutdown: {e}")
                pass
        
        # Stop container security monitoring (non-blocking - threads are daemon or have timeout)
        if self.container_security_monitor:
            try:
                self.container_security_monitor.running = False
                # Don't wait for threads - they're daemon or have timeout
            except (AttributeError, RuntimeError) as e:
                # Ignore errors during shutdown - component may already be stopped
                self.logger.debug(f"Error stopping container monitor during shutdown: {e}")
                pass
        
        # Save risk scores before shutdown (fast, non-blocking)
        try:
            self._save_risk_scores()
        except (OSError, PermissionError, json.JSONEncodeError) as e:
            # Ignore errors during shutdown - not critical
            self.logger.debug(f"Could not save risk scores during shutdown: {e}")
            pass
        
        self.logger.info("Enhanced security monitoring stopped")
    
    def _load_risk_scores(self):
        """Load risk scores from previous run if available - with validation"""
        try:
            if os.path.exists(self.risk_score_file):
                # Check file size to avoid loading corrupted huge files
                if os.path.getsize(self.risk_score_file) > 10 * 1024 * 1024:  # 10MB limit
                    return  # File too large, likely corrupted
                
                with open(self.risk_score_file, 'r') as f:
                    saved_data = json.load(f)
                    
                # Validate JSON structure
                if not isinstance(saved_data, dict):
                    return  # Invalid structure
                
                # Store for later restoration (processes dict may be empty at init)
                # We'll restore after processes are populated during monitoring
                self._saved_risk_scores = saved_data
        except (json.JSONDecodeError, OSError, ValueError):
            # File corrupted or invalid - will start fresh
            self._saved_risk_scores = {}
        except Exception:
            pass  # Ignore other errors - start fresh if file doesn't exist
    
    def _save_risk_scores(self):
        """Save current risk scores to file for next run - ATOMIC WRITE with secure permissions"""
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
                # Ensure directory exists with secure permissions
                score_dir = os.path.dirname(self.risk_score_file)
                if score_dir:
                    os.makedirs(score_dir, mode=0o700, exist_ok=True)
                
                # Atomic write: write to temp file first, then rename
                temp_file = self.risk_score_file + '.tmp'
                try:
                    with open(temp_file, 'w') as f:
                        json.dump(saved_data, f, indent=2)
                        f.flush()
                        os.fsync(f.fileno())  # Force write to disk
                    # Set secure permissions (user-only read/write)
                    os.chmod(temp_file, 0o600)
                    # Atomic rename (rename is atomic on POSIX systems)
                    os.rename(temp_file, self.risk_score_file)
                    # Ensure final file has secure permissions
                    os.chmod(self.risk_score_file, 0o600)
                except (OSError, PermissionError) as rename_error:
                    # Clean up temp file if rename fails
                    try:
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                    except (OSError, PermissionError) as cleanup_error:
                        # Ignore cleanup errors
                        self.logger.debug(f"Could not clean up temp file: {cleanup_error}")
                        pass
        except (OSError, PermissionError, json.JSONEncodeError, ValueError) as e:
            # Ignore errors - not critical, but log in debug mode
            if self.debug_mode:
                self.logger.debug(f"Could not save risk scores: {e}")
    
    def _handle_syscall_event(self, pid: int, syscall: str, event_info: Optional[Dict[str, Any]] = None) -> None:
        """Handle syscall event from eBPF monitor"""
        # Input validation
        if not isinstance(pid, int) or pid <= 0:
            self.logger.warning(f"Invalid PID in syscall event: {pid}")
            return
        
        if not isinstance(syscall, str) or not syscall.strip():
            self.logger.warning(f"Invalid syscall in event: {syscall}")
            return
        
        # Sanitize inputs
        syscall = syscall.strip()[:SYSCALL_NAME_MAX_LENGTH]
        
        # Get process info from psutil (non-blocking)
        process_info = None
        try:
            proc = psutil.Process(pid)
            # Cache CPU calculation - call it once per second per process
            cache_key = f"cpu_cache_{pid}"
            cache_time_key = f"cpu_time_{pid}"
            
            if not hasattr(self, '_cpu_cache'):
                self._cpu_cache = {}
                self._cpu_cache_time = {}
                self._cpu_cache_lock = threading.Lock()  # Lock for cache access
            
            current_time = time.time()
            
            # Thread-safe cache access
            with getattr(self, '_cpu_cache_lock', threading.Lock()):
                last_cache_time = self._cpu_cache_time.get(cache_time_key, 0)
                
                # Update CPU every 1 second per process (to avoid overhead)
                # cpu_percent(interval=None) is non-blocking but requires previous call
                # We use cached value and only update occasionally
                if current_time - last_cache_time >= 1.0:
                    try:
                        # Non-blocking call - returns 0.0 if not previously initialized
                        # Actual value accumulates over time, so we use cached value
                        cpu_val = proc.cpu_percent(interval=None)
                        if cpu_val == 0.0:
                            # First call or no CPU usage - use cached if available
                            cpu_val = self._cpu_cache.get(cache_key, 0.0)
                        else:
                            # Store for next time
                            self._cpu_cache[cache_key] = cpu_val
                            self._cpu_cache_time[cache_time_key] = current_time
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
                        # Use cached value if process check fails
                        cpu_val = self._cpu_cache.get(cache_key, 0.0)
                else:
                    # Use cached value (updated within last second)
                    cpu_val = self._cpu_cache.get(cache_key, 0.0)
            
            process_info = {
                'cpu_percent': cpu_val,
                'memory_percent': proc.memory_percent(),
                'num_threads': proc.num_threads()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError, AttributeError):
            # Ignore errors - not critical
            process_info = None
        
        self.process_syscall_event(pid, syscall, process_info)
    
    def _get_container_info(self, pid: int) -> Optional[str]:
        """Get container ID for a process (thread-safe)"""
        if not self.container_security_monitor:
            return None
        
        try:
            # FIXED: Always use lock if available to ensure thread safety
            # Check for lock first to avoid TOCTOU (Time-Of-Check-Time-Of-Use) race condition
            if hasattr(self.container_security_monitor, 'containers_lock'):
                # Lock exists - use it for safe access
                with self.container_security_monitor.containers_lock:
                    # Re-check process_containers exists inside lock (TOCTOU protection)
                    if hasattr(self.container_security_monitor, 'process_containers'):
                        return self.container_security_monitor.process_containers.get(pid)
            # Fallback: try without lock (risky, but better than nothing if lock doesn't exist)
            elif hasattr(self.container_security_monitor, 'process_containers'):
                # No lock available - access directly (not ideal, but handles edge case)
                return self.container_security_monitor.process_containers.get(pid)
        except (AttributeError, RuntimeError, KeyError) as e:
            # Log in debug mode for troubleshooting
            if self.debug_mode:
                self.logger.debug(f"Error getting container info for PID {pid}: {e}")
        return None
    
    def _validate_container_policy(self, pid: int, syscall: str) -> bool:
        """Validate syscall against container policy. Returns True if allowed."""
        if not self.container_security_monitor:
            return True
        try:
            if not self.container_security_monitor.validate_syscall(pid, syscall):
                with self.stats_lock:
                    self.stats['policy_violations'] += 1
                return False
        except (AttributeError, Exception) as e:
            # Process may have terminated or info unavailable - not an error
            self.logger.debug(f"Could not validate process {pid}: {e}")
        return True
    
    def _get_process_state(self, pid: int) -> Optional[Any]:
        """Get process state from eBPF monitor"""
        if not self.enhanced_ebpf_monitor:
            return None
        try:
            return self.enhanced_ebpf_monitor.get_process_state(pid)
        except (AttributeError, Exception):
            return None
    
    def _create_new_process_entry(self, pid: int, container_id: Optional[str], 
                                  process_state: Optional[Any], current_time: float) -> bool:
        """Create new process entry. Returns True if successful."""
        try:
            saved_score = 0.0
            if hasattr(self, '_saved_risk_scores') and self._saved_risk_scores:
                saved_data = self._saved_risk_scores.get(str(pid))
                if saved_data and isinstance(saved_data, dict):
                    saved_score = saved_data.get('risk_score', 0.0)
            
            self.processes[pid] = {
                'name': self._get_process_name(pid),
                'risk_score': saved_score,
                'anomaly_score': 0.0,
                'syscall_count': 0,
                'last_update': current_time,
                'last_risk_update': current_time,
                'syscalls': deque(maxlen=1000),
                'container_id': container_id,
                'process_state': process_state
            }
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def _calculate_and_cache_risk_score(self, pid: int, syscalls: List[str], 
                                       process_info: Optional[Dict[str, Any]], 
                                       anomaly_score: float, container_id: Optional[str],
                                       current_time: float) -> float:
        """Calculate risk score with caching"""
        if not self.enhanced_risk_scorer:
            return 0.0
        
        # Check cache
        cached_score = None
        with self._risk_score_cache_lock:
            if pid in self._risk_score_cache:
                cached_score, cache_time = self._risk_score_cache[pid]
                if current_time - cache_time < self._risk_score_cache_ttl:
                    return cached_score
                else:
                    del self._risk_score_cache[pid]
        
        # Calculate new score
        risk_score = self.enhanced_risk_scorer.update_risk_score(
            pid, syscalls, process_info, anomaly_score, container_id
        )
        
        # Add threat intelligence boost if available
        if self.threat_intelligence and process_info:
            try:
                threat_boost = self.threat_intelligence.get_risk_boost(syscalls, process_info)
                risk_score += threat_boost
                risk_score = min(100.0, risk_score)  # Cap at 100
            except Exception as e:
                self.logger.debug(f"Threat intelligence boost failed: {e}")
        
        # Update cache
        with self._risk_score_cache_lock:
            self._risk_score_cache[pid] = (risk_score, current_time)
        
        return risk_score
    
    def _should_run_ml_inference(self, pid: int, syscall_count: int, 
                                current_time: float) -> bool:
        """Determine if ML inference should run based on rate limiting"""
        with self._ml_inference_lock:
            if pid not in self._ml_inference_tracking:
                self._ml_inference_tracking[pid] = (0, 0)
            
            last_ml_time, ml_count = self._ml_inference_tracking[pid]
            time_since_last = current_time - last_ml_time
            syscalls_since_last = syscall_count - ml_count
            
            # Load from config, fallback to constant
            perf_config = self.config.get('performance', {})
            min_syscalls = perf_config.get('min_syscalls_for_ml', MIN_SYSCALLS_FOR_ML)
            if (syscall_count >= min_syscalls and 
                (time_since_last >= self._ml_inference_time_interval or 
                 syscalls_since_last >= self._ml_inference_interval)):
                self._ml_inference_tracking[pid] = (current_time, syscall_count)
                return True
        return False
    
    def _update_anomaly_scores(self, pid: int, anomaly_result: Optional[Any], 
                               process_snapshot: Dict[str, Any]) -> None:
        """Update anomaly scores in process dict (thread-safe)"""
        if anomaly_result is None:
            return
        
        with self.processes_lock:
            if pid not in self.processes:
                return
            
            prev_flag = bool(self.processes[pid].get('is_anomaly', False))
            old_score = self.processes[pid].get('anomaly_score', 0.0)
            
            self.processes[pid]['anomaly_score'] = anomaly_result.anomaly_score
            self.processes[pid]['is_anomaly'] = bool(anomaly_result.is_anomaly)
            
            # Count transitions (thread-safe)
            if anomaly_result.is_anomaly and not prev_flag:
                with self.stats_lock:
                    self.stats['anomalies_detected'] += 1
                
                # Debug logging
                if self.config.get('debug', False):
                    try:
                        with self._debug_rate_limit_lock:
                            current_time = time.time()
                            last_print = self._debug_rate_limit.get(pid, 0)
                            if current_time - last_print >= 10.0:
                                self.logger.debug(f"Anomaly DETECTED: PID={pid} ({process_snapshot.get('name', 'unknown')}) "
                                                  f"score={anomaly_result.anomaly_score:.2f}, "
                                                  f"confidence={anomaly_result.confidence:.2f}, "
                                                  f"explanation={anomaly_result.explanation[:80] if anomaly_result.explanation else 'N/A'}")
                                self._debug_rate_limit[pid] = current_time
                    except AttributeError:
                        pass
    
    def process_syscall_event(self, pid: int, syscall: str, process_info: Optional[Dict[str, Any]] = None) -> None:
        """Process a system call event with enhanced analysis"""
        # Input validation
        if not isinstance(pid, int) or pid <= 0:
            self.logger.warning(f"Invalid PID received: {pid}")
            return
        
        if not isinstance(syscall, str) or not syscall.strip():
            self.logger.warning(f"Invalid syscall name received: {syscall}")
            return
        
        # Sanitize syscall name
        syscall = syscall.strip()[:SYSCALL_NAME_MAX_LENGTH]
        
        try:
            # Get container and process context
            container_id = self._get_container_info(pid)
            if not self._validate_container_policy(pid, syscall):
                return
            
            process_state = self._get_process_state(pid)
            
            # Update process information
            current_time = time.time()
            process_snapshot = None
            risk_score = 0.0
            should_log_high_risk = False
            
            with self.processes_lock:
                if pid not in self.processes:
                    if not self._create_new_process_entry(pid, container_id, process_state, current_time):
                        return
                
                process = self.processes[pid]
                process['syscalls'].append(syscall)  # Deque append is O(1)
                syscall_count = process['syscall_count'] = process['syscall_count'] + 1  # Cache count
                process['last_update'] = current_time
                
                # Update CPU periodically
                if process['syscall_count'] % 10 == 0 and process_info:
                    cpu_val = process_info.get('cpu_percent', 0.0)
                    process['cpu_percent'] = cpu_val if cpu_val is not None else 0.0
                
                # Create snapshot - OPTIMIZED: only copy needed fields
                # CRITICAL: Snapshot syscalls ONCE to avoid race condition with concurrent appends
                syscalls_snapshot = list(process['syscalls'])
                process_snapshot = {
                    'name': process.get('name', '<unknown>'),
                    'risk_score': process.get('risk_score', 0.0),
                    'anomaly_score': process.get('anomaly_score', 0.0),
                    'syscall_count': syscall_count,
                    'syscalls': syscalls_snapshot,  # Use snapshot to avoid race condition
                    'cpu_percent': process.get('cpu_percent'),
                    'container_id': process.get('container_id')
                }
                
                # Calculate risk score using snapshot to ensure consistency
                risk_score = self._calculate_and_cache_risk_score(
                    pid, syscalls_snapshot, process_info,
                    process.get('anomaly_score', 0.0), container_id, current_time
                )
                
                # Smooth with EMA
                old_risk_score = process.get('risk_score', 0.0)
                if old_risk_score > 0:
                    new_risk_score = 0.7 * risk_score + 0.3 * old_risk_score
                else:
                    new_risk_score = risk_score
                
                process['risk_score'] = new_risk_score
                process['last_risk_update'] = current_time
                
                # Collect training samples for incremental retraining (only normal/low-risk behavior)
                if (self._enable_incremental_training and 
                    new_risk_score < 30.0 and  # Only collect normal behavior
                    syscall_count >= 20 and  # Enough syscalls to be useful
                    syscall_count % 50 == 0):  # Sample every 50 syscalls to avoid overhead
                    self._collect_training_sample(pid, process_snapshot, process_info)
                
                # Check threshold crossing (thread-safe stats update)
                risk_threshold = self.config.get('risk_threshold', 50.0)
                if new_risk_score >= risk_threshold and old_risk_score < risk_threshold:
                    with self.stats_lock:
                        self.stats['high_risk_processes'] += 1
                    should_log_high_risk = True
            
            # Heavy work outside lock
            if not process_snapshot:
                return
            
            # ML inference (rate limited)
            anomaly_result = None
            if self.enhanced_anomaly_detector:
                if self._should_run_ml_inference(pid, process_snapshot.get('syscall_count', 0), current_time):
                    try:
                        anomaly_result = self.enhanced_anomaly_detector.detect_anomaly_ensemble(
                            process_snapshot['syscalls'], process_info, pid
                        )
                        
                        # Feed sample to incremental trainer (if enabled)
                        if self.incremental_trainer and anomaly_result:
                            try:
                                self.incremental_trainer.add_sample(
                                    list(process_snapshot['syscalls']),
                                    process_info,
                                    anomaly_result.anomaly_score
                                )
                            except Exception as e:
                                self.logger.debug(f"Incremental trainer sample collection failed: {e}")
                    except Exception as e:
                        self.logger.warning(f"ML inference failed for PID {pid}: {e}")
                
                # Update anomaly scores
                self._update_anomaly_scores(pid, anomaly_result, process_snapshot)
                
                # Log anomaly if detected
                if anomaly_result and anomaly_result.is_anomaly:
                    try:
                        self._log_security_event('anomaly_detected', {
                            'pid': pid,
                            'process_name': process_snapshot.get('name', '<unknown>'),
                            'anomaly_score': anomaly_result.anomaly_score,
                            'explanation': anomaly_result.explanation if anomaly_result.explanation else None
                        })
                    except Exception as e:
                        self.logger.debug(f"Error logging anomaly event: {e}")
            
            # Log high-risk event
            if should_log_high_risk:
                self._log_security_event('high_risk_process', {
                    'pid': pid,
                    'process_name': process_snapshot.get('name', '<unknown>'),
                    'risk_score': risk_score,
                    'anomaly_score': process_snapshot.get('anomaly_score', 0.0)
                })
            
            # Take action if needed (use new response handler, fallback to legacy)
            action_taken = None
            if self.response_handler:
                try:
                    with self.processes_lock:
                        if pid in self.processes:
                            process = self.processes[pid]
                            # Build reason string
                            reason_parts = []
                            if process.get('risk_score', 0) >= self.config.get('risk_threshold', 50.0):
                                reason_parts.append(f"High risk score: {process['risk_score']:.1f}")
                            if anomaly_result and anomaly_result.is_anomaly:
                                reason_parts.append(f"Anomaly detected: {anomaly_result.anomaly_score:.2f}")
                            if self.threat_intelligence:
                                # Check for IOC matches
                                ioc_matches = self.threat_intelligence.check_ioc(process_snapshot)
                                if ioc_matches:
                                    reason_parts.append(f"IOC match: {ioc_matches[0].get('type', 'unknown')}")
                                # Check for ATT&CK techniques
                                technique_matches = self.threat_intelligence.match_attack_technique(
                                    syscalls_snapshot, pid
                                )
                                if technique_matches:
                                    reason_parts.append(f"ATT&CK: {technique_matches[0][1]['name']}")
                            
                            reason = "; ".join(reason_parts) if reason_parts else "Risk threshold exceeded"
                            
                            action_taken = self.response_handler.take_action(
                                pid, process['name'], process['risk_score'], 
                                process.get('anomaly_score', 0.0), reason
                            )
                            if action_taken:
                                with self.stats_lock:
                                    self.stats['actions_taken'] += 1
                except Exception as e:
                    self.logger.error(f"Response handler error: {e}")
            elif self.action_handler:  # Legacy fallback
                try:
                    with self.processes_lock:
                        if pid in self.processes:
                            process = self.processes[pid]
                            self.action_handler.take_action(
                                pid, process['name'], process['risk_score'], 
                                process.get('anomaly_score', 0.0)
                            )
                            with self.stats_lock:
                                self.stats['actions_taken'] += 1
                except Exception as e:
                    self.logger.error(f"Action handler error: {e}")
            
            # Update statistics (thread-safe)
            self.syscall_counts[syscall] += 1
            with self.processes_lock:
                process_count = len(self.processes)
            with self.stats_lock:
                self.stats['total_processes'] = process_count
            
        except Exception as e:
            self.logger.error(f"Error processing syscall event: {e}", exc_info=True)
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name by PID with caching"""
        # Validate PID - load from config, fallback to constant
        system_config = self.config.get('system', {})
        max_pid = system_config.get('max_valid_pid', MAX_VALID_PID)
        if not isinstance(pid, int) or pid <= 0 or pid > max_pid:
            return f"<invalid:{pid}>"
        
        current_time = time.time()
        cache_key = pid
        
        # Check cache first
        with self._process_name_cache_lock:
            if cache_key in self._process_name_cache:
                cache_time = self._process_name_cache_time.get(cache_key, 0)
                if current_time - cache_time < self._process_name_cache_ttl:
                    return self._process_name_cache[cache_key]
        
        # Cache miss - get from psutil
        try:
            process = psutil.Process(pid)
            name = process.name()
            
            # Update cache
            with self._process_name_cache_lock:
                self._process_name_cache[cache_key] = name
                self._process_name_cache_time[cache_key] = current_time
            
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Cache the unknown result to avoid repeated lookups
            with self._process_name_cache_lock:
                unknown_name = f"<unknown:{pid}>"
                self._process_name_cache[cache_key] = unknown_name
                self._process_name_cache_time[cache_key] = current_time
            return unknown_name
        except (ValueError, OSError) as e:
            # Invalid PID or system error
            self.logger.debug(f"Invalid PID {pid}: {e}")
            return f"<invalid:{pid}>"
    
    def _log_security_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log security event"""
        event = {
            'timestamp': time.time(),
            'event_type': event_type,
            'details': details
        }
        self.security_events.append(event)
    
    def get_high_risk_processes(self, threshold: float = DEFAULT_RISK_THRESHOLD) -> List[Tuple[int, str, float, float]]:
        """Get processes with risk scores above threshold - OPTIMIZED"""
        # OPTIMIZED: Pre-extract data during lock, filter and sort outside
        with self.processes_lock:
            process_data = [
                (pid, proc.get('name', '<unknown>'), proc.get('risk_score', 0.0), 
                 proc.get('anomaly_score', 0.0))
                for pid, proc in self.processes.items()
            ]
        
        # Filter and sort outside lock (safe because we have immutable tuples)
        high_risk = [(pid, name, rs, as_) for pid, name, rs, as_ in process_data if rs >= threshold]
        return sorted(high_risk, key=lambda x: x[2], reverse=True)
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get comprehensive monitoring statistics"""
        stats = {
            **self.stats,
            'enhanced_ebpf_stats': self.enhanced_ebpf_monitor.get_monitoring_stats() if self.enhanced_ebpf_monitor else {},
            'anomaly_detection_stats': self.enhanced_anomaly_detector.get_detection_stats() if self.enhanced_anomaly_detector else {},
            'container_security_stats': self.container_security_monitor.get_security_stats() if self.container_security_monitor else {},
            'incremental_training_stats': self.incremental_trainer.get_stats() if self.incremental_trainer else {},
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
    
    def _format_process_row(self, pid: int, proc: Dict[str, Any]) -> Tuple[str, str, str, str, str, str]:
        """Format a single process row for dashboard table"""
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
        
        # Anomaly indicator
        anomaly_display = "⚠️" if anomaly_score >= 0.5 else "✓"
        
        # CPU display
        cpu_percent = proc.get('cpu_percent', None)
        if cpu_percent is not None:
            cpu_percent = min(100.0, max(0.0, cpu_percent))
            cpu_display = f"{cpu_percent:.0f}%" if cpu_percent >= 0.5 else ""
        else:
            try:
                p = psutil.Process(int(pid))
                cpu = p.cpu_percent(interval=None) or 0.0
                cpu = min(100.0, max(0.0, cpu))
                cpu_display = f"{cpu:.0f}%" if cpu >= 0.5 else ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu_display = "N/A"
            except (AttributeError, ValueError) as e:
                cpu_display = ""
                self.logger.debug(f"Error getting CPU for PID {pid}: {e}")
        
        syscall_display = f"{syscall_count:,}" if syscall_count > 0 else "0"
        proc_name = proc.get('name', '<unknown>')
        if len(proc_name) > 13:
            proc_name = proc_name[:11] + "..."
        
        return (str(pid), proc_name, risk_display, anomaly_display, syscall_display, cpu_display)
    
    def _create_dashboard(self) -> Panel:
        """Create detailed real-time monitoring dashboard"""
        try:
            # Main processes table - fixed widths to prevent wrapping
            table = Table(
                title="🖥️ Live Process Monitoring", 
                box=box.ROUNDED, 
                show_header=True, 
                header_style="bold",
                padding=(0, 1)
            )
            # Compact column widths for narrow terminals
            table.add_column("PID", style="cyan", no_wrap=True, width=6, justify="right", overflow="ignore")
            table.add_column("Proc", style="magenta", width=14, no_wrap=True, overflow="ellipsis")
            table.add_column("Risk", justify="right", style="yellow", width=7, no_wrap=True, overflow="ignore")
            table.add_column("Anom", justify="center", style="yellow", width=4, no_wrap=True, overflow="ignore")
            table.add_column("Sysc", justify="right", style="green", width=7, no_wrap=True, overflow="ignore")
            table.add_column("CPU", justify="right", style="cyan", width=5, no_wrap=True, overflow="ignore")
            
            # Add processes sorted by risk score - THREAD SAFE: create snapshot under lock
            # Use timeout to avoid deadlock
            processes_snapshot = {}
            try:
                # Try to acquire lock with timeout (non-blocking check)
                if self.processes_lock.acquire(timeout=0.1):
                    try:
                        # Create snapshot to avoid holding lock during expensive operations
                        processes_snapshot = {
                            pid: dict(proc) for pid, proc in self.processes.items()
                        }
                    finally:
                        self.processes_lock.release()
                else:
                    # Lock timeout - use empty snapshot
                    self.logger.debug("Could not acquire processes_lock for dashboard")
            except Exception as e:
                self.logger.debug(f"Error acquiring lock: {e}")
            
            # Sort outside the lock (safe because we have a snapshot)
            sorted_processes = sorted(
                processes_snapshot.items(),
                key=lambda x: x[1].get('risk_score', 0) or 0,
                reverse=True
            )[:10]  # Show top 10
            
            if sorted_processes:
                for pid, proc in sorted_processes:
                    try:
                        pid_str, proc_name, risk_display, anomaly_display, syscall_display, cpu_display = \
                            self._format_process_row(pid, proc)
                        table.add_row(pid_str, proc_name, risk_display, anomaly_display, syscall_display, cpu_display)
                    except Exception as e:
                        self.logger.debug(f"Error formatting row for PID {pid}: {e}")
                        continue
            else:
                table.add_row("Waiting for syscall events...", "", "", "", "", "", style="dim")
            
            # Get stats safely (read-only, no lock needed for reading)
            try:
                total_processes = self.stats.get('total_processes', 0)
                high_risk = self.stats.get('high_risk_processes', 0)
                anomalies = self.stats.get('anomalies_detected', 0)
                policy_violations = self.stats.get('policy_violations', 0)
            except Exception:
                total_processes = high_risk = anomalies = policy_violations = 0
            
            # Stats panel with explanations - simplified to avoid rendering issues
            stats_text = f"""📊 Statistics
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 Processes: {total_processes} | ⚠️ High Risk: {high_risk} | 🚨 Anomalies: {anomalies} | 🔒 Violations: {policy_violations}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 eBPF capturing syscalls | ML analyzing patterns | Dashboard updating...
💡 Risk: 🟢 0-30 Normal | 🟡 30-50 Suspicious | 🔴 50+ High Risk"""
            
            # Use Rich's rendering to properly display table
            from rich.console import Group
            from rich.text import Text
            
            # Create a simple text panel for stats
            stats_panel = Panel(stats_text, border_style="blue", padding=(0, 1))
            
            # Group table and stats - this should render properly
            try:
                content = Group(table, stats_panel)
            except Exception:
                # Fallback: just use table if Group fails
                content = table
            
            return Panel(content, title="🛡️ Enhanced Linux Security Agent", 
                        border_style="green", padding=(0, 1))
        except Exception as e:
            # Fallback simple dashboard
            self.logger.error(f"Error creating dashboard: {e}")
            return Panel("Dashboard error - see logs", title="Error", border_style="red")

    def _create_tui_table(self) -> Table:
        """Create compact table-only TUI (PID | Proc | Risk | Anom | Sysc | CPU)"""
        table = Table(
            title=None,
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
            padding=(0, 1)
        )
        table.add_column("PID", style="cyan", no_wrap=True, width=6, justify="right", overflow="ignore")
        table.add_column("Proc", style="magenta", width=14, no_wrap=True, overflow="ellipsis")
        table.add_column("Risk", justify="right", style="yellow", width=7, no_wrap=True, overflow="ignore")
        table.add_column("Anom", justify="center", style="yellow", width=4, no_wrap=True, overflow="ignore")
        table.add_column("Sysc", justify="right", style="green", width=7, no_wrap=True, overflow="ignore")
        table.add_column("CPU", justify="right", style="cyan", width=5, no_wrap=True, overflow="ignore")

        with self.processes_lock:
            processes_snapshot = {pid: dict(proc) for pid, proc in self.processes.items()}

        # OPTIMIZED: Use itemgetter for faster sorting, pre-extract risk scores
        sorted_processes = sorted(
            processes_snapshot.items(), 
            key=lambda x: x[1].get('risk_score', 0.0), 
            reverse=True
        )[:15]

        if not sorted_processes:
            table.add_row("Waiting...", "", "", "", "", "", style="dim")
            return table

        for pid, proc in sorted_processes:
            risk_score = proc.get('risk_score', 0) or 0
            anomaly_score = proc.get('anomaly_score', 0.0)
            syscall_count = proc.get('syscall_count', 0)

            if risk_score >= 50:
                risk_display = f"🔴 {risk_score:.0f}"
            elif risk_score >= 30:
                risk_display = f"🟡 {risk_score:.0f}"
            else:
                risk_display = f"🟢 {risk_score:.0f}"

            anomaly_display = "⚠️" if anomaly_score >= 0.5 else "✓"
            cpu_display = ""
            cpu_percent = proc.get('cpu_percent', None)
            if cpu_percent is not None:
                cpu_percent = min(100.0, max(0.0, cpu_percent))
                cpu_display = f"{cpu_percent:.0f}%" if cpu_percent >= 0.5 else ""

            proc_name = proc.get('name', '<unknown>')
            if len(proc_name) > 13:
                proc_name = proc_name[:11] + "..."

            table.add_row(str(pid), proc_name, risk_display, anomaly_display, f"{syscall_count:,}", cpu_display)

        return table
    
    def _list_processes(self) -> None:
        """List all monitored processes"""
        print("\n" + "="*80)
        print("📋 MONITORED PROCESSES")
        print("="*80)
        
        with self.processes_lock:
            if not self.processes:
                print("No processes monitored yet.")
                return
            
            # Sort by risk score - THREAD SAFE: create snapshot
            processes_snapshot = dict(self.processes)
        
        # Sort outside the lock
        sorted_procs = sorted(
            processes_snapshot.items(),
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
    
    def _list_anomalies(self) -> None:
        """List all detected anomalies"""
        print("\n" + "="*80)
        print("🚨 DETECTED ANOMALIES")
        print("="*80)
        
        with self.processes_lock:
            # Create snapshot under lock
            processes_snapshot = {pid: dict(proc) for pid, proc in self.processes.items()}
        
        # Process outside lock
        anomalies = []
        for pid, proc in processes_snapshot.items():
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
    
    def _show_stats(self) -> None:
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
    parser.add_argument('--tui', action='store_true', help='Show compact TUI (table only)')
    parser.add_argument('--collector', choices=['ebpf', 'auditd'], default='ebpf', help='Choose event collector (default: ebpf)')
    parser.add_argument('--threshold', type=float, default=30.0, help='Risk threshold for alerts')
    parser.add_argument('--timeout', type=int, default=0, help='Run for specified seconds (0 = indefinitely)')
    parser.add_argument('--output', choices=['console', 'json'], default='console', help='Output format')
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--train-models', action='store_true', help='Train anomaly detection models')
    parser.add_argument('--append', action='store_true', help='Append to previous feature store when training')
    parser.add_argument('--export-training-data', type=str, metavar='FILE', help='Export current training data to JSON file')
    parser.add_argument('--train-from-file', type=str, metavar='FILE', help='Train models from JSON file containing training data')
    parser.add_argument('--train-from-files', nargs='+', metavar='FILE', help='Train models from multiple JSON files (merged)')
    parser.add_argument('--train-from-directory', type=str, metavar='DIR', help='Train models from all JSON files in directory')
    parser.add_argument('--train-from-url', type=str, metavar='URL', help='Train models from URL (HTTP/HTTPS)')
    parser.add_argument('--merge-and-train', action='store_true', help='Merge local + external data before training')
    parser.add_argument('--external-files', nargs='+', metavar='FILE', help='External training data files to merge (use with --merge-and-train)')
    parser.add_argument('--no-incremental-training', action='store_true', help='Disable automatic incremental retraining')
    parser.add_argument('--retrain-interval', type=int, default=3600, help='Incremental retraining interval in seconds (default: 3600 = 1 hour)')
    parser.add_argument('--min-retrain-samples', type=int, default=100, help='Minimum samples needed for incremental retraining (default: 100)')
    parser.add_argument('--list-processes', action='store_true', help='List all monitored processes and exit')
    parser.add_argument('--list-anomalies', action='store_true', help='List all detected anomalies and exit')
    parser.add_argument('--stats', action='store_true', help='Show statistics and exit')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode with detailed logging')
    parser.add_argument('--daemon', action='store_true', help='Run as background daemon (logs to file)')
    # SECURITY FIX: Use secure cache directory instead of /tmp
    default_log_dir = os.path.join(os.path.expanduser('~'), '.cache', 'security_agent')
    os.makedirs(default_log_dir, mode=0o700, exist_ok=True)
    default_log_file = os.path.join(default_log_dir, 'security_agent.log')
    parser.add_argument('--log-file', type=str, default=default_log_file, help='Log file for daemon mode')
    
    args = parser.parse_args()
    
    # Load configuration (supports YAML or JSON). Priority: --config > config/config.yml > config/config.json
    def _load_external_config(path: Optional[str]) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {}
        try:
            if path:
                p = Path(path)
                if p.exists():
                    if p.suffix.lower() in ['.yml', '.yaml'] and YAML_AVAILABLE:
                        with open(p, 'r') as f:
                            cfg = yaml.safe_load(f) or {}
                    else:
                        with open(p, 'r') as f:
                            cfg = json.load(f)
                    return cfg if isinstance(cfg, dict) else {}
            # Try defaults
            yml = Path(__file__).resolve().parent.parent / 'config' / 'config.yml'
            if yml.exists() and YAML_AVAILABLE:
                with open(yml, 'r') as f:
                    cfg = yaml.safe_load(f) or {}
                return cfg if isinstance(cfg, dict) else {}
            jsn = Path(__file__).resolve().parent.parent / 'config' / 'config.json'
            if jsn.exists():
                with open(jsn, 'r') as f:
                    cfg = json.load(f)
                return cfg if isinstance(cfg, dict) else {}
        except Exception:
            return {}
        return {}

    config = _load_external_config(args.config)
    # Warn if YAML requested but not available
    if args.config and args.config.lower().endswith(('.yml', '.yaml')) and not YAML_AVAILABLE:
        print("⚠️ YAML config requested but PyYAML not installed; install pyyaml or use JSON.")
    
    # Validate and sanitize config values
    def _validate_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize configuration values"""
        validated = {}
        
        # Risk threshold: 0-100
        threshold = float(cfg.get('risk_threshold', args.threshold))
        validated['risk_threshold'] = max(0.0, min(100.0, threshold))
        
        # Output format
        validated['output_format'] = str(cfg.get('output_format', args.output))
        if validated['output_format'] not in ['console', 'json']:
            validated['output_format'] = 'console'
        
        # Debug mode
        validated['debug'] = bool(cfg.get('debug', args.debug))
        
        # Merge system and performance configs into main config
        if 'system' in cfg:
            validated['system'] = cfg['system']
        if 'performance' in cfg:
            validated['performance'] = cfg['performance']
        
        # Collector: ebpf or auditd
        collector = str(cfg.get('collector', args.collector)).lower()
        validated['collector'] = collector if collector in ['ebpf', 'auditd'] else 'ebpf'
        
        # Anomaly weight: 0-1
        anomaly_weight = float(cfg.get('anomaly_weight', 0.3))
        validated['anomaly_weight'] = max(0.0, min(1.0, anomaly_weight))
        
        # Decay factor: 0-1
        decay_factor = float(cfg.get('decay_factor', 0.95))
        validated['decay_factor'] = max(0.0, min(1.0, decay_factor))
        
        # Decay interval: positive integer
        decay_interval = int(cfg.get('decay_interval', 60))
        validated['decay_interval'] = max(1, decay_interval)
        
        # Base risk scores: validate dict
        if isinstance(cfg.get('base_risk_scores'), dict):
            validated['base_risk_scores'] = {}
            for syscall, score in cfg['base_risk_scores'].items():
                if isinstance(syscall, str) and isinstance(score, (int, float)):
                    validated['base_risk_scores'][syscall] = max(0, min(100, int(score)))
        
        # Merge other config values
        for key, value in cfg.items():
            if key not in validated:
                validated[key] = value
        
        return validated
    
    config = _validate_config(config)
    
    # Incremental retraining configuration (from args or config file)
    if args.no_incremental_training:
        config['enable_incremental_training'] = False
    else:
        config['enable_incremental_training'] = config.get('enable_incremental_training', True)
    
    config['retrain_interval'] = config.get('retrain_interval', args.retrain_interval)
    config['min_samples_for_retrain'] = config.get('min_samples_for_retrain', args.min_retrain_samples)
    
    config.update({
        'risk_threshold': config.get('risk_threshold', args.threshold),
        'output_format': config.get('output_format', args.output),
        'debug': config.get('debug', args.debug or False),
        'collector': config.get('collector', args.collector)
    })
    
    # Handle daemon mode (background operation) - FUTURE IMPLEMENTATION
    if args.daemon:
        print("⚠️  Daemon mode coming soon!")
        # Use secure log directory
        log_dir = os.path.join(os.path.expanduser('~'), '.cache', 'security_agent')
        log_file = os.path.join(log_dir, 'agent.log')
        print(f"For now, use: nohup sudo python3 core/enhanced_security_agent.py --dashboard --timeout 3600 > {log_file} 2>&1 &")
        print(f"Then check logs: tail -f {log_file}")
        sys.exit(0)
    
    # Create enhanced security agent
    agent = EnhancedSecurityAgent(config)
    
    # Export training data if requested
    if args.export_training_data:
        if not agent.enhanced_anomaly_detector:
            print("❌ Anomaly detector not initialized")
            return
        
        # Collect current training data
        agent.console.print("📊 Collecting training data for export...", style="yellow")
        agent.start_monitoring()
        time.sleep(10)  # Collect for 10 seconds
        
        # Get training samples from processes
        training_data = []
        with agent.processes_lock:
            for pid, proc in agent.processes.items():
                syscalls_list = proc.get('syscalls', [])
                if len(syscalls_list) >= 5:
                    syscalls = list(syscalls_list)[-50:]
                    try:
                        p = psutil.Process(pid)
                        with p.oneshot():
                            process_info = {
                                'cpu_percent': p.cpu_percent(interval=None) or 0,
                                'memory_percent': p.memory_percent(),
                                'num_threads': p.num_threads(),
                                'pid': pid,
                                'process_name': proc.get('name', 'unknown')
                            }
                        training_data.append((syscalls, process_info))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        
        agent.stop_monitoring()
        
        # Export to file
        import platform
        metadata = {
            'source': platform.node(),
            'os': platform.system(),
            'os_version': platform.release(),
            'collection_date': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'total_samples': len(training_data)
        }
        
        if agent.enhanced_anomaly_detector.export_training_data(training_data, args.export_training_data, metadata):
            print(f"✅ Training data exported to {args.export_training_data}")
        else:
            print(f"❌ Failed to export training data")
        return
    
    # Train from external sources if requested
    if args.train_from_file or args.train_from_files or args.train_from_directory or args.train_from_url or args.train_from_api:
        if not agent.enhanced_anomaly_detector:
            print("❌ Anomaly detector not initialized")
            return
        
        training_data = []
        
        # Load from single file
        if args.train_from_file:
            training_data = agent.enhanced_anomaly_detector.load_training_data_from_file(args.train_from_file)
        
        # Load from multiple files
        elif args.train_from_files:
            datasets = []
            for file_path in args.train_from_files:
                file_data = agent.enhanced_anomaly_detector.load_training_data_from_file(file_path)
                datasets.append(file_data)
            training_data = agent.enhanced_anomaly_detector.merge_training_datasets(*datasets)
        
        # Load from directory
        elif args.train_from_directory:
            training_data = agent.enhanced_anomaly_detector.load_training_data_from_directory(args.train_from_directory)
        
        # Load from URL
        elif args.train_from_url:
            training_data = agent.enhanced_anomaly_detector.load_training_data_from_url(args.train_from_url)
        
        if not training_data:
            print("❌ No training data loaded")
            return
        
        # Train models
        agent.console.print(f"🧠 Training models on {len(training_data)} external samples...", style="yellow")
        agent.config['append_training'] = args.append
        agent.enhanced_anomaly_detector.train_models(training_data, append=args.append)
        agent.console.print("✅ Models trained from external data", style="green")
        return
    
    # Merge and train if requested
    if args.merge_and_train:
        if not agent.enhanced_anomaly_detector:
            print("❌ Anomaly detector not initialized")
            return
        
        datasets = []
        
        # Collect local data
        if args.train_models or True:  # Always collect local if merging
            agent.console.print("📊 Collecting local training data...", style="yellow")
            agent.start_monitoring()
            time.sleep(10)
            
            local_data = []
            with agent.processes_lock:
                for pid, proc in agent.processes.items():
                    syscalls_list = proc.get('syscalls', [])
                    if len(syscalls_list) >= 5:
                        syscalls = list(syscalls_list)[-50:]
                        try:
                            p = psutil.Process(pid)
                            with p.oneshot():
                                process_info = {
                                    'cpu_percent': p.cpu_percent(interval=None) or 0,
                                    'memory_percent': p.memory_percent(),
                                    'num_threads': p.num_threads(),
                                    'pid': pid
                                }
                            local_data.append((syscalls, process_info))
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            
            agent.stop_monitoring()
            datasets.append(local_data)
            agent.console.print(f"✅ Collected {len(local_data)} local samples", style="green")
        
        # Load external files
        if args.external_files:
            for file_path in args.external_files:
                file_data = agent.enhanced_anomaly_detector.load_training_data_from_file(file_path)
                datasets.append(file_data)
        
        # Merge all datasets
        training_data = agent.enhanced_anomaly_detector.merge_training_datasets(*datasets)
        
        if not training_data:
            print("❌ No training data after merge")
            return
        
        # Train on merged data
        agent.console.print(f"🧠 Training models on {len(training_data)} merged samples...", style="yellow")
        agent.config['append_training'] = args.append
        agent.enhanced_anomaly_detector.train_models(training_data, append=args.append)
        agent.console.print("✅ Models trained on merged data", style="green")
        return
    
    # Train models if requested (original behavior)
    if args.train_models and agent.enhanced_anomaly_detector:
        try:
            # CRITICAL: Start monitoring BEFORE training to collect real syscall data
            agent.start_monitoring()
            # Give monitoring a moment to initialize and start capturing events
            time.sleep(2)
            
            # Pass append flag via config for downstream use
            agent.config['append_training'] = args.append
            agent._train_anomaly_models()
            
            # Training complete - show summary
            print("\n" + "="*60)
            print("✅ TRAINING COMPLETE")
            print("="*60)
            print("Models are saved and ready to use.")
            
            # If dashboard was also requested, continue to monitoring
            if args.dashboard or args.tui:
                print("Starting dashboard with trained models...")
                print("="*60 + "\n")
                # Ensure agent is still running
                if not agent.running:
                    print("⚠️ Agent not running, restarting monitoring...")
                    agent.start_monitoring()
                # Don't return - fall through to dashboard code below
            else:
                print("You can now run the agent with:")
                print("  sudo python3 core/enhanced_security_agent.py --dashboard")
                print("="*60 + "\n")
                # Stop monitoring and exit
                try:
                    agent.stop_monitoring()
                except Exception:
                    pass
                return
        except KeyboardInterrupt:
            print("\n⚠️ Training interrupted by user")
            print("Stopping monitoring and exiting...")
            try:
                agent.stop_monitoring()
            except Exception:
                pass
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
        # Write directly to stderr for immediate visibility (stdout might be buffered)
        import sys
        sys.stderr.write("\n🛑 Ctrl+C detected! Stopping agent...\n")
        sys.stderr.flush()
        
        # Set exit flags IMMEDIATELY
        exit_requested.set()
        agent.running = False
        
        # Force immediate stop of all threads
        if agent.enhanced_ebpf_monitor:
            agent.enhanced_ebpf_monitor.running = False
        
        if shutdown_initiated:
            # Force immediate exit on second Ctrl+C (within 2 seconds)
            sys.stderr.write("🛑 Force exit!\n")
            sys.stderr.flush()
            os._exit(1)
        
        shutdown_initiated = True
    
    # Install signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring (skip if already started from training)
    if not agent.running:
        agent.start_monitoring()
    
    try:
        start_time = time.time()
        
        if args.dashboard or args.tui:
            # Show real-time dashboard - use Live with screen=False for better signal handling
            print(f"📊 Starting dashboard (agent.running={agent.running})...")
            from rich.live import Live
            live = None
            try:
                print("Creating dashboard view...")
                try:
                    # Add timeout protection for dashboard creation
                    # Note: signal is already imported at top of file
                    
                    def timeout_handler(signum, frame):
                        raise TimeoutError("Dashboard creation timed out after 5 seconds")
                    
                    # Set 5 second timeout
                    signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(5)
                    
                    try:
                        if args.tui:
                            print("Creating TUI table...")
                            view = agent._create_tui_table()
                            print("TUI table created, initializing Live...")
                            live = Live(view, refresh_per_second=2, screen=False)
                        else:
                            print("Creating dashboard panel...")
                            view = agent._create_dashboard()
                            print("Dashboard panel created, initializing Live...")
                            live = Live(view, refresh_per_second=2, screen=False)
                        signal.alarm(0)  # Cancel timeout
                        print("Starting live dashboard...")
                        live.start()
                        print("✅ Dashboard started! Press Ctrl+C to exit.")
                    except TimeoutError as e:
                        signal.alarm(0)
                        print(f"❌ Dashboard creation timed out: {e}")
                        print("This might indicate a deadlock. Trying to continue anyway...")
                        # Create a simple fallback view
                        from rich.panel import Panel
                        from rich.text import Text
                        view = Panel(Text("Dashboard loading... (if stuck, press Ctrl+C)", style="yellow"))
                        live = Live(view, refresh_per_second=2, screen=False)
                        live.start()
                    finally:
                        signal.alarm(0)  # Always cancel timeout
                except Exception as e:
                    print(f"❌ Failed to create dashboard: {e}")
                    import traceback
                    traceback.print_exc()
                    # Don't raise - try to continue with a simple view
                    try:
                        from rich.panel import Panel
                        from rich.text import Text
                        view = Panel(Text(f"Dashboard error: {e}\nPress Ctrl+C to exit.", style="red"))
                        live = Live(view, refresh_per_second=2, screen=False)
                        live.start()
                    except Exception as fallback_error:
                        logger.error(f"Failed to display fallback error view: {fallback_error}")
                        raise
                
                while agent.running and not exit_requested.is_set():
                    elapsed = time.time() - start_time
                    if args.timeout > 0 and elapsed >= args.timeout:
                        print(f"\n⏰ Timeout reached ({args.timeout}s) - stopping agent...", flush=True)
                        agent.running = False
                        exit_requested.set()
                        break
                    
                    if exit_requested.is_set() or not agent.running:
                        break
                    
                    # Check exit BEFORE expensive dashboard creation
                    if exit_requested.is_set() or not agent.running:
                        break
                    
                    try:
                        if args.tui:
                            view = agent._create_tui_table()
                        else:
                            view = agent._create_dashboard()
                        # Check exit AGAIN before updating
                        if exit_requested.is_set() or not agent.running:
                            break
                        live.update(view)
                    except (KeyboardInterrupt, SystemExit):
                        exit_requested.set()
                        agent.running = False
                        break
                    except (AttributeError, RuntimeError, OSError) as e:
                        # Suppress dashboard errors during shutdown
                        if exit_requested.is_set() or not agent.running:
                            break
                        if args.debug:
                            logger.debug(f"Dashboard error: {e}")
                    
                    # Very short sleep - check exit VERY frequently
                    if exit_requested.is_set() or not agent.running:
                        break
                    time.sleep(0.05)  # 50ms - allows signal handler to work
            except (KeyboardInterrupt, SystemExit):
                agent.running = False
            finally:
                if live:
                    try:
                        # Stop Live immediately, don't wait
                        live.stop()
                        live.refresh()
                    except (RuntimeError, AttributeError, KeyboardInterrupt) as e:
                        # Ignore UI errors during shutdown
                        if args.debug:
                            print(f"Warning: Error stopping live UI: {e}")
                        # Error during UI cleanup - non-critical, process is exiting
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
        # Force stop everything - non-blocking
        try:
            agent.stop_monitoring()
        except Exception:
            pass  # Ignore errors during shutdown
        
        # Export data if requested (fast, don't let it block exit)
        if args.output == 'json':
            try:
                data = agent.export_monitoring_data()
                print(json.dumps(data, indent=2))
            except Exception:
                pass  # Don't block exit on export errors

if __name__ == "__main__":
    main()
