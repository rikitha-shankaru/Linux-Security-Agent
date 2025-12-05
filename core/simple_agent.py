#!/usr/bin/env python3
"""
Simplified Security Agent - Minimal working version
This is a clean, simple implementation that actually works
"""
import os
import sys
import time
import signal
import threading
import logging
import traceback
import pickle
from logging.handlers import RotatingFileHandler
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

# Add core to path
_core_dir = os.path.dirname(os.path.abspath(__file__))
if _core_dir not in sys.path:
    sys.path.insert(0, _core_dir)

# Setup logging with file output
def setup_logging(log_dir=None):
    """Setup logging to both console and file"""
    if log_dir is None:
        # Default: ~/.cache/security_agent/logs or ./logs
        home_log = Path.home() / '.cache' / 'security_agent' / 'logs'
        local_log = Path(__file__).parent.parent / 'logs'
        log_dir = local_log if local_log.exists() else home_log
    
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Log file path
    log_file = log_dir / 'security_agent.log'
    
    # Create formatters
    detailed_format = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    console_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    root_logger.handlers = []
    
    # File handler with rotation (10MB, keep 5 backups)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)  # More detailed in file
    file_handler.setFormatter(logging.Formatter(detailed_format))
    root_logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)  # Less verbose on console
    console_handler.setFormatter(logging.Formatter(console_format))
    root_logger.addHandler(console_handler)
    
    return str(log_file)

# Setup logging
log_file_path = setup_logging()
logger = logging.getLogger('security_agent.simple')
logger.info(f"📝 Logging to file: {log_file_path}")

# Imports
try:
    from core.collectors.collector_factory import get_collector
    from core.collectors.base import SyscallEvent
    from core.detection.risk_scorer import EnhancedRiskScorer
    from core.utils.validator import validate_system, print_validation_results
except ImportError:
    # Fallback for direct execution
    from collectors.collector_factory import get_collector
    from collectors.base import SyscallEvent
    from detection.risk_scorer import EnhancedRiskScorer
    from utils.validator import validate_system, print_validation_results

try:
    from enhanced_anomaly_detector import EnhancedAnomalyDetector
    ML_AVAILABLE = True
except ImportError:
    try:
        from core.enhanced_anomaly_detector import EnhancedAnomalyDetector
        ML_AVAILABLE = True
    except ImportError:
        ML_AVAILABLE = False
        EnhancedAnomalyDetector = None

# Connection pattern analyzer
try:
    from connection_pattern_analyzer import ConnectionPatternAnalyzer
    CONN_PATTERN_AVAILABLE = True
except ImportError:
    try:
        from core.connection_pattern_analyzer import ConnectionPatternAnalyzer
        CONN_PATTERN_AVAILABLE = True
    except ImportError:
        CONN_PATTERN_AVAILABLE = False
        ConnectionPatternAnalyzer = None

import psutil
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel


class SimpleSecurityAgent:
    """Simplified security agent - just the essentials"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.console = Console()
        self.running = False
        
        # Components
        self.collector = None
        self.risk_scorer = EnhancedRiskScorer(config)
        self.anomaly_detector = None
        
        # Connection pattern analyzer (for C2, port scanning, exfiltration)
        if CONN_PATTERN_AVAILABLE:
            self.connection_analyzer = ConnectionPatternAnalyzer(config)
            logger.info("✅ Connection pattern analyzer enabled")
        else:
            self.connection_analyzer = None
        
        # Process tracking
        self.processes = {}  # pid -> {name, syscalls, risk_score, anomaly_score, last_update}
        self.processes_lock = threading.Lock()
        
        # Stats
        self.stats = {
            'total_processes': 0,
            'high_risk': 0,
            'anomalies': 0,
            'total_syscalls': 0,
            'c2_beacons': 0,
            'port_scans': 0
        }
        
        # Cache info panel to prevent re-creation (reduces blinking)
        self._info_panel_cache = None
        
        # Initialize ML if available
        if ML_AVAILABLE:
            try:
                logger.info("Initializing ML anomaly detector...")
                self.anomaly_detector = EnhancedAnomalyDetector(config)
                logger.info(f"ML detector initialized. Model directory: {getattr(self.anomaly_detector, 'model_dir', 'default')}")
                
                # Try to load pre-trained models
                try:
                    logger.debug("Attempting to load pre-trained ML models...")
                    load_result = self.anomaly_detector._load_models()
                    if self.anomaly_detector.is_fitted:
                        models_loaded = [name for name, trained in self.anomaly_detector.models_trained.items() if trained]
                        logger.info(f"✅ Loaded pre-trained ML models: {', '.join(models_loaded) if models_loaded else 'all models'}")
                        logger.info(f"   Models available: IsolationForest={models_loaded.count('isolation_forest')>0}, "
                                  f"SVM={models_loaded.count('one_class_svm')>0}, "
                                  f"Scaler={hasattr(self.anomaly_detector, 'scaler') and self.anomaly_detector.scaler is not None}, "
                                  f"PCA={hasattr(self.anomaly_detector, 'pca') and self.anomaly_detector.pca is not None}")
                    else:
                        logger.warning("⚠️  ML models not fully loaded - some components missing")
                        logger.warning(f"   is_fitted={self.anomaly_detector.is_fitted}, "
                                     f"models_trained={self.anomaly_detector.models_trained}")
                except FileNotFoundError as e:
                    logger.info(f"ℹ️  No pre-trained models found at expected location: {e}")
                    logger.info("   Train models with: python3 scripts/train_with_dataset.py")
                except pickle.UnpicklingError as e:
                    logger.error(f"❌ Error loading ML models (corrupted file): {e}")
                    logger.error("   Models may be corrupted. Retrain with: python3 scripts/train_with_dataset.py")
                except Exception as e:
                    logger.error(f"❌ Error loading ML models: {type(e).__name__}: {e}")
                    logger.debug(f"   Full traceback: {traceback.format_exc()}")
                    logger.info("   Agent will continue without ML detection. Train models to enable ML features.")
            except ImportError as e:
                logger.warning(f"⚠️  ML detector import failed: {e}")
                logger.warning("   ML features will be disabled")
            except Exception as e:
                logger.error(f"❌ ML detector initialization failed: {type(e).__name__}: {e}")
                logger.debug(f"   Full traceback: {traceback.format_exc()}")
                logger.warning("   Agent will continue without ML detection")
    
    def start(self) -> bool:
        """Start the agent"""
        logger.info("="*60)
        logger.info("Starting Security Agent...")
        logger.info(f"Collector type: {self.config.get('collector', 'ebpf')}")
        logger.info(f"Risk threshold: {self.config.get('risk_threshold', 30.0)}")
        logger.info(f"ML detector available: {self.anomaly_detector is not None}")
        logger.info(f"Connection analyzer available: {self.connection_analyzer is not None}")
        
        # Validate system
        logger.debug("Validating system requirements...")
        is_valid, errors = validate_system(self.config)
        if not is_valid:
            logger.error("System validation failed:")
            for error in errors:
                logger.error(f"  - {error}")
            print_validation_results(False, errors)
            return False
        logger.info("✅ System validation passed")
        
        # Get collector (default to eBPF, fallback to auditd)
        collector_type = self.config.get('collector', 'ebpf')
        logger.info(f"Initializing collector: {collector_type}")
        self.collector = get_collector(self.config, preferred=collector_type)
        if not self.collector:
            logger.error("❌ No collector available - cannot start agent")
            return False
        logger.info(f"✅ Collector initialized: {self.collector.get_name()}")
        
        # Start collector
        logger.info("Starting event monitoring...")
        if not self.collector.start_monitoring(self._handle_event):
            logger.error("❌ Failed to start collector - cannot start agent")
            return False
        
        self.running = True
        logger.info(f"✅ Agent started successfully with {self.collector.get_name()}")
        
        # Health check: Wait a few seconds and verify events are being captured
        logger.info("Performing health check (waiting 5 seconds for events)...")
        initial_syscalls = self.stats['total_syscalls']
        time.sleep(5)
        events_captured = self.stats['total_syscalls'] - initial_syscalls
        
        if events_captured > 0:
            logger.info(f"✅ Health check passed: Captured {events_captured} syscalls in 5 seconds")
            logger.info(f"   Capture rate: ~{events_captured/5:.0f} syscalls/second")
        else:
            logger.warning("⚠️  Health check warning: No events captured in 5 seconds")
            logger.warning("   This may indicate:")
            logger.warning("   - eBPF not capturing events (check kernel support)")
            logger.warning("   - No system activity (normal if system is idle)")
            logger.warning("   - Collector issue (check logs for errors)")
            logger.warning("   Agent will continue, but monitor for events...")
        
        logger.info("="*60)
        return True
    
    def stop(self):
        """Stop the agent"""
        logger.info("Stopping agent...")
        self.running = False
        if self.collector:
            logger.debug("Stopping collector...")
            self.collector.stop_monitoring()
            logger.debug("Collector stopped")
        
        # Log final statistics
        logger.info("="*60)
        logger.info("Agent stopped - Final Statistics:")
        logger.info(f"  Total processes monitored: {self.stats['total_processes']}")
        logger.info(f"  Total syscalls processed: {self.stats['total_syscalls']}")
        logger.info(f"  High risk detections: {self.stats['high_risk']}")
        logger.info(f"  Anomalies detected: {self.stats['anomalies']}")
        logger.info(f"  C2 beacons detected: {self.stats['c2_beacons']}")
        logger.info(f"  Port scans detected: {self.stats['port_scans']}")
        logger.info("="*60)
    
    def _handle_event(self, event: SyscallEvent):
        """Handle syscall event"""
        if not self.running:
            return
        
        try:
            # DEBUG: Log first few events to confirm flow
            if self.stats['total_syscalls'] < 5:
                logger.info(f"🔍 EVENT RECEIVED: PID={event.pid} Syscall={event.syscall} Comm={getattr(event, 'comm', 'N/A')}")
                logger.debug(f"   Event details: {vars(event) if hasattr(event, '__dict__') else 'N/A'}")
            
            pid = event.pid
            syscall = event.syscall
            
            with self.processes_lock:
                # Update process info
                if pid not in self.processes:
                    # Get actual process name from psutil if comm is empty
                    process_name = event.comm
                    if not process_name or process_name.startswith('pid_'):
                        try:
                            p = psutil.Process(pid)
                            process_name = p.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            process_name = event.comm or f'pid_{pid}'
                    
                    self.processes[pid] = {
                        'name': process_name,
                        'syscalls': deque(maxlen=100),  # Last 100 for analysis
                        'total_syscalls': 0,  # Actual total count
                        'risk_score': 0.0,
                        'anomaly_score': 0.0,
                        'last_update': time.time()
                    }
                    self.stats['total_processes'] += 1
                else:
                    # Update process name if we have a better one
                    if not self.processes[pid]['name'] or self.processes[pid]['name'].startswith('pid_'):
                        if event.comm:
                            self.processes[pid]['name'] = event.comm
                        else:
                            try:
                                p = psutil.Process(pid)
                                self.processes[pid]['name'] = p.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                
                proc = self.processes[pid]
                proc['syscalls'].append(syscall)
                proc['total_syscalls'] += 1  # Increment actual total count
                proc['last_update'] = time.time()
                self.stats['total_syscalls'] += 1
                
                syscall_list = list(proc['syscalls'])
                
                # Initialize process_info (needed for risk scoring)
                process_info = {}
                try:
                    p = psutil.Process(pid)
                    process_info = {
                        'cpu_percent': p.cpu_percent(interval=0.1) if p.is_running() else 0.0,
                        'memory_percent': p.memory_percent() if p.is_running() else 0.0,
                        'num_threads': p.num_threads() if p.is_running() else 0
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_info = {}  # Use empty dict if process not available
                
                # Calculate anomaly score FIRST (needed for risk score)
                # Preserve previous anomaly score if ML fails temporarily
                previous_anomaly_score = proc.get('anomaly_score', 0.0)
                anomaly_score = previous_anomaly_score  # Default to previous score
                anomaly_result = None
                
                if self.anomaly_detector:
                    # Try to load models if not fitted (only log once per process)
                    if not self.anomaly_detector.is_fitted:
                        if pid not in getattr(self, '_model_load_attempted', set()):
                            if not hasattr(self, '_model_load_attempted'):
                                self._model_load_attempted = set()
                            self._model_load_attempted.add(pid)
                            
                            try:
                                logger.debug(f"Attempting to load ML models for PID {pid}...")
                                self.anomaly_detector._load_models()
                                if self.anomaly_detector.is_fitted:
                                    logger.info(f"✅ ML models loaded successfully for PID {pid}")
                                else:
                                    logger.warning(f"⚠️  ML models partially loaded for PID {pid} - some components missing")
                            except FileNotFoundError as e:
                                logger.debug(f"ML models not found for PID {pid}: {e}")
                            except pickle.UnpicklingError as e:
                                logger.error(f"❌ Corrupted ML model file for PID {pid}: {e}")
                            except Exception as e:
                                logger.warning(f"⚠️  Failed to load ML models for PID {pid}: {type(e).__name__}: {e}")
                                logger.debug(f"   Traceback: {traceback.format_exc()}")
                    
                    if self.anomaly_detector.is_fitted:
                        try:
                            # CORRECT function signature: (syscalls, process_info, pid)
                            logger.debug(f"Running ML detection for PID {pid} (syscalls={len(syscall_list)})")
                            anomaly_result = self.anomaly_detector.detect_anomaly_ensemble(
                                syscall_list, process_info, pid
                            )
                            anomaly_score = abs(anomaly_result.anomaly_score)  # Use absolute value
                            proc['anomaly_score'] = anomaly_score
                            
                            # Log ML result for first few processes or when anomaly detected
                            if len(syscall_list) == 20:  # First time we have 20 syscalls
                                logger.info(f"🤖 ML RESULT: PID={pid} Process={proc['name']} "
                                          f"Score={anomaly_score:.1f} IsAnomaly={anomaly_result.is_anomaly} "
                                          f"Confidence={anomaly_result.confidence:.2f}")
                            
                            if anomaly_result.is_anomaly:
                                self.stats['anomalies'] += 1
                                logger.debug(f"Anomaly detected: PID={pid} Score={anomaly_score:.1f} "
                                           f"Explanation={anomaly_result.explanation}")
                        except ValueError as e:
                            logger.warning(f"⚠️  ML detection ValueError for PID {pid}: {e}")
                            logger.debug(f"   This may indicate insufficient features or data. Traceback: {traceback.format_exc()}")
                            # Keep previous score instead of resetting to 0
                            anomaly_score = previous_anomaly_score
                            proc['anomaly_score'] = anomaly_score
                        except AttributeError as e:
                            logger.error(f"❌ ML detection AttributeError for PID {pid}: {e}")
                            logger.error(f"   ML model may be corrupted. Traceback: {traceback.format_exc()}")
                            anomaly_score = previous_anomaly_score
                            proc['anomaly_score'] = anomaly_score
                        except Exception as e:
                            logger.error(f"❌ ML detection failed for PID {pid}: {type(e).__name__}: {e}")
                            logger.error(f"   Traceback: {traceback.format_exc()}")
                            # Keep previous score instead of resetting to 0
                            anomaly_score = previous_anomaly_score
                            proc['anomaly_score'] = anomaly_score
                    else:
                        # ML not trained yet - keep previous score or set to 0.00
                        if previous_anomaly_score == 0.0:
                            logger.debug(f"ML not fitted for PID {pid} - using default score 0.0")
                        anomaly_score = previous_anomaly_score if previous_anomaly_score > 0 else 0.0
                        proc['anomaly_score'] = anomaly_score
                else:
                    # No ML detector available
                    anomaly_score = previous_anomaly_score if previous_anomaly_score > 0 else 0.0
                    proc['anomaly_score'] = anomaly_score
                    if pid not in getattr(self, '_ml_unavailable_logged', set()):
                        if not hasattr(self, '_ml_unavailable_logged'):
                            self._ml_unavailable_logged = set()
                        self._ml_unavailable_logged.add(pid)
                        logger.debug(f"ML detector not available for PID {pid}")
                
                # Check for network connection patterns (C2, port scanning, exfiltration)
                connection_risk_bonus = 0.0
                if self.connection_analyzer and syscall in ['socket', 'connect', 'sendto', 'sendmsg']:
                    try:
                        # Extract connection info from event
                        dest_ip = '0.0.0.0'
                        dest_port = 0
                        
                        # Try to get from event_info if available
                        if hasattr(event, 'event_info') and event.event_info:
                            dest_ip = event.event_info.get('dest_ip', '0.0.0.0')
                            dest_port = event.event_info.get('dest_port', 0)
                            logger.debug(f"Connection event for PID {pid}: syscall={syscall} dest_ip={dest_ip} dest_port={dest_port}")
                        else:
                            logger.debug(f"Connection event for PID {pid}: syscall={syscall} (no event_info available)")
                        
                        # For socket/connect syscalls, use a simulated port based on PID for pattern detection
                        # (In real implementation, would extract from syscall arguments via eBPF)
                        if dest_port == 0 and syscall in ['socket', 'connect']:
                            # Use a hash of PID + syscall count to simulate different ports
                            dest_port = 1000 + (pid % 1000) + (len(syscall_list) % 100)
                            logger.debug(f"Using simulated port for PID {pid}: {dest_port} (NOTE: This is simulated, not real eBPF data)")
                        
                        # Analyze connection pattern
                        logger.debug(f"Analyzing connection pattern for PID {pid}: IP={dest_ip} Port={dest_port}")
                        conn_result = self.connection_analyzer.analyze_connection(
                            pid=pid,
                            dest_ip=dest_ip,
                            dest_port=dest_port,
                            timestamp=time.time()
                        )
                        
                        if conn_result:
                            connection_risk_bonus = 30.0  # Boost risk for connection patterns
                            pattern_type = conn_result.get('type', 'UNKNOWN')
                            explanation = conn_result.get('explanation', 'No explanation')
                            
                            logger.warning(f"🌐 CONNECTION PATTERN DETECTED: {pattern_type} PID={pid} Process={proc['name']}")
                            logger.warning(f"   Details: {explanation}")
                            logger.warning(f"   Destination: {dest_ip}:{dest_port} (NOTE: Port may be simulated)")
                            logger.warning(f"   Risk bonus added: +{connection_risk_bonus:.1f}")
                            
                            # Update stats
                            if pattern_type == 'C2_BEACONING':
                                self.stats['c2_beacons'] += 1
                                logger.warning(f"   C2 beaconing count: {self.stats['c2_beacons']}")
                            elif pattern_type == 'PORT_SCANNING':
                                self.stats['port_scans'] += 1
                                logger.warning(f"   Port scan count: {self.stats['port_scans']}")
                    except AttributeError as e:
                        logger.debug(f"Connection pattern analysis AttributeError for PID {pid}: {e}")
                        logger.debug(f"   Traceback: {traceback.format_exc()}")
                    except KeyError as e:
                        logger.debug(f"Connection pattern analysis KeyError for PID {pid}: {e}")
                        logger.debug(f"   Missing key in connection result. Traceback: {traceback.format_exc()}")
                    except Exception as e:
                        # Don't fail on connection analysis errors
                        logger.warning(f"⚠️  Connection pattern analysis error for PID {pid}: {type(e).__name__}: {e}")
                        logger.debug(f"   Traceback: {traceback.format_exc()}")
                
                # Calculate risk score WITH anomaly score AND connection pattern bonus
                base_risk_score = self.risk_scorer.update_risk_score(
                    pid, syscall_list, process_info, anomaly_score
                )
                risk_score = base_risk_score + connection_risk_bonus
                proc['risk_score'] = risk_score
                
                # DEBUG: Log all scores periodically
                if len(syscall_list) >= 20 and len(syscall_list) % 20 == 0:
                    comm = proc.get('name', 'unknown')
                    logger.info(f"📊 SCORE UPDATE: PID={pid} Process={comm} Risk={risk_score:.1f} Anomaly={anomaly_score:.1f} "
                              f"Syscalls={len(syscall_list)} TotalSyscalls={proc.get('total_syscalls', 0)} "
                              f"ConnectionBonus={connection_risk_bonus:.1f}")
                    logger.debug(f"   Process info: CPU={process_info.get('cpu_percent', 0):.1f}% "
                               f"Memory={process_info.get('memory_percent', 0):.1f}% "
                               f"Threads={process_info.get('num_threads', 0)}")
                
                # Update high risk count and LOG detections
                threshold = self.config.get('risk_threshold', 30.0)
                if risk_score >= threshold:
                    self.stats['high_risk'] = sum(1 for p in self.processes.values() 
                                                 if p['risk_score'] >= threshold)
                    # LOG HIGH-RISK DETECTION with full details
                    comm = proc.get('name', 'unknown')
                    logger.warning(f"🔴 HIGH RISK DETECTED: PID={pid} Process={comm} Risk={risk_score:.1f} Anomaly={anomaly_score:.1f}")
                    logger.warning(f"   Threshold: {threshold:.1f} | Base Risk: {base_risk_score:.1f} | "
                                 f"Connection Bonus: {connection_risk_bonus:.1f} | Total Syscalls: {proc.get('total_syscalls', 0)}")
                    logger.warning(f"   Recent syscalls: {', '.join(list(proc['syscalls'])[-10:])}")
                    if process_info:
                        logger.warning(f"   Process resources: CPU={process_info.get('cpu_percent', 0):.1f}% "
                                     f"Memory={process_info.get('memory_percent', 0):.1f}% "
                                     f"Threads={process_info.get('num_threads', 0)}")
                
                # Also log anomalies even if risk is low
                if anomaly_result and anomaly_result.is_anomaly and anomaly_score > 50:
                    comm = proc.get('name', 'unknown')
                    logger.warning(f"⚠️  ANOMALY DETECTED: PID={pid} Process={comm} AnomalyScore={anomaly_score:.1f}")
                    logger.warning(f"   Confidence: {anomaly_result.confidence:.2f} | Explanation: {anomaly_result.explanation}")
                    logger.warning(f"   Risk Score: {risk_score:.1f} | Total Syscalls: {proc.get('total_syscalls', 0)}")
        
        except AttributeError as e:
            # Missing attribute in event
            logger.error(f"❌ AttributeError processing event for PID={event.pid if hasattr(event, 'pid') else 'unknown'}: {e}")
            logger.error(f"   Event object may be malformed. Traceback: {traceback.format_exc()}")
        except KeyError as e:
            # Missing key in dictionary
            logger.error(f"❌ KeyError processing event for PID={event.pid if hasattr(event, 'pid') else 'unknown'}: {e}")
            logger.error(f"   Missing key in process data. Traceback: {traceback.format_exc()}")
        except ValueError as e:
            # Invalid value
            logger.error(f"❌ ValueError processing event for PID={event.pid if hasattr(event, 'pid') else 'unknown'}: {e}")
            logger.error(f"   Invalid data in event. Traceback: {traceback.format_exc()}")
        except Exception as e:
            # Log errors but don't crash the agent
            logger.error(f"❌ Unexpected error processing event for PID={event.pid if hasattr(event, 'pid') else 'unknown'}: {type(e).__name__}: {e}")
            logger.error(f"   Full traceback: {traceback.format_exc()}")
    
    def create_dashboard(self) -> Panel:
        """Create dashboard view"""
        with self.processes_lock:
            # Create table with more informative columns
            table = Table(title="🛡️ Security Agent - Live Monitoring", show_header=True)
            table.add_column("PID", style="cyan", width=6)
            table.add_column("Process", style="green", width=16)
            table.add_column("Risk", style="yellow", width=6, justify="right")
            table.add_column("Anomaly", style="magenta", width=7, justify="right")
            table.add_column("Syscalls", style="blue", width=7, justify="right")
            table.add_column("Recent Syscalls", style="cyan", width=35)  # Increased from 20 to 35
            table.add_column("Last Update", style="dim", width=8, justify="right")
            
            # Sort by risk score, but also show recently active processes
            current_time = time.time()
            sorted_procs = sorted(
                self.processes.items(),
                key=lambda x: (
                    x[1]['risk_score'],  # Primary: risk score
                    current_time - x[1].get('last_update', 0)  # Secondary: recency (negative for reverse)
                ),
                reverse=True
            )[:30]  # Top 30 (increased to show more processes)
            
            # Add processes or "Waiting for data..." message
            if sorted_procs:
                for pid, proc in sorted_procs:
                    risk = proc['risk_score']
                    risk_style = "red" if risk >= 50 else "yellow" if risk >= 30 else "green"
                    
                    # Check if process is still alive (recently active)
                    time_since_update = current_time - proc.get('last_update', 0)
                    is_active = time_since_update < 5.0  # Active if updated in last 5 seconds
                    
                    # Highlight recently active processes
                    process_name = proc['name'][:18]
                    if not is_active and time_since_update < 30:
                        process_name = f"{process_name} (recent)"
                    
                    # Get recent syscalls (last 8-10 unique syscalls for better visibility)
                    syscalls_list = list(proc['syscalls'])
                    if syscalls_list:
                        # Get unique recent syscalls (last 12-15, then take up to 10)
                        recent_syscalls = list(dict.fromkeys(syscalls_list[-15:]))[-10:]
                        recent_str = ", ".join(recent_syscalls)
                        # Allow up to 33 characters (35 width - 2 padding)
                        if len(recent_str) > 33:
                            recent_str = recent_str[:30] + "..."
                    else:
                        recent_str = "---"
                    
                    # Format last update time
                    if time_since_update < 60:
                        last_update_str = f"{int(time_since_update)}s"
                    elif time_since_update < 3600:
                        last_update_str = f"{int(time_since_update/60)}m"
                    else:
                        last_update_str = f"{int(time_since_update/3600)}h"
                    
                    # Add status indicator
                    status_indicator = "🟢" if is_active else "⚪" if time_since_update < 30 else "⚫"
                    
                    table.add_row(
                        str(pid),
                        f"{status_indicator} {process_name}",
                        f"[{risk_style}]{risk:.1f}[/]",
                        f"{proc['anomaly_score']:.2f}",
                        str(proc.get('total_syscalls', len(proc['syscalls']))),  # Show actual total
                        recent_str,
                        last_update_str
                    )
            else:
                # Show info panel when no data yet
                table.add_row(
                    "---",
                    "Waiting for syscalls...",
                    "---",
                    "---",
                    "---",
                    "---",
                    "---"
                )
            
            # Stats
            stats_text = (
                f"Processes: {self.stats['total_processes']} | "
                f"High Risk: {self.stats['high_risk']} | "
                f"Anomalies: {self.stats['anomalies']} | "
                f"C2: {self.stats['c2_beacons']} | "
                f"Scans: {self.stats['port_scans']} | "
                f"Syscalls: {self.stats['total_syscalls']}"
            )
            
            # Create info panel explaining scores (show FIRST)
            info_panel = self._create_info_panel()
            
            # Combine info FIRST, then table
            from rich.console import Group
            content = Group(info_panel, table)
            
            return Panel(content, title=stats_text, border_style="green")
    
    def _create_info_panel(self) -> Panel:
        """Create info panel explaining risk and anomaly scores (cached)"""
        # Cache the panel since it doesn't change (reduces blinking)
        if self._info_panel_cache is None:
            threshold = self.config.get('risk_threshold', 30.0)
            
            info_text = f"""
[bold cyan]📊 Score Guide:[/bold cyan]

[bold]Risk Score (0-100):[/bold]
  [green]🟢 0-{threshold:.0f}[/green]   Normal behavior - typical system operations
  [yellow]🟡 {threshold:.0f}-50[/yellow]  Suspicious - unusual patterns detected
  [red]🔴 50-100[/red]  High Risk - potential threat, investigate immediately

[bold]Anomaly Score (ML-based):[/bold]
  [green]0.00-10.00[/green]  Normal - matches learned behavior patterns
  [yellow]10.00-30.00[/yellow]  Unusual - deviates from baseline
  [red]30.00+[/red]      Anomalous - significant deviation, likely threat

[bold]How Scores Work:[/bold]
  • Risk Score: Based on syscall types, frequency, and behavioral patterns
  • Anomaly Score: ML model detects deviations from normal behavior
  • Both scores update in real-time as processes execute syscalls
  • Scores reset when agent restarts (not persisted between runs)

[bold]Current Threshold:[/bold] {threshold:.1f} (configurable with --threshold)
"""
            
            self._info_panel_cache = Panel(info_text.strip(), title="ℹ️  Score Information", border_style="blue")
        
        return self._info_panel_cache
    
    def run_dashboard(self):
        """Run with dashboard"""
        # Show startup info
        self.console.print("\n[bold green]🛡️  Security Agent Starting...[/bold green]")
        self.console.print("[yellow]ℹ️  Score information will be displayed in the dashboard[/yellow]")
        self.console.print(f"[cyan]📝 Log file: {log_file_path}[/cyan]\n")
        logger.info("="*60)
        logger.info("Security Agent Starting")
        logger.info(f"Log file: {log_file_path}")
        logger.info("="*60)
        time.sleep(2)  # Give user time to read startup message
        
        if not self.start():
            return
        
        try:
            # Use screen=True for better rendering and reduce refresh rate to minimize blinking
            # refresh_per_second=2 means update every 0.5 seconds (less frequent = less blinking)
            with Live(self.create_dashboard(), refresh_per_second=2, screen=True, transient=False) as live:
                while self.running:
                    # Update dashboard - create_dashboard() is called here
                    live.update(self.create_dashboard())
                    # Sleep matches refresh rate to avoid unnecessary updates
                    time.sleep(0.5)
        except KeyboardInterrupt:
            logger.info("Agent stopped by user (Ctrl+C)")
        except Exception as e:
            logger.error(f"Fatal error in dashboard: {e}", exc_info=True)
            raise
        finally:
            logger.info("Shutting down agent...")
            self.stop()
            logger.info("Agent shutdown complete")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Simple Security Agent")
    parser.add_argument('--collector', choices=['ebpf', 'auditd'], default='auditd',
                       help='Collector to use (default: auditd)')
    parser.add_argument('--threshold', type=float, default=30.0,
                       help='Risk threshold (default: 30.0)')
    parser.add_argument('--config', type=str, help='Config file path')
    
    args = parser.parse_args()
    
    # Load config
    config = {'collector': args.collector, 'risk_threshold': args.threshold}
    if args.config and os.path.exists(args.config):
        try:
            import yaml
            with open(args.config) as f:
                config.update(yaml.safe_load(f))
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
    
    # Create and run agent
    try:
        agent = SimpleSecurityAgent(config)
        agent.run_dashboard()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n❌ Fatal error: {e}")
        print(f"📝 Check log file for details: {log_file_path}")
        sys.exit(1)


if __name__ == '__main__':
    main()

