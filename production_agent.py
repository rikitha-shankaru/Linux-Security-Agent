#!/usr/bin/env python3
"""
Production-Ready Linux Security Agent
Combines all components for enterprise deployment
"""

import os
import sys
import time
import json
import signal
import logging
import argparse
import threading
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

# Import our enhanced components
from ebpf_monitor import EnhancedEBPFMonitor, SyscallEvent
from advanced_risk_engine import AdvancedRiskEngine, ProcessProfile
from mitre_attack_detector import MITREAttackDetector, ThreatDetection
from cloud_backend import CloudBackendManager
from performance_optimizer import PerformanceOptimizer, OptimizationConfig
from security_hardener import SecurityHardener, SecurityConfig

# Import original components
from security_agent import SyscallRiskScorer, ProcessMonitor
from anomaly_detector import AnomalyDetector
from action_handler import ActionHandler, ActionType

class ProductionSecurityAgent:
    """Production-ready security agent with all advanced features"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.running = False
        
        # Initialize components
        self.ebpf_monitor = None
        self.risk_engine = AdvancedRiskEngine()
        self.attack_detector = MITREAttackDetector()
        self.anomaly_detector = None
        self.action_handler = None
        self.cloud_backend = CloudBackendManager(config)
        
        # Performance optimization
        perf_config = OptimizationConfig(
            max_threads=config.get('max_threads', 4),
            max_processes=config.get('max_processes', 2),
            queue_size_limit=config.get('queue_size_limit', 10000),
            batch_size=config.get('batch_size', 100),
            memory_threshold=config.get('memory_threshold', 80.0),
            cpu_threshold=config.get('cpu_threshold', 80.0),
            gc_threshold=config.get('gc_threshold', 1000),
            enable_profiling=config.get('enable_profiling', True),
            enable_caching=config.get('enable_caching', True),
            cache_size=config.get('cache_size', 1000),
            compression_enabled=config.get('compression_enabled', True)
        )
        self.performance_optimizer = PerformanceOptimizer(perf_config)
        
        # Security hardening
        security_config = SecurityConfig(
            enable_tamper_protection=config.get('enable_tamper_protection', True),
            enable_integrity_checking=config.get('enable_integrity_checking', True),
            enable_process_protection=config.get('enable_process_protection', True),
            enable_file_monitoring=config.get('enable_file_monitoring', True),
            enable_memory_protection=config.get('enable_memory_protection', True),
            encryption_key=config.get('encryption_key'),
            integrity_hash=config.get('integrity_hash'),
            protected_files=config.get('protected_files', [
                "/usr/bin/python3",
                "/usr/bin/security_agent",
                "/etc/security_agent/config.json"
            ]),
            protected_processes=config.get('protected_processes', [
                "security_agent",
                "systemd",
                "sshd"
            ]),
            alert_threshold=config.get('alert_threshold', 7.0)
        )
        self.security_hardener = SecurityHardener(security_config)
        
        # Legacy components for compatibility
        self.legacy_risk_scorer = SyscallRiskScorer()
        self.legacy_monitor = ProcessMonitor(self.legacy_risk_scorer)
        
        # Configuration
        self.config_file = self.config.get('config_file', '/etc/security-agent/config.json')
        self.log_file = self.config.get('log_file', '/var/log/security-agent.log')
        self.data_dir = self.config.get('data_dir', '/var/lib/security-agent')
        
        # Performance settings
        self.batch_size = self.config.get('batch_size', 1000)
        self.update_interval = self.config.get('update_interval', 1.0)
        
        # Setup logging
        self._setup_logging()
        
        # Create data directory
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self._load_config()
        
        # Initialize components
        self._initialize_components()
        
    def _setup_logging(self):
        """Setup production logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('security_agent')
        
    def _load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    self.config.update(file_config)
                self.logger.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                self.logger.error(f"Error loading config: {e}")
        else:
            self.logger.warning(f"Config file not found: {self.config_file}")
    
    def _initialize_components(self):
        """Initialize all components"""
        try:
            # Initialize eBPF monitor
            if self.config.get('use_ebpf', True):
                self.ebpf_monitor = EnhancedEBPFMonitor(self.config)
                self.logger.info("eBPF monitor initialized")
            
            # Initialize anomaly detector
            if self.config.get('use_anomaly_detection', True):
                self.anomaly_detector = AnomalyDetector()
                if not self.anomaly_detector.load_model():
                    self.logger.info("Training anomaly detection model...")
                    training_data = self.anomaly_detector.generate_training_data(1000)
                    self.anomaly_detector.fit(training_data)
                self.logger.info("Anomaly detector initialized")
            
            # Initialize action handler
            if self.config.get('use_actions', True):
                action_config = {
                    'warn_threshold': self.config.get('warn_threshold', 30.0),
                    'freeze_threshold': self.config.get('freeze_threshold', 70.0),
                    'kill_threshold': self.config.get('kill_threshold', 90.0),
                    'enable_warnings': self.config.get('enable_warnings', True),
                    'enable_freeze': self.config.get('enable_freeze', True),
                    'enable_kill': self.config.get('enable_kill', False),
                    'log_file': self.log_file
                }
                self.action_handler = ActionHandler(action_config)
                self.logger.info("Action handler initialized")
            
        # Load baselines
        baseline_file = os.path.join(self.data_dir, 'baselines.pkl')
        self.risk_engine.load_baselines(baseline_file)
        
        # Start cloud backend
        self.cloud_backend.start()
        
        # Start performance optimization
        self.performance_optimizer.start()
        
        # Create optimized event processor
        self.event_processor = self.performance_optimizer.create_event_processor(
            self._process_syscall_event
        )
        self.event_processor.start()
        
        # Start security hardening
        self.security_hardener.start()
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}")
            raise
    
    def start_monitoring(self):
        """Start the security monitoring"""
        self.running = True
        self.logger.info("Starting Production Security Agent...")
        
        # Start eBPF monitoring if available
        if self.ebpf_monitor:
            self._start_ebpf_monitoring()
        else:
            self._start_legacy_monitoring()
    
    def _start_ebpf_monitoring(self):
        """Start eBPF-based monitoring"""
        def event_callback(event: SyscallEvent):
            try:
                # Update risk engine
                self.risk_engine.add_syscall(event.pid, event.syscall_name, event.args)
                
                # Update process info
                self.risk_engine.update_process(
                    event.pid, event.comm, "", "", event.ppid, 0, 0
                )
                
                # Detect threats
                if hasattr(self, '_current_syscalls'):
                    self._current_syscalls[event.pid].append(event.syscall_name)
                else:
                    self._current_syscalls = {event.pid: [event.syscall_name]}
                
                # Check for threats every 100 syscalls
                if len(self._current_syscalls[event.pid]) >= 100:
                    syscalls = self._current_syscalls[event.pid]
                    detections = self.attack_detector.detect_threats(
                        event.pid, event.comm, syscalls, [], []
                    )
                    
                    if detections:
                        self._handle_threat_detections(detections)
                    
                    self._current_syscalls[event.pid] = []
                
                # Send monitoring data to cloud
                risk_score = self.risk_engine.calculate_behavioral_risk(event.pid)
                self.cloud_backend.send_process_monitoring(event.pid, event.comm, risk_score)
                
            except Exception as e:
                self.logger.error(f"Error processing event: {e}")
    
    def _process_syscall_event_optimized(self, event: SyscallEvent):
        """Process a syscall event using optimized event processor"""
        self.event_processor.process_event(event)
        
        # Start monitoring in separate thread
        monitor_thread = threading.Thread(
            target=self.ebpf_monitor.start_monitoring,
            args=(self._process_syscall_event_optimized,),
            daemon=True
        )
        monitor_thread.start()
        
        # Main monitoring loop
        while self.running:
            try:
                self._update_dashboard()
                time.sleep(self.update_interval)
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1)
    
    def _start_legacy_monitoring(self):
        """Start legacy monitoring as fallback"""
        self.logger.warning("Using legacy monitoring (eBPF not available)")
        
        while self.running:
            try:
                # Use legacy monitoring
                import psutil
                for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        
                        # Simulate syscalls
                        syscalls = self._simulate_syscalls_for_process(proc)
                        
                        if syscalls:
                            self.risk_engine.add_syscall(pid, syscalls[0])
                            self.risk_engine.update_process(pid, name, "", "", 0, 0, 0)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                self._update_dashboard()
                time.sleep(self.update_interval)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Error in legacy monitoring: {e}")
                time.sleep(1)
    
    def _simulate_syscalls_for_process(self, proc) -> List[str]:
        """Simulate system calls for process (legacy method)"""
        syscalls = []
        try:
            name = proc.info['name']
            if 'python' in name.lower():
                syscalls.extend(['read', 'write', 'open', 'close'])
            elif 'bash' in name.lower():
                syscalls.extend(['read', 'write', 'execve'])
            else:
                syscalls.extend(['read', 'write', 'open', 'close'])
        except:
            pass
        return syscalls
    
    def _handle_threat_detections(self, detections: List[ThreatDetection]):
        """Handle threat detections"""
        for detection in detections:
            self.logger.warning(
                f"THREAT DETECTED: {detection.technique_name} "
                f"({detection.technique_id}) in PID {detection.process_pid} "
                f"({detection.process_name}) - Confidence: {detection.confidence:.2f}"
            )
            
            # Send threat detection to cloud
            self.cloud_backend.send_threat_detection(
                detection.process_pid,
                detection.process_name,
                detection.risk_score,
                detection.technique_id,
                f"Threat detected: {detection.technique_name}"
            )
            
            # Take action if configured
            if self.action_handler and detection.risk_score >= 7:
                risk_score = detection.risk_score * 10  # Scale to 0-100
                self.action_handler.take_action(
                    detection.process_pid,
                    detection.process_name,
                    risk_score,
                    detection.confidence
                )
                
                # Send action taken to cloud
                self.cloud_backend.send_action_taken(
                    detection.process_pid,
                    detection.process_name,
                    "action_taken",
                    f"Risk score {risk_score} exceeded threshold"
                )
    
    def _update_dashboard(self):
        """Update the dashboard display"""
        if not self.config.get('show_dashboard', True):
            return
        
        # Clear screen
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Get high-risk processes
        high_risk_processes = self.risk_engine.get_high_risk_processes(30.0)
        
        # Get active threats
        active_threats = self.attack_detector.get_active_threats()
        
        # Display dashboard
        print("=" * 80)
        print("🛡️  PRODUCTION SECURITY AGENT - ENTERPRISE EDR")
        print("=" * 80)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Processes Monitored: {len(self.risk_engine.processes)}")
        print(f"Active Threats: {len(active_threats)}")
        print()
        
        # Display high-risk processes
        if high_risk_processes:
            print("🚨 HIGH RISK PROCESSES:")
            print("-" * 80)
            for pid, process, risk_score in high_risk_processes[:10]:
                risk_level = self.risk_engine.get_risk_level(risk_score)
                print(f"PID {pid:6d} | {process.name:20s} | Risk: {risk_score:6.1f} ({risk_level})")
            print()
        
        # Display active threats
        if active_threats:
            print("⚠️  ACTIVE THREATS:")
            print("-" * 80)
            for pid, detections in list(active_threats.items())[:5]:
                for detection in detections:
                    print(f"PID {pid:6d} | {detection.technique_name:30s} | "
                          f"Confidence: {detection.confidence:.2f} | Risk: {detection.risk_score}")
            print()
        
        # Display system stats
        syscall_stats = self.ebpf_monitor.get_syscall_stats() if self.ebpf_monitor else {}
        if syscall_stats:
            print("📊 SYSTEM CALL STATISTICS:")
            print("-" * 80)
            for syscall, count in sorted(syscall_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"{syscall:20s} | {count:8d} calls")
            print()
    
    def stop_monitoring(self):
        """Stop the security monitoring"""
        self.running = False
        
        # Stop eBPF monitoring
        if self.ebpf_monitor:
            self.ebpf_monitor.stop_monitoring()
        
        # Save baselines
        baseline_file = os.path.join(self.data_dir, 'baselines.pkl')
        self.risk_engine.save_baselines(baseline_file)
        
        # Stop cloud backend
        self.cloud_backend.stop()
        
        # Stop performance optimizer
        self.performance_optimizer.stop()
        if self.event_processor:
            self.event_processor.stop()
        
        # Stop security hardening
        self.security_hardener.stop()
        
        self.logger.info("Security Agent stopped")
    
    def get_status(self) -> Dict:
        """Get agent status"""
        status = {
            'running': self.running,
            'processes_monitored': len(self.risk_engine.processes),
            'active_threats': len(self.attack_detector.active_threats),
            'total_detections': len(self.attack_detector.detection_history),
            'ebpf_available': self.ebpf_monitor is not None,
            'anomaly_detection': self.anomaly_detector is not None,
            'action_handler': self.action_handler is not None
        }
        
        # Add performance metrics
        perf_report = self.performance_optimizer.get_performance_report()
        status['performance'] = perf_report
        
        # Add security report
        security_report = self.security_hardener.get_security_report()
        status['security'] = security_report
        
        return status
    
    def export_data(self, format: str = 'json') -> str:
        """Export monitoring data"""
        data = {
            'status': self.get_status(),
            'high_risk_processes': [
                {
                    'pid': pid,
                    'name': process.name,
                    'risk_score': self.risk_engine.calculate_behavioral_risk(pid),
                    'risk_level': self.risk_engine.get_risk_level(
                        self.risk_engine.calculate_behavioral_risk(pid)
                    )
                }
                for pid, process, _ in self.risk_engine.get_high_risk_processes(30.0)
            ],
            'active_threats': [
                {
                    'pid': pid,
                    'detections': [asdict(d) for d in detections]
                }
                for pid, detections in self.attack_detector.get_active_threats().items()
            ],
            'threat_summary': self.attack_detector.get_threat_summary()
        }
        
        if format == 'json':
            return json.dumps(data, indent=2)
        return str(data)

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global agent
    if agent:
        agent.stop_monitoring()
    sys.exit(0)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Production Security Agent')
    parser.add_argument('--config', type=str, default='/etc/security-agent/config.json',
                       help='Configuration file path')
    parser.add_argument('--log-file', type=str, default='/var/log/security-agent.log',
                       help='Log file path')
    parser.add_argument('--data-dir', type=str, default='/var/lib/security-agent',
                       help='Data directory path')
    parser.add_argument('--no-dashboard', action='store_true',
                       help='Disable dashboard display')
    parser.add_argument('--no-ebpf', action='store_true',
                       help='Disable eBPF monitoring')
    parser.add_argument('--no-anomaly-detection', action='store_true',
                       help='Disable anomaly detection')
    parser.add_argument('--no-actions', action='store_true',
                       help='Disable automated actions')
    parser.add_argument('--export', type=str, choices=['json', 'csv'],
                       help='Export data and exit')
    
    args = parser.parse_args()
    
    # Check if running as root (required for eBPF)
    if not args.no_ebpf and os.geteuid() != 0:
        print("Error: eBPF monitoring requires root privileges")
        print("Run with sudo or use --no-ebpf flag")
        sys.exit(1)
    
    # Create configuration
    config = {
        'config_file': args.config,
        'log_file': args.log_file,
        'data_dir': args.data_dir,
        'show_dashboard': not args.no_dashboard,
        'use_ebpf': not args.no_ebpf,
        'use_anomaly_detection': not args.no_anomaly_detection,
        'use_actions': not args.no_actions
    }
    
    # Create and start agent
    global agent
    agent = ProductionSecurityAgent(config)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if args.export:
            # Export data and exit
            data = agent.export_data(args.export)
            print(data)
        else:
            # Start monitoring
            agent.start_monitoring()
    except KeyboardInterrupt:
        agent.stop_monitoring()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
