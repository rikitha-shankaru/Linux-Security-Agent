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
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
from datetime import datetime

# Add core to path
_core_dir = os.path.dirname(os.path.abspath(__file__))
if _core_dir not in sys.path:
    sys.path.insert(0, _core_dir)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('security_agent.simple')

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
        
        # Process tracking
        self.processes = {}  # pid -> {name, syscalls, risk_score, anomaly_score, last_update}
        self.processes_lock = threading.Lock()
        
        # Stats
        self.stats = {
            'total_processes': 0,
            'high_risk': 0,
            'anomalies': 0,
            'total_syscalls': 0
        }
        
        # Initialize ML if available
        if ML_AVAILABLE:
            try:
                self.anomaly_detector = EnhancedAnomalyDetector(config)
            except Exception as e:
                logger.warning(f"ML detector not available: {e}")
    
    def start(self) -> bool:
        """Start the agent"""
        # Validate system
        is_valid, errors = validate_system(self.config)
        if not is_valid:
            print_validation_results(False, errors)
            return False
        
        # Get collector
        collector_type = self.config.get('collector', 'auditd')
        self.collector = get_collector(self.config, preferred=collector_type)
        if not self.collector:
            logger.error("No collector available")
            return False
        
        # Start collector
        if not self.collector.start_monitoring(self._handle_event):
            logger.error("Failed to start collector")
            return False
        
        self.running = True
        logger.info(f"✅ Agent started with {self.collector.get_name()}")
        return True
    
    def stop(self):
        """Stop the agent"""
        self.running = False
        if self.collector:
            self.collector.stop_monitoring()
        logger.info("Agent stopped")
    
    def _handle_event(self, event: SyscallEvent):
        """Handle syscall event"""
        if not self.running:
            return
        
        pid = event.pid
        syscall = event.syscall
        
        with self.processes_lock:
            # Update process info
            if pid not in self.processes:
                self.processes[pid] = {
                    'name': event.comm or f'pid_{pid}',
                    'syscalls': deque(maxlen=100),
                    'risk_score': 0.0,
                    'anomaly_score': 0.0,
                    'last_update': time.time()
                }
                self.stats['total_processes'] += 1
            
            proc = self.processes[pid]
            proc['syscalls'].append(syscall)
            proc['last_update'] = time.time()
            self.stats['total_syscalls'] += 1
            
            # Calculate risk score
            syscall_list = list(proc['syscalls'])
            risk_score = self.risk_scorer.update_risk_score(pid, syscall_list)
            proc['risk_score'] = risk_score
            
            # Calculate anomaly score (if ML available)
            if self.anomaly_detector:
                try:
                    anomaly_result = self.anomaly_detector.detect_anomaly_ensemble(
                        pid, syscall_list, {}
                    )
                    proc['anomaly_score'] = anomaly_result.anomaly_score
                    if anomaly_result.is_anomaly:
                        self.stats['anomalies'] += 1
                except Exception:
                    pass  # ML may not be trained yet
            
            # Update high risk count
            threshold = self.config.get('risk_threshold', 30.0)
            if risk_score >= threshold:
                self.stats['high_risk'] = sum(1 for p in self.processes.values() 
                                             if p['risk_score'] >= threshold)
    
    def create_dashboard(self) -> Panel:
        """Create dashboard view"""
        with self.processes_lock:
            # Create table
            table = Table(title="🛡️ Security Agent - Live Monitoring", show_header=True)
            table.add_column("PID", style="cyan")
            table.add_column("Process", style="green")
            table.add_column("Risk", style="yellow")
            table.add_column("Anomaly", style="magenta")
            table.add_column("Syscalls", style="blue")
            
            # Sort by risk score
            sorted_procs = sorted(
                self.processes.items(),
                key=lambda x: x[1]['risk_score'],
                reverse=True
            )[:20]  # Top 20
            
            for pid, proc in sorted_procs:
                risk = proc['risk_score']
                risk_style = "red" if risk >= 50 else "yellow" if risk >= 30 else "green"
                
                table.add_row(
                    str(pid),
                    proc['name'][:30],
                    f"[{risk_style}]{risk:.1f}[/]",
                    f"{proc['anomaly_score']:.2f}",
                    str(len(proc['syscalls']))
                )
            
            # Stats
            stats_text = (
                f"Processes: {self.stats['total_processes']} | "
                f"High Risk: {self.stats['high_risk']} | "
                f"Anomalies: {self.stats['anomalies']} | "
                f"Syscalls: {self.stats['total_syscalls']}"
            )
            
            return Panel(table, title=stats_text, border_style="green")
    
    def run_dashboard(self):
        """Run with dashboard"""
        if not self.start():
            return
        
        try:
            with Live(self.create_dashboard(), refresh_per_second=2, screen=False) as live:
                while self.running:
                    live.update(self.create_dashboard())
                    time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


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
    agent = SimpleSecurityAgent(config)
    agent.run_dashboard()


if __name__ == '__main__':
    main()

