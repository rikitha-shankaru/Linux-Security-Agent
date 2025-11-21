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
        
        # Cache info panel to prevent re-creation (reduces blinking)
        self._info_panel_cache = None
        
        # Initialize ML if available
        if ML_AVAILABLE:
            try:
                self.anomaly_detector = EnhancedAnomalyDetector(config)
                # Try to load pre-trained models
                try:
                    self.anomaly_detector._load_models()
                    if self.anomaly_detector.is_fitted:
                        logger.info("✅ Loaded pre-trained ML models")
                except Exception:
                    logger.info("ℹ️ No pre-trained models found - train with --train-models")
            except Exception as e:
                logger.warning(f"ML detector not available: {e}")
    
    def start(self) -> bool:
        """Start the agent"""
        # Validate system
        is_valid, errors = validate_system(self.config)
        if not is_valid:
            print_validation_results(False, errors)
            return False
        
        # Get collector (default to eBPF, fallback to auditd)
        collector_type = self.config.get('collector', 'ebpf')
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
            
            # Calculate anomaly score FIRST (needed for risk score)
            anomaly_score = 0.0
            if self.anomaly_detector:
                # Try to load models if not fitted
                if not self.anomaly_detector.is_fitted:
                    try:
                        self.anomaly_detector._load_models()
                    except Exception:
                        pass  # Models not available
                
                if self.anomaly_detector.is_fitted:
                    try:
                        # Get process info for ML
                        process_info = {}
                        try:
                            p = psutil.Process(pid)
                            process_info = {
                                'cpu_percent': p.cpu_percent(interval=0.1) if p.is_running() else 0.0,
                                'memory_percent': p.memory_percent() if p.is_running() else 0.0,
                                'num_threads': p.num_threads() if p.is_running() else 0
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                        
                        # CORRECT function signature: (syscalls, process_info, pid)
                        anomaly_result = self.anomaly_detector.detect_anomaly_ensemble(
                            syscall_list, process_info, pid
                        )
                        anomaly_score = abs(anomaly_result.anomaly_score)  # Use absolute value
                        proc['anomaly_score'] = anomaly_score
                        if anomaly_result.is_anomaly:
                            self.stats['anomalies'] += 1
                    except Exception as e:
                        logger.debug(f"ML detection failed for PID {pid}: {e}")
                        anomaly_score = 0.0
                        proc['anomaly_score'] = 0.0
                else:
                    # ML not trained yet - set to 0.00
                    anomaly_score = 0.0
                    proc['anomaly_score'] = 0.0
            else:
                anomaly_score = 0.0
                proc['anomaly_score'] = 0.0
            
            # Calculate risk score WITH anomaly score included
            risk_score = self.risk_scorer.update_risk_score(
                pid, syscall_list, process_info, anomaly_score
            )
            proc['risk_score'] = risk_score
            
            # Update high risk count
            threshold = self.config.get('risk_threshold', 30.0)
            if risk_score >= threshold:
                self.stats['high_risk'] = sum(1 for p in self.processes.values() 
                                             if p['risk_score'] >= threshold)
    
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
        self.console.print("[yellow]ℹ️  Score information will be displayed in the dashboard[/yellow]\n")
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

