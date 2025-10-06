#!/usr/bin/env python3
"""
Linux Security Agent - macOS Compatible Version
This version works on macOS using psutil for process monitoring
"""

import os
import sys
import json
import time
import signal
import argparse
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import psutil
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich import box

# Import our modules
from security_agent import SyscallRiskScorer, ProcessMonitor

class MacSecurityAgent:
    """macOS-compatible security agent"""
    
    def __init__(self, args):
        self.args = args
        self.risk_scorer = SyscallRiskScorer()
        self.monitor = ProcessMonitor(self.risk_scorer)
        self.console = Console()
        self.running = False
        
        # macOS-specific process monitoring
        self.process_cache = {}
        self.last_scan = time.time()
        
    def start_monitoring(self):
        """Start the security monitoring on macOS"""
        self.running = True
        self.console.print("[bold green]Starting macOS Security Agent...[/bold green]")
        self.console.print("[yellow]Note: Running in macOS compatibility mode[/yellow]")
        
        if self.args.timeout > 0:
            self.console.print(f"[blue]Will run for {self.args.timeout} seconds[/blue]")
        else:
            self.console.print("[blue]Press Ctrl+C to stop monitoring[/blue]")
        
        start_time = time.time()
        
        while self.running:
            try:
                self._scan_processes()
                self._display_results()
                time.sleep(1)
                
                # Check timeout
                if self.args.timeout > 0 and (time.time() - start_time) >= self.args.timeout:
                    self.console.print(f"\n[yellow]Timeout reached ({self.args.timeout}s), stopping...[/yellow]")
                    break
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Stopping security agent...[/yellow]")
                break
            except Exception as e:
                self.console.print(f"[red]Monitoring error: {e}[/red]")
                time.sleep(1)
    
    def _scan_processes(self):
        """Scan processes and simulate system calls"""
        current_time = time.time()
        
        # Get all processes
        for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cpu_percent', 'memory_percent']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                
                # Skip system processes and our own process
                if pid <= 1 or pid == os.getpid():
                    continue
                
                # Simulate system calls based on process activity
                syscalls = self._simulate_syscalls_for_process(proc)
                
                if syscalls:
                    self.monitor.update_process_risk(pid, syscalls)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Cleanup old processes
        self.monitor.cleanup_old_processes()
        self.last_scan = current_time
    
    def _simulate_syscalls_for_process(self, proc) -> List[str]:
        """Simulate system calls for a process based on its characteristics"""
        syscalls = []
        
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            cpu_percent = proc.info.get('cpu_percent', 0) or 0
            memory_percent = proc.info.get('memory_percent', 0) or 0
            
            # Base syscalls for all processes
            syscalls.extend(['read', 'write', 'open', 'close'])
            
            # Add syscalls based on process characteristics
            if 'python' in name.lower():
                syscalls.extend(['read', 'write', 'open', 'close'])
                # Simulate suspicious behavior occasionally
                if pid % 100 == 0:  # 1% chance
                    syscalls.extend(['execve', 'chmod', 'setuid'])
            elif 'bash' in name.lower() or 'zsh' in name.lower():
                syscalls.extend(['read', 'write', 'execve'])
                if pid % 50 == 0:  # 2% chance
                    syscalls.extend(['chmod', 'setuid', 'ptrace'])
            elif 'ls' in name.lower():
                syscalls.extend(['read', 'stat', 'getdents'])
            elif 'cat' in name.lower():
                syscalls.extend(['read', 'write', 'open', 'close'])
            elif 'curl' in name.lower() or 'wget' in name.lower():
                syscalls.extend(['socket', 'connect', 'send', 'recv'])
            elif 'docker' in name.lower():
                syscalls.extend(['clone', 'mount', 'umount', 'chroot'])
            elif 'chrome' in name.lower() or 'safari' in name.lower():
                syscalls.extend(['mmap', 'munmap', 'socket', 'connect'])
            elif 'finder' in name.lower():
                syscalls.extend(['read', 'stat', 'getdents', 'open'])
            elif 'terminal' in name.lower():
                syscalls.extend(['read', 'write', 'ioctl', 'select'])
            
            # Add syscalls based on resource usage
            if cpu_percent > 50:
                syscalls.extend(['nanosleep', 'sched_yield'])
            if memory_percent > 10:
                syscalls.extend(['mmap', 'munmap', 'brk'])
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return syscalls
    
    def _display_results(self):
        """Display monitoring results"""
        if self.args.dashboard:
            self._display_dashboard()
        elif self.args.output == 'json':
            self._output_json()
        else:
            self._output_console()
    
    def _display_dashboard(self):
        """Display real-time dashboard"""
        # Clear screen
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Create dashboard
        table = Table(title="macOS Security Agent - Process Risk Dashboard", box=box.ROUNDED)
        table.add_column("PID", style="cyan", no_wrap=True)
        table.add_column("Process Name", style="magenta")
        table.add_column("Risk Score", style="red")
        table.add_column("Syscalls", style="yellow")
        table.add_column("Last Update", style="green")
        
        # Add processes to table
        for pid, process in sorted(self.monitor.processes.items(), 
                                 key=lambda x: x[1].get('risk_score', 0) or 0, reverse=True):
            risk_score = process.get('risk_score', 0) or 0
            risk_color = "red" if risk_score >= 50 else "yellow" if risk_score >= 20 else "green"
            
            table.add_row(
                str(pid),
                process['name'],
                f"[{risk_color}]{risk_score:.1f}[/{risk_color}]",
                str(process['syscall_count']),
                time.strftime("%H:%M:%S", time.localtime(process['last_update']))
            )
        
        # Display table
        self.console.print(table)
        
        # Display high-risk processes
        high_risk = self.monitor.get_high_risk_processes(self.args.threshold)
        if high_risk:
            self.console.print(f"\n[bold red]High Risk Processes (>{self.args.threshold}):[/bold red]")
            for pid, name, score, anomaly_score in high_risk:
                anomaly_info = f", Anomaly: {anomaly_score:.2f}" if anomaly_score != 0.0 else ""
                self.console.print(f"  PID {pid}: {name} (Risk: {score:.1f}{anomaly_info})")
        
        # Display system info
        self.console.print(f"\n[bold blue]System Info:[/bold blue]")
        self.console.print(f"  Processes monitored: {len(self.monitor.processes)}")
        self.console.print(f"  Total syscalls: {sum(self.monitor.syscall_counts.values())}")
        self.console.print(f"  Last scan: {time.strftime('%H:%M:%S', time.localtime(self.last_scan))}")
    
    def _output_console(self):
        """Output to console"""
        high_risk = self.monitor.get_high_risk_processes(self.args.threshold)
        if high_risk:
            for pid, name, score, anomaly_score in high_risk:
                anomaly_info = f", Anomaly: {anomaly_score:.2f}" if anomaly_score != 0.0 else ""
                self.console.print(f"[red]HIGH RISK[/red] PID {pid}: {name} (Risk: {score:.1f}{anomaly_info})")
    
    def _output_json(self):
        """Output JSON format"""
        output = {
            'timestamp': datetime.now().isoformat(),
            'platform': 'macOS',
            'processes': []
        }
        
        for pid, process in self.monitor.processes.items():
            output['processes'].append({
                'pid': pid,
                'name': process['name'],
                'risk_score': process.get('risk_score', 0) or 0,
                'anomaly_score': process.get('anomaly_score', 0.0),
                'syscall_count': process['syscall_count'],
                'last_update': process['last_update']
            })
        
        print(json.dumps(output, indent=2))
    
    def stop_monitoring(self):
        """Stop the security monitoring"""
        self.running = False
        self.console.print("\n[bold red]macOS Security Agent stopped[/bold red]")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global agent
    if agent:
        agent.stop_monitoring()
    sys.exit(0)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='macOS Security Agent')
    parser.add_argument('--threshold', type=float, default=50.0,
                       help='Risk score threshold for alerts (default: 50.0)')
    parser.add_argument('--output', choices=['console', 'json'], default='console',
                       help='Output format (default: console)')
    parser.add_argument('--dashboard', action='store_true',
                       help='Display real-time dashboard')
    parser.add_argument('--timeout', type=int, default=0,
                       help='Run for specified seconds then exit (0 = run indefinitely)')
    
    args = parser.parse_args()
    
    # Create and start agent
    global agent
    agent = MacSecurityAgent(args)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        agent.start_monitoring()
    except KeyboardInterrupt:
        agent.stop_monitoring()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
