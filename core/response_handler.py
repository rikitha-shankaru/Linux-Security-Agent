#!/usr/bin/env python3
"""
Response Handler - Automated Threat Response
Implements blocking, isolation, and remediation capabilities
"""

import os
import json
import signal
import subprocess
import logging
import threading
from typing import Dict, Optional, List, Any
from enum import Enum
from datetime import datetime
from pathlib import Path

logger = logging.getLogger('security_agent.response')

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available - some response actions may be limited")


class ResponseAction(Enum):
    """Response action types"""
    WARN = "warn"
    FREEZE = "freeze"
    ISOLATE = "isolate"
    KILL = "kill"
    QUARANTINE = "quarantine"
    NETWORK_BLOCK = "network_block"


class ResponseHandler:
    """Handles automated response actions"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get('enable_responses', False)
        self.kill_enabled = self.config.get('enable_kill', False)
        self.isolation_enabled = self.config.get('enable_isolation', False)
        self.network_block_enabled = self.config.get('enable_network_block', False)
        
        # Action thresholds
        self.warn_threshold = self.config.get('warn_threshold', 60.0)
        self.freeze_threshold = self.config.get('freeze_threshold', 80.0)
        self.isolate_threshold = self.config.get('isolate_threshold', 90.0)
        self.kill_threshold = self.config.get('kill_threshold', 95.0)
        
        # Action log
        default_log_dir = Path.home() / '.cache' / 'security_agent'
        default_log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.action_log_file = default_log_dir / 'response_actions.log'
        
        # Track frozen/isolated processes
        self.frozen_processes: Dict[int, datetime] = {}
        self.isolated_processes: Dict[int, Dict[str, Any]] = {}
        self.killed_processes: Dict[int, datetime] = {}
        
        # Thread lock for thread safety
        self.action_lock = threading.Lock()
        
        logger.info(f"Response handler initialized (enabled={self.enabled}, "
                   f"kill={self.kill_enabled}, isolate={self.isolation_enabled})")
    
    def take_action(self, pid: int, process_name: str, risk_score: float, 
                   anomaly_score: float = 0.0, reason: str = "") -> Optional[ResponseAction]:
        """Take appropriate action based on risk score"""
        if not self.enabled:
            return None
        
        with self.action_lock:
            # Check if process still exists
            if not self._process_exists(pid):
                return None
            
            # Determine action based on thresholds
            action = None
            
            if risk_score >= self.kill_threshold and self.kill_enabled:
                action = self._kill_process(pid, process_name, risk_score, reason)
            elif risk_score >= self.isolate_threshold and self.isolation_enabled:
                action = self._isolate_process(pid, process_name, risk_score, reason)
            elif risk_score >= self.freeze_threshold:
                action = self._freeze_process(pid, process_name, risk_score, reason)
            elif risk_score >= self.warn_threshold:
                action = self._warn_process(pid, process_name, risk_score, reason)
            
            if action:
                self._log_action(action, pid, process_name, risk_score, reason)
            
            return action
    
    def _process_exists(self, pid: int) -> bool:
        """Check if process exists"""
        try:
            if PSUTIL_AVAILABLE:
                return psutil.pid_exists(pid)
            else:
                # Fallback: try to send signal 0 (doesn't actually send, just checks)
                os.kill(pid, 0)
                return True
        except (OSError, ProcessLookupError):
            return False
    
    def _warn_process(self, pid: int, process_name: str, risk_score: float, 
                     reason: str) -> ResponseAction:
        """Send warning signal to process"""
        try:
            # Send SIGUSR1 as warning (if process handles it)
            os.kill(pid, signal.SIGUSR1)
            logger.warning(f"⚠️ WARN: PID {pid} ({process_name}) - Risk: {risk_score:.1f} - {reason}")
            return ResponseAction.WARN
        except (OSError, ProcessLookupError) as e:
            logger.debug(f"Failed to warn process {pid}: {e}")
            return None
    
    def _freeze_process(self, pid: int, process_name: str, risk_score: float, 
                       reason: str) -> ResponseAction:
        """Freeze process using SIGSTOP"""
        try:
            if pid in self.frozen_processes:
                return ResponseAction.FREEZE  # Already frozen
            
            os.kill(pid, signal.SIGSTOP)
            self.frozen_processes[pid] = datetime.now()
            logger.warning(f"❄️ FREEZE: PID {pid} ({process_name}) - Risk: {risk_score:.1f} - {reason}")
            return ResponseAction.FREEZE
        except (OSError, ProcessLookupError) as e:
            logger.debug(f"Failed to freeze process {pid}: {e}")
            return None
    
    def _isolate_process(self, pid: int, process_name: str, risk_score: float, 
                        reason: str) -> ResponseAction:
        """Isolate process using cgroups/namespaces"""
        try:
            if pid in self.isolated_processes:
                return ResponseAction.ISOLATE  # Already isolated
            
            # Method 1: Use cgroups to limit resources
            if self._isolate_with_cgroup(pid):
                self.isolated_processes[pid] = {
                    'name': process_name,
                    'risk_score': risk_score,
                    'reason': reason,
                    'timestamp': datetime.now()
                }
                logger.warning(f"🔒 ISOLATE: PID {pid} ({process_name}) - Risk: {risk_score:.1f} - {reason}")
                return ResponseAction.ISOLATE
            
            # Method 2: Fallback to freezing if cgroup isolation fails
            return self._freeze_process(pid, process_name, risk_score, reason)
        except Exception as e:
            logger.error(f"Failed to isolate process {pid}: {e}")
            return None
    
    def _isolate_with_cgroup(self, pid: int) -> bool:
        """Isolate process using cgroups"""
        try:
            # Create cgroup for isolated processes
            cgroup_path = Path('/sys/fs/cgroup/security_agent/isolated')
            cgroup_path.mkdir(parents=True, exist_ok=True)
            
            # Add PID to cgroup
            pid_file = cgroup_path / 'cgroup.procs'
            with open(pid_file, 'w') as f:
                f.write(str(pid))
            
            # Limit CPU (50% max)
            cpu_quota = cgroup_path / 'cpu.cfs_quota_us'
            cpu_period = cgroup_path / 'cpu.cfs_period_us'
            if cpu_period.exists():
                with open(cpu_period, 'r') as f:
                    period = int(f.read().strip())
                with open(cpu_quota, 'w') as f:
                    f.write(str(period // 2))  # 50% CPU
            
            # Limit memory (512MB max)
            memory_max = cgroup_path / 'memory.max'
            if memory_max.exists():
                with open(memory_max, 'w') as f:
                    f.write('536870912')  # 512MB in bytes
            
            return True
        except PermissionError:
            logger.warning("Need root privileges for cgroup isolation")
            return False
        except Exception as e:
            logger.debug(f"Cgroup isolation failed: {e}")
            return False
    
    def _kill_process(self, pid: int, process_name: str, risk_score: float, 
                     reason: str) -> ResponseAction:
        """Kill process using SIGKILL"""
        try:
            if pid in self.killed_processes:
                return ResponseAction.KILL  # Already killed
            
            # First try SIGTERM (graceful)
            try:
                os.kill(pid, signal.SIGTERM)
                import time
                time.sleep(1)  # Give process time to exit
            except (OSError, ProcessLookupError) as sigterm_error:
                logger.debug(f"Failed to send SIGTERM to PID {pid} (will try SIGKILL): {sigterm_error}")
            
            # Force kill with SIGKILL
            if self._process_exists(pid):
                os.kill(pid, signal.SIGKILL)
            
            self.killed_processes[pid] = datetime.now()
            logger.error(f"💀 KILL: PID {pid} ({process_name}) - Risk: {risk_score:.1f} - {reason}")
            return ResponseAction.KILL
        except (OSError, ProcessLookupError) as e:
            logger.debug(f"Failed to kill process {pid}: {e}")
            return None
    
    def _block_network(self, pid: int, process_name: str) -> bool:
        """Block network access for process using iptables"""
        if not self.network_block_enabled:
            return False
        
        try:
            # Get process network namespace (if available)
            # This is a simplified version - full implementation would use network namespaces
            
            # Use iptables to block by PID (requires iptables-persistent)
            cmd = ['iptables', '-A', 'OUTPUT', '-m', 'owner', '--pid-owner', str(pid), '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                logger.warning(f"🚫 NETWORK BLOCK: PID {pid} ({process_name})")
                return True
            else:
                logger.debug(f"Failed to block network for PID {pid}: {result.stderr}")
                return False
        except Exception as e:
            logger.debug(f"Network blocking failed: {e}")
            return False
    
    def unfreeze_process(self, pid: int) -> bool:
        """Unfreeze a frozen process"""
        try:
            if pid not in self.frozen_processes:
                return False
            
            os.kill(pid, signal.SIGCONT)
            del self.frozen_processes[pid]
            logger.info(f"✅ Unfroze process {pid}")
            return True
        except (OSError, ProcessLookupError) as e:
            logger.debug(f"Failed to unfreeze process {pid}: {e}")
            return False
    
    def _log_action(self, action: ResponseAction, pid: int, process_name: str, 
                   risk_score: float, reason: str) -> None:
        """Log response action"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': action.value,
                'pid': pid,
                'process_name': process_name,
                'risk_score': risk_score,
                'reason': reason
            }
            
            with open(self.action_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.debug(f"Failed to log action: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get response handler statistics"""
        return {
            'enabled': self.enabled,
            'kill_enabled': self.kill_enabled,
            'isolation_enabled': self.isolation_enabled,
            'frozen_processes': len(self.frozen_processes),
            'isolated_processes': len(self.isolated_processes),
            'killed_processes': len(self.killed_processes),
            'action_log_file': str(self.action_log_file)
        }

