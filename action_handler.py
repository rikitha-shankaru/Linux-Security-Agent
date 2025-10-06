#!/usr/bin/env python3
"""
Action handler for threshold-based security responses
"""

import os
import sys
import time
import signal
import subprocess
import logging
from typing import Dict, List, Tuple, Optional
from enum import Enum
from datetime import datetime

class ActionType(Enum):
    """Types of actions that can be taken"""
    WARN = "warn"
    FREEZE = "freeze"
    KILL = "kill"
    LOG = "log"

class ActionHandler:
    """Handles security actions based on risk thresholds"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.action_history = []
        self.frozen_processes = set()
        
        # Default thresholds
        self.warn_threshold = self.config.get('warn_threshold', 30.0)
        self.freeze_threshold = self.config.get('freeze_threshold', 70.0)
        self.kill_threshold = self.config.get('kill_threshold', 90.0)
        
        # Action settings
        self.enable_warnings = self.config.get('enable_warnings', True)
        self.enable_freeze = self.config.get('enable_freeze', True)
        self.enable_kill = self.config.get('enable_kill', False)  # Default to False for safety
        
        # Logging settings
        self.log_file = self.config.get('log_file', '/var/log/security_agent.log')
        self.max_log_size = self.config.get('max_log_size', 10 * 1024 * 1024)  # 10MB
        
        # Set up logger after log_file is defined
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        """Set up logging for actions"""
        logger = logging.getLogger('security_agent_actions')
        logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        try:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except PermissionError:
            # Fallback to console if can't write to log file
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        return logger
    
    def should_take_action(self, pid: int, risk_score: float, anomaly_score: float = 0.0) -> Optional[ActionType]:
        """Determine if action should be taken based on risk score"""
        # Safety check for None risk_score
        if risk_score is None:
            risk_score = 0.0
            
        # Check if process is already frozen
        if pid in self.frozen_processes:
            return None
        
        # Determine action based on thresholds
        if risk_score >= self.kill_threshold and self.enable_kill:
            return ActionType.KILL
        elif risk_score >= self.freeze_threshold and self.enable_freeze:
            return ActionType.FREEZE
        elif risk_score >= self.warn_threshold and self.enable_warnings:
            return ActionType.WARN
        else:
            return ActionType.LOG
    
    def take_action(self, pid: int, process_name: str, risk_score: float, 
                   anomaly_score: float = 0.0, action_type: ActionType = None) -> bool:
        """Take action on a process based on risk score"""
        if action_type is None:
            action_type = self.should_take_action(pid, risk_score, anomaly_score)
        
        if action_type is None:
            return False
        
        success = False
        timestamp = datetime.now().isoformat()
        
        try:
            if action_type == ActionType.WARN:
                success = self._warn_process(pid, process_name, risk_score, anomaly_score)
            elif action_type == ActionType.FREEZE:
                success = self._freeze_process(pid, process_name, risk_score, anomaly_score)
            elif action_type == ActionType.KILL:
                success = self._kill_process(pid, process_name, risk_score, anomaly_score)
            elif action_type == ActionType.LOG:
                success = self._log_process(pid, process_name, risk_score, anomaly_score)
            
            # Record action in history
            self.action_history.append({
                'timestamp': timestamp,
                'pid': pid,
                'process_name': process_name,
                'risk_score': risk_score,
                'anomaly_score': anomaly_score,
                'action': action_type.value,
                'success': success
            })
            
            # Log the action
            self.logger.info(
                f"Action {action_type.value.upper()} on PID {pid} ({process_name}) - "
                f"Risk: {risk_score:.1f}, Anomaly: {anomaly_score:.2f}, Success: {success}"
            )
            
        except Exception as e:
            self.logger.error(f"Error taking action {action_type.value} on PID {pid}: {e}")
            success = False
        
        return success
    
    def _warn_process(self, pid: int, process_name: str, risk_score: float, 
                     anomaly_score: float) -> bool:
        """Send warning signal to process"""
        try:
            # Send SIGUSR1 signal as warning
            os.kill(pid, signal.SIGUSR1)
            
            # Log warning
            self.logger.warning(
                f"WARNING sent to PID {pid} ({process_name}) - "
                f"Risk: {risk_score:.1f}, Anomaly: {anomaly_score:.2f}"
            )
            
            return True
            
        except ProcessLookupError:
            self.logger.warning(f"Process {pid} not found for warning")
            return False
        except PermissionError:
            self.logger.error(f"Permission denied to send warning to PID {pid}")
            return False
        except Exception as e:
            self.logger.error(f"Error sending warning to PID {pid}: {e}")
            return False
    
    def _freeze_process(self, pid: int, process_name: str, risk_score: float, 
                       anomaly_score: float) -> bool:
        """Freeze process using SIGSTOP"""
        try:
            # Send SIGSTOP signal to freeze process
            os.kill(pid, signal.SIGSTOP)
            
            # Add to frozen processes set
            self.frozen_processes.add(pid)
            
            # Log freeze action
            self.logger.warning(
                f"FROZEN PID {pid} ({process_name}) - "
                f"Risk: {risk_score:.1f}, Anomaly: {anomaly_score:.2f}"
            )
            
            return True
            
        except ProcessLookupError:
            self.logger.warning(f"Process {pid} not found for freezing")
            return False
        except PermissionError:
            self.logger.error(f"Permission denied to freeze PID {pid}")
            return False
        except Exception as e:
            self.logger.error(f"Error freezing PID {pid}: {e}")
            return False
    
    def _kill_process(self, pid: int, process_name: str, risk_score: float, 
                     anomaly_score: float) -> bool:
        """Kill process using SIGKILL"""
        try:
            # Send SIGKILL signal to kill process
            os.kill(pid, signal.SIGKILL)
            
            # Remove from frozen processes if it was frozen
            self.frozen_processes.discard(pid)
            
            # Log kill action
            self.logger.critical(
                f"KILLED PID {pid} ({process_name}) - "
                f"Risk: {risk_score:.1f}, Anomaly: {anomaly_score:.2f}"
            )
            
            return True
            
        except ProcessLookupError:
            self.logger.warning(f"Process {pid} not found for killing")
            return False
        except PermissionError:
            self.logger.error(f"Permission denied to kill PID {pid}")
            return False
        except Exception as e:
            self.logger.error(f"Error killing PID {pid}: {e}")
            return False
    
    def _log_process(self, pid: int, process_name: str, risk_score: float, 
                    anomaly_score: float) -> bool:
        """Log process information"""
        try:
            # Log process information
            self.logger.info(
                f"MONITORING PID {pid} ({process_name}) - "
                f"Risk: {risk_score:.1f}, Anomaly: {anomaly_score:.2f}"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error logging PID {pid}: {e}")
            return False
    
    def unfreeze_process(self, pid: int, process_name: str) -> bool:
        """Unfreeze a previously frozen process"""
        try:
            if pid not in self.frozen_processes:
                self.logger.warning(f"Process {pid} is not frozen")
                return False
            
            # Send SIGCONT signal to unfreeze process
            os.kill(pid, signal.SIGCONT)
            
            # Remove from frozen processes set
            self.frozen_processes.remove(pid)
            
            # Log unfreeze action
            self.logger.info(f"UNFROZEN PID {pid} ({process_name})")
            
            return True
            
        except ProcessLookupError:
            self.logger.warning(f"Process {pid} not found for unfreezing")
            self.frozen_processes.discard(pid)
            return False
        except PermissionError:
            self.logger.error(f"Permission denied to unfreeze PID {pid}")
            return False
        except Exception as e:
            self.logger.error(f"Error unfreezing PID {pid}: {e}")
            return False
    
    def get_frozen_processes(self) -> List[Tuple[int, str]]:
        """Get list of currently frozen processes"""
        frozen = []
        for pid in list(self.frozen_processes):
            try:
                # Get process name
                with open(f'/proc/{pid}/comm', 'r') as f:
                    process_name = f.read().strip()
                frozen.append((pid, process_name))
            except (FileNotFoundError, PermissionError):
                # Process no longer exists, remove from set
                self.frozen_processes.discard(pid)
        
        return frozen
    
    def get_action_history(self, limit: int = 100) -> List[Dict]:
        """Get recent action history"""
        return self.action_history[-limit:]
    
    def clear_action_history(self):
        """Clear action history"""
        self.action_history.clear()
    
    def update_config(self, new_config: Dict):
        """Update configuration"""
        self.config.update(new_config)
        
        # Update thresholds
        self.warn_threshold = self.config.get('warn_threshold', self.warn_threshold)
        self.freeze_threshold = self.config.get('freeze_threshold', self.freeze_threshold)
        self.kill_threshold = self.config.get('kill_threshold', self.kill_threshold)
        
        # Update action settings
        self.enable_warnings = self.config.get('enable_warnings', self.enable_warnings)
        self.enable_freeze = self.config.get('enable_freeze', self.enable_freeze)
        self.enable_kill = self.config.get('enable_kill', self.enable_kill)
        
        self.logger.info(f"Configuration updated: {new_config}")
    
    def get_status(self) -> Dict:
        """Get current status of action handler"""
        return {
            'frozen_processes': len(self.frozen_processes),
            'action_history_count': len(self.action_history),
            'thresholds': {
                'warn': self.warn_threshold,
                'freeze': self.freeze_threshold,
                'kill': self.kill_threshold
            },
            'enabled_actions': {
                'warnings': self.enable_warnings,
                'freeze': self.enable_freeze,
                'kill': self.enable_kill
            }
        }


# Example usage and testing
if __name__ == "__main__":
    # Test action handler
    config = {
        'warn_threshold': 30.0,
        'freeze_threshold': 70.0,
        'kill_threshold': 90.0,
        'enable_warnings': True,
        'enable_freeze': True,
        'enable_kill': False,  # Safety first
        'log_file': '/tmp/security_agent_test.log'
    }
    
    handler = ActionHandler(config)
    
    # Test with a real process (current process)
    pid = os.getpid()
    process_name = "python3"
    
    # Test warning
    print("Testing warning action...")
    handler.take_action(pid, process_name, 35.0, 0.1, ActionType.WARN)
    
    # Test logging
    print("Testing log action...")
    handler.take_action(pid, process_name, 25.0, 0.05, ActionType.LOG)
    
    # Get status
    status = handler.get_status()
    print(f"Action handler status: {status}")
    
    # Get action history
    history = handler.get_action_history()
    print(f"Action history: {history}")
    
    print("Action handler test complete!")
