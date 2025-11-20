"""
Auditd collector - implements BaseCollector interface directly
"""
import os
import re
import threading
import time
from typing import Callable, Dict, Any, Optional
import logging

from .base import BaseCollector, SyscallEvent

logger = logging.getLogger('security_agent.collector.auditd')


class AuditdCollector(BaseCollector):
    """Auditd-based syscall collector"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.audit_log_path = self.config.get('audit_log_path', '/var/log/audit/audit.log')
        self.thread: Optional[threading.Thread] = None
        
        # Regex to extract basic fields from auditd SYSCALL line
        # Matches both numeric and named syscall tokens
        # Example numeric: syscall=59; named: syscall=execve
        self.syscall_re = re.compile(
            r"type=SYSCALL .*?syscall=([^\s]+).*?pid=(\d+).*?uid=(\d+).*?comm=\"([^\"]*)\".*?exe=\"([^\"]*)\""
        )
        
        # Simple syscall number to name map (subset); eBPF path has full map
        self.syscall_num_to_name = {
            '59': 'execve', '322': 'execveat', '57': 'fork', '56': 'clone', '58': 'vfork',
            '257': 'openat', '2': 'open', '3': 'close', '0': 'read', '1': 'write',
            '101': 'ptrace', '160': 'mount', '166': 'umount2', '105': 'setuid', '106': 'setgid',
            '90': 'chmod', '92': 'chown', '49': 'bind', '42': 'connect', '43': 'accept'
        }
    
    def is_available(self) -> bool:
        """Check if auditd is available"""
        return os.path.exists(self.audit_log_path) and os.access(self.audit_log_path, os.R_OK)
    
    def start_monitoring(self, event_callback: Callable[[SyscallEvent], None]) -> bool:
        """Start auditd monitoring"""
        if not self.is_available():
            logger.error(f"Audit log not available: {self.audit_log_path}")
            return False
        
        try:
            self.running = True
            self.thread = threading.Thread(target=self._tail_loop, args=(event_callback,), daemon=True)
            self.thread.start()
            logger.info(f"✅ Auditd collector started monitoring {self.audit_log_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to start auditd collector: {e}")
            self.running = False
            return False
    
    def stop_monitoring(self) -> None:
        """Stop auditd monitoring"""
        self.running = False
        # Thread is daemon; it will exit shortly
    
    def _tail_loop(self, event_callback: Callable[[SyscallEvent], None]):
        """Tail audit log and emit events"""
        try:
            with open(self.audit_log_path, 'r', errors='ignore') as f:
                # Seek to end for live tail
                f.seek(0, os.SEEK_END)
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    
                    # Only process SYSCALL lines
                    if 'type=SYSCALL' not in line:
                        continue
                    
                    m = self.syscall_re.search(line)
                    if not m:
                        continue
                    
                    syscall_token, pid_str, uid_str, comm, exe = m.groups()
                    pid = int(pid_str)
                    uid = int(uid_str)
                    
                    # Prefer named token; if numeric, map best-effort
                    if syscall_token.isdigit():
                        syscall_name = self.syscall_num_to_name.get(syscall_token, syscall_token)
                    else:
                        syscall_name = syscall_token
                    
                    # Create SyscallEvent
                    event = SyscallEvent(
                        pid=pid,
                        syscall=syscall_name,
                        uid=uid,
                        comm=comm,
                        exe=exe,
                        timestamp=time.time(),
                        event_info={'source': 'auditd'}
                    )
                    
                    try:
                        event_callback(event)
                    except Exception as e:
                        # Ignore callback errors to keep tailing
                        logger.debug(f"Callback error: {e}")
        except Exception as e:
            logger.error(f"Error in auditd tail loop: {e}")
            self.running = False
