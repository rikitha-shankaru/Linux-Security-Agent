#!/usr/bin/env python3
"""
Auditd collector (fallback) - tails /var/log/audit/audit.log and emits normalized syscall events

Unified event schema passed to callback(event):
    pid: int
    syscall: str
    event_info: Dict[str, Any] (optional extra fields)

The EnhancedSecurityAgent expects callback(pid, syscall, event_info).
"""

import os
import re
import threading
import time
from typing import Callable, Dict, Any, Optional


class AuditdCollector:
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.audit_log_path = self.config.get('audit_log_path', '/var/log/audit/audit.log')
        self.running = False
        self.thread: Optional[threading.Thread] = None

        # Regex to extract basic fields from auditd SYSCALL line
        # Matches both numeric and named syscall tokens
        # Example numeric: syscall=59; named: syscall=execve
        self.syscall_re = re.compile(r"type=SYSCALL .*?syscall=([^\s]+).*?pid=(\d+).*?uid=(\d+).*?comm=\"([^\"]*)\".*?exe=\"([^\"]*)\"")

        # Simple syscall number to name map (subset); eBPF path has full map
        self.syscall_num_to_name = {
            '59': 'execve', '322': 'execveat', '57': 'fork', '56': 'clone', '58': 'vfork',
            '257': 'openat', '2': 'open', '3': 'close', '0': 'read', '1': 'write',
            '101': 'ptrace', '160': 'mount', '166': 'umount2', '105': 'setuid', '106': 'setgid',
            '90': 'chmod', '92': 'chown', '49': 'bind', '42': 'connect', '43': 'accept'
        }

    def start_monitoring(self, event_callback: Callable[[int, str, Dict[str, Any]], None]) -> bool:
        if not os.path.exists(self.audit_log_path) or not os.access(self.audit_log_path, os.R_OK):
            return False

        self.running = True
        self.thread = threading.Thread(target=self._tail_loop, args=(event_callback,), daemon=True)
        self.thread.start()
        return True

    def stop_monitoring(self):
        self.running = False
        # Thread is daemon; it will exit shortly

    def _tail_loop(self, event_callback: Callable[[int, str, Dict[str, Any]], None]):
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
                    event_info = {
                        'uid': uid,
                        'comm': comm,
                        'exe': exe,
                        'source': 'auditd'
                    }
                    try:
                        event_callback(pid, syscall_name, event_info)
                    except Exception:
                        # Ignore callback errors to keep tailing
                        pass
        except Exception:
            # Silently exit on errors; agent will manage lifecycle
            self.running = False


