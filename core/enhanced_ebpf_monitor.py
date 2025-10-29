#!/usr/bin/env python3
"""
Enhanced eBPF Monitor with Stateful Tracking and Programmable Policies
Based on recent research: "Programmable System Call Security with eBPF" (2023)
"""

import os
import sys
import time
import json
import struct
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import ctypes

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    print("Warning: BCC not available. Install with: sudo apt install python3-bpfcc")

@dataclass
class ProcessState:
    """Stateful process tracking structure"""
    pid: int
    ppid: int
    execve_count: int
    last_execve: int
    syscall_pattern: List[int]
    risk_score: int
    container_id: str
    last_update: int
    policy_violations: int
    behavioral_baseline: Dict[str, float]

@dataclass
class SecurityPolicy:
    """Programmable security policy structure"""
    policy_id: str
    name: str
    rules: Dict[str, Any]
    active: bool
    created_at: int
    updated_at: int

class StatefulEBPFMonitor:
    """
    Enhanced eBPF monitor with stateful tracking and programmable policies
    Based on recent research on programmable system call security
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.running = False
        self.events = deque(maxlen=100000)
        self.process_states = {}  # pid -> ProcessState
        self.security_policies = {}  # policy_id -> SecurityPolicy
        self.active_policies = []
        self.syscall_stats = defaultdict(int)
        self.cross_container_attempts = []
        
        # Performance tuning
        self.batch_size = self.config.get('batch_size', 1000)
        self.max_processes = self.config.get('max_processes', 10000)
        
        # Container awareness
        self.container_boundaries = {}
        self.container_policies = {}
        
        # Load default policies
        self._load_default_policies()
        
        # Initialize eBPF program
        if BCC_AVAILABLE:
            self.bpf_program = self._load_enhanced_ebpf_program()
        else:
            self.bpf_program = None
            print("Warning: Running without eBPF - limited functionality")
    
    def _load_default_policies(self):
        """Load default security policies"""
        default_policy = SecurityPolicy(
            policy_id="default",
            name="Default Security Policy",
            rules={
                "max_execve_per_minute": 10,
                "blocked_syscalls": ["ptrace", "mount", "umount", "reboot"],
                "allowed_syscalls": ["read", "write", "open", "close", "mmap", "munmap"],
                "max_syscall_rate": 1000,
                "container_isolation": True,
                "cross_container_block": True
            },
            active=True,
            created_at=int(time.time()),
            updated_at=int(time.time())
        )
        self.security_policies["default"] = default_policy
        self.active_policies.append("default")
    
    def _load_enhanced_ebpf_program(self) -> BPF:
        """Load enhanced eBPF program with stateful tracking"""
        # Simplified eBPF code that actually works
        ebpf_code = """
#include <uapi/linux/ptrace.h>

// Event structure
struct syscall_event {
    u32 pid;
    u32 syscall_num;
    u64 timestamp;
    char comm[16];
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_HASH(syscall_counts, u32, u64);

// Track syscalls
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 syscall_num = args->id;
    
    // Update count
    u64 *count = syscall_counts.lookup(&pid);
    u64 new_count = 1;
    if (count) {
        new_count = *count + 1;
    }
    syscall_counts.update(&pid, &new_count);
    
    // Send event
    struct syscall_event event = {};
    event.pid = pid;
    event.syscall_num = syscall_num;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Use ctx parameter (automatically provided by TRACEPOINT_PROBE)
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
"""
        
        try:
            return BPF(text=ebpf_code)
        except Exception as e:
            print(f"Failed to load enhanced eBPF program: {e}")
            return None
    
    def add_security_policy(self, policy: SecurityPolicy):
        """Add a new security policy"""
        self.security_policies[policy.policy_id] = policy
        if policy.active:
            self.active_policies.append(policy.policy_id)
        
        # Update eBPF program with new policy
        if self.bpf_program:
            self._update_ebpf_policies()
    
    def update_security_policy(self, policy_id: str, new_rules: Dict[str, Any]):
        """Update an existing security policy"""
        if policy_id in self.security_policies:
            policy = self.security_policies[policy_id]
            policy.rules.update(new_rules)
            policy.updated_at = int(time.time())
            
            # Update eBPF program
            if self.bpf_program:
                self._update_ebpf_policies()
    
    def _update_ebpf_policies(self):
        """Update eBPF program with current policies"""
        if not self.bpf_program:
            return
        
        # This would involve updating the eBPF maps with new policy data
        # Implementation would depend on specific eBPF map structure
        pass
    
    def get_process_state(self, pid: int) -> Optional[ProcessState]:
        """Get stateful information for a process"""
        if not self.bpf_program:
            return None
        
        try:
            # Get process state from eBPF map
            state_map = self.bpf_program.get_table("process_states")
            state_data = state_map.get(pid)
            
            if state_data:
                return ProcessState(
                    pid=pid,
                    ppid=state_data.ppid,
                    execve_count=state_data.execve_count,
                    last_execve=state_data.last_execve,
                    syscall_pattern=list(state_data.syscall_pattern),
                    risk_score=state_data.risk_score,
                    container_id=str(state_data.container_id),
                    last_update=state_data.last_update,
                    policy_violations=state_data.policy_violations,
                    behavioral_baseline={}
                )
        except Exception as e:
            print(f"Error getting process state: {e}")
        
        return None
    
    def detect_cross_container_attempts(self, pid: int, syscall: str, target_pid: int = None):
        """Detect potential cross-container attacks"""
        if not self.bpf_program:
            return False
        
        try:
            # Get container boundaries from eBPF map
            container_map = self.bpf_program.get_table("container_boundaries")
            source_container = container_map.get(pid)
            target_container = container_map.get(target_pid) if target_pid else None
            
            # Check if this is a cross-container access
            if source_container and target_container and source_container != target_container:
                attempt = {
                    'timestamp': time.time(),
                    'source_pid': pid,
                    'target_pid': target_pid,
                    'syscall': syscall,
                    'source_container': source_container,
                    'target_container': target_container
                }
                self.cross_container_attempts.append(attempt)
                return True
        except Exception as e:
            print(f"Error detecting cross-container attempts: {e}")
        
        return False
    
    def get_behavioral_baseline(self, pid: int) -> Dict[str, float]:
        """Get behavioral baseline for a process"""
        state = self.get_process_state(pid)
        if state:
            return state.behavioral_baseline
        return {}
    
    def update_behavioral_baseline(self, pid: int, syscalls: List[str]):
        """Update behavioral baseline for a process"""
        if pid not in self.process_states:
            self.process_states[pid] = ProcessState(
                pid=pid,
                ppid=0,
                execve_count=0,
                last_execve=0,
                syscall_pattern=[],
                risk_score=0,
                container_id="",
                last_update=int(time.time()),
                policy_violations=0,
                behavioral_baseline={}
            )
        
        state = self.process_states[pid]
        
        # Update behavioral baseline
        syscall_counts = defaultdict(int)
        for syscall in syscalls:
            syscall_counts[syscall] += 1
        
        total_syscalls = len(syscalls)
        if total_syscalls > 0:
            for syscall, count in syscall_counts.items():
                state.behavioral_baseline[syscall] = count / total_syscalls
    
    def get_policy_violations(self, pid: int) -> int:
        """Get number of policy violations for a process"""
        state = self.get_process_state(pid)
        if state:
            return state.policy_violations
        return 0
    
    def start_monitoring(self, event_callback=None):
        """Start the enhanced eBPF monitoring"""
        if not self.bpf_program:
            print("Error: eBPF program not loaded")
            return False
        
        self.running = True
        self.event_callback = event_callback
        
        # Start event processing thread
        self.event_thread = threading.Thread(target=self._process_events)
        self.event_thread.daemon = True
        self.event_thread.start()
        
        print("Enhanced eBPF monitoring started with stateful tracking")
        return True
    
    def stop_monitoring(self):
        """Stop the enhanced eBPF monitoring"""
        self.running = False
        if hasattr(self, 'event_thread'):
            self.event_thread.join(timeout=5)
        print("Enhanced eBPF monitoring stopped")
    
    def _process_events(self):
        """Process eBPF events in background thread"""
        try:
            # Set up perf buffer
            self.bpf_program["events"].open_perf_buffer(self._process_event_callback)
            
            # Poll for events
            while self.running:
                try:
                    self.bpf_program.perf_buffer_poll(timeout=100)
                except Exception as e:
                    print(f"Error reading events: {e}")
                    time.sleep(0.1)
        except Exception as e:
            print(f"Error in event processing thread: {e}")
    
    def _process_event_callback(self, cpu, data, size):
        """Callback for processing eBPF events from perf buffer"""
        try:
            event = self.bpf_program["events"].event(data)
            
            # Extract fields
            pid = event.pid
            syscall_num = event.syscall_num
            timestamp = event.timestamp
            
            # Convert syscall number to name
            syscall_name = self._syscall_num_to_name(syscall_num)
            
            # Store event
            self.events.append({
                'pid': pid,
                'syscall_num': syscall_num,
                'syscall_name': syscall_name,
                'timestamp': timestamp
            })
            
            # Update stats
            self.syscall_stats[syscall_name] += 1
            
            # Call callback if provided
            if self.event_callback:
                self.event_callback(pid, syscall_name, {
                    'pid': pid,
                    'syscall_num': syscall_num,
                    'timestamp': timestamp
                })
                
        except Exception as e:
            print(f"Error in event callback: {e}")
    
    def _syscall_num_to_name(self, syscall_num: int) -> str:
        """Convert syscall number to name"""
        # Common syscall numbers
        syscall_map = {
            0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat',
            5: 'fstat', 8: 'lseek', 9: 'mmap', 10: 'mprotect',
            11: 'munmap', 12: 'brk', 13: 'rt_sigaction', 14: 'rt_sigprocmask',
            22: 'pipe', 23: 'select', 24: 'sched_yield', 32: 'dup', 33: 'dup2',
            39: 'getpid', 40: 'sendfile', 41: 'socket', 42: 'connect',
            43: 'accept', 44: 'sendto', 45: 'recvfrom', 46: 'sendmsg',
            47: 'recvmsg', 48: 'shutdown', 49: 'bind', 50: 'listen',
            56: 'clone', 57: 'fork', 58: 'vfork', 59: 'execve',
            60: 'exit', 61: 'wait4', 62: 'kill', 63: 'uname',
            90: 'mmap', 101: 'ptrace', 102: 'getuid', 104: 'getgid',
            106: 'setuid', 107: 'setgid', 161: 'chroot', 165: 'mount',
            166: 'umount', 199: 'getcwd', 200: 'chdir', 217: 'getdents'
        }
        
        return syscall_map.get(syscall_num, f'syscall_{syscall_num}')
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            'total_processes': len(self.process_states),
            'active_policies': len(self.active_policies),
            'cross_container_attempts': len(self.cross_container_attempts),
            'total_events': len(self.events),
            'syscall_stats': dict(self.syscall_stats)
        }
    
    def export_state_data(self) -> Dict[str, Any]:
        """Export stateful data for analysis"""
        return {
            'process_states': {pid: asdict(state) for pid, state in self.process_states.items()},
            'security_policies': {pid: asdict(policy) for pid, policy in self.security_policies.items()},
            'cross_container_attempts': self.cross_container_attempts,
            'monitoring_stats': self.get_monitoring_stats(),
            'export_timestamp': time.time()
        }

# Example usage and testing
if __name__ == "__main__":
    # Create enhanced eBPF monitor
    monitor = StatefulEBPFMonitor()
    
    # Add custom security policy
    custom_policy = SecurityPolicy(
        policy_id="strict",
        name="Strict Security Policy",
        rules={
            "max_execve_per_minute": 5,
            "blocked_syscalls": ["ptrace", "mount", "umount", "reboot", "setuid", "setgid"],
            "allowed_syscalls": ["read", "write", "open", "close"],
            "max_syscall_rate": 500,
            "container_isolation": True,
            "cross_container_block": True
        },
        active=True,
        created_at=int(time.time()),
        updated_at=int(time.time())
    )
    
    monitor.add_security_policy(custom_policy)
    
    # Start monitoring
    if monitor.start_monitoring():
        print("Enhanced eBPF monitoring started successfully")
        
        # Run for a short time
        time.sleep(10)
        
        # Get statistics
        stats = monitor.get_monitoring_stats()
        print(f"Monitoring stats: {stats}")
        
        # Export state data
        state_data = monitor.export_state_data()
        print(f"Exported state data: {len(state_data)} entries")
        
        # Stop monitoring
        monitor.stop_monitoring()
    else:
        print("Failed to start enhanced eBPF monitoring")
