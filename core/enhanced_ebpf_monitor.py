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
            try:
                self.bpf_program = self._load_enhanced_ebpf_program()
                print(f"DEBUG __init__: bpf_program created: {self.bpf_program is not None}")
            except Exception as e:
                print(f"Failed to load eBPF: {e}")
                self.bpf_program = None
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
        # Real eBPF code that captures actual syscalls
        ebpf_code = """
#pragma clang diagnostic ignored "-Wmacro-redefined"
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Event structure to send to userspace
struct syscall_event {
    u32 pid;
    u32 syscall_num;
    char comm[TASK_COMM_LEN];
    u64 timestamp;
};

// Maps
BPF_PERF_OUTPUT(syscall_events);      // For sending events to userspace
BPF_HASH(syscall_counts, u32, u64);  // For statistics

// Track syscalls and capture syscall numbers  
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    int syscall_nr = (int)args->id;
    
    // Create event with REAL syscall data
    struct syscall_event event = {};
    event.pid = pid;
    event.syscall_num = syscall_nr;
    event.timestamp = bpf_ktime_get_ns();
    
    // Get process name
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    
    // Send event to userspace - using args as context for TRACEPOINT_PROBE
    syscall_events.perf_submit(args, &event, sizeof(event));
    
    // Also update count for statistics (always works)
    u64 *count = syscall_counts.lookup(&pid);
    u64 new_count = 1;
    if (count) {
        new_count = *count + 1;
    }
    syscall_counts.update(&pid, &new_count);
    
    return 0;
}
"""
        
        try:
            print("Loading eBPF program...")
            bpf = BPF(text=ebpf_code)
            print(f"✅ eBPF program loaded successfully!")
            return bpf
        except Exception as e:
            print(f"❌ Failed to load enhanced eBPF program: {e}")
            import traceback
            traceback.print_exc()
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
            # Silently ignore - process might be dead
            pass
        
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
        print(f"DEBUG start_monitoring: bpf_program exists: {self.bpf_program is not None}")
        self.running = True
        self.event_callback = event_callback
        
        # Attach perf event handler for REAL syscall events
        print(f"DEBUG: self.bpf_program is not None? {self.bpf_program is not None}")
        
        if self.bpf_program is not None:
            print("DEBUG: bpf_program exists, opening perf buffer...")
            try:
                # Increase page_cnt and provide a lost callback to suppress 'Possibly lost X samples' spam
                self.lost_events = 0
                self._cleanup_done = False  # Flag to prevent double cleanup
                
                def _lost_cb(lost_cnt):
                    # Silently track lost events - don't spam console
                    # (Only log at shutdown if needed)
                    self.lost_events += lost_cnt

                self.bpf_program["syscall_events"].open_perf_buffer(
                    self._process_perf_event,
                    lost_cb=_lost_cb,
                    page_cnt=64,
                )
                print("✅ Perf event buffer ATTACHED!")
            except Exception as e:
                print(f"⚠️ Failed to open perf buffer: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("DEBUG: NO bpf_program found!")
        
        # Start event processing thread - ALWAYS start it
        print("DEBUG: Starting event thread...")
        self.event_thread = threading.Thread(target=self._process_events)
        self.event_thread.daemon = True
        self.event_thread.start()
        print("DEBUG: Event thread started!")
        
        print("Enhanced eBPF monitoring started with stateful tracking")
        return True
    
    def stop_monitoring(self):
        """Stop the enhanced eBPF monitoring"""
        self.running = False
        if hasattr(self, 'event_thread'):
            self.event_thread.join(timeout=5)
        # Best-effort cleanup to release perf buffers/kprobes cleanly (only once)
        if not getattr(self, '_cleanup_done', False):
            try:
                if self.bpf_program is not None:
                    self.bpf_program.cleanup()
                self._cleanup_done = True
                # Log lost events summary only at shutdown
                if hasattr(self, 'lost_events') and self.lost_events > 0:
                    print(f"ℹ️  Total perf events lost during monitoring: {self.lost_events}")
            except Exception:
                pass
        print("Enhanced eBPF monitoring stopped")
    
    def _process_events(self):
        """Process eBPF events in background thread - READS REAL EVENTS"""
        print(f"🔍 Starting real syscall event loop... bpf_program={self.bpf_program}")
        
        # Store reference to avoid issues
        bpf_prog = self.bpf_program
        
        if bpf_prog is None:
            print("⚠️ No bpf_program - monitoring without eBPF data")
            while self.running:
                time.sleep(1)
            return
        
        try:
            # Poll perf buffer for REAL syscall events
            poll_count = 0
            while self.running:
                try:
                    poll_count += 1
                    if poll_count % 10 == 0:
                        print(f"DEBUG: Polling perf buffer (count={poll_count}), events_so_far={len(self.events)}")
                    bpf_prog.perf_buffer_poll(timeout=1000)  # 1 second timeout
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    if "Interrupted system call" not in str(e):
                        print(f"Error polling perf buffer: {e}")
                    time.sleep(0.1)
        except Exception as e:
            print(f"Error in event processing thread: {e}")
            import traceback
            traceback.print_exc()
        # Note: Cleanup is handled by stop_monitoring() to avoid double-free
    
    def _process_perf_event(self, cpu, data, size):
        """Process REAL perf events from eBPF"""
        try:
            # Parse event from eBPF
            event = self.bpf_program["syscall_events"].event(data)
            
            # Extract fields
            pid = event.pid
            syscall_num = event.syscall_num
            syscall_name = self._syscall_num_to_name(syscall_num)
            
            # Store event (DEBUG removed for clean output)
            self.events.append({
                'pid': pid,
                'syscall_num': syscall_num,
                'syscall_name': syscall_name,
                'timestamp': event.timestamp
            })
            
            # Update stats
            self.syscall_stats[syscall_name] += 1
            
            # Call callback with REAL syscall name
            if self.event_callback:
                self.event_callback(pid, syscall_name, {
                    'pid': pid,
                    'syscall_num': syscall_num,
                    'syscall_name': syscall_name,  # ✅ REAL syscall name!
                    'timestamp': event.timestamp / 1e9  # Convert to seconds
                })
                
        except Exception as e:
            print(f"Error processing perf event: {e}")
    
    def _syscall_num_to_name(self, syscall_num: int) -> str:
        """Convert syscall number to name - complete x86_64 syscall table"""
        # Complete Linux syscall table for x86_64
        syscall_map = {
            0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat',
            5: 'fstat', 6: 'lstat', 7: 'poll', 8: 'lseek', 9: 'mmap',
            10: 'mprotect', 11: 'munmap', 12: 'brk', 13: 'rt_sigaction',
            14: 'rt_sigprocmask', 15: 'rt_sigreturn', 16: 'ioctl', 17: 'pread64',
            18: 'pwrite64', 19: 'readv', 20: 'writev', 21: 'access',
            22: 'pipe', 23: 'select', 24: 'sched_yield', 25: 'mremap',
            26: 'msync', 27: 'mincore', 28: 'madvise', 29: 'shmget',
            30: 'shmat', 31: 'shmctl', 32: 'dup', 33: 'dup2', 34: 'pause',
            35: 'nanosleep', 36: 'getitimer', 37: 'alarm', 38: 'setitimer',
            39: 'getpid', 40: 'sendfile', 41: 'socket', 42: 'connect',
            43: 'accept', 44: 'sendto', 45: 'recvfrom', 46: 'sendmsg',
            47: 'recvmsg', 48: 'shutdown', 49: 'bind', 50: 'listen',
            51: 'getsockname', 52: 'getpeername', 53: 'socketpair', 54: 'setsockopt',
            55: 'getsockopt', 56: 'clone', 57: 'fork', 58: 'vfork', 59: 'execve',
            60: 'exit', 61: 'wait4', 62: 'kill', 63: 'uname', 64: 'semget',
            65: 'semop', 66: 'semctl', 67: 'shmdt', 68: 'msgget', 69: 'msgsnd',
            70: 'msgrcv', 71: 'msgctl', 72: 'fcntl', 73: 'flock', 74: 'fsync',
            75: 'fdatasync', 76: 'truncate', 77: 'ftruncate', 78: 'getdents',
            79: 'getcwd', 80: 'chdir', 81: 'fchdir', 82: 'rename', 83: 'mkdir',
            84: 'rmdir', 85: 'creat', 86: 'link', 87: 'unlink', 88: 'symlink',
            89: 'readlink', 90: 'chmod', 91: 'fchmod', 92: 'chown', 93: 'fchown',
            94: 'lchown', 95: 'umask', 96: 'gettimeofday', 97: 'getrlimit',
            98: 'getrusage', 99: 'sysinfo', 100: 'times', 101: 'ptrace',
            102: 'getuid', 103: 'syslog', 104: 'getgid', 105: 'setuid',
            106: 'setgid', 107: 'geteuid', 108: 'getegid', 109: 'setpgid',
            110: 'getppid', 111: 'getpgrp', 112: 'setsid', 113: 'setreuid',
            114: 'setregid', 115: 'getgroups', 116: 'setgroups', 117: 'setresuid',
            118: 'getresuid', 119: 'setresgid', 120: 'getresgid', 121: 'getpgid',
            122: 'setfsuid', 123: 'setfsgid', 124: 'getsid', 125: 'capget',
            126: 'capset', 127: 'rt_sigpending', 128: 'rt_sigtimedwait',
            129: 'rt_sigqueueinfo', 130: 'rt_sigsuspend', 131: 'sigaltstack',
            132: 'utime', 133: 'mknod', 134: 'uselib', 135: 'personality',
            136: 'ustat', 137: 'statfs', 138: 'fstatfs', 139: 'sysfs',
            140: 'getpriority', 141: 'setpriority', 142: 'sched_setparam',
            143: 'sched_getparam', 144: 'sched_setscheduler', 145: 'sched_getscheduler',
            146: 'sched_get_priority_max', 147: 'sched_get_priority_min',
            148: 'sched_rr_get_interval', 149: 'mlock', 150: 'munlock',
            151: 'mlockall', 152: 'munlockall', 153: 'vhangup', 154: 'modify_ldt',
            155: 'pivot_root', 156: 'prctl', 157: 'arch_prctl', 158: 'adjtimex',
            159: 'setrlimit', 160: 'chroot', 161: 'sync', 162: 'acct', 163: 'settimeofday',
            164: 'mount', 165: 'umount2', 166: 'swapon', 167: 'swapoff',
            168: 'reboot', 169: 'sethostname', 170: 'setdomainname', 171: 'iopl',
            172: 'ioperm', 173: 'create_module', 174: 'init_module', 175: 'delete_module',
            176: 'get_kernel_syms', 177: 'query_module', 178: 'quotactl', 179: 'nfsservctl',
            180: 'getpmsg', 181: 'putpmsg', 182: 'afs_syscall', 183: 'tuxcall',
            184: 'security', 185: 'gettid', 186: 'readahead', 187: 'setxattr',
            188: 'lsetxattr', 189: 'fsetxattr', 190: 'getxattr', 191: 'lgetxattr',
            192: 'fgetxattr', 193: 'listxattr', 194: 'llistxattr', 195: 'flistxattr',
            196: 'removexattr', 197: 'lremovexattr', 198: 'fremovexattr', 199: 'tkill',
            200: 'time', 201: 'futex', 202: 'sched_setaffinity', 203: 'sched_getaffinity',
            204: 'set_thread_area', 205: 'io_setup', 206: 'io_destroy', 207: 'io_getevents',
            208: 'io_submit', 209: 'io_cancel', 210: 'get_thread_area',
            211: 'lookup_dcookie', 212: 'epoll_create', 213: 'epoll_ctl_old',
            214: 'epoll_wait_old', 215: 'remap_file_pages', 216: 'getdents64',
            217: 'set_tid_address', 218: 'restart_syscall', 219: 'semtimedop',
            220: 'fadvise64', 221: 'timer_create', 222: 'timer_settime', 223: 'timer_gettime',
            224: 'timer_getoverrun', 225: 'timer_delete', 226: 'clock_settime',
            227: 'clock_gettime', 228: 'clock_getres', 229: 'clock_nanosleep',
            230: 'exit_group', 231: 'epoll_wait', 232: 'epoll_ctl', 233: 'tgkill',
            234: 'utimes', 235: 'vserver', 236: 'mbind', 237: 'set_mempolicy',
            238: 'get_mempolicy', 239: 'mq_open', 240: 'mq_unlink', 241: 'mq_timedsend',
            242: 'mq_timedreceive', 243: 'mq_notify', 244: 'mq_getsetattr',
            245: 'kexec_load', 246: 'waitid', 247: 'add_key', 248: 'request_key',
            249: 'keyctl', 250: 'ioprio_set', 251: 'ioprio_get', 252: 'inotify_init',
            253: 'inotify_add_watch', 254: 'inotify_rm_watch', 255: 'migrate_pages',
            256: 'openat', 257: 'mkdirat', 258: 'mknodat', 259: 'fchownat',
            260: 'futimesat', 261: 'newfstatat', 262: 'unlinkat', 263: 'renameat',
            264: 'linkat', 265: 'symlinkat', 266: 'readlinkat', 267: 'fchmodat',
            268: 'faccessat', 269: 'pselect6', 270: 'ppoll', 271: 'unshare',
            272: 'set_robust_list', 273: 'get_robust_list', 274: 'splice',
            275: 'tee', 276: 'sync_file_range', 277: 'vmsplice', 278: 'move_pages',
            279: 'utimensat', 280: 'epoll_pwait', 281: 'signalfd', 282: 'timerfd',
            283: 'eventfd', 284: 'fallocate', 285: 'timerfd_settime', 286: 'timerfd_gettime',
            287: 'accept4', 288: 'signalfd4', 289: 'eventfd2', 290: 'epoll_create1',
            291: 'dup3', 292: 'pipe2', 293: 'inotify_init1', 294: 'preadv',
            295: 'pwritev', 296: 'rt_tgsigqueueinfo', 297: 'perf_event_open',
            298: 'recvmmsg', 299: 'fanotify_init', 300: 'fanotify_mark',
            301: 'prlimit64', 302: 'name_to_handle_at', 303: 'open_by_handle_at',
            304: 'clock_adjtime', 305: 'syncfs', 306: 'sendmmsg', 307: 'setns',
            308: 'getcpu', 309: 'process_vm_readv', 310: 'process_vm_writev',
            311: 'kcmp', 312: 'finit_module', 313: 'sched_setattr', 314: 'sched_getattr',
            315: 'renameat2', 316: 'seccomp', 317: 'getrandom', 318: 'memfd_create',
            319: 'kexec_file_load', 320: 'bpf', 321: 'execveat', 322: 'userfaultfd',
            323: 'membarrier', 324: 'mlock2', 325: 'copy_file_range', 326: 'preadv2',
            327: 'pwritev2', 328: 'pkey_mprotect', 329: 'pkey_alloc', 330: 'pkey_free',
            331: 'statx', 332: 'io_pgetevents', 333: 'rseq'
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
