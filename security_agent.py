#!/usr/bin/env python3
"""
Linux Security Agent - Real-time system call monitoring and risk assessment
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

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    print("Warning: BCC not available. Using fallback monitoring.")

import psutil
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich import box
import click

# Import anomaly detection
try:
    from anomaly_detector import AnomalyDetector
    ANOMALY_DETECTION_AVAILABLE = True
except ImportError:
    ANOMALY_DETECTION_AVAILABLE = False
    print("Warning: Anomaly detection not available. Install scikit-learn for ML features.")

# Import action handler
try:
    from action_handler import ActionHandler, ActionType
    ACTION_HANDLER_AVAILABLE = True
except ImportError:
    ACTION_HANDLER_AVAILABLE = False
    print("Warning: Action handler not available.")


class SyscallRiskScorer:
    """Risk scoring system based on system call patterns"""
    
    def __init__(self):
        # Define risk levels for different system calls
        self.syscall_risks = {
            # Low risk - normal operations
            'read': 1, 'write': 1, 'open': 1, 'close': 1, 'lseek': 1,
            'stat': 1, 'fstat': 1, 'lstat': 1, 'access': 1, 'readlink': 1,
            'getcwd': 1, 'chdir': 1, 'fchdir': 1, 'getpid': 1, 'getppid': 1,
            'getuid': 1, 'getgid': 1, 'geteuid': 1, 'getegid': 1,
            'getpgrp': 1, 'getsid': 1, 'getpgid': 1, 'umask': 1,
            'uname': 1, 'sysinfo': 1, 'times': 1, 'getrusage': 1,
            'gettimeofday': 1, 'clock_gettime': 1, 'nanosleep': 1,
            'select': 1, 'poll': 1, 'epoll_wait': 1, 'waitpid': 1,
            'wait4': 1, 'exit': 1, 'exit_group': 1, 'brk': 1, 'mmap': 1,
            'munmap': 1, 'mprotect': 1, 'msync': 1, 'madvise': 1,
            'shmget': 1, 'shmat': 1, 'shmdt': 1, 'shmctl': 1,
            'socket': 1, 'bind': 1, 'listen': 1, 'accept': 1,
            'connect': 1, 'send': 1, 'recv': 1, 'sendto': 1, 'recvfrom': 1,
            'shutdown': 1, 'getsockopt': 1, 'setsockopt': 1,
            'getsockname': 1, 'getpeername': 1, 'socketpair': 1,
            
            # Medium risk - potentially suspicious
            'fork': 3, 'vfork': 3, 'clone': 3, 'execve': 5, 'execveat': 5,
            'chmod': 3, 'fchmod': 3, 'chown': 3, 'fchown': 3, 'lchown': 3,
            'fchownat': 3, 'chmod': 3, 'fchmodat': 3, 'utime': 3,
            'utimes': 3, 'futimesat': 3, 'utimensat': 3, 'truncate': 3,
            'ftruncate': 3, 'rename': 3, 'renameat': 3, 'renameat2': 3,
            'unlink': 3, 'unlinkat': 3, 'rmdir': 3, 'mkdir': 3,
            'mkdirat': 3, 'mknod': 3, 'mknodat': 3, 'symlink': 3,
            'symlinkat': 3, 'link': 3, 'linkat': 3, 'readlinkat': 3,
            'mount': 4, 'umount': 4, 'umount2': 4, 'pivot_root': 4,
            'chroot': 4, 'acct': 4, 'swapon': 4, 'swapoff': 4,
            'reboot': 4, 'sethostname': 4, 'setdomainname': 4,
            'iopl': 4, 'ioperm': 4, 'create_module': 4, 'init_module': 4,
            'delete_module': 4, 'get_kernel_syms': 4, 'query_module': 4,
            'quotactl': 4, 'nfsservctl': 4, 'getpmsg': 4, 'putpmsg': 4,
            'afs_syscall': 4, 'tuxcall': 4, 'security': 4,
            'gettid': 2, 'set_tid_address': 2, 'restart_syscall': 2,
            'semtimedop': 2, 'fadvise64': 2, 'timer_create': 2,
            'timer_settime': 2, 'timer_gettime': 2, 'timer_getoverrun': 2,
            'timer_delete': 2, 'clock_settime': 2, 'clock_getres': 2,
            'clock_nanosleep': 2, 'exit_group': 2, 'epoll_create': 2,
            'epoll_ctl': 2, 'epoll_pwait': 2, 'utimensat': 2,
            'signalfd': 2, 'timerfd_create': 2, 'eventfd': 2,
            'fallocate': 2, 'timerfd_settime': 2, 'timerfd_gettime': 2,
            'accept4': 2, 'signalfd4': 2, 'eventfd2': 2, 'epoll_create1': 2,
            'dup3': 2, 'pipe2': 2, 'inotify_init1': 2, 'preadv': 2,
            'pwritev': 2, 'rt_tgsigqueueinfo': 2, 'perf_event_open': 2,
            'recvmmsg': 2, 'fanotify_init': 2, 'fanotify_mark': 2,
            'prlimit64': 2, 'name_to_handle_at': 2, 'open_by_handle_at': 2,
            'clock_adjtime': 2, 'syncfs': 2, 'sendmmsg': 2, 'setns': 2,
            'getcpu': 2, 'process_vm_readv': 2, 'process_vm_writev': 2,
            'kcmp': 2, 'finit_module': 2, 'sched_setattr': 2, 'sched_getattr': 2,
            'renameat2': 2, 'seccomp': 2, 'getrandom': 2, 'memfd_create': 2,
            'kexec_file_load': 2, 'bpf': 2, 'execveat': 2, 'userfaultfd': 2,
            'membarrier': 2, 'mlock2': 2, 'copy_file_range': 2, 'preadv2': 2,
            'pwritev2': 2, 'pkey_mprotect': 2, 'pkey_alloc': 2, 'pkey_free': 2,
            'statx': 2, 'io_pgetevents': 2, 'rseq': 2, 'pidfd_send_signal': 2,
            'io_uring_setup': 2, 'io_uring_enter': 2, 'io_uring_register': 2,
            'openat2': 2, 'pidfd_getfd': 2, 'close_range': 2, 'pidfd_open': 2,
            'pidfd_clone': 2, 'faccessat2': 2, 'process_madvise': 2,
            'epoll_pwait2': 2, 'mount_setattr': 2, 'quotactl_fd': 2,
            'landlock_create_ruleset': 2, 'landlock_add_rule': 2,
            'landlock_restrict_self': 2, 'memfd_secret': 2, 'process_mrelease': 2,
            'futex_waitv': 2, 'set_mempolicy_home_node': 2,
            
            # High risk - very suspicious
            'ptrace': 8, 'setuid': 8, 'setgid': 8, 'setreuid': 8, 'setregid': 8,
            'setresuid': 8, 'setresgid': 8, 'setfsuid': 8, 'setfsgid': 8,
            'capget': 8, 'capset': 8, 'prctl': 8, 'arch_prctl': 8,
            'personality': 8, 'setpriority': 8, 'sched_setscheduler': 8,
            'sched_setparam': 8, 'sched_setaffinity': 8, 'sched_yield': 8,
            'sched_get_priority_max': 8, 'sched_get_priority_min': 8,
            'sched_rr_get_interval': 8, 'mlock': 8, 'munlock': 8,
            'mlockall': 8, 'munlockall': 8, 'vhangup': 8, 'modify_ldt': 8,
            'pivot_root': 8, 'prctl': 8, 'arch_prctl': 8, 'adjtimex': 8,
            'setrlimit': 8, 'chroot': 8, 'sync': 8, 'acct': 8, 'settimeofday': 8,
            'madvise': 8, 'getrlimit': 8, 'getrusage': 8, 'gettimeofday': 8,
            'settimeofday': 8, 'getgroups': 8, 'setgroups': 8, 'setresuid': 8,
            'getresuid': 8, 'setresgid': 8, 'getresgid': 8, 'setfsuid': 8,
            'setfsgid': 8, 'getfsuid': 8, 'getfsgid': 8, 'times': 8,
            'ptrace': 8, 'getuid': 8, 'syslog': 8, 'getgid': 8, 'setuid': 8,
            'setgid': 8, 'geteuid': 8, 'getegid': 8, 'setpgid': 8, 'getppid': 8,
            'getpgrp': 8, 'setsid': 8, 'setreuid': 8, 'setregid': 8,
            'getgroups': 8, 'setgroups': 8, 'setresuid': 8, 'getresuid': 8,
            'setresgid': 8, 'getresgid': 8, 'setfsuid': 8, 'setfsgid': 8,
            'getfsuid': 8, 'getfsgid': 8, 'times': 8, 'ptrace': 8,
            'getuid': 8, 'syslog': 8, 'getgid': 8, 'setuid': 8, 'setgid': 8,
            'geteuid': 8, 'getegid': 8, 'setpgid': 8, 'getppid': 8,
            'getpgrp': 8, 'setsid': 8, 'setreuid': 8, 'setregid': 8,
            'getgroups': 8, 'setgroups': 8, 'setresuid': 8, 'getresuid': 8,
            'setresgid': 8, 'getresgid': 8, 'setfsuid': 8, 'setfsgid': 8,
            'getfsuid': 8, 'getfsgid': 8, 'times': 8, 'ptrace': 8,
            
            # Very high risk - extremely suspicious
            'syscall': 10, 'sysenter': 10, 'int80': 10, 'syscall64': 10,
            'sysenter64': 10, 'int80_64': 10, 'syscall32': 10, 'sysenter32': 10,
            'int80_32': 10, 'syscall16': 10, 'sysenter16': 10, 'int80_16': 10,
            'syscall8': 10, 'sysenter8': 10, 'int80_8': 10, 'syscall4': 10,
            'sysenter4': 10, 'int80_4': 10, 'syscall2': 10, 'sysenter2': 10,
            'int80_2': 10, 'syscall1': 10, 'sysenter1': 10, 'int80_1': 10,
        }
        
        # Default risk for unknown syscalls
        self.default_risk = 2
        
        # Risk score decay factor (how quickly scores decrease over time)
        self.decay_factor = 0.95
        
        # Maximum risk score
        self.max_risk = 100
        
        # Minimum risk score
        self.min_risk = 0
        
        # Risk score history for anomaly detection
        self.score_history = deque(maxlen=1000)
        
    def get_syscall_risk(self, syscall_name: str) -> int:
        """Get risk score for a specific system call"""
        return self.syscall_risks.get(syscall_name, self.default_risk)
    
    def calculate_risk_score(self, syscalls: List[str], time_window: float = 60.0) -> float:
        """Calculate risk score based on system calls in time window"""
        if not syscalls:
            return 0.0
            
        # Calculate base score from syscalls
        base_score = sum(self.get_syscall_risk(syscall) for syscall in syscalls)
        
        # Apply time decay
        decayed_score = base_score * (1.0 - (time.time() % time_window) / time_window)
        
        # Normalize to 0-100 range
        normalized_score = min(max(decayed_score, self.min_risk), self.max_risk)
        
        return normalized_score
    
    def update_risk_score(self, current_score: float, new_syscalls: List[str]) -> float:
        """Update risk score with new system calls"""
        if not new_syscalls:
            return current_score * self.decay_factor
            
        # Calculate new score contribution
        new_contribution = sum(self.get_syscall_risk(syscall) for syscall in new_syscalls)
        
        # Update score with decay
        updated_score = (current_score * self.decay_factor) + new_contribution
        
        # Normalize to 0-100 range
        normalized_score = min(max(updated_score, self.min_risk), self.max_risk)
        
        # Store in history for anomaly detection
        self.score_history.append(normalized_score)
        
        return normalized_score


class ProcessMonitor:
    """Monitor processes and their system calls"""
    
    def __init__(self, risk_scorer: SyscallRiskScorer):
        self.risk_scorer = risk_scorer
        self.processes = {}  # pid -> process info
        self.syscall_counts = defaultdict(int)  # syscall -> count
        self.running = False
        self.console = Console()
        
    def get_process_name(self, pid: int) -> str:
        """Get process name by PID"""
        try:
            process = psutil.Process(pid)
            return process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"<unknown:{pid}>"
    
    def update_process_risk(self, pid: int, syscalls: List[str]):
        """Update risk score for a process"""
        if pid not in self.processes:
            self.processes[pid] = {
                'name': self.get_process_name(pid),
                'risk_score': 0.0,
                'syscall_count': 0,
                'last_update': time.time(),
                'syscalls': [],
                'anomaly_score': 0.0
            }
        
        process = self.processes[pid]
        
        # Update syscall list
        process['syscalls'].extend(syscalls)
        process['syscall_count'] += len(syscalls)
        process['last_update'] = time.time()
        
        # Update risk score
        current_score = process.get('risk_score', 0) or 0
        process['risk_score'] = self.risk_scorer.update_risk_score(
            current_score, syscalls
        )
        
        # Update anomaly score if anomaly detection is enabled
        if hasattr(self, 'anomaly_detector') and self.anomaly_detector:
            for syscall in syscalls:
                self.anomaly_detector.add_syscall(syscall, pid)
            process['anomaly_score'] = self.anomaly_detector.get_process_anomaly_score(pid)
        
        # Take action if action handler is enabled
        if hasattr(self, 'action_handler') and self.action_handler:
            anomaly_score = process.get('anomaly_score', 0.0)
            current_risk_score = process.get('risk_score', 0) or 0
            self.action_handler.take_action(pid, process['name'], current_risk_score, anomaly_score)
        
        # Update global syscall counts
        for syscall in syscalls:
            self.syscall_counts[syscall] += 1
    
    def get_high_risk_processes(self, threshold: float = 50.0) -> List[Tuple[int, str, float, float]]:
        """Get processes with risk scores above threshold"""
        high_risk = []
        for pid, process in self.processes.items():
            risk_score = process.get('risk_score', 0) or 0
            if risk_score >= threshold:
                anomaly_score = process.get('anomaly_score', 0.0)
                high_risk.append((pid, process['name'], risk_score, anomaly_score))
        return sorted(high_risk, key=lambda x: x[2], reverse=True)
    
    def cleanup_old_processes(self, max_age: float = 300.0):
        """Remove old process entries"""
        current_time = time.time()
        to_remove = []
        
        for pid, process in self.processes.items():
            if current_time - process['last_update'] > max_age:
                to_remove.append(pid)
        
        for pid in to_remove:
            del self.processes[pid]


class SecurityAgent:
    """Main security agent class"""
    
    def __init__(self, args):
        self.args = args
        self.risk_scorer = SyscallRiskScorer()
        self.monitor = ProcessMonitor(self.risk_scorer)
        self.console = Console()
        self.running = False
        
        # Initialize anomaly detector if available
        self.anomaly_detector = None
        if ANOMALY_DETECTION_AVAILABLE and args.anomaly_detection:
            self.anomaly_detector = AnomalyDetector()
            # Try to load existing model or train new one
            if not self.anomaly_detector.load_model():
                self.console.print("[yellow]Training anomaly detection model...[/yellow]")
                training_data = self.anomaly_detector.generate_training_data(1000)
                self.anomaly_detector.fit(training_data)
                self.console.print("[green]Anomaly detection model trained[/green]")
        
        # Initialize action handler if available
        self.action_handler = None
        if ACTION_HANDLER_AVAILABLE:
            action_config = {
                'warn_threshold': args.threshold * 0.6,  # 60% of main threshold
                'freeze_threshold': args.threshold * 1.2,  # 120% of main threshold
                'kill_threshold': args.threshold * 1.8,   # 180% of main threshold
                'enable_warnings': True,
                'enable_freeze': True,
                'enable_kill': args.enable_kill if hasattr(args, 'enable_kill') else False,
                'log_file': args.action_log
            }
            self.action_handler = ActionHandler(action_config)
            self.console.print("[green]Action handler initialized[/green]")
        
        # eBPF program for system call monitoring
        self.bpf_program = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        #include <linux/fs.h>
        #include <linux/dcache.h>
        #include <linux/version.h>
        
        struct syscall_event_t {
            u32 pid;
            u32 syscall_num;
            char comm[TASK_COMM_LEN];
            u64 timestamp;
        };
        
        BPF_PERF_OUTPUT(events);
        
        int trace_syscall(struct pt_regs *ctx) {
            struct syscall_event_t event = {};
            event.pid = bpf_get_current_pid_tgid() >> 32;
            event.syscall_num = PT_REGS_PARM1(ctx);
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            event.timestamp = bpf_ktime_get_ns();
            
            events.perf_submit(ctx, &event, sizeof(event));
            return 0;
        }
        """
        
        # System call number to name mapping
        self.syscall_names = self._load_syscall_names()
        
    def _load_syscall_names(self) -> Dict[int, str]:
        """Load system call number to name mapping"""
        # This is a simplified mapping - in production, you'd want to load
        # the full syscall table from the kernel
        syscall_names = {}
        
        # Common syscalls (x86_64)
        common_syscalls = {
            0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat',
            5: 'fstat', 6: 'lstat', 7: 'poll', 8: 'lseek', 9: 'mmap',
            10: 'mprotect', 11: 'munmap', 12: 'brk', 13: 'rt_sigaction',
            14: 'rt_sigprocmask', 15: 'rt_sigreturn', 16: 'ioctl',
            17: 'pread64', 18: 'pwrite64', 19: 'readv', 20: 'writev',
            21: 'access', 22: 'pipe', 23: 'select', 24: 'sched_yield',
            25: 'mremap', 26: 'msync', 27: 'mincore', 28: 'madvise',
            29: 'shmget', 30: 'shmat', 31: 'shmctl', 32: 'dup',
            33: 'dup2', 34: 'pause', 35: 'nanosleep', 36: 'getitimer',
            37: 'alarm', 38: 'setitimer', 39: 'getpid', 40: 'sendfile',
            41: 'socket', 42: 'connect', 43: 'accept', 44: 'sendto',
            45: 'recvfrom', 46: 'sendmsg', 47: 'recvmsg', 48: 'shutdown',
            49: 'bind', 50: 'listen', 51: 'getsockname', 52: 'getpeername',
            53: 'socketpair', 54: 'setsockopt', 55: 'getsockopt',
            56: 'clone', 57: 'fork', 58: 'vfork', 59: 'execve',
            60: 'exit', 61: 'wait4', 62: 'kill', 63: 'uname',
            64: 'semget', 65: 'semop', 66: 'semctl', 67: 'shmdt',
            68: 'msgget', 69: 'msgsnd', 70: 'msgrcv', 71: 'msgctl',
            72: 'fcntl', 73: 'flock', 74: 'fsync', 75: 'fdatasync',
            76: 'truncate', 77: 'ftruncate', 78: 'getdents', 79: 'getcwd',
            80: 'chdir', 81: 'fchdir', 82: 'rename', 83: 'mkdir',
            84: 'rmdir', 85: 'creat', 86: 'link', 87: 'unlink',
            88: 'symlink', 89: 'readlink', 90: 'chmod', 91: 'fchmod',
            92: 'chown', 93: 'fchown', 94: 'lchown', 95: 'umask',
            96: 'gettimeofday', 97: 'getrlimit', 98: 'getrusage',
            99: 'sysinfo', 100: 'times', 101: 'ptrace', 102: 'getuid',
            103: 'syslog', 104: 'getgid', 105: 'setuid', 106: 'setgid',
            107: 'geteuid', 108: 'getegid', 109: 'setpgid', 110: 'getppid',
            111: 'getpgrp', 112: 'setsid', 113: 'setreuid', 114: 'setregid',
            115: 'getgroups', 116: 'setgroups', 117: 'setresuid',
            118: 'getresuid', 119: 'setresgid', 120: 'getresgid',
            121: 'getpgid', 122: 'setfsuid', 123: 'setfsgid',
            124: 'getsid', 125: 'capget', 126: 'capset', 127: 'rt_sigpending',
            128: 'rt_sigtimedwait', 129: 'rt_sigqueueinfo', 130: 'rt_sigsuspend',
            131: 'sigaltstack', 132: 'utime', 133: 'mknod', 134: 'uselib',
            135: 'personality', 136: 'ustat', 137: 'statfs', 138: 'fstatfs',
            139: 'sysfs', 140: 'getpriority', 141: 'setpriority', 142: 'sched_setparam',
            143: 'sched_getparam', 144: 'sched_setscheduler', 145: 'sched_getscheduler',
            146: 'sched_get_priority_max', 147: 'sched_get_priority_min',
            148: 'sched_rr_get_interval', 149: 'mlock', 150: 'munlock',
            151: 'mlockall', 152: 'munlockall', 153: 'vhangup', 154: 'modify_ldt',
            155: 'pivot_root', 156: 'prctl', 157: 'arch_prctl', 158: 'adjtimex',
            159: 'setrlimit', 160: 'chroot', 161: 'sync', 162: 'acct',
            163: 'settimeofday', 164: 'mount', 165: 'umount2', 166: 'swapon',
            167: 'swapoff', 168: 'reboot', 169: 'sethostname', 170: 'setdomainname',
            171: 'iopl', 172: 'ioperm', 173: 'create_module', 174: 'init_module',
            175: 'delete_module', 176: 'get_kernel_syms', 177: 'query_module',
            178: 'quotactl', 179: 'nfsservctl', 180: 'getpmsg', 181: 'putpmsg',
            182: 'afs_syscall', 183: 'tuxcall', 184: 'security', 185: 'gettid',
            186: 'readahead', 187: 'setxattr', 188: 'lsetxattr', 189: 'fsetxattr',
            190: 'getxattr', 191: 'lgetxattr', 192: 'fgetxattr', 193: 'listxattr',
            194: 'llistxattr', 195: 'flistxattr', 196: 'removexattr',
            197: 'lremovexattr', 198: 'fremovexattr', 199: 'tkill', 200: 'time',
            201: 'futex', 202: 'sched_setaffinity', 203: 'sched_getaffinity',
            204: 'set_thread_area', 205: 'io_setup', 206: 'io_destroy',
            207: 'io_getevents', 208: 'io_submit', 209: 'io_cancel', 210: 'get_thread_area',
            211: 'lookup_dcookie', 212: 'epoll_create', 213: 'epoll_ctl_old',
            214: 'epoll_wait_old', 215: 'remap_file_pages', 216: 'getdents64',
            217: 'set_tid_address', 218: 'restart_syscall', 219: 'semtimedop',
            220: 'fadvise64', 221: 'timer_create', 222: 'timer_settime',
            223: 'timer_gettime', 224: 'timer_getoverrun', 225: 'timer_delete',
            226: 'clock_settime', 227: 'clock_gettime', 228: 'clock_getres',
            229: 'clock_nanosleep', 230: 'exit_group', 231: 'epoll_wait',
            232: 'epoll_ctl', 233: 'tgkill', 234: 'utimes', 235: 'vserver',
            236: 'mbind', 237: 'set_mempolicy', 238: 'get_mempolicy',
            239: 'mq_open', 240: 'mq_unlink', 241: 'mq_timedsend',
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
            279: 'utimensat', 280: 'epoll_pwait', 281: 'signalfd', 282: 'timerfd_create',
            283: 'eventfd', 284: 'fallocate', 285: 'timerfd_settime',
            286: 'timerfd_gettime', 287: 'accept4', 288: 'signalfd4', 289: 'eventfd2',
            290: 'epoll_create1', 291: 'dup3', 292: 'pipe2', 293: 'inotify_init1',
            294: 'preadv', 295: 'pwritev', 296: 'rt_tgsigqueueinfo',
            297: 'perf_event_open', 298: 'recvmmsg', 299: 'fanotify_init',
            300: 'fanotify_mark', 301: 'prlimit64', 302: 'name_to_handle_at',
            303: 'open_by_handle_at', 304: 'clock_adjtime', 305: 'syncfs',
            306: 'sendmmsg', 307: 'setns', 308: 'getcpu', 309: 'process_vm_readv',
            310: 'process_vm_writev', 311: 'kcmp', 312: 'finit_module',
            313: 'sched_setattr', 314: 'sched_getattr', 315: 'renameat2',
            316: 'seccomp', 317: 'getrandom', 318: 'memfd_create',
            319: 'kexec_file_load', 320: 'bpf', 321: 'execveat', 322: 'userfaultfd',
            323: 'membarrier', 324: 'mlock2', 325: 'copy_file_range',
            326: 'preadv2', 327: 'pwritev2', 328: 'pkey_mprotect', 329: 'pkey_alloc',
            330: 'pkey_free', 331: 'statx', 332: 'io_pgetevents', 333: 'rseq',
            334: 'pidfd_send_signal', 335: 'io_uring_setup', 336: 'io_uring_enter',
            337: 'io_uring_register', 338: 'openat2', 339: 'pidfd_getfd',
            340: 'close_range', 341: 'pidfd_open', 342: 'pidfd_clone',
            343: 'faccessat2', 344: 'process_madvise', 345: 'epoll_pwait2',
            346: 'mount_setattr', 347: 'quotactl_fd', 348: 'landlock_create_ruleset',
            349: 'landlock_add_rule', 350: 'landlock_restrict_self',
            351: 'memfd_secret', 352: 'process_mrelease', 353: 'futex_waitv',
            354: 'set_mempolicy_home_node'
        }
        
        return common_syscalls
    
    def start_monitoring(self):
        """Start the security monitoring"""
        self.running = True
        self.console.print("[bold green]Starting Linux Security Agent...[/bold green]")
        
        if BCC_AVAILABLE and self.args.use_ebpf:
            self._start_ebpf_monitoring()
        else:
            self._start_fallback_monitoring()
    
    def _start_ebpf_monitoring(self):
        """Start eBPF-based monitoring"""
        try:
            # Load eBPF program
            bpf = BPF(text=self.bpf_program)
            
            # Attach to syscall tracepoint
            bpf.attach_kprobe(event="sys_enter", fn_name="trace_syscall")
            
            self.console.print("[green]eBPF monitoring started[/green]")
            
            # Process events
            def process_event(cpu, data, size):
                event = bpf["events"].event(data)
                pid = event.pid
                syscall_num = event.syscall_num
                syscall_name = self.syscall_names.get(syscall_num, f"syscall_{syscall_num}")
                
                # Update process risk
                self.monitor.update_process_risk(pid, [syscall_name])
            
            # Start event processing
            bpf["events"].open_perf_buffer(process_event)
            
            while self.running:
                bpf.perf_buffer_poll()
                
                # Cleanup old processes
                self.monitor.cleanup_old_processes()
                
                # Display results
                if self.args.dashboard:
                    self._display_dashboard()
                elif self.args.output == 'json':
                    self._output_json()
                else:
                    self._output_console()
                
                time.sleep(1)
                
        except Exception as e:
            self.console.print(f"[red]eBPF monitoring failed: {e}[/red]")
            self.console.print("[yellow]Falling back to process monitoring...[/yellow]")
            self._start_fallback_monitoring()
    
    def _start_fallback_monitoring(self):
        """Start fallback monitoring using psutil"""
        self.console.print("[yellow]Using fallback monitoring (psutil)[/yellow]")
        
        while self.running:
            try:
                # Monitor all processes
                for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        
                        # Simulate some system calls based on process activity
                        # This is a simplified approach - in production you'd want
                        # more sophisticated monitoring
                        syscalls = self._simulate_syscalls_for_process(proc)
                        
                        if syscalls:
                            self.monitor.update_process_risk(pid, syscalls)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Cleanup old processes
                self.monitor.cleanup_old_processes()
                
                # Display results
                if self.args.dashboard:
                    self._display_dashboard()
                elif self.args.output == 'json':
                    self._output_json()
                else:
                    self._output_console()
                
                time.sleep(1)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.console.print(f"[red]Monitoring error: {e}[/red]")
                time.sleep(1)
    
    def _simulate_syscalls_for_process(self, proc) -> List[str]:
        """Simulate system calls for a process (fallback method)"""
        syscalls = []
        
        try:
            # Get process info
            pid = proc.info['pid']
            name = proc.info['name']
            
            # Simulate syscalls based on process characteristics
            if 'python' in name.lower():
                syscalls.extend(['read', 'write', 'open', 'close'])
                # Simulate suspicious behavior occasionally
                if pid % 100 == 0:  # 1% chance
                    syscalls.extend(['execve', 'chmod', 'setuid'])
            elif 'bash' in name.lower() or 'sh' in name.lower():
                syscalls.extend(['read', 'write', 'execve'])
                if pid % 50 == 0:  # 2% chance
                    syscalls.extend(['chmod', 'setuid', 'ptrace'])
            elif 'ls' in name.lower():
                syscalls.extend(['read', 'stat', 'getdents'])
            elif 'cat' in name.lower():
                syscalls.extend(['read', 'write', 'open', 'close'])
            else:
                # Generic syscalls
                syscalls.extend(['read', 'write', 'open', 'close'])
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return syscalls
    
    def _display_dashboard(self):
        """Display real-time dashboard"""
        # Clear screen
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Create dashboard
        table = Table(title="Linux Security Agent - Process Risk Dashboard", box=box.ROUNDED)
        table.add_column("PID", style="cyan", no_wrap=True)
        table.add_column("Process Name", style="magenta")
        table.add_column("Risk Score", style="red")
        table.add_column("Syscalls", style="yellow")
        table.add_column("Last Update", style="green")
        
        # Add processes to table
        for pid, process in sorted(self.monitor.processes.items(), 
                                 key=lambda x: x[1].get('risk_score', 0) or 0, reverse=True):
            risk_score = process.get('risk_score', 0) or 0
            anomaly_score = process.get('anomaly_score', 0.0)
            risk_color = "red" if risk_score >= 50 else "yellow" if risk_score >= 20 else "green"
            
            # Add anomaly score to display if available
            display_score = f"{risk_score:.1f}"
            if anomaly_score != 0.0:
                display_score += f" (A:{anomaly_score:.2f})"
            
            table.add_row(
                str(pid),
                process['name'],
                f"[{risk_color}]{display_score}[/{risk_color}]",
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
        
        # Display frozen processes if action handler is available
        if hasattr(self, 'action_handler') and self.action_handler:
            frozen_processes = self.action_handler.get_frozen_processes()
            if frozen_processes:
                self.console.print(f"\n[bold yellow]Frozen Processes:[/bold yellow]")
                for pid, name in frozen_processes:
                    self.console.print(f"  PID {pid}: {name}")
    
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
        self.console.print("\n[bold red]Security Agent stopped[/bold red]")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global agent
    if agent:
        agent.stop_monitoring()
    sys.exit(0)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Linux Security Agent')
    parser.add_argument('--threshold', type=float, default=50.0,
                       help='Risk score threshold for alerts (default: 50.0)')
    parser.add_argument('--output', choices=['console', 'json'], default='console',
                       help='Output format (default: console)')
    parser.add_argument('--dashboard', action='store_true',
                       help='Display real-time dashboard')
    parser.add_argument('--use-ebpf', action='store_true', default=True,
                       help='Use eBPF monitoring (default: True)')
    parser.add_argument('--anomaly-detection', action='store_true',
                       help='Enable anomaly detection')
    parser.add_argument('--enable-kill', action='store_true',
                       help='Enable kill action (DANGEROUS - use with caution)')
    parser.add_argument('--action-log', type=str, default='/var/log/security_agent.log',
                       help='Log file for actions (default: /var/log/security_agent.log)')
    
    args = parser.parse_args()
    
    # Check if running as root (required for eBPF)
    if args.use_ebpf and os.geteuid() != 0:
        print("Error: eBPF monitoring requires root privileges")
        print("Run with sudo or use --no-ebpf flag")
        sys.exit(1)
    
    # Create and start agent
    global agent
    agent = SecurityAgent(args)
    
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
