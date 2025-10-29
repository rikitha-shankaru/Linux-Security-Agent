#!/usr/bin/env python3
"""
Enhanced eBPF-based system call monitoring for production EDR
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

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    print("Warning: BCC not available. Install with: sudo apt install python3-bpfcc")

@dataclass
class SyscallEvent:
    """Structured system call event"""
    pid: int  
    ppid: int
    tid: int
    syscall_num: int
    syscall_name: str
    timestamp: float
    comm: str
    args: List[int]
    retval: int
    cpu: int
    flags: int

class EnhancedEBPFMonitor:
    """Production-grade eBPF system call monitor"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.running = False
        self.events = deque(maxlen=100000)  # Ring buffer for events
        self.process_tree = {}  # Process parent-child relationships
        self.syscall_stats = defaultdict(int)
        
        # Performance tuning
        self.batch_size = self.config.get('batch_size', 1000)
        self.buffer_size = self.config.get('buffer_size', 1024 * 1024)  # 1MB
        
        # eBPF program with enhanced monitoring
        self.bpf_program = self._get_enhanced_bpf_program()
        self.syscall_names = self._load_syscall_names()
        
    def _get_enhanced_bpf_program(self) -> str:
        """Enhanced eBPF program for comprehensive monitoring"""
        return """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        #include <linux/fs.h>
        #include <linux/dcache.h>
        #include <linux/version.h>
        #include <linux/cred.h>
        #include <linux/security.h>
        
        struct syscall_event_t {
            u32 pid;
            u32 ppid;
            u32 tid;
            u32 syscall_num;
            u64 timestamp;
            char comm[TASK_COMM_LEN];
            u64 args[6];
            long retval;
            u32 cpu;
            u32 flags;
        };
        
        BPF_PERF_OUTPUT(events);
        BPF_HASH(process_tree, u32, u32);  // pid -> ppid mapping
        
        int trace_syscall_enter(struct pt_regs *ctx) {
            struct syscall_event_t event = {};
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
            
            event.pid = pid;
            event.tid = tid;
            event.syscall_num = PT_REGS_PARM1(ctx);
            event.timestamp = bpf_ktime_get_ns();
            event.cpu = bpf_get_smp_processor_id();
            
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            
            // Get process parent
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            event.ppid = task->real_parent->tgid;
            
            // Store process tree info
            process_tree.update(&pid, &event.ppid);
            
            // Get syscall arguments
            event.args[0] = PT_REGS_PARM2(ctx);
            event.args[1] = PT_REGS_PARM3(ctx);
            event.args[2] = PT_REGS_PARM4(ctx);
            event.args[3] = PT_REGS_PARM5(ctx);
            event.args[4] = PT_REGS_PARM6(ctx);
            event.args[5] = PT_REGS_PARM7(ctx);
            
            // Set flags for interesting syscalls
            if (event.syscall_num == 59 || event.syscall_num == 322) {  // execve, execveat
                event.flags |= 0x01;  // EXEC_FLAG
            }
            if (event.syscall_num == 105 || event.syscall_num == 106) {  // setuid, setgid
                event.flags |= 0x02;  // PRIV_ESC_FLAG
            }
            if (event.syscall_num == 101) {  // ptrace
                event.flags |= 0x04;  // DEBUG_FLAG
            }
            
            events.perf_submit(ctx, &event, sizeof(event));
            return 0;
        }
        
        int trace_syscall_exit(struct pt_regs *ctx) {
            struct syscall_event_t event = {};
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
            
            event.pid = pid;
            event.tid = tid;
            event.syscall_num = PT_REGS_PARM1(ctx);
            event.timestamp = bpf_ktime_get_ns();
            event.retval = PT_REGS_RC(ctx);
            event.cpu = bpf_get_smp_processor_id();
            
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            
            // Get process parent
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            event.ppid = task->real_parent->tgid;
            
            events.perf_submit(ctx, &event, sizeof(event));
            return 0;
        }
        """
    
    def _load_syscall_names(self) -> Dict[int, str]:
        """Load comprehensive system call names"""
        # This would typically load from /usr/include/asm/unistd.h
        # For now, using a comprehensive mapping
        syscalls = {}
        
        # Load from system if available
        try:
            with open('/usr/include/asm/unistd_64.h', 'r') as f:
                for line in f:
                    if line.startswith('#define __NR_'):
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            name = parts[1].replace('__NR_', '')
                            num = int(parts[2])
                            syscalls[num] = name
        except FileNotFoundError:
            # Fallback to hardcoded mapping
            pass
        
        # Add common syscalls if not loaded from system
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
            101: 'ptrace', 102: 'getuid', 105: 'setuid', 106: 'setgid',
            160: 'chroot', 161: 'sync', 162: 'acct', 163: 'settimeofday',
            164: 'mount', 165: 'umount2', 322: 'execveat'
        }
        
        syscalls.update(common_syscalls)
        return syscalls
    
    def start_monitoring(self, callback=None):
        """Start eBPF monitoring"""
        if not BCC_AVAILABLE:
            raise RuntimeError("BCC not available")
        
        self.running = True
        
        # Load eBPF program
        bpf = BPF(text=self.bpf_program)
        
        # Attach to syscall tracepoints
        bpf.attach_kprobe(event="sys_enter", fn_name="trace_syscall_enter")
        bpf.attach_kprobe(event="sys_exit", fn_name="trace_syscall_exit")
        
        # Process events
        def process_event(cpu, data, size):
            if not self.running:
                return
                
            event = bpf["events"].event(data)
            
            # Convert to structured event
            syscall_event = SyscallEvent(
                pid=event.pid,
                ppid=event.ppid,
                tid=event.tid,
                syscall_num=event.syscall_num,
                syscall_name=self.syscall_names.get(event.syscall_num, f"syscall_{event.syscall_num}"),
                timestamp=event.timestamp / 1e9,  # Convert to seconds
                comm=event.comm.decode('utf-8', errors='ignore'),
                args=[event.args[i] for i in range(6)],
                retval=event.retval,
                cpu=event.cpu,
                flags=event.flags
            )
            
            # Add to event buffer
            self.events.append(syscall_event)
            
            # Update statistics
            self.syscall_stats[syscall_event.syscall_name] += 1
            
            # Call callback if provided
            if callback:
                callback(syscall_event)
        
        # Start event processing
        bpf["events"].open_perf_buffer(process_event, page_cnt=self.buffer_size // 4096)
        
        # Main monitoring loop
        while self.running:
            try:
                bpf.perf_buffer_poll(timeout=100)  # 100ms timeout
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(0.1)
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
    
    def get_recent_events(self, count: int = 1000) -> List[SyscallEvent]:
        """Get recent events"""
        return list(self.events)[-count:]
    
    def get_process_tree(self) -> Dict[int, int]:
        """Get process parent-child relationships"""
        return dict(self.process_tree)
    
    def get_syscall_stats(self) -> Dict[str, int]:
        """Get system call statistics"""
        return dict(self.syscall_stats)
    
    def export_events(self, format: str = 'json') -> str:
        """Export events in specified format"""
        if format == 'json':
            events_data = [asdict(event) for event in self.events]
            return json.dumps(events_data, indent=2)
        elif format == 'csv':
            # CSV export implementation
            pass
        return ""

# Example usage
if __name__ == "__main__":
    monitor = EnhancedEBPFMonitor()
    
    def event_callback(event: SyscallEvent):
        print(f"PID {event.pid}: {event.syscall_name} (ret: {event.retval})")
    
    try:
        monitor.start_monitoring(callback=event_callback)
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("Monitoring stopped")
