"""
Enhanced risk scoring system with behavioral baselining
"""
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any


class EnhancedRiskScorer:
    """
    Enhanced risk scoring system with behavioral baselining and adaptive thresholds
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        
        # Risk scoring parameters (allow overrides from config)
        default_base = {
            # Low risk - normal operations
            'read': 1, 'write': 1, 'open': 1, 'close': 1, 'lseek': 1,
            'stat': 1, 'fstat': 1, 'lstat': 1, 'access': 1, 'readlink': 1,
            'getcwd': 1, 'chdir': 1, 'fchdir': 1, 'getpid': 1, 'getppid': 1,
            'getuid': 1, 'getgid': 1, 'geteuid': 1, 'getegid': 1,
            'socket': 1, 'bind': 1, 'listen': 1, 'accept': 1, 'connect': 1,
            'send': 1, 'recv': 1, 'sendto': 1, 'recvfrom': 1, 'shutdown': 1,
            
            # Medium risk - potentially suspicious
            'fork': 3, 'vfork': 3, 'clone': 3, 'execve': 5, 'execveat': 5,
            'chmod': 3, 'fchmod': 3, 'chown': 3, 'fchown': 3, 'lchown': 3,
            'rename': 3, 'unlink': 3, 'rmdir': 3, 'mkdir': 3, 'mknod': 3,
            'symlink': 3, 'link': 3, 'mount': 4, 'umount': 4, 'umount2': 4,
            
            # High risk - very suspicious
            'ptrace': 10, 'setuid': 8, 'setgid': 8, 'chroot': 8, 'pivot_root': 8,
            'reboot': 10, 'sethostname': 6, 'setdomainname': 6, 'iopl': 8,
            'ioperm': 8, 'create_module': 10, 'init_module': 10, 'delete_module': 10
        }
        self.base_risk_scores = dict(default_base)
        if isinstance(self.config.get('base_risk_scores'), dict):
            try:
                # Shallow merge: override provided keys
                self.base_risk_scores.update(self.config['base_risk_scores'])
            except Exception:
                pass
        
        # Adaptive risk scoring
        self.process_baselines = {}  # pid -> baseline behavior
        # Use deque with maxlen to prevent unbounded growth
        self.risk_history = defaultdict(lambda: deque(maxlen=50))  # pid -> risk history (max 50 entries)
        self.adaptive_thresholds = {}  # pid -> adaptive threshold
        
        # Time decay parameters
        self.decay_factor = self.config.get('decay_factor', 0.95)
        self.decay_interval = self.config.get('decay_interval', 60)  # seconds
        
        # Behavioral analysis
        self.behavioral_window = self.config.get('behavioral_window', 100)
        self.anomaly_weight = self.config.get('anomaly_weight', 0.3)
    
    def update_risk_score(self, pid: int, syscalls: List[str], 
                         process_info: Optional[Dict[str, Any]] = None, 
                         anomaly_score: float = 0.0, 
                         container_id: Optional[str] = None) -> float:
        """
        Update risk score with enhanced behavioral analysis
        """
        current_time = time.time()
        
        # Initialize process baseline if needed
        if pid not in self.process_baselines:
            self.process_baselines[pid] = {
                'syscall_frequencies': defaultdict(int),
                'temporal_patterns': deque(maxlen=self.behavioral_window),
                'resource_usage': {},
                'last_updated': current_time,
                'sample_count': 0
            }
        
        baseline = self.process_baselines[pid]
        
        # Calculate base risk score
        base_score = 0.0
        for syscall in syscalls:
            base_score += self.base_risk_scores.get(syscall, 2)
        
        # Normalize by number of syscalls
        if syscalls:
            base_score = base_score / len(syscalls) * 10  # Scale to 0-100
        
        # Apply behavioral analysis
        behavioral_score = self._calculate_behavioral_score(pid, syscalls, process_info)
        
        # Apply container-specific adjustments
        container_score = self._calculate_container_score(pid, syscalls, container_id)
        
        # Combine scores with weights
        final_score = (
            base_score * 0.4 +
            behavioral_score * 0.3 +
            anomaly_score * self.anomaly_weight +
            container_score * 0.1
        )
        
        # Apply time decay (relative to last update if available)
        if pid in self.risk_history and self.risk_history[pid]:
            last_score = self.risk_history[pid][-1]
            time_since_last = current_time - baseline['last_updated']
            if time_since_last > self.decay_interval:
                decayed_score = last_score * (self.decay_factor ** (time_since_last / self.decay_interval))
                final_score = max(final_score, decayed_score)
        
        # Update history and baseline
        # deque with maxlen automatically handles size limit
        self.risk_history[pid].append(final_score)
        
        self._update_behavioral_baseline(pid, syscalls, process_info)
        
        # Clamp to 0-100 range
        return min(100.0, max(0.0, final_score))
    
    def _calculate_behavioral_score(self, pid: int, syscalls: List[str], 
                                    process_info: Optional[Dict[str, Any]] = None) -> float:
        """Calculate behavioral deviation score"""
        if pid not in self.process_baselines:
            return 0.0
        
        baseline = self.process_baselines[pid]
        
        # Calculate syscall frequency deviation
        current_frequencies = defaultdict(int)
        for syscall in syscalls:
            current_frequencies[syscall] += 1
        
        total_syscalls = len(syscalls)
        if total_syscalls == 0:
            return 0.0
        
        # Compare with baseline
        deviation_score = 0.0
        # Total baseline counts
        baseline_total = sum(baseline['syscall_frequencies'].values()) or 1
        for syscall, count in current_frequencies.items():
            current_freq = count / total_syscalls
            baseline_freq = baseline['syscall_frequencies'].get(syscall, 0) / baseline_total
            
            # Calculate deviation
            deviation = abs(current_freq - baseline_freq)
            deviation_score += deviation * 10  # Scale to 0-100
        
        # Resource usage deviation
        if process_info:
            cpu_deviation = abs(process_info.get('cpu_percent', 0) - baseline['resource_usage'].get('cpu_percent', 0))
            memory_deviation = abs(process_info.get('memory_percent', 0) - baseline['resource_usage'].get('memory_percent', 0))
            
            deviation_score += (cpu_deviation + memory_deviation) * 0.1
        
        return min(100.0, deviation_score)
    
    def _calculate_container_score(self, pid: int, syscalls: List[str], 
                                   container_id: Optional[str] = None) -> float:
        """Calculate container-specific risk score"""
        if not container_id:
            return 0.0
        
        # Container-specific risk adjustments
        container_risk = 0.0
        
        # Check for container escape attempts
        escape_syscalls = ['mount', 'umount', 'chroot', 'pivot_root', 'setns']
        for syscall in syscalls:
            if syscall in escape_syscalls:
                container_risk += 5
        
        # Check for privilege escalation
        privilege_syscalls = ['setuid', 'setgid', 'seteuid', 'setegid']
        for syscall in syscalls:
            if syscall in privilege_syscalls:
                container_risk += 3
        
        return min(100.0, container_risk)
    
    def _update_behavioral_baseline(self, pid: int, syscalls: List[str], 
                                    process_info: Optional[Dict[str, Any]] = None) -> None:
        """Update behavioral baseline for a process"""
        if pid not in self.process_baselines:
            return
        
        baseline = self.process_baselines[pid]
        
        # Update syscall frequencies (cap size to avoid unbounded growth)
        for syscall in syscalls:
            baseline['syscall_frequencies'][syscall] += 1
        # Cap to top-N most frequent entries
        max_keys = int(self.config.get('baseline_max_keys', 500))
        if len(baseline['syscall_frequencies']) > max_keys:
            # Keep top-N by count
            top_items = sorted(baseline['syscall_frequencies'].items(), key=lambda x: x[1], reverse=True)[:max_keys]
            baseline['syscall_frequencies'].clear()
            baseline['syscall_frequencies'].update(top_items)
        
        # Update resource usage
        if process_info:
            baseline['resource_usage'].update({
                'cpu_percent': process_info.get('cpu_percent', 0),
                'memory_percent': process_info.get('memory_percent', 0)
            })
        
        baseline['last_updated'] = time.time()
        baseline['sample_count'] += 1

