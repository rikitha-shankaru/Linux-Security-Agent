#!/usr/bin/env python3
"""
Advanced Risk Scoring Engine with Behavioral Baselining
Similar to CrowdStrike's Falcon platform
"""

import time
import json
import hashlib
import numpy as np
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
import pickle
import os

@dataclass
class ProcessProfile:
    """Process behavioral profile"""
    pid: int
    name: str
    path: str
    command_line: str
    parent_pid: int
    start_time: float
    user_id: int
    group_id: int
    
    # Behavioral metrics
    syscall_patterns: Dict[str, int]
    file_access_patterns: List[str]
    network_connections: List[Tuple[str, int]]
    process_children: List[int]
    
    # Risk indicators
    privilege_escalation_attempts: int
    suspicious_file_access: int
    network_anomalies: int
    process_injection_attempts: int
    
    # Baseline data
    baseline_syscalls: Dict[str, float]
    baseline_file_access: List[str]
    baseline_network: List[Tuple[str, int]]
    
    # Risk score
    current_risk_score: float
    max_risk_score: float
    risk_trend: List[float]
    
    # Timestamps
    last_update: float
    last_risk_calculation: float

class BehavioralBaseline:
    """Behavioral baseline for processes"""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.baselines = {}  # process_hash -> baseline_data
        self.learning_period = 3600  # 1 hour learning period
        self.min_samples = 100  # Minimum samples for baseline
        
    def add_sample(self, process_hash: str, syscalls: List[str], 
                   file_access: List[str], network: List[Tuple[str, int]]):
        """Add sample to baseline"""
        if process_hash not in self.baselines:
            self.baselines[process_hash] = {
                'syscalls': deque(maxlen=self.window_size),
                'file_access': deque(maxlen=self.window_size),
                'network': deque(maxlen=self.window_size),
                'timestamps': deque(maxlen=self.window_size),
                'sample_count': 0
            }
        
        baseline = self.baselines[process_hash]
        baseline['syscalls'].append(syscalls)
        baseline['file_access'].append(file_access)
        baseline['network'].append(network)
        baseline['timestamps'].append(time.time())
        baseline['sample_count'] += 1
    
    def get_baseline(self, process_hash: str) -> Optional[Dict]:
        """Get baseline for process"""
        if process_hash not in self.baselines:
            return None
        
        baseline = self.baselines[process_hash]
        
        # Check if we have enough samples
        if baseline['sample_count'] < self.min_samples:
            return None
        
        # Check if baseline is recent enough
        if baseline['timestamps']:
            age = time.time() - max(baseline['timestamps'])
            if age > self.learning_period * 2:  # Baseline too old
                return None
        
        # Calculate baseline statistics
        syscall_freq = defaultdict(int)
        for syscall_list in baseline['syscalls']:
            for syscall in syscall_list:
                syscall_freq[syscall] += 1
        
        # Normalize frequencies
        total_syscalls = sum(syscall_freq.values())
        if total_syscalls > 0:
            for syscall in syscall_freq:
                syscall_freq[syscall] /= total_syscalls
        
        return {
            'syscall_frequencies': dict(syscall_freq),
            'common_file_access': list(set().union(*baseline['file_access'])),
            'common_network': list(set().union(*baseline['network'])),
            'sample_count': baseline['sample_count'],
            'last_updated': max(baseline['timestamps']) if baseline['timestamps'] else 0
        }

class AdvancedRiskEngine:
    """Advanced risk scoring engine with behavioral analysis"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.processes = {}  # pid -> ProcessProfile
        self.baseline = BehavioralBaseline()
        self.risk_rules = self._load_risk_rules()
        
        # Risk scoring weights
        self.weights = {
            'syscall_anomaly': 0.3,
            'file_access_anomaly': 0.2,
            'network_anomaly': 0.15,
            'privilege_escalation': 0.2,
            'process_injection': 0.1,
            'temporal_anomaly': 0.05
        }
        
        # Risk thresholds
        self.thresholds = {
            'low': 20,
            'medium': 50,
            'high': 80,
            'critical': 95
        }
        
        # Threading
        self.lock = threading.RLock()
        
    def _load_risk_rules(self) -> Dict:
        """Load risk assessment rules"""
        return {
            'high_risk_syscalls': {
                'ptrace': 10, 'setuid': 8, 'setgid': 8, 'setreuid': 8,
                'setregid': 8, 'setresuid': 8, 'setresgid': 8,
                'chroot': 7, 'mount': 6, 'umount': 6, 'pivot_root': 8,
                'execve': 5, 'execveat': 5, 'clone': 4, 'fork': 3
            },
            'suspicious_file_patterns': [
                '/etc/passwd', '/etc/shadow', '/etc/sudoers',
                '/root/.ssh/', '/home/*/.ssh/', '*.key', '*.pem',
                '/proc/self/mem', '/dev/mem', '/dev/kmem'
            ],
            'suspicious_network_patterns': [
                ('.*', 22),  # SSH
                ('.*', 3389),  # RDP
                ('.*', 5985),  # WinRM
                ('.*', 445),   # SMB
            ],
            'process_injection_indicators': [
                'ptrace', 'process_vm_writev', 'process_vm_readv'
            ]
        }
    
    def _calculate_process_hash(self, name: str, path: str, command_line: str) -> str:
        """Calculate unique hash for process"""
        content = f"{name}:{path}:{command_line}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def update_process(self, pid: int, name: str, path: str, command_line: str,
                      parent_pid: int, user_id: int, group_id: int):
        """Update process information"""
        with self.lock:
            if pid not in self.processes:
                self.processes[pid] = ProcessProfile(
                    pid=pid,
                    name=name,
                    path=path,
                    command_line=command_line,
                    parent_pid=parent_pid,
                    start_time=time.time(),
                    user_id=user_id,
                    group_id=group_id,
                    syscall_patterns={},
                    file_access_patterns=[],
                    network_connections=[],
                    process_children=[],
                    privilege_escalation_attempts=0,
                    suspicious_file_access=0,
                    network_anomalies=0,
                    process_injection_attempts=0,
                    baseline_syscalls={},
                    baseline_file_access=[],
                    baseline_network=[],
                    current_risk_score=0.0,
                    max_risk_score=0.0,
                    risk_trend=[],
                    last_update=time.time(),
                    last_risk_calculation=time.time()
                )
            
            self.processes[pid].last_update = time.time()
    
    def add_syscall(self, pid: int, syscall_name: str, args: List[int] = None):
        """Add system call to process"""
        with self.lock:
            if pid not in self.processes:
                return
            
            process = self.processes[pid]
            process.syscall_patterns[syscall_name] = process.syscall_patterns.get(syscall_name, 0) + 1
            
            # Check for high-risk syscalls
            if syscall_name in self.risk_rules['high_risk_syscalls']:
                risk_value = self.risk_rules['high_risk_syscalls'][syscall_name]
                process.current_risk_score += risk_value
            
            # Check for privilege escalation
            if syscall_name in ['setuid', 'setgid', 'setreuid', 'setregid', 'setresuid', 'setresgid']:
                process.privilege_escalation_attempts += 1
            
            # Check for process injection
            if syscall_name in self.risk_rules['process_injection_indicators']:
                process.process_injection_attempts += 1
            
            # Update risk trend
            process.risk_trend.append(process.current_risk_score)
            if len(process.risk_trend) > 100:  # Keep last 100 scores
                process.risk_trend.pop(0)
            
            process.max_risk_score = max(process.max_risk_score, process.current_risk_score)
            process.last_risk_calculation = time.time()
    
    def add_file_access(self, pid: int, file_path: str):
        """Add file access to process"""
        with self.lock:
            if pid not in self.processes:
                return
            
            process = self.processes[pid]
            process.file_access_patterns.append(file_path)
            
            # Check for suspicious file access
            for pattern in self.risk_rules['suspicious_file_patterns']:
                if pattern in file_path or self._match_pattern(file_path, pattern):
                    process.suspicious_file_access += 1
                    process.current_risk_score += 5
                    break
    
    def add_network_connection(self, pid: int, host: str, port: int):
        """Add network connection to process"""
        with self.lock:
            if pid not in self.processes:
                return
            
            process = self.processes[pid]
            process.network_connections.append((host, port))
            
            # Check for suspicious network patterns
            for pattern_host, pattern_port in self.risk_rules['suspicious_network_patterns']:
                if (self._match_pattern(host, pattern_host) and 
                    (pattern_port == port or pattern_port == -1)):
                    process.network_anomalies += 1
                    process.current_risk_score += 3
                    break
    
    def _match_pattern(self, text: str, pattern: str) -> bool:
        """Simple pattern matching"""
        if '*' in pattern:
            import fnmatch
            return fnmatch.fnmatch(text, pattern)
        return pattern in text
    
    def calculate_behavioral_risk(self, pid: int) -> float:
        """Calculate behavioral risk score"""
        with self.lock:
            if pid not in self.processes:
                return 0.0
            
            process = self.processes[pid]
            process_hash = self._calculate_process_hash(
                process.name, process.path, process.command_line
            )
            
            # Get baseline
            baseline = self.baseline.get_baseline(process_hash)
            
            if not baseline:
                # No baseline available, use rule-based scoring
                return self._calculate_rule_based_risk(process)
            
            # Calculate behavioral anomalies
            syscall_anomaly = self._calculate_syscall_anomaly(process, baseline)
            file_anomaly = self._calculate_file_anomaly(process, baseline)
            network_anomaly = self._calculate_network_anomaly(process, baseline)
            
            # Calculate temporal anomaly
            temporal_anomaly = self._calculate_temporal_anomaly(process)
            
            # Weighted risk score
            risk_score = (
                syscall_anomaly * self.weights['syscall_anomaly'] +
                file_anomaly * self.weights['file_access_anomaly'] +
                network_anomaly * self.weights['network_anomaly'] +
                process.privilege_escalation_attempts * self.weights['privilege_escalation'] +
                process.process_injection_attempts * self.weights['process_injection'] +
                temporal_anomaly * self.weights['temporal_anomaly']
            )
            
            # Normalize to 0-100 scale
            risk_score = min(100.0, max(0.0, risk_score))
            
            return risk_score
    
    def _calculate_syscall_anomaly(self, process: ProcessProfile, baseline: Dict) -> float:
        """Calculate syscall pattern anomaly"""
        if not baseline['syscall_frequencies']:
            return 0.0
        
        # Calculate current syscall frequencies
        total_syscalls = sum(process.syscall_patterns.values())
        if total_syscalls == 0:
            return 0.0
        
        current_freq = {}
        for syscall, count in process.syscall_patterns.items():
            current_freq[syscall] = count / total_syscalls
        
        # Calculate anomaly score
        anomaly_score = 0.0
        for syscall, baseline_freq in baseline['syscall_frequencies'].items():
            current_freq_val = current_freq.get(syscall, 0.0)
            # Calculate deviation from baseline
            deviation = abs(current_freq_val - baseline_freq)
            anomaly_score += deviation * 100  # Scale to 0-100
        
        return min(100.0, anomaly_score)
    
    def _calculate_file_anomaly(self, process: ProcessProfile, baseline: Dict) -> float:
        """Calculate file access anomaly"""
        if not baseline['common_file_access']:
            return 0.0
        
        # Count new file accesses not in baseline
        new_accesses = 0
        for file_path in process.file_access_patterns:
            if file_path not in baseline['common_file_access']:
                new_accesses += 1
        
        # Calculate anomaly score
        total_accesses = len(process.file_access_patterns)
        if total_accesses == 0:
            return 0.0
        
        anomaly_ratio = new_accesses / total_accesses
        return anomaly_ratio * 100
    
    def _calculate_network_anomaly(self, process: ProcessProfile, baseline: Dict) -> float:
        """Calculate network anomaly"""
        if not baseline['common_network']:
            return 0.0
        
        # Count new network connections not in baseline
        new_connections = 0
        for connection in process.network_connections:
            if connection not in baseline['common_network']:
                new_connections += 1
        
        # Calculate anomaly score
        total_connections = len(process.network_connections)
        if total_connections == 0:
            return 0.0
        
        anomaly_ratio = new_connections / total_connections
        return anomaly_ratio * 100
    
    def _calculate_temporal_anomaly(self, process: ProcessProfile) -> float:
        """Calculate temporal anomaly (unusual timing patterns)"""
        if len(process.risk_trend) < 10:
            return 0.0
        
        # Calculate risk score volatility
        risk_scores = np.array(process.risk_trend)
        volatility = np.std(risk_scores)
        
        # High volatility indicates suspicious behavior
        return min(100.0, volatility * 10)
    
    def _calculate_rule_based_risk(self, process: ProcessProfile) -> float:
        """Calculate rule-based risk score when no baseline available"""
        risk_score = 0.0
        
        # Base risk from syscalls
        for syscall, count in process.syscall_patterns.items():
            if syscall in self.risk_rules['high_risk_syscalls']:
                risk_score += self.risk_rules['high_risk_syscalls'][syscall] * count
        
        # Add risk from other indicators
        risk_score += process.privilege_escalation_attempts * 10
        risk_score += process.suspicious_file_access * 5
        risk_score += process.network_anomalies * 3
        risk_score += process.process_injection_attempts * 15
        
        return min(100.0, risk_score)
    
    def get_risk_level(self, risk_score: float) -> str:
        """Get risk level from score"""
        if risk_score >= self.thresholds['critical']:
            return 'critical'
        elif risk_score >= self.thresholds['high']:
            return 'high'
        elif risk_score >= self.thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def get_high_risk_processes(self, threshold: float = 50.0) -> List[Tuple[int, ProcessProfile, float]]:
        """Get processes with risk scores above threshold"""
        with self.lock:
            high_risk = []
            for pid, process in self.processes.items():
                risk_score = self.calculate_behavioral_risk(pid)
                if risk_score >= threshold:
                    high_risk.append((pid, process, risk_score))
            
            return sorted(high_risk, key=lambda x: x[2], reverse=True)
    
    def export_process_data(self, pid: int) -> Dict:
        """Export process data for analysis"""
        with self.lock:
            if pid not in self.processes:
                return {}
            
            process = self.processes[pid]
            return asdict(process)
    
    def save_baselines(self, filepath: str):
        """Save behavioral baselines"""
        with self.lock:
            with open(filepath, 'wb') as f:
                pickle.dump(self.baseline.baselines, f)
    
    def load_baselines(self, filepath: str):
        """Load behavioral baselines"""
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                self.baseline.baselines = pickle.load(f)

# Example usage
if __name__ == "__main__":
    engine = AdvancedRiskEngine()
    
    # Simulate process monitoring
    engine.update_process(1234, "python3", "/usr/bin/python3", "python3 script.py", 1000, 1000, 1000)
    
    # Add some syscalls
    engine.add_syscall(1234, "read")
    engine.add_syscall(1234, "write")
    engine.add_syscall(1234, "setuid")  # High risk
    
    # Calculate risk
    risk_score = engine.calculate_behavioral_risk(1234)
    risk_level = engine.get_risk_level(risk_score)
    
    print(f"Process 1234: Risk Score {risk_score:.1f}, Level: {risk_level}")
