#!/usr/bin/env python3
"""
Container-Aware Security Monitoring
Based on recent research: "Cross Container Attacks: The Bewildered eBPF on Clouds" (2023)
"""

import os
import sys
import time
import json
import psutil
import threading
import logging

# Setup logging
logger = logging.getLogger('security_agent.container')

# Docker is optional - only needed for container monitoring
try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None  # Placeholder for type checking
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess
import re

@dataclass
class ContainerInfo:
    """Container information structure"""
    container_id: str
    name: str
    image: str
    status: str
    pid: int
    created_at: str
    network_mode: str
    privileged: bool
    security_options: List[str]
    mounts: List[Dict[str, str]]
    environment: Dict[str, str]

@dataclass
class CrossContainerAttempt:
    """Cross-container attack attempt"""
    timestamp: float
    source_container: str
    target_container: str
    source_pid: int
    target_pid: int
    syscall: str
    severity: str
    blocked: bool
    details: Dict[str, Any]

@dataclass
class ContainerSecurityPolicy:
    """Container-specific security policy"""
    container_id: str
    policy_name: str
    allowed_syscalls: List[str]
    blocked_syscalls: List[str]
    max_syscall_rate: int
    max_memory_usage: int
    max_cpu_usage: float
    network_restrictions: bool
    filesystem_restrictions: bool
    privileged_operations: bool
    cross_container_access: bool
    created_at: float
    updated_at: float

class ContainerSecurityMonitor:
    """
    Container-aware security monitoring system
    Prevents cross-container attacks and enforces container-specific policies
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.running = False
        
        # Thread locks for shared data
        self.containers_lock = threading.Lock()
        self.policies_lock = threading.Lock()
        self.attempts_lock = threading.Lock()
        
        # Docker client (optional - only needed for container monitoring)
        self.docker_client = None
        self.docker_available = False
        
        if DOCKER_AVAILABLE:
            try:
                self.docker_client = docker.from_env()
                self.docker_available = True
            except Exception as e:
                logger.info(f"Docker not running - container monitoring disabled: {e}")
        else:
            logger.info("docker package not installed - container monitoring disabled")
        
        # Container tracking
        self.containers = {}  # container_id -> ContainerInfo
        self.container_processes = {}  # pid -> container_id
        self.container_boundaries = {}  # container_id -> set of pids
        self.process_containers = {}  # pid -> container_id
        
        # Cache for container lookups (PID -> container_id, with TTL)
        self._container_lookup_cache = {}  # pid -> (container_id, timestamp)
        self._container_cache_ttl = 60  # 1 minute TTL
        
        # Security policies
        self.container_policies = {}  # container_id -> ContainerSecurityPolicy
        self.default_policy = self._create_default_policy()
        
        # Attack detection
        self.cross_container_attempts = deque(maxlen=10000)
        self.policy_violations = deque(maxlen=10000)
        self.security_events = deque(maxlen=10000)
        
        # Monitoring threads
        self.monitor_thread = None
        self.policy_thread = None
        
        # Statistics
        self.stats = {
            'total_containers': 0,
            'active_containers': 0,
            'cross_container_attempts': 0,
            'policy_violations': 0,
            'blocked_attempts': 0
        }
    
    def _create_default_policy(self) -> ContainerSecurityPolicy:
        """Create default security policy for containers"""
        return ContainerSecurityPolicy(
            container_id="default",
            policy_name="Default Container Policy",
            allowed_syscalls=[
                'read', 'write', 'open', 'close', 'mmap', 'munmap',
                'fork', 'execve', 'exit', 'exit_group', 'waitpid',
                'socket', 'bind', 'listen', 'accept', 'connect',
                'send', 'recv', 'sendto', 'recvfrom', 'shutdown'
            ],
            blocked_syscalls=[
                'ptrace', 'mount', 'umount', 'reboot', 'setuid',
                'setgid', 'chroot', 'pivot_root', 'acct', 'swapon',
                'swapoff', 'sethostname', 'setdomainname', 'iopl',
                'ioperm', 'create_module', 'init_module', 'delete_module'
            ],
            max_syscall_rate=1000,
            max_memory_usage=512 * 1024 * 1024,  # 512MB
            max_cpu_usage=50.0,  # 50%
            network_restrictions=True,
            filesystem_restrictions=True,
            privileged_operations=False,
            cross_container_access=False,
            created_at=time.time(),
            updated_at=time.time()
        )
    
    def start_monitoring(self) -> bool:
        """Start container security monitoring"""
        if not self.docker_available:
            logger.error("Docker not available")
            return False
        
        self.running = True
        
        # Start monitoring threads
        self.monitor_thread = threading.Thread(target=self._monitor_containers)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.policy_thread = threading.Thread(target=self._enforce_policies)
        self.policy_thread.daemon = True
        self.policy_thread.start()
        
        logger.info("Container security monitoring started")
        return True
    
    def stop_monitoring(self) -> None:
        """Stop container security monitoring"""
        self.running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        if self.policy_thread:
            self.policy_thread.join(timeout=5)
        
        logger.info("Container security monitoring stopped")
    
    def _monitor_containers(self) -> None:
        """Monitor container lifecycle and process mappings"""
        while self.running:
            try:
                self._update_container_info()
                self._update_process_mappings()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Error in container monitoring: {e}")
                time.sleep(10)
    
    def _update_container_info(self):
        """Update container information"""
        try:
            containers = self.docker_client.containers.list(all=True)
            current_containers = set()
            
            for container in containers:
                container_id = container.id
                current_containers.add(container_id)
                
                if container_id not in self.containers:
                    # New container detected
                    container_info = self._extract_container_info(container)
                    self.containers[container_id] = container_info
                    self._create_container_policy(container_id)
                    logger.info(f"New container detected: {container_info.name}")
                
                # Update existing container info
                elif container.status != self.containers[container_id].status:
                    self.containers[container_id].status = container.status
                    logger.info(f"Container status updated: {container.name} -> {container.status}")
            
            # Remove stopped containers
            stopped_containers = set(self.containers.keys()) - current_containers
            for container_id in stopped_containers:
                container_info = self.containers[container_id]
                logger.info(f"Container stopped: {container_info.name}")
                del self.containers[container_id]
                if container_id in self.container_policies:
                    del self.container_policies[container_id]
            
            # Update statistics
            self.stats['total_containers'] = len(self.containers)
            self.stats['active_containers'] = len([c for c in self.containers.values() if c.status == 'running'])
            
        except Exception as e:
            logger.error(f"Error updating container info: {e}")
    
    def _extract_container_info(self, container) -> ContainerInfo:
        """Extract detailed information from Docker container"""
        try:
            # Get container top (processes)
            top_info = container.top()
            main_pid = int(top_info['Processes'][0][1]) if top_info['Processes'] else 0
            
            # Get container details
            container_details = container.attrs
            
            return ContainerInfo(
                container_id=container.id,
                name=container.name,
                image=container.image.tags[0] if container.image.tags else 'unknown',
                status=container.status,
                pid=main_pid,
                created_at=container_details['Created'],
                network_mode=container_details['HostConfig']['NetworkMode'],
                privileged=container_details['HostConfig']['Privileged'],
                security_options=container_details['HostConfig']['SecurityOpt'] or [],
                mounts=[mount for mount in container_details['Mounts']],
                environment=dict(container_details['Config']['Env'] or [])
            )
        except Exception as e:
            logger.error(f"Error extracting container info: {e}")
            return ContainerInfo(
                container_id=container.id,
                name=container.name,
                image='unknown',
                status=container.status,
                pid=0,
                created_at='',
                network_mode='',
                privileged=False,
                security_options=[],
                mounts=[],
                environment={}
            )
    
    def _update_process_mappings(self):
        """Update process-to-container mappings - OPTIMIZED with incremental updates"""
        try:
            with self.containers_lock:
                if not self.containers:
                    # Clear mappings atomically if no containers
                    self.container_boundaries.clear()
                    self.process_containers.clear()
                    return
                
                containers_snapshot = dict(self.containers)  # Snapshot for processing
                current_pids = set(self.process_containers.keys())  # Track existing PIDs
            
            # Get current system PIDs (limit for performance)
            try:
                system_pids = set(psutil.pids()[:2000])  # Increased limit slightly
            except Exception:
                return
            
            # Incremental update: only check new/changed PIDs
            new_pids = system_pids - current_pids
            removed_pids = current_pids - system_pids
            
            # Update mappings for new PIDs only (much faster than full scan)
            new_process_containers = {}
            new_container_boundaries = {}
            
            # Pre-populate boundaries from existing data
            with self.containers_lock:
                for container_id in self.container_boundaries.keys():
                    new_container_boundaries[container_id] = set(self.container_boundaries[container_id])
                # Remove dead PIDs from boundaries
                for container_id in new_container_boundaries:
                    new_container_boundaries[container_id] -= removed_pids
            
            # Only check NEW PIDs (incremental update)
            for pid in new_pids:
                try:
                    container_id = self._get_process_container(pid)
                    
                    if container_id:
                        new_process_containers[pid] = container_id
                        
                        if container_id in new_container_boundaries:
                            new_container_boundaries[container_id].add(pid)
                        elif len(container_id) > 12:
                            # Try to find matching full ID
                            for full_id in containers_snapshot.keys():
                                if full_id.startswith(container_id):
                                    if full_id not in new_container_boundaries:
                                        new_container_boundaries[full_id] = set()
                                    new_container_boundaries[full_id].add(pid)
                                    new_process_containers[pid] = full_id
                                    break
                        else:
                            # Short ID - create entry
                            if container_id not in new_container_boundaries:
                                new_container_boundaries[container_id] = set()
                            new_container_boundaries[container_id].add(pid)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                    continue
            
            # Merge with existing mappings
            with self.containers_lock:
                # Add new mappings
                self.process_containers.update(new_process_containers)
                # Update boundaries
                for container_id, pids in new_container_boundaries.items():
                    if container_id in self.container_boundaries:
                        self.container_boundaries[container_id].update(pids)
                    else:
                        self.container_boundaries[container_id] = pids
            
        except Exception as e:
            logger.error(f"Error updating process mappings: {e}")
    
    def _get_process_container(self, pid: int) -> Optional[str]:
        """Get container ID for a process - IMPROVED VERSION with caching"""
        # Validate PID
        if not isinstance(pid, int) or pid <= 0:
            return None
        
        # Check cache first
        current_time = time.time()
        if pid in self._container_lookup_cache:
            container_id, cache_time = self._container_lookup_cache[pid]
            if current_time - cache_time < self._container_cache_ttl:
                return container_id
        
        try:
            # Method 1: Use Docker API (most reliable if available)
            if self.docker_client and self.containers:
                try:
                    # Get process info
                    proc = psutil.Process(pid)
                    
                    # Check if this process's ancestor is a container's main process
                    current_pid = pid
                    depth = 0
                    max_depth = 50
                    
                    while depth < max_depth:
                        try:
                            for container_id, container_info in self.containers.items():
                                if container_info.pid == current_pid:
                                    # Found match - this is container's main process or descendant
                                    return container_id[:12]  # Return short ID
                            
                            # Check parent
                            parent = proc.parent()
                            if parent and parent.pid > 1:  # Not init
                                current_pid = parent.pid
                                proc = parent
                                depth += 1
                            else:
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            break
                except Exception:
                    pass
            
            # Method 2: Parse cgroup (improved regex)
            cgroup_path = f"/proc/{pid}/cgroup"
            if os.path.exists(cgroup_path):
                with open(cgroup_path, 'r') as f:
                    for line in f:
                        # Docker pattern: .../docker/<12-char-container-id>
                        docker_match = re.search(r'/docker[:\/]?([a-f0-9]{12,64})', line)
                        if docker_match:
                            container_id = docker_match.group(1)
                            return container_id[:12]  # Return short ID
                        
                        # Kubernetes pattern: .../kubepods/.../pod<pod-id>
                        k8s_match = re.search(r'/kubepods/.*/pod([a-f0-9-]+)', line)
                        if k8s_match:
                            return f"k8s-{k8s_match.group(1)[:8]}"
            
            # Method 3: Check if already in our tracked containers
            for container_id, container_info in self.containers.items():
                if container_id in self.container_boundaries:
                    pids = self.container_boundaries[container_id]
                    if pid in pids:
                        result = container_id[:12]
                        # Update cache
                        self._container_lookup_cache[pid] = (result, current_time)
                        return result
            
        except Exception as e:
            # Silent fail - process might not be in container
            pass
        
        # Cache None result (not in container)
        self._container_lookup_cache[pid] = (None, current_time)
        return None
    
    def _is_descendant_of(self, pid: int, ancestor_pid: int) -> bool:
        """Check if pid is descendant of ancestor_pid (helper method for API method)"""
        if ancestor_pid == 0:
            return False
        
        current_pid = pid
        depth = 0
        max_depth = 100
        
        while current_pid != ancestor_pid and depth < max_depth:
            try:
                proc = psutil.Process(current_pid)
                current_pid = proc.ppid()
                if current_pid == ancestor_pid:
                    return True
                depth += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False
        
        return False
    
    def _create_container_policy(self, container_id: str):
        """Create security policy for a container"""
        if container_id in self.containers:
            container_info = self.containers[container_id]
            
            # Create policy based on container characteristics
            policy = ContainerSecurityPolicy(
                container_id=container_id,
                policy_name=f"Policy for {container_info.name}",
                allowed_syscalls=self.default_policy.allowed_syscalls.copy(),
                blocked_syscalls=self.default_policy.blocked_syscalls.copy(),
                max_syscall_rate=self.default_policy.max_syscall_rate,
                max_memory_usage=self.default_policy.max_memory_usage,
                max_cpu_usage=self.default_policy.max_cpu_usage,
                network_restrictions=self.default_policy.network_restrictions,
                filesystem_restrictions=self.default_policy.filesystem_restrictions,
                privileged_operations=container_info.privileged,
                cross_container_access=False,  # Always block by default
                created_at=time.time(),
                updated_at=time.time()
            )
            
            # Adjust policy based on container characteristics
            if container_info.privileged:
                # Allow more syscalls for privileged containers
                policy.allowed_syscalls.extend(['mount', 'umount', 'setuid', 'setgid'])
                policy.privileged_operations = True
            
            if 'network' in container_info.name.lower():
                # Allow more network syscalls for network containers
                policy.allowed_syscalls.extend(['iptables', 'netlink'])
            
            self.container_policies[container_id] = policy
            logger.info(f"Created security policy for container: {container_info.name}")
    
    def _enforce_policies(self) -> None:
        """Enforce container security policies"""
        while self.running:
            try:
                self._check_cross_container_access()
                self._check_resource_usage()
                self._check_syscall_violations()
                time.sleep(1)  # Check every second
            except Exception as e:
                logger.error(f"Error enforcing policies: {e}")
                time.sleep(5)
    
    def _check_cross_container_access(self):
        """Check for cross-container access attempts"""
        # Monitor syscalls between containers for potential attacks
        # This integrates with the enhanced security agent's syscall monitoring
        
        # Track potential cross-container syscalls
        # The actual detection happens via detect_cross_container_attempt()
        # which is called from the main agent when syscalls occur
        
        # Additional monitoring: Check for suspicious inter-container communication
        for container_id, container_info in self.containers.items():
            if container_info.status != 'running':
                continue
                
            # Check if this container is attempting to access files from another container
            if container_id in self.container_boundaries:
                pids = self.container_boundaries[container_id]
                
                # Monitor for processes trying to access host or other container namespaces
                for pid in list(pids):  # Use list() to avoid modification during iteration
                    try:
                        proc = psutil.Process(pid)
                        
                        # Check for namespace isolation violations
                        try:
                            # Check if process is accessing mount points outside container
                            proc_info = proc.as_dict(['exe', 'name', 'cwd'])
                            
                            # Detect potential container escape attempts
                            if proc_info.get('exe') and 'container' not in proc_info.get('cwd', '').lower():
                                # Could be a container escape attempt
                                pass  # Would trigger alert in production
                                
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    
    
    def _check_resource_usage(self):
        """Check container resource usage against policies"""
        for container_id, policy in self.container_policies.items():
            if container_id in self.container_boundaries:
                pids = self.container_boundaries[container_id]
                
                # Check memory usage
                total_memory = 0
                total_cpu = 0.0
                
                for pid in pids:
                    try:
                        proc = psutil.Process(pid)
                        memory_info = proc.memory_info()
                        total_memory += memory_info.rss
                        total_cpu += proc.cpu_percent()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Check policy violations
                if total_memory > policy.max_memory_usage:
                    violation = {
                        'timestamp': time.time(),
                        'container_id': container_id,
                        'violation_type': 'memory_usage',
                        'current_value': total_memory,
                        'limit': policy.max_memory_usage,
                        'severity': 'high'
                    }
                    self.policy_violations.append(violation)
                    logger.warning(f"Memory violation in container {container_id}: {total_memory} > {policy.max_memory_usage}")
                
                if total_cpu > policy.max_cpu_usage:
                    violation = {
                        'timestamp': time.time(),
                        'container_id': container_id,
                        'violation_type': 'cpu_usage',
                        'current_value': total_cpu,
                        'limit': policy.max_cpu_usage,
                        'severity': 'medium'
                    }
                    self.policy_violations.append(violation)
                    logger.warning(f"CPU violation in container {container_id}: {total_cpu} > {policy.max_cpu_usage}")
    
    def _check_syscall_violations(self):
        """Check for syscall policy violations"""
        # Monitor recent syscall patterns against container policies
        # This complements the real-time validation done in validate_syscall()
        
        # Track syscall rates and flag violations
        for container_id, policy in self.container_policies.items():
            if container_id not in self.container_boundaries:
                continue
                
            pids = self.container_boundaries[container_id]
            
            # Count suspicious syscalls in this container
            high_risk_count = 0
            total_syscalls = 0
            
            for pid in list(pids):
                try:
                    proc = psutil.Process(pid)
                    
                    # Check if process is making too many syscalls
                    # In production, this would track actual syscall history
                    # Here we simulate based on process activity
                    
                    cpu_percent = proc.cpu_percent(interval=0.1)
                    
                    # High CPU typically indicates many syscalls
                    if cpu_percent > policy.max_cpu_usage:
                        violation = {
                            'timestamp': time.time(),
                            'container_id': container_id,
                            'pid': pid,
                            'violation_type': 'high_syscall_rate',
                            'cpu_percent': cpu_percent,
                            'limit': policy.max_cpu_usage,
                            'severity': 'high'
                        }
                        self.policy_violations.append(violation)
                        logger.warning(f"High syscall rate in container {container_id}: {cpu_percent}% CPU")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            # Log if container is making excessive syscalls
            if high_risk_count > policy.max_syscall_rate / 10:  # Alert at 10% of limit
                logger.warning(f"Container {container_id} approaching syscall rate limit")
    
    def detect_cross_container_attempt(self, source_pid: int, target_pid: int, syscall: str) -> bool:
        """Detect cross-container access attempt"""
        source_container = self.process_containers.get(source_pid)
        target_container = self.process_containers.get(target_pid)
        
        if source_container and target_container and source_container != target_container:
            # Cross-container access detected
            attempt = CrossContainerAttempt(
                timestamp=time.time(),
                source_container=source_container,
                target_container=target_container,
                source_pid=source_pid,
                target_pid=target_pid,
                syscall=syscall,
                severity='high',
                blocked=True,
                details={'detection_method': 'process_mapping'}
            )
            
            self.cross_container_attempts.append(attempt)
            self.stats['cross_container_attempts'] += 1
            self.stats['blocked_attempts'] += 1
            
            logger.warning(f"Cross-container attack blocked: {syscall} from {source_container} to {target_container}")
            return True
        
        return False
    
    def validate_syscall(self, pid: int, syscall: str) -> bool:
        """Validate syscall against container policy"""
        container_id = self.process_containers.get(pid)
        if not container_id or container_id not in self.container_policies:
            return True  # Allow if no policy
        
        policy = self.container_policies[container_id]
        
        # Check blocked syscalls
        if syscall in policy.blocked_syscalls:
            violation = {
                'timestamp': time.time(),
                'container_id': container_id,
                'pid': pid,
                'violation_type': 'blocked_syscall',
                'syscall': syscall,
                'severity': 'high'
            }
            self.policy_violations.append(violation)
            self.stats['policy_violations'] += 1
            logger.warning(f"Blocked syscall {syscall} in container {container_id}")
            return False
        
        # Check allowed syscalls
        if policy.allowed_syscalls and syscall not in policy.allowed_syscalls:
            violation = {
                'timestamp': time.time(),
                'container_id': container_id,
                'pid': pid,
                'violation_type': 'unauthorized_syscall',
                'syscall': syscall,
                'severity': 'medium'
            }
            self.policy_violations.append(violation)
            self.stats['policy_violations'] += 1
            logger.warning(f"Unauthorized syscall {syscall} in container {container_id}")
            return False
        
        return True
    
    def get_container_info(self, container_id: str) -> Optional[ContainerInfo]:
        """Get information about a specific container"""
        return self.containers.get(container_id)
    
    def get_container_policy(self, container_id: str) -> Optional[ContainerSecurityPolicy]:
        """Get security policy for a container"""
        return self.container_policies.get(container_id)
    
    def update_container_policy(self, container_id: str, policy_updates: Dict[str, Any]) -> None:
        """Update security policy for a container"""
        if container_id in self.container_policies:
            policy = self.container_policies[container_id]
            
            for key, value in policy_updates.items():
                if hasattr(policy, key):
                    setattr(policy, key, value)
            
            policy.updated_at = time.time()
            logger.info(f"Updated policy for container {container_id}")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security monitoring statistics"""
        return {
            **self.stats,
            'containers': len(self.containers),
            'policies': len(self.container_policies),
            'recent_cross_container_attempts': len([a for a in self.cross_container_attempts if time.time() - a.timestamp < 3600]),
            'recent_policy_violations': len([v for v in self.policy_violations if time.time() - v.timestamp < 3600])
        }
    
    def export_security_data(self) -> Dict[str, Any]:
        """Export security monitoring data"""
        return {
            'containers': {cid: asdict(info) for cid, info in self.containers.items()},
            'policies': {cid: asdict(policy) for cid, policy in self.container_policies.items()},
            'cross_container_attempts': [asdict(attempt) for attempt in self.cross_container_attempts],
            'policy_violations': list(self.policy_violations),
            'stats': self.stats,
            'export_timestamp': time.time()
        }

# Example usage and testing
if __name__ == "__main__":
    # Create container security monitor
    monitor = ContainerSecurityMonitor()
    
    # Start monitoring
    if monitor.start_monitoring():
        print("Container security monitoring started")
        
        # Run for a short time
        time.sleep(30)
        
        # Get statistics
        stats = monitor.get_security_stats()
        print(f"Security stats: {stats}")
        
        # Export data
        export_data = monitor.export_security_data()
        print(f"Exported {len(export_data)} data entries")
        
        # Stop monitoring
        monitor.stop_monitoring()
    else:
        print("Failed to start container security monitoring")
