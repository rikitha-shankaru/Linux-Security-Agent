#!/usr/bin/env python3
"""
Threat Intelligence Module
Integrates MITRE ATT&CK framework and IOC (Indicators of Compromise) feeds
"""

import os
import json
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
import ipaddress

logger = logging.getLogger('security_agent.threat_intel')

# MITRE ATT&CK Technique to Syscall Mapping
# Based on common attack patterns and research
ATTACK_TECHNIQUES = {
    # Execution Techniques
    'T1059': {  # Command and Scripting Interpreter
        'name': 'Command and Scripting Interpreter',
        'syscalls': ['execve', 'execveat', 'fork', 'clone'],
        'risk': 8
    },
    'T1106': {  # Native API
        'name': 'Native API',
        'syscalls': ['execve', 'execveat', 'ptrace', 'syscall'],
        'risk': 7
    },
    'T1055': {  # Process Injection
        'name': 'Process Injection',
        'syscalls': ['ptrace', 'mmap', 'mprotect', 'execve'],
        'risk': 9
    },
    
    # Persistence Techniques
    'T1543': {  # Create or Modify System Process
        'name': 'Create or Modify System Process',
        'syscalls': ['execve', 'fork', 'clone', 'setuid', 'setgid'],
        'risk': 8
    },
    'T1547': {  # Boot or Logon Autostart Execution
        'name': 'Boot or Logon Autostart Execution',
        'syscalls': ['open', 'openat', 'write', 'symlink', 'link'],
        'risk': 7
    },
    
    # Privilege Escalation
    'T1078': {  # Valid Accounts
        'name': 'Valid Accounts',
        'syscalls': ['setuid', 'setgid', 'setreuid', 'setregid'],
        'risk': 9
    },
    'T1134': {  # Access Token Manipulation
        'name': 'Access Token Manipulation',
        'syscalls': ['setuid', 'setgid', 'setreuid', 'setregid', 'capset'],
        'risk': 9
    },
    
    # Defense Evasion
    'T1070': {  # Indicator Removal on Host
        'name': 'Indicator Removal on Host',
        'syscalls': ['unlink', 'unlinkat', 'rmdir', 'rename', 'renameat'],
        'risk': 7
    },
    'T1562': {  # Impair Defenses
        'name': 'Impair Defenses',
        'syscalls': ['ptrace', 'kill', 'iopl', 'ioperm'],
        'risk': 8
    },
    'T1036': {  # Masquerading
        'name': 'Masquerading',
        'syscalls': ['execve', 'symlink', 'link', 'rename'],
        'risk': 6
    },
    
    # Credential Access
    'T1003': {  # OS Credential Dumping
        'name': 'OS Credential Dumping',
        'syscalls': ['open', 'openat', 'read', 'ptrace', 'memfd_create'],
        'risk': 9
    },
    'T1555': {  # Credentials from Password Stores
        'name': 'Credentials from Password Stores',
        'syscalls': ['open', 'openat', 'read', 'stat', 'access'],
        'risk': 8
    },
    
    # Discovery
    'T1083': {  # File and Directory Discovery
        'name': 'File and Directory Discovery',
        'syscalls': ['getdents', 'getdents64', 'stat', 'statfs', 'readdir'],
        'risk': 4
    },
    'T1057': {  # Process Discovery
        'name': 'Process Discovery',
        'syscalls': ['getdents', 'getdents64', 'read', 'open', 'openat'],
        'risk': 5
    },
    'T1018': {  # Remote System Discovery
        'name': 'Remote System Discovery',
        'syscalls': ['socket', 'connect', 'sendto', 'recvfrom'],
        'risk': 6
    },
    
    # Lateral Movement
    'T1021': {  # Remote Services
        'name': 'Remote Services',
        'syscalls': ['socket', 'connect', 'execve', 'clone'],
        'risk': 7
    },
    'T1071': {  # Application Layer Protocol
        'name': 'Application Layer Protocol',
        'syscalls': ['socket', 'connect', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg'],
        'risk': 6
    },
    
    # Collection
    'T1005': {  # Data from Local System
        'name': 'Data from Local System',
        'syscalls': ['open', 'openat', 'read', 'readv', 'pread', 'pread64'],
        'risk': 6
    },
    'T1114': {  # Email Collection
        'name': 'Email Collection',
        'syscalls': ['open', 'openat', 'read', 'socket', 'connect'],
        'risk': 5
    },
    
    # Exfiltration
    'T1041': {  # Exfiltration Over C2 Channel
        'name': 'Exfiltration Over C2 Channel',
        'syscalls': ['socket', 'connect', 'sendto', 'sendmsg', 'write', 'writev'],
        'risk': 8
    },
    'T1020': {  # Automated Exfiltration
        'name': 'Automated Exfiltration',
        'syscalls': ['socket', 'connect', 'sendto', 'write', 'open', 'read'],
        'risk': 7
    },
    
    # Impact
    'T1486': {  # Data Encrypted for Impact
        'name': 'Data Encrypted for Impact',
        'syscalls': ['open', 'openat', 'write', 'writev', 'fchmod', 'chmod'],
        'risk': 9
    },
    'T1490': {  # Inhibit System Recovery
        'name': 'Inhibit System Recovery',
        'syscalls': ['unlink', 'unlinkat', 'rmdir', 'mount', 'umount2'],
        'risk': 8
    }
}


class IOCFeed:
    """Indicator of Compromise Feed Manager"""
    
    def __init__(self, feed_dir: Optional[str] = None):
        self.feed_dir = Path(feed_dir) if feed_dir else Path.home() / '.cache' / 'security_agent' / 'ioc_feeds'
        self.feed_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # IOC storage
        self.file_hashes: Set[str] = set()
        self.ip_addresses: Set[str] = set()
        self.domains: Set[str] = set()
        self.file_paths: Set[str] = set()
        self.process_names: Set[str] = set()
        
        # Metadata
        self.ioc_metadata: Dict[str, Dict[str, Any]] = {}
        self.last_update: Optional[datetime] = None
        
        self._load_feeds()
    
    def _load_feeds(self) -> None:
        """Load IOC feeds from files"""
        feed_file = self.feed_dir / 'ioc_feed.json'
        if feed_file.exists():
            try:
                with open(feed_file, 'r') as f:
                    data = json.load(f)
                    self.file_hashes = set(data.get('file_hashes', []))
                    self.ip_addresses = set(data.get('ip_addresses', []))
                    self.domains = set(data.get('domains', []))
                    self.file_paths = set(data.get('file_paths', []))
                    self.process_names = set(data.get('process_names', []))
                    self.ioc_metadata = data.get('metadata', {})
                    
                    if 'last_update' in data:
                        self.last_update = datetime.fromisoformat(data['last_update'])
                    
                    logger.info(f"Loaded {len(self.file_hashes)} file hashes, "
                              f"{len(self.ip_addresses)} IPs, {len(self.domains)} domains")
            except Exception as e:
                logger.error(f"Failed to load IOC feed: {e}")
    
    def _save_feeds(self) -> None:
        """Save IOC feeds to file"""
        feed_file = self.feed_dir / 'ioc_feed.json'
        try:
            data = {
                'file_hashes': list(self.file_hashes),
                'ip_addresses': list(self.ip_addresses),
                'domains': list(self.domains),
                'file_paths': list(self.file_paths),
                'process_names': list(self.process_names),
                'metadata': self.ioc_metadata,
                'last_update': datetime.now().isoformat()
            }
            with open(feed_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.last_update = datetime.now()
        except Exception as e:
            logger.error(f"Failed to save IOC feed: {e}")
    
    def add_file_hash(self, file_hash: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a file hash to the IOC feed"""
        self.file_hashes.add(file_hash.lower())
        if metadata:
            self.ioc_metadata[file_hash] = metadata
        self._save_feeds()
    
    def add_ip_address(self, ip: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add an IP address to the IOC feed"""
        try:
            # Validate IP
            ipaddress.ip_address(ip)
            self.ip_addresses.add(ip)
            if metadata:
                self.ioc_metadata[ip] = metadata
            self._save_feeds()
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
    
    def add_domain(self, domain: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a domain to the IOC feed"""
        self.domains.add(domain.lower())
        if metadata:
            self.ioc_metadata[domain] = metadata
        self._save_feeds()
    
    def add_file_path(self, path: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a file path pattern to the IOC feed"""
        self.file_paths.add(path)
        if metadata:
            self.ioc_metadata[path] = metadata
        self._save_feeds()
    
    def add_process_name(self, name: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a process name to the IOC feed"""
        self.process_names.add(name.lower())
        if metadata:
            self.ioc_metadata[name] = metadata
        self._save_feeds()
    
    def check_file_hash(self, file_path: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if a file's hash matches any IOC"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            if file_hash in self.file_hashes:
                return True, self.ioc_metadata.get(file_hash, {})
            return False, None
        except Exception as e:
            logger.debug(f"Failed to check file hash: {e}")
            return False, None
    
    def check_ip(self, ip: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if an IP address matches any IOC"""
        if ip in self.ip_addresses:
            return True, self.ioc_metadata.get(ip, {})
        return False, None
    
    def check_domain(self, domain: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if a domain matches any IOC"""
        if domain.lower() in self.domains:
            return True, self.ioc_metadata.get(domain, {})
        return False, None
    
    def check_file_path(self, path: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if a file path matches any IOC pattern"""
        for ioc_path in self.file_paths:
            if ioc_path in path or path in ioc_path:
                return True, self.ioc_metadata.get(ioc_path, {})
        return False, None
    
    def check_process_name(self, name: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if a process name matches any IOC"""
        if name.lower() in self.process_names:
            return True, self.ioc_metadata.get(name, {})
        return False, None
    
    def load_from_file(self, file_path: str, feed_type: str = 'json') -> int:
        """Load IOCs from an external file"""
        count = 0
        try:
            if feed_type == 'json':
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    for hash_val in data.get('hashes', []):
                        self.add_file_hash(hash_val)
                        count += 1
                    for ip in data.get('ips', []):
                        self.add_ip_address(ip)
                        count += 1
                    for domain in data.get('domains', []):
                        self.add_domain(domain)
                        count += 1
            elif feed_type == 'txt':
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        # Try to detect type
                        if '/' in line and os.path.exists(line):
                            self.add_file_path(line)
                        elif self._is_ip(line):
                            self.add_ip_address(line)
                        elif '.' in line:
                            self.add_domain(line)
                        count += 1
            
            logger.info(f"Loaded {count} IOCs from {file_path}")
            return count
        except Exception as e:
            logger.error(f"Failed to load IOCs from file: {e}")
            return 0
    
    @staticmethod
    def _is_ip(addr: str) -> bool:
        """Check if string is an IP address"""
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False


class ThreatIntelligence:
    """Main Threat Intelligence Engine"""
    
    def __init__(self, ioc_feed_dir: Optional[str] = None):
        self.ioc_feed = IOCFeed(ioc_feed_dir)
        self.technique_matches: Dict[str, List[str]] = defaultdict(list)  # technique -> [pids]
        self.ioc_matches: List[Dict[str, Any]] = []
        
    def match_attack_technique(self, syscalls: List[str], pid: int) -> List[Tuple[str, Dict[str, Any]]]:
        """Match syscalls against MITRE ATT&CK techniques"""
        matches = []
        syscall_set = set(syscalls)
        
        for technique_id, technique_info in ATTACK_TECHNIQUES.items():
            technique_syscalls = set(technique_info['syscalls'])
            
            # Check if any technique syscalls match
            if syscall_set.intersection(technique_syscalls):
                # Calculate match score (how many syscalls match)
                match_count = len(syscall_set.intersection(technique_syscalls))
                match_ratio = match_count / len(technique_syscalls) if technique_syscalls else 0
                
                matches.append((
                    technique_id,
                    {
                        'name': technique_info['name'],
                        'risk': technique_info['risk'],
                        'match_ratio': match_ratio,
                        'matched_syscalls': list(syscall_set.intersection(technique_syscalls)),
                        'pid': pid
                    }
                ))
                self.technique_matches[technique_id].append(pid)
        
        return matches
    
    def check_ioc(self, process_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check process against IOC feed"""
        matches = []
        pid = process_info.get('pid')
        name = process_info.get('name', '')
        exe = process_info.get('exe', '')
        
        # Check process name
        matched, metadata = self.ioc_feed.check_process_name(name)
        if matched:
            matches.append({
                'type': 'process_name',
                'value': name,
                'metadata': metadata,
                'pid': pid
            })
        
        # Check executable path
        if exe:
            matched, metadata = self.ioc_feed.check_file_path(exe)
            if matched:
                matches.append({
                    'type': 'file_path',
                    'value': exe,
                    'metadata': metadata,
                    'pid': pid
                })
            
            # Check file hash if file exists
            if os.path.exists(exe):
                matched, metadata = self.ioc_feed.check_file_hash(exe)
                if matched:
                    matches.append({
                        'type': 'file_hash',
                        'value': exe,
                        'metadata': metadata,
                        'pid': pid
                    })
        
        if matches:
            self.ioc_matches.extend(matches)
        
        return matches
    
    def get_risk_boost(self, syscalls: List[str], process_info: Dict[str, Any]) -> float:
        """Calculate risk boost from threat intelligence"""
        boost = 0.0
        
        # Check ATT&CK techniques
        technique_matches = self.match_attack_technique(syscalls, process_info.get('pid', 0))
        for technique_id, match_info in technique_matches:
            # Risk boost based on technique risk level and match ratio
            boost += match_info['risk'] * match_info['match_ratio'] * 0.1
        
        # Check IOCs
        ioc_matches = self.check_ioc(process_info)
        for match in ioc_matches:
            boost += 15.0  # Significant boost for IOC matches
        
        return min(boost, 50.0)  # Cap at 50 points
    
    def get_summary(self) -> Dict[str, Any]:
        """Get threat intelligence summary"""
        return {
            'attack_techniques_matched': len(self.technique_matches),
            'ioc_matches': len(self.ioc_matches),
            'technique_details': {
                tid: {
                    'name': ATTACK_TECHNIQUES[tid]['name'],
                    'pids': list(set(pids))
                }
                for tid, pids in self.technique_matches.items()
            },
            'ioc_feed_stats': {
                'file_hashes': len(self.ioc_feed.file_hashes),
                'ip_addresses': len(self.ioc_feed.ip_addresses),
                'domains': len(self.ioc_feed.domains),
                'file_paths': len(self.ioc_feed.file_paths),
                'process_names': len(self.ioc_feed.process_names),
                'last_update': self.ioc_feed.last_update.isoformat() if self.ioc_feed.last_update else None
            }
        }

