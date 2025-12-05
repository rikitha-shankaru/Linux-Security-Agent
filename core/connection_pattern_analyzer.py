#!/usr/bin/env python3
"""
Connection Pattern Analyzer
============================

Detects suspicious network connection patterns including:
- C2 beaconing (regular intervals)
- Port scanning (rapid connections to multiple ports)
- Data exfiltration (large uploads)
- Unusual destinations

Improves MITRE ATT&CK coverage for:
- T1071: Application Layer Protocol (C2)
- T1041: Exfiltration Over C2 Channel
- T1046: Network Service Scanning

Author: Likitha Shankar
"""

import time
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
import statistics
import logging

logger = logging.getLogger('security_agent.connection_pattern')


class ConnectionPatternAnalyzer:
    """
    Analyzes network connection patterns to detect:
    - C2 beaconing (regular communication intervals)
    - Port scanning (rapid connections to many ports)
    - Data exfiltration patterns
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize connection pattern analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Connection tracking per process
        self.connection_history = defaultdict(lambda: deque(maxlen=100))
        
        # Port scanning detection
        self.port_access_history = defaultdict(set)  # pid -> set of ports
        
        # Beaconing detection parameters (lowered thresholds for better detection)
        self.beacon_threshold_variance = self.config.get('beacon_variance_threshold', 5.0)  # seconds
        self.min_connections_for_beacon = self.config.get('min_connections_for_beacon', 3)  # Lowered from 5 to 3
        
        # Port scanning parameters (lowered thresholds for better detection)
        self.port_scan_threshold = self.config.get('port_scan_threshold', 5)  # unique ports (lowered from 10 to 5)
        self.port_scan_timeframe = self.config.get('port_scan_timeframe', 60)  # seconds
        
        # Data transfer tracking
        self.bytes_sent = defaultdict(int)
        self.bytes_received = defaultdict(int)
        self.exfiltration_threshold = self.config.get('exfiltration_threshold', 100 * 1024 * 1024)  # 100 MB
        
        # Statistics
        self.stats = {
            'beacons_detected': 0,
            'port_scans_detected': 0,
            'exfiltrations_detected': 0,
            'total_connections_analyzed': 0
        }
    
    def analyze_connection(self, pid: int, dest_ip: str, dest_port: int, 
                          timestamp: float = None) -> Optional[Dict]:
        """
        Analyze a network connection for suspicious patterns
        
        Args:
            pid: Process ID
            dest_ip: Destination IP address
            dest_port: Destination port
            timestamp: Connection timestamp (default: current time)
        
        Returns:
            Detection result if suspicious, None otherwise
        """
        if timestamp is None:
            timestamp = time.time()
        
        self.stats['total_connections_analyzed'] += 1
        
        # Record connection
        connection_info = {
            'dest': f"{dest_ip}:{dest_port}",
            'ip': dest_ip,
            'port': dest_port,
            'time': timestamp
        }
        self.connection_history[pid].append(connection_info)
        self.port_access_history[pid].add(dest_port)
        
        # Check for beaconing
        beacon_result = self._detect_beaconing(pid)
        if beacon_result:
            self.stats['beacons_detected'] += 1
            return beacon_result
        
        # Check for port scanning
        scan_result = self._detect_port_scanning(pid, timestamp)
        if scan_result:
            self.stats['port_scans_detected'] += 1
            return scan_result
        
        return None
    
    def _detect_beaconing(self, pid: int) -> Optional[Dict]:
        """
        Detect C2 beaconing patterns (regular intervals)
        
        C2 malware often "calls home" at regular intervals (e.g., every 60 seconds)
        """
        connections = list(self.connection_history[pid])
        
        if len(connections) < self.min_connections_for_beacon:
            return None
        
        # Calculate time intervals between connections
        intervals = []
        for i in range(1, len(connections)):
            interval = connections[i]['time'] - connections[i-1]['time']
            intervals.append(interval)
        
        if len(intervals) < self.min_connections_for_beacon - 1:
            return None
        
        # Check for regular timing (low variance = beaconing)
        try:
            mean_interval = statistics.mean(intervals)
            
            # Only consider if intervals are reasonably long (> 1 second)
            if mean_interval < 1.0:
                return None
            
            # Calculate variance
            if len(intervals) >= 2:
                variance = statistics.variance(intervals)
                stdev = statistics.stdev(intervals)
                
                # Low variance indicates regular beaconing
                if stdev < self.beacon_threshold_variance and mean_interval > 5.0:
                    return {
                        'type': 'C2_BEACONING',
                        'technique': 'T1071',
                        'pid': pid,
                        'mean_interval': mean_interval,
                        'variance': variance,
                        'stdev': stdev,
                        'connections': len(connections),
                        'destination': connections[-1]['dest'],
                        'risk_score': 85,
                        'explanation': f'Regular beaconing detected: {mean_interval:.1f}s intervals (±{stdev:.1f}s)',
                        'confidence': 0.9,
                        'severity': 'HIGH'
                    }
        except statistics.StatisticsError:
            pass
        
        return None
    
    def _detect_port_scanning(self, pid: int, current_time: float) -> Optional[Dict]:
        """
        Detect port scanning (accessing many ports quickly)
        """
        unique_ports = len(self.port_access_history[pid])
        
        if unique_ports < self.port_scan_threshold:
            return None
        
        # Check if this happened in a short timeframe
        connections = list(self.connection_history[pid])
        if not connections:
            return None
        
        # Get time range
        oldest = connections[0]['time']
        newest = connections[-1]['time']
        timeframe = newest - oldest
        
        # Port scan: Many unique ports in short time
        if timeframe < self.port_scan_timeframe and unique_ports >= self.port_scan_threshold:
            ports_per_second = unique_ports / max(timeframe, 1)
            
            return {
                'type': 'PORT_SCANNING',
                'technique': 'T1046',
                'pid': pid,
                'unique_ports': unique_ports,
                'timeframe': timeframe,
                'rate': ports_per_second,
                'risk_score': 75,
                'explanation': f'Port scanning: {unique_ports} ports in {timeframe:.1f}s',
                'confidence': 0.85,
                'severity': 'HIGH'
            }
        
        return None
    
    def track_data_transfer(self, pid: int, bytes_sent: int = 0, bytes_received: int = 0) -> Optional[Dict]:
        """
        Track data transfers to detect exfiltration
        
        Args:
            pid: Process ID
            bytes_sent: Bytes sent in this operation
            bytes_received: Bytes received in this operation
        
        Returns:
            Detection result if exfiltration suspected
        """
        self.bytes_sent[pid] += bytes_sent
        self.bytes_received[pid] += bytes_received
        
        # Check for large uploads (potential exfiltration)
        if self.bytes_sent[pid] > self.exfiltration_threshold:
            self.stats['exfiltrations_detected'] += 1
            
            return {
                'type': 'DATA_EXFILTRATION',
                'technique': 'T1041',
                'pid': pid,
                'bytes_sent': self.bytes_sent[pid],
                'bytes_received': self.bytes_received[pid],
                'ratio': self.bytes_sent[pid] / max(self.bytes_received[pid], 1),
                'risk_score': 90,
                'explanation': f'Large data upload: {self.bytes_sent[pid] / (1024*1024):.1f} MB sent',
                'confidence': 0.8,
                'severity': 'CRITICAL'
            }
        
        return None
    
    def get_suspicious_destinations(self, pid: int) -> List[str]:
        """Get list of suspicious destinations for a process"""
        connections = list(self.connection_history[pid])
        
        # Look for unusual patterns
        suspicious = []
        
        # Group by destination
        dest_counts = defaultdict(int)
        for conn in connections:
            dest_counts[conn['dest']] += 1
        
        # Single destination with many connections = suspicious
        for dest, count in dest_counts.items():
            if count >= 10:  # Same destination 10+ times
                suspicious.append(dest)
        
        return suspicious
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return dict(self.stats)
    
    def reset_process(self, pid: int):
        """Reset tracking for a process (when it exits)"""
        if pid in self.connection_history:
            del self.connection_history[pid]
        if pid in self.port_access_history:
            del self.port_access_history[pid]
        if pid in self.bytes_sent:
            del self.bytes_sent[pid]
        if pid in self.bytes_received:
            del self.bytes_received[pid]

