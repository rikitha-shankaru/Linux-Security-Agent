#!/usr/bin/env python3
"""
Cloud Backend Integration for Linux Security Agent
Provides centralized management, data aggregation, and remote configuration
Similar to CrowdStrike Falcon's cloud console
"""

import os
import sys
import json
import time
import ssl
import threading
import queue
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import hashlib
import hmac
import base64

@dataclass
class AgentInfo:
    """Agent information for cloud registration"""
    agent_id: str
    hostname: str
    os_type: str
    os_version: str
    kernel_version: str
    architecture: str
    ip_address: str
    mac_address: str
    cpu_count: int
    memory_gb: float
    disk_gb: float
    last_seen: float
    version: str
    status: str  # online, offline, error

@dataclass
class SecurityEvent:
    """Security event for cloud transmission"""
    event_id: str
    agent_id: str
    timestamp: float
    event_type: str  # threat_detected, process_monitored, action_taken
    severity: str    # low, medium, high, critical
    process_pid: int
    process_name: str
    risk_score: float
    threat_technique: Optional[str]
    description: str
    raw_data: Dict[str, Any]

@dataclass
class CloudConfig:
    """Cloud configuration for agent"""
    cloud_endpoint: str
    api_key: str
    agent_id: str
    polling_interval: int
    batch_size: int
    compression_enabled: bool
    encryption_enabled: bool
    tls_cert: Optional[str]
    tls_key: Optional[str]

class CloudBackendClient:
    """Client for cloud backend communication"""
    
    def __init__(self, config: CloudConfig):
        self.config = config
        self.session = self._create_session()
        self.event_queue = queue.Queue(maxsize=10000)
        self.running = False
        self.last_heartbeat = 0
        self.agent_info = self._get_agent_info()
        
        # Threading
        self.upload_thread = None
        self.heartbeat_thread = None
        
    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic"""
        session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Headers
        session.headers.update({
            'User-Agent': 'Linux-Security-Agent/1.0.0',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.config.api_key}'
        })
        
        # SSL configuration
        if self.config.tls_cert and self.config.tls_key:
            session.cert = (self.config.tls_cert, self.config.tls_key)
        
        return session
    
    def _get_agent_info(self) -> AgentInfo:
        """Get current agent information"""
        import platform
        import socket
        import psutil
        
        # Get network info
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        
        # Get MAC address
        mac_address = ':'.join(['{:02x}'.format((socket.inet_aton(ip_address)[i])) for i in range(3)])
        
        # Get system info
        cpu_count = psutil.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024**3)
        disk_gb = psutil.disk_usage('/').total / (1024**3)
        
        return AgentInfo(
            agent_id=self.config.agent_id,
            hostname=hostname,
            os_type=platform.system(),
            os_version=platform.release(),
            kernel_version=platform.version(),
            architecture=platform.machine(),
            ip_address=ip_address,
            mac_address=mac_address,
            cpu_count=cpu_count,
            memory_gb=memory_gb,
            disk_gb=disk_gb,
            last_seen=time.time(),
            version="1.0.0",
            status="online"
        )
    
    def register_agent(self) -> bool:
        """Register agent with cloud backend"""
        try:
            url = f"{self.config.cloud_endpoint}/api/v1/agents/register"
            response = self.session.post(url, json=asdict(self.agent_info), timeout=30)
            
            if response.status_code == 200:
                print("✅ Agent registered successfully with cloud backend")
                return True
            else:
                print(f"❌ Agent registration failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Agent registration error: {e}")
            return False
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to cloud backend"""
        try:
            self.agent_info.last_seen = time.time()
            url = f"{self.config.cloud_endpoint}/api/v1/agents/{self.config.agent_id}/heartbeat"
            response = self.session.post(url, json=asdict(self.agent_info), timeout=10)
            
            if response.status_code == 200:
                self.last_heartbeat = time.time()
                return True
            else:
                print(f"⚠️ Heartbeat failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"⚠️ Heartbeat error: {e}")
            return False
    
    def send_security_event(self, event: SecurityEvent) -> bool:
        """Send security event to cloud backend"""
        try:
            # Add to queue for batch processing
            self.event_queue.put(event, timeout=1)
            return True
        except queue.Full:
            print("⚠️ Event queue full, dropping event")
            return False
    
    def _upload_events_batch(self):
        """Upload events in batches"""
        while self.running:
            try:
                events = []
                
                # Collect events from queue
                while len(events) < self.config.batch_size:
                    try:
                        event = self.event_queue.get(timeout=1)
                        events.append(asdict(event))
                    except queue.Empty:
                        break
                
                if events:
                    # Send batch to cloud
                    url = f"{self.config.cloud_endpoint}/api/v1/events/batch"
                    
                    payload = {
                        'agent_id': self.config.agent_id,
                        'events': events,
                        'timestamp': time.time()
                    }
                    
                    # Compress if enabled
                    if self.config.compression_enabled:
                        import gzip
                        payload_json = json.dumps(payload)
                        payload = gzip.compress(payload_json.encode())
                        headers = {'Content-Encoding': 'gzip'}
                    else:
                        headers = {}
                    
                    response = self.session.post(url, json=payload, headers=headers, timeout=30)
                    
                    if response.status_code == 200:
                        print(f"✅ Uploaded {len(events)} events to cloud")
                    else:
                        print(f"❌ Event upload failed: {response.status_code}")
                        # Re-queue events on failure
                        for event_data in events:
                            try:
                                self.event_queue.put(event_data, timeout=0.1)
                            except queue.Full:
                                break
                
                time.sleep(5)  # Upload every 5 seconds
                
            except Exception as e:
                print(f"❌ Event upload error: {e}")
                time.sleep(10)
    
    def _heartbeat_loop(self):
        """Heartbeat loop"""
        while self.running:
            try:
                self.send_heartbeat()
                time.sleep(self.config.polling_interval)
            except Exception as e:
                print(f"❌ Heartbeat loop error: {e}")
                time.sleep(30)
    
    def get_remote_config(self) -> Optional[Dict]:
        """Get remote configuration from cloud"""
        try:
            url = f"{self.config.cloud_endpoint}/api/v1/agents/{self.config.agent_id}/config"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                return None
                
        except Exception as e:
            print(f"❌ Remote config error: {e}")
            return None
    
    def send_agent_status(self, status: Dict) -> bool:
        """Send agent status to cloud"""
        try:
            url = f"{self.config.cloud_endpoint}/api/v1/agents/{self.config.agent_id}/status"
            response = self.session.post(url, json=status, timeout=10)
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"❌ Status update error: {e}")
            return False
    
    def start(self):
        """Start cloud backend client"""
        self.running = True
        
        # Register agent
        if not self.register_agent():
            print("❌ Failed to register agent, continuing in offline mode")
        
        # Start threads
        self.upload_thread = threading.Thread(target=self._upload_events_batch, daemon=True)
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        
        self.upload_thread.start()
        self.heartbeat_thread.start()
        
        print("✅ Cloud backend client started")
    
    def stop(self):
        """Stop cloud backend client"""
        self.running = False
        
        # Send final heartbeat
        self.send_heartbeat()
        
        # Wait for threads to finish
        if self.upload_thread:
            self.upload_thread.join(timeout=5)
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=5)
        
        print("✅ Cloud backend client stopped")

class CloudBackendManager:
    """Manager for cloud backend integration"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.client = None
        self.enabled = config.get('cloud_enabled', False)
        
        if self.enabled:
            cloud_config = CloudConfig(
                cloud_endpoint=config.get('cloud_endpoint', ''),
                api_key=config.get('api_key', ''),
                agent_id=config.get('agent_id', self._generate_agent_id()),
                polling_interval=config.get('polling_interval', 60),
                batch_size=config.get('batch_size', 100),
                compression_enabled=config.get('compression_enabled', True),
                encryption_enabled=config.get('encryption_enabled', True),
                tls_cert=config.get('tls_cert'),
                tls_key=config.get('tls_key')
            )
            
            self.client = CloudBackendClient(cloud_config)
    
    def _generate_agent_id(self) -> str:
        """Generate unique agent ID"""
        import socket
        import platform
        
        hostname = socket.gethostname()
        system_info = f"{hostname}-{platform.system()}-{platform.machine()}"
        return hashlib.md5(system_info.encode()).hexdigest()
    
    def start(self):
        """Start cloud backend integration"""
        if self.enabled and self.client:
            self.client.start()
        else:
            print("ℹ️ Cloud backend integration disabled")
    
    def stop(self):
        """Stop cloud backend integration"""
        if self.client:
            self.client.stop()
    
    def send_threat_detection(self, pid: int, process_name: str, risk_score: float, 
                            technique: str, description: str):
        """Send threat detection to cloud"""
        if not self.enabled or not self.client:
            return
        
        event = SecurityEvent(
            event_id=self._generate_event_id(),
            agent_id=self.client.config.agent_id,
            timestamp=time.time(),
            event_type="threat_detected",
            severity=self._get_severity(risk_score),
            process_pid=pid,
            process_name=process_name,
            risk_score=risk_score,
            threat_technique=technique,
            description=description,
            raw_data={
                'pid': pid,
                'process_name': process_name,
                'risk_score': risk_score,
                'technique': technique
            }
        )
        
        self.client.send_security_event(event)
    
    def send_process_monitoring(self, pid: int, process_name: str, risk_score: float):
        """Send process monitoring data to cloud"""
        if not self.enabled or not self.client:
            return
        
        event = SecurityEvent(
            event_id=self._generate_event_id(),
            agent_id=self.client.config.agent_id,
            timestamp=time.time(),
            event_type="process_monitored",
            severity=self._get_severity(risk_score),
            process_pid=pid,
            process_name=process_name,
            risk_score=risk_score,
            threat_technique=None,
            description=f"Process {process_name} (PID {pid}) monitored with risk score {risk_score}",
            raw_data={
                'pid': pid,
                'process_name': process_name,
                'risk_score': risk_score
            }
        )
        
        self.client.send_security_event(event)
    
    def send_action_taken(self, pid: int, process_name: str, action: str, reason: str):
        """Send action taken to cloud"""
        if not self.enabled or not self.client:
            return
        
        event = SecurityEvent(
            event_id=self._generate_event_id(),
            agent_id=self.client.config.agent_id,
            timestamp=time.time(),
            event_type="action_taken",
            severity="high",
            process_pid=pid,
            process_name=process_name,
            risk_score=0.0,
            threat_technique=None,
            description=f"Action {action} taken on {process_name} (PID {pid}): {reason}",
            raw_data={
                'pid': pid,
                'process_name': process_name,
                'action': action,
                'reason': reason
            }
        )
        
        self.client.send_security_event(event)
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        timestamp = str(int(time.time() * 1000))
        random_part = str(hash(str(time.time())))[:8]
        return f"evt_{timestamp}_{random_part}"
    
    def _get_severity(self, risk_score: float) -> str:
        """Get severity level from risk score"""
        if risk_score >= 80:
            return "critical"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 40:
            return "medium"
        else:
            return "low"
    
    def get_remote_config(self) -> Optional[Dict]:
        """Get remote configuration"""
        if self.client:
            return self.client.get_remote_config()
        return None
    
    def send_status_update(self, status: Dict):
        """Send status update to cloud"""
        if self.client:
            self.client.send_agent_status(status)

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        'cloud_enabled': True,
        'cloud_endpoint': 'https://api.security-agent.com',
        'api_key': 'your-api-key-here',
        'agent_id': 'agent-12345',
        'polling_interval': 60,
        'batch_size': 100,
        'compression_enabled': True,
        'encryption_enabled': True
    }
    
    # Create cloud backend manager
    cloud_manager = CloudBackendManager(config)
    
    # Start cloud integration
    cloud_manager.start()
    
    # Send some test events
    cloud_manager.send_threat_detection(1234, "malware.exe", 85.5, "T1055", "Process injection detected")
    cloud_manager.send_process_monitoring(5678, "chrome.exe", 25.3)
    cloud_manager.send_action_taken(9999, "suspicious.exe", "freeze", "High risk score")
    
    # Keep running
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        cloud_manager.stop()
