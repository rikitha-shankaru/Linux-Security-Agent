#!/usr/bin/env python3
"""
Security Hardening Module for Linux Security Agent
Implements tamper protection, integrity checking, and security hardening
"""

import os
import sys
import time
import hashlib
import hmac
import json
import threading
import subprocess
import signal
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
import psutil
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets

@dataclass
class SecurityConfig:
    """Security configuration"""
    enable_tamper_protection: bool
    enable_integrity_checking: bool
    enable_process_protection: bool
    enable_file_monitoring: bool
    enable_memory_protection: bool
    encryption_key: Optional[str]
    integrity_hash: Optional[str]
    protected_files: List[str]
    protected_processes: List[str]
    alert_threshold: float

@dataclass
class SecurityEvent:
    """Security event for tamper detection"""
    event_type: str
    timestamp: float
    process_pid: int
    process_name: str
    file_path: Optional[str]
    action: str
    severity: str
    description: str

class IntegrityChecker:
    """File and process integrity checking"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.file_hashes = {}
        self.process_hashes = {}
        self.baseline_hashes = {}
        self.running = False
        self.check_thread = None
        
    def start(self):
        """Start integrity checking"""
        self.running = True
        self.check_thread = threading.Thread(target=self._integrity_loop, daemon=True)
        self.check_thread.start()
        print("✅ Integrity checking started")
    
    def stop(self):
        """Stop integrity checking"""
        self.running = False
        if self.check_thread:
            self.check_thread.join(timeout=5)
        print("✅ Integrity checking stopped")
    
    def _integrity_loop(self):
        """Main integrity checking loop"""
        while self.running:
            try:
                # Check protected files
                for file_path in self.config.protected_files:
                    if os.path.exists(file_path):
                        self._check_file_integrity(file_path)
                
                # Check protected processes
                for process_name in self.config.protected_processes:
                    self._check_process_integrity(process_name)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"Integrity check error: {e}")
                time.sleep(60)
    
    def _check_file_integrity(self, file_path: str):
        """Check file integrity"""
        try:
            current_hash = self._calculate_file_hash(file_path)
            
            if file_path in self.baseline_hashes:
                baseline_hash = self.baseline_hashes[file_path]
                if current_hash != baseline_hash:
                    self._handle_integrity_violation(
                        "file_tamper", file_path, f"Hash mismatch: {current_hash} vs {baseline_hash}"
                    )
            else:
                # First time seeing this file, store baseline
                self.baseline_hashes[file_path] = current_hash
            
            self.file_hashes[file_path] = current_hash
            
        except Exception as e:
            print(f"File integrity check error for {file_path}: {e}")
    
    def _check_process_integrity(self, process_name: str):
        """Check process integrity"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                if proc.info['name'] == process_name:
                    exe_path = proc.info['exe']
                    if exe_path and os.path.exists(exe_path):
                        current_hash = self._calculate_file_hash(exe_path)
                        
                        if exe_path in self.baseline_hashes:
                            baseline_hash = self.baseline_hashes[exe_path]
                            if current_hash != baseline_hash:
                                self._handle_integrity_violation(
                                    "process_tamper", exe_path, 
                                    f"Process binary tampered: {current_hash} vs {baseline_hash}"
                                )
                        else:
                            self.baseline_hashes[exe_path] = current_hash
                        
                        self.process_hashes[exe_path] = current_hash
                        
        except Exception as e:
            print(f"Process integrity check error for {process_name}: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Hash calculation error for {file_path}: {e}")
            return ""
    
    def _handle_integrity_violation(self, event_type: str, file_path: str, description: str):
        """Handle integrity violation"""
        event = SecurityEvent(
            event_type=event_type,
            timestamp=time.time(),
            process_pid=0,
            process_name="system",
            file_path=file_path,
            action="tamper_detected",
            severity="critical",
            description=description
        )
        
        print(f"🚨 INTEGRITY VIOLATION: {description}")
        
        # Log the event
        self._log_security_event(event)
        
        # Take protective action
        self._take_protective_action(event)
    
    def _log_security_event(self, event: SecurityEvent):
        """Log security event"""
        log_entry = {
            'timestamp': event.timestamp,
            'event_type': event.event_type,
            'severity': event.severity,
            'description': event.description,
            'file_path': event.file_path,
            'process_pid': event.process_pid,
            'process_name': event.process_name
        }
        
        # Write to security log
        log_file = "/var/log/security_agent_integrity.log"
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"Failed to log security event: {e}")
    
    def _take_protective_action(self, event: SecurityEvent):
        """Take protective action"""
        if event.event_type == "file_tamper":
            # Quarantine the file
            self._quarantine_file(event.file_path)
        elif event.event_type == "process_tamper":
            # Kill the process
            self._kill_process(event.process_pid)
    
    def _quarantine_file(self, file_path: str):
        """Quarantine a tampered file"""
        try:
            quarantine_dir = "/var/quarantine"
            os.makedirs(quarantine_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, f"{filename}.quarantined")
            
            # Move file to quarantine
            subprocess.run(['mv', file_path, quarantine_path], check=True)
            print(f"🔒 File quarantined: {file_path} -> {quarantine_path}")
            
        except Exception as e:
            print(f"Failed to quarantine file {file_path}: {e}")
    
    def _kill_process(self, pid: int):
        """Kill a tampered process"""
        try:
            if pid > 0:
                os.kill(pid, signal.SIGKILL)
                print(f"🔒 Process killed: PID {pid}")
        except Exception as e:
            print(f"Failed to kill process {pid}: {e}")

class ProcessProtector:
    """Process protection and monitoring"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.protected_processes = set(config.protected_processes)
        self.process_monitor_thread = None
        self.running = False
        
    def start(self):
        """Start process protection"""
        self.running = True
        self.process_monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        self.process_monitor_thread.start()
        print("✅ Process protection started")
    
    def stop(self):
        """Stop process protection"""
        self.running = False
        if self.process_monitor_thread:
            self.process_monitor_thread.join(timeout=5)
        print("✅ Process protection stopped")
    
    def _monitor_processes(self):
        """Monitor protected processes"""
        while self.running:
            try:
                current_processes = set()
                
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] in self.protected_processes:
                        current_processes.add(proc.info['name'])
                
                # Check for missing processes
                missing_processes = self.protected_processes - current_processes
                if missing_processes:
                    self._handle_missing_processes(missing_processes)
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                print(f"Process monitoring error: {e}")
                time.sleep(30)
    
    def _handle_missing_processes(self, missing_processes: set):
        """Handle missing protected processes"""
        for process_name in missing_processes:
            event = SecurityEvent(
                event_type="process_missing",
                timestamp=time.time(),
                process_pid=0,
                process_name=process_name,
                file_path=None,
                action="process_killed",
                severity="high",
                description=f"Protected process {process_name} is missing"
            )
            
            print(f"🚨 PROTECTED PROCESS MISSING: {process_name}")
            self._log_security_event(event)
    
    def _log_security_event(self, event: SecurityEvent):
        """Log security event"""
        log_entry = {
            'timestamp': event.timestamp,
            'event_type': event.event_type,
            'severity': event.severity,
            'description': event.description,
            'process_name': event.process_name
        }
        
        log_file = "/var/log/security_agent_protection.log"
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"Failed to log security event: {e}")

class MemoryProtector:
    """Memory protection and monitoring"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.memory_monitor_thread = None
        self.running = False
        
    def start(self):
        """Start memory protection"""
        self.running = True
        self.memory_monitor_thread = threading.Thread(target=self._monitor_memory, daemon=True)
        self.memory_monitor_thread.start()
        print("✅ Memory protection started")
    
    def stop(self):
        """Stop memory protection"""
        self.running = False
        if self.memory_monitor_thread:
            self.memory_monitor_thread.join(timeout=5)
        print("✅ Memory protection stopped")
    
    def _monitor_memory(self):
        """Monitor memory usage and patterns"""
        while self.running:
            try:
                # Check for suspicious memory patterns
                memory = psutil.virtual_memory()
                
                if memory.percent > 90:
                    self._handle_high_memory_usage(memory.percent)
                
                # Check for memory leaks in our own process
                our_process = psutil.Process()
                our_memory = our_process.memory_info().rss / 1024 / 1024  # MB
                
                if our_memory > 500:  # 500MB threshold
                    self._handle_memory_leak(our_memory)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"Memory monitoring error: {e}")
                time.sleep(60)
    
    def _handle_high_memory_usage(self, memory_percent: float):
        """Handle high memory usage"""
        event = SecurityEvent(
            event_type="high_memory_usage",
            timestamp=time.time(),
            process_pid=0,
            process_name="system",
            file_path=None,
            action="memory_warning",
            severity="medium",
            description=f"System memory usage is {memory_percent:.1f}%"
        )
        
        print(f"⚠️ HIGH MEMORY USAGE: {memory_percent:.1f}%")
        self._log_security_event(event)
    
    def _handle_memory_leak(self, memory_mb: float):
        """Handle potential memory leak"""
        event = SecurityEvent(
            event_type="memory_leak",
            timestamp=time.time(),
            process_pid=os.getpid(),
            process_name="security_agent",
            file_path=None,
            action="memory_leak_detected",
            severity="high",
            description=f"Security agent memory usage is {memory_mb:.1f}MB"
        )
        
        print(f"🚨 MEMORY LEAK DETECTED: {memory_mb:.1f}MB")
        self._log_security_event(event)
        
        # Force garbage collection
        import gc
        gc.collect()
    
    def _log_security_event(self, event: SecurityEvent):
        """Log security event"""
        log_entry = {
            'timestamp': event.timestamp,
            'event_type': event.event_type,
            'severity': event.severity,
            'description': event.description,
            'memory_mb': event.process_pid
        }
        
        log_file = "/var/log/security_agent_memory.log"
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"Failed to log security event: {e}")

class EncryptionManager:
    """Encryption and secure communication"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.encryption_key = None
        self.cipher = None
        
        if config.encryption_key:
            self._setup_encryption(config.encryption_key)
    
    def _setup_encryption(self, key: str):
        """Setup encryption"""
        try:
            # Derive key from password
            password = key.encode()
            salt = b'security_agent_salt'  # In production, use random salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key_bytes = base64.urlsafe_b64encode(kdf.derive(password))
            
            self.cipher = Fernet(key_bytes)
            print("✅ Encryption setup completed")
            
        except Exception as e:
            print(f"Encryption setup error: {e}")
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt data"""
        if not self.cipher:
            return data
        
        try:
            encrypted_data = self.cipher.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            print(f"Encryption error: {e}")
            return data
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data"""
        if not self.cipher:
            return encrypted_data
        
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.cipher.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return encrypted_data

class SecurityHardener:
    """Main security hardening manager"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.integrity_checker = IntegrityChecker(config)
        self.process_protector = ProcessProtector(config)
        self.memory_protector = MemoryProtector(config)
        self.encryption_manager = EncryptionManager(config)
        
        # Security event log
        self.security_events = []
        self.event_lock = threading.Lock()
        
    def start(self):
        """Start all security hardening components"""
        if self.config.enable_integrity_checking:
            self.integrity_checker.start()
        
        if self.config.enable_process_protection:
            self.process_protector.start()
        
        if self.config.enable_memory_protection:
            self.memory_protector.start()
        
        print("✅ Security hardening started")
    
    def stop(self):
        """Stop all security hardening components"""
        self.integrity_checker.stop()
        self.process_protector.stop()
        self.memory_protector.stop()
        print("✅ Security hardening stopped")
    
    def add_security_event(self, event: SecurityEvent):
        """Add security event"""
        with self.event_lock:
            self.security_events.append(event)
            
            # Keep only last 1000 events
            if len(self.security_events) > 1000:
                self.security_events = self.security_events[-1000:]
    
    def get_security_report(self) -> Dict:
        """Get security report"""
        with self.event_lock:
            events = self.security_events.copy()
        
        # Categorize events
        event_counts = {}
        for event in events:
            event_type = event.event_type
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        return {
            'total_events': len(events),
            'event_counts': event_counts,
            'recent_events': events[-10:] if events else [],
            'integrity_status': 'active' if self.config.enable_integrity_checking else 'disabled',
            'process_protection': 'active' if self.config.enable_process_protection else 'disabled',
            'memory_protection': 'active' if self.config.enable_memory_protection else 'disabled',
            'encryption': 'active' if self.config.encryption_key else 'disabled'
        }
    
    def generate_integrity_baseline(self) -> Dict:
        """Generate integrity baseline"""
        baseline = {}
        
        for file_path in self.config.protected_files:
            if os.path.exists(file_path):
                baseline[file_path] = self.integrity_checker._calculate_file_hash(file_path)
        
        return baseline
    
    def save_integrity_baseline(self, baseline: Dict, file_path: str):
        """Save integrity baseline"""
        try:
            with open(file_path, 'w') as f:
                json.dump(baseline, f, indent=2)
            print(f"✅ Integrity baseline saved to {file_path}")
        except Exception as e:
            print(f"Failed to save integrity baseline: {e}")
    
    def load_integrity_baseline(self, file_path: str) -> Dict:
        """Load integrity baseline"""
        try:
            with open(file_path, 'r') as f:
                baseline = json.load(f)
            print(f"✅ Integrity baseline loaded from {file_path}")
            return baseline
        except Exception as e:
            print(f"Failed to load integrity baseline: {e}")
            return {}

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = SecurityConfig(
        enable_tamper_protection=True,
        enable_integrity_checking=True,
        enable_process_protection=True,
        enable_file_monitoring=True,
        enable_memory_protection=True,
        encryption_key="your-secret-key-here",
        integrity_hash=None,
        protected_files=[
            "/usr/bin/python3",
            "/usr/bin/security_agent",
            "/etc/security_agent/config.json"
        ],
        protected_processes=[
            "security_agent",
            "systemd",
            "sshd"
        ],
        alert_threshold=7.0
    )
    
    # Create security hardener
    hardener = SecurityHardener(config)
    
    # Start security hardening
    hardener.start()
    
    # Generate and save baseline
    baseline = hardener.generate_integrity_baseline()
    hardener.save_integrity_baseline(baseline, "/var/lib/security_agent/baseline.json")
    
    # Run for a while
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        pass
    
    # Get security report
    report = hardener.get_security_report()
    print(f"Security Report: {report}")
    
    # Stop
    hardener.stop()
