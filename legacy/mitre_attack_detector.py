#!/usr/bin/env python3
"""
MITRE ATT&CK Framework Integration for Threat Detection
Maps system call patterns to ATT&CK techniques
"""

import json
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict

class AttackTactic(Enum):
    """MITRE ATT&CK Tactics"""
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"

@dataclass
class AttackTechnique:
    """MITRE ATT&CK Technique"""
    technique_id: str
    name: str
    tactic: AttackTactic
    description: str
    syscall_indicators: List[str]
    file_indicators: List[str]
    network_indicators: List[Tuple[str, int]]
    process_indicators: List[str]
    risk_score: int  # 1-10

@dataclass
class ThreatDetection:
    """Threat detection result"""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float  # 0.0 - 1.0
    indicators: List[str]
    timestamp: float
    process_pid: int
    process_name: str
    risk_score: int

class MITREAttackDetector:
    """MITRE ATT&CK threat detection engine"""
    
    def __init__(self):
        self.techniques = self._load_attack_techniques()
        self.detection_history = []
        self.active_threats = {}  # pid -> List[ThreatDetection]
        
    def _load_attack_techniques(self) -> Dict[str, AttackTechnique]:
        """Load MITRE ATT&CK techniques with system call mappings"""
        techniques = {}
        
        # T1055 - Process Injection
        techniques["T1055"] = AttackTechnique(
            technique_id="T1055",
            name="Process Injection",
            tactic=AttackTactic.DEFENSE_EVASION,
            description="Adversaries may inject code into processes in order to evade process-based defenses",
            syscall_indicators=["ptrace", "process_vm_writev", "process_vm_readv", "mmap", "mprotect"],
            file_indicators=["/proc/*/mem", "/dev/mem", "/dev/kmem"],
            network_indicators=[],
            process_indicators=["inject", "injection", "dll", "payload"],
            risk_score=9
        )
        
        # T1059 - Command and Scripting Interpreter
        techniques["T1059"] = AttackTechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic=AttackTactic.EXECUTION,
            description="Adversaries may abuse command and script interpreters to execute commands",
            syscall_indicators=["execve", "execveat", "system", "popen"],
            file_indicators=["*.sh", "*.py", "*.pl", "*.rb", "*.ps1", "*.bat", "*.cmd"],
            network_indicators=[],
            process_indicators=["bash", "sh", "python", "perl", "ruby", "powershell"],
            risk_score=6
        )
        
        # T1071 - Application Layer Protocol
        techniques["T1071"] = AttackTechnique(
            technique_id="T1071",
            name="Application Layer Protocol",
            tactic=AttackTactic.COMMAND_AND_CONTROL,
            description="Adversaries may communicate using application layer protocols",
            syscall_indicators=["socket", "connect", "send", "recv", "sendto", "recvfrom"],
            file_indicators=[],
            network_indicators=[(".*", 80), (".*", 443), (".*", 8080), (".*", 8443)],
            process_indicators=[],
            risk_score=5
        )
        
        # T1083 - File and Directory Discovery
        techniques["T1083"] = AttackTechnique(
            technique_id="T1083",
            name="File and Directory Discovery",
            tactic=AttackTactic.DISCOVERY,
            description="Adversaries may enumerate files and directories",
            syscall_indicators=["getdents", "getdents64", "readdir", "stat", "lstat", "fstat"],
            file_indicators=["/etc/", "/home/", "/root/", "/var/", "/tmp/"],
            network_indicators=[],
            process_indicators=["find", "ls", "dir", "tree"],
            risk_score=3
        )
        
        # T1105 - Ingress Tool Transfer
        techniques["T1105"] = AttackTechnique(
            technique_id="T1105",
            name="Ingress Tool Transfer",
            tactic=AttackTactic.COMMAND_AND_CONTROL,
            description="Adversaries may transfer tools or other files from an external system",
            syscall_indicators=["socket", "connect", "recv", "write", "open", "creat"],
            file_indicators=["/tmp/", "/var/tmp/", "*.exe", "*.dll", "*.so"],
            network_indicators=[(".*", 80), (".*", 443), (".*", 21), (".*", 22)],
            process_indicators=["wget", "curl", "ftp", "scp", "rsync"],
            risk_score=7
        )
        
        # T1134 - Access Token Manipulation
        techniques["T1134"] = AttackTechnique(
            technique_id="T1134",
            name="Access Token Manipulation",
            tactic=AttackTactic.DEFENSE_EVASION,
            description="Adversaries may modify access tokens to operate under a different user",
            syscall_indicators=["setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid"],
            file_indicators=[],
            network_indicators=[],
            process_indicators=[],
            risk_score=8
        )
        
        # T1140 - Deobfuscate/Decode Files or Information
        techniques["T1140"] = AttackTechnique(
            technique_id="T1140",
            name="Deobfuscate/Decode Files or Information",
            tactic=AttackTactic.DEFENSE_EVASION,
            description="Adversaries may use obfuscated files or information to hide artifacts",
            syscall_indicators=["read", "write", "mmap", "munmap"],
            file_indicators=["*.enc", "*.encrypted", "*.base64", "*.hex"],
            network_indicators=[],
            process_indicators=["base64", "openssl", "gpg", "decrypt"],
            risk_score=6
        )
        
        # T1486 - Data Encrypted for Impact
        techniques["T1486"] = AttackTechnique(
            technique_id="T1486",
            name="Data Encrypted for Impact",
            tactic=AttackTactic.IMPACT,
            description="Adversaries may encrypt data on target systems to interrupt availability",
            syscall_indicators=["open", "read", "write", "rename", "unlink"],
            file_indicators=["*.encrypted", "*.locked", "*.ransom", "README.txt"],
            network_indicators=[],
            process_indicators=["encrypt", "ransom", "crypto", "lock"],
            risk_score=10
        )
        
        # T1543 - Create or Modify System Process
        techniques["T1543"] = AttackTechnique(
            technique_id="T1543",
            name="Create or Modify System Process",
            tactic=AttackTactic.PERSISTENCE,
            description="Adversaries may create or modify system-level processes to repeatedly execute malicious payloads",
            syscall_indicators=["execve", "fork", "clone", "systemctl", "service"],
            file_indicators=["/etc/systemd/", "/etc/init.d/", "/etc/rc.d/"],
            network_indicators=[],
            process_indicators=["systemd", "init", "service"],
            risk_score=7
        )
        
        # T1566 - Phishing
        techniques["T1566"] = AttackTechnique(
            technique_id="T1566",
            name="Phishing",
            tactic=AttackTactic.INITIAL_ACCESS,
            description="Adversaries may send phishing messages to gain access to victim systems",
            syscall_indicators=["socket", "connect", "send", "recv"],
            file_indicators=["*.eml", "*.msg", "*.html", "*.pdf"],
            network_indicators=[(".*", 25), (".*", 587), (".*", 465), (".*", 993), (".*", 995)],
            process_indicators=["mail", "sendmail", "postfix", "thunderbird", "outlook"],
            risk_score=4
        )
        
        return techniques
    
    def detect_threats(self, pid: int, process_name: str, syscalls: List[str], 
                      file_access: List[str], network_connections: List[Tuple[str, int]]) -> List[ThreatDetection]:
        """Detect threats based on system call patterns"""
        detections = []
        
        for technique_id, technique in self.techniques.items():
            confidence = self._calculate_confidence(technique, syscalls, file_access, network_connections, process_name)
            
            if confidence > 0.3:  # Minimum confidence threshold
                indicators = self._get_matching_indicators(technique, syscalls, file_access, network_connections, process_name)
                
                detection = ThreatDetection(
                    technique_id=technique_id,
                    technique_name=technique.name,
                    tactic=technique.tactic.value,
                    confidence=confidence,
                    indicators=indicators,
                    timestamp=time.time(),
                    process_pid=pid,
                    process_name=process_name,
                    risk_score=technique.risk_score
                )
                
                detections.append(detection)
        
        # Store detections
        if detections:
            if pid not in self.active_threats:
                self.active_threats[pid] = []
            self.active_threats[pid].extend(detections)
            self.detection_history.extend(detections)
        
        return detections
    
    def _calculate_confidence(self, technique: AttackTechnique, syscalls: List[str], 
                            file_access: List[str], network_connections: List[Tuple[str, int]], 
                            process_name: str) -> float:
        """Calculate confidence score for technique detection"""
        confidence = 0.0
        total_indicators = 0
        matched_indicators = 0
        
        # Check syscall indicators
        if technique.syscall_indicators:
            total_indicators += len(technique.syscall_indicators)
            for indicator in technique.syscall_indicators:
                if indicator in syscalls:
                    matched_indicators += 1
                    confidence += 0.3  # High weight for syscall matches
        
        # Check file indicators
        if technique.file_indicators:
            total_indicators += len(technique.file_indicators)
            for indicator in technique.file_indicators:
                for file_path in file_access:
                    if self._match_file_pattern(file_path, indicator):
                        matched_indicators += 1
                        confidence += 0.2
                        break
        
        # Check network indicators
        if technique.network_indicators:
            total_indicators += len(technique.network_indicators)
            for host_pattern, port in technique.network_indicators:
                for host, conn_port in network_connections:
                    if self._match_network_pattern(host, port, host_pattern, conn_port):
                        matched_indicators += 1
                        confidence += 0.2
                        break
        
        # Check process indicators
        if technique.process_indicators:
            total_indicators += len(technique.process_indicators)
            for indicator in technique.process_indicators:
                if indicator.lower() in process_name.lower():
                    matched_indicators += 1
                    confidence += 0.1
        
        # Normalize confidence
        if total_indicators > 0:
            confidence = min(1.0, confidence)
        
        return confidence
    
    def _get_matching_indicators(self, technique: AttackTechnique, syscalls: List[str], 
                               file_access: List[str], network_connections: List[Tuple[str, int]], 
                               process_name: str) -> List[str]:
        """Get list of matching indicators"""
        indicators = []
        
        # Syscall matches
        for indicator in technique.syscall_indicators:
            if indicator in syscalls:
                indicators.append(f"syscall:{indicator}")
        
        # File matches
        for indicator in technique.file_indicators:
            for file_path in file_access:
                if self._match_file_pattern(file_path, indicator):
                    indicators.append(f"file:{file_path}")
                    break
        
        # Network matches
        for host_pattern, port in technique.network_indicators:
            for host, conn_port in network_connections:
                if self._match_network_pattern(host, port, host_pattern, conn_port):
                    indicators.append(f"network:{host}:{conn_port}")
                    break
        
        # Process matches
        for indicator in technique.process_indicators:
            if indicator.lower() in process_name.lower():
                indicators.append(f"process:{process_name}")
                break
        
        return indicators
    
    def _match_file_pattern(self, file_path: str, pattern: str) -> bool:
        """Match file path against pattern"""
        import fnmatch
        return fnmatch.fnmatch(file_path, pattern)
    
    def _match_network_pattern(self, host: str, port: int, host_pattern: str, target_port: int) -> bool:
        """Match network connection against pattern"""
        import fnmatch
        
        # Check port match
        if target_port != port and port != -1:
            return False
        
        # Check host pattern
        return fnmatch.fnmatch(host, host_pattern)
    
    def get_active_threats(self, pid: int = None) -> Dict[int, List[ThreatDetection]]:
        """Get active threats for process or all processes"""
        if pid:
            return {pid: self.active_threats.get(pid, [])}
        return self.active_threats.copy()
    
    def get_threat_summary(self) -> Dict[str, int]:
        """Get summary of detected threats by technique"""
        summary = defaultdict(int)
        for detection in self.detection_history:
            summary[detection.technique_id] += 1
        return dict(summary)
    
    def get_high_risk_processes(self) -> List[Tuple[int, str, List[ThreatDetection]]]:
        """Get processes with high-risk threat detections"""
        high_risk = []
        for pid, detections in self.active_threats.items():
            high_risk_detections = [d for d in detections if d.risk_score >= 7]
            if high_risk_detections:
                process_name = high_risk_detections[0].process_name
                high_risk.append((pid, process_name, high_risk_detections))
        
        return sorted(high_risk, key=lambda x: max(d.risk_score for d in x[2]), reverse=True)
    
    def export_detections(self, format: str = 'json') -> str:
        """Export threat detections"""
        if format == 'json':
            detections_data = [asdict(detection) for detection in self.detection_history]
            return json.dumps(detections_data, indent=2)
        return ""
    
    def clear_old_detections(self, max_age: float = 3600):
        """Clear detections older than max_age seconds"""
        current_time = time.time()
        
        # Clear from history
        self.detection_history = [
            d for d in self.detection_history 
            if current_time - d.timestamp < max_age
        ]
        
        # Clear from active threats
        for pid in list(self.active_threats.keys()):
            self.active_threats[pid] = [
                d for d in self.active_threats[pid]
                if current_time - d.timestamp < max_age
            ]
            if not self.active_threats[pid]:
                del self.active_threats[pid]

# Example usage
if __name__ == "__main__":
    detector = MITREAttackDetector()
    
    # Simulate threat detection
    syscalls = ["ptrace", "process_vm_writev", "mmap"]
    file_access = ["/proc/1234/mem"]
    network_connections = [("192.168.1.100", 443)]
    
    detections = detector.detect_threats(1234, "malware", syscalls, file_access, network_connections)
    
    for detection in detections:
        print(f"Threat: {detection.technique_name} ({detection.technique_id})")
        print(f"Confidence: {detection.confidence:.2f}")
        print(f"Risk Score: {detection.risk_score}")
        print(f"Indicators: {detection.indicators}")
        print()
