"""
Auditd collector - adapts AuditdCollector to BaseCollector interface
"""
import time
from typing import Callable, Dict, Any, Optional
import logging

from .base import BaseCollector, SyscallEvent

logger = logging.getLogger('security_agent.collector.auditd')

try:
    from core.collector_auditd import AuditdCollector as _AuditdCollector
    AUDITD_AVAILABLE = True
except ImportError:
    try:
        from collector_auditd import AuditdCollector as _AuditdCollector
        AUDITD_AVAILABLE = True
    except ImportError:
        AUDITD_AVAILABLE = False
        _AuditdCollector = None


class AuditdCollectorWrapper(BaseCollector):
    """Auditd-based syscall collector"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.collector: Optional[_AuditdCollector] = None
    
    def is_available(self) -> bool:
        """Check if auditd is available"""
        if not AUDITD_AVAILABLE:
            return False
        import os
        audit_log = self.config.get('audit_log_path', '/var/log/audit/audit.log')
        return os.path.exists(audit_log) and os.access(audit_log, os.R_OK)
    
    def start_monitoring(self, event_callback: Callable[[SyscallEvent], None]) -> bool:
        """Start auditd monitoring"""
        if not self.is_available():
            return False
        
        try:
            self.collector = _AuditdCollector(self.config)
            
            # Wrap callback to convert to SyscallEvent
            def wrapped_callback(pid: int, syscall: str, event_info: Dict[str, Any]):
                event = SyscallEvent(
                    pid=pid,
                    syscall=syscall,
                    uid=event_info.get('uid', 0),
                    comm=event_info.get('comm', ''),
                    exe=event_info.get('exe', ''),
                    timestamp=time.time(),
                    event_info=event_info
                )
                event_callback(event)
            
            success = self.collector.start_monitoring(wrapped_callback)
            if success:
                self.running = True
            return success
        except Exception as e:
            logger.error(f"Failed to start auditd collector: {e}")
            return False
    
    def stop_monitoring(self) -> None:
        """Stop auditd monitoring"""
        self.running = False
        if self.collector:
            try:
                self.collector.stop_monitoring()
            except Exception as e:
                logger.debug(f"Error stopping auditd collector: {e}")

