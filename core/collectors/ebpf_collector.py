"""
eBPF collector wrapper - adapts StatefulEBPFMonitor to BaseCollector interface
"""
import time
from typing import Callable, Dict, Any, Optional
import logging

from .base import BaseCollector, SyscallEvent

logger = logging.getLogger('security_agent.collector.ebpf')

try:
    from core.enhanced_ebpf_monitor import StatefulEBPFMonitor
    EBPF_AVAILABLE = True
except ImportError:
    try:
        from enhanced_ebpf_monitor import StatefulEBPFMonitor
        EBPF_AVAILABLE = True
    except ImportError:
        EBPF_AVAILABLE = False
        StatefulEBPFMonitor = None


class EBPFCollector(BaseCollector):
    """eBPF-based syscall collector"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.monitor: Optional[StatefulEBPFMonitor] = None
    
    def is_available(self) -> bool:
        """Check if eBPF is available"""
        if not EBPF_AVAILABLE:
            return False
        try:
            # Try to create monitor to verify eBPF works
            test_monitor = StatefulEBPFMonitor(self.config)
            return True
        except Exception as e:
            logger.debug(f"eBPF not available: {e}")
            return False
    
    def start_monitoring(self, event_callback: Callable[[SyscallEvent], None]) -> bool:
        """Start eBPF monitoring"""
        if not self.is_available():
            return False
        
        try:
            self.monitor = StatefulEBPFMonitor(self.config)
            
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
            
            self.monitor.start_monitoring(wrapped_callback)
            self.running = True
            return True
        except Exception as e:
            logger.error(f"Failed to start eBPF collector: {e}")
            return False
    
    def stop_monitoring(self) -> None:
        """Stop eBPF monitoring"""
        self.running = False
        if self.monitor:
            try:
                self.monitor.stop_monitoring()
            except Exception as e:
                logger.debug(f"Error stopping eBPF monitor: {e}")

