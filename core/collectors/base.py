"""
Abstract base class for syscall collectors
"""
from abc import ABC, abstractmethod
from typing import Callable, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class SyscallEvent:
    """Unified syscall event structure"""
    pid: int
    syscall: str
    uid: int = 0
    comm: str = ""
    exe: str = ""
    timestamp: float = 0.0
    event_info: Optional[Dict[str, Any]] = None


class BaseCollector(ABC):
    """Abstract base class for all collectors"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.running = False
        self._event_callback: Optional[Callable[[SyscallEvent], None]] = None
    
    @abstractmethod
    def start_monitoring(self, event_callback: Callable[[SyscallEvent], None]) -> bool:
        """
        Start monitoring syscalls
        
        Args:
            event_callback: Function to call for each syscall event
            
        Returns:
            True if started successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def stop_monitoring(self) -> None:
        """Stop monitoring syscalls"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if this collector is available on the system"""
        pass
    
    def get_name(self) -> str:
        """Get collector name"""
        return self.__class__.__name__

