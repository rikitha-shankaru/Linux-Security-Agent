"""
Collector modules for syscall event capture
"""
from .base import BaseCollector, SyscallEvent
from .collector_factory import get_collector

__all__ = ['BaseCollector', 'SyscallEvent', 'get_collector']

