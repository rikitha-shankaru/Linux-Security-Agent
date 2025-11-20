"""
Factory for creating collectors with automatic fallback
"""
import logging
from typing import Dict, Any, Optional

from .base import BaseCollector
from .ebpf_collector import EBPFCollector
from .auditd_collector import AuditdCollector

logger = logging.getLogger('security_agent.collector.factory')


def get_collector(config: Optional[Dict[str, Any]] = None, preferred: Optional[str] = None) -> Optional[BaseCollector]:
    """
    Get a collector with automatic fallback
    
    Args:
        config: Configuration dictionary
        preferred: Preferred collector ('ebpf' or 'auditd'), None for auto-select
        
    Returns:
        BaseCollector instance or None if no collector available
    """
    config = config or {}
    preferred = preferred or config.get('collector', 'ebpf').lower()  # Default to eBPF
    
    # Try preferred collector first
    if preferred == 'ebpf':
        collector = EBPFCollector(config)
        if collector.is_available():
            logger.info("✅ Using eBPF collector")
            return collector
        else:
            logger.warning("⚠️ eBPF not available, falling back to auditd")
    
    # Fallback to auditd
    collector = AuditdCollector(config)
    if collector.is_available():
        logger.info("✅ Using auditd collector")
        return collector
    
    # No collector available
    logger.error("❌ No collectors available (eBPF and auditd both failed)")
    return None

