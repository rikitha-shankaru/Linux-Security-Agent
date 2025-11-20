"""
Validation and system checks for the security agent
"""
import os
import sys
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger('security_agent.validator')


def check_collector_available(collector_type: str, config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Check if a collector is available
    
    Returns:
        (is_available, error_message)
    """
    if collector_type == 'auditd':
        audit_log = config.get('audit_log_path', '/var/log/audit/audit.log')
        if not os.path.exists(audit_log):
            return False, f"Audit log not found: {audit_log}\n  Fix: sudo systemctl start auditd"
        if not os.access(audit_log, os.R_OK):
            return False, f"Cannot read audit log: {audit_log}\n  Fix: sudo chmod 644 {audit_log}"
        return True, ""
    
    elif collector_type == 'ebpf':
        try:
            from bcc import BPF
            return True, ""
        except ImportError:
            return False, "BCC tools not installed\n  Fix: sudo apt-get install bpfcc-tools python3-bpfcc"
        except Exception as e:
            return False, f"eBPF not available: {e}\n  Fix: Use auditd collector instead"
    
    return False, f"Unknown collector type: {collector_type}"


def validate_system(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate system requirements
    
    Returns:
        (is_valid, list_of_errors)
    """
    errors = []
    
    # Check Python version
    if sys.version_info < (3, 7):
        errors.append(f"Python 3.7+ required, found {sys.version}")
    
    # Check collector
    collector = config.get('collector', 'auditd')
    available, error = check_collector_available(collector, config)
    if not available:
        errors.append(f"Collector '{collector}' not available: {error}")
    
    # Check ML dependencies (optional but recommended)
    try:
        import sklearn
        import numpy
        import pandas
    except ImportError as e:
        errors.append(f"ML dependencies missing: {e}\n  Fix: pip install scikit-learn numpy pandas")
    
    return len(errors) == 0, errors


def print_validation_results(is_valid: bool, errors: List[str]) -> None:
    """Print validation results in a user-friendly way"""
    if is_valid:
        print("✅ System validation passed")
        return
    
    print("❌ System validation failed:")
    print()
    for i, error in enumerate(errors, 1):
        print(f"  {i}. {error}")
    print()
    print("Please fix the errors above and try again.")

