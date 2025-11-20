"""
Pytest configuration and fixtures
"""
import pytest
import sys
import os
from unittest.mock import Mock, MagicMock

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))


@pytest.fixture
def mock_config():
    """Fixture for default test configuration"""
    return {
        'risk_threshold': 50.0,
        'anomaly_weight': 0.3,
        'decay_factor': 0.95,
        'decay_interval': 60,
        'collector': 'ebpf',
        'debug': False
    }


@pytest.fixture
def mock_psutil():
    """Fixture for mocking psutil"""
    with pytest.mock.patch('psutil.Process') as mock_proc:
        mock_proc.return_value.name.return_value = 'test_process'
        mock_proc.return_value.cpu_percent.return_value = 5.0
        mock_proc.return_value.memory_percent.return_value = 2.0
        mock_proc.return_value.num_threads.return_value = 2
        yield mock_proc


@pytest.fixture
def mock_logger():
    """Fixture for mocking logger"""
    import logging
    logger = logging.getLogger('test_security_agent')
    logger.setLevel(logging.DEBUG)
    return logger

