"""
Centralized logging helper for consistent logging across modules
"""
import logging
import sys
from typing import Optional

# Global logger instance
_logger: Optional[logging.Logger] = None

def setup_logging(level: int = logging.INFO, log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging configuration"""
    global _logger
    
    # Create logger
    _logger = logging.getLogger('security_agent')
    _logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    _logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    _logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        _logger.addHandler(file_handler)
    
    return _logger

def get_logger(name: str = 'security_agent') -> logging.Logger:
    """Get logger instance"""
    return logging.getLogger(name)

