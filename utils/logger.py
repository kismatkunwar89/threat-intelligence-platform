"""
Logging configuration for the application.

This module demonstrates:
- Python logging module configuration
- Custom log formatting
- File and console handlers
- Log rotation
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from config import Config


def setup_logging(app_name: str = "threat_intel_app", log_level: str = None):
    """
    Configure application-wide logging.

    This sets up:
    - Console output (colored if possible)
    - File output with rotation
    - Custom formatting
    - Different log levels for dev/prod

    Args:
        app_name: Name of the application for log files
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    # Determine log level
    if log_level is None:
        log_level = logging.DEBUG if Config.is_development() else logging.INFO

    # Create logs directory
    log_dir = Path(__file__).parent.parent / 'logs'
    log_dir.mkdir(exist_ok=True)

    # Define log format
    log_format = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Detailed format for file logging
    detailed_format = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(log_format)
    root_logger.addHandler(console_handler)

    # File Handler with rotation (10 MB max, keep 5 backups)
    log_file = log_dir / f'{app_name}.log'
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)  # Always log DEBUG to file
    file_handler.setFormatter(detailed_format)
    root_logger.addHandler(file_handler)

    # Error file handler (separate file for errors)
    error_log_file = log_dir / f'{app_name}_errors.log'
    error_handler = RotatingFileHandler(
        error_log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_format)
    root_logger.addHandler(error_handler)

    # Log startup message
    root_logger.info(f"Logging initialized - Level: {logging.getLevelName(log_level)}")
    root_logger.info(f"Log file: {log_file}")
    root_logger.info(f"Error log file: {error_log_file}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    Args:
        name: Logger name (usually __name__)

    Returns:
        logging.Logger: Configured logger instance

    Example:
        logger = get_logger(__name__)
        logger.info("Starting process")
    """
    return logging.getLogger(name)
