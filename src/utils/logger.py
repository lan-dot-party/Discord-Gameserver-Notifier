"""
Logging configuration and setup for Discord Gameserver Notifier.
Provides structured logging with both console and file output capabilities.
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional, Dict, Any

class LoggerSetup:
    """Handles the setup and configuration of the application's logging system."""
    
    DEFAULT_FORMAT = '%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s'
    DEFAULT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    
    @staticmethod
    def setup_logger(config: Dict[Any, Any]) -> logging.Logger:
        """
        Sets up the logger based on the provided configuration.
        
        Args:
            config: Dictionary containing logging configuration from config.yaml
                   Expected structure:
                   {
                       'debugging': {
                           'log_level': 'INFO',
                           'log_to_file': True,
                           'log_file': './notifier.log'
                       }
                   }
        
        Returns:
            logging.Logger: Configured logger instance
        """
        # Extract logging configuration
        debug_config = config.get('debugging', {})
        log_level = debug_config.get('log_level', 'INFO').upper()
        log_to_file = debug_config.get('log_to_file', True)
        log_file = debug_config.get('log_file', './notifier.log')
        
        # Create logger
        logger = logging.getLogger('GameServerNotifier')
        logger.setLevel(getattr(logging, log_level))
        
        # Create formatters
        formatter = logging.Formatter(
            fmt=LoggerSetup.DEFAULT_FORMAT,
            datefmt=LoggerSetup.DEFAULT_DATE_FORMAT
        )
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # Add file handler if enabled
        if log_to_file:
            # Ensure log directory exists
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create rotating file handler (10 MB per file, keep 5 backup files)
            file_handler = logging.handlers.RotatingFileHandler(
                filename=log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        # Prevent propagation to root logger
        logger.propagate = False
        
        # Log initial setup
        logger.info(f"Logger initialized with level {log_level}")
        if log_to_file:
            logger.info(f"Logging to file: {log_file}")
        
        return logger

    @staticmethod
    def get_module_logger(module_name: str) -> logging.Logger:
        """
        Gets a logger instance for a specific module.
        
        Args:
            module_name: Name of the module requesting the logger
            
        Returns:
            logging.Logger: Logger instance for the module
        """
        return logging.getLogger(f'GameServerNotifier.{module_name}') 