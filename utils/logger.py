import logging
from datetime import datetime
from pathlib import Path

class Logger:
    """Centralized logging with file and console handlers. Prevents duplicate handlers."""
    
    _initialized_loggers = set()
    
    def __init__(self, name: str = 'MoD'):
        """Initialize logger with idempotency check to prevent duplicate handlers.
        
        Args:
            name: Logger name (default: 'MoD').
        """
        self.logger = logging.getLogger(name)
        
        # Prevent duplicate handlers for same logger (memory leak fix)
        if name not in Logger._initialized_loggers:
            self.logger.setLevel(logging.DEBUG)
            self.logger.propagate = False
            
            log_dir = Path.home() / '.mod' / 'logs'
            log_dir.mkdir(parents=True, exist_ok=True)
            
            log_file = log_dir / f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
            Logger._initialized_loggers.add(name)
    
    def debug(self, message: str) -> None:
        """Log debug message.
        
        Args:
            message: Debug message.
        """
        self.logger.debug(message)
    
    def info(self, message: str) -> None:
        """Log info message.
        
        Args:
            message: Info message.
        """
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """Log warning message.
        
        Args:
            message: Warning message.
        """
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log error message.
        
        Args:
            message: Error message.
        """
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """Log critical message.
        
        Args:
            message: Critical message.
        """
        self.logger.critical(message)