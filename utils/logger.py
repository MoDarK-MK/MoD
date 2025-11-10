import logging
from datetime import datetime
from pathlib import Path

class Logger:
    def __init__(self, name: str = 'MoD'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
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
    
    def debug(self, message: str):
        self.logger.debug(message)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)