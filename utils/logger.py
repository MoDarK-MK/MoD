import logging
import requests
from datetime import datetime
from pathlib import Path
from typing import Set, Optional
from queue import Queue
import threading

class DiscordHandler(logging.Handler):
    """Custom logging handler that sends logs to Discord webhook"""
    
    def __init__(self, webhook_url: str, queue_size: int = 100):
        super().__init__()
        self.webhook_url = webhook_url
        self.queue = Queue(maxsize=queue_size)
        self.is_running = True
        
        # Start background thread for sending logs
        self.thread = threading.Thread(target=self._process_logs, daemon=True)
        self.thread.start()
    
    def emit(self, record: logging.LogRecord):
        """Send log record to Discord"""
        try:
            if not self.webhook_url:
                return
            
            # Don't queue if queue is full
            if self.queue.full():
                return
            
            self.queue.put(record, block=False)
        except Exception:
            pass
    
    def _process_logs(self):
        """Process logs from queue in background thread"""
        while self.is_running:
            try:
                record = self.queue.get(timeout=1)
                self._send_to_discord(record)
            except:
                pass
    
    def _send_to_discord(self, record: logging.LogRecord):
        """Send log to Discord webhook with formatting"""
        try:
            level_colors = {
                'DEBUG': 0x808080,      # Gray
                'INFO': 0x0099ff,       # Blue
                'WARNING': 0xffff00,    # Yellow
                'ERROR': 0xff6600,      # Orange
                'CRITICAL': 0xff0000   # Red
            }
            
            color = level_colors.get(record.levelname, 0x0099ff)
            
            # Format message (truncate if too long for Discord)
            message = self.format(record)
            if len(message) > 1900:
                message = message[:1897] + '...'
            
            embed = {
                'title': f'🔔 {record.levelname}',
                'description': message,
                'color': color,
                'timestamp': datetime.utcnow().isoformat(),
                'fields': [
                    {
                        'name': 'Logger',
                        'value': record.name,
                        'inline': True
                    },
                    {
                        'name': 'Module',
                        'value': record.module if record.module else 'N/A',
                        'inline': True
                    }
                ]
            }
            
            payload = {'embeds': [embed]}
            
            requests.post(self.webhook_url, json=payload, timeout=5)
        except Exception:
            pass
    
    def close(self):
        """Close handler and stop background thread"""
        self.is_running = False
        if self.thread.is_alive():
            self.thread.join(timeout=2)
        super().close()


class Logger:
    """Centralized logging with file, console, and Discord webhook handlers. Prevents duplicate handlers."""
    
    _initialized_loggers: Set[str] = set()
    _discord_handlers: dict = {}
    
    def __init__(self, name: str = 'MoD', discord_webhook: str = None):
        """Initialize logger with idempotency check to prevent duplicate handlers.
        
        Args:
            name: Logger name (default: 'MoD').
            discord_webhook: Optional Discord webhook URL for live logging.
        """
        self.logger = logging.getLogger(name)
        self.discord_webhook = discord_webhook
        
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
        
        # Add Discord handler if webhook is provided
        if discord_webhook:
            self.enable_discord_logging(discord_webhook)
    
    def enable_discord_logging(self, webhook_url: str, min_level: str = 'INFO'):
        """Enable Discord webhook logging
        
        Args:
            webhook_url: Discord webhook URL
            min_level: Minimum log level to send to Discord (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        if not webhook_url:
            return False
        
        try:
            # Check if we already have a handler for this webhook
            if webhook_url in Logger._discord_handlers:
                return True
            
            discord_handler = DiscordHandler(webhook_url)
            
            # Set log level
            level_map = {
                'DEBUG': logging.DEBUG,
                'INFO': logging.INFO,
                'WARNING': logging.WARNING,
                'ERROR': logging.ERROR,
                'CRITICAL': logging.CRITICAL
            }
            discord_handler.setLevel(level_map.get(min_level, logging.INFO))
            
            formatter = logging.Formatter('%(message)s')
            discord_handler.setFormatter(formatter)
            
            self.logger.addHandler(discord_handler)
            Logger._discord_handlers[webhook_url] = discord_handler
            
            return True
        except Exception:
            return False
    
    def disable_discord_logging(self, webhook_url: str = None):
        """Disable Discord webhook logging
        
        Args:
            webhook_url: Optional specific webhook to disable. If None, disables all.
        """
        if webhook_url:
            if webhook_url in Logger._discord_handlers:
                handler = Logger._discord_handlers[webhook_url]
                self.logger.removeHandler(handler)
                handler.close()
                del Logger._discord_handlers[webhook_url]
                return True
        else:
            # Disable all Discord handlers
            for webhook_url in list(Logger._discord_handlers.keys()):
                self.disable_discord_logging(webhook_url)
            return True
        
        return False
    
    def get_active_webhooks(self) -> list:
        """Get list of active Discord webhooks"""
        return list(Logger._discord_handlers.keys())
    
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