"""
Configuration management for MoD Security Scanner v4.0.0.2
Handles application settings with validation and defaults.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger('MoD.config')


class Config:
    """Application configuration with validation and defaults."""
    
    VERSION = "4.0.0.2"
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration with defaults.
        
        Args:
            config_path: Optional custom configuration directory path.
        """
        self.config_dir = config_path or (Path.home() / '.mod')
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_dir / 'config.json'
        
        self.default_config: Dict[str, Any] = {
            'theme': 'dark',
            'max_threads': 10,
            'timeout': 10,
            'verify_ssl': False,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'scan': {
                'concurrent_scans': 10,
                'timeout': 30,
                'request_delay': 0.5,
                'retry_attempts': 3,
                'follow_redirects': True,
                'verify_ssl': False,
                'allow_cookies': True
            },
            'performance': {
                'max_threads': 50,
                'batch_size': 100,
                'connection_pool_size': 50,
                'memory_limit': 1024,
                'compression': True,
                'caching': True,
                'optimization_level': 'High'
            },
            'security': {
                'user_agent': 'Mozilla/5.0',
                'proxy_enabled': False,
                'proxy_url': '',
                'randomize_headers': True,
                'waf_bypass': False,
                'rate_limit_bypass': False
            },
            'integration': {
                'slack_webhook': '',
                'teams_webhook': '',
                'github_token': '',
                'gitlab_token': '',
                'jira_url': '',
                'jira_token': ''
            },
            'logging': {
                'log_level': 'INFO',
                'log_to_file': True,
                'log_to_console': True,
                'max_log_size': 100,
                'retention_days': 30,
                'verbose': False
            },
            'cache': {
                'ttl': 3600,
                'max_size': 1000,
                'strategy': 'LRU',
                'redis_enabled': False,
                'redis_host': 'localhost'
            },
            'compliance': {
                'framework': 'OWASP Top 10',
                'auto_report': True,
                'remediation': True,
                'severity_threshold': 'Medium',
                'data_retention': 365
            },
            'updates': {
                'check_on_startup': True,
                'check_frequency_days': 7,
                'last_check_date': None,
                'auto_download': False,
                'notify_on_update': True
            }
        }
    
    def _validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize configuration values.
        
        Args:
            config: Configuration dictionary to validate.
            
        Returns:
            Validated configuration.
            
        Raises:
            ValueError: If critical validation fails.
        """
        try:
            if not isinstance(config, dict):
                logger.warning("Config is not a dict, using defaults")
                return self.default_config.copy()
            if 'max_threads' in config:
                max_threads = config.get('max_threads', 10)
                if not isinstance(max_threads, int) or max_threads < 1 or max_threads > 1000:
                    logger.warning(f"Invalid max_threads {max_threads}, using default 10")
                    config['max_threads'] = 10
            
            if 'timeout' in config:
                timeout = config.get('timeout', 10)
                if not isinstance(timeout, (int, float)) or timeout < 1 or timeout > 300:
                    logger.warning(f"Invalid timeout {timeout}, using default 10")
                    config['timeout'] = 10
            
            if 'scan' in config:
                scan_cfg = config['scan']
                concurrent = scan_cfg.get('concurrent_scans', 10)
                if not isinstance(concurrent, int) or concurrent < 1 or concurrent > 500:
                    scan_cfg['concurrent_scans'] = 10
                    
                scan_timeout = scan_cfg.get('timeout', 30)
                if not isinstance(scan_timeout, (int, float)) or scan_timeout < 1 or scan_timeout > 300:
                    scan_cfg['timeout'] = 30
                    
                delay = scan_cfg.get('request_delay', 0.5)
                if not isinstance(delay, (int, float)) or delay < 0 or delay > 10:
                    scan_cfg['request_delay'] = 0.5
            
            if 'performance' in config:
                perf_cfg = config['performance']
                pool_size = perf_cfg.get('connection_pool_size', 50)
                if not isinstance(pool_size, int) or pool_size < 1 or pool_size > 500:
                    perf_cfg['connection_pool_size'] = 50
                    
                batch = perf_cfg.get('batch_size', 100)
                if not isinstance(batch, int) or batch < 1 or batch > 10000:
                    perf_cfg['batch_size'] = 100
            
            if 'cache' in config:
                cache_cfg = config['cache']
                ttl = cache_cfg.get('ttl', 3600)
                if not isinstance(ttl, int) or ttl < 60 or ttl > 86400:
                    cache_cfg['ttl'] = 3600
                    
                max_size = cache_cfg.get('max_size', 1000)
                if not isinstance(max_size, int) or max_size < 10 or max_size > 100000:
                    cache_cfg['max_size'] = 1000
            
            logger.debug("Configuration validation passed")
            return config
        
        except Exception as e:
            logger.exception(f"Error validating config: {e}")
            return self.default_config.copy()
    
    def load(self) -> Dict[str, Any]:
        """Load configuration from file or return defaults.
        
        Returns:
            Configuration dictionary.
        """
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    if not isinstance(config, dict):
                        logger.error("Config file did not contain a JSON object; using defaults")
                        return self.default_config.copy()
                    return self._validate_config(config)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in config file: {e}")
                return self.default_config.copy()
            except Exception as e:
                logger.exception(f"Error loading config: {e}")
                return self.default_config.copy()
        return self.default_config.copy()
    
    def save(self, config: Dict[str, Any]) -> None:
        """Save configuration to file.
        
        Args:
            config: Configuration dictionary to save.
        """
        try:
            validated = self._validate_config(config)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(validated, f, indent=4)
            logger.debug("Configuration saved successfully")
        except Exception as e:
            logger.exception(f"Error saving config: {e}")
    
    def reset(self) -> None:
        """Reset configuration to defaults."""
        try:
            self.save(self.default_config.copy())
            logger.info("Configuration reset to defaults")
        except Exception as e:
            logger.exception(f"Error resetting config: {e}")