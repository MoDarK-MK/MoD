import json
from pathlib import Path
from typing import Dict

class Config:
    def __init__(self):
        self.config_dir = Path.home() / '.mod'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_dir / 'config.json'
        
        self.default_config = {
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
            }
        }
    
    def load(self) -> Dict:
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return self.default_config.copy()
        return self.default_config.copy()
    
    def save(self, config: Dict):
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=4)
    
    def reset(self):
        self.save(self.default_config)