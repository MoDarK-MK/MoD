from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QLabel, QLineEdit, QSpinBox, QDoubleSpinBox,
                             QCheckBox, QPushButton, QComboBox, QTabWidget,
                             QFormLayout, QHeaderView, QFileDialog)
from PyQt6.QtCore import Qt, pyqtSignal
from utils.config import Config
import json

class AdvancedSettingsTab(QWidget):
    settings_changed = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.config = Config()
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)
        
        settings_tabs = QTabWidget()
        
        self.scan_settings_widget = self._create_scan_settings()
        self.performance_settings_widget = self._create_performance_settings()
        self.security_settings_widget = self._create_security_settings()
        self.integration_settings_widget = self._create_integration_settings()
        self.logging_settings_widget = self._create_logging_settings()
        self.cache_settings_widget = self._create_cache_settings()
        self.compliance_settings_widget = self._create_compliance_settings()
        
        settings_tabs.addTab(self.scan_settings_widget, '🔍 Scan')
        settings_tabs.addTab(self.performance_settings_widget, '⚡ Performance')
        settings_tabs.addTab(self.security_settings_widget, '🔒 Security')
        settings_tabs.addTab(self.integration_settings_widget, '🔄 Integration')
        settings_tabs.addTab(self.logging_settings_widget, '📝 Logging')
        settings_tabs.addTab(self.cache_settings_widget, '💾 Cache')
        settings_tabs.addTab(self.compliance_settings_widget, '📋 Compliance')
        
        main_layout.addWidget(settings_tabs)
        
        button_layout = QHBoxLayout()
        
        self.save_button = QPushButton('💾 Save All Settings')
        self.save_button.clicked.connect(self.save_settings)
        button_layout.addWidget(self.save_button)
        
        self.reset_button = QPushButton('🔄 Reset to Defaults')
        self.reset_button.clicked.connect(self.reset_settings)
        button_layout.addWidget(self.reset_button)
        
        self.export_button = QPushButton('📤 Export Config')
        self.export_button.clicked.connect(self.export_config)
        button_layout.addWidget(self.export_button)
        
        self.import_button = QPushButton('📥 Import Config')
        self.import_button.clicked.connect(self.import_config)
        button_layout.addWidget(self.import_button)
        
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)
    
    def _create_scan_settings(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout()
        
        self.concurrent_scans = QSpinBox()
        self.concurrent_scans.setRange(1, 100)
        self.concurrent_scans.setValue(10)
        layout.addRow('Concurrent Scans:', self.concurrent_scans)
        
        self.scan_timeout = QSpinBox()
        self.scan_timeout.setRange(5, 300)
        self.scan_timeout.setValue(30)
        self.scan_timeout.setSuffix(' seconds')
        layout.addRow('Scan Timeout:', self.scan_timeout)
        
        self.request_delay = QDoubleSpinBox()
        self.request_delay.setRange(0, 10)
        self.request_delay.setValue(0.5)
        self.request_delay.setSuffix(' seconds')
        layout.addRow('Request Delay:', self.request_delay)
        
        self.retry_attempts = QSpinBox()
        self.retry_attempts.setRange(0, 10)
        self.retry_attempts.setValue(3)
        layout.addRow('Retry Attempts:', self.retry_attempts)
        
        self.follow_redirects = QCheckBox('Follow Redirects')
        self.follow_redirects.setChecked(True)
        layout.addRow('', self.follow_redirects)
        
        self.verify_ssl = QCheckBox('Verify SSL Certificate')
        self.verify_ssl.setChecked(False)
        layout.addRow('', self.verify_ssl)
        
        self.allow_cookies = QCheckBox('Allow Cookies')
        self.allow_cookies.setChecked(True)
        layout.addRow('', self.allow_cookies)
        
        widget.setLayout(layout)
        return widget
    
    def _create_performance_settings(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout()
        
        self.max_threads = QSpinBox()
        self.max_threads.setRange(1, 500)
        self.max_threads.setValue(50)
        layout.addRow('Max Thread Pool Size:', self.max_threads)
        
        self.batch_size = QSpinBox()
        self.batch_size.setRange(1, 1000)
        self.batch_size.setValue(100)
        layout.addRow('Batch Size:', self.batch_size)
        
        self.connection_pool_size = QSpinBox()
        self.connection_pool_size.setRange(1, 200)
        self.connection_pool_size.setValue(50)
        layout.addRow('Connection Pool Size:', self.connection_pool_size)
        
        self.memory_limit = QSpinBox()
        self.memory_limit.setRange(100, 8192)
        self.memory_limit.setValue(1024)
        self.memory_limit.setSuffix(' MB')
        layout.addRow('Memory Limit:', self.memory_limit)
        
        self.enable_compression = QCheckBox('Enable Response Compression')
        self.enable_compression.setChecked(True)
        layout.addRow('', self.enable_compression)
        
        self.enable_caching = QCheckBox('Enable Result Caching')
        self.enable_caching.setChecked(True)
        layout.addRow('', self.enable_caching)
        
        self.optimization_level = QComboBox()
        self.optimization_level.addItems(['Low', 'Medium', 'High', 'Maximum'])
        layout.addRow('Optimization Level:', self.optimization_level)
        
        widget.setLayout(layout)
        return widget
    
    def _create_security_settings(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout()
        
        self.user_agent = QLineEdit()
        self.user_agent.setText('Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        layout.addRow('Custom User-Agent:', self.user_agent)
        
        self.enable_proxy = QCheckBox('Enable Proxy')
        self.enable_proxy.setChecked(False)
        layout.addRow('', self.enable_proxy)
        
        self.proxy_url = QLineEdit()
        self.proxy_url.setPlaceholderText('http://proxy.example.com:8080')
        self.proxy_url.setEnabled(False)
        layout.addRow('Proxy URL:', self.proxy_url)
        
        self.enable_proxy.stateChanged.connect(lambda: self.proxy_url.setEnabled(self.enable_proxy.isChecked()))
        
        self.randomize_headers = QCheckBox('Randomize Headers')
        self.randomize_headers.setChecked(True)
        layout.addRow('', self.randomize_headers)
        
        self.waf_bypass = QCheckBox('Enable WAF Bypass Techniques')
        self.waf_bypass.setChecked(False)
        layout.addRow('', self.waf_bypass)
        
        self.rate_limit_bypass = QCheckBox('Intelligent Rate Limit Bypass')
        self.rate_limit_bypass.setChecked(False)
        layout.addRow('', self.rate_limit_bypass)
        
        widget.setLayout(layout)
        return widget
    
    def _create_integration_settings(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout()
        
        self.slack_webhook = QLineEdit()
        self.slack_webhook.setPlaceholderText('https://hooks.slack.com/services/...')
        layout.addRow('Slack Webhook:', self.slack_webhook)
        
        self.teams_webhook = QLineEdit()
        self.teams_webhook.setPlaceholderText('https://outlook.webhook.office.com/...')
        layout.addRow('Teams Webhook:', self.teams_webhook)
        
        self.github_token = QLineEdit()
        self.github_token.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow('GitHub Token:', self.github_token)
        
        self.gitlab_token = QLineEdit()
        self.gitlab_token.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow('GitLab Token:', self.gitlab_token)
        
        self.jira_url = QLineEdit()
        self.jira_url.setPlaceholderText('https://jira.example.com')
        layout.addRow('Jira URL:', self.jira_url)
        
        self.jira_token = QLineEdit()
        self.jira_token.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow('Jira API Token:', self.jira_token)
        
        widget.setLayout(layout)
        return widget
    
    def _create_logging_settings(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout()
        
        self.log_level = QComboBox()
        self.log_level.addItems(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
        self.log_level.setCurrentText('INFO')
        layout.addRow('Log Level:', self.log_level)
        
        self.log_to_file = QCheckBox('Log to File')
        self.log_to_file.setChecked(True)
        layout.addRow('', self.log_to_file)
        
        self.log_to_console = QCheckBox('Log to Console')
        self.log_to_console.setChecked(True)
        layout.addRow('', self.log_to_console)
        
        self.max_log_size = QSpinBox()
        self.max_log_size.setRange(1, 1000)
        self.max_log_size.setValue(100)
        self.max_log_size.setSuffix(' MB')
        layout.addRow('Max Log File Size:', self.max_log_size)
        
        self.log_retention_days = QSpinBox()
        self.log_retention_days.setRange(1, 365)
        self.log_retention_days.setValue(30)
        self.log_retention_days.setSuffix(' days')
        layout.addRow('Log Retention:', self.log_retention_days)
        
        self.verbose_logging = QCheckBox('Verbose Logging')
        self.verbose_logging.setChecked(False)
        layout.addRow('', self.verbose_logging)
        
        widget.setLayout(layout)
        return widget
    
    def _create_cache_settings(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout()
        
        self.cache_ttl = QSpinBox()
        self.cache_ttl.setRange(60, 86400)
        self.cache_ttl.setValue(3600)
        self.cache_ttl.setSuffix(' seconds')
        layout.addRow('Cache TTL:', self.cache_ttl)
        
        self.cache_max_size = QSpinBox()
        self.cache_max_size.setRange(10, 10000)
        self.cache_max_size.setValue(1000)
        layout.addRow('Max Cache Entries:', self.cache_max_size)
        
        self.cache_strategy = QComboBox()
        self.cache_strategy.addItems(['LRU', 'LFU', 'FIFO'])
        layout.addRow('Cache Strategy:', self.cache_strategy)
        
        self.enable_redis = QCheckBox('Enable Redis Caching')
        self.enable_redis.setChecked(False)
        layout.addRow('', self.enable_redis)
        
        self.redis_host = QLineEdit()
        self.redis_host.setText('localhost')
        self.redis_host.setEnabled(False)
        layout.addRow('Redis Host:', self.redis_host)
        
        self.enable_redis.stateChanged.connect(lambda: self.redis_host.setEnabled(self.enable_redis.isChecked()))
        
        widget.setLayout(layout)
        return widget
    
    def _create_compliance_settings(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout()
        
        self.compliance_framework = QComboBox()
        self.compliance_framework.addItems([
            'None',
            'OWASP Top 10',
            'PCI-DSS',
            'HIPAA',
            'ISO27001',
            'GDPR',
            'SOC 2',
            'CIS'
        ])
        layout.addRow('Compliance Framework:', self.compliance_framework)
        
        self.generate_compliance_report = QCheckBox('Auto Generate Compliance Report')
        self.generate_compliance_report.setChecked(True)
        layout.addRow('', self.generate_compliance_report)
        
        self.include_remediation = QCheckBox('Include Remediation Steps')
        self.include_remediation.setChecked(True)
        layout.addRow('', self.include_remediation)
        
        self.severity_threshold = QComboBox()
        self.severity_threshold.addItems(['Critical', 'High', 'Medium', 'Low', 'Info'])
        layout.addRow('Minimum Severity:', self.severity_threshold)
        
        self.data_retention_days = QSpinBox()
        self.data_retention_days.setRange(7, 2555)
        self.data_retention_days.setValue(365)
        self.data_retention_days.setSuffix(' days')
        layout.addRow('Data Retention:', self.data_retention_days)
        
        widget.setLayout(layout)
        return widget
    
    def save_settings(self):
        settings = {
            'scan': {
                'concurrent_scans': self.concurrent_scans.value(),
                'timeout': self.scan_timeout.value(),
                'request_delay': self.request_delay.value(),
                'retry_attempts': self.retry_attempts.value(),
                'follow_redirects': self.follow_redirects.isChecked(),
                'verify_ssl': self.verify_ssl.isChecked(),
                'allow_cookies': self.allow_cookies.isChecked()
            },
            'performance': {
                'max_threads': self.max_threads.value(),
                'batch_size': self.batch_size.value(),
                'connection_pool_size': self.connection_pool_size.value(),
                'memory_limit': self.memory_limit.value(),
                'compression': self.enable_compression.isChecked(),
                'caching': self.enable_caching.isChecked(),
                'optimization_level': self.optimization_level.currentText()
            },
            'security': {
                'user_agent': self.user_agent.text(),
                'proxy_enabled': self.enable_proxy.isChecked(),
                'proxy_url': self.proxy_url.text(),
                'randomize_headers': self.randomize_headers.isChecked(),
                'waf_bypass': self.waf_bypass.isChecked(),
                'rate_limit_bypass': self.rate_limit_bypass.isChecked()
            },
            'integration': {
                'slack_webhook': self.slack_webhook.text(),
                'teams_webhook': self.teams_webhook.text(),
                'github_token': self.github_token.text(),
                'gitlab_token': self.gitlab_token.text(),
                'jira_url': self.jira_url.text(),
                'jira_token': self.jira_token.text()
            },
            'logging': {
                'log_level': self.log_level.currentText(),
                'log_to_file': self.log_to_file.isChecked(),
                'log_to_console': self.log_to_console.isChecked(),
                'max_log_size': self.max_log_size.value(),
                'retention_days': self.log_retention_days.value(),
                'verbose': self.verbose_logging.isChecked()
            },
            'cache': {
                'ttl': self.cache_ttl.value(),
                'max_size': self.cache_max_size.value(),
                'strategy': self.cache_strategy.currentText(),
                'redis_enabled': self.enable_redis.isChecked(),
                'redis_host': self.redis_host.text()
            },
            'compliance': {
                'framework': self.compliance_framework.currentText(),
                'auto_report': self.generate_compliance_report.isChecked(),
                'remediation': self.include_remediation.isChecked(),
                'severity_threshold': self.severity_threshold.currentText(),
                'data_retention': self.data_retention_days.value()
            }
        }
        
        self.config.save(settings)
        self.settings_changed.emit(settings)
    
    def load_settings(self):
        settings = self.config.load()
        
        if 'scan' in settings:
            scan = settings['scan']
            self.concurrent_scans.setValue(scan.get('concurrent_scans', 10))
            self.scan_timeout.setValue(scan.get('timeout', 30))
            self.request_delay.setValue(scan.get('request_delay', 0.5))
            self.retry_attempts.setValue(scan.get('retry_attempts', 3))
            self.follow_redirects.setChecked(scan.get('follow_redirects', True))
            self.verify_ssl.setChecked(scan.get('verify_ssl', False))
            self.allow_cookies.setChecked(scan.get('allow_cookies', True))
    
    def reset_settings(self):
        self.config.reset()
        self.load_settings()
    
    def export_config(self):
        filename, _ = QFileDialog.getSaveFileName(
            self,
            'Export Configuration',
            'mod_config.json',
            'JSON Files (*.json)'
        )
        
        if filename:
            settings = self.config.load()
            with open(filename, 'w') as f:
                json.dump(settings, f, indent=4)
    
    def import_config(self):
        filename, _ = QFileDialog.getOpenFileName(
            self,
            'Import Configuration',
            '',
            'JSON Files (*.json)'
        )
        
        if filename:
            with open(filename, 'r') as f:
                settings = json.load(f)
            self.config.save(settings)
            self.load_settings()