from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                           QPushButton, QComboBox, QCheckBox, QTextEdit, QGroupBox,
                           QMessageBox, QSpinBox, QDoubleSpinBox)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon, QFont
import requests
import json
from datetime import datetime


class DiscordTab(QWidget):
    """Discord Integration Tab"""
    
    settings_changed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """Initialize Discord tab UI"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Discord Integration")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(14)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Webhook Configuration Group
        webhook_group = QGroupBox("Webhook Configuration")
        webhook_layout = QVBoxLayout()
        
        # Webhook URL
        webhook_url_layout = QHBoxLayout()
        webhook_url_layout.addWidget(QLabel("Discord Webhook URL:"))
        self.webhook_url_input = QLineEdit()
        self.webhook_url_input.setPlaceholderText("https://discord.com/api/webhooks/...")
        self.webhook_url_input.setEchoMode(QLineEdit.EchoMode.Password)
        webhook_url_layout.addWidget(self.webhook_url_input)
        webhook_layout.addLayout(webhook_url_layout)
        
        # Test Connection Button
        test_layout = QHBoxLayout()
        self.test_webhook_btn = QPushButton("Test Connection")
        self.test_webhook_btn.clicked.connect(self.test_discord_webhook)
        test_layout.addWidget(self.test_webhook_btn)
        test_layout.addStretch()
        webhook_layout.addLayout(test_layout)
        
        webhook_group.setLayout(webhook_layout)
        layout.addWidget(webhook_group)
        
        # Logging Configuration Group
        logging_group = QGroupBox("Logging Configuration")
        logging_layout = QVBoxLayout()
        
        # Log Level
        log_level_layout = QHBoxLayout()
        log_level_layout.addWidget(QLabel("Log Level:"))
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
        self.log_level_combo.setCurrentText('INFO')
        log_level_layout.addWidget(self.log_level_combo)
        log_level_layout.addStretch()
        logging_layout.addLayout(log_level_layout)
        
        # Enable Discord Logging
        self.enable_logging_checkbox = QCheckBox("Enable Discord Logging")
        self.enable_logging_checkbox.stateChanged.connect(self.on_logging_toggled)
        logging_layout.addWidget(self.enable_logging_checkbox)
        
        # Log Scans
        self.log_scans_checkbox = QCheckBox("Log Vulnerability Scans")
        logging_layout.addWidget(self.log_scans_checkbox)
        
        # Log Vulnerabilities Found
        self.log_vuln_checkbox = QCheckBox("Log Vulnerabilities Found")
        logging_layout.addWidget(self.log_vuln_checkbox)
        
        # Log Results Summary
        self.log_summary_checkbox = QCheckBox("Log Results Summary")
        logging_layout.addWidget(self.log_summary_checkbox)
        
        logging_group.setLayout(logging_layout)
        layout.addWidget(logging_group)
        
        # Export Configuration Group
        export_group = QGroupBox("Export Configuration")
        export_layout = QVBoxLayout()
        
        # Enable Export
        self.enable_export_checkbox = QCheckBox("Enable Result Export to Discord")
        export_layout.addWidget(self.enable_export_checkbox)
        
        # Export Format
        export_format_layout = QHBoxLayout()
        export_format_layout.addWidget(QLabel("Export Format:"))
        self.export_format_combo = QComboBox()
        self.export_format_combo.addItems(['Embeds', 'Text', 'Code Blocks'])
        export_format_layout.addWidget(self.export_format_combo)
        export_format_layout.addStretch()
        export_layout.addLayout(export_format_layout)
        
        # Export Severity Filter
        severity_layout = QHBoxLayout()
        severity_layout.addWidget(QLabel("Export Severity:"))
        self.severity_filter_combo = QComboBox()
        self.severity_filter_combo.addItems(['All', 'Critical', 'High', 'Medium', 'Low'])
        severity_layout.addWidget(self.severity_filter_combo)
        severity_layout.addStretch()
        export_layout.addLayout(severity_layout)
        
        # Max Results
        max_results_layout = QHBoxLayout()
        max_results_layout.addWidget(QLabel("Max Results to Export:"))
        self.max_results_spinbox = QSpinBox()
        self.max_results_spinbox.setMinimum(1)
        self.max_results_spinbox.setMaximum(100)
        self.max_results_spinbox.setValue(10)
        max_results_layout.addWidget(self.max_results_spinbox)
        max_results_layout.addStretch()
        export_layout.addLayout(max_results_layout)
        
        export_group.setLayout(export_layout)
        layout.addWidget(export_group)
        
        # Notification Settings Group
        notif_group = QGroupBox("Notification Settings")
        notif_layout = QVBoxLayout()
        
        # Notify on Critical
        self.notify_critical_checkbox = QCheckBox("Notify on Critical Vulnerabilities")
        self.notify_critical_checkbox.setChecked(True)
        notif_layout.addWidget(self.notify_critical_checkbox)
        
        # Notify on High
        self.notify_high_checkbox = QCheckBox("Notify on High Vulnerabilities")
        self.notify_high_checkbox.setChecked(True)
        notif_layout.addWidget(self.notify_high_checkbox)
        
        # Notify on Scan Start
        self.notify_scan_start_checkbox = QCheckBox("Notify on Scan Start")
        notif_layout.addWidget(self.notify_scan_start_checkbox)
        
        # Notify on Scan Complete
        self.notify_scan_complete_checkbox = QCheckBox("Notify on Scan Complete")
        self.notify_scan_complete_checkbox.setChecked(True)
        notif_layout.addWidget(self.notify_scan_complete_checkbox)
        
        notif_group.setLayout(notif_layout)
        layout.addWidget(notif_group)
        
        # Advanced Settings Group
        advanced_group = QGroupBox("Advanced Settings")
        advanced_layout = QVBoxLayout()
        
        # Message Batch Size
        batch_layout = QHBoxLayout()
        batch_layout.addWidget(QLabel("Messages per Batch:"))
        self.batch_size_spinbox = QSpinBox()
        self.batch_size_spinbox.setMinimum(1)
        self.batch_size_spinbox.setMaximum(10)
        self.batch_size_spinbox.setValue(5)
        batch_layout.addWidget(self.batch_size_spinbox)
        batch_layout.addStretch()
        advanced_layout.addLayout(batch_layout)
        
        # Embed Size
        embed_size_layout = QHBoxLayout()
        embed_size_layout.addWidget(QLabel("Embed Size:"))
        self.embed_size_combo = QComboBox()
        self.embed_size_combo.addItems(['Very Small', 'Small', 'Medium', 'Large'])
        self.embed_size_combo.setCurrentText('Medium')
        embed_size_layout.addWidget(self.embed_size_combo)
        embed_size_layout.addStretch()
        advanced_layout.addLayout(embed_size_layout)
        
        # Color Theme
        color_layout = QHBoxLayout()
        color_layout.addWidget(QLabel("Color Theme:"))
        self.color_theme_combo = QComboBox()
        self.color_theme_combo.addItems(['Severity-based', 'Monochrome', 'Rainbow'])
        color_layout.addWidget(self.color_theme_combo)
        color_layout.addStretch()
        advanced_layout.addLayout(color_layout)
        
        # Rate Limit
        rate_limit_layout = QHBoxLayout()
        rate_limit_layout.addWidget(QLabel("Rate Limit (seconds):"))
        self.rate_limit_spinbox = QDoubleSpinBox()
        self.rate_limit_spinbox.setMinimum(0.1)
        self.rate_limit_spinbox.setMaximum(10.0)
        self.rate_limit_spinbox.setValue(1.0)
        self.rate_limit_spinbox.setSingleStep(0.1)
        rate_limit_layout.addWidget(self.rate_limit_spinbox)
        rate_limit_layout.addStretch()
        advanced_layout.addLayout(rate_limit_layout)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        # Action Buttons
        button_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("Save Settings")
        self.save_btn.clicked.connect(self.save_settings)
        button_layout.addWidget(self.save_btn)
        
        self.reset_btn = QPushButton("Reset to Defaults")
        self.reset_btn.clicked.connect(self.reset_defaults)
        button_layout.addWidget(self.reset_btn)
        
        layout.addLayout(button_layout)
        
        # Test Log Area
        self.test_log = QTextEdit()
        self.test_log.setReadOnly(True)
        self.test_log.setMaximumHeight(150)
        self.test_log.setPlaceholderText("Test connection logs appear here...")
        layout.addWidget(QLabel("Connection Log:"))
        layout.addWidget(self.test_log)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def test_discord_webhook(self):
        """Test Discord webhook connection"""
        webhook_url = self.webhook_url_input.text().strip()
        
        if not webhook_url:
            QMessageBox.warning(self, "Error", "Please enter a Discord webhook URL")
            return
        
        try:
            # Send test message
            data = {
                'content': 'Test message from MoD Security Scanner',
                'embeds': [{
                    'title': 'Connection Test',
                    'description': 'This is a test message from MoD',
                    'color': 3447003,  # Blue
                    'timestamp': datetime.now().isoformat()
                }]
            }
            
            response = requests.post(webhook_url, json=data, timeout=5)
            
            if response.status_code in [200, 204]:
                self.test_log.append("[✓] Connection successful!")
                self.test_log.append(f"[✓] Webhook URL verified")
                QMessageBox.information(self, "Success", "Discord webhook connection verified!")
            else:
                error_msg = f"Status Code: {response.status_code}"
                self.test_log.append(f"[✗] Connection failed: {error_msg}")
                QMessageBox.warning(self, "Error", f"Connection failed:\n{error_msg}")
        
        except requests.exceptions.Timeout:
            self.test_log.append("[✗] Connection timeout")
            QMessageBox.warning(self, "Error", "Connection timeout. Check your webhook URL.")
        
        except requests.exceptions.RequestException as e:
            self.test_log.append(f"[✗] Request failed: {str(e)}")
            QMessageBox.warning(self, "Error", f"Request failed:\n{str(e)}")
        
        except Exception as e:
            self.test_log.append(f"[✗] Error: {str(e)}")
            QMessageBox.warning(self, "Error", f"Error testing connection:\n{str(e)}")
    
    def on_logging_toggled(self):
        """Handle logging toggle"""
        enabled = self.enable_logging_checkbox.isChecked()
        self.log_level_combo.setEnabled(enabled)
        self.log_scans_checkbox.setEnabled(enabled)
        self.log_vuln_checkbox.setEnabled(enabled)
        self.log_summary_checkbox.setEnabled(enabled)
    
    def save_settings(self):
        """Save Discord settings"""
        settings = {
            'discord_webhook': self.webhook_url_input.text(),
            'discord_log_level': self.log_level_combo.currentText(),
            'discord_logging_enabled': self.enable_logging_checkbox.isChecked(),
            'discord_log_scans': self.log_scans_checkbox.isChecked(),
            'discord_log_vulns': self.log_vuln_checkbox.isChecked(),
            'discord_log_summary': self.log_summary_checkbox.isChecked(),
            'discord_export_enabled': self.enable_export_checkbox.isChecked(),
            'discord_export_format': self.export_format_combo.currentText(),
            'discord_severity_filter': self.severity_filter_combo.currentText(),
            'discord_max_results': self.max_results_spinbox.value(),
            'discord_notify_critical': self.notify_critical_checkbox.isChecked(),
            'discord_notify_high': self.notify_high_checkbox.isChecked(),
            'discord_notify_scan_start': self.notify_scan_start_checkbox.isChecked(),
            'discord_notify_scan_complete': self.notify_scan_complete_checkbox.isChecked(),
            'discord_batch_size': self.batch_size_spinbox.value(),
            'discord_embed_size': self.embed_size_combo.currentText(),
            'discord_color_theme': self.color_theme_combo.currentText(),
            'discord_rate_limit': self.rate_limit_spinbox.value(),
        }
        
        self.settings_changed.emit(settings)
        QMessageBox.information(self, "Success", "Discord settings saved successfully!")
    
    def reset_defaults(self):
        """Reset to default settings"""
        reply = QMessageBox.question(self, "Confirm", 
                                    "Are you sure you want to reset to default settings?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.webhook_url_input.clear()
            self.log_level_combo.setCurrentText('INFO')
            self.enable_logging_checkbox.setChecked(False)
            self.log_scans_checkbox.setChecked(False)
            self.log_vuln_checkbox.setChecked(False)
            self.log_summary_checkbox.setChecked(True)
            self.enable_export_checkbox.setChecked(False)
            self.export_format_combo.setCurrentText('Embeds')
            self.severity_filter_combo.setCurrentText('All')
            self.max_results_spinbox.setValue(10)
            self.notify_critical_checkbox.setChecked(True)
            self.notify_high_checkbox.setChecked(True)
            self.notify_scan_start_checkbox.setChecked(False)
            self.notify_scan_complete_checkbox.setChecked(True)
            self.batch_size_spinbox.setValue(5)
            self.embed_size_combo.setCurrentText('Medium')
            self.color_theme_combo.setCurrentText('Severity-based')
            self.rate_limit_spinbox.setValue(1.0)
            self.test_log.clear()
    
    def load_settings(self):
        """Load settings from config"""
        try:
            from utils.config import Config
            config = Config()
            
            # Load settings if available
            settings = config.get_all_settings()
            
            if 'discord_webhook' in settings:
                self.webhook_url_input.setText(settings.get('discord_webhook', ''))
            
            if 'discord_log_level' in settings:
                self.log_level_combo.setCurrentText(settings.get('discord_log_level', 'INFO'))
            
            if 'discord_logging_enabled' in settings:
                self.enable_logging_checkbox.setChecked(settings.get('discord_logging_enabled', False))
            
            if 'discord_log_scans' in settings:
                self.log_scans_checkbox.setChecked(settings.get('discord_log_scans', False))
            
            if 'discord_log_vulns' in settings:
                self.log_vuln_checkbox.setChecked(settings.get('discord_log_vulns', False))
            
            if 'discord_log_summary' in settings:
                self.log_summary_checkbox.setChecked(settings.get('discord_log_summary', True))
            
            if 'discord_export_enabled' in settings:
                self.enable_export_checkbox.setChecked(settings.get('discord_export_enabled', False))
            
            if 'discord_export_format' in settings:
                self.export_format_combo.setCurrentText(settings.get('discord_export_format', 'Embeds'))
            
            if 'discord_severity_filter' in settings:
                self.severity_filter_combo.setCurrentText(settings.get('discord_severity_filter', 'All'))
            
            if 'discord_max_results' in settings:
                self.max_results_spinbox.setValue(settings.get('discord_max_results', 10))
            
            if 'discord_notify_critical' in settings:
                self.notify_critical_checkbox.setChecked(settings.get('discord_notify_critical', True))
            
            if 'discord_notify_high' in settings:
                self.notify_high_checkbox.setChecked(settings.get('discord_notify_high', True))
            
            if 'discord_notify_scan_start' in settings:
                self.notify_scan_start_checkbox.setChecked(settings.get('discord_notify_scan_start', False))
            
            if 'discord_notify_scan_complete' in settings:
                self.notify_scan_complete_checkbox.setChecked(settings.get('discord_notify_scan_complete', True))
            
            if 'discord_batch_size' in settings:
                self.batch_size_spinbox.setValue(settings.get('discord_batch_size', 5))
            
            if 'discord_embed_size' in settings:
                self.embed_size_combo.setCurrentText(settings.get('discord_embed_size', 'Medium'))
            
            if 'discord_color_theme' in settings:
                self.color_theme_combo.setCurrentText(settings.get('discord_color_theme', 'Severity-based'))
            
            if 'discord_rate_limit' in settings:
                self.rate_limit_spinbox.setValue(settings.get('discord_rate_limit', 1.0))
        
        except Exception as e:
            print(f"Error loading Discord settings: {str(e)}")
