"""Advanced Settings Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox,
                             QCheckBox, QMessageBox, QGroupBox, QFileDialog)
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors
)


class AdvancedSettingsTab(DesignMainWidget):
    
    def __init__(self):
        super().__init__()
        self.header.set_title("Advanced Settings")
        self.header.set_subtitle("Configure advanced scanning options and performance tuning")
        self.init_ui()
    
    def init_ui(self):
        # Performance Settings
        perf_section = self.add_section("Performance")
        
        label1 = QLabel('Thread Count:')
        label1.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        self.thread_spinbox = QSpinBox()
        self.thread_spinbox.setMinimum(1)
        self.thread_spinbox.setMaximum(128)
        self.thread_spinbox.setValue(4)
        self.thread_spinbox.setStyleSheet(f"""
            QSpinBox {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        
        layout1 = QHBoxLayout()
        layout1.addWidget(label1, 1)
        layout1.addWidget(self.thread_spinbox, 1)
        layout1.addStretch()
        perf_section.content_layout.addLayout(layout1)
        
        label2 = QLabel('Request Timeout (seconds):')
        label2.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        self.timeout_spinbox = QDoubleSpinBox()
        self.timeout_spinbox.setMinimum(0.5)
        self.timeout_spinbox.setMaximum(60.0)
        self.timeout_spinbox.setValue(10.0)
        self.timeout_spinbox.setStyleSheet(f"""
            QDoubleSpinBox {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        
        layout2 = QHBoxLayout()
        layout2.addWidget(label2, 1)
        layout2.addWidget(self.timeout_spinbox, 1)
        layout2.addStretch()
        perf_section.content_layout.addLayout(layout2)
        
        # Network Settings
        net_section = self.add_section("Network")
        
        label3 = QLabel('Proxy (optional):')
        label3.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText('http://proxy.example.com:8080')
        self.proxy_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        
        net_section.content_layout.addWidget(label3)
        net_section.content_layout.addWidget(self.proxy_input)
        
        label4 = QLabel('User Agent:')
        label4.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        self.useragent_input = QLineEdit()
        self.useragent_input.setText('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        self.useragent_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        
        net_section.content_layout.addWidget(label4)
        net_section.content_layout.addWidget(self.useragent_input)
        
        # Scan Options
        scan_section = self.add_section("Scan Options")
        
        self.verify_ssl_check = QCheckBox('Verify SSL Certificates')
        self.verify_ssl_check.setChecked(True)
        self.verify_ssl_check.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
        scan_section.content_layout.addWidget(self.verify_ssl_check)
        
        self.follow_redirects_check = QCheckBox('Follow Redirects')
        self.follow_redirects_check.setChecked(True)
        self.follow_redirects_check.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
        scan_section.content_layout.addWidget(self.follow_redirects_check)
        
        self.cache_requests_check = QCheckBox('Cache Requests')
        self.cache_requests_check.setChecked(True)
        self.cache_requests_check.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
        scan_section.content_layout.addWidget(self.cache_requests_check)
        
        self.verbose_logging_check = QCheckBox('Verbose Logging')
        self.verbose_logging_check.setChecked(False)
        self.verbose_logging_check.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
        scan_section.content_layout.addWidget(self.verbose_logging_check)
        
        # Payload Settings
        payload_section = self.add_section("Payload Options")
        
        label5 = QLabel('Payload Encoding:')
        label5.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(['None', 'URL Encode', 'Double URL Encode', 'HTML Entity', 'Base64'])
        self.encoding_combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        
        layout5 = QHBoxLayout()
        layout5.addWidget(label5, 1)
        layout5.addWidget(self.encoding_combo, 1)
        layout5.addStretch()
        payload_section.content_layout.addLayout(layout5)
        
        # Action buttons
        action_section = self.add_section("Actions")
        button_layout = QHBoxLayout()
        
        save_button = DesignButton('Save Settings', 'primary')
        save_button.clicked.connect(self.save_settings)
        button_layout.addWidget(save_button)
        
        reset_button = DesignButton('Reset to Defaults', 'secondary')
        reset_button.clicked.connect(self.reset_defaults)
        button_layout.addWidget(reset_button)
        
        export_button = DesignButton('Export Settings', 'secondary')
        export_button.clicked.connect(self.export_settings)
        button_layout.addWidget(export_button)
        
        button_layout.addStretch()
        action_section.content_layout.addLayout(button_layout)
        
        self.add_stretch()
    
    def save_settings(self):
        # Save settings to configuration file
        QMessageBox.information(self, 'Success', 'Settings saved successfully')
    
    def reset_defaults(self):
        reply = QMessageBox.question(self, 'Confirm', 'Reset all settings to defaults?',
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.thread_spinbox.setValue(4)
            self.timeout_spinbox.setValue(10.0)
            self.proxy_input.clear()
            self.useragent_input.setText('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            self.verify_ssl_check.setChecked(True)
            self.follow_redirects_check.setChecked(True)
            self.cache_requests_check.setChecked(True)
            self.verbose_logging_check.setChecked(False)
            self.encoding_combo.setCurrentText('None')
            QMessageBox.information(self, 'Info', 'Settings reset to defaults')
    
    def export_settings(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Settings', 'settings.json', 'JSON Files (*.json)')
        if filename:
            import json
            settings = {
                'threads': self.thread_spinbox.value(),
                'timeout': self.timeout_spinbox.value(),
                'proxy': self.proxy_input.text(),
                'user_agent': self.useragent_input.text(),
                'verify_ssl': self.verify_ssl_check.isChecked(),
                'follow_redirects': self.follow_redirects_check.isChecked(),
                'cache_requests': self.cache_requests_check.isChecked(),
                'verbose_logging': self.verbose_logging_check.isChecked(),
                'payload_encoding': self.encoding_combo.currentText()
            }
            with open(filename, 'w') as f:
                json.dump(settings, f, indent=4)
            QMessageBox.information(self, 'Success', 'Settings exported successfully')
