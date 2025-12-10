"""
JS Finder Webhook Dialog for MoD v4.0.0.5
Prompts user for webhook URL on first run
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QCheckBox, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from utils.config import Config


class JSFinderWebhookDialog(QDialog):
    """Dialog for JS Finder webhook configuration"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = Config()
        self.webhook_url = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize dialog UI"""
        self.setWindowTitle("🔎 JavaScript Finder - Webhook Configuration")
        self.setMinimumWidth(500)
        self.setMinimumHeight(250)
        self.setModal(True)
        
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        title = QLabel("🔎 JavaScript Finder Webhook")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Description
        desc = QLabel(
            "JavaScript Finder sends detected JavaScript files to a webhook URL.\n\n"
            "This allows real-time monitoring of:\n"
            "• External JavaScript files\n"
            "• Inline scripts\n"
            "• Event handlers\n"
            "• Sensitive data detection\n"
            "• Framework detection"
        )
        desc.setStyleSheet("color: #888; line-height: 1.5;")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # Webhook URL input
        url_layout = QVBoxLayout()
        url_label = QLabel("Webhook URL (optional):")
        url_label_font = QFont()
        url_label_font.setBold(True)
        url_label.setFont(url_label_font)
        url_layout.addWidget(url_label)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText(
            "https://your-server.com/webhook/js-finder\n"
            "(Leave empty to disable)"
        )
        self.url_input.setMinimumHeight(40)
        url_layout.addWidget(self.url_input)
        
        layout.addLayout(url_layout)
        
        # Enable checkbox
        self.enable_checkbox = QCheckBox("Enable JS Finder Webhook")
        self.enable_checkbox.setChecked(False)
        self.enable_checkbox.stateChanged.connect(self.on_enable_changed)
        layout.addWidget(self.enable_checkbox)
        
        # Info
        info = QLabel(
            "💡 Tip: You can always change or disable this in Settings → JS Finder"
        )
        info.setStyleSheet("color: #666; font-style: italic; font-size: 9pt;")
        layout.addWidget(info)
        
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        skip_btn = QPushButton("⏭️  Skip for Now")
        skip_btn.setMinimumHeight(40)
        skip_btn.setMinimumWidth(120)
        skip_btn.clicked.connect(self.reject)
        button_layout.addWidget(skip_btn)
        
        self.save_btn = QPushButton("[OK] Save Configuration")
        self.save_btn.setMinimumHeight(40)
        self.save_btn.setMinimumWidth(150)
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                font-weight: bold;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            QPushButton:pressed {
                background-color: #229954;
            }
        """)
        self.save_btn.clicked.connect(self.save_configuration)
        self.save_btn.setEnabled(False)
        button_layout.addWidget(self.save_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QLineEdit {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 2px solid #444;
                border-radius: 4px;
                padding: 8px;
            }
            QLineEdit:focus {
                border: 2px solid #2ecc71;
            }
            QCheckBox {
                color: #ffffff;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                background-color: #2d2d2d;
                border: 2px solid #444;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                background-color: #2ecc71;
                border: 2px solid #2ecc71;
            }
        """)
    
    def on_enable_changed(self):
        """Handle enable/disable checkbox change"""
        self.save_btn.setEnabled(self.enable_checkbox.isChecked())
        if self.enable_checkbox.isChecked():
            self.url_input.setFocus()
    
    def save_configuration(self):
        """Save webhook configuration"""
        if not self.enable_checkbox.isChecked():
            self.accept()
            return
        
        webhook_url = self.url_input.text().strip()
        
        if not webhook_url:
            QMessageBox.warning(
                self, 
                "[WARN] Warning",
                "Please enter a webhook URL or uncheck 'Enable JS Finder Webhook'"
            )
            return
        
        if not webhook_url.startswith('http://') and not webhook_url.startswith('https://'):
            webhook_url = 'https://' + webhook_url
        
        # Validate URL
        if not self._validate_url(webhook_url):
            QMessageBox.warning(
                self,
                "[FAIL] Invalid URL",
                "Please enter a valid webhook URL (e.g., https://example.com/webhook)"
            )
            return
        
        # Save to config
        try:
            config_data = self.config.load()
            if 'integration' not in config_data:
                config_data['integration'] = {}
            
            config_data['integration']['js_finder_webhook'] = webhook_url
            self.config.save(config_data)
            
            self.webhook_url = webhook_url
            QMessageBox.information(
                self,
                "[OK] Success",
                f"Webhook URL saved successfully!\n\n{webhook_url}"
            )
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "[FAIL] Error",
                f"Failed to save configuration:\n{str(e)}"
            )
    
    @staticmethod
    def _validate_url(url: str) -> bool:
        """Validate URL format"""
        try:
            from urllib.parse import urlparse
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def prompt_for_webhook(parent=None) -> str:
        """Show webhook dialog and return URL if configured
        
        Args:
            parent: Parent widget
            
        Returns:
            Webhook URL if configured, None otherwise
        """
        dialog = JSFinderWebhookDialog(parent)
        result = dialog.exec()
        return dialog.webhook_url if result == QDialog.DialogCode.Accepted else None
