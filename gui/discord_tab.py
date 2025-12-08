"""Discord Integration Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QMessageBox, QTextEdit)
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors
)


class DiscordTab(DesignMainWidget):
    
    def __init__(self):
        super().__init__()
        self.header.set_title("Discord Integration")
        self.header.set_subtitle("Send scan results to Discord notifications")
        self.init_ui()
    
    def init_ui(self):
        # Discord Webhook Configuration
        config_section = self.add_section("Discord Webhook")
        
        label1 = QLabel('Webhook URL:')
        label1.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.webhook_input = QLineEdit()
        self.webhook_input.setPlaceholderText('https://discordapp.com/api/webhooks/...')
        self.webhook_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.webhook_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        
        config_section.content_layout.addWidget(label1)
        config_section.content_layout.addWidget(self.webhook_input)
        
        # Message template
        template_label = QLabel('Message Template:')
        template_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.template_input = QTextEdit()
        self.template_input.setPlaceholderText('Customize message template with {variables}')
        self.template_input.setMaximumHeight(120)
        self.template_input.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
            }}
        """)
        self.template_input.setText("Scan Result: {vulnerability_type}\nSeverity: {severity}\nURL: {target}")
        
        config_section.content_layout.addWidget(template_label)
        config_section.content_layout.addWidget(self.template_input)
        
        # Action buttons
        action_section = self.add_section("Actions")
        button_layout = QHBoxLayout()
        
        test_button = DesignButton('Test Webhook', 'primary')
        test_button.clicked.connect(self.test_webhook)
        button_layout.addWidget(test_button)
        
        save_button = DesignButton('Save Configuration', 'primary')
        save_button.clicked.connect(self.save_config)
        button_layout.addWidget(save_button)
        
        clear_button = DesignButton('Clear', 'danger')
        clear_button.clicked.connect(self.clear_config)
        button_layout.addWidget(clear_button)
        
        button_layout.addStretch()
        action_section.content_layout.addLayout(button_layout)
        
        # Info section
        info_section = self.add_section("Information")
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setMaximumHeight(150)
        info_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
            }}
        """)
        info_text.setMarkdown("""
**Available Variables:**
- {target}: Target URL
- {vulnerability_type}: Type of vulnerability
- {severity}: Severity level
- {description}: Detailed description
- {timestamp}: Scan timestamp

**How to get a webhook:**
1. Open Discord server
2. Go to Server Settings → Integrations → Webhooks
3. Create New Webhook
4. Copy the webhook URL
        """)
        info_section.content_layout.addWidget(info_text)
        
        self.add_stretch()
    
    def test_webhook(self):
        webhook_url = self.webhook_input.text().strip()
        if not webhook_url:
            QMessageBox.warning(self, 'Warning', 'Please enter webhook URL')
            return
        
        try:
            import requests
            data = {
                "content": "🧪 Test message from Security Scanning Tool",
                "embeds": [{
                    "title": "Webhook Test",
                    "color": 3447003,
                    "description": "If you see this, your webhook is working!"
                }]
            }
            response = requests.post(webhook_url, json=data)
            if response.status_code == 204:
                QMessageBox.information(self, 'Success', 'Webhook test successful!')
            else:
                QMessageBox.warning(self, 'Error', f'Webhook test failed: {response.status_code}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Failed to test webhook: {str(e)}')
    
    def save_config(self):
        webhook_url = self.webhook_input.text().strip()
        if not webhook_url:
            QMessageBox.warning(self, 'Warning', 'Please enter webhook URL')
            return
        
        # Here you would save the configuration
        QMessageBox.information(self, 'Success', 'Discord configuration saved')
    
    def clear_config(self):
        self.webhook_input.clear()
        self.template_input.clear()
