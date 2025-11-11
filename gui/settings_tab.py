# gui/settings_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QGroupBox, QComboBox, QCheckBox, QTextEdit,
                             QMessageBox, QTabWidget)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont


class SettingsTab(QWidget):
    theme_changed = pyqtSignal(str)
    settings_changed = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        title = QLabel('APPLICATION SETTINGS')
        title.setStyleSheet("""
            QLabel {
                font-size: 20pt;
                font-weight: bold;
                color: #58a6ff;
            }
        """)
        main_layout.addWidget(title)
        
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #30363d;
                background: #0d1117;
                border-radius: 6px;
            }
            QTabBar::tab {
                background: #161b22;
                color: #8b949e;
                padding: 10px 20px;
                margin-right: 2px;
                border: 1px solid #30363d;
                border-bottom: 2px solid transparent;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background: #21262d;
                color: #c9d1d9;
            }
            QTabBar::tab:selected {
                background: #0d1117;
                color: #58a6ff;
                border-bottom: 2px solid #1f6feb;
            }
        """)
        
        tabs.addTab(self.create_ai_settings_tab(), 'AI INTEGRATION')
        tabs.addTab(self.create_scanner_settings_tab(), 'SCANNER CONFIG')
        tabs.addTab(self.create_general_settings_tab(), 'GENERAL')
        
        main_layout.addWidget(tabs, 1)
        
        self.setLayout(main_layout)
    
    def create_ai_settings_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        ai_group = QGroupBox('AI MODEL CONFIGURATION')
        ai_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        ai_layout = QVBoxLayout()
        
        provider_layout = QHBoxLayout()
        provider_label = QLabel('AI PROVIDER:')
        provider_label.setStyleSheet('color: #c9d1d9; font-weight: bold; min-width: 150px;')
        provider_layout.addWidget(provider_label)
        
        self.ai_provider_combo = QComboBox()
        self.ai_provider_combo.addItems(['None', 'OpenAI', 'Anthropic', 'Google Gemini'])
        self.ai_provider_combo.setMinimumHeight(36)
        self.ai_provider_combo.setStyleSheet("""
            QComboBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 6px 10px;
                font-weight: bold;
            }
            QComboBox:hover {
                border: 2px solid #1f6feb;
            }
        """)
        self.ai_provider_combo.currentTextChanged.connect(self.on_provider_changed)
        provider_layout.addWidget(self.ai_provider_combo, 1)
        ai_layout.addLayout(provider_layout)
        
        api_key_layout = QHBoxLayout()
        api_key_label = QLabel('API KEY:')
        api_key_label.setStyleSheet('color: #c9d1d9; font-weight: bold; min-width: 150px;')
        api_key_layout.addWidget(api_key_label)
        
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText('Enter your API key here...')
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setMinimumHeight(36)
        self.api_key_input.setStyleSheet("""
            QLineEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 8px 12px;
                font-size: 11pt;
            }
            QLineEdit:focus {
                border: 2px solid #1f6feb;
            }
        """)
        api_key_layout.addWidget(self.api_key_input, 1)
        ai_layout.addLayout(api_key_layout)
        
        test_layout = QHBoxLayout()
        test_layout.addStretch()
        
        test_btn = QPushButton('TEST CONNECTION')
        test_btn.setMinimumHeight(36)
        test_btn.setMinimumWidth(150)
        test_btn.clicked.connect(self.test_ai_connection)
        test_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #0969da, stop:1 #0757b8);
                color: white;
                border: 2px solid #1f6feb;
                border-radius: 6px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #1f6feb, stop:1 #0969da);
            }
        """)
        test_layout.addWidget(test_btn)
        
        ai_layout.addLayout(test_layout)
        
        ai_group.setLayout(ai_layout)
        layout.addWidget(ai_group)
        
        info_group = QGroupBox('SUPPORTED AI PROVIDERS')
        info_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        info_layout = QVBoxLayout()
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-size: 10pt;
            }
        """)
        
        info_content = """
OpenAI (GPT-4):
  • Model: gpt-4
  • Website: https://openai.com/api/
  • Get Key: https://platform.openai.com/api-keys

Anthropic (Claude):
  • Model: claude-3-opus-20240229
  • Website: https://www.anthropic.com/
  • Get Key: https://console.anthropic.com/

Google Gemini:
  • Model: gemini-pro
  • Website: https://ai.google.dev/
  • Get Key: https://makersuite.google.com/app/apikey

Note: POC generation and advanced verification requires a valid AI API key.
Without API key, smart verification and basic POC templates will be used.
        """
        
        info_text.setText(info_content)
        info_layout.addWidget(info_text)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        layout.addStretch()
        return widget
    
    def create_scanner_settings_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        scan_group = QGroupBox('SCANNER VERIFICATION SETTINGS')
        scan_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        scan_layout = QVBoxLayout()
        
        verify_check = QCheckBox('Enable Real Vulnerability Verification')
        verify_check.setChecked(True)
        verify_check.setStyleSheet("""
            QCheckBox {
                color: #c9d1d9;
                font-weight: bold;
                font-size: 11pt;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:checked {
                background: #238636;
                border: 2px solid #2ea043;
            }
        """)
        self.verify_check = verify_check
        scan_layout.addWidget(verify_check)
        
        info_label = QLabel('When enabled, the scanner will verify each detected CVE by testing actual parameters and payloads.')
        info_label.setStyleSheet('color: #8b949e; font-size: 10pt; margin-left: 20px;')
        info_label.setWordWrap(True)
        scan_layout.addWidget(info_label)
        
        scan_layout.addSpacing(20)
        
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel('Verification Timeout (seconds):')
        timeout_label.setStyleSheet('color: #c9d1d9; font-weight: bold; min-width: 200px;')
        timeout_layout.addWidget(timeout_label)
        
        self.timeout_spin = QLineEdit('10')
        self.timeout_spin.setMaximumWidth(100)
        self.timeout_spin.setMinimumHeight(36)
        self.timeout_spin.setStyleSheet("""
            QLineEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 6px 10px;
                font-weight: bold;
            }
        """)
        timeout_layout.addWidget(self.timeout_spin)
        timeout_layout.addStretch()
        scan_layout.addLayout(timeout_layout)
        
        retries_layout = QHBoxLayout()
        retries_label = QLabel('Verification Retries:')
        retries_label.setStyleSheet('color: #c9d1d9; font-weight: bold; min-width: 200px;')
        retries_layout.addWidget(retries_label)
        
        self.retries_spin = QLineEdit('3')
        self.retries_spin.setMaximumWidth(100)
        self.retries_spin.setMinimumHeight(36)
        self.retries_spin.setStyleSheet("""
            QLineEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 6px 10px;
                font-weight: bold;
            }
        """)
        retries_layout.addWidget(self.retries_spin)
        retries_layout.addStretch()
        scan_layout.addLayout(retries_layout)
        
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)
        
        verify_group = QGroupBox('VERIFICATION METHODS')
        verify_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        verify_layout = QVBoxLayout()
        
        methods_info = QTextEdit()
        methods_info.setReadOnly(True)
        methods_info.setMaximumHeight(200)
        methods_info.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #2ea043;
                border: 1px solid #238636;
                border-radius: 4px;
                padding: 10px;
                font-size: 9pt;
                font-family: 'Courier New';
            }
        """)
        
        methods_text = """VERIFICATION METHODS USED:

✓ PAYLOAD_RESPONSE: Tests if payload response contains expected indicators
✓ TIME_BASED: Measures response delay to confirm time-based vulnerabilities
✓ ERROR_BASED: Detects SQL/XML errors in response
✓ RESPONSE_DIFF: Analyzes response size and content differences
✓ METADATA_ACCESS: Attempts to access cloud metadata endpoints
✓ EXPRESSION_EVAL: Tests expression evaluation in templates
✓ FILE_DISCLOSURE: Attempts to read sensitive files
✓ DEBUG_DETECTION: Identifies debug mode and sensitive information
        """
        
        methods_info.setText(methods_text)
        verify_layout.addWidget(methods_info)
        
        verify_group.setLayout(verify_layout)
        layout.addWidget(verify_group)
        
        layout.addStretch()
        return widget
    
    def create_general_settings_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        theme_group = QGroupBox('APPLICATION THEME')
        theme_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        theme_layout = QVBoxLayout()
        
        dark_check = QCheckBox('Dark Theme (Default)')
        dark_check.setChecked(True)
        dark_check.setEnabled(False)
        dark_check.setStyleSheet("""
            QCheckBox {
                color: #c9d1d9;
                font-weight: bold;
                font-size: 11pt;
                spacing: 8px;
            }
        """)
        theme_layout.addWidget(dark_check)
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        save_layout = QHBoxLayout()
        save_layout.addStretch()
        
        save_btn = QPushButton('SAVE SETTINGS')
        save_btn.setMinimumHeight(40)
        save_btn.setMinimumWidth(150)
        save_btn.clicked.connect(self.save_settings)
        save_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #238636, stop:1 #1a6b2c);
                color: white;
                border: 2px solid #2ea043;
                border-radius: 6px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #2ea043, stop:1 #238636);
            }
        """)
        save_layout.addWidget(save_btn)
        
        layout.addStretch()
        layout.addLayout(save_layout)
        
        return widget
    
    def on_provider_changed(self, provider: str):
        if provider == 'None':
            self.api_key_input.setEnabled(False)
        else:
            self.api_key_input.setEnabled(True)
    
    def test_ai_connection(self):
        provider = self.ai_provider_combo.currentText()
        api_key = self.api_key_input.text().strip()
        
        if provider == 'None':
            QMessageBox.warning(self, 'No Provider', 'Please select an AI provider')
            return
        
        if not api_key:
            QMessageBox.warning(self, 'Missing API Key', 'Please enter your API key')
            return
        
        QMessageBox.information(self, 'Connection Test', f'Testing connection to {provider}...\nThis feature requires active API configuration.')
    
    def save_settings(self):
        settings = {
            'ai_provider': self.ai_provider_combo.currentText(),
            'api_key': self.api_key_input.text(),
            'verify_vulnerabilities': self.verify_check.isChecked(),
            'verification_timeout': int(self.timeout_spin.text() or 10),
            'verification_retries': int(self.retries_spin.text() or 3)
        }
        
        self.settings_changed.emit(settings)
        QMessageBox.information(self, 'Success', 'Settings saved successfully!')
