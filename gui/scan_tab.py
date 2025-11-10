from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QCheckBox, QGroupBox,
                             QFormLayout, QSpinBox, QDoubleSpinBox, QProgressBar,
                             QComboBox, QTextEdit)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from core.scanner_engine import ScannerEngine
from core.auth_manager import AuthManager
from utils.logger import Logger

class ScanTab(QWidget):
    scan_started = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    vulnerability_found = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.scanner_engine = ScannerEngine()
        self.auth_manager = AuthManager()
        self.logger = Logger()
        self.is_scanning = False
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)
        
        target_group = QGroupBox('Target Configuration')
        target_layout = QFormLayout()
        
        self.target_url_input = QLineEdit()
        self.target_url_input.setPlaceholderText('Enter target URL (e.g., https://example.com/page?id=1)')
        target_layout.addRow('Target URL:', self.target_url_input)
        
        target_group.setLayout(target_layout)
        main_layout.addWidget(target_group)
        
        scanner_group = QGroupBox('Scanner Selection')
        scanner_layout = QVBoxLayout()
        
        self.xss_checkbox = QCheckBox('XSS Injection')
        self.sql_checkbox = QCheckBox('SQL Injection')
        self.rce_checkbox = QCheckBox('Remote Code Execution')
        self.cmd_checkbox = QCheckBox('Command Injection')
        self.ssrf_checkbox = QCheckBox('Server-Side Request Forgery')
        self.csrf_checkbox = QCheckBox('CSRF (Cross-Site Request Forgery)')
        self.xxe_checkbox = QCheckBox('XXE (XML External Entity)')
        self.upload_checkbox = QCheckBox('File Upload Vulnerabilities')
        self.api_checkbox = QCheckBox('API Security Testing')
        self.websocket_checkbox = QCheckBox('WebSocket Security')
        self.graphql_checkbox = QCheckBox('GraphQL Testing')
        self.ssti_checkbox = QCheckBox('Server-Side Template Injection')
        self.ldap_checkbox = QCheckBox('LDAP Injection')
        self.oauth_checkbox = QCheckBox('OAuth2/SAML')
        
        for checkbox in [self.xss_checkbox, self.sql_checkbox, self.rce_checkbox,
                        self.cmd_checkbox, self.ssrf_checkbox, self.csrf_checkbox,
                        self.xxe_checkbox, self.upload_checkbox, self.api_checkbox,
                        self.websocket_checkbox, self.graphql_checkbox, self.ssti_checkbox,
                        self.ldap_checkbox, self.oauth_checkbox]:
            scanner_layout.addWidget(checkbox)
            checkbox.setChecked(True)
        
        select_all_btn = QPushButton('Select All')
        select_all_btn.clicked.connect(self.select_all_scanners)
        scanner_layout.addWidget(select_all_btn)
        
        scanner_group.setLayout(scanner_layout)
        main_layout.addWidget(scanner_group)
        
        settings_group = QGroupBox('Scan Settings')
        settings_layout = QFormLayout()
        
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 100)
        self.threads_spinbox.setValue(10)
        settings_layout.addRow('Concurrent Threads:', self.threads_spinbox)
        
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(5, 300)
        self.timeout_spinbox.setValue(30)
        self.timeout_spinbox.setSuffix(' seconds')
        settings_layout.addRow('Request Timeout:', self.timeout_spinbox)
        
        self.delay_spinbox = QDoubleSpinBox()
        self.delay_spinbox.setRange(0, 10)
        self.delay_spinbox.setValue(0.5)
        self.delay_spinbox.setSuffix(' seconds')
        settings_layout.addRow('Request Delay:', self.delay_spinbox)
        
        self.verify_ssl_checkbox = QCheckBox('Verify SSL Certificate')
        self.verify_ssl_checkbox.setChecked(False)
        settings_layout.addRow('SSL/TLS:', self.verify_ssl_checkbox)
        
        settings_group.setLayout(settings_layout)
        main_layout.addWidget(settings_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton('▶️ Start Scan')
        self.start_button.setMinimumHeight(50)
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton('⏹️ Stop Scan')
        self.stop_button.setMinimumHeight(50)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        button_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton('🗑️ Clear')
        self.clear_button.setMinimumHeight(50)
        self.clear_button.clicked.connect(self.clear_inputs)
        button_layout.addWidget(self.clear_button)
        
        main_layout.addLayout(button_layout)
        main_layout.addStretch()
        
        self.setLayout(main_layout)
    
    def start_scan(self):
        target_url = self.target_url_input.text().strip()
        if not target_url:
            return
        
        scan_types = []
        if self.xss_checkbox.isChecked():
            scan_types.append('XSS')
        if self.sql_checkbox.isChecked():
            scan_types.append('SQL')
        if self.rce_checkbox.isChecked():
            scan_types.append('RCE')
        if self.cmd_checkbox.isChecked():
            scan_types.append('CommandInjection')
        if self.ssrf_checkbox.isChecked():
            scan_types.append('SSRF')
        if self.csrf_checkbox.isChecked():
            scan_types.append('CSRF')
        if self.xxe_checkbox.isChecked():
            scan_types.append('XXE')
        if self.upload_checkbox.isChecked():
            scan_types.append('FileUpload')
        if self.api_checkbox.isChecked():
            scan_types.append('API')
        if self.websocket_checkbox.isChecked():
            scan_types.append('WebSocket')
        if self.graphql_checkbox.isChecked():
            scan_types.append('GraphQL')
        if self.ssti_checkbox.isChecked():
            scan_types.append('SSTI')
        if self.ldap_checkbox.isChecked():
            scan_types.append('LDAP')
        if self.oauth_checkbox.isChecked():
            scan_types.append('OAuth2')
        
        if not scan_types:
            return
        
        self.is_scanning = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        
        self.scan_started.emit(target_url)
        
        self.scanner_engine.set_authentication(self.auth_manager)
        self.scanner_engine.set_proxy('')
        
        results = self.scanner_engine.start_scan(target_url, scan_types, self.on_vulnerability_found)
        
        self.scan_completed.emit(results)
        
        self.is_scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
    
    def stop_scan(self):
        self.scanner_engine.stop_scan()
        self.is_scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    def on_vulnerability_found(self, vulnerability: dict):
        self.vulnerability_found.emit(vulnerability)
        current_value = self.progress_bar.value()
        self.progress_bar.setValue(min(current_value + 1, 99))
    
    def select_all_scanners(self):
        is_checked = self.xss_checkbox.isChecked()
        for checkbox in [self.xss_checkbox, self.sql_checkbox, self.rce_checkbox,
                        self.cmd_checkbox, self.ssrf_checkbox, self.csrf_checkbox,
                        self.xxe_checkbox, self.upload_checkbox, self.api_checkbox,
                        self.websocket_checkbox, self.graphql_checkbox, self.ssti_checkbox,
                        self.ldap_checkbox, self.oauth_checkbox]:
            checkbox.setChecked(not is_checked)
    
    def clear_inputs(self):
        self.target_url_input.clear()
        self.progress_bar.setValue(0)
    
    def set_auth_manager(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager
