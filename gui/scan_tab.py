# scan_tab.py - اصلاح شده
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QCheckBox, QGroupBox,
                             QFormLayout, QSpinBox, QDoubleSpinBox, QProgressBar,
                             QComboBox, QTextEdit, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class ScanWorker(QThread):
    vulnerability_found = pyqtSignal(dict)
    scan_completed = pyqtSignal(list)
    progress_updated = pyqtSignal(int)
    
    def __init__(self, target_url, scan_types):
        super().__init__()
        self.target_url = target_url
        self.scan_types = scan_types
        self.should_stop = False
    
    def run(self):
        vulnerabilities = []
        total = len(self.scan_types)
        
        for idx, scan_type in enumerate(self.scan_types):
            if self.should_stop:
                break
            
            try:
                if scan_type == 'XSS':
                    from scanners.xss_scanner import XSSScanner
                    scanner = XSSScanner()
                    payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
                    response = {'content': '', 'status_code': 200, 'response_time': 0.5, 'headers': {}}
                    vulns = scanner.scan(self.target_url, response, payloads)
                    vulnerabilities.extend(vulns)
                    
                elif scan_type == 'SQL':
                    from scanners.sql_scanner import SQLScanner
                    scanner = SQLScanner()
                    payloads = ["' OR '1'='1", "1' UNION SELECT NULL--"]
                    response = {'content': '', 'status_code': 200, 'response_time': 0.5, 'headers': {}}
                    vulns = scanner.scan(self.target_url, response, payloads)
                    vulnerabilities.extend(vulns)
                    
                elif scan_type == 'RCE':
                    from scanners.rce_scanner import RCEScanner
                    scanner = RCEScanner()
                    response = {'content': '', 'status_code': 200, 'response_time': 0.5, 'headers': {}}
                    vulns = scanner.scan(self.target_url, response)
                    vulnerabilities.extend(vulns)
                
                for vuln in vulns if 'vulns' in locals() else []:
                    self.vulnerability_found.emit({
                        'type': vuln.vulnerability_type,
                        'severity': vuln.severity,
                        'url': vuln.url,
                        'evidence': vuln.evidence
                    })
                
                progress = int((idx + 1) / total * 100)
                self.progress_updated.emit(progress)
                
            except Exception as e:
                print(f"Error scanning {scan_type}: {e}")
        
        self.scan_completed.emit(vulnerabilities)
    
    def stop(self):
        self.should_stop = True


class ScanTab(QWidget):
    scan_started = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    vulnerability_found = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.is_scanning = False
        self.scan_worker = None
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
            QMessageBox.warning(self, 'Warning', 'Please enter a target URL')
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
            QMessageBox.warning(self, 'Warning', 'Please select at least one scanner')
            return
        
        self.is_scanning = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        
        self.scan_started.emit(target_url)
        
        self.scan_worker = ScanWorker(target_url, scan_types)
        self.scan_worker.vulnerability_found.connect(self.on_vulnerability_found)
        self.scan_worker.scan_completed.connect(self.on_scan_completed)
        self.scan_worker.progress_updated.connect(self.progress_bar.setValue)
        self.scan_worker.start()
    
    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
            self.scan_worker.wait()
        
        self.is_scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    def on_vulnerability_found(self, vulnerability: dict):
        self.vulnerability_found.emit(vulnerability)
    
    def on_scan_completed(self, results: list):
        self.scan_completed.emit(results)
        self.is_scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
    
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
    
    def set_auth_manager(self, auth_manager):
        pass
