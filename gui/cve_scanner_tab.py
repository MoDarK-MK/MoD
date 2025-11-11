# gui/cve_scanner_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QHeaderView, QLabel,
                             QLineEdit, QComboBox, QProgressBar, QGroupBox, QSplitter,
                             QTextEdit, QMessageBox, QDialog, QScrollArea, QTabWidget as QTabWidgetBase)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QDateTime
from PyQt6.QtGui import QColor, QFont
from scanners.cve_scanner import CVEScanner
from core.poc_generator import POCGenerator
from typing import List, Dict


class POCDialog(QDialog):
    
    def __init__(self, poc_data: Dict, parent=None):
        super().__init__(parent)
        self.poc_data = poc_data
        self.init_ui()
        self.setWindowTitle(f"POC - {poc_data['cve_id']}")
        self.setMinimumSize(900, 700)
    
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        header_layout = QHBoxLayout()
        
        title = QLabel(f"{self.poc_data['cve_id']} - {self.poc_data['cve_name']}")
        title.setStyleSheet("""
            QLabel {
                font-size: 16pt;
                font-weight: bold;
                color: #58a6ff;
            }
        """)
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        severity = QLabel(self.poc_data['severity'])
        severity.setStyleSheet(f"""
            QLabel {{
                font-size: 12pt;
                font-weight: bold;
                color: {'#f85149' if self.poc_data['severity'] == 'CRITICAL' else '#d29922' if self.poc_data['severity'] == 'HIGH' else '#58a6ff'};
                padding: 6px 12px;
                background: #161b22;
                border-radius: 4px;
                border: 2px solid {'#f85149' if self.poc_data['severity'] == 'CRITICAL' else '#d29922' if self.poc_data['severity'] == 'HIGH' else '#58a6ff'};
            }}
        """)
        header_layout.addWidget(severity)
        
        layout.addLayout(header_layout)
        
        tabs = QTabWidgetBase()
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
        
        tabs.addTab(self.create_overview_tab(), 'OVERVIEW')
        tabs.addTab(self.create_exploitation_tab(), 'EXPLOITATION')
        tabs.addTab(self.create_payloads_tab(), 'PAYLOADS')
        tabs.addTab(self.create_mitigation_tab(), 'MITIGATION')
        
        layout.addWidget(tabs, 1)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        copy_btn = QPushButton('COPY ALL')
        copy_btn.setMinimumHeight(40)
        copy_btn.setMinimumWidth(120)
        copy_btn.clicked.connect(self.copy_to_clipboard)
        copy_btn.setStyleSheet("""
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
        button_layout.addWidget(copy_btn)
        
        close_btn = QPushButton('CLOSE')
        close_btn.setMinimumHeight(40)
        close_btn.setMinimumWidth(120)
        close_btn.clicked.connect(self.accept)
        close_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #da3633, stop:1 #b92222);
                color: white;
                border: 2px solid #f85149;
                border-radius: 6px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #f85149, stop:1 #da3633);
            }
        """)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def create_overview_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        overview_group = QGroupBox('VULNERABILITY OVERVIEW')
        overview_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        overview_layout = QVBoxLayout()
        overview_text = QTextEdit()
        overview_text.setReadOnly(True)
        overview_text.setPlainText(self.poc_data.get('overview', 'No overview available'))
        overview_text.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-size: 10pt;
            }
        """)
        overview_layout.addWidget(overview_text)
        overview_group.setLayout(overview_layout)
        layout.addWidget(overview_group)
        
        prereq_group = QGroupBox('PREREQUISITES')
        prereq_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        prereq_layout = QVBoxLayout()
        prereq_text = QTextEdit()
        prereq_text.setReadOnly(True)
        prereq_text.setPlainText(self.poc_data.get('prerequisites', 'No prerequisites listed'))
        prereq_text.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-size: 10pt;
            }
        """)
        prereq_layout.addWidget(prereq_text)
        prereq_group.setLayout(prereq_layout)
        layout.addWidget(prereq_group)
        
        return widget
    
    def create_exploitation_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        steps_group = QGroupBox('EXPLOITATION STEPS')
        steps_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        steps_layout = QVBoxLayout()
        steps_text = QTextEdit()
        steps_text.setReadOnly(True)
        
        steps = self.poc_data.get('exploitation_steps', [])
        steps_content = '\n\n'.join(steps) if steps else 'No exploitation steps available'
        steps_text.setPlainText(steps_content)
        
        steps_text.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #2ea043;
                border: 2px solid #238636;
                border-radius: 4px;
                padding: 10px;
                font-size: 10pt;
                font-weight: bold;
                font-family: 'Courier New';
            }
        """)
        steps_layout.addWidget(steps_text)
        steps_group.setLayout(steps_layout)
        layout.addWidget(steps_group)
        
        results_group = QGroupBox('EXPECTED RESULTS')
        results_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        results_layout = QVBoxLayout()
        results_text = QTextEdit()
        results_text.setReadOnly(True)
        results_text.setPlainText(self.poc_data.get('expected_results', 'No expected results documented'))
        results_text.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-size: 10pt;
            }
        """)
        results_layout.addWidget(results_text)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return widget
    
    def create_payloads_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        
        payloads_group = QGroupBox('EXAMPLE PAYLOADS')
        payloads_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        payloads_layout = QVBoxLayout()
        payloads_text = QTextEdit()
        payloads_text.setReadOnly(True)
        
        payloads = self.poc_data.get('payloads', [])
        payloads_content = '\n\n'.join(payloads) if payloads else 'No payloads available'
        payloads_text.setPlainText(payloads_content)
        
        payloads_text.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #f85149;
                border: 2px solid #da3633;
                border-radius: 4px;
                padding: 10px;
                font-size: 10pt;
                font-family: 'Courier New';
                font-weight: bold;
            }
        """)
        payloads_layout.addWidget(payloads_text)
        payloads_group.setLayout(payloads_layout)
        layout.addWidget(payloads_group)
        
        return widget
    
    def create_mitigation_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        mitigation_group = QGroupBox('MITIGATION STRATEGIES')
        mitigation_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #2ea043;
            }
        """)
        
        mitigation_layout = QVBoxLayout()
        mitigation_text = QTextEdit()
        mitigation_text.setReadOnly(True)
        mitigation_text.setPlainText(self.poc_data.get('mitigation', 'No mitigation strategies documented'))
        mitigation_text.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #2ea043;
                border: 2px solid #238636;
                border-radius: 4px;
                padding: 10px;
                font-size: 10pt;
            }
        """)
        mitigation_layout.addWidget(mitigation_text)
        mitigation_group.setLayout(mitigation_layout)
        layout.addWidget(mitigation_group)
        
        ref_group = QGroupBox('REFERENCES')
        ref_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)
        
        ref_layout = QVBoxLayout()
        ref_text = QTextEdit()
        ref_text.setReadOnly(True)
        
        references = self.poc_data.get('references', [])
        ref_content = '\n\n'.join(references) if references else 'No references available'
        ref_text.setPlainText(ref_content)
        
        ref_text.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #58a6ff;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-size: 10pt;
                font-family: 'Courier New';
            }
        """)
        ref_layout.addWidget(ref_text)
        ref_group.setLayout(ref_layout)
        layout.addWidget(ref_group)
        
        return widget
    
    def copy_to_clipboard(self):
        from PyQt6.QtWidgets import QApplication
        
        text = f"""{'='*80}
CVE POC: {self.poc_data['cve_id']} - {self.poc_data['cve_name']}
Severity: {self.poc_data['severity']} (Score: {self.poc_data['score']})
Category: {self.poc_data['category']}
{'='*80}

OVERVIEW:
{self.poc_data.get('overview', '')}

PREREQUISITES:
{self.poc_data.get('prerequisites', '')}

EXPLOITATION STEPS:
{chr(10).join(self.poc_data.get('exploitation_steps', []))}

PAYLOADS:
{chr(10).join(self.poc_data.get('payloads', []))}

EXPECTED RESULTS:
{self.poc_data.get('expected_results', '')}

MITIGATION:
{self.poc_data.get('mitigation', '')}

REFERENCES:
{chr(10).join(self.poc_data.get('references', []))}
{'='*80}"""
        
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, 'Success', 'POC copied to clipboard!')


class CVEScanThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    cve_found = pyqtSignal(dict)
    scan_completed = pyqtSignal(list)
    
    def __init__(self, target_url: str, timeout: int, severity_filter: str):
        super().__init__()
        self.target_url = target_url
        self.timeout = timeout
        self.severity_filter = severity_filter
        self.should_stop = False
    
    def run(self):
        try:
            self.status_updated.emit(f'Initializing scan on {self.target_url}')
            self.progress_updated.emit(5)
            
            scanner = CVEScanner(timeout=self.timeout, max_workers=10)
            
            self.status_updated.emit('Connecting to target...')
            self.progress_updated.emit(10)
            
            from core.cve_payloads import CVEPayloads
            cve_list = CVEPayloads.get_all_cves()
            
            if self.severity_filter != 'ALL':
                cve_list = [cve for cve in cve_list if cve['severity'] == self.severity_filter or 
                           (self.severity_filter == 'HIGH' and cve['severity'] == 'CRITICAL')]
            
            total = len(cve_list)
            
            self.status_updated.emit(f'Testing {total} CVE signatures...')
            self.progress_updated.emit(20)
            
            results = scanner.scan(self.target_url, self.severity_filter)
            
            for idx, vuln in enumerate(results):
                if self.should_stop:
                    break
                
                vuln['found_at'] = QDateTime.currentDateTime().toString('yyyy-MM-dd hh:mm:ss')
                self.cve_found.emit(vuln)
                
                progress = 20 + int((idx + 1) / max(len(results), 1) * 70)
                self.progress_updated.emit(min(progress, 90))
            
            self.progress_updated.emit(100)
            self.status_updated.emit(f'Scan completed - Found {len(results)} vulnerabilities')
            self.scan_completed.emit(results)
            
        except Exception as e:
            self.status_updated.emit(f'Error: {str(e)}')
            self.scan_completed.emit([])
    
    def stop(self):
        self.should_stop = True


class CVEScannerTab(QWidget):
    
    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.vulnerabilities = []
        self.poc_generator = None
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
        
        version = QLabel('v3.0 Enterprise')
        version.setStyleSheet("""
            QLabel {
                font-size: 10pt;
                color: #8b949e;
                padding: 6px 12px;
                background: #161b22;
                border-radius: 4px;
                border: 1px solid #30363d;
            }
        """)
        header_layout.addWidget(version)
        
        main_layout.addLayout(header_layout)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(2)
        splitter.setStyleSheet("""
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
        
        splitter.addWidget(top_panel)
        splitter.addWidget(bottom_panel)
        splitter.setSizes([280, 520])
        
        main_layout.addWidget(splitter, 1)
        
        self.setLayout(main_layout)
    
    def create_scan_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        config_group = QGroupBox('TARGET CONFIGURATION')
        config_group.setStyleSheet("""
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
        
        config_layout = QVBoxLayout()
        
        url_layout = QHBoxLayout()
        url_label = QLabel('TARGET:')
        url_label.setStyleSheet('color: #c9d1d9; font-weight: bold; font-size: 11pt; min-width: 80px;')
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
        config_layout.addLayout(url_layout)
        
        options_layout = QHBoxLayout()
        
        timeout_label = QLabel('TIMEOUT:')
        timeout_label.setStyleSheet('color: #8b949e; font-weight: bold; min-width: 80px;')
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
        
        severity_label = QLabel('SEVERITY:')
        severity_label.setStyleSheet('color: #8b949e; font-weight: bold; min-width: 80px;')
        options_layout.addWidget(severity_label)
        
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'])
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
        config_layout.addLayout(options_layout)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        control_layout = QHBoxLayout()
        
        self.scan_button = QPushButton('START SCAN')
        self.scan_button.setMinimumHeight(50)
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
            QPushButton:disabled {
                background: #21262d;
                color: #6e7681;
                border: 2px solid #30363d;
            }
        """)
        control_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton('STOP')
        self.stop_button.setMinimumHeight(50)
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
        
        layout.addLayout(control_layout)
        
        progress_group = QGroupBox('SCAN PROGRESS')
        progress_group.setStyleSheet("""
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
        
        progress_layout = QVBoxLayout()
        
        self.status_label = QLabel('Ready to scan')
        self.status_label.setStyleSheet('color: #58a6ff; font-size: 10pt; font-weight: bold;')
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
        self.total_label.setStyleSheet('color: #c9d1d9; font-weight: bold; font-size: 10pt;')
        stats_layout.addWidget(self.total_label)
        
        self.critical_label = QLabel('CRITICAL: 0')
        self.critical_label.setStyleSheet('color: #f85149; font-weight: bold; font-size: 10pt;')
        stats_layout.addWidget(self.critical_label)
        
        self.high_label = QLabel('HIGH: 0')
        self.high_label.setStyleSheet('color: #d29922; font-weight: bold; font-size: 10pt;')
        stats_layout.addWidget(self.high_label)
        
        stats_layout.addStretch()
        progress_layout.addLayout(stats_layout)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        return panel
    
    def create_results_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        results_group = QGroupBox('VULNERABILITIES DETECTED (Double-click for POC)')
        results_group.setStyleSheet("""
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
        self.results_table.itemDoubleClicked.connect(self.show_poc_dialog)
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
    
    def set_api_config(self, api_key: str, api_provider: str):
        self.poc_generator = POCGenerator(api_key, api_provider)
    
    def start_scan(self):
        target = self.target_input.text().strip()
        
        if not target:
            self.status_label.setText('Error: Enter target URL')
            self.status_label.setStyleSheet('color: #f85149; font-size: 10pt; font-weight: bold;')
            return
        
        if not target.startswith('http'):
            target = 'https://' + target
        
        timeout = int(self.timeout_combo.currentText().replace('s', ''))
        severity = self.severity_combo.currentText()
        
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.target_input.setEnabled(False)
        self.results_table.setRowCount(0)
        self.vulnerabilities.clear()
        self.progress_bar.setValue(0)
        
        self.scan_thread = CVEScanThread(target, timeout, severity)
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.status_updated.connect(self.update_status)
        self.scan_thread.cve_found.connect(self.add_vulnerability)
        self.scan_thread.scan_completed.connect(self.scan_finished)
        self.scan_thread.start()
    
    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread.wait()
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.status_label.setText('Scan stopped')
        self.status_label.setStyleSheet('color: #d29922; font-size: 10pt; font-weight: bold;')
    
    def update_progress(self, value: int):
        self.progress_bar.setValue(value)
    
    def update_status(self, text: str):
        self.status_label.setText(text)
        self.status_label.setStyleSheet('color: #58a6ff; font-size: 10pt; font-weight: bold;')
    
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
        else:
            severity.setForeground(QColor('#58a6ff'))
        
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
        
        self.total_label.setText(f'TOTAL: {total}')
        self.critical_label.setText(f'CRITICAL: {critical}')
        self.high_label.setText(f'HIGH: {high}')
    
    def scan_finished(self, results: list):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.progress_bar.setValue(100)
        
        if results:
            self.status_label.setText(f'Completed - {len(results)} vulnerabilities found')
            self.status_label.setStyleSheet('color: #2ea043; font-size: 10pt; font-weight: bold;')
        else:
            self.status_label.setText('Completed - No vulnerabilities found')
            self.status_label.setStyleSheet('color: #2ea043; font-size: 10pt; font-weight: bold;')
    
    def show_poc_dialog(self, item):
        row = item.row()
        if row >= len(self.vulnerabilities):
            return
        
        vuln = self.vulnerabilities[row]
        
        self.status_label.setText(f'Generating POC for {vuln["id"]}...')
        self.status_label.setStyleSheet('color: #58a6ff; font-size: 10pt; font-weight: bold;')
        
        from PyQt6.QtWidgets import QApplication
        QApplication.processEvents()
        
        if not self.poc_generator:
            self.poc_generator = POCGenerator()
        
        target = self.target_input.text().strip()
        poc_data = self.poc_generator.generate_poc(vuln, target)
        
        self.status_label.setText('POC generated successfully')
        self.status_label.setStyleSheet('color: #2ea043; font-size: 10pt; font-weight: bold;')
        
        dialog = POCDialog(poc_data, self)
        dialog.exec()
