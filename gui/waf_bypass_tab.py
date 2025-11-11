# gui/waf_bypass_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QHeaderView, QLabel,
                             QLineEdit, QComboBox, QProgressBar, QGroupBox,
                             QMessageBox, QTextEdit, QCheckBox, QSpinBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from scanners.waf_bypass_engine import (
    WAFBypassEngine, IntelligentPayloadGenerator, PayloadMutator, WAFDetector
)
from typing import List, Dict


class WAFBypassThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    bypass_found = pyqtSignal(dict)
    bypass_completed = pyqtSignal(list)
    
    def __init__(self, target_url: str, vector_type: str, max_iterations: int = 500):
        super().__init__()
        self.target_url = target_url
        self.vector_type = vector_type
        self.max_iterations = max_iterations
        self.should_stop = False
    
    def run(self):
        try:
            self.status_updated.emit(f'Initializing WAF Bypass on {self.target_url}')
            self.progress_updated.emit(5)
            
            engine = WAFBypassEngine(self.target_url, timeout=15, max_workers=30)
            
            self.status_updated.emit('Detecting WAF...')
            self.progress_updated.emit(10)
            
            waf_type, confidence = engine.detect_waf()
            self.status_updated.emit(f'WAF Detected: {waf_type} (Confidence: {confidence*100:.0f}%)')
            self.progress_updated.emit(20)
            
            self.status_updated.emit('Getting baseline response...')
            engine.get_baseline_response()
            self.progress_updated.emit(30)
            
            self.status_updated.emit(f'Starting adaptive bypass with {self.vector_type} payloads...')
            self.progress_updated.emit(40)
            
            successful_bypasses = engine.adaptive_bypass(self.vector_type, self.max_iterations)
            
            for idx, bypass in enumerate(successful_bypasses):
                if self.should_stop:
                    break
                
                self.bypass_found.emit(bypass)
                
                progress = 40 + int((idx + 1) / max(len(successful_bypasses), 1) * 50)
                self.progress_updated.emit(min(progress, 90))
            
            self.progress_updated.emit(100)
            self.status_updated.emit(f'Bypass Completed - {len(successful_bypasses)} payloads bypassed WAF')
            self.bypass_completed.emit(successful_bypasses)
            
        except Exception as e:
            self.status_updated.emit(f'Error: {str(e)}')
            self.bypass_completed.emit([])
    
    def stop(self):
        self.should_stop = True


class WAFBypassTab(QWidget):
    
    def __init__(self):
        super().__init__()
        self.bypass_thread = None
        self.bypassed_payloads = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        title = QLabel('WAF BYPASS ENGINE - World Class')
        title.setStyleSheet("""
            QLabel {
                font-size: 22pt;
                font-weight: bold;
                color: #f85149;
                text-shadow: 2px 2px 4px #000;
            }
        """)
        main_layout.addWidget(title)
        
        config_group = QGroupBox('TARGET CONFIGURATION')
        config_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #f85149;
                border-radius: 8px;
                padding-top: 12px;
                background: #0d1117;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #f85149;
            }
        """)
        
        config_layout = QVBoxLayout()
        
        url_layout = QHBoxLayout()
        url_label = QLabel('TARGET URL:')
        url_label.setStyleSheet('color: #c9d1d9; font-weight: bold; min-width: 120px;')
        url_layout.addWidget(url_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('https://target.com/vulnerable')
        self.target_input.setMinimumHeight(40)
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #f85149;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 11pt;
                font-family: 'Courier New';
            }
            QLineEdit:focus {
                border: 2px solid #58a6ff;
                background: #0d1117;
            }
        """)
        url_layout.addWidget(self.target_input, 1)
        config_layout.addLayout(url_layout)
        
        options_layout = QHBoxLayout()
        
        vector_label = QLabel('ATTACK VECTOR:')
        vector_label.setStyleSheet('color: #c9d1d9; font-weight: bold;')
        options_layout.addWidget(vector_label)
        
        self.vector_combo = QComboBox()
        self.vector_combo.addItems(['XSS', 'SQLi', 'RCE', 'SSRF', 'XXE'])
        self.vector_combo.setMinimumHeight(36)
        self.vector_combo.setStyleSheet("""
            QComboBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #f85149;
                border-radius: 4px;
                padding: 6px 10px;
                font-weight: bold;
            }
        """)
        options_layout.addWidget(self.vector_combo)
        
        iterations_label = QLabel('MAX ITERATIONS:')
        iterations_label.setStyleSheet('color: #c9d1d9; font-weight: bold;')
        options_layout.addWidget(iterations_label)
        
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setMinimum(50)
        self.iterations_spin.setMaximum(5000)
        self.iterations_spin.setValue(500)
        self.iterations_spin.setStyleSheet("""
            QSpinBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #f85149;
                border-radius: 4px;
                padding: 6px 10px;
                font-weight: bold;
            }
        """)
        options_layout.addWidget(self.iterations_spin)
        
        options_layout.addStretch()
        config_layout.addLayout(options_layout)
        
        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)
        
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton('START WAF BYPASS')
        self.start_button.setMinimumHeight(50)
        self.start_button.clicked.connect(self.start_bypass)
        self.start_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #f85149, stop:1 #da3633);
                color: white;
                border: 2px solid #f85149;
                border-radius: 8px;
                font-weight: bold;
                font-size: 13pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #da3633, stop:1 #c42e2e);
            }
        """)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton('STOP')
        self.stop_button.setMinimumHeight(50)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_bypass)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #0969da, stop:1 #0757b8);
                color: white;
                border: 2px solid #1f6feb;
                border-radius: 8px;
                font-weight: bold;
                font-size: 13pt;
            }
        """)
        button_layout.addWidget(self.stop_button)
        
        main_layout.addLayout(button_layout)
        
        progress_group = QGroupBox('BYPASS PROGRESS')
        progress_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #f85149;
                border-radius: 8px;
                padding-top: 12px;
                background: #0d1117;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #f85149;
            }
        """)
        
        progress_layout = QVBoxLayout()
        
        self.status_label = QLabel('Ready to bypass WAF')
        self.status_label.setStyleSheet('color: #2ea043; font-weight: bold; font-size: 11pt;')
        progress_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(35)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: #161b22;
                border: 2px solid #f85149;
                border-radius: 6px;
                text-align: center;
                color: #f85149;
                font-weight: bold;
                font-size: 11pt;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                           stop:0 #f85149, stop:1 #da3633);
                border-radius: 4px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        stats_layout = QHBoxLayout()
        
        self.waf_label = QLabel('WAF: Detecting...')
        self.waf_label.setStyleSheet('color: #d29922; font-weight: bold;')
        stats_layout.addWidget(self.waf_label)
        
        self.bypassed_label = QLabel('BYPASSED: 0')
        self.bypassed_label.setStyleSheet('color: #f85149; font-weight: bold;')
        stats_layout.addWidget(self.bypassed_label)
        
        self.attempts_label = QLabel('ATTEMPTS: 0')
        self.attempts_label.setStyleSheet('color: #58a6ff; font-weight: bold;')
        stats_layout.addWidget(self.attempts_label)
        
        stats_layout.addStretch()
        progress_layout.addLayout(stats_layout)
        
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)
        
        results_group = QGroupBox('SUCCESSFUL BYPASSES')
        results_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #2ea043;
                border-radius: 8px;
                padding-top: 12px;
                background: #0d1117;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #2ea043;
            }
        """)
        
        results_layout = QVBoxLayout()
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(['Payload', 'Injection Point', 'Status', 'Confidence', 'Response Time'])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                alternate-background-color: #161b22;
                gridline-color: #30363d;
                border: 2px solid #2ea043;
                border-radius: 6px;
                color: #c9d1d9;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background: #f85149;
                color: white;
            }
            QHeaderView::section {
                background: #161b22;
                color: #2ea043;
                padding: 8px;
                border: none;
                border-right: 1px solid #2ea043;
                font-weight: bold;
            }
        """)
        
        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)
        main_layout.addWidget(results_group, 1)
        
        self.setLayout(main_layout)
    
    def start_bypass(self):
        target = self.target_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, 'Error', 'Please enter target URL')
            return
        
        if not target.startswith('http'):
            target = 'https://' + target
        
        vector_type = self.vector_combo.currentText()
        max_iterations = self.iterations_spin.value()
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.target_input.setEnabled(False)
        self.results_table.setRowCount(0)
        self.bypassed_payloads.clear()
        self.progress_bar.setValue(0)
        
        self.bypass_thread = WAFBypassThread(target, vector_type, max_iterations)
        self.bypass_thread.progress_updated.connect(self.update_progress)
        self.bypass_thread.status_updated.connect(self.update_status)
        self.bypass_thread.bypass_found.connect(self.add_bypass)
        self.bypass_thread.bypass_completed.connect(self.bypass_finished)
        self.bypass_thread.start()
    
    def stop_bypass(self):
        if self.bypass_thread:
            self.bypass_thread.stop()
            self.bypass_thread.wait()
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.status_label.setText('Bypass stopped')
    
    def update_progress(self, value: int):
        self.progress_bar.setValue(value)
    
    def update_status(self, text: str):
        self.status_label.setText(text)
        
        if 'WAF Detected' in text:
            self.waf_label.setText(text.split(':')[1] if ':' in text else 'Unknown')
    
    def add_bypass(self, bypass_data: dict):
        self.bypassed_payloads.append(bypass_data)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        payload_item = QTableWidgetItem(bypass_data['payload'][:80])
        payload_item.setFont(QFont('Courier New', 8))
        self.results_table.setItem(row, 0, payload_item)
        
        injection_item = QTableWidgetItem(bypass_data['injection_point'])
        injection_item.setFont(QFont('Arial', 9))
        injection_item.setForeground(QColor('#f85149'))
        self.results_table.setItem(row, 1, injection_item)
        
        status_item = QTableWidgetItem('✓ BYPASSED')
        status_item.setFont(QFont('Arial', 10, QFont.Weight.Bold))
        status_item.setForeground(QColor('#2ea043'))
        self.results_table.setItem(row, 2, status_item)
        
        confidence_item = QTableWidgetItem(f"{bypass_data['confidence']*100:.0f}%")
        confidence_item.setFont(QFont('Arial', 9))
        self.results_table.setItem(row, 3, confidence_item)
        
        time_item = QTableWidgetItem(f"{bypass_data['response_time']:.2f}s")
        time_item.setFont(QFont('Arial', 9))
        self.results_table.setItem(row, 4, time_item)
        
        self.bypassed_label.setText(f'BYPASSED: {len(self.bypassed_payloads)}')
    
    def bypass_finished(self, results: list):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.progress_bar.setValue(100)
        
        if results:
            QMessageBox.information(
                self,
                'Success',
                f'WAF Bypass Complete!\n\nSuccessfully bypassed {len(results)} payloads\n\nUse these payloads for further exploitation'
            )
        else:
            QMessageBox.warning(self, 'No Bypasses Found', 'Could not find any successful bypass payloads')
