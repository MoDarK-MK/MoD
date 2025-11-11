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
    
    def __init__(self, target_url: str, vector_type: str):
        super().__init__()
        self.target_url = target_url
        self.vector_type = vector_type
        self.should_stop = False
        self.engine = None
    
    def run(self):
        try:
            self.status_updated.emit(f'⚙️ Initializing WAF Bypass on {self.target_url}')
            self.progress_updated.emit(5)
            
            self.engine = WAFBypassEngine(self.target_url, timeout=15, max_workers=30)
            
            self.status_updated.emit('🛡️ Detecting WAF...')
            self.progress_updated.emit(10)
            
            waf_type, confidence = self.engine.detect_waf()
            self.status_updated.emit(f'✓ WAF Detected: {waf_type} (Confidence: {confidence*100:.0f}%)')
            self.progress_updated.emit(20)
            
            self.status_updated.emit('📊 Getting baseline response...')
            self.engine.get_baseline_response()
            self.progress_updated.emit(30)
            
            self.status_updated.emit(f'🚀 Starting Unlimited WAF Bypass with {self.vector_type} payloads...')
            self.progress_updated.emit(40)
            
            bypass_counter = 0
            
            while not self.should_stop:
                if self.should_stop:
                    break
                
                successful_bypasses = self.engine.adaptive_bypass_unlimited(self.vector_type)
                
                for bypass in successful_bypasses:
                    if self.should_stop:
                        break
                    
                    self.bypass_found.emit(bypass)
                    bypass_counter += 1
                    
                    if bypass_counter % 5 == 0:
                        self.status_updated.emit(f'🔥 Found {bypass_counter} bypasses... (Running unlimited - Press STOP to quit)')
                        self.progress_updated.emit(min(40 + (bypass_counter % 50), 95))
                
                if self.should_stop:
                    break
                
                self.status_updated.emit(f'🔄 Generating new advanced payload mutations... ({bypass_counter} bypasses found)')
                self.progress_updated.emit(min(40 + (bypass_counter % 50), 95))
            
            self.progress_updated.emit(100)
            self.status_updated.emit(f'⏹️ Bypass Stopped - Total Successful Bypasses: {bypass_counter}')
            self.bypass_completed.emit([])
            
        except Exception as e:
            self.status_updated.emit(f'❌ Error: {str(e)}')
            self.bypass_completed.emit([])
    
    def stop(self):
        self.should_stop = True
        if self.engine:
            self.engine.stop_bypass()


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
        
        title = QLabel('🔥 WAF BYPASS ENGINE - Unlimited Mode')
        title.setStyleSheet("""
            QLabel {
                font-size: 22pt;
                font-weight: bold;
                color: #f85149;
                text-shadow: 2px 2px 4px #000;
            }
        """)
        main_layout.addWidget(title)
        
        subtitle = QLabel('Enterprise-Grade Intelligent Payload Mutation & WAF Evasion')
        subtitle.setStyleSheet("""
            QLabel {
                font-size: 10pt;
                color: #d29922;
                font-style: italic;
            }
        """)
        main_layout.addWidget(subtitle)
        
        config_group = QGroupBox('⚙️ TARGET CONFIGURATION')
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
        url_label = QLabel('🌐 TARGET URL:')
        url_label.setStyleSheet('color: #c9d1d9; font-weight: bold; min-width: 120px;')
        url_layout.addWidget(url_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('https://target.com/vulnerable?param=value')
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
        
        vector_label = QLabel('🎯 ATTACK VECTOR:')
        vector_label.setStyleSheet('color: #c9d1d9; font-weight: bold;')
        options_layout.addWidget(vector_label)
        
        self.vector_combo = QComboBox()
        self.vector_combo.addItems(['XSS', 'SQLi', 'RCE', 'SSRF', 'XXE'])
        self.vector_combo.setCurrentText('XSS')
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
        
        mode_label = QLabel('📊 MODE:')
        mode_label.setStyleSheet('color: #c9d1d9; font-weight: bold;')
        options_layout.addWidget(mode_label)
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(['Unlimited', 'Aggressive', 'Stealth', 'Balanced'])
        self.mode_combo.setCurrentText('Unlimited')
        self.mode_combo.setMinimumHeight(36)
        self.mode_combo.setStyleSheet("""
            QComboBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #f85149;
                border-radius: 4px;
                padding: 6px 10px;
                font-weight: bold;
            }
        """)
        options_layout.addWidget(self.mode_combo)
        
        workers_label = QLabel('⚡ WORKERS:')
        workers_label.setStyleSheet('color: #c9d1d9; font-weight: bold;')
        options_layout.addWidget(workers_label)
        
        self.workers_spin = QSpinBox()
        self.workers_spin.setMinimum(5)
        self.workers_spin.setMaximum(100)
        self.workers_spin.setValue(30)
        self.workers_spin.setStyleSheet("""
            QSpinBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #f85149;
                border-radius: 4px;
                padding: 6px 10px;
                font-weight: bold;
                width: 60px;
            }
        """)
        options_layout.addWidget(self.workers_spin)
        
        options_layout.addStretch()
        config_layout.addLayout(options_layout)
        
        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)
        
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton('▶️ START UNLIMITED BYPASS')
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
        
        self.stop_button = QPushButton('⏹️ STOP BYPASS')
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
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #0757b8, stop:1 #0644a5);
            }
        """)
        button_layout.addWidget(self.stop_button)
        
        main_layout.addLayout(button_layout)
        
        progress_group = QGroupBox('📈 BYPASS PROGRESS')
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
        
        self.status_label = QLabel('🟢 Ready for Unlimited WAF Bypass')
        self.status_label.setStyleSheet('color: #2ea043; font-weight: bold; font-size: 11pt;')
        progress_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(35)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(100)
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
        
        self.waf_label = QLabel('🛡️ WAF: Detecting...')
        self.waf_label.setStyleSheet('color: #d29922; font-weight: bold;')
        stats_layout.addWidget(self.waf_label)
        
        self.bypassed_label = QLabel('✓ BYPASSED: 0')
        self.bypassed_label.setStyleSheet('color: #f85149; font-weight: bold;')
        stats_layout.addWidget(self.bypassed_label)
        
        self.attempts_label = QLabel('📊 ATTEMPTS: ∞')
        self.attempts_label.setStyleSheet('color: #58a6ff; font-weight: bold;')
        stats_layout.addWidget(self.attempts_label)
        
        self.time_label = QLabel('⏱️ ELAPSED: 00:00')
        self.time_label.setStyleSheet('color: #8b949e; font-weight: bold;')
        stats_layout.addWidget(self.time_label)
        
        stats_layout.addStretch()
        progress_layout.addLayout(stats_layout)
        
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)
        
        results_group = QGroupBox('🎯 SUCCESSFUL BYPASSES')
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
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            'Payload', 'Injection Point', 'Status', 'Confidence', 'Response Time', 'Technique'
        ])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
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
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.target_input.setEnabled(False)
        self.vector_combo.setEnabled(False)
        self.mode_combo.setEnabled(False)
        self.workers_spin.setEnabled(False)
        self.results_table.setRowCount(0)
        self.bypassed_payloads.clear()
        self.progress_bar.setValue(0)
        
        self.bypass_thread = WAFBypassThread(target, vector_type)
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
        self.vector_combo.setEnabled(True)
        self.mode_combo.setEnabled(True)
        self.workers_spin.setEnabled(True)
        self.status_label.setText('⏹️ Bypass stopped by user')
    
    def update_progress(self, value: int):
        self.progress_bar.setValue(value)
    
    def update_status(self, text: str):
        self.status_label.setText(text)
        
        if 'WAF Detected:' in text:
            parts = text.split(': ')
            if len(parts) > 1:
                self.waf_label.setText(f"🛡️ {parts[1]}")
    
    def add_bypass(self, bypass_data: dict):
        self.bypassed_payloads.append(bypass_data)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        payload_item = QTableWidgetItem(bypass_data['payload'][:70])
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
        
        technique_item = QTableWidgetItem(bypass_data.get('technique_used', 'Unknown'))
        technique_item.setFont(QFont('Arial', 8))
        technique_item.setForeground(QColor('#58a6ff'))
        self.results_table.setItem(row, 5, technique_item)
        
        self.bypassed_label.setText(f'✓ BYPASSED: {len(self.bypassed_payloads)}')
        
        self.results_table.scrollToBottom()
    
    def bypass_finished(self, results: list):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.vector_combo.setEnabled(True)
        self.mode_combo.setEnabled(True)
        self.workers_spin.setEnabled(True)
        self.progress_bar.setValue(100)
        
        QMessageBox.information(
            self,
            '✓ Bypass Complete',
            f'🎉 WAF Bypass Completed!\n\n'
            f'✓ Successfully bypassed {len(self.bypassed_payloads)} payloads\n\n'
            f'💾 All payloads saved and ready for exploitation\n\n'
            f'⚙️ Use these advanced techniques for your penetration test'
        )
