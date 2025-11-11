# gui/waf_bypass_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QHeaderView, QLabel,
                             QLineEdit, QComboBox, QGroupBox, QMessageBox, QTabWidget)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from scanners.waf_bypass_engine import WAFBypassEngine, IntelligentPayloadGenerator
import time


class WAFBypassThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    test_payload_live = pyqtSignal(dict)
    bypass_found = pyqtSignal(dict)
    bypass_completed = pyqtSignal(list)
    
    def __init__(self, target_url: str, vector_type: str):
        super().__init__()
        self.target_url = target_url
        self.vector_type = vector_type
        self.should_stop = False
        self.engine = None
        self._start_time = 0
        self.daemon = True
    
    def run(self):
        try:
            self._start_time = time.time()
            
            self.status_updated.emit('⚙️ Initializing...')
            self.progress_updated.emit(5)
            
            self.engine = WAFBypassEngine(self.target_url, timeout=2, max_workers=50)
            
            self.status_updated.emit('🛡️ Detecting WAF...')
            self.engine.detect_waf()
            self.engine.get_baseline_response()
            self.progress_updated.emit(20)
            
            self.status_updated.emit(f'🚀 Starting {self.vector_type}')
            self.progress_updated.emit(30)
            
            bypass_counter = 0
            test_counter = 0
            
            while not self.should_stop:
                if self.should_stop:
                    break
                
                payloads = IntelligentPayloadGenerator.generate_intelligent_payloads(
                    self.vector_type,
                    unlimited=True
                )
                
                from concurrent.futures import ThreadPoolExecutor, as_completed
                
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = []
                    
                    for payload in payloads:
                        if self.should_stop:
                            break
                        
                        if payload not in self.engine.payload_cache:
                            self.engine.payload_cache.add(payload)
                            future = executor.submit(
                                self.engine.test_payload_fast,
                                payload,
                                'query'
                            )
                            futures.append(future)
                    
                    for future in as_completed(futures, timeout=2):
                        if self.should_stop:
                            break
                        
                        try:
                            result = future.result(timeout=2)
                            test_counter += 1
                            
                            self.test_payload_live.emit(result)
                            
                            if result['is_bypassed']:
                                self.bypass_found.emit(result)
                                bypass_counter += 1
                            
                            if test_counter % 10 == 0:
                                elapsed = time.time() - self._start_time
                                speed = test_counter / max(elapsed, 1)
                                self.status_updated.emit(f'🔥 {bypass_counter} | {test_counter} | {speed:.1f}/s')
                                self.progress_updated.emit(min(30 + (test_counter % 60), 95))
                        
                        except Exception:
                            pass
                
                if self.should_stop:
                    break
            
            self.progress_updated.emit(100)
            self.status_updated.emit(f'⏹️ {bypass_counter}/{test_counter}')
            self.bypass_completed.emit([])
        
        except Exception as e:
            self.status_updated.emit(f'❌ {str(e)[:40]}')
            self.bypass_completed.emit([])
    
    def stop(self):
        self.should_stop = True
        if self.engine:
            self.engine.should_stop = True


class WAFBypassTab(QWidget):
    
    def __init__(self):
        super().__init__()
        self.bypass_thread = None
        self.bypassed_payloads = []
        self.tested_payloads = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        title = QLabel('🔥 WAF BYPASS - Ultra Fast')
        title.setStyleSheet("""
            QLabel {
                font-size: 22pt;
                font-weight: bold;
                color: #f85149;
                text-shadow: 2px 2px 4px #000;
            }
        """)
        main_layout.addWidget(title)
        
        config_group = QGroupBox('⚙️ TARGET')
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
        url_label = QLabel('URL:')
        url_label.setStyleSheet('color: #c9d1d9; font-weight: bold;')
        url_layout.addWidget(url_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('https://target.com')
        self.target_input.setMinimumHeight(36)
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #f85149;
                border-radius: 4px;
                padding: 6px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #58a6ff;
            }
        """)
        url_layout.addWidget(self.target_input, 1)
        
        vector_label = QLabel('VECTOR:')
        vector_label.setStyleSheet('color: #c9d1d9; font-weight: bold;')
        url_layout.addWidget(vector_label)
        
        self.vector_combo = QComboBox()
        self.vector_combo.addItems(['XSS', 'SQLi', 'RCE', 'SSRF', 'XXE'])
        self.vector_combo.setMinimumHeight(36)
        self.vector_combo.setStyleSheet("""
            QComboBox {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #f85149;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        url_layout.addWidget(self.vector_combo)
        config_layout.addLayout(url_layout)
        
        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)
        
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton('▶️ START')
        self.start_button.setMinimumHeight(45)
        self.start_button.clicked.connect(self.start_bypass)
        self.start_button.setStyleSheet("""
            QPushButton {
                background: #f85149;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12pt;
            }
            QPushButton:hover {
                background: #da3633;
            }
        """)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton('⏹️ STOP')
        self.stop_button.setMinimumHeight(45)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_bypass)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background: #0969da;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12pt;
            }
        """)
        button_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton('🗑️ CLEAR')
        self.clear_button.setMinimumHeight(45)
        self.clear_button.clicked.connect(self.clear_all)
        self.clear_button.setStyleSheet("""
            QPushButton {
                background: #6b7280;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12pt;
            }
        """)
        button_layout.addWidget(self.clear_button)
        
        main_layout.addLayout(button_layout)
        
        status_group = QGroupBox('📊 STATUS')
        status_group.setStyleSheet("""
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
        
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel('🟢 Ready')
        self.status_label.setStyleSheet('color: #2ea043; font-weight: bold;')
        status_layout.addWidget(self.status_label)
        
        stats_layout = QHBoxLayout()
        
        self.bypassed_label = QLabel('✓ 0')
        self.bypassed_label.setStyleSheet('color: #f85149; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.bypassed_label)
        
        self.tested_label = QLabel('📊 0')
        self.tested_label.setStyleSheet('color: #58a6ff; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.tested_label)
        
        self.success_rate = QLabel('📈 0%')
        self.success_rate.setStyleSheet('color: #2ea043; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.success_rate)
        
        self.speed_label = QLabel('⚡ 0/s')
        self.speed_label.setStyleSheet('color: #58a6ff; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.speed_label)
        
        stats_layout.addStretch()
        status_layout.addLayout(stats_layout)
        
        status_group.setLayout(status_layout)
        main_layout.addWidget(status_group)
        
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane { border: 2px solid #30363d; background: #0d1117; }
            QTabBar::tab { background: #161b22; color: #8b949e; padding: 8px 16px; border: 1px solid #30363d; }
            QTabBar::tab:selected { background: #0d1117; color: #58a6ff; border-bottom: 2px solid #58a6ff; }
        """)
        
        successful_tab = QWidget()
        successful_layout = QVBoxLayout(successful_tab)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(['Payload', 'Injection', 'Confidence', 'Time', 'Status'])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1, 5):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                alternate-background-color: #161b22;
                gridline-color: #30363d;
                border: 2px solid #2ea043;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QTableWidget::item { padding: 3px; }
            QHeaderView::section { background: #161b22; color: #2ea043; padding: 4px; font-weight: bold; }
        """)
        
        successful_layout.addWidget(self.results_table)
        
        all_tests_tab = QWidget()
        all_tests_layout = QVBoxLayout(all_tests_tab)
        
        self.all_tests_table = QTableWidget()
        self.all_tests_table.setColumnCount(6)
        self.all_tests_table.setHorizontalHeaderLabels(['Payload', 'Code', 'Time', 'Blocked', 'Status', 'Signal'])
        
        header2 = self.all_tests_table.horizontalHeader()
        header2.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1, 6):
            header2.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        
        self.all_tests_table.setAlternatingRowColors(True)
        self.all_tests_table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                alternate-background-color: #161b22;
                gridline-color: #30363d;
                border: 2px solid #58a6ff;
                border-radius: 4px;
                color: #c9d1d9;
            }
            QTableWidget::item { padding: 3px; font-size: 8pt; }
            QHeaderView::section { background: #161b22; color: #58a6ff; padding: 4px; font-weight: bold; }
        """)
        
        all_tests_layout.addWidget(self.all_tests_table)
        
        tabs.addTab(successful_tab, '✓ Bypassed')
        tabs.addTab(all_tests_tab, '📊 All')
        
        main_layout.addWidget(tabs, 1)
        self.setLayout(main_layout)
    
    def start_bypass(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, 'Error', 'Enter URL')
            return
        
        if not target.startswith('http'):
            target = 'https://' + target
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.target_input.setEnabled(False)
        
        self.results_table.setRowCount(0)
        self.all_tests_table.setRowCount(0)
        self.bypassed_payloads.clear()
        self.tested_payloads.clear()
        
        self.bypass_thread = WAFBypassThread(target, self.vector_combo.currentText())
        self.bypass_thread.status_updated.connect(self.update_status)
        self.bypass_thread.test_payload_live.connect(self.add_all_test)
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
    
    def clear_all(self):
        self.results_table.setRowCount(0)
        self.all_tests_table.setRowCount(0)
        self.bypassed_payloads.clear()
        self.tested_payloads.clear()
        self.bypassed_label.setText('✓ 0')
        self.tested_label.setText('📊 0')
        self.success_rate.setText('📈 0%')
        self.speed_label.setText('⚡ 0/s')
        self.status_label.setText('🟢 Ready')
    
    def update_status(self, text: str):
        self.status_label.setText(text)
        if '/' in text and '|' in text:
            try:
                parts = text.split('|')
                self.speed_label.setText(f"⚡ {parts[2].strip().split('/')[0]}/s")
            except:
                pass
    
    def add_all_test(self, result: dict):
        self.tested_payloads.append(result)
        
        if self.all_tests_table.rowCount() >= 1000:
            self.all_tests_table.removeRow(0)
        
        row = self.all_tests_table.rowCount()
        self.all_tests_table.insertRow(row)
        
        items = [
            result['payload'][:40],
            str(result.get('response_status', '-')),
            f"{result['response_time']:.2f}s",
            'Y' if result['is_blocked'] else 'N',
            '✓' if result['is_bypassed'] else '✗',
            result['detection_signals'][0][:20] if result['detection_signals'] else '-'
        ]
        
        for i, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setFont(QFont('Arial', 7))
            if i == 4:
                color = '#2ea043' if result['is_bypassed'] else '#d1242f'
                item.setForeground(QColor(color))
            self.all_tests_table.setItem(row, i, item)
        
        self.tested_label.setText(f'📊 {len(self.tested_payloads)}')
        self.update_success_rate()
    
    def add_bypass(self, bypass_data: dict):
        self.bypassed_payloads.append(bypass_data)
        
        if self.results_table.rowCount() >= 500:
            self.results_table.removeRow(0)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        items = [
            bypass_data['payload'][:50],
            bypass_data['injection_point'],
            f"{bypass_data['confidence']*100:.0f}%",
            f"{bypass_data['response_time']:.2f}s",
            '✓ BYPASSED'
        ]
        
        for i, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setFont(QFont('Arial', 8))
            if i == 4:
                item.setForeground(QColor('#2ea043'))
            self.results_table.setItem(row, i, item)
        
        self.bypassed_label.setText(f'✓ {len(self.bypassed_payloads)}')
        self.update_success_rate()
    
    def update_success_rate(self):
        if self.tested_payloads:
            rate = len(self.bypassed_payloads) / len(self.tested_payloads) * 100
            self.success_rate.setText(f'📈 {rate:.1f}%')
    
    def bypass_finished(self, results: list):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        
        QMessageBox.information(
            self,
            'Complete',
            f'✓ {len(self.bypassed_payloads)}\n'
            f'📊 {len(self.tested_payloads)}\n'
            f'📈 {len(self.bypassed_payloads)/max(len(self.tested_payloads),1)*100:.1f}%'
        )
