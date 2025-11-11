# gui/wayback_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QHeaderView, QLabel,
                             QLineEdit, QGroupBox, QProgressBar, QMessageBox,
                             QComboBox, QTextEdit)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from scanners.wayback_scanner import WaybackScanner
from typing import List, Dict


class WaybackFetchThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    url_found = pyqtSignal(dict)
    fetch_completed = pyqtSignal(list)
    
    def __init__(self, domain: str, timeout: int = 15):
        super().__init__()
        self.domain = domain
        self.timeout = timeout
        self.should_stop = False
    
    def run(self):
        try:
            self.status_updated.emit(f'Fetching URLs for {self.domain}...')
            self.progress_updated.emit(10)
            
            scanner = WaybackScanner(timeout=self.timeout)
            
            self.status_updated.emit('Querying Wayback Machine...')
            self.progress_updated.emit(30)
            
            urls = scanner.fetch_urls(self.domain)
            
            self.progress_updated.emit(60)
            
            for idx, url_info in enumerate(urls):
                if self.should_stop:
                    break
                
                self.url_found.emit(url_info)
                
                progress = 60 + int((idx + 1) / max(len(urls), 1) * 35)
                self.progress_updated.emit(min(progress, 95))
            
            self.progress_updated.emit(100)
            self.status_updated.emit(f'Completed - Found {len(urls)} URLs')
            self.fetch_completed.emit(urls)
            
        except Exception as e:
            self.status_updated.emit(f'Error: {str(e)}')
            self.fetch_completed.emit([])
    
    def stop(self):
        self.should_stop = True


class WaybackTab(QWidget):
    fetch_started = pyqtSignal(str)
    fetch_completed = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.fetch_thread = None
        self.urls = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        title = QLabel('WAYBACK MACHINE URL FETCHER')
        title.setStyleSheet("""
            QLabel {
                font-size: 20pt;
                font-weight: bold;
                color: #58a6ff;
            }
        """)
        main_layout.addWidget(title)
        
        input_group = QGroupBox('TARGET DOMAIN')
        input_group.setStyleSheet("""
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
        
        input_layout = QVBoxLayout()
        
        domain_layout = QHBoxLayout()
        domain_label = QLabel('DOMAIN:')
        domain_label.setStyleSheet('color: #c9d1d9; font-weight: bold; min-width: 100px;')
        domain_layout.addWidget(domain_label)
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText('example.com')
        self.domain_input.setMinimumHeight(40)
        self.domain_input.setStyleSheet("""
            QLineEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 11pt;
            }
            QLineEdit:focus {
                border: 2px solid #1f6feb;
            }
        """)
        domain_layout.addWidget(self.domain_input, 1)
        input_layout.addLayout(domain_layout)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        button_layout = QHBoxLayout()
        
        self.fetch_button = QPushButton('FETCH URLS')
        self.fetch_button.setMinimumHeight(50)
        self.fetch_button.clicked.connect(self.start_fetch)
        self.fetch_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #238636, stop:1 #1a6b2c);
                color: white;
                border: 2px solid #2ea043;
                border-radius: 8px;
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
        button_layout.addWidget(self.fetch_button)
        
        self.stop_button = QPushButton('STOP')
        self.stop_button.setMinimumHeight(50)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_fetch)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #da3633, stop:1 #b92222);
                color: white;
                border: 2px solid #f85149;
                border-radius: 8px;
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
        button_layout.addWidget(self.stop_button)
        
        export_button = QPushButton('EXPORT')
        export_button.setMinimumHeight(50)
        export_button.clicked.connect(self.export_urls)
        export_button.setStyleSheet("""
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
                                           stop:0 #1f6feb, stop:1 #0969da);
            }
        """)
        button_layout.addWidget(export_button)
        
        main_layout.addLayout(button_layout)
        
        progress_group = QGroupBox('PROGRESS')
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
        
        self.status_label = QLabel('Ready to fetch URLs')
        self.status_label.setStyleSheet('color: #58a6ff; font-weight: bold;')
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
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                           stop:0 #238636, stop:1 #2ea043);
                border-radius: 4px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        self.count_label = QLabel('URLs Found: 0')
        self.count_label.setStyleSheet('color: #c9d1d9; font-weight: bold;')
        progress_layout.addWidget(self.count_label)
        
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)
        
        results_group = QGroupBox('ARCHIVED URLS')
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
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(['URL', 'Timestamp', 'Status', 'Source'])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
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
                padding: 6px;
            }
            QTableWidget::item:selected {
                background: #1f6feb;
                color: white;
            }
            QHeaderView::section {
                background: #161b22;
                color: #c9d1d9;
                padding: 8px;
                border: none;
                border-right: 1px solid #30363d;
                font-weight: bold;
            }
        """)
        
        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)
        main_layout.addWidget(results_group, 1)
        
        self.setLayout(main_layout)
    
    def start_fetch(self):
        domain = self.domain_input.text().strip()
        
        if not domain:
            QMessageBox.warning(self, 'Error', 'Please enter a domain')
            return
        
        self.fetch_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.domain_input.setEnabled(False)
        self.results_table.setRowCount(0)
        self.urls.clear()
        self.progress_bar.setValue(0)
        
        self.fetch_started.emit(domain)
        
        self.fetch_thread = WaybackFetchThread(domain)
        self.fetch_thread.progress_updated.connect(self.update_progress)
        self.fetch_thread.status_updated.connect(self.update_status)
        self.fetch_thread.url_found.connect(self.add_url)
        self.fetch_thread.fetch_completed.connect(self.fetch_finished)
        self.fetch_thread.start()
    
    def stop_fetch(self):
        if self.fetch_thread:
            self.fetch_thread.stop()
            self.fetch_thread.wait()
        
        self.fetch_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.domain_input.setEnabled(True)
        self.status_label.setText('Fetch stopped')
    
    def update_progress(self, value: int):
        self.progress_bar.setValue(value)
    
    def update_status(self, text: str):
        self.status_label.setText(text)
    
    def add_url(self, url_info: dict):
        self.urls.append(url_info)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        url_item = QTableWidgetItem(url_info.get('url', ''))
        url_item.setFont(QFont('Courier New', 9))
        self.results_table.setItem(row, 0, url_item)
        
        timestamp_item = QTableWidgetItem(url_info.get('timestamp', ''))
        timestamp_item.setFont(QFont('Arial', 9))
        self.results_table.setItem(row, 1, timestamp_item)
        
        status_item = QTableWidgetItem(url_info.get('status', ''))
        status_item.setFont(QFont('Arial', 9))
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        if url_info.get('status', '') == '200':
            status_item.setForeground(QColor('#2ea043'))
        elif url_info.get('status', '').startswith('4'):
            status_item.setForeground(QColor('#d29922'))
        elif url_info.get('status', '').startswith('5'):
            status_item.setForeground(QColor('#f85149'))
        
        self.results_table.setItem(row, 2, status_item)
        
        source_item = QTableWidgetItem(url_info.get('source', ''))
        source_item.setFont(QFont('Arial', 9))
        source_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row, 3, source_item)
        
        self.count_label.setText(f'URLs Found: {len(self.urls)}')
    
    def fetch_finished(self, results: list):
        self.fetch_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.domain_input.setEnabled(True)
        self.progress_bar.setValue(100)
        
        self.fetch_completed.emit(results)
        
        if results:
            QMessageBox.information(self, 'Success', f'Found {len(results)} URLs from Wayback Machine')
        else:
            QMessageBox.warning(self, 'No Results', 'No archived URLs found for this domain')
    
    def export_urls(self):
        if not self.urls:
            QMessageBox.warning(self, 'No Data', 'No URLs to export')
            return
        
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            'Save URLs',
            'wayback_urls.txt',
            'Text Files (*.txt);;All Files (*)'
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    for url_info in self.urls:
                        f.write(f"{url_info['url']}\n")
                
                QMessageBox.information(self, 'Success', f'Exported {len(self.urls)} URLs to {filename}')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to export: {str(e)}')
