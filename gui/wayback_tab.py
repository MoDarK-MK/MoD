from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QGroupBox, QFormLayout, QTextEdit,
                             QProgressBar, QFileDialog, QMessageBox, QSpinBox)
from PyQt6.QtCore import pyqtSignal
from utils.wayback_client import WaybackClient
import json

class WaybackTab(QWidget):
    fetch_started = pyqtSignal(str)
    fetch_completed = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.wayback_client = WaybackClient()
        self.urls = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)
        
        input_group = QGroupBox('Wayback Machine Configuration')
        input_layout = QFormLayout()
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText('Enter domain (e.g., example.com)')
        input_layout.addRow('Domain:', self.domain_input)
        
        self.limit_spinbox = QSpinBox()
        self.limit_spinbox.setRange(1, 5000)
        self.limit_spinbox.setValue(1000)
        input_layout.addRow('Limit:', self.limit_spinbox)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        filter_group = QGroupBox('Filter URLs')
        filter_layout = QFormLayout()
        
        self.extension_input = QLineEdit()
        self.extension_input.setPlaceholderText('Extensions (e.g., .php,.asp,.aspx)')
        filter_layout.addRow('Extensions:', self.extension_input)
        
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText('Keywords (e.g., admin,login,api)')
        filter_layout.addRow('Keywords:', self.keyword_input)
        
        filter_group.setLayout(filter_layout)
        main_layout.addWidget(filter_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        button_layout = QHBoxLayout()
        
        self.fetch_button = QPushButton('🔍 Fetch URLs')
        self.fetch_button.setMinimumHeight(40)
        self.fetch_button.clicked.connect(self.fetch_urls)
        button_layout.addWidget(self.fetch_button)
        
        self.filter_button = QPushButton('🔎 Apply Filter')
        self.filter_button.setMinimumHeight(40)
        self.filter_button.clicked.connect(self.apply_filter)
        button_layout.addWidget(self.filter_button)
        
        self.export_button = QPushButton('💾 Export URLs')
        self.export_button.setMinimumHeight(40)
        self.export_button.clicked.connect(self.export_urls)
        button_layout.addWidget(self.export_button)
        
        self.clear_button = QPushButton('🗑️ Clear')
        self.clear_button.setMinimumHeight(40)
        self.clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_button)
        
        main_layout.addLayout(button_layout)
        
        self.urls_output = QTextEdit()
        self.urls_output.setReadOnly(True)
        main_layout.addWidget(self.urls_output)
        
        self.setLayout(main_layout)
    
    def fetch_urls(self):
        domain = self.domain_input.text().strip()
        if not domain:
            return
        
        self.fetch_started.emit(domain)
        self.progress_bar.setValue(0)
        self.urls_output.clear()
        
        urls = self.wayback_client.get_urls(domain, self.limit_spinbox.value())
        self.urls = urls
        
        self.display_urls(urls)
        self.progress_bar.setValue(100)
        
        self.fetch_completed.emit(urls)
    
    def apply_filter(self):
        if not self.urls:
            return
        
        extensions_text = self.extension_input.text().strip()
        keywords_text = self.keyword_input.text().strip()
        
        filtered_urls = self.urls.copy()
        
        if extensions_text:
            extensions = [ext.strip() for ext in extensions_text.split(',')]
            filtered_urls = self.wayback_client.filter_urls_by_extension(filtered_urls, extensions)
        
        if keywords_text:
            keywords = [kw.strip() for kw in keywords_text.split(',')]
            filtered_urls = self.wayback_client.filter_urls_by_keyword(filtered_urls, keywords)
        
        self.display_urls(filtered_urls)
    
    def display_urls(self, urls: list):
        output_text = '\n'.join(urls)
        self.urls_output.setText(output_text)
    
    def export_urls(self):
        if not self.urls:
            QMessageBox.warning(self, 'Warning', 'No URLs to export')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export URLs', 'wayback_urls.txt', 'Text Files (*.txt)')
        if filename:
            with open(filename, 'w') as f:
                f.write('\n'.join(self.urls))
            QMessageBox.information(self, 'Success', f'URLs exported to {filename}')
    
    def clear_results(self):
        self.urls = []
        self.urls_output.clear()
        self.domain_input.clear()
        self.extension_input.clear()
        self.keyword_input.clear()
        self.progress_bar.setValue(0)