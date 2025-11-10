from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QGroupBox, QFormLayout, QProgressBar)
from PyQt6.QtCore import pyqtSignal, QThread, pyqtSlot
from scanners.subdomain_scanner import SubdomainScanner

class SubdomainTab(QWidget):
    scan_started = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.scanner = SubdomainScanner()
        self.results = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)
        
        input_group = QGroupBox('Domain Configuration')
        input_layout = QFormLayout()
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText('Enter domain (e.g., example.com)')
        input_layout.addRow('Domain:', self.domain_input)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton('🔍 Start Enumeration')
        self.scan_button.setMinimumHeight(40)
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.export_button = QPushButton('💾 Export Results')
        self.export_button.setMinimumHeight(40)
        self.export_button.clicked.connect(self.export_results)
        button_layout.addWidget(self.export_button)
        
        self.clear_button = QPushButton('🗑️ Clear')
        self.clear_button.setMinimumHeight(40)
        self.clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_button)
        
        main_layout.addLayout(button_layout)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(['Subdomain', 'IP Address', 'Status', 'Title'])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        main_layout.addWidget(self.results_table)
        
        self.setLayout(main_layout)
    
    def start_scan(self):
        domain = self.domain_input.text().strip()
        if not domain:
            return
        
        self.scan_started.emit(domain)
        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)
        
        self.results = self.scanner.scan(domain)
        self.display_results()
        self.progress_bar.setValue(100)
        
        self.scan_completed.emit(self.results)
    
    def display_results(self):
        self.results_table.setRowCount(len(self.results))
        
        for row_idx, result in enumerate(self.results):
            subdomain_item = QTableWidgetItem(result.get('subdomain', ''))
            ips_item = QTableWidgetItem(', '.join(result.get('ips', [])))
            status_item = QTableWidgetItem(str(result.get('status_code', 'N/A')))
            title_item = QTableWidgetItem(result.get('title', ''))
            
            self.results_table.setItem(row_idx, 0, subdomain_item)
            self.results_table.setItem(row_idx, 1, ips_item)
            self.results_table.setItem(row_idx, 2, status_item)
            self.results_table.setItem(row_idx, 3, title_item)
    
    def export_results(self):
        if not self.results:
            return
        
        import json
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Results', 'subdomains.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
    
    def clear_results(self):
        self.results = []
        self.results_table.setRowCount(0)
        self.domain_input.clear()
        self.progress_bar.setValue(0)