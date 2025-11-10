from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QGroupBox, QFormLayout, QMessageBox)
from PyQt6.QtCore import pyqtSignal
from scanners.graphql_scanner import GraphQLScanner

class GraphQLTab(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner = GraphQLScanner()
        self.results = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)
        
        input_group = QGroupBox('GraphQL Configuration')
        input_layout = QFormLayout()
        
        self.graphql_url_input = QLineEdit()
        self.graphql_url_input.setPlaceholderText('Enter GraphQL endpoint URL')
        input_layout.addRow('Endpoint:', self.graphql_url_input)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        button_layout = QHBoxLayout()
        
        scan_button = QPushButton('🔍 Start GraphQL Scan')
        scan_button.setMinimumHeight(40)
        scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(scan_button)
        
        export_button = QPushButton('💾 Export Results')
        export_button.setMinimumHeight(40)
        export_button.clicked.connect(self.export_results)
        button_layout.addWidget(export_button)
        
        clear_button = QPushButton('🗑️ Clear')
        clear_button.setMinimumHeight(40)
        clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(clear_button)
        
        main_layout.addLayout(button_layout)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(['Vulnerability Type', 'Severity', 'Description'])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        main_layout.addWidget(self.results_table)
        
        self.setLayout(main_layout)
    
    def start_scan(self):
        graphql_url = self.graphql_url_input.text().strip()
        if not graphql_url:
            QMessageBox.warning(self, 'Warning', 'Please enter GraphQL endpoint URL')
            return
        
        self.results_table.setRowCount(0)
        
        self.results = self.scanner.scan(graphql_url)
        self.display_results()
    
    def display_results(self):
        self.results_table.setRowCount(len(self.results))
        
        for row_idx, result in enumerate(self.results):
            type_item = QTableWidgetItem(result.get('type', ''))
            severity_item = QTableWidgetItem(result.get('severity', ''))
            desc_item = QTableWidgetItem(result.get('description', ''))
            
            self.results_table.setItem(row_idx, 0, type_item)
            self.results_table.setItem(row_idx, 1, severity_item)
            self.results_table.setItem(row_idx, 2, desc_item)
    
    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        import json
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Results', 'graphql_results.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
    
    def clear_results(self):
        self.results = []
        self.results_table.setRowCount(0)
        self.graphql_url_input.clear()