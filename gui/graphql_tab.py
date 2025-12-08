"""GraphQL Scanner Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QFileDialog)
from PyQt6.QtCore import pyqtSignal
from scanners.graphql_scanner import GraphQLScanner
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors, get_table_stylesheet
)
import json


class GraphQLTab(DesignMainWidget):
    def __init__(self):
        super().__init__()
        self.header.set_title("GraphQL Scanner")
        self.header.set_subtitle("Test GraphQL endpoints for vulnerabilities")
        
        self.scanner = GraphQLScanner()
        self.results = []
        self.init_ui()
    
    def init_ui(self):
        # Configuration section
        config_section = self.add_section("Configuration")
        
        label = QLabel('GraphQL Endpoint URL:')
        label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.graphql_url_input = QLineEdit()
        self.graphql_url_input.setPlaceholderText('e.g., http://example.com/graphql')
        self.graphql_url_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        
        config_section.content_layout.addWidget(label)
        config_section.content_layout.addWidget(self.graphql_url_input)
        
        # Action buttons section
        action_section = self.add_section("Actions")
        button_layout = QHBoxLayout()
        
        scan_button = DesignButton('Start GraphQL Scan', 'primary')
        scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(scan_button)
        
        export_button = DesignButton('Export Results', 'secondary')
        export_button.clicked.connect(self.export_results)
        button_layout.addWidget(export_button)
        
        clear_button = DesignButton('Clear', 'danger')
        clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(clear_button)
        
        button_layout.addStretch()
        action_section.content_layout.addLayout(button_layout)
        
        # Results section
        results_section = self.add_section("Vulnerabilities Found")
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(['Vulnerability Type', 'Severity', 'Description'])
        self.results_table.setStyleSheet(get_table_stylesheet())
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        results_section.content_layout.addWidget(self.results_table)
        
        self.add_stretch()
    
    def start_scan(self):
        graphql_url = self.graphql_url_input.text().strip()
        if not graphql_url:
            QMessageBox.warning(self, 'Warning', 'Please enter GraphQL endpoint URL')
            return
        
        self.results_table.setRowCount(0)
        
        try:
            self.results = self.scanner.scan(graphql_url)
            self.display_results()
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Scan failed: {str(e)}')
    
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
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Results', 'graphql_results.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            QMessageBox.information(self, 'Success', 'Results exported successfully')
    
    def clear_results(self):
        self.results = []
        self.results_table.setRowCount(0)
        self.graphql_url_input.clear()
