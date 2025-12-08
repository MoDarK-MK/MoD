"""CORS Misconfiguration Scanner Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QTextEdit, QFileDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from scanners.cors_scanner import CORSScanner
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors, get_table_stylesheet
)
from typing import List, Dict, Any, Optional
import json


class CORSScanThread(QThread):
    """Worker thread for CORS scanning."""
    
    progress_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    scan_error = pyqtSignal(str)
    
    def __init__(self, target_url: str, custom_origins: Optional[List[str]] = None) -> None:
        super().__init__()
        self.target_url = target_url
        self.custom_origins = custom_origins
        self.scanner = CORSScanner()
    
    def run(self) -> None:
        """Run the scan."""
        try:
            self.progress_updated.emit(f"Starting CORS scan on {self.target_url}...")
            results = self.scanner.scan(self.target_url, self.custom_origins)
            self.progress_updated.emit(f"Scan completed. Found {len(results)} results.")
            self.scan_completed.emit(results)
        except Exception as e:
            self.scan_error.emit(f"Scan error: {str(e)}")


class CORSTab(DesignMainWidget):
    """Tab for CORS misconfiguration testing."""
    
    def __init__(self) -> None:
        super().__init__()
        self.header.set_title("CORS Tester")
        self.header.set_subtitle("Test for CORS misconfigurations and vulnerabilities")
        
        self.scanner = CORSScanner()
        self.results: List[Dict[str, Any]] = []
        self.scan_thread: Optional[CORSScanThread] = None
        self.init_ui()
    
    def init_ui(self) -> None:
        """Initialize user interface."""
        # Input configuration section
        input_section = self.add_section("Configuration")
        
        label = QLabel('Target URL:')
        label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        self.target_url_input = QLineEdit()
        self.target_url_input.setPlaceholderText('e.g., http://example.com')
        self.target_url_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        input_section.content_layout.addWidget(label)
        input_section.content_layout.addWidget(self.target_url_input)
        
        label2 = QLabel('Custom Origins (one per line):')
        label2.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        self.origins_input = QTextEdit()
        self.origins_input.setPlaceholderText('Leave empty for default origins')
        self.origins_input.setMaximumHeight(100)
        self.origins_input.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
            }}
        """)
        input_section.content_layout.addWidget(label2)
        input_section.content_layout.addWidget(self.origins_input)
        
        # Control buttons section
        button_section = self.add_section("Actions")
        button_layout = QHBoxLayout()
        
        scan_button = DesignButton('Start CORS Scan', 'primary')
        scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(scan_button)
        
        poc_button = DesignButton('Generate PoC', 'secondary')
        poc_button.clicked.connect(self.generate_poc)
        button_layout.addWidget(poc_button)
        
        export_button = DesignButton('Export Results', 'secondary')
        export_button.clicked.connect(self.export_results)
        button_layout.addWidget(export_button)
        
        button_layout.addStretch()
        button_section.content_layout.addLayout(button_layout)
        
        # Results section
        results_section = self.add_section("Results")
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(['Origin', 'Status', 'Credentials', 'Methods'])
        self.results_table.setStyleSheet(get_table_stylesheet())
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        results_section.content_layout.addWidget(self.results_table)
        
        self.add_stretch()
    
    def start_scan(self):
        target_url = self.target_url_input.text().strip()
        if not target_url:
            QMessageBox.warning(self, 'Warning', 'Please enter target URL')
            return
        
        custom_origins = [line.strip() for line in self.origins_input.toPlainText().split('\n') if line.strip()]
        
        self.results_table.setRowCount(0)
        
        self.scan_thread = CORSScanThread(target_url, custom_origins if custom_origins else None)
        self.scan_thread.scan_completed.connect(self.display_results)
        self.scan_thread.scan_error.connect(lambda e: QMessageBox.critical(self, 'Error', e))
        self.scan_thread.start()
    
    def display_results(self, results: List[Dict[str, Any]]):
        self.results = results
        self.results_table.setRowCount(len(results))
        
        for row_idx, result in enumerate(results):
            origin_item = QTableWidgetItem(result.get('origin', ''))
            status_item = QTableWidgetItem(result.get('status', ''))
            creds_item = QTableWidgetItem(str(result.get('credentials', False)))
            methods_item = QTableWidgetItem(', '.join(result.get('methods', [])))
            
            self.results_table.setItem(row_idx, 0, origin_item)
            self.results_table.setItem(row_idx, 1, status_item)
            self.results_table.setItem(row_idx, 2, creds_item)
            self.results_table.setItem(row_idx, 3, methods_item)
    
    def generate_poc(self):
        if not self.results:
            QMessageBox.warning(self, 'Warning', 'No results to generate PoC from')
            return
        
        poc_code = "// CORS PoC - Proof of Concept\n"
        for result in self.results:
            poc_code += f"\n// Origin: {result.get('origin', '')}\n"
            poc_code += "fetch('{}', {{\n".format(self.target_url_input.text())
            poc_code += "  credentials: 'include',\n"
            poc_code += "  headers: {'Content-Type': 'application/json'}\n"
            poc_code += "});\n"
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Save PoC', 'cors_poc.js', 'JavaScript Files (*.js)')
        if filename:
            with open(filename, 'w') as f:
                f.write(poc_code)
            QMessageBox.information(self, 'Success', 'PoC generated successfully')
    
    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Results', 'cors_results.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            QMessageBox.information(self, 'Success', 'Results exported successfully')
