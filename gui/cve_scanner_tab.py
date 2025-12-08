"""CVE Scanner Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QFileDialog, QComboBox)
from PyQt6.QtCore import QThread, pyqtSignal
from scanners.cve_scanner import CVEScanner
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors, get_table_stylesheet
)
from typing import List, Dict, Any, Optional
import json


class CVEScanThread(QThread):
    progress_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    scan_error = pyqtSignal(str)
    
    def __init__(self, target: str, scan_type: str) -> None:
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.scanner = CVEScanner()
    
    def run(self) -> None:
        try:
            self.progress_updated.emit(f"Scanning for CVEs on {self.target}...")
            results = self.scanner.scan(self.target, self.scan_type)
            self.scan_completed.emit(results)
        except Exception as e:
            self.scan_error.emit(f"Scan error: {str(e)}")


class CVEScannerTab(DesignMainWidget):
    
    def __init__(self) -> None:
        super().__init__()
        self.header.set_title("CVE Scanner")
        self.header.set_subtitle("Search for known vulnerabilities affecting your target")
        
        self.scanner = CVEScanner()
        self.results: List[Dict[str, Any]] = []
        self.scan_thread: Optional[CVEScanThread] = None
        self.init_ui()
    
    def init_ui(self) -> None:
        # Configuration section
        config_section = self.add_section("Configuration")
        
        label1 = QLabel('Target or Software:')
        label1.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('e.g., example.com or Apache 2.4.50')
        self.target_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        
        config_section.content_layout.addWidget(label1)
        config_section.content_layout.addWidget(self.target_input)
        
        label2 = QLabel('Scan Type:')
        label2.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        self.scan_type_combo.addItems(['All', 'Critical', 'High', 'Medium', 'Low'])
        
        config_section.content_layout.addWidget(label2)
        config_section.content_layout.addWidget(self.scan_type_combo)
        
        # Action buttons
        action_section = self.add_section("Actions")
        button_layout = QHBoxLayout()
        
        scan_button = DesignButton('Start CVE Scan', 'primary')
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
        results_section = self.add_section("CVEs Found")
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(['CVE ID', 'Severity', 'Description', 'Score'])
        self.results_table.setStyleSheet(get_table_stylesheet())
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        results_section.content_layout.addWidget(self.results_table)
        
        self.add_stretch()
    
    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, 'Warning', 'Please enter target or software name')
            return
        
        scan_type = self.scan_type_combo.currentText()
        
        self.results_table.setRowCount(0)
        
        self.scan_thread = CVEScanThread(target, scan_type)
        self.scan_thread.scan_completed.connect(self.display_results)
        self.scan_thread.scan_error.connect(lambda e: QMessageBox.critical(self, 'Error', e))
        self.scan_thread.start()
    
    def display_results(self, results: List[Dict[str, Any]]):
        self.results = results
        self.results_table.setRowCount(len(results))
        
        for row_idx, result in enumerate(results):
            cve_item = QTableWidgetItem(result.get('cve_id', ''))
            severity_item = QTableWidgetItem(result.get('severity', ''))
            desc_item = QTableWidgetItem(result.get('description', ''))
            score_item = QTableWidgetItem(str(result.get('score', '')))
            
            self.results_table.setItem(row_idx, 0, cve_item)
            self.results_table.setItem(row_idx, 1, severity_item)
            self.results_table.setItem(row_idx, 2, desc_item)
            self.results_table.setItem(row_idx, 3, score_item)
    
    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Results', 'cve_results.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            QMessageBox.information(self, 'Success', 'Results exported successfully')
    
    def clear_results(self):
        self.results = []
        self.results_table.setRowCount(0)
        self.target_input.clear()
