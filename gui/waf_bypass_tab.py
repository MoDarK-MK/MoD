"""WAF Bypass Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QFileDialog, QComboBox)
from PyQt6.QtCore import QThread, pyqtSignal
from scanners.waf_bypass_engine_v2 import EnhancedWAFBypassEngine
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors, get_table_stylesheet
)
from typing import List, Dict, Any, Optional
import json


class WAFBypassThread(QThread):
    progress_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    scan_error = pyqtSignal(str)
    
    def __init__(self, target_url: str, payload: str) -> None:
        super().__init__()
        self.target_url = target_url
        self.payload = payload
        self.engine = EnhancedWAFBypassEngine()
    
    def run(self) -> None:
        try:
            self.progress_updated.emit(f"Testing WAF bypass techniques on {self.target_url}...")
            results = self.engine.test_bypass(self.target_url, self.payload)
            self.scan_completed.emit(results)
        except Exception as e:
            self.scan_error.emit(f"Scan error: {str(e)}")


class WAFBypassTab(DesignMainWidget):
    
    def __init__(self) -> None:
        super().__init__()
        self.header.set_title("WAF Bypass")
        self.header.set_subtitle("Test Web Application Firewall evasion techniques")
        
        self.engine = EnhancedWAFBypassEngine()
        self.results: List[Dict[str, Any]] = []
        self.scan_thread: Optional[WAFBypassThread] = None
        self.init_ui()
    
    def init_ui(self) -> None:
        # Configuration section
        config_section = self.add_section("Configuration")
        
        label1 = QLabel('Target URL:')
        label1.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('e.g., http://example.com/search?q=')
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
        
        label2 = QLabel('Test Payload:')
        label2.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.payload_input = QLineEdit()
        self.payload_input.setPlaceholderText('e.g., <script>alert(1)</script>')
        self.payload_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
                min-height: 32px;
            }}
        """)
        
        config_section.content_layout.addWidget(label2)
        config_section.content_layout.addWidget(self.payload_input)
        
        # Action buttons
        action_section = self.add_section("Actions")
        button_layout = QHBoxLayout()
        
        test_button = DesignButton('Test WAF Bypass', 'primary')
        test_button.clicked.connect(self.start_test)
        button_layout.addWidget(test_button)
        
        export_button = DesignButton('Export Results', 'secondary')
        export_button.clicked.connect(self.export_results)
        button_layout.addWidget(export_button)
        
        clear_button = DesignButton('Clear', 'danger')
        clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(clear_button)
        
        button_layout.addStretch()
        action_section.content_layout.addLayout(button_layout)
        
        # Results section
        results_section = self.add_section("Bypass Techniques Tested")
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(['Technique', 'Payload', 'Bypassed', 'Response'])
        self.results_table.setStyleSheet(get_table_stylesheet())
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        results_section.content_layout.addWidget(self.results_table)
        
        self.add_stretch()
    
    def start_test(self):
        target = self.target_input.text().strip()
        payload = self.payload_input.text().strip()
        
        if not target or not payload:
            QMessageBox.warning(self, 'Warning', 'Please enter target URL and payload')
            return
        
        self.results_table.setRowCount(0)
        
        self.scan_thread = WAFBypassThread(target, payload)
        self.scan_thread.scan_completed.connect(self.display_results)
        self.scan_thread.scan_error.connect(lambda e: QMessageBox.critical(self, 'Error', e))
        self.scan_thread.start()
    
    def display_results(self, results: List[Dict[str, Any]]):
        self.results = results
        self.results_table.setRowCount(len(results))
        
        for row_idx, result in enumerate(results):
            technique_item = QTableWidgetItem(result.get('technique', ''))
            payload_item = QTableWidgetItem(result.get('payload', ''))
            bypassed_item = QTableWidgetItem(str(result.get('bypassed', False)))
            response_item = QTableWidgetItem(result.get('response', ''))
            
            self.results_table.setItem(row_idx, 0, technique_item)
            self.results_table.setItem(row_idx, 1, payload_item)
            self.results_table.setItem(row_idx, 2, bypassed_item)
            self.results_table.setItem(row_idx, 3, response_item)
    
    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Results', 'waf_bypass_results.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            QMessageBox.information(self, 'Success', 'Results exported successfully')
    
    def clear_results(self):
        self.results = []
        self.results_table.setRowCount(0)
        self.target_input.clear()
        self.payload_input.clear()
