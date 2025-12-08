"""WebSocket Scanner Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QTextEdit, QFileDialog)
from PyQt6.QtCore import QThread, pyqtSignal
from scanners.websocket_scanner import WebSocketScanner
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors, get_table_stylesheet
)
from typing import List, Dict, Any, Optional
import json


class WebSocketScanThread(QThread):
    progress_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    scan_error = pyqtSignal(str)
    
    def __init__(self, target_url: str) -> None:
        super().__init__()
        self.target_url = target_url
        self.scanner = WebSocketScanner()
    
    def run(self) -> None:
        try:
            self.progress_updated.emit(f"Scanning {self.target_url}...")
            results = self.scanner.scan(self.target_url)
            self.scan_completed.emit(results)
        except Exception as e:
            self.scan_error.emit(f"Scan error: {str(e)}")


class WebSocketTab(DesignMainWidget):
    
    def __init__(self) -> None:
        super().__init__()
        self.header.set_title("WebSocket Scanner")
        self.header.set_subtitle("Test WebSocket endpoints for vulnerabilities")
        
        self.scanner = WebSocketScanner()
        self.results: List[Dict[str, Any]] = []
        self.scan_thread: Optional[WebSocketScanThread] = None
        self.init_ui()
    
    def init_ui(self) -> None:
        # Configuration section
        config_section = self.add_section("Configuration")
        
        label = QLabel('WebSocket URL:')
        label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.ws_url_input = QLineEdit()
        self.ws_url_input.setPlaceholderText('e.g., ws://example.com:8080/ws')
        self.ws_url_input.setStyleSheet(f"""
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
        config_section.content_layout.addWidget(self.ws_url_input)
        
        # Message input
        msg_label = QLabel('Test Messages (one per line):')
        msg_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText('Messages to send to WebSocket')
        self.message_input.setMaximumHeight(80)
        self.message_input.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.SM}px;
            }}
        """)
        
        config_section.content_layout.addWidget(msg_label)
        config_section.content_layout.addWidget(self.message_input)
        
        # Action buttons
        action_section = self.add_section("Actions")
        button_layout = QHBoxLayout()
        
        scan_button = DesignButton('Start WebSocket Scan', 'primary')
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
        results_section = self.add_section("Vulnerabilities")
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(['Issue Type', 'Severity', 'Description'])
        self.results_table.setStyleSheet(get_table_stylesheet())
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        results_section.content_layout.addWidget(self.results_table)
        
        self.add_stretch()
    
    def start_scan(self):
        ws_url = self.ws_url_input.text().strip()
        if not ws_url:
            QMessageBox.warning(self, 'Warning', 'Please enter WebSocket URL')
            return
        
        messages = [msg.strip() for msg in self.message_input.toPlainText().split('\n') if msg.strip()]
        
        self.results_table.setRowCount(0)
        
        self.scan_thread = WebSocketScanThread(ws_url)
        self.scan_thread.scan_completed.connect(self.display_results)
        self.scan_thread.scan_error.connect(lambda e: QMessageBox.critical(self, 'Error', e))
        self.scan_thread.start()
    
    def display_results(self, results: List[Dict[str, Any]]):
        self.results = results
        self.results_table.setRowCount(len(results))
        
        for row_idx, result in enumerate(results):
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
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Results', 'websocket_results.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            QMessageBox.information(self, 'Success', 'Results exported successfully')
    
    def clear_results(self):
        self.results = []
        self.results_table.setRowCount(0)
        self.ws_url_input.clear()
        self.message_input.clear()
