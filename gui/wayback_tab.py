"""Wayback Machine Integration Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QFileDialog)
from PyQt6.QtCore import QThread, pyqtSignal
from utils.wayback_client import WaybackClient
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors, get_table_stylesheet
)
from typing import List, Dict, Any, Optional
import json


class WaybackScanThread(QThread):
    progress_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    scan_error = pyqtSignal(str)
    
    def __init__(self, domain: str) -> None:
        super().__init__()
        self.domain = domain
        self.client = WaybackClient()
    
    def run(self) -> None:
        try:
            self.progress_updated.emit(f"Fetching historical data for {self.domain}...")
            results = self.client.get_snapshots(self.domain)
            self.scan_completed.emit(results)
        except Exception as e:
            self.scan_error.emit(f"Scan error: {str(e)}")


class WaybackTab(DesignMainWidget):
    
    def __init__(self) -> None:
        super().__init__()
        self.header.set_title("Wayback Machine")
        self.header.set_subtitle("Discover archived URLs and historical endpoints")
        
        self.client = WaybackClient()
        self.results: List[Dict[str, Any]] = []
        self.scan_thread: Optional[WaybackScanThread] = None
        self.init_ui()
    
    def init_ui(self) -> None:
        # Configuration section
        config_section = self.add_section("Configuration")
        
        label = QLabel('Domain/URL:')
        label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText('e.g., example.com or example.com/path')
        self.url_input.setStyleSheet(f"""
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
        config_section.content_layout.addWidget(self.url_input)
        
        # Action buttons
        action_section = self.add_section("Actions")
        button_layout = QHBoxLayout()
        
        search_button = DesignButton('Search Wayback', 'primary')
        search_button.clicked.connect(self.start_search)
        button_layout.addWidget(search_button)
        
        export_button = DesignButton('Export Results', 'secondary')
        export_button.clicked.connect(self.export_results)
        button_layout.addWidget(export_button)
        
        clear_button = DesignButton('Clear', 'danger')
        clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(clear_button)
        
        button_layout.addStretch()
        action_section.content_layout.addLayout(button_layout)
        
        # Results section
        results_section = self.add_section("Snapshots")
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(['Date', 'Status', 'URL'])
        self.results_table.setStyleSheet(get_table_stylesheet())
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        results_section.content_layout.addWidget(self.results_table)
        
        self.add_stretch()
    
    def start_search(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, 'Warning', 'Please enter domain or URL')
            return
        
        self.results_table.setRowCount(0)
        
        self.scan_thread = WaybackScanThread(url)
        self.scan_thread.scan_completed.connect(self.display_results)
        self.scan_thread.scan_error.connect(lambda e: QMessageBox.critical(self, 'Error', e))
        self.scan_thread.start()
    
    def display_results(self, results: List[Dict[str, Any]]):
        self.results = results
        self.results_table.setRowCount(len(results))
        
        for row_idx, result in enumerate(results):
            date_item = QTableWidgetItem(result.get('date', ''))
            status_item = QTableWidgetItem(result.get('status', ''))
            url_item = QTableWidgetItem(result.get('url', ''))
            
            self.results_table.setItem(row_idx, 0, date_item)
            self.results_table.setItem(row_idx, 1, status_item)
            self.results_table.setItem(row_idx, 2, url_item)
    
    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Results', 'wayback_results.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            QMessageBox.information(self, 'Success', 'Results exported successfully')
    
    def clear_results(self):
        self.results = []
        self.results_table.setRowCount(0)
        self.url_input.clear()
