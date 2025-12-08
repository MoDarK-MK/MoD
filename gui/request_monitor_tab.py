"""Request Monitor Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QMessageBox, QFileDialog, QPushButton)
from PyQt6.QtCore import QThread, pyqtSignal
from core.request_handler import RequestHandler
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors, get_table_stylesheet
)
from typing import List, Dict, Any
import json


class RequestMonitorTab(DesignMainWidget):
    
    def __init__(self):
        super().__init__()
        self.header.set_title("Request Monitor")
        self.header.set_subtitle("Monitor all HTTP/HTTPS requests during scanning")
        
        self.request_handler = RequestHandler()
        self.requests: List[Dict[str, Any]] = []
        self.init_ui()
    
    def init_ui(self):
        # Control section
        control_section = self.add_section("Controls")
        button_layout = QHBoxLayout()
        
        start_button = DesignButton('Start Monitoring', 'primary')
        start_button.clicked.connect(self.start_monitoring)
        button_layout.addWidget(start_button)
        
        stop_button = DesignButton('Stop Monitoring', 'secondary')
        stop_button.clicked.connect(self.stop_monitoring)
        button_layout.addWidget(stop_button)
        
        clear_button = DesignButton('Clear Logs', 'danger')
        clear_button.clicked.connect(self.clear_logs)
        button_layout.addWidget(clear_button)
        
        export_button = DesignButton('Export Logs', 'secondary')
        export_button.clicked.connect(self.export_logs)
        button_layout.addWidget(export_button)
        
        button_layout.addStretch()
        control_section.content_layout.addLayout(button_layout)
        
        # Requests section
        requests_section = self.add_section("Captured Requests")
        
        self.requests_table = QTableWidget()
        self.requests_table.setColumnCount(5)
        self.requests_table.setHorizontalHeaderLabels(['Method', 'URL', 'Status', 'Time', 'Size'])
        self.requests_table.setStyleSheet(get_table_stylesheet())
        
        header = self.requests_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        
        requests_section.content_layout.addWidget(self.requests_table)
        
        self.add_stretch()
    
    def start_monitoring(self):
        try:
            self.request_handler.start_monitoring()
            QMessageBox.information(self, 'Info', 'Request monitoring started')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to start monitoring: {str(e)}')
    
    def stop_monitoring(self):
        try:
            self.requests = self.request_handler.stop_monitoring()
            self.display_requests()
            QMessageBox.information(self, 'Info', 'Request monitoring stopped')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to stop monitoring: {str(e)}')
    
    def display_requests(self):
        self.requests_table.setRowCount(len(self.requests))
        
        for row_idx, req in enumerate(self.requests):
            method_item = QTableWidgetItem(req.get('method', 'GET'))
            url_item = QTableWidgetItem(req.get('url', ''))
            status_item = QTableWidgetItem(str(req.get('status_code', '')))
            time_item = QTableWidgetItem(f"{req.get('time', 0):.2f}s")
            size_item = QTableWidgetItem(f"{req.get('size', 0)} B")
            
            self.requests_table.setItem(row_idx, 0, method_item)
            self.requests_table.setItem(row_idx, 1, url_item)
            self.requests_table.setItem(row_idx, 2, status_item)
            self.requests_table.setItem(row_idx, 3, time_item)
            self.requests_table.setItem(row_idx, 4, size_item)
    
    def clear_logs(self):
        self.requests = []
        self.requests_table.setRowCount(0)
        QMessageBox.information(self, 'Info', 'Request logs cleared')
    
    def export_logs(self):
        if not self.requests:
            QMessageBox.warning(self, 'Warning', 'No requests to export')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Logs', 'request_logs.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.requests, f, indent=4)
            QMessageBox.information(self, 'Success', 'Request logs exported successfully')
