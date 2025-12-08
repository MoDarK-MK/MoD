"""Subdomain Enumeration Tab - Professional Design."""

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QFileDialog, QCheckBox)
from PyQt6.QtCore import QThread, pyqtSignal
from scanners.subdomain_scanner import SubdomainScanner
from .design_system import (
    DesignMainWidget, DesignSection, DesignButton,
    DesignSpacing, DesignColors, get_table_stylesheet
)
from typing import List, Dict, Any, Optional
import json


class SubdomainScanThread(QThread):
    progress_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    scan_error = pyqtSignal(str)
    
    def __init__(self, domain: str, use_wordlist: bool = True, use_dns: bool = True, use_wayback: bool = False) -> None:
        super().__init__()
        self.domain = domain
        self.use_wordlist = use_wordlist
        self.use_dns = use_dns
        self.use_wayback = use_wayback
        self.scanner = SubdomainScanner()
    
    def run(self) -> None:
        try:
            self.progress_updated.emit(f"Enumerating subdomains for {self.domain}...")
            results = self.scanner.scan(self.domain, self.use_wordlist, self.use_dns, self.use_wayback)
            self.scan_completed.emit(results)
        except Exception as e:
            self.scan_error.emit(f"Scan error: {str(e)}")


class SubdomainTab(DesignMainWidget):
    
    def __init__(self) -> None:
        super().__init__()
        self.header.set_title("Subdomain Enumeration")
        self.header.set_subtitle("Find subdomains and discover attack surface")
        
        self.scanner = SubdomainScanner()
        self.results: List[Dict[str, Any]] = []
        self.scan_thread: Optional[SubdomainScanThread] = None
        self.init_ui()
    
    def init_ui(self) -> None:
        # Configuration section
        config_section = self.add_section("Configuration")
        
        label = QLabel('Domain:')
        label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText('e.g., example.com')
        self.domain_input.setStyleSheet(f"""
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
        config_section.content_layout.addWidget(self.domain_input)
        
        # Scan options
        options_label = QLabel('Scan Methods:')
        options_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        config_section.content_layout.addWidget(options_label)
        
        self.wordlist_check = QCheckBox('Wordlist Brute-force')
        self.wordlist_check.setChecked(True)
        self.wordlist_check.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
        
        self.dns_check = QCheckBox('DNS Resolution')
        self.dns_check.setChecked(True)
        self.dns_check.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
        
        self.wayback_check = QCheckBox('Wayback Machine')
        self.wayback_check.setChecked(False)
        self.wayback_check.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
        
        config_section.content_layout.addWidget(self.wordlist_check)
        config_section.content_layout.addWidget(self.dns_check)
        config_section.content_layout.addWidget(self.wayback_check)
        
        # Action buttons
        action_section = self.add_section("Actions")
        button_layout = QHBoxLayout()
        
        scan_button = DesignButton('Start Enumeration', 'primary')
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
        results_section = self.add_section("Subdomains Found")
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(['Subdomain', 'IP Address', 'Status'])
        self.results_table.setStyleSheet(get_table_stylesheet())
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        results_section.content_layout.addWidget(self.results_table)
        
        self.add_stretch()
    
    def start_scan(self):
        domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, 'Warning', 'Please enter domain name')
            return
        
        self.results_table.setRowCount(0)
        
        self.scan_thread = SubdomainScanThread(
            domain,
            self.wordlist_check.isChecked(),
            self.dns_check.isChecked(),
            self.wayback_check.isChecked()
        )
        self.scan_thread.scan_completed.connect(self.display_results)
        self.scan_thread.scan_error.connect(lambda e: QMessageBox.critical(self, 'Error', e))
        self.scan_thread.start()
    
    def display_results(self, results: List[Dict[str, Any]]):
        self.results = results
        self.results_table.setRowCount(len(results))
        
        for row_idx, result in enumerate(results):
            subdomain_item = QTableWidgetItem(result.get('subdomain', ''))
            ip_item = QTableWidgetItem(result.get('ip_address', ''))
            status_item = QTableWidgetItem(result.get('status', 'Unknown'))
            
            self.results_table.setItem(row_idx, 0, subdomain_item)
            self.results_table.setItem(row_idx, 1, ip_item)
            self.results_table.setItem(row_idx, 2, status_item)
    
    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Results', 'subdomains.json', 'JSON Files (*.json)')
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            QMessageBox.information(self, 'Success', 'Results exported successfully')
    
    def clear_results(self):
        self.results = []
        self.results_table.setRowCount(0)
        self.domain_input.clear()
