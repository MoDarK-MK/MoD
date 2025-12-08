"""CORS Misconfiguration Scanner Tab."""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QGroupBox, QFormLayout, QMessageBox,
                             QTextEdit, QFileDialog, QProgressBar, QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor
from scanners.cors_scanner import CORSScanner
from typing import List, Dict, Any, Optional
import json


class CORSScanThread(QThread):
    """Worker thread for CORS scanning."""
    
    progress_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    scan_error = pyqtSignal(str)
    
    def __init__(self, target_url: str, custom_origins: Optional[List[str]] = None) -> None:
        """Initialize scan thread.
        
        Args:
            target_url: URL to scan.
            custom_origins: Custom origins to test.
        """
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


class CORSTab(QWidget):
    """Tab for CORS misconfiguration testing."""
    
    def __init__(self) -> None:
        """Initialize CORS tab."""
        super().__init__()
        self.scanner = CORSScanner()
        self.results: List[Dict[str, Any]] = []
        self.scan_thread: Optional[CORSScanThread] = None
        self.init_ui()
    
    def init_ui(self) -> None:
        """Initialize user interface."""
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(12)
        
        # Input configuration group
        input_group = QGroupBox('🔍 CORS Configuration')
        input_group.setStyleSheet("""QGroupBox {
                border-radius: 12px;
                font-weight: bold;
        }""")
        input_layout = QFormLayout()
        
        self.target_url_input = QLineEdit()
        self.target_url_input.setPlaceholderText('Enter target URL (e.g., http://example.com)')
        self.target_url_input.setMinimumHeight(40)
        input_layout.addRow('Target URL:', self.target_url_input)
        
        # Custom origins input
        self.origins_input = QTextEdit()
        self.origins_input.setPlaceholderText('Enter custom origins (one per line)\nLeave empty to use default origins')
        self.origins_input.setMinimumHeight(80)
        self.origins_input.setMaximumHeight(120)
        input_layout.addRow('Custom Origins:', self.origins_input)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        
        scan_button = QPushButton('🔬 Start CORS Scan')
        scan_button.setMinimumHeight(40)
        scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(scan_button)
        
        generate_poc_button = QPushButton('📏 Generate PoC')
        generate_poc_button.setMinimumHeight(40)
        generate_poc_button.clicked.connect(self.generate_poc)
        button_layout.addWidget(generate_poc_button)
        
        export_button = QPushButton('💾 Export Results')
        export_button.setMinimumHeight(40)
        export_button.clicked.connect(self.export_results)
        button_layout.addWidget(export_button)
        
        clear_button = QPushButton('🗑️ Clear All')
        clear_button.setMinimumHeight(40)
        clear_button.clicked.connect(self.clear_all)
        button_layout.addWidget(clear_button)
        
        main_layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximum(0)
        main_layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel('Ready')
        self.status_label.setStyleSheet('color: #2196F3; font-weight: bold;')
        main_layout.addWidget(self.status_label)
        
        # Results table
        results_group = QGroupBox('📊 CORS Scan Results')
        results_group.setStyleSheet("""QGroupBox {
                border-radius: 12px;
                font-weight: bold;
        }""")
        results_layout = QVBoxLayout()
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels([
            'Origin',
            'Allowed Origin',
            'Allow Credentials',
            'Methods',
            'Severity',
            'Status',
            'Description'
        ])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        
        self.results_table.setMaximumHeight(300)
        results_layout.addWidget(self.results_table)
        
        results_group.setLayout(results_layout)
        main_layout.addWidget(results_group)
        
        # PoC viewer
        poc_group = QGroupBox('🎯 Generated PoC HTML')
        poc_group.setStyleSheet("""QGroupBox {
                border-radius: 12px;
                font-weight: bold;
        }""")
        poc_layout = QVBoxLayout()
        
        self.poc_display = QTextEdit()
        self.poc_display.setReadOnly(True)
        self.poc_display.setPlaceholderText('PoC HTML will appear here after generation')
        self.poc_display.setMinimumHeight(150)
        self.poc_display.setMaximumHeight(250)
        poc_layout.addWidget(self.poc_display)
        
        poc_button_layout = QHBoxLayout()
        
        copy_poc_button = QPushButton('📋 Copy PoC')
        copy_poc_button.clicked.connect(self.copy_poc)
        poc_button_layout.addWidget(copy_poc_button)
        
        save_poc_button = QPushButton('💾 Save PoC as HTML')
        save_poc_button.clicked.connect(self.save_poc_html)
        poc_button_layout.addWidget(save_poc_button)
        
        poc_layout.addLayout(poc_button_layout)
        poc_group.setLayout(poc_layout)
        main_layout.addWidget(poc_group)
        
        main_layout.addStretch()
        self.setLayout(main_layout)
    
    def start_scan(self) -> None:
        """Start CORS scan."""
        target_url = self.target_url_input.text().strip()
        
        if not target_url:
            QMessageBox.warning(self, 'Warning', 'Please enter a target URL')
            return
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
            self.target_url_input.setText(target_url)
        
        # Get custom origins if provided
        custom_origins_text = self.origins_input.toPlainText().strip()
        custom_origins = None
        if custom_origins_text:
            custom_origins = [o.strip() for o in custom_origins_text.split('\n') if o.strip()]
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.poc_display.clear()
        
        # Show progress bar
        self.progress_bar.setVisible(True)
        self.status_label.setText('🔄 Scanning in progress...')
        self.status_label.setStyleSheet('color: #FF9800; font-weight: bold;')
        
        # Start scan in thread
        self.scan_thread = CORSScanThread(target_url, custom_origins)
        self.scan_thread.progress_updated.connect(self.update_status)
        self.scan_thread.scan_completed.connect(self.display_results)
        self.scan_thread.scan_error.connect(self.handle_error)
        self.scan_thread.start()
    
    def update_status(self, message: str) -> None:
        """Update status message.
        
        Args:
            message: Status message.
        """
        self.status_label.setText(message)
    
    def display_results(self, results: List[Dict[str, Any]]) -> None:
        """Display scan results.
        
        Args:
            results: List of results from scan.
        """
        self.results = results
        self.results_table.setRowCount(len(results))
        
        for row_idx, result in enumerate(results):
            origin = result.get('origin_tested', '')
            allowed_origin = result.get('allowed_origin', '')
            credentials = result.get('allow_credentials', '')
            methods = result.get('allow_methods', '')
            severity = result.get('severity', '')
            status = '✅ Vulnerable' if result.get('is_vulnerable') else '✓ Detected'
            description = result.get('description', '')
            
            self.results_table.setItem(row_idx, 0, QTableWidgetItem(origin))
            self.results_table.setItem(row_idx, 1, QTableWidgetItem(allowed_origin))
            self.results_table.setItem(row_idx, 2, QTableWidgetItem(credentials))
            self.results_table.setItem(row_idx, 3, QTableWidgetItem(methods))
            
            severity_item = QTableWidgetItem(severity)
            if severity == 'Critical':
                severity_item.setBackground(QColor(255, 0, 0))
                severity_item.setForeground(QColor(255, 255, 255))
            elif severity == 'High':
                severity_item.setBackground(QColor(255, 152, 0))
            elif severity == 'Medium':
                severity_item.setBackground(QColor(255, 193, 7))
            
            self.results_table.setItem(row_idx, 4, severity_item)
            self.results_table.setItem(row_idx, 5, QTableWidgetItem(status))
            self.results_table.setItem(row_idx, 6, QTableWidgetItem(description))
        
        # Update status
        vulnerable_count = sum(1 for r in results if r.get('is_vulnerable'))
        self.progress_bar.setVisible(False)
        self.status_label.setText(
            f'✅ Scan complete! Found {vulnerable_count} vulnerable configurations'
        )
        self.status_label.setStyleSheet('color: #4CAF50; font-weight: bold;')
    
    def handle_error(self, error: str) -> None:
        """Handle scan error.
        
        Args:
            error: Error message.
        """
        self.progress_bar.setVisible(False)
        self.status_label.setText(f'❌ {error}')
        self.status_label.setStyleSheet('color: #F44336; font-weight: bold;')
        QMessageBox.critical(self, 'Scan Error', error)
    
    def generate_poc(self) -> None:
        """Generate PoC HTML for first vulnerable result."""
        if not self.results:
            QMessageBox.warning(self, 'Warning', 'No results to generate PoC from. Run a scan first.')
            return
        
        # Find first vulnerable result
        vulnerable = next((r for r in self.results if r.get('is_vulnerable')), None)
        if not vulnerable:
            vulnerable = self.results[0]  # Use first result if none vulnerable
        
        target_url = self.target_url_input.text().strip()
        poc_html = self.scanner.generate_poc_html(target_url, vulnerable)
        
        self.poc_display.setPlainText(poc_html)
        self.status_label.setText('✅ PoC HTML generated successfully')
        self.status_label.setStyleSheet('color: #4CAF50; font-weight: bold;')
    
    def copy_poc(self) -> None:
        """Copy PoC to clipboard."""
        from PyQt6.QtWidgets import QApplication
        
        poc_text = self.poc_display.toPlainText()
        if not poc_text:
            QMessageBox.warning(self, 'Warning', 'No PoC to copy. Generate one first.')
            return
        
        QApplication.clipboard().setText(poc_text)
        QMessageBox.information(self, 'Success', 'PoC HTML copied to clipboard!')
    
    def save_poc_html(self) -> None:
        """Save PoC HTML to file."""
        poc_text = self.poc_display.toPlainText()
        if not poc_text:
            QMessageBox.warning(self, 'Warning', 'No PoC to save. Generate one first.')
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Save PoC', 'cors_poc.html', 'HTML Files (*.html);;All Files (*)'
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(poc_text)
                QMessageBox.information(self, 'Success', f'PoC saved to {filename}')
                self.status_label.setText(f'✅ PoC saved to {filename}')
                self.status_label.setStyleSheet('color: #4CAF50; font-weight: bold;')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to save file: {str(e)}')
    
    def export_results(self) -> None:
        """Export results to JSON file."""
        if not self.results:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 'Export Results', 'cors_results.json', 'JSON Files (*.json);;All Files (*)'
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=4, ensure_ascii=False)
                QMessageBox.information(self, 'Success', f'Results exported to {filename}')
                self.status_label.setText(f'✅ Results exported to {filename}')
                self.status_label.setStyleSheet('color: #4CAF50; font-weight: bold;')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to export: {str(e)}')
    
    def clear_all(self) -> None:
        """Clear all data."""
        self.target_url_input.clear()
        self.origins_input.clear()
        self.results_table.setRowCount(0)
        self.poc_display.clear()
        self.results = []
        self.status_label.setText('Ready')
        self.status_label.setStyleSheet('color: #2196F3; font-weight: bold;')
