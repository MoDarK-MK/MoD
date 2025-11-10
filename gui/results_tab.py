from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QTableWidget, QTableWidgetItem, QFileDialog,
                             QMessageBox, QHeaderView, QComboBox)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from utils.report_generator import ReportGenerator
from utils.database import Database
import json

class ResultsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.report_generator = ReportGenerator()
        self.database = Database()
        self.vulnerabilities = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)
        
        toolbar_layout = QHBoxLayout()
        
        self.export_pdf_btn = QPushButton('📄 Export PDF')
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        toolbar_layout.addWidget(self.export_pdf_btn)
        
        self.export_html_btn = QPushButton('🌐 Export HTML')
        self.export_html_btn.clicked.connect(self.export_html)
        toolbar_layout.addWidget(self.export_html_btn)
        
        self.export_json_btn = QPushButton('📋 Export JSON')
        self.export_json_btn.clicked.connect(self.export_json)
        toolbar_layout.addWidget(self.export_json_btn)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(['All', 'Critical', 'High', 'Medium', 'Low', 'Info'])
        self.severity_filter.currentTextChanged.connect(self.filter_results)
        toolbar_layout.addWidget(self.severity_filter)
        
        self.clear_btn = QPushButton('🗑️ Clear Results')
        self.clear_btn.clicked.connect(self.clear_results)
        toolbar_layout.addWidget(self.clear_btn)
        
        toolbar_layout.addStretch()
        
        main_layout.addLayout(toolbar_layout)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(['Type', 'Severity', 'URL', 'Parameter', 'Payload', 'Description'])
        
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        
        main_layout.addWidget(self.results_table)
        
        self.setLayout(main_layout)
    
    def display_results(self, vulnerabilities: list):
        self.vulnerabilities = vulnerabilities
        self.refresh_table()
    
    def add_vulnerability(self, vulnerability: dict):
        self.vulnerabilities.append(vulnerability)
        self.refresh_table()
    
    def refresh_table(self):
        self.results_table.setRowCount(0)
        
        filtered_vulns = self.vulnerabilities
        selected_severity = self.severity_filter.currentText()
        if selected_severity != 'All':
            filtered_vulns = [v for v in filtered_vulns if v.get('severity') == selected_severity]
        
        for row_idx, vuln in enumerate(filtered_vulns):
            self.results_table.insertRow(row_idx)
            
            type_item = QTableWidgetItem(vuln.get('type', ''))
            severity_item = QTableWidgetItem(vuln.get('severity', ''))
            url_item = QTableWidgetItem(vuln.get('url', ''))
            param_item = QTableWidgetItem(vuln.get('parameter', ''))
            payload_item = QTableWidgetItem(vuln.get('payload', '')[:50])
            desc_item = QTableWidgetItem(vuln.get('description', '')[:50])
            
            severity = vuln.get('severity', 'Low')
            color = self._get_severity_color(severity)
            severity_item.setBackground(QColor(color))
            severity_item.setForeground(QColor('white'))
            
            self.results_table.setItem(row_idx, 0, type_item)
            self.results_table.setItem(row_idx, 1, severity_item)
            self.results_table.setItem(row_idx, 2, url_item)
            self.results_table.setItem(row_idx, 3, param_item)
            self.results_table.setItem(row_idx, 4, payload_item)
            self.results_table.setItem(row_idx, 5, desc_item)
    
    def filter_results(self):
        self.refresh_table()
    
    def clear_results(self):
        self.vulnerabilities = []
        self.results_table.setRowCount(0)
    
    def _get_severity_color(self, severity: str) -> str:
        colors = {
            'Critical': '#ff0000',
            'High': '#ff6600',
            'Medium': '#ffff00',
            'Low': '#00ff00',
            'Info': '#0099ff'
        }
        return colors.get(severity, '#0099ff')
    
    def export_pdf(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export PDF', 'report.pdf', 'PDF Files (*.pdf)')
        if filename:
            try:
                self.report_generator.generate_pdf_report(filename, 'Target', self.vulnerabilities)
                QMessageBox.information(self, 'Success', f'Report saved to {filename}')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to export PDF: {str(e)}')
    
    def export_html(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export HTML', 'report.html', 'HTML Files (*.html)')
        if filename:
            try:
                self.report_generator.generate_html_report(filename, 'Target', self.vulnerabilities)
                QMessageBox.information(self, 'Success', f'Report saved to {filename}')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to export HTML: {str(e)}')
    
    def export_json(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export JSON', 'report.json', 'JSON Files (*.json)')
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.vulnerabilities, f, indent=4)
                QMessageBox.information(self, 'Success', f'Report saved to {filename}')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to export JSON: {str(e)}')
    
    def export_results(self):
        if not self.vulnerabilities:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        self.export_pdf()
