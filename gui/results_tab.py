from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QTableWidget, QTableWidgetItem, QFileDialog,
                             QMessageBox, QHeaderView, QComboBox, QInputDialog,
                             QScrollArea, QFrame, QLabel)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from utils.report_generator import ReportGenerator
from utils.database import Database
from .design_system import (
    DesignColors, DesignSpacing, DesignTypography, DesignButton,
    DesignCard, DesignSection, DesignHeader, DesignMainWidget,
    get_table_stylesheet, get_combobox_stylesheet
)
import json
import requests

class ResultsTab(DesignMainWidget):
    def __init__(self):
        super().__init__()
        self.header.set_title("Scan Results Analysis")
        self.header.set_subtitle("View and export vulnerability findings")
        
        self.report_generator = ReportGenerator()
        self.database = Database()
        self.vulnerabilities = []
        self.init_ui()
    
    def init_ui(self):
        # Controls Section
        controls_section = self.add_section("Controls")
        
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setSpacing(DesignSpacing.MD)
        
        self.export_pdf_btn = DesignButton('📄 Export PDF', 'primary')
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        toolbar_layout.addWidget(self.export_pdf_btn)
        
        self.export_html_btn = DesignButton('🌐 Export HTML', 'primary')
        self.export_html_btn.clicked.connect(self.export_html)
        toolbar_layout.addWidget(self.export_html_btn)
        
        self.export_json_btn = DesignButton('📋 Export JSON', 'primary')
        self.export_json_btn.clicked.connect(self.export_json)
        toolbar_layout.addWidget(self.export_json_btn)
        
        self.export_discord_btn = DesignButton('🎮 Export to Discord', 'primary')
        self.export_discord_btn.clicked.connect(self.export_discord)
        toolbar_layout.addWidget(self.export_discord_btn)
        
        toolbar_layout.addSpacing(DesignSpacing.LG)
        
        # Severity filter
        filter_label = QLabel('Filter by Severity:')
        filter_label.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
        toolbar_layout.addWidget(filter_label)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(['All', 'Critical', 'High', 'Medium', 'Low', 'Info'])
        self.severity_filter.setStyleSheet(get_combobox_stylesheet())
        self.severity_filter.setMinimumWidth(150)
        self.severity_filter.currentTextChanged.connect(self.filter_results)
        toolbar_layout.addWidget(self.severity_filter)
        
        toolbar_layout.addStretch()
        
        self.clear_btn = DesignButton('🗑️ Clear Results', 'danger')
        self.clear_btn.clicked.connect(self.clear_results)
        toolbar_layout.addWidget(self.clear_btn)
        
        controls_section.add_layout(toolbar_layout)
        
        # Results Table Section
        results_section = self.add_section("Vulnerability Results")
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            'Type', 'Severity', 'URL', 'Parameter', 'Payload', 'Description'
        ])
        self.results_table.setStyleSheet(get_table_stylesheet())
        self.results_table.setMinimumHeight(400)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        
        header = self.results_table.horizontalHeader()
        header.setFixedHeight(40)
        self.results_table.verticalHeader().setDefaultSectionSize(35)
        
        results_section.add_widget(self.results_table)
        
        self.scroll_content.layout().addStretch()
    
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
    
    def export_discord(self):
        """Export scan results to Discord webhook"""
        if not self.vulnerabilities:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        # Ask user for Discord webhook URL
        webhook_url, ok = QInputDialog.getText(
            self,
            'Discord Webhook',
            'Enter Discord webhook URL:',
            text='https://discord.com/api/webhooks/'
        )
        
        if not ok or not webhook_url:
            return
        
        try:
            # Group vulnerabilities by severity
            severity_groups = {
                'Critical': [],
                'High': [],
                'Medium': [],
                'Low': [],
                'Info': []
            }
            
            for vuln in self.vulnerabilities:
                severity = vuln.get('severity', 'Info')
                if severity in severity_groups:
                    severity_groups[severity].append(vuln)
            
            # Create summary embed
            embeds = []
            
            # Summary embed
            total_count = len(self.vulnerabilities)
            summary_embed = {
                'title': '🔒 Security Scan Report Summary',
                'color': 0x0099ff,
                'fields': [
                    {'name': 'Total Vulnerabilities', 'value': str(total_count), 'inline': True},
                    {'name': 'Critical', 'value': str(len(severity_groups['Critical'])), 'inline': True},
                    {'name': 'High', 'value': str(len(severity_groups['High'])), 'inline': True},
                    {'name': 'Medium', 'value': str(len(severity_groups['Medium'])), 'inline': True},
                    {'name': 'Low', 'value': str(len(severity_groups['Low'])), 'inline': True},
                    {'name': 'Info', 'value': str(len(severity_groups['Info'])), 'inline': True},
                ]
            }
            embeds.append(summary_embed)
            
            # Vulnerability details (limit to 10 most critical)
            displayed_count = 0
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                for vuln in severity_groups[severity]:
                    if displayed_count >= 10:
                        break
                    
                    severity_colors = {
                        'Critical': 0xff0000,
                        'High': 0xff6600,
                        'Medium': 0xffff00,
                        'Low': 0x00ff00,
                        'Info': 0x0099ff
                    }
                    
                    vuln_embed = {
                        'title': f'{severity} - {vuln.get("type", "Unknown")}',
                        'color': severity_colors.get(severity, 0x0099ff),
                        'fields': [
                            {'name': 'URL', 'value': vuln.get('url', 'N/A'), 'inline': False},
                            {'name': 'Parameter', 'value': vuln.get('parameter', 'N/A'), 'inline': True},
                            {'name': 'Description', 'value': vuln.get('description', 'N/A')[:100], 'inline': False},
                        ]
                    }
                    embeds.append(vuln_embed)
                    displayed_count += 1
                
                if displayed_count >= 10:
                    break
            
            # Send to Discord (split into multiple messages if needed, max 10 embeds per message)
            while embeds:
                batch = embeds[:10]
                embeds = embeds[10:]
                
                payload = {'embeds': batch}
                response = requests.post(webhook_url, json=payload, timeout=10)
                
                if response.status_code not in [200, 204]:
                    raise Exception(f'Discord returned error code: {response.status_code}')
            
            QMessageBox.information(
                self,
                'Success',
                f'Successfully exported {total_count} vulnerabilities to Discord!'
            )
        
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Failed to export to Discord:\n{str(e)}')
    
    def export_results(self):
        if not self.vulnerabilities:
            QMessageBox.warning(self, 'Warning', 'No results to export')
            return
        
        self.export_pdf()
