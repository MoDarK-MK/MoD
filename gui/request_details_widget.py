from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget,
                             QTextEdit, QSplitter, QGroupBox, QFormLayout, QScrollArea)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor, QSyntaxHighlighter, QTextDocument
import json


class JSONHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
    
    def highlightBlock(self, text):
        pass


class RequestDetailsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.current_request = None
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(15, 15, 15, 15)
        header_layout.setSpacing(10)
        
        self.request_info_label = QLabel()
        self.request_info_label.setStyleSheet("""
            QLabel {
                font-size: 13pt;
                font-weight: bold;
                color: #0969da;
            }
        """)
        header_layout.addWidget(self.request_info_label)
        
        self.status_label = QLabel()
        self.status_label.setStyleSheet("""
            QLabel {
                font-size: 11pt;
                padding: 5px 10px;
                border-radius: 4px;
                background: #f0f0f0;
            }
        """)
        header_layout.addWidget(self.status_label)
        
        header_layout.addStretch()
        
        self.time_label = QLabel()
        self.time_label.setStyleSheet("color: #666; font-size: 10pt;")
        header_layout.addWidget(self.time_label)
        
        header_widget.setStyleSheet("border-bottom: 1px solid #e0e0e0;")
        main_layout.addWidget(header_widget)

        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #e0e0e0; }
            QTabBar::tab {
                background: #f5f5f5;
                padding: 8px 16px;
                border: 1px solid #e0e0e0;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: white;
                border-bottom: 2px solid #0969da;
            }
        """)
        
        request_tab = self.create_request_tab()
        tabs.addTab(request_tab, '📤 Request')
        
        response_tab = self.create_response_tab()
        tabs.addTab(response_tab, '📥 Response')
        
        headers_tab = self.create_headers_tab()
        tabs.addTab(headers_tab, '📋 Headers')
        
        analysis_tab = self.create_analysis_tab()
        tabs.addTab(analysis_tab, '🔍 Analysis')
        
        main_layout.addWidget(tabs)
        self.setLayout(main_layout)
    
    def create_request_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        url_group = QGroupBox('Request URL')
        url_layout = QFormLayout()
        self.url_display = QTextEdit()
        self.url_display.setReadOnly(True)
        self.url_display.setMaximumHeight(60)
        self.url_display.setStyleSheet("""
            QTextEdit {
                background: #f9f9f9;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Courier New';
                font-size: 10pt;
            }
        """)
        url_layout.addRow(self.url_display)
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)

        method_group = QGroupBox('Request Details')
        method_layout = QFormLayout()
        
        self.method_label = QLabel()
        self.method_label.setStyleSheet("font-weight: bold; font-size: 11pt;")
        method_layout.addRow('Method:', self.method_label)
        
        self.param_label = QLabel()
        method_layout.addRow('Parameters:', self.param_label)
        
        method_group.setLayout(method_layout)
        layout.addWidget(method_group)

        body_group = QGroupBox('Request Body')
        body_layout = QVBoxLayout()
        self.request_body = QTextEdit()
        self.request_body.setReadOnly(True)
        self.request_body.setStyleSheet("""
            QTextEdit {
                background: #f9f9f9;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                font-family: 'Courier New';
                font-size: 9pt;
            }
        """)
        body_layout.addWidget(self.request_body)
        body_group.setLayout(body_layout)
        layout.addWidget(body_group)
        
        layout.addStretch()
        return widget
    
    def create_response_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        status_group = QGroupBox('Response Status')
        status_layout = QFormLayout()
        
        self.response_status_label = QLabel()
        self.response_status_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        status_layout.addRow('Status Code:', self.response_status_label)
        
        self.response_size_label = QLabel()
        status_layout.addRow('Response Size:', self.response_size_label)
        
        self.response_time_label = QLabel()
        status_layout.addRow('Response Time:', self.response_time_label)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        content_group = QGroupBox('Response Content')
        content_layout = QVBoxLayout()
        self.response_body = QTextEdit()
        self.response_body.setReadOnly(True)
        self.response_body.setStyleSheet("""
            QTextEdit {
                background: #f9f9f9;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                font-family: 'Courier New';
                font-size: 9pt;
            }
        """)
        content_layout.addWidget(self.response_body)
        content_group.setLayout(content_layout)
        layout.addWidget(content_group)
        
        return widget
    
    def create_headers_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)

        req_group = QGroupBox('Request Headers')
        req_layout = QVBoxLayout()
        self.request_headers = QTextEdit()
        self.request_headers.setReadOnly(True)
        self.request_headers.setStyleSheet("""
            QTextEdit {
                background: #f9f9f9;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                font-family: 'Courier New';
                font-size: 9pt;
            }
        """)
        req_layout.addWidget(self.request_headers)
        req_group.setLayout(req_layout)
        splitter.addWidget(req_group)

        resp_group = QGroupBox('Response Headers')
        resp_layout = QVBoxLayout()
        self.response_headers = QTextEdit()
        self.response_headers.setReadOnly(True)
        self.response_headers.setStyleSheet("""
            QTextEdit {
                background: #f9f9f9;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                font-family: 'Courier New';
                font-size: 9pt;
            }
        """)
        resp_layout.addWidget(self.response_headers)
        resp_group.setLayout(resp_layout)
        splitter.addWidget(resp_group)
        
        splitter.setSizes([500, 500])
        layout.addWidget(splitter)
        
        return widget
    
    def create_analysis_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        security_group = QGroupBox('🔒 Security Headers Analysis')
        security_layout = QVBoxLayout()
        self.security_analysis = QTextEdit()
        self.security_analysis.setReadOnly(True)
        self.security_analysis.setStyleSheet("""
            QTextEdit {
                background: #f9f9f9;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                font-family: 'Courier New';
                font-size: 9pt;
            }
        """)
        security_layout.addWidget(self.security_analysis)
        security_group.setLayout(security_layout)
        layout.addWidget(security_group)

        issues_group = QGroupBox('⚠️ Potential Issues')
        issues_layout = QVBoxLayout()
        self.issues_analysis = QTextEdit()
        self.issues_analysis.setReadOnly(True)
        self.issues_analysis.setStyleSheet("""
            QTextEdit {
                background: #fff5f5;
                border: 1px solid #ffcccc;
                border-radius: 4px;
                font-family: 'Courier New';
                font-size: 9pt;
            }
        """)
        issues_layout.addWidget(self.issues_analysis)
        issues_group.setLayout(issues_layout)
        layout.addWidget(issues_group)
        
        return widget
    
    def display_request(self, request_data: dict):
        self.current_request = request_data

        url = request_data.get('url', 'N/A')
        method = request_data.get('method', 'GET')
        status = request_data.get('status_code', 0)
        
        self.request_info_label.setText(f"{method} {url[:60]}...")
        
        if 200 <= status < 300:
            status_color = '#2ea043'
            status_text = '✅ Success'
        elif 300 <= status < 400:
            status_color = '#0969da'
            status_text = '➡️ Redirect'
        elif 400 <= status < 500:
            status_color = '#d29922'
            status_text = '⚠️ Client Error'
        else:
            status_color = '#da3633'
            status_text = '❌ Server Error'
        
        self.status_label.setText(status_text)
        self.status_label.setStyleSheet(f"""
            QLabel {{
                color: {status_color};
                font-weight: bold;
                padding: 5px 10px;
                border-radius: 4px;
                background: #f0f0f0;
            }}
        """)
        
        duration = request_data.get('duration', 0)
        self.time_label.setText(f"⏱️ {duration:.3f}s")

        self.url_display.setText(url)
        self.method_label.setText(f"{method}")
        
        params = request_data.get('request_headers', {})
        self.param_label.setText(f"{len(params)} headers")

        self.response_status_label.setText(f"{status}")
        response_text = request_data.get('response', '')
        response_size = len(response_text)
        
        if response_size < 1024:
            size_str = f"{response_size} B"
        elif response_size < 1024 * 1024:
            size_str = f"{response_size / 1024:.2f} KB"
        else:
            size_str = f"{response_size / (1024 * 1024):.2f} MB"
        
        self.response_size_label.setText(size_str)
        self.response_time_label.setText(f"{duration:.3f}s")
        self.response_body.setText(response_text[:2000])

        req_headers = request_data.get('request_headers', {})
        headers_text = '\n'.join([f"{k}: {v}" for k, v in req_headers.items()])
        self.request_headers.setText(headers_text or "No headers")
        
        resp_headers = request_data.get('response_headers', {})
        headers_text = '\n'.join([f"{k}: {v}" for k, v in resp_headers.items()])
        self.response_headers.setText(headers_text or "No headers")

        self._analyze_security(resp_headers)
    
    def _analyze_security(self, headers: dict):
        security_checks = {
            'Content-Security-Policy': ('✅ CSP configured', '❌ CSP not set'),
            'X-Frame-Options': ('✅ Clickjacking protection enabled', '❌ No clickjacking protection'),
            'X-Content-Type-Options': ('✅ MIME-sniffing protection', '❌ No MIME protection'),
            'Strict-Transport-Security': ('✅ HSTS enabled', '❌ No HSTS'),
            'X-XSS-Protection': ('✅ XSS protection enabled', '❌ No XSS protection'),
        }
        
        security_text = ""
        issues_text = ""
        
        for header, (good_msg, bad_msg) in security_checks.items():
            if header in headers:
                security_text += f"✅ {good_msg}\n"
            else:
                security_text += f"❌ {bad_msg}\n"
                issues_text += f"⚠️ Missing {header}\n"
        
        self.security_analysis.setText(security_text)
        self.issues_analysis.setText(issues_text or "✅ No obvious security issues")

from gui.request_details_widget import RequestDetailsWidget

class RequestMonitorTab(QWidget):
    def __init__(self):
        super().__init__()
        self.requests_history = []
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.requests_table = QTableWidget()
        splitter.addWidget(self.requests_table)
        self.request_details = RequestDetailsWidget()
        splitter.addWidget(self.request_details)
        
        splitter.setSizes([400, 300])
        
        main_layout.addWidget(splitter)
        self.setLayout(main_layout)
        
        self.requests_table.itemSelectionChanged.connect(self.show_request_details)
    
    def show_request_details(self):
        selected_rows = self.requests_table.selectedItems()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        if row >= len(self.requests_history):
            return
        
        request = self.requests_history[row]
        self.request_details.display_request(request)
