# gui/request_monitor_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QHeaderView, QLabel,
                             QLineEdit, QComboBox, QTextEdit, QSplitter, QGroupBox,
                             QCheckBox, QTabWidget, QScrollArea, QFileDialog, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal, QDateTime, QSize
from PyQt6.QtGui import QColor, QFont
import json


class RequestDetailsWidget(QWidget):

    def __init__(self):
        super().__init__()
        self.current_request = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        header = self.create_header()
        main_layout.addWidget(header)

        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363d;
                background: #0d1117;
            }
            QTabBar::tab {
                background: #161b22;
                color: #8b949e;
                padding: 12px 20px;
                border: 1px solid #30363d;
                margin-right: 2px;
                border-bottom: 2px solid transparent;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background: #21262d;
                color: #c9d1d9;
            }
            QTabBar::tab:selected {
                background: #0d1117;
                color: #58a6ff;
                border-bottom: 2px solid #1f6feb;
            }
        """)

        tabs.addTab(self.create_request_tab(), 'REQUEST')
        tabs.addTab(self.create_response_tab(), 'RESPONSE')
        tabs.addTab(self.create_headers_tab(), 'HEADERS')
        tabs.addTab(self.create_analysis_tab(), 'SECURITY')

        main_layout.addWidget(tabs, 1)
        self.setLayout(main_layout)

    def create_header(self):
        header = QWidget()
        header.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                           stop:0 #0969da, stop:1 #1f6feb);
                padding: 16px;
                border-bottom: 2px solid #30363d;
            }
            QLabel {
                color: white;
            }
        """)
        header.setMinimumHeight(100)

        layout = QVBoxLayout(header)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        row1 = QHBoxLayout()

        self.method_badge = QLabel()
        self.method_badge.setFont(QFont('Arial', 11, QFont.Weight.Bold))
        self.method_badge.setStyleSheet("""
            QLabel {
                background: rgba(255,255,255,0.15);
                padding: 6px 12px;
                border-radius: 4px;
                min-width: 60px;
                text-align: center;
            }
        """)
        row1.addWidget(self.method_badge)

        self.url_badge = QLabel()
        self.url_badge.setFont(QFont('Courier New', 10))
        self.url_badge.setStyleSheet("""
            QLabel {
                color: white;
                word-wrap: break-word;
            }
        """)
        row1.addWidget(self.url_badge, 1)

        layout.addLayout(row1)

        row2 = QHBoxLayout()

        self.status_badge = QLabel()
        self.status_badge.setFont(QFont('Arial', 11, QFont.Weight.Bold))
        self.status_badge.setStyleSheet("""
            QLabel {
                background: rgba(255,255,255,0.15);
                padding: 6px 12px;
                border-radius: 4px;
                min-width: 70px;
                text-align: center;
            }
        """)
        row2.addWidget(self.status_badge)

        self.size_label = QLabel()
        self.size_label.setFont(QFont('Arial', 10))
        self.size_label.setStyleSheet("color: rgba(255,255,255,0.8);")
        row2.addWidget(self.size_label)

        self.time_label = QLabel()
        self.time_label.setFont(QFont('Arial', 10))
        self.time_label.setStyleSheet("color: rgba(255,255,255,0.8);")
        row2.addWidget(self.time_label)

        row2.addStretch()
        layout.addLayout(row2)

        return header

    def create_request_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        url_group = QGroupBox('REQUEST URL')
        url_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
                margin-top: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)

        url_layout = QVBoxLayout()
        self.url_text = QTextEdit()
        self.url_text.setReadOnly(True)
        self.url_text.setMinimumHeight(80)
        self.url_text.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 10pt;
                selection-background-color: #1f6feb;
            }
        """)
        url_layout.addWidget(self.url_text)
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)

        detail_group = QGroupBox('REQUEST DETAILS')
        detail_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
                margin-top: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)

        detail_layout = QVBoxLayout()

        detail_info = QHBoxLayout()

        method_label = QLabel("METHOD:")
        method_label.setStyleSheet("color: #8b949e; font-weight: bold;")
        detail_info.addWidget(method_label)

        method_info = QLabel()
        method_info.setStyleSheet("font-weight: bold; color: #2ea043; font-size: 11pt;")
        detail_info.addWidget(method_info)
        self.req_method_label = method_info

        detail_info.addSpacing(50)

        param_label = QLabel("PARAMETERS:")
        param_label.setStyleSheet("color: #8b949e; font-weight: bold;")
        detail_info.addWidget(param_label)

        param_info = QLabel()
        param_info.setStyleSheet("color: #58a6ff; font-weight: bold;")
        detail_info.addWidget(param_info)
        self.req_param_label = param_info

        detail_info.addStretch()
        detail_layout.addLayout(detail_info)

        detail_group.setLayout(detail_layout)
        layout.addWidget(detail_group)

        body_group = QGroupBox('REQUEST BODY')
        body_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
                margin-top: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)

        body_layout = QVBoxLayout()
        self.request_body = QTextEdit()
        self.request_body.setReadOnly(True)
        self.request_body.setMinimumHeight(120)
        self.request_body.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 9pt;
                selection-background-color: #1f6feb;
            }
        """)
        body_layout.addWidget(self.request_body)
        body_group.setLayout(body_layout)
        layout.addWidget(body_group)

        layout.addStretch()
        return widget

    def create_response_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        status_group = QGroupBox('RESPONSE STATUS')
        status_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
                margin-top: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)

        status_layout = QHBoxLayout()

        status_label = QLabel("STATUS:")
        status_label.setStyleSheet("color: #8b949e; font-weight: bold;")
        status_layout.addWidget(status_label)

        status_info = QLabel()
        status_info.setStyleSheet("font-weight: bold; font-size: 12pt; color: #2ea043;")
        status_layout.addWidget(status_info)
        self.resp_status_label = status_info

        status_layout.addSpacing(50)

        size_label = QLabel("SIZE:")
        size_label.setStyleSheet("color: #8b949e; font-weight: bold;")
        status_layout.addWidget(size_label)

        size_info = QLabel()
        size_info.setStyleSheet("color: #58a6ff;")
        status_layout.addWidget(size_info)
        self.resp_size_label = size_info

        status_layout.addSpacing(50)

        time_label = QLabel("TIME:")
        time_label.setStyleSheet("color: #8b949e; font-weight: bold;")
        status_layout.addWidget(time_label)

        time_info = QLabel()
        time_info.setStyleSheet("color: #58a6ff;")
        status_layout.addWidget(time_info)
        self.resp_time_label = time_info

        status_layout.addStretch()
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        content_group = QGroupBox('RESPONSE BODY')
        content_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
                margin-top: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)

        content_layout = QVBoxLayout()
        self.response_body = QTextEdit()
        self.response_body.setReadOnly(True)
        self.response_body.setMinimumHeight(200)
        self.response_body.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 9pt;
                selection-background-color: #1f6feb;
            }
        """)
        content_layout.addWidget(self.response_body)
        content_group.setLayout(content_layout)
        layout.addWidget(content_group, 1)

        return widget

    def create_headers_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #30363d;
                width: 4px;
            }
            QSplitter::handle:hover {
                background-color: #484f58;
            }
        """)

        req_group = QGroupBox('REQUEST HEADERS')
        req_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)

        req_layout = QVBoxLayout()
        self.request_headers = QTextEdit()
        self.request_headers.setReadOnly(True)
        self.request_headers.setMinimumWidth(300)
        self.request_headers.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 9pt;
                selection-background-color: #1f6feb;
            }
        """)
        req_layout.addWidget(self.request_headers)
        req_group.setLayout(req_layout)
        splitter.addWidget(req_group)

        resp_group = QGroupBox('RESPONSE HEADERS')
        resp_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)

        resp_layout = QVBoxLayout()
        self.response_headers = QTextEdit()
        self.response_headers.setReadOnly(True)
        self.response_headers.setMinimumWidth(300)
        self.response_headers.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 9pt;
                selection-background-color: #1f6feb;
            }
        """)
        resp_layout.addWidget(self.response_headers)
        resp_group.setLayout(resp_layout)
        splitter.addWidget(resp_group)

        splitter.setSizes([500, 500])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        layout.addWidget(splitter, 1)

        return widget

    def create_analysis_tab(self):
        widget = QWidget()
        widget.setStyleSheet("background: #0d1117;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        sec_group = QGroupBox('SECURITY HEADERS')
        sec_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)

        sec_layout = QVBoxLayout()
        self.security_analysis = QTextEdit()
        self.security_analysis.setReadOnly(True)
        self.security_analysis.setMinimumHeight(150)
        self.security_analysis.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #2ea043;
                border: 2px solid #238636;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 9pt;
                font-weight: bold;
            }
        """)
        sec_layout.addWidget(self.security_analysis)
        sec_group.setLayout(sec_layout)
        layout.addWidget(sec_group, 1)

        issues_group = QGroupBox('POTENTIAL ISSUES')
        issues_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #da3633;
            }
        """)

        issues_layout = QVBoxLayout()
        self.issues_analysis = QTextEdit()
        self.issues_analysis.setReadOnly(True)
        self.issues_analysis.setMinimumHeight(150)
        self.issues_analysis.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #f85149;
                border: 2px solid #da3633;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 9pt;
                font-weight: bold;
            }
        """)
        issues_layout.addWidget(self.issues_analysis)
        issues_group.setLayout(issues_layout)
        layout.addWidget(issues_group, 1)

        return widget

    def display_request(self, request_data: dict):
        self.current_request = request_data

        url = request_data.get('url', 'N/A')
        method = request_data.get('method', 'GET')
        status = request_data.get('status_code', 0)
        duration = request_data.get('duration', 0)
        response_size = len(request_data.get('response', ''))

        self.method_badge.setText(method)
        self.url_badge.setText(url[:100])

        status_color = {
            (200, 300): '#2ea043',
            (300, 400): '#0969da',
            (400, 500): '#d29922',
            (500, 600): '#da3633',
        }

        for (min_s, max_s), color in status_color.items():
            if min_s <= status < max_s:
                self.status_badge.setStyleSheet(f"""
                    QLabel {{
                        background: {color};
                        padding: 6px 12px;
                        border-radius: 4px;
                        color: white;
                        font-weight: bold;
                    }}
                """)
                self.status_badge.setText(str(status))
                break

        self.size_label.setText(f"{self.format_size(response_size)}")
        self.time_label.setText(f"{duration:.3f}s")

        self.url_text.setText(url)
        self.req_method_label.setText(method)
        self.req_param_label.setText(f"{len(request_data.get('request_headers', {}))} Headers")

        self.resp_status_label.setText(f"{status}")
        self.resp_size_label.setText(self.format_size(response_size))
        self.resp_time_label.setText(f"{duration:.3f}s")
        self.response_body.setText(request_data.get('response', '')[:2000])

        req_headers = request_data.get('request_headers', {})
        self.request_headers.setText('\n'.join([f"{k}: {v}" for k, v in req_headers.items()]) or "No headers")

        resp_headers = request_data.get('response_headers', {})
        self.response_headers.setText('\n'.join([f"{k}: {v}" for k, v in resp_headers.items()]) or "No headers")

        self.analyze_security(resp_headers)

    def analyze_security(self, headers: dict):
        checks = {
            'Content-Security-Policy': ('CSP Configured', 'CSP Not Set'),
            'X-Frame-Options': ('Clickjacking Protection', 'No Protection'),
            'X-Content-Type-Options': ('MIME Sniffing Protection', 'No Protection'),
            'Strict-Transport-Security': ('HSTS Enabled', 'HSTS Not Enabled'),
            'X-XSS-Protection': ('XSS Protection', 'No XSS Protection'),
        }

        sec_text = ""
        issues_text = ""

        for header, (good, bad) in checks.items():
            if header in headers:
                sec_text += f"✓ {good}\n"
            else:
                sec_text += f"✗ {bad}\n"
                issues_text += f"! Missing: {header}\n"

        self.security_analysis.setText(sec_text or "No security headers found")
        self.issues_analysis.setText(issues_text or "No issues detected")

    def format_size(self, size: int) -> str:
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        else:
            return f"{size / (1024 * 1024):.2f} MB"


class RequestMonitorTab(QWidget):
    request_captured = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.requests_history = []
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        header_layout = QHBoxLayout()

        title = QLabel('HTTP REQUEST MONITOR')
        title.setStyleSheet("""
            QLabel {
                font-size: 18pt;
                font-weight: bold;
                color: #58a6ff;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                           stop:0 transparent, stop:1 transparent);
            }
        """)
        header_layout.addWidget(title)

        header_layout.addStretch()

        self.auto_scroll_checkbox = QCheckBox('Auto Scroll')
        self.auto_scroll_checkbox.setChecked(True)
        self.auto_scroll_checkbox.setStyleSheet("""
            QCheckBox {
                color: #c9d1d9;
                spacing: 8px;
            }
        """)
        header_layout.addWidget(self.auto_scroll_checkbox)

        self.clear_button = QPushButton('CLEAR ALL')
        self.clear_button.setMinimumWidth(120)
        self.clear_button.setMinimumHeight(36)
        self.clear_button.clicked.connect(self.clear_requests)
        self.clear_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #da3633, stop:1 #b92222);
                color: white;
                border: 1px solid #f85149;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #f85149, stop:1 #da3633);
            }
        """)
        header_layout.addWidget(self.clear_button)

        self.export_button = QPushButton('EXPORT')
        self.export_button.setMinimumWidth(120)
        self.export_button.setMinimumHeight(36)
        self.export_button.clicked.connect(self.export_requests)
        self.export_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #238636, stop:1 #1a6b2c);
                color: white;
                border: 1px solid #2ea043;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 #2ea043, stop:1 #238636);
            }
        """)
        header_layout.addWidget(self.export_button)

        main_layout.addLayout(header_layout)

        filter_group = QGroupBox('FILTERS & SEARCH')
        filter_group.setMinimumHeight(70)
        filter_group.setStyleSheet("""
            QGroupBox {
                color: #c9d1d9;
                font-weight: bold;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding-top: 12px;
                margin-top: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #58a6ff;
            }
        """)

        filter_layout = QHBoxLayout()
        filter_layout.setContentsMargins(12, 8, 12, 8)
        filter_layout.setSpacing(15)

        filter_layout.addWidget(QLabel('METHOD:'))
        self.method_filter = QComboBox()
        self.method_filter.addItems(['All', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        self.method_filter.currentTextChanged.connect(self.apply_filters)
        self.method_filter.setMinimumWidth(120)
        self.method_filter.setMinimumHeight(32)
        self.method_filter.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 6px 10px;
                font-weight: bold;
            }
            QComboBox:hover {
                border: 2px solid #58a6ff;
            }
        """)
        filter_layout.addWidget(self.method_filter)

        filter_layout.addWidget(QLabel('STATUS:'))
        self.status_filter = QComboBox()
        self.status_filter.addItems(['All', '2xx', '3xx', '4xx', '5xx'])
        self.status_filter.currentTextChanged.connect(self.apply_filters)
        self.status_filter.setMinimumWidth(120)
        self.status_filter.setMinimumHeight(32)
        self.status_filter.setStyleSheet("""
            QComboBox {
                background-color: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 6px 10px;
                font-weight: bold;
            }
            QComboBox:hover {
                border: 2px solid #58a6ff;
            }
        """)
        filter_layout.addWidget(self.status_filter)

        filter_layout.addWidget(QLabel('SEARCH:'))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText('Search URL...')
        self.search_input.textChanged.connect(self.apply_filters)
        self.search_input.setMinimumHeight(32)
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #58a6ff;
            }
        """)
        filter_layout.addWidget(self.search_input, 1)

        filter_layout.addStretch()
        filter_group.setLayout(filter_layout)
        main_layout.addWidget(filter_group)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #30363d;
                height: 4px;
            }
            QSplitter::handle:hover {
                background-color: #484f58;
            }
        """)

        self.requests_table = QTableWidget()
        self.requests_table.setColumnCount(7)
        self.requests_table.setHorizontalHeaderLabels(['#', 'Time', 'Method', 'URL', 'Status', 'Size', 'Duration'])
        self.requests_table.setMinimumHeight(300)

        header = self.requests_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)

        self.requests_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.requests_table.setAlternatingRowColors(True)
        self.requests_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                alternate-background-color: #161b22;
                gridline-color: #30363d;
                border: 2px solid #30363d;
                border-radius: 6px;
                color: #c9d1d9;
            }
            QTableWidget::item:selected {
                background-color: #1f6feb;
                color: white;
                font-weight: bold;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #c9d1d9;
                padding: 10px;
                border: none;
                border-right: 1px solid #30363d;
                font-weight: bold;
            }
        """)

        self.requests_table.itemSelectionChanged.connect(self.show_request_details)
        self.requests_table.setRowHeight(0, 32)
        splitter.addWidget(self.requests_table)

        self.details_widget = RequestDetailsWidget()
        self.details_widget.setMinimumHeight(300)
        splitter.addWidget(self.details_widget)

        splitter.setSizes([350, 450])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        main_layout.addWidget(splitter, 1)

        stats_layout = QHBoxLayout()
        stats_layout.setContentsMargins(0, 10, 0, 0)
        stats_layout.setSpacing(20)

        self.total_requests_label = QLabel('TOTAL: 0')
        self.total_requests_label.setStyleSheet('color: #c9d1d9; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.total_requests_label)

        self.success_label = QLabel('SUCCESS: 0')
        self.success_label.setStyleSheet('color: #2ea043; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.success_label)

        self.error_label = QLabel('ERRORS: 0')
        self.error_label.setStyleSheet('color: #da3633; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.error_label)

        self.avg_time_label = QLabel('AVG: 0.00s')
        self.avg_time_label.setStyleSheet('color: #58a6ff; font-weight: bold; font-size: 11pt;')
        stats_layout.addWidget(self.avg_time_label)

        stats_layout.addStretch()
        main_layout.addLayout(stats_layout)

        self.setLayout(main_layout)

    def add_request(self, request_data: dict):
        self.requests_history.append(request_data)

        row = self.requests_table.rowCount()
        self.requests_table.insertRow(row)
        self.requests_table.setRowHeight(row, 32)

        index_item = QTableWidgetItem(str(row + 1))
        index_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.requests_table.setItem(row, 0, index_item)

        timestamp = QDateTime.currentDateTime().toString('hh:mm:ss')
        time_item = QTableWidgetItem(timestamp)
        time_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.requests_table.setItem(row, 1, time_item)

        method = request_data.get('method', 'GET')
        method_item = QTableWidgetItem(method)
        method_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        method_item.setFont(QFont('Arial', 10, QFont.Weight.Bold))

        colors = {
            'GET': '#0969da',
            'POST': '#1f883d',
            'PUT': '#bf8700',
            'PATCH': '#bf8700',
            'DELETE': '#da3633',
        }
        method_item.setForeground(QColor(colors.get(method, '#666')))
        self.requests_table.setItem(row, 2, method_item)

        url = request_data.get('url', '')
        url_item = QTableWidgetItem(url)
        self.requests_table.setItem(row, 3, url_item)

        status = request_data.get('status_code', 0)
        status_item = QTableWidgetItem(str(status))
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        status_item.setFont(QFont('Arial', 10, QFont.Weight.Bold))

        status_colors = {
            (200, 300): '#2ea043',
            (300, 400): '#0969da',
            (400, 500): '#d29922',
            (500, 600): '#da3633',
        }

        for (min_s, max_s), color in status_colors.items():
            if min_s <= status < max_s:
                status_item.setForeground(QColor(color))
                break

        self.requests_table.setItem(row, 4, status_item)

        size = len(request_data.get('response', ''))
        size_item = QTableWidgetItem(self.format_size(size))
        size_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.requests_table.setItem(row, 5, size_item)

        duration = request_data.get('duration', 0)
        duration_item = QTableWidgetItem(f"{duration:.2f}s")
        duration_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.requests_table.setItem(row, 6, duration_item)

        if self.auto_scroll_checkbox.isChecked():
            self.requests_table.scrollToBottom()

        self.update_statistics()
        self.request_captured.emit(request_data)

    def show_request_details(self):
        selected = self.requests_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        if row < len(self.requests_history):
            self.details_widget.display_request(self.requests_history[row])

    def format_size(self, size: int) -> str:
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        else:
            return f"{size / (1024 * 1024):.2f} MB"

    def apply_filters(self):
        method_filter = self.method_filter.currentText()
        status_filter = self.status_filter.currentText()
        search_text = self.search_input.text().lower()

        for row in range(self.requests_table.rowCount()):
            show = True

            if method_filter != 'All':
                method_item = self.requests_table.item(row, 2)
                if method_item and method_item.text() != method_filter:
                    show = False

            if status_filter != 'All':
                status_item = self.requests_table.item(row, 4)
                if status_item:
                    status = int(status_item.text())
                    ranges = {
                        '2xx': (200, 300),
                        '3xx': (300, 400),
                        '4xx': (400, 500),
                        '5xx': (500, 600),
                    }
                    min_s, max_s = ranges.get(status_filter, (0, 0))
                    if not (min_s <= status < max_s):
                        show = False

            if search_text:
                url_item = self.requests_table.item(row, 3)
                if url_item and search_text not in url_item.text().lower():
                    show = False

            self.requests_table.setRowHidden(row, not show)

    def update_statistics(self):
        total = len(self.requests_history)
        success = sum(1 for r in self.requests_history if 200 <= r.get('status_code', 0) < 300)
        errors = sum(1 for r in self.requests_history if r.get('status_code', 0) >= 400)
        durations = [r.get('duration', 0) for r in self.requests_history if r.get('duration', 0) > 0]
        avg_time = sum(durations) / len(durations) if durations else 0

        self.total_requests_label.setText(f'TOTAL: {total}')
        self.success_label.setText(f'SUCCESS: {success}')
        self.error_label.setText(f'ERRORS: {errors}')
        self.avg_time_label.setText(f'AVG: {avg_time:.2f}s')

    def clear_requests(self):
        self.requests_history.clear()
        self.requests_table.setRowCount(0)
        self.update_statistics()

    def export_requests(self):
        if not self.requests_history:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, 'Export Requests', 'requests.json',
            'JSON Files (*.json);;Text Files (*.txt)'
        )

        if filename:
            if filename.endswith('.json'):
                with open(filename, 'w') as f:
                    json.dump(self.requests_history, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    for idx, req in enumerate(self.requests_history, 1):
                        f.write(f"Request #{idx}\n")
                        f.write(f"URL: {req.get('url')}\n")
                        f.write(f"Method: {req.get('method')}\n")
                        f.write(f"Status: {req.get('status_code')}\n")
                        f.write(f"Duration: {req.get('duration'):.3f}s\n")
                        f.write("=" * 80 + "\n\n")
