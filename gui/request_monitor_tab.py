# gui/request_monitor_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QHeaderView, QLabel,
                             QLineEdit, QComboBox, QTextEdit, QSplitter, QGroupBox,
                             QCheckBox, QTabWidget, QScrollArea, QFileDialog, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal, QDateTime
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
                color: #0969da;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background: #fafafa;
            }
        """)

        tabs.addTab(self.create_request_tab(), 'Request')
        tabs.addTab(self.create_response_tab(), 'Response')
        tabs.addTab(self.create_headers_tab(), 'Headers')
        tabs.addTab(self.create_analysis_tab(), 'Analysis')

        main_layout.addWidget(tabs)
        self.setLayout(main_layout)

    def create_header(self):
        header = QWidget()
        header.setStyleSheet("""
            QWidget {
                background: linear-gradient(135deg, #0969da 0%, #0d6efd 100%);
                padding: 15px;
                border-radius: 4px;
            }
            QLabel {
                color: white;
            }
        """)

        layout = QVBoxLayout(header)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(8)

        row1 = QHBoxLayout()
        self.method_badge = QLabel()
        self.method_badge.setFont(QFont('Arial', 10, QFont.Weight.Bold))
        self.method_badge.setStyleSheet("""
            QLabel {
                background: rgba(255,255,255,0.2);
                padding: 4px 8px;
                border-radius: 3px;
                min-width: 50px;
                text-align: center;
            }
        """)
        row1.addWidget(self.method_badge)

        self.url_badge = QLabel()
        self.url_badge.setFont(QFont('Courier New', 9))
        self.url_badge.setStyleSheet("color: white; word-wrap: break-word;")
        row1.addWidget(self.url_badge, 1)

        layout.addLayout(row1)

        row2 = QHBoxLayout()

        self.status_badge = QLabel()
        self.status_badge.setFont(QFont('Arial', 9, QFont.Weight.Bold))
        self.status_badge.setStyleSheet("""
            QLabel {
                background: rgba(255,255,255,0.2);
                padding: 4px 8px;
                border-radius: 3px;
                min-width: 60px;
                text-align: center;
            }
        """)
        row2.addWidget(self.status_badge)

        self.size_label = QLabel()
        self.size_label.setFont(QFont('Arial', 9))
        row2.addWidget(self.size_label)

        self.time_label = QLabel()
        self.time_label.setFont(QFont('Arial', 9))
        row2.addWidget(self.time_label)

        row2.addStretch()
        layout.addLayout(row2)

        return header

    def create_request_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        url_group = QGroupBox('Request URL')
        url_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)

        url_layout = QVBoxLayout()
        self.url_text = QTextEdit()
        self.url_text.setReadOnly(True)
        self.url_text.setMaximumHeight(60)
        self.url_text.setStyleSheet("""
            QTextEdit {
                background: #f9f9f9;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Courier New';
                font-size: 10pt;
                selection-background-color: #0969da;
            }
        """)
        url_layout.addWidget(self.url_text)
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)

        detail_group = QGroupBox('Request Details')
        detail_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
                margin-top: 10px;
            }
        """)

        detail_layout = QVBoxLayout()

        detail_info = QHBoxLayout()

        method_info = QLabel()
        method_info.setStyleSheet("font-weight: bold; color: #0969da;")
        detail_info.addWidget(QLabel("Method:"))
        detail_info.addWidget(method_info)
        self.req_method_label = method_info

        detail_info.addSpacing(30)

        param_info = QLabel()
        detail_info.addWidget(QLabel("Parameters:"))
        detail_info.addWidget(param_info)
        self.req_param_label = param_info

        detail_info.addStretch()
        detail_layout.addLayout(detail_info)

        detail_group.setLayout(detail_layout)
        layout.addWidget(detail_group)

        body_group = QGroupBox('Request Body')
        body_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
                margin-top: 10px;
            }
        """)

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
        status_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
                margin-top: 10px;
            }
        """)

        status_layout = QHBoxLayout()

        status_info = QLabel()
        status_info.setStyleSheet("font-weight: bold; font-size: 12pt;")
        status_layout.addWidget(QLabel("Status:"))
        status_layout.addWidget(status_info)
        self.resp_status_label = status_info

        status_layout.addSpacing(30)

        size_info = QLabel()
        status_layout.addWidget(QLabel("Size:"))
        status_layout.addWidget(size_info)
        self.resp_size_label = size_info

        status_layout.addSpacing(30)

        time_info = QLabel()
        status_layout.addWidget(QLabel("Time:"))
        status_layout.addWidget(time_info)
        self.resp_time_label = time_info

        status_layout.addStretch()
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        content_group = QGroupBox('Response Content')
        content_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
                margin-top: 10px;
            }
        """)

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
        req_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
            }
        """)

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
        resp_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
            }
        """)

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

        sec_group = QGroupBox('Security Headers Analysis')
        sec_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
            }
        """)

        sec_layout = QVBoxLayout()
        self.security_analysis = QTextEdit()
        self.security_analysis.setReadOnly(True)
        self.security_analysis.setStyleSheet("""
            QTextEdit {
                background: #f0fff4;
                border: 1px solid #86efac;
                border-radius: 4px;
                font-family: 'Courier New';
                font-size: 9pt;
            }
        """)
        sec_layout.addWidget(self.security_analysis)
        sec_group.setLayout(sec_layout)
        layout.addWidget(sec_group)

        issues_group = QGroupBox('Potential Issues')
        issues_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
            }
        """)

        issues_layout = QVBoxLayout()
        self.issues_analysis = QTextEdit()
        self.issues_analysis.setReadOnly(True)
        self.issues_analysis.setStyleSheet("""
            QTextEdit {
                background: #fff5f5;
                border: 1px solid #fca5a5;
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
                        padding: 4px 8px;
                        border-radius: 3px;
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
        self.req_param_label.setText(f"{len(request_data.get('request_headers', {}))} headers")

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
            'Content-Security-Policy': ('CSP configured', 'CSP not set'),
            'X-Frame-Options': ('Clickjacking protection enabled', 'No protection'),
            'X-Content-Type-Options': ('MIME protection', 'No MIME protection'),
            'Strict-Transport-Security': ('HSTS enabled', 'No HSTS'),
        }

        sec_text = ""
        issues_text = ""

        for header, (good, bad) in checks.items():
            if header in headers:
                sec_text += f"OK: {good}\n"
            else:
                sec_text += f"MISSING: {bad}\n"
                issues_text += f"Missing: {header}\n"

        self.security_analysis.setText(sec_text)
        self.issues_analysis.setText(issues_text or "No issues")

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

        title = QLabel('HTTP Request Monitor')
        title.setStyleSheet('font-size: 16pt; font-weight: bold; color: #0969da;')
        header_layout.addWidget(title)

        header_layout.addStretch()

        self.auto_scroll_checkbox = QCheckBox('Auto Scroll')
        self.auto_scroll_checkbox.setChecked(True)
        header_layout.addWidget(self.auto_scroll_checkbox)

        self.clear_button = QPushButton('Clear All')
        self.clear_button.clicked.connect(self.clear_requests)
        header_layout.addWidget(self.clear_button)

        self.export_button = QPushButton('Export')
        self.export_button.clicked.connect(self.export_requests)
        header_layout.addWidget(self.export_button)

        main_layout.addLayout(header_layout)

        filter_group = QGroupBox('Filters & Search')
        filter_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding-top: 10px;
                margin-top: 5px;
            }
        """)

        filter_layout = QHBoxLayout()

        filter_layout.addWidget(QLabel('Method:'))
        self.method_filter = QComboBox()
        self.method_filter.addItems(['All', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        self.method_filter.currentTextChanged.connect(self.apply_filters)
        self.method_filter.setMaximumWidth(100)
        filter_layout.addWidget(self.method_filter)

        filter_layout.addWidget(QLabel('Status:'))
        self.status_filter = QComboBox()
        self.status_filter.addItems(['All', '2xx', '3xx', '4xx', '5xx'])
        self.status_filter.currentTextChanged.connect(self.apply_filters)
        self.status_filter.setMaximumWidth(100)
        filter_layout.addWidget(self.status_filter)

        filter_layout.addWidget(QLabel('Search:'))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText('Search URL...')
        self.search_input.textChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.search_input)

        filter_layout.addStretch()
        filter_group.setLayout(filter_layout)
        main_layout.addWidget(filter_group)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.requests_table = QTableWidget()
        self.requests_table.setColumnCount(7)
        self.requests_table.setHorizontalHeaderLabels(['#', 'Time', 'Method', 'URL', 'Status', 'Size', 'Duration'])

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
                border: 1px solid #e0e0e0;
                border-radius: 4px;
            }
            QTableWidget::item:selected {
                background-color: #e7f1ff;
            }
            QHeaderView::section {
                background: #f5f5f5;
                padding: 8px;
                border: none;
                border-right: 1px solid #e0e0e0;
                font-weight: bold;
            }
        """)

        self.requests_table.itemSelectionChanged.connect(self.show_request_details)
        splitter.addWidget(self.requests_table)

        self.details_widget = RequestDetailsWidget()
        splitter.addWidget(self.details_widget)

        splitter.setSizes([350, 400])
        main_layout.addWidget(splitter)

        stats_layout = QHBoxLayout()

        self.total_requests_label = QLabel('Total: 0')
        self.total_requests_label.setStyleSheet('font-weight: bold;')
        stats_layout.addWidget(self.total_requests_label)

        self.success_label = QLabel('Success: 0')
        self.success_label.setStyleSheet('color: #2ea043; font-weight: bold;')
        stats_layout.addWidget(self.success_label)

        self.error_label = QLabel('Errors: 0')
        self.error_label.setStyleSheet('color: #da3633; font-weight: bold;')
        stats_layout.addWidget(self.error_label)

        self.avg_time_label = QLabel('Avg: 0.00s')
        stats_layout.addWidget(self.avg_time_label)

        stats_layout.addStretch()
        main_layout.addLayout(stats_layout)

        self.setLayout(main_layout)

    def add_request(self, request_data: dict):
        self.requests_history.append(request_data)

        row = self.requests_table.rowCount()
        self.requests_table.insertRow(row)

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
        method_item.setFont(QFont('Arial', 9, QFont.Weight.Bold))

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
        status_item.setFont(QFont('Arial', 9, QFont.Weight.Bold))

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

        self.total_requests_label.setText(f'Total: {total}')
        self.success_label.setText(f'Success: {success}')
        self.error_label.setText(f'Errors: {errors}')
        self.avg_time_label.setText(f'Avg: {avg_time:.2f}s')

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
