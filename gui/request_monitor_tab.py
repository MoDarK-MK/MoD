from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QHeaderView, QLabel,
                             QLineEdit, QComboBox, QTextEdit, QSplitter, QGroupBox,
                             QCheckBox)
from PyQt6.QtCore import Qt, pyqtSignal, QDateTime
from PyQt6.QtGui import QColor
import json

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
        
        title_label = QLabel('📡 HTTP Request Monitor')
        title_label.setStyleSheet('font-size: 16pt; font-weight: bold;')
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        self.auto_scroll_checkbox = QCheckBox('Auto Scroll')
        self.auto_scroll_checkbox.setChecked(True)
        header_layout.addWidget(self.auto_scroll_checkbox)
        
        self.clear_button = QPushButton('🗑️ Clear All')
        self.clear_button.clicked.connect(self.clear_requests)
        header_layout.addWidget(self.clear_button)
        
        self.export_button = QPushButton('💾 Export')
        self.export_button.clicked.connect(self.export_requests)
        header_layout.addWidget(self.export_button)
        
        main_layout.addLayout(header_layout)
        
        filter_group = QGroupBox('Filters')
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel('Method:'))
        self.method_filter = QComboBox()
        self.method_filter.addItems(['All', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        self.method_filter.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.method_filter)
        
        filter_layout.addWidget(QLabel('Status:'))
        self.status_filter = QComboBox()
        self.status_filter.addItems(['All', '2xx', '3xx', '4xx', '5xx'])
        self.status_filter.currentTextChanged.connect(self.apply_filters)
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
        self.requests_table.setHorizontalHeaderLabels([
            '#', 'Time', 'Method', 'URL', 'Status', 'Size', 'Duration'
        ])
        
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
        self.requests_table.itemSelectionChanged.connect(self.show_request_details)
        
        splitter.addWidget(self.requests_table)
        
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        details_label = QLabel('Request Details')
        details_label.setStyleSheet('font-weight: bold; font-size: 12pt;')
        details_layout.addWidget(details_label)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        splitter.addWidget(details_widget)
        splitter.setSizes([400, 300])
        
        main_layout.addWidget(splitter)
        
        stats_layout = QHBoxLayout()
        
        self.total_requests_label = QLabel('Total: 0')
        stats_layout.addWidget(self.total_requests_label)
        
        self.success_label = QLabel('✅ Success: 0')
        self.success_label.setStyleSheet('color: #2ea043;')
        stats_layout.addWidget(self.success_label)
        
        self.error_label = QLabel('❌ Errors: 0')
        self.error_label.setStyleSheet('color: #da3633;')
        stats_layout.addWidget(self.error_label)
        
        self.avg_time_label = QLabel('⏱️ Avg: 0.00s')
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
        
        if method == 'GET':
            method_item.setForeground(QColor('#0969da'))
        elif method == 'POST':
            method_item.setForeground(QColor('#1f883d'))
        elif method in ['PUT', 'PATCH']:
            method_item.setForeground(QColor('#bf8700'))
        elif method == 'DELETE':
            method_item.setForeground(QColor('#da3633'))
        
        self.requests_table.setItem(row, 2, method_item)
        
        url = request_data.get('url', '')
        url_item = QTableWidgetItem(url)
        self.requests_table.setItem(row, 3, url_item)
        
        status = request_data.get('status_code', 0)
        status_item = QTableWidgetItem(str(status))
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        if 200 <= status < 300:
            status_item.setForeground(QColor('#2ea043'))
        elif 300 <= status < 400:
            status_item.setForeground(QColor('#0969da'))
        elif 400 <= status < 500:
            status_item.setForeground(QColor('#d29922'))
        elif status >= 500:
            status_item.setForeground(QColor('#da3633'))
        
        self.requests_table.setItem(row, 4, status_item)
        
        size = len(request_data.get('response', ''))
        size_str = self.format_size(size)
        size_item = QTableWidgetItem(size_str)
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
        selected_rows = self.requests_table.selectedItems()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        if row >= len(self.requests_history):
            return
        
        request = self.requests_history[row]
        
        details = f"""
═══════════════════════════════════════════════════════════════════
                        REQUEST DETAILS #{row + 1}
═══════════════════════════════════════════════════════════════════

📍 URL: {request.get('url', 'N/A')}

🔧 METHOD: {request.get('method', 'GET')}

📊 STATUS CODE: {request.get('status_code', 0)}

⏱️ DURATION: {request.get('duration', 0):.3f} seconds

📦 RESPONSE SIZE: {self.format_size(len(request.get('response', '')))}

───────────────────────────────────────────────────────────────────
📤 REQUEST HEADERS:
───────────────────────────────────────────────────────────────────
{self.format_dict(request.get('request_headers', {}))}

───────────────────────────────────────────────────────────────────
📥 RESPONSE HEADERS:
───────────────────────────────────────────────────────────────────
{self.format_dict(request.get('response_headers', {}))}

───────────────────────────────────────────────────────────────────
📄 RESPONSE BODY (Preview):
───────────────────────────────────────────────────────────────────
{request.get('response', '')[:500]}
{'...' if len(request.get('response', '')) > 500 else ''}

═══════════════════════════════════════════════════════════════════
"""
        self.details_text.setPlainText(details)
    
    def format_dict(self, data: dict) -> str:
        if not data:
            return '  (empty)'
        return '\n'.join([f"  {k}: {v}" for k, v in data.items()])
    
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
            show_row = True
            
            if method_filter != 'All':
                method_item = self.requests_table.item(row, 2)
                if method_item and method_item.text() != method_filter:
                    show_row = False
            
            if status_filter != 'All':
                status_item = self.requests_table.item(row, 4)
                if status_item:
                    status = int(status_item.text())
                    if status_filter == '2xx' and not (200 <= status < 300):
                        show_row = False
                    elif status_filter == '3xx' and not (300 <= status < 400):
                        show_row = False
                    elif status_filter == '4xx' and not (400 <= status < 500):
                        show_row = False
                    elif status_filter == '5xx' and not (500 <= status < 600):
                        show_row = False
            
            if search_text:
                url_item = self.requests_table.item(row, 3)
                if url_item and search_text not in url_item.text().lower():
                    show_row = False
            
            self.requests_table.setRowHidden(row, not show_row)
    
    def update_statistics(self):
        total = len(self.requests_history)
        success = sum(1 for r in self.requests_history if 200 <= r.get('status_code', 0) < 300)
        errors = sum(1 for r in self.requests_history if r.get('status_code', 0) >= 400)
        
        durations = [r.get('duration', 0) for r in self.requests_history if r.get('duration', 0) > 0]
        avg_time = sum(durations) / len(durations) if durations else 0
        
        self.total_requests_label.setText(f'Total: {total}')
        self.success_label.setText(f'✅ Success: {success}')
        self.error_label.setText(f'❌ Errors: {errors}')
        self.avg_time_label.setText(f'⏱️ Avg: {avg_time:.2f}s')
    
    def clear_requests(self):
        self.requests_history.clear()
        self.requests_table.setRowCount(0)
        self.details_text.clear()
        self.update_statistics()
    
    def export_requests(self):
        from PyQt6.QtWidgets import QFileDialog
        
        if not self.requests_history:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            'Export Requests',
            'requests_log.json',
            'JSON Files (*.json);;Text Files (*.txt)'
        )
        
        if filename:
            if filename.endswith('.json'):
                with open(filename, 'w') as f:
                    json.dump(self.requests_history, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    for idx, req in enumerate(self.requests_history):
                        f.write(f"Request #{idx + 1}\n")
                        f.write(f"URL: {req.get('url')}\n")
                        f.write(f"Method: {req.get('method')}\n")
                        f.write(f"Status: {req.get('status_code')}\n")
                        f.write(f"Duration: {req.get('duration'):.3f}s\n")
                        f.write("=" * 80 + "\n\n")
