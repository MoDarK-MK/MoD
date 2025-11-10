# scan_tab.py - بهبود شده با Intelligent Scanner
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QCheckBox, QGroupBox,
                             QFormLayout, QSpinBox, QDoubleSpinBox, QProgressBar,
                             QComboBox, QTextEdit, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.intelligent_scanner import IntelligentScanner


class ScanWorker(QThread):
    vulnerability_found = pyqtSignal(dict)
    scan_completed = pyqtSignal(list)
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    request_sent = pyqtSignal(dict)
    
    def __init__(self, target_url, scan_types, timeout, verify_ssl, delay, num_workers):
        super().__init__()
        self.target_url = target_url
        self.scan_types = scan_types
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.num_workers = num_workers
        self.should_stop = False
        self.session = requests.Session()
        self.session.verify = verify_ssl
    
    def fetch_url(self, url, method='GET', data=None, headers=None):
        try:
            start_time = time.time()
            
            if method == 'GET':
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers=headers or {}
                )
            else:
                response = self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers=headers or {}
                )
            
            response_time = time.time() - start_time
            
            request_data = {
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'duration': response_time,
                'request_headers': headers or {},
                'response_headers': dict(response.headers),
                'response': response.text[:500]
            }
            self.request_sent.emit(request_data)
            
            return {
                'content': response.text,
                'status_code': response.status_code,
                'response_time': response_time,
                'headers': dict(response.headers)
            }
        except Exception as e:
            response_time = time.time() - start_time
            
            request_data = {
                'url': url,
                'method': method,
                'status_code': 0,
                'duration': response_time,
                'request_headers': headers or {},
                'response_headers': {},
                'response': str(e)[:200]
            }
            self.request_sent.emit(request_data)
            
            return {
                'content': str(e),
                'status_code': 0,
                'response_time': response_time,
                'headers': {}
            }
    
    def inject_payload_in_url(self, base_url, payload):
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        
        if params:
            for key in params.keys():
                params[key] = [payload]
            new_query = urlencode(params, doseq=True)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                             parsed.params, new_query, parsed.fragment))
        else:
            separator = '&' if '?' in base_url else '?'
            return f"{base_url}{separator}test={payload}"
    
    def run(self):
        vulnerabilities = []
        total_scans = len(self.scan_types)
        
        self.status_updated.emit(f'🎯 Target: {self.target_url}')
        
        base_response = self.fetch_url(self.target_url)
        if base_response['status_code'] == 0:
            self.status_updated.emit('❌ Failed to connect to target')
            self.scan_completed.emit([])
            return
        
        self.status_updated.emit(f'✅ Connected (Status: {base_response["status_code"]})')
        
        intelligent_scan_types = {'XSS', 'SQL', 'SSTI'}
        use_intelligent = any(st in intelligent_scan_types for st in self.scan_types)
        
        if use_intelligent:
            self.status_updated.emit('📡 Stage 1: Intelligent Site Mapping...')
            self.progress_updated.emit(5)
            
            try:
                intelligent_scanner = IntelligentScanner(self.session, self.timeout)
                intel_vulns = intelligent_scanner.scan_intelligent(self.target_url, max_pages=15)
                
                vulnerabilities.extend(intel_vulns)
                
                for vuln in intel_vulns:
                    self.vulnerability_found.emit({
                        'type': vuln.get('type'),
                        'severity': f"{int(vuln.get('confidence', 0.5) * 100)}%",
                        'url': vuln.get('url'),
                        'evidence': vuln.get('evidence')
                    })
                
                self.status_updated.emit(f'✅ Intelligent Scanner: {len(intel_vulns)} vulnerabilities')
                self.progress_updated.emit(25)
                
            except Exception as e:
                self.status_updated.emit(f'⚠️ Intelligent Scanner: {str(e)[:50]}')
        
        self.status_updated.emit('🔍 Stage 2: Running Traditional Scanners...')
        
        for idx, scan_type in enumerate(self.scan_types):
            if self.should_stop:
                break
            
            try:
                self.status_updated.emit(f'🔍 Running {scan_type} scanner...')
                vulns = []
                
                if scan_type == 'XSS':
                    vulns = self.scan_xss_fast()
                elif scan_type == 'SQL':
                    vulns = self.scan_sql_fast()
                elif scan_type == 'RCE':
                    vulns = self.scan_rce()
                elif scan_type == 'CommandInjection':
                    vulns = self.scan_command_injection()
                elif scan_type == 'SSRF':
                    vulns = self.scan_ssrf()
                elif scan_type == 'CSRF':
                    vulns = self.scan_csrf()
                elif scan_type == 'XXE':
                    vulns = self.scan_xxe()
                elif scan_type == 'FileUpload':
                    vulns = self.scan_file_upload()
                elif scan_type == 'API':
                    vulns = self.scan_api()
                elif scan_type == 'WebSocket':
                    vulns = self.scan_websocket()
                elif scan_type == 'GraphQL':
                    vulns = self.scan_graphql()
                elif scan_type == 'SSTI':
                    vulns = self.scan_ssti_fast()
                elif scan_type == 'LDAP':
                    vulns = self.scan_ldap()
                elif scan_type == 'OAuth2':
                    vulns = self.scan_oauth()
                
                vulnerabilities.extend(vulns)
                
                for vuln in vulns:
                    self.vulnerability_found.emit({
                        'type': getattr(vuln, 'vulnerability_type', 'Unknown'),
                        'severity': getattr(vuln, 'severity', 'Unknown'),
                        'url': getattr(vuln, 'url', self.target_url),
                        'evidence': getattr(vuln, 'evidence', 'No evidence')
                    })
                
                self.status_updated.emit(f'✅ {scan_type}: {len(vulns)} vulnerabilities')
                
                progress = 25 + int((idx + 1) / total_scans * 75)
                self.progress_updated.emit(progress)
                
            except Exception as e:
                self.status_updated.emit(f'❌ Error in {scan_type}: {str(e)[:50]}')
        
        self.status_updated.emit(f'🎉 Scan completed - Total: {len(vulnerabilities)} vulnerabilities')
        self.scan_completed.emit(vulnerabilities)
    
    def scan_xss_fast(self):
        from scanners.xss_scanner import XSSScanner
        scanner = XSSScanner()
        
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
        ]
        
        with ThreadPoolExecutor(max_workers=min(3, self.num_workers)) as executor:
            futures = []
            for payload in payloads:
                if self.should_stop:
                    break
                
                test_url = self.inject_payload_in_url(self.target_url, payload)
                future = executor.submit(self.fetch_url, test_url)
                futures.append((future, payload, scanner))
            
            all_vulns = []
            for future, payload, scanner in futures:
                if self.should_stop:
                    break
                
                try:
                    response = future.result(timeout=self.timeout)
                    vulns = scanner.scan(self.target_url, response, [payload])
                    all_vulns.extend(vulns)
                    
                    if vulns:
                        break
                except Exception:
                    pass
        
        return all_vulns[:5]
    
    def scan_sql_fast(self):
        from scanners.sql_scanner import SQLScanner
        scanner = SQLScanner()
        
        payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "' AND 1=1--",
        ]
        
        with ThreadPoolExecutor(max_workers=min(3, self.num_workers)) as executor:
            futures = []
            for payload in payloads:
                if self.should_stop:
                    break
                
                test_url = self.inject_payload_in_url(self.target_url, payload)
                future = executor.submit(self.fetch_url, test_url)
                futures.append((future, payload, scanner))
            
            all_vulns = []
            for future, payload, scanner in futures:
                if self.should_stop:
                    break
                
                try:
                    response = future.result(timeout=self.timeout)
                    vulns = scanner.scan(self.target_url, response, [payload])
                    all_vulns.extend(vulns)
                    
                    if vulns:
                        break
                except Exception:
                    pass
        
        return all_vulns[:5]
    
    def scan_ssti_fast(self):
        from scanners.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()
        
        payloads = [
            '{{7*7}}',
            '${7*7}',
            '<%=7*7%>',
        ]
        
        with ThreadPoolExecutor(max_workers=min(3, self.num_workers)) as executor:
            futures = []
            for payload in payloads:
                if self.should_stop:
                    break
                
                test_url = self.inject_payload_in_url(self.target_url, payload)
                future = executor.submit(self.fetch_url, test_url)
                futures.append((future, payload, scanner))
            
            all_vulns = []
            for future, payload, scanner in futures:
                if self.should_stop:
                    break
                
                try:
                    response = future.result(timeout=self.timeout)
                    vulns = scanner.scan(self.target_url, response)
                    all_vulns.extend(vulns)
                    
                    if vulns:
                        break
                except Exception:
                    pass
        
        return all_vulns[:5]
    
    def scan_rce(self):
        from scanners.rce_scanner import RCEScanner
        scanner = RCEScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan(self.target_url, response)
    
    def scan_command_injection(self):
        from scanners.command_injection_scanner import CommandInjectionScanner
        scanner = CommandInjectionScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan(self.target_url, response)
    
    def scan_ssrf(self):
        from scanners.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan(self.target_url, response)
    
    def scan_csrf(self):
        from scanners.csrf_scanner import CSRFScanner
        scanner = CSRFScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan(self.target_url, response)
    
    def scan_xxe(self):
        from scanners.xxe_scanner import XXEScanner
        scanner = XXEScanner()
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ]
        response = self.fetch_url(self.target_url)
        return scanner.scan(self.target_url, response, payloads)
    
    def scan_file_upload(self):
        from scanners.file_upload_scanner import FileUploadScanner
        scanner = FileUploadScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan(self.target_url, response)
    
    def scan_api(self):
        from scanners.api_scanner import APIScanner
        scanner = APIScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan_oauth(self.target_url, response)
    
    def scan_websocket(self):
        from scanners.websocket_scanner import WebSocketScanner
        scanner = WebSocketScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan(self.target_url, response)
    
    def scan_graphql(self):
        from scanners.graphql_scanner import GraphQLScanner
        scanner = GraphQLScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan(self.target_url, response)
    
    def scan_ldap(self):
        from scanners.ldap_scanner import LDAPScanner
        scanner = LDAPScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan(self.target_url, response)
    
    def scan_oauth(self):
        from scanners.oauth_saml_scanner import OAuthSAMLScanner
        scanner = OAuthSAMLScanner()
        response = self.fetch_url(self.target_url)
        return scanner.scan_oauth(self.target_url, response)
    
    def stop(self):
        self.should_stop = True


class ScanTab(QWidget):
    request_sent = pyqtSignal(dict)
    scan_started = pyqtSignal(str)
    scan_completed = pyqtSignal(list)
    vulnerability_found = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.is_scanning = False
        self.scan_worker = None
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)
        
        target_group = QGroupBox('Target Configuration')
        target_layout = QFormLayout()
        
        self.target_url_input = QLineEdit()
        self.target_url_input.setPlaceholderText('Enter target URL (e.g., https://example.com/page?id=1)')
        target_layout.addRow('Target URL:', self.target_url_input)
        
        target_group.setLayout(target_layout)
        main_layout.addWidget(target_group)
        
        scanner_group = QGroupBox('Scanner Selection')
        scanner_layout = QVBoxLayout()
        
        self.xss_checkbox = QCheckBox('🔴 XSS Injection')
        self.sql_checkbox = QCheckBox('💉 SQL Injection')
        self.rce_checkbox = QCheckBox('💣 Remote Code Execution')
        self.cmd_checkbox = QCheckBox('⚡ Command Injection')
        self.ssrf_checkbox = QCheckBox('🌐 Server-Side Request Forgery')
        self.csrf_checkbox = QCheckBox('🔗 CSRF (Cross-Site Request Forgery)')
        self.xxe_checkbox = QCheckBox('📄 XXE (XML External Entity)')
        self.upload_checkbox = QCheckBox('📁 File Upload Vulnerabilities')
        self.api_checkbox = QCheckBox('🔌 API Security Testing')
        self.websocket_checkbox = QCheckBox('🔌 WebSocket Security')
        self.graphql_checkbox = QCheckBox('📊 GraphQL Testing')
        self.ssti_checkbox = QCheckBox('🎭 Server-Side Template Injection')
        self.ldap_checkbox = QCheckBox('🔐 LDAP Injection')
        self.oauth_checkbox = QCheckBox('🔑 OAuth2/SAML')
        
        for checkbox in [self.xss_checkbox, self.sql_checkbox, self.rce_checkbox,
                        self.cmd_checkbox, self.ssrf_checkbox, self.csrf_checkbox,
                        self.xxe_checkbox, self.upload_checkbox, self.api_checkbox,
                        self.websocket_checkbox, self.graphql_checkbox, self.ssti_checkbox,
                        self.ldap_checkbox, self.oauth_checkbox]:
            scanner_layout.addWidget(checkbox)
            checkbox.setChecked(True)
        
        select_all_btn = QPushButton('Select All / Deselect All')
        select_all_btn.clicked.connect(self.select_all_scanners)
        scanner_layout.addWidget(select_all_btn)
        
        scanner_group.setLayout(scanner_layout)
        main_layout.addWidget(scanner_group)
        
        settings_group = QGroupBox('Scan Settings')
        settings_layout = QFormLayout()
        
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(2, 50)
        self.threads_spinbox.setValue(10)
        settings_layout.addRow('Concurrent Threads:', self.threads_spinbox)
        
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(5, 60)
        self.timeout_spinbox.setValue(15)
        self.timeout_spinbox.setSuffix(' seconds')
        settings_layout.addRow('Request Timeout:', self.timeout_spinbox)
        
        self.delay_spinbox = QDoubleSpinBox()
        self.delay_spinbox.setRange(0, 5)
        self.delay_spinbox.setValue(0.1)
        self.delay_spinbox.setSuffix(' seconds')
        settings_layout.addRow('Request Delay:', self.delay_spinbox)
        
        self.verify_ssl_checkbox = QCheckBox('Verify SSL Certificate')
        self.verify_ssl_checkbox.setChecked(False)
        settings_layout.addRow('SSL/TLS:', self.verify_ssl_checkbox)
        
        settings_group.setLayout(settings_layout)
        main_layout.addWidget(settings_group)
        
        self.status_label = QLabel('Ready')
        main_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton('▶️ Start Scan')
        self.start_button.setMinimumHeight(50)
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton('⏹️ Stop Scan')
        self.stop_button.setMinimumHeight(50)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        button_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton('🗑️ Clear')
        self.clear_button.setMinimumHeight(50)
        self.clear_button.clicked.connect(self.clear_inputs)
        button_layout.addWidget(self.clear_button)
        
        main_layout.addLayout(button_layout)
        main_layout.addStretch()
        
        self.setLayout(main_layout)
    
    def start_scan(self):
        target_url = self.target_url_input.text().strip()
        if not target_url:
            QMessageBox.warning(self, 'Warning', 'Please enter a target URL')
            return
        
        if not target_url.startswith('http'):
            QMessageBox.warning(self, 'Warning', 'URL must start with http:// or https://')
            return
        
        scan_types = []
        if self.xss_checkbox.isChecked():
            scan_types.append('XSS')
        if self.sql_checkbox.isChecked():
            scan_types.append('SQL')
        if self.rce_checkbox.isChecked():
            scan_types.append('RCE')
        if self.cmd_checkbox.isChecked():
            scan_types.append('CommandInjection')
        if self.ssrf_checkbox.isChecked():
            scan_types.append('SSRF')
        if self.csrf_checkbox.isChecked():
            scan_types.append('CSRF')
        if self.xxe_checkbox.isChecked():
            scan_types.append('XXE')
        if self.upload_checkbox.isChecked():
            scan_types.append('FileUpload')
        if self.api_checkbox.isChecked():
            scan_types.append('API')
        if self.websocket_checkbox.isChecked():
            scan_types.append('WebSocket')
        if self.graphql_checkbox.isChecked():
            scan_types.append('GraphQL')
        if self.ssti_checkbox.isChecked():
            scan_types.append('SSTI')
        if self.ldap_checkbox.isChecked():
            scan_types.append('LDAP')
        if self.oauth_checkbox.isChecked():
            scan_types.append('OAuth2')
        
        if not scan_types:
            QMessageBox.warning(self, 'Warning', 'Please select at least one scanner')
            return
        
        self.is_scanning = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText('🚀 Starting scan...')
        
        self.scan_started.emit(target_url)
        
        timeout = self.timeout_spinbox.value()
        verify_ssl = self.verify_ssl_checkbox.isChecked()
        num_workers = self.threads_spinbox.value()
        
        self.scan_worker = ScanWorker(target_url, scan_types, timeout, verify_ssl, 0.05, num_workers)
        self.scan_worker.vulnerability_found.connect(self.on_vulnerability_found)
        self.scan_worker.scan_completed.connect(self.on_scan_completed)
        self.scan_worker.progress_updated.connect(self.progress_bar.setValue)
        self.scan_worker.status_updated.connect(self.status_label.setText)
        self.scan_worker.request_sent.connect(self.on_request_sent)
        self.scan_worker.start()
    
    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
            self.scan_worker.wait()
        
        self.is_scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText('⏹️ Scan stopped')
    
    def on_vulnerability_found(self, vulnerability: dict):
        self.vulnerability_found.emit(vulnerability)
    
    def on_request_sent(self, request_data: dict):
        self.request_sent.emit(request_data)
    
    def on_scan_completed(self, results: list):
        self.scan_completed.emit(results)
        self.is_scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
    
    def select_all_scanners(self):
        is_checked = self.xss_checkbox.isChecked()
        for checkbox in [self.xss_checkbox, self.sql_checkbox, self.rce_checkbox,
                        self.cmd_checkbox, self.ssrf_checkbox, self.csrf_checkbox,
                        self.xxe_checkbox, self.upload_checkbox, self.api_checkbox,
                        self.websocket_checkbox, self.graphql_checkbox, self.ssti_checkbox,
                        self.ldap_checkbox, self.oauth_checkbox]:
            checkbox.setChecked(not is_checked)
    
    def clear_inputs(self):
        self.target_url_input.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText('Ready')
    
    def set_auth_manager(self, auth_manager):
        pass
