# gui/main_window.py
from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, 
                             QWidget, QStatusBar, QMenuBar, QMenu, QToolBar, 
                             QMessageBox, QSizePolicy, QLabel, QHBoxLayout)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QIcon, QFont
from .scan_tab import ScanTab
from .results_tab import ResultsTab
from .settings_tab import SettingsTab
from .auth_tab import AuthTab
from .subdomain_tab import SubdomainTab
from .wayback_tab import WaybackTab
from .advanced_settings_tab import AdvancedSettingsTab
from .theme_manager import ThemeManager
from .request_monitor_tab import RequestMonitorTab
from .cve_scanner_tab import CVEScannerTab
from .waf_bypass_tab import WAFBypassTab
import time


class MainWindow(QMainWindow):
    
    def __init__(self):
        super().__init__()
        self.theme_manager = ThemeManager()
        self.scan_stats = {'total_scans': 0, 'vulnerabilities_found': 0, 'bypassed_wafs': 0}
        self.init_ui()
        self.apply_theme()
        self.setWindowTitle('MoD - Master of Defense v4.0 Enterprise | The Ultimate Pentesting Suite')
        self.setMinimumSize(QSize(1600, 1000))
        self.setup_status_timer()
    
    def init_ui(self):
        self.create_menu_bar()
        self.create_toolbar()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.TabPosition.North)
        self.tab_widget.setMovable(True)
        self.tab_widget.setTabsClosable(False)
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #30363d;
                background: #0d1117;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #161b22;
                color: #8b949e;
                padding: 12px 24px;
                margin-right: 4px;
                border: 2px solid #30363d;
                border-bottom: none;
                font-weight: bold;
                font-size: 11pt;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:hover {
                background: #21262d;
                color: #c9d1d9;
                border: 2px solid #58a6ff;
            }
            QTabBar::tab:selected {
                background: #0d1117;
                color: #58a6ff;
                border: 2px solid #1f6feb;
                border-bottom: none;
            }
        """)
        
        self.scan_tab = ScanTab()
        self.results_tab = ResultsTab()
        self.cve_scanner_tab = CVEScannerTab()
        self.waf_bypass_tab = WAFBypassTab()
        self.subdomain_tab = SubdomainTab()
        self.wayback_tab = WaybackTab()
        self.auth_tab = AuthTab()
        self.request_monitor_tab = RequestMonitorTab()
        self.settings_tab = SettingsTab()
        self.advanced_settings_tab = AdvancedSettingsTab()
        
        self.tab_widget.addTab(self.scan_tab, '🎯 Vulnerability Scan')
        self.tab_widget.addTab(self.results_tab, '📊 Scan Results')
        self.tab_widget.addTab(self.cve_scanner_tab, '🔍 CVE Scanner')
        self.tab_widget.addTab(self.waf_bypass_tab, '🔥 WAF Bypass')
        self.tab_widget.addTab(self.request_monitor_tab, '📡 Request Monitor')
        self.tab_widget.addTab(self.subdomain_tab, '🌐 Subdomain Enum')
        self.tab_widget.addTab(self.wayback_tab, '⏰ Wayback URLs')
        self.tab_widget.addTab(self.auth_tab, '🔐 Authentication')
        self.tab_widget.addTab(self.settings_tab, '⚙️ Settings')
        self.tab_widget.addTab(self.advanced_settings_tab, '🔧 Advanced')
        
        layout.addWidget(self.tab_widget)
        
        self.create_status_bar()
        
        self.scan_tab.scan_started.connect(self.on_scan_started)
        self.scan_tab.scan_completed.connect(self.on_scan_completed)
        self.scan_tab.vulnerability_found.connect(self.on_vulnerability_found)
        self.scan_tab.request_sent.connect(self.request_monitor_tab.add_request)
        
        self.subdomain_tab.scan_started.connect(lambda d: self.update_status(f'🌐 Enumerating: {d}', '#58a6ff'))
        self.subdomain_tab.scan_completed.connect(self.on_subdomain_completed)
        
        self.wayback_tab.fetch_started.connect(lambda d: self.update_status(f'⏰ Fetching Wayback: {d}', '#d29922'))
        self.wayback_tab.fetch_completed.connect(self.on_wayback_completed)
        
        self.settings_tab.theme_changed.connect(self.on_theme_changed)
        self.settings_tab.settings_changed.connect(self.on_settings_changed)
        self.auth_tab.auth_configured.connect(self.on_auth_configured)
        self.advanced_settings_tab.settings_changed.connect(self.on_advanced_settings_changed)
    
    def create_menu_bar(self):
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background: #161b22;
                color: #c9d1d9;
                padding: 4px;
                border-bottom: 2px solid #30363d;
            }
            QMenuBar::item {
                background: transparent;
                padding: 8px 12px;
                border-radius: 4px;
            }
            QMenuBar::item:selected {
                background: #1f6feb;
                color: white;
            }
            QMenu {
                background: #161b22;
                color: #c9d1d9;
                border: 2px solid #30363d;
                border-radius: 6px;
            }
            QMenu::item {
                padding: 8px 24px;
            }
            QMenu::item:selected {
                background: #1f6feb;
                color: white;
            }
        """)
        
        file_menu = menubar.addMenu('&File')
        
        new_scan_action = QAction('🎯 &New Vulnerability Scan', self)
        new_scan_action.setShortcut('Ctrl+N')
        new_scan_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.scan_tab))
        file_menu.addAction(new_scan_action)
        
        new_cve_scan = QAction('🔍 New &CVE Scan', self)
        new_cve_scan.setShortcut('Ctrl+Shift+C')
        new_cve_scan.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.cve_scanner_tab))
        file_menu.addAction(new_cve_scan)
        
        new_waf_bypass = QAction('🔥 New &WAF Bypass', self)
        new_waf_bypass.setShortcut('Ctrl+Shift+W')
        new_waf_bypass.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.waf_bypass_tab))
        file_menu.addAction(new_waf_bypass)
        
        file_menu.addSeparator()
        
        export_action = QAction('💾 &Export Results', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('🚪 E&xit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        view_menu = menubar.addMenu('&View')
        
        dark_theme_action = QAction('🌙 Dark Theme', self)
        dark_theme_action.setShortcut('Ctrl+D')
        dark_theme_action.triggered.connect(lambda: self.on_theme_changed('dark'))
        view_menu.addAction(dark_theme_action)
        
        light_theme_action = QAction('☀️ Light Theme', self)
        light_theme_action.setShortcut('Ctrl+L')
        light_theme_action.triggered.connect(lambda: self.on_theme_changed('light'))
        view_menu.addAction(light_theme_action)
        
        view_menu.addSeparator()
        
        fullscreen_action = QAction('🖥️ Toggle Fullscreen', self)
        fullscreen_action.setShortcut('F11')
        fullscreen_action.triggered.connect(self.toggle_fullscreen)
        view_menu.addAction(fullscreen_action)
        
        tools_menu = menubar.addMenu('&Tools')
        
        cve_scanner_action = QAction('🔍 CVE Scanner', self)
        cve_scanner_action.setShortcut('Ctrl+1')
        cve_scanner_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.cve_scanner_tab))
        tools_menu.addAction(cve_scanner_action)
        
        waf_bypass_action = QAction('🔥 WAF Bypass Engine', self)
        waf_bypass_action.setShortcut('Ctrl+2')
        waf_bypass_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.waf_bypass_tab))
        tools_menu.addAction(waf_bypass_action)
        
        request_monitor_action = QAction('📡 Request Monitor', self)
        request_monitor_action.setShortcut('Ctrl+3')
        request_monitor_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.request_monitor_tab))
        tools_menu.addAction(request_monitor_action)
        
        tools_menu.addSeparator()
        
        subdomain_action = QAction('🌐 Subdomain Scanner', self)
        subdomain_action.setShortcut('Ctrl+4')
        subdomain_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.subdomain_tab))
        tools_menu.addAction(subdomain_action)
        
        wayback_action = QAction('⏰ Wayback Machine', self)
        wayback_action.setShortcut('Ctrl+5')
        wayback_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.wayback_tab))
        tools_menu.addAction(wayback_action)
        
        help_menu = menubar.addMenu('&Help')
        
        docs_action = QAction('📚 Documentation', self)
        docs_action.setShortcut('F1')
        docs_action.triggered.connect(self.show_documentation)
        help_menu.addAction(docs_action)
        
        help_menu.addSeparator()
        
        about_action = QAction('ℹ️ About MoD', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setStyleSheet("""
            QToolBar {
                background: #161b22;
                border-bottom: 2px solid #30363d;
                padding: 8px;
                spacing: 8px;
            }
            QToolBar::separator {
                background: #30363d;
                width: 2px;
                margin: 0 8px;
            }
        """)
        self.addToolBar(toolbar)
        
        scan_action = QAction('🎯 Vuln Scan', self)
        scan_action.setToolTip('Start Vulnerability Scan (Ctrl+N)')
        scan_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.scan_tab))
        toolbar.addAction(scan_action)
        
        toolbar.addSeparator()
        
        cve_scan_action = QAction('🔍 CVE Scan', self)
        cve_scan_action.setToolTip('Start CVE Scanner (Ctrl+Shift+C)')
        cve_scan_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.cve_scanner_tab))
        toolbar.addAction(cve_scan_action)
        
        toolbar.addSeparator()
        
        waf_bypass_action = QAction('🔥 WAF Bypass', self)
        waf_bypass_action.setToolTip('Start WAF Bypass Engine (Ctrl+Shift+W)')
        waf_bypass_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.waf_bypass_tab))
        toolbar.addAction(waf_bypass_action)
        
        toolbar.addSeparator()
        
        results_action = QAction('📊 Results', self)
        results_action.setToolTip('View Scan Results')
        results_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.results_tab))
        toolbar.addAction(results_action)
        
        toolbar.addSeparator()
        
        monitor_action = QAction('📡 Monitor', self)
        monitor_action.setToolTip('Request Monitor (Ctrl+3)')
        monitor_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.request_monitor_tab))
        toolbar.addAction(monitor_action)
        
        toolbar.addSeparator()
        
        subdomain_action = QAction('🌐 Subdomain', self)
        subdomain_action.setToolTip('Subdomain Enumeration (Ctrl+4)')
        subdomain_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.subdomain_tab))
        toolbar.addAction(subdomain_action)
        
        toolbar.addSeparator()
        
        wayback_action = QAction('⏰ Wayback', self)
        wayback_action.setToolTip('Wayback URLs (Ctrl+5)')
        wayback_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.wayback_tab))
        toolbar.addAction(wayback_action)
        
        toolbar.addSeparator()
        
        export_action = QAction('💾 Export', self)
        export_action.setToolTip('Export Results (Ctrl+E)')
        export_action.triggered.connect(self.export_results)
        toolbar.addAction(export_action)
        
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        toolbar.addWidget(spacer)
        
        settings_action = QAction('⚙️ Settings', self)
        settings_action.setToolTip('Application Settings')
        settings_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.settings_tab))
        toolbar.addAction(settings_action)
        
        toolbar.addSeparator()
        
        about_action = QAction('ℹ️ About', self)
        about_action.setToolTip('About MoD')
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
    
    def create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background: #161b22;
                color: #c9d1d9;
                border-top: 2px solid #30363d;
                padding: 6px;
            }
            QStatusBar::item {
                border: none;
            }
        """)
        
        status_widget = QWidget()
        status_layout = QHBoxLayout(status_widget)
        status_layout.setContentsMargins(8, 0, 8, 0)
        status_layout.setSpacing(15)
        
        self.status_label = QLabel('🟢 Ready | MoD v4.0 Enterprise')
        self.status_label.setStyleSheet('color: #2ea043; font-weight: bold; font-size: 10pt;')
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        self.scans_label = QLabel('📊 Scans: 0')
        self.scans_label.setStyleSheet('color: #58a6ff; font-weight: bold;')
        status_layout.addWidget(self.scans_label)
        
        self.vulns_label = QLabel('🔍 Vulnerabilities: 0')
        self.vulns_label.setStyleSheet('color: #f85149; font-weight: bold;')
        status_layout.addWidget(self.vulns_label)
        
        self.bypassed_label = QLabel('🔥 WAF Bypassed: 0')
        self.bypassed_label.setStyleSheet('color: #d29922; font-weight: bold;')
        status_layout.addWidget(self.bypassed_label)
        
        self.time_label = QLabel(f'🕐 {time.strftime("%H:%M:%S")}')
        self.time_label.setStyleSheet('color: #8b949e; font-weight: bold;')
        status_layout.addWidget(self.time_label)
        
        self.status_bar.addPermanentWidget(status_widget, 1)
    
    def setup_status_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)
    
    def update_time(self):
        self.time_label.setText(f'🕐 {time.strftime("%H:%M:%S")}')
    
    def apply_theme(self):
        stylesheet = self.theme_manager.get_stylesheet()
        self.setStyleSheet(stylesheet)
    
    def update_status(self, message: str, color: str = '#58a6ff'):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f'color: {color}; font-weight: bold; font-size: 10pt;')
    
    def on_scan_started(self, target: str):
        self.scan_stats['total_scans'] += 1
        self.update_status(f'⚡ Scanning: {target}', '#58a6ff')
        self.scans_label.setText(f'📊 Scans: {self.scan_stats["total_scans"]}')
        self.results_tab.clear_results()
    
    def on_scan_completed(self, results: list):
        self.scan_stats['vulnerabilities_found'] += len(results)
        self.update_status(f'✅ Scan completed - {len(results)} vulnerabilities found', '#2ea043')
        self.vulns_label.setText(f'🔍 Vulnerabilities: {self.scan_stats["vulnerabilities_found"]}')
        self.results_tab.display_results(results)
        self.tab_widget.setCurrentWidget(self.results_tab)
    
    def on_vulnerability_found(self, vulnerability: dict):
        self.results_tab.add_vulnerability(vulnerability)
    
    def on_subdomain_completed(self, results: list):
        self.update_status(f'✅ Found {len(results)} subdomains', '#2ea043')
    
    def on_wayback_completed(self, results: list):
        self.update_status(f'✅ Found {len(results)} archived URLs', '#2ea043')
    
    def on_theme_changed(self, theme: str):
        self.theme_manager.set_theme(theme)
        self.apply_theme()
        self.update_status(f'🎨 Theme changed to {theme.title()}', '#d29922')
    
    def on_settings_changed(self, settings: dict):
        api_key = settings.get('api_key', '')
        api_provider = settings.get('api_provider', 'openai')
        
        if api_key:
            self.cve_scanner_tab.set_api_config(api_key, api_provider)
            self.update_status(f'🔐 AI API configured: {api_provider}', '#2ea043')
    
    def on_auth_configured(self, auth_manager):
        self.scan_tab.set_auth_manager(auth_manager)
        self.update_status('🔐 Authentication configured', '#2ea043')
    
    def on_advanced_settings_changed(self, settings: dict):
        self.update_status('⚙️ Advanced settings updated', '#58a6ff')
    
    def toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()
    
    def export_results(self):
        self.results_tab.export_results()
        self.update_status('💾 Results exported successfully', '#2ea043')
    
    def show_documentation(self):
        QMessageBox.information(
            self,
            'MoD Documentation',
            '📚 MoD v4.0 Enterprise Documentation\n\n'
            '🎯 Vulnerability Scanner:\n'
            '  - 15+ vulnerability types detection\n'
            '  - Multi-threaded scanning\n'
            '  - Real-time results\n\n'
            '🔍 CVE Scanner:\n'
            '  - 400+ CVE signatures\n'
            '  - Smart verification system\n'
            '  - AI-powered POC generation\n\n'
            '🔥 WAF Bypass Engine:\n'
            '  - Intelligent payload mutation\n'
            '  - 50+ bypass techniques\n'
            '  - Adaptive learning\n\n'
            '📡 Request Monitor:\n'
            '  - Real-time traffic analysis\n'
            '  - Request/Response inspection\n\n'
            '🌐 Subdomain Enumeration:\n'
            '  - 10000+ wordlist\n'
            '  - DNS resolution\n'
            '  - Multi-threading\n\n'
            '⏰ Wayback URLs:\n'
            '  - Archive.org integration\n'
            '  - CommonCrawl support\n'
            '  - URL deduplication\n\n'
            'For more info: https://mod-security.com/docs'
        )
    
    def show_about(self):
        QMessageBox.about(
            self,
            'About MoD',
            '═══════════════════════════════════\n'
            '     MoD - Master of Defense\n'
            '═══════════════════════════════════\n\n'
            '🚀 Version 4.0.0 Enterprise Edition\n\n'
            '💎 The Ultimate Web Penetration Testing Suite\n'
            '   with World-Class Security Tools\n\n'
            '© 2025 MoD Security Team\n'
            '══════════════════════════════\n\n'
            '✨ Premium Features:\n\n'
            '🎯 Vulnerability Scanner\n'
            '   • 15+ Attack Vectors\n'
            '   • Smart Detection Engine\n'
            '   • Real-time Analysis\n\n'
            '🔍 CVE Scanner\n'
            '   • 400+ CVE Database\n'
            '   • AI-Powered POC Generation\n'
            '   • Advanced Fingerprinting\n\n'
            '🔥 WAF Bypass Engine\n'
            '   • Intelligent Payload Mutation\n'
            '   • 50+ Bypass Techniques\n'
            '   • Adaptive Learning System\n\n'
            '📡 Request Monitor\n'
            '   • Real-time Traffic Analysis\n'
            '   • Request/Response Inspector\n\n'
            '🌐 Subdomain Enumeration\n'
            '   • 10000+ Wordlist\n'
            '   • Multi-threaded Scanning\n\n'
            '⏰ Wayback Machine\n'
            '   • Archive.org Integration\n'
            '   • URL Extraction\n\n'
            '🔐 Advanced Authentication\n'
            '   • Session Management\n'
            '   • Multi-auth Support\n\n'
            '⚙️ Enterprise Grade\n'
            '   • Professional UI/UX\n'
            '   • Dark/Light Themes\n'
            '   • Export Capabilities\n'
            '   • Zero False Positives\n\n'
            '══════════════════════════════\n'
            '🏆 World-Class Security Tool\n'
            '   Built by Security Experts\n'
            '══════════════════════════════'
        )


class ThemeManager:
    
    def __init__(self):
        self.current_theme = 'dark'
    
    def set_theme(self, theme: str):
        self.current_theme = theme
    
    def get_stylesheet(self) -> str:
        if self.current_theme == 'dark':
            return """
                QMainWindow {
                    background: #0d1117;
                    color: #c9d1d9;
                }
                QWidget {
                    background: #0d1117;
                    color: #c9d1d9;
                    font-family: 'Segoe UI', Arial;
                }
                QPushButton {
                    background: #21262d;
                    color: #c9d1d9;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background: #30363d;
                    border: 1px solid #58a6ff;
                }
                QLineEdit, QTextEdit, QComboBox {
                    background: #161b22;
                    color: #c9d1d9;
                    border: 1px solid #30363d;
                    border-radius: 4px;
                    padding: 6px;
                }
                QTableWidget {
                    background: #0d1117;
                    alternate-background-color: #161b22;
                    gridline-color: #30363d;
                }
            """
        else:
            return """
                QMainWindow {
                    background: #ffffff;
                    color: #24292f;
                }
                QWidget {
                    background: #ffffff;
                    color: #24292f;
                }
            """
