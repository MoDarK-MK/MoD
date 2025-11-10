from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, 
                             QWidget, QStatusBar, QMenuBar, QMenu, QToolBar, QMessageBox, QSizePolicy)
from PyQt6.QtCore import Qt, QSize, pyqtSignal
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

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.theme_manager = ThemeManager()
        self.init_ui()
        self.apply_theme()
        self.setWindowTitle('MoD - Master of Defense v3.0')
        self.setMinimumSize(QSize(1400, 900))
    
    def init_ui(self):
        self.request_monitor_tab = RequestMonitorTab()
        self.tab_widget.addTab(self.request_monitor_tab, '📡 Request Monitor')
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

        self.scan_tab.request_sent.connect(self.request_monitor_tab.add_request)
        self.scan_tab = ScanTab()
        self.results_tab = ResultsTab()
        self.subdomain_tab = SubdomainTab()
        self.wayback_tab = WaybackTab()
        self.auth_tab = AuthTab()
        self.settings_tab = SettingsTab()
        self.advanced_settings_tab = AdvancedSettingsTab()
        
        self.tab_widget.addTab(self.scan_tab, '🎯 Vulnerability Scan')
        self.tab_widget.addTab(self.results_tab, '📊 Results')
        self.tab_widget.addTab(self.subdomain_tab, '🌐 Subdomain Enum')
        self.tab_widget.addTab(self.wayback_tab, '⏰ Wayback URLs')
        self.tab_widget.addTab(self.auth_tab, '🔐 Authentication')
        self.tab_widget.addTab(self.settings_tab, '⚙️ Settings')
        self.tab_widget.addTab(self.advanced_settings_tab, '🔧 Advanced')
        
        layout.addWidget(self.tab_widget)
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('Ready | MoD v3.0')
        
        self.scan_tab.scan_started.connect(self.on_scan_started)
        self.scan_tab.scan_completed.connect(self.on_scan_completed)
        self.scan_tab.vulnerability_found.connect(self.on_vulnerability_found)
        
        self.subdomain_tab.scan_started.connect(lambda d: self.status_bar.showMessage(f'Enumerating: {d}'))
        self.subdomain_tab.scan_completed.connect(lambda r: self.status_bar.showMessage(f'Found {len(r)} subdomains'))
        
        self.wayback_tab.fetch_started.connect(lambda d: self.status_bar.showMessage(f'Fetching Wayback: {d}'))
        self.wayback_tab.fetch_completed.connect(lambda r: self.status_bar.showMessage(f'Found {len(r)} URLs'))
        
        self.settings_tab.theme_changed.connect(self.on_theme_changed)
        self.auth_tab.auth_configured.connect(self.on_auth_configured)
        self.advanced_settings_tab.settings_changed.connect(self.on_advanced_settings_changed)
    
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu('&File')
        
        new_scan_action = QAction('&New Scan', self)
        new_scan_action.setShortcut('Ctrl+N')
        new_scan_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.scan_tab))
        file_menu.addAction(new_scan_action)
        
        file_menu.addSeparator()
        
        export_action = QAction('&Export Results', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('E&xit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        view_menu = menubar.addMenu('&View')
        
        dark_theme_action = QAction('🌙 Dark Theme', self)
        dark_theme_action.triggered.connect(lambda: self.theme_manager.set_theme('dark'))
        view_menu.addAction(dark_theme_action)
        
        light_theme_action = QAction('☀️ Light Theme', self)
        light_theme_action.triggered.connect(lambda: self.theme_manager.set_theme('light'))
        view_menu.addAction(light_theme_action)
        
        tools_menu = menubar.addMenu('&Tools')
        
        subdomain_action = QAction('🌐 Subdomain Scanner', self)
        subdomain_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.subdomain_tab))
        tools_menu.addAction(subdomain_action)
        
        wayback_action = QAction('⏰ Wayback Machine', self)
        wayback_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.wayback_tab))
        tools_menu.addAction(wayback_action)
        
        help_menu = menubar.addMenu('&Help')
        
        about_action = QAction('About MoD', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        scan_action = QAction('🎯 Start Scan', self)
        scan_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.scan_tab))
        toolbar.addAction(scan_action)
        
        toolbar.addSeparator()
        
        results_action = QAction('📊 Results', self)
        results_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.results_tab))
        toolbar.addAction(results_action)
        
        toolbar.addSeparator()
        
        export_action = QAction('💾 Export', self)
        export_action.triggered.connect(self.export_results)
        toolbar.addAction(export_action)
        
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        toolbar.addWidget(spacer)
        
        about_action = QAction('ℹ️ About', self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)
    
    def apply_theme(self):
        stylesheet = self.theme_manager.get_stylesheet()
        self.setStyleSheet(stylesheet)
    
    def on_scan_started(self, target: str):
        self.status_bar.showMessage(f'⚡ Scanning: {target}')
        self.results_tab.clear_results()
    
    def on_scan_completed(self, results: list):
        self.status_bar.showMessage(f'✅ Scan completed - {len(results)} vulnerabilities found')
        self.results_tab.display_results(results)
        self.tab_widget.setCurrentWidget(self.results_tab)
    
    def on_vulnerability_found(self, vulnerability: dict):
        self.results_tab.add_vulnerability(vulnerability)
    
    def on_theme_changed(self, theme: str):
        self.theme_manager.set_theme(theme)
        self.apply_theme()
    
    def on_auth_configured(self, auth_manager):
        self.scan_tab.set_auth_manager(auth_manager)
        self.status_bar.showMessage('🔐 Authentication configured')
    
    def on_advanced_settings_changed(self, settings: dict):
        self.status_bar.showMessage('⚙️ Advanced settings updated')
    
    def export_results(self):
        self.results_tab.export_results()
    
    def show_about(self):
        QMessageBox.about(
            self,
            'About MoD',
            'MoD - Master of Defense\n\n'
            'Version 3.0.0\n\n'
            'Advanced Web Penetration Testing Tool\n'
            'with modern UI/UX design\n\n'
            '© 2025 MoD Security Team\n\n'
            'Features:\n'
            '• 15 Vulnerability Scanners\n'
            '• Multi-threaded Scanning\n'
            '• Advanced Authentication\n'
            '• Real-time Reporting\n'
            '• Integration Support'
        )
