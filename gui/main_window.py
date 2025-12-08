 
from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, 
                             QWidget, QStatusBar, QMenuBar, QMenu, QToolBar, 
                             QMessageBox, QSizePolicy, QLabel, QHBoxLayout,
                             QDialog, QGridLayout, QFrame, QScrollArea, QPushButton,
                             QCheckBox)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QIcon, QFont

from .scan_tab import ScanTab
from .results_tab import ResultsTab
from .settings_tab import SettingsTab
from .auth_tab import AuthTab
from .subdomain_tab import SubdomainTab
from .wayback_tab import WaybackTab
from .advanced_settings_tab import AdvancedSettingsTab
from .request_monitor_tab import RequestMonitorTab
from .cve_scanner_tab import CVEScannerTab
from .waf_bypass_tab import WAFBypassTab
from .cors_tab import CORSTab
from .discord_tab import DiscordTab
from .help_tab import HelpTab
from gui.theme_manager import ThemeManager
import time


class ScannerCard(QFrame):
    def __init__(self, scanner_id, title, icon, description, parent=None):
        super().__init__(parent)
        self.scanner_id = scanner_id
        self.is_selected = True
        self.setup_ui(title, icon, description)
    
    def setup_ui(self, title, icon, description):
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(100)
        self.setMaximumHeight(100)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)
        
        header_layout = QHBoxLayout()
        header_layout.setSpacing(10)
        
        icon_label = QLabel(icon)
        icon_label.setStyleSheet('font-size: 22px;')
        header_layout.addWidget(icon_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet('font-size: 12pt; font-weight: 700;')
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        self.status_label = QLabel('✓')
        self.status_label.setStyleSheet('font-size: 16px; color: #00FF41; font-weight: bold;')
        header_layout.addWidget(self.status_label)
        
        layout.addLayout(header_layout)
        
        desc_label = QLabel(description)
        desc_label.setStyleSheet('font-size: 9pt; opacity: 0.7;')
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        self.update_style()
    
    def mousePressEvent(self, event):
        self.toggle_selection()
        super().mousePressEvent(event)
    
    def toggle_selection(self):
        self.is_selected = not self.is_selected
        self.status_label.setText('✓' if self.is_selected else '✗')
        self.status_label.setStyleSheet(
            f'font-size: 16px; color: {"#00FF41" if self.is_selected else "#FF0040"}; font-weight: bold;'
        )
        self.update_style()
    
    def update_style(self):
        if self.is_selected:
            self.setStyleSheet('''
                ScannerCard {
                    background: rgba(0, 255, 65, 0.1);
                    border: 2px solid rgba(0, 255, 65, 0.35);
                    border-radius: 10px;
                }
                ScannerCard:hover {
                    background: rgba(0, 255, 65, 0.15);
                    border: 2px solid rgba(0, 255, 65, 0.5);
                    transform: translateY(-2px);
                }
            ''')
        else:
            self.setStyleSheet('''
                ScannerCard {
                    background: rgba(255, 0, 64, 0.06);
                    border: 2px solid rgba(255, 0, 64, 0.25);
                    border-radius: 10px;
                }
                ScannerCard:hover {
                    background: rgba(255, 0, 64, 0.1);
                    border: 2px solid rgba(255, 0, 64, 0.35);
                }
            ''')


class ScannerSelectionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner_cards = {}
        self.selected_scanners = set()
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle('🔍 Scanner Selection Manager')
        self.setMinimumSize(900, 700)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(12)
        
        title_label = QLabel('🔍 ADVANCED SCANNER SELECTION')
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)
        
        desc_label = QLabel('Select which vulnerability scanners to include in your security assessment')
        desc_label.setStyleSheet('font-size: 10pt; opacity: 0.8;')
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(desc_label)
        
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setSpacing(10)
        
        select_all_btn = QPushButton('✓ Select All')
        select_all_btn.setMinimumHeight(38)
        select_all_btn.setMinimumWidth(120)
        select_all_btn.clicked.connect(self.select_all)
        toolbar_layout.addWidget(select_all_btn)
        
        deselect_all_btn = QPushButton('✗ Deselect All')
        deselect_all_btn.setMinimumHeight(38)
        deselect_all_btn.setMinimumWidth(120)
        deselect_all_btn.clicked.connect(self.deselect_all)
        toolbar_layout.addWidget(deselect_all_btn)
        
        toolbar_layout.addStretch()
        
        self.count_label = QLabel('Selected: 0/15')
        self.count_label.setStyleSheet('font-size: 12pt; font-weight: 700; color: #00FF41;')
        toolbar_layout.addWidget(self.count_label)
        
        main_layout.addLayout(toolbar_layout)
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setMinimumHeight(450)
        
        scroll_widget = QWidget()
        scanner_layout = QGridLayout(scroll_widget)
        scanner_layout.setSpacing(12)
        
        scanners = [
            ('sql', 'SQL Injection', '💉', 'Database query manipulation attacks'),
            ('xss', 'Cross-Site Scripting', '🔥', 'JavaScript injection vulnerabilities'),
            ('xxe', 'XML External Entity', '📄', 'XML parser exploitation'),
            ('ssrf', 'Server-Side Request Forgery', '🌐', 'Internal network access'),
            ('lfi', 'Local File Inclusion', '📁', 'Server file disclosure'),
            ('rfi', 'Remote File Inclusion', '🔗', 'External file execution'),
            ('cmd', 'Command Injection', '⚡', 'OS command execution'),
            ('open_redirect', 'Open Redirect', '🔄', 'Unvalidated redirects'),
            ('cors', 'CORS Misconfiguration', '🔐', 'Cross-origin policy issues'),
            ('clickjacking', 'Clickjacking', '🖱️', 'UI redress attacks'),
            ('csrf', 'CSRF', '🎭', 'Cross-site request forgery'),
            ('security_headers', 'Security Headers', '🛡️', 'HTTP header analysis'),
            ('ssti', 'Template Injection', '🎨', 'Server-side template flaws'),
            ('jwt', 'JWT Vulnerabilities', '🔑', 'Token security analysis'),
            ('path_traversal', 'Path Traversal', '📂', 'Directory traversal'),
        ]
        
        row = 0
        col = 0
        for scanner_id, title, icon, description in scanners:
            card = ScannerCard(scanner_id, title, icon, description)
            self.scanner_cards[scanner_id] = card
            self.selected_scanners.add(scanner_id)
            
            scanner_layout.addWidget(card, row, col)
            
            col += 1
            if col > 2:
                col = 0
                row += 1
        
        scroll_area.setWidget(scroll_widget)
        main_layout.addWidget(scroll_area)
        
        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        
        apply_btn = QPushButton('✅ Apply Selection')
        apply_btn.setMinimumHeight(36)
        apply_btn.setMinimumWidth(180)
        apply_btn.clicked.connect(self.accept)
        button_layout.addWidget(apply_btn)
        
        cancel_btn = QPushButton('❌ Cancel')
        cancel_btn.setMinimumHeight(36)
        cancel_btn.setMinimumWidth(180)
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        button_layout.addStretch()
        
        main_layout.addLayout(button_layout)
        
        self.update_count()
    
    def select_all(self):
        for card in self.scanner_cards.values():
            if not card.is_selected:
                card.toggle_selection()
        self.update_count()
    
    def deselect_all(self):
        for card in self.scanner_cards.values():
            if card.is_selected:
                card.toggle_selection()
        self.update_count()
    
    def update_count(self):
        selected = sum(1 for card in self.scanner_cards.values() if card.is_selected)
        total = len(self.scanner_cards)
        self.count_label.setText(f'Selected: {selected}/{total}')
    
    def get_selected_scanners(self):
        return [sid for sid, card in self.scanner_cards.items() if card.is_selected]


class MainWindow(QMainWindow):
    
    def __init__(self):
        super().__init__()
        
        self.theme_manager = ThemeManager(default_theme='cyber_green')
        
        self.scan_stats = {
            'total_scans': 0,
            'vulnerabilities_found': 0,
            'bypassed_wafs': 0
        }
        
        self.init_ui()
        self.apply_theme()
        
        self.setWindowTitle('🔥 MoD - Master of Defense v4.0 Enterprise | The Ultimate Pentesting Suite')
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
        
        self.scan_tab = ScanTab()
        self.results_tab = ResultsTab()
        self.cve_scanner_tab = CVEScannerTab()
        self.waf_bypass_tab = WAFBypassTab()
        self.subdomain_tab = SubdomainTab()
        self.wayback_tab = WaybackTab()
        self.auth_tab = AuthTab()
        self.request_monitor_tab = RequestMonitorTab()
        self.settings_tab = SettingsTab(self.theme_manager)
        self.advanced_settings_tab = AdvancedSettingsTab()
        self.cors_tab = CORSTab()
        self.discord_tab = DiscordTab()
        self.help_tab = HelpTab()
        
        self.tab_widget.addTab(self.scan_tab, '🎯 Vulnerability Scan')
        self.tab_widget.addTab(self.results_tab, '📊 Scan Results')
        self.tab_widget.addTab(self.cve_scanner_tab, '🔍 CVE Scanner')
        self.tab_widget.addTab(self.waf_bypass_tab, '🔥 WAF Bypass')
        self.tab_widget.addTab(self.request_monitor_tab, '📡 Request Monitor')
        self.tab_widget.addTab(self.subdomain_tab, '🌐 Subdomain Enum')
        self.tab_widget.addTab(self.wayback_tab, '⏰ Wayback URLs')
        self.tab_widget.addTab(self.auth_tab, '🔐 Authentication')
        self.tab_widget.addTab(self.cors_tab, '🌐 CORS Tester')
        self.tab_widget.addTab(self.discord_tab, '💬 Discord')
        self.tab_widget.addTab(self.help_tab, '📚 Help & Documentation')
        self.tab_widget.addTab(self.settings_tab, '⚙️ Settings')
        self.tab_widget.addTab(self.advanced_settings_tab, '🔧 Advanced')
        
        layout.addWidget(self.tab_widget)
        
        self.create_status_bar()
        
        self.scan_tab.scan_started.connect(self.on_scan_started)
        self.scan_tab.scan_completed.connect(self.on_scan_completed)
        self.scan_tab.vulnerability_found.connect(self.on_vulnerability_found)
        self.scan_tab.request_sent.connect(self.request_monitor_tab.add_request)
        
        self.subdomain_tab.scan_started.connect(lambda d: self.update_status(f'🌐 Enumerating: {d}'))
        self.subdomain_tab.scan_completed.connect(self.on_subdomain_completed)
        
        self.wayback_tab.fetch_started.connect(lambda d: self.update_status(f'⏰ Fetching Wayback: {d}'))
        self.wayback_tab.fetch_completed.connect(self.on_wayback_completed)
        
        self.settings_tab.theme_changed.connect(self.on_theme_changed)
        self.settings_tab.ui_size_changed.connect(self.on_ui_size_changed)
        self.settings_tab.settings_changed.connect(self.on_settings_changed)
        
        self.discord_tab.settings_changed.connect(self.on_discord_settings_changed)
        
        self.auth_tab.auth_configured.connect(self.on_auth_configured)
        self.advanced_settings_tab.settings_changed.connect(self.on_advanced_settings_changed)
    
    def create_menu_bar(self):
        menubar = self.menuBar()
        
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
        
        scanner_selection_action = QAction('🔍 Scanner &Selection', self)
        scanner_selection_action.setShortcut('Ctrl+Shift+S')
        scanner_selection_action.triggered.connect(self.show_scanner_selection)
        file_menu.addAction(scanner_selection_action)
        
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
        
        theme_display_names = self.theme_manager.get_theme_display_names()
        for theme_key, theme_name in theme_display_names.items():
            theme_action = QAction(f'{theme_name}', self)
            theme_action.triggered.connect(lambda checked, t=theme_key: self.on_theme_changed(t))
            view_menu.addAction(theme_action)
        
        view_menu.addSeparator()
        
        fullscreen_action = QAction('🖥️ Toggle Fullscreen', self)
        fullscreen_action.setShortcut('F11')
        fullscreen_action.triggered.connect(self.toggle_fullscreen)
        view_menu.addAction(fullscreen_action)
        
        tools_menu = menubar.addMenu('&Tools')
        
        scanner_manager_action = QAction('🔍 Scanner Manager', self)
        scanner_manager_action.setShortcut('Ctrl+M')
        scanner_manager_action.triggered.connect(self.show_scanner_selection)
        tools_menu.addAction(scanner_manager_action)
        
        tools_menu.addSeparator()
        
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
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        scan_action = QAction('🎯 Vuln Scan', self)
        scan_action.setToolTip('Start Vulnerability Scan (Ctrl+N)')
        scan_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.scan_tab))
        toolbar.addAction(scan_action)
        
        toolbar.addSeparator()
        
        scanner_select_action = QAction('🔍 Scanners', self)
        scanner_select_action.setToolTip('Scanner Selection (Ctrl+Shift+S)')
        scanner_select_action.triggered.connect(self.show_scanner_selection)
        toolbar.addAction(scanner_select_action)
        
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
        
        status_widget = QWidget()
        status_layout = QHBoxLayout(status_widget)
        status_layout.setContentsMargins(8, 0, 8, 0)
        status_layout.setSpacing(15)
        
        self.status_label = QLabel('🟢 Ready | MoD v4.0 Enterprise')
        self.status_label.setStyleSheet('font-weight: bold; font-size: 10pt;')
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        self.scans_label = QLabel('📊 Scans: 0')
        self.scans_label.setStyleSheet('font-weight: bold;')
        status_layout.addWidget(self.scans_label)
        
        self.vulns_label = QLabel('🔍 Vulnerabilities: 0')
        self.vulns_label.setStyleSheet('font-weight: bold;')
        status_layout.addWidget(self.vulns_label)
        
        self.bypassed_label = QLabel('🔥 WAF Bypassed: 0')
        self.bypassed_label.setStyleSheet('font-weight: bold;')
        status_layout.addWidget(self.bypassed_label)
        
        self.time_label = QLabel(f'🕐 {time.strftime("%H:%M:%S")}')
        self.time_label.setStyleSheet('font-weight: bold;')
        status_layout.addWidget(self.time_label)
        
        self.status_bar.addPermanentWidget(status_widget, 1)
    
    def setup_status_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)
    
    def update_time(self):
        self.time_label.setText(f'🕐 {time.strftime("%H:%M:%S")}')
    
    def apply_theme(self):
        try:
            stylesheet = self.theme_manager.get_stylesheet()
            self.setStyleSheet(stylesheet)
        except Exception as e:
            print(f"Error applying theme: {e}")
    
    def apply_ui_size(self, size: str):
        """Apply UI size scaling based on selection (Small/Medium/Large)"""
        try:
            # Define size multipliers
            size_multipliers = {
                'Small': 0.85,
                'Medium': 1.0,
                'Large': 1.15
            }
            
            multiplier = size_multipliers.get(size, 1.0)
            
            # Base font sizes
            base_sizes = {
                'Small': {'title': 12, 'label': 10, 'normal': 9},
                'Medium': {'title': 14, 'label': 11, 'normal': 10},
                'Large': {'title': 16, 'label': 13, 'normal': 11}
            }
            
            sizes = base_sizes.get(size, base_sizes['Medium'])
            
            # Generate stylesheet with size adjustments
            stylesheet = f"""
                QWidget {{ font-size: {sizes['normal']}pt; }}
                QLabel {{ font-size: {sizes['label']}pt; }}
                QPushButton {{ padding: {int(8 * multiplier)}px; font-size: {sizes['label']}pt; }}
                QLineEdit {{ padding: {int(6 * multiplier)}px; font-size: {sizes['normal']}pt; }}
                QComboBox {{ padding: {int(6 * multiplier)}px; font-size: {sizes['normal']}pt; }}
                QSpinBox {{ padding: {int(4 * multiplier)}px; font-size: {sizes['normal']}pt; }}
                QCheckBox {{ font-size: {sizes['normal']}pt; }}
                QGroupBox {{ font-size: {sizes['label']}pt; padding-top: {int(10 * multiplier)}px; }}
                QGroupBox::title {{ padding: {int(4 * multiplier)}px; }}
                QTabWidget::pane {{ border: none; padding: {int(4 * multiplier)}px; }}
                QTabBar::tab {{ padding: {int(6 * multiplier)}px {int(12 * multiplier)}px; font-size: {sizes['normal']}pt; }}
            """
            
            current_stylesheet = self.styleSheet()
            self.setStyleSheet(current_stylesheet + stylesheet)
            
            self.update_status(f'✅ UI resized to {size}')
        except Exception as e:
            print(f"Error applying UI size: {e}")
    
    def update_status(self, message: str, color: str = None):
        self.status_label.setText(message)
        if color:
            self.status_label.setStyleSheet(f'color: {color}; font-weight: bold; font-size: 10pt;')
    
    def show_scanner_selection(self):
        dialog = ScannerSelectionDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = dialog.get_selected_scanners()
            self.update_status(f'🔍 Scanner selection updated: {len(selected)} scanners active')
    
    def on_scan_started(self, target: str):
        self.scan_stats['total_scans'] += 1
        self.update_status(f'⚡ Scanning: {target}')
        self.scans_label.setText(f'📊 Scans: {self.scan_stats["total_scans"]}')
        self.results_tab.clear_results()
    
    def on_scan_completed(self, results: list):
        self.scan_stats['vulnerabilities_found'] += len(results)
        self.update_status(f'✅ Scan completed - {len(results)} vulnerabilities found')
        self.vulns_label.setText(f'🔍 Vulnerabilities: {self.scan_stats["vulnerabilities_found"]}')
        self.results_tab.display_results(results)
        self.tab_widget.setCurrentWidget(self.results_tab)
    
    def on_vulnerability_found(self, vulnerability: dict):
        self.results_tab.add_vulnerability(vulnerability)
    
    def on_subdomain_completed(self, results: list):
        self.update_status(f'✅ Found {len(results)} subdomains')
    
    def on_wayback_completed(self, results: list):
        self.update_status(f'✅ Found {len(results)} archived URLs')
    
    def on_theme_changed(self, theme_key: str):
        self.theme_manager.set_theme(theme_key)
        self.apply_theme()
        theme_name = self.theme_manager.THEMES[theme_key]['name']
        self.update_status(f'🎨 Theme changed to {theme_name}')
    
    def on_ui_size_changed(self, size: str):
        """Handle UI size change (Small/Medium/Large)"""
        self.apply_ui_size(size)
        self.update_status(f'🔧 UI Size changed to {size}')
    
    def on_settings_changed(self, settings: dict):
        api_key = settings.get('api_key', '')
        api_provider = settings.get('ai_provider', 'None')
        
        if api_key and api_provider != 'None':
            if hasattr(self.cve_scanner_tab, 'set_api_config'):
                self.cve_scanner_tab.set_api_config(api_key, api_provider)
            self.update_status(f'🔐 AI API configured: {api_provider}')
        
        # Save update check preferences
        auto_update = settings.get('auto_update', True)
        update_frequency = settings.get('update_frequency', 7)
        
        try:
            from utils.update_checker import UpdateChecker
            checker = UpdateChecker()
            checker.save_check_settings(auto_update, update_frequency)
            if auto_update:
                self.update_status(f'🔄 Update checks enabled (every {update_frequency} days)')
            else:
                self.update_status('🔄 Update checks disabled')
        except Exception as e:
            print(f"Error saving update settings: {e}")
        
        # Configure Discord logging
        discord_webhook = settings.get('discord_webhook', '')
        discord_log_level = settings.get('discord_log_level', 'INFO')
        
        try:
            from utils.logger import Logger
            logger = Logger('MoD')
            
            if discord_webhook:
                # Enable Discord logging
                if logger.enable_discord_logging(discord_webhook, discord_log_level):
                    self.update_status(f'🎮 Discord logging enabled ({discord_log_level})')
                else:
                    self.update_status('⚠️ Failed to enable Discord logging')
            else:
                # Disable Discord logging if webhook is empty
                logger.disable_discord_logging()
                self.update_status('🎮 Discord logging disabled')
        except Exception as e:
            print(f"Error configuring Discord logging: {e}")
    
    def on_discord_settings_changed(self, settings: dict):
        """Handle Discord tab settings changes"""
        discord_webhook = settings.get('discord_webhook', '')
        discord_log_level = settings.get('discord_log_level', 'INFO')
        logging_enabled = settings.get('discord_logging_enabled', False)
        
        try:
            from utils.logger import Logger
            logger = Logger('MoD')
            
            if discord_webhook and logging_enabled:
                # Enable Discord logging
                if logger.enable_discord_logging(discord_webhook, discord_log_level):
                    self.update_status(f'💬 Discord logging enabled ({discord_log_level})')
                else:
                    self.update_status('⚠️ Failed to enable Discord logging')
            else:
                # Disable Discord logging if webhook is empty or disabled
                logger.disable_discord_logging()
                self.update_status('💬 Discord logging disabled')
        except Exception as e:
            print(f"Error configuring Discord settings: {e}")
    
    def on_auth_configured(self, auth_manager):
        if hasattr(self.scan_tab, 'set_auth_manager'):
            self.scan_tab.set_auth_manager(auth_manager)
        self.update_status('🔐 Authentication configured')
    
    def on_advanced_settings_changed(self, settings: dict):
        self.update_status('⚙️ Advanced settings updated')
    
    def toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()
    
    def export_results(self):
        if hasattr(self.results_tab, 'export_results'):
            self.results_tab.export_results()
            self.update_status('💾 Results exported successfully')
        else:
            QMessageBox.information(self, 'Export', 'No results to export')
    
    def show_documentation(self):
        QMessageBox.information(
            self,
            '📚 MoD Documentation',
            '═══════════════════════════════════\n'
            '   MoD v4.0 Enterprise Documentation\n'
            '═══════════════════════════════════\n\n'
            '🎯 VULNERABILITY SCANNER\n'
            '  • 15+ vulnerability types detection\n'
            '  • Multi-threaded scanning engine\n'
            '  • Real-time vulnerability discovery\n'
            '  • Smart payload generation\n\n'
            '🔍 CVE SCANNER\n'
            '  • 400+ CVE signatures database\n'
            '  • Smart verification system\n'
            '  • AI-powered POC generation\n'
            '  • Zero false positives\n\n'
            '🔥 WAF BYPASS ENGINE\n'
            '  • Intelligent payload mutation\n'
            '  • 50+ bypass techniques\n'
            '  • Adaptive learning system\n\n'
            '📡 REQUEST MONITOR\n'
            '  • Real-time traffic analysis\n'
            '  • Request/Response inspection\n\n'
            '🌐 SUBDOMAIN ENUMERATION\n'
            '  • 10000+ wordlist database\n'
            '  • Multi-threaded discovery\n\n'
            '⏰ WAYBACK MACHINE\n'
            '  • Archive.org integration\n'
            '  • Smart URL deduplication\n\n'
            '══════════════════════════════\n'
            'https://mod-security.com/docs\n'
            '══════════════════════════════'
        )
    
    def show_about(self):
        QMessageBox.about(
            self,
            'About MoD',
            '═══════════════════════════════════\n'
            '     🔥 MoD - Master of Defense 🔥\n'
            '═══════════════════════════════════\n\n'
            '🚀 Version 4.0.0 Enterprise Edition\n\n'
            '💎 The Ultimate Web Penetration Testing Suite\n\n'
            '© 2025 MoD Security Team\n'
            '══════════════════════════════\n\n'
            '✨ PREMIUM FEATURES:\n\n'
            '🎯 Vulnerability Scanner\n'
            '   • 15+ Attack Vectors\n'
            '   • Smart Detection Engine\n\n'
            '🔍 CVE Scanner\n'
            '   • 400+ CVE Database\n'
            '   • AI-Powered POC Generation\n\n'
            '🔥 WAF Bypass Engine\n'
            '   • 50+ Bypass Techniques\n'
            '   • Adaptive Learning\n\n'
            '📡 Request Monitor\n'
            '   • Real-time Analysis\n\n'
            '🌐 Subdomain Enumeration\n'
            '   • 10000+ Wordlist\n\n'
            '⚙️ Enterprise Grade\n'
            '   • 4 Professional Themes\n'
            '   • Cyber Green (Matrix)\n'
            '   • Export Capabilities\n\n'
            '══════════════════════════════\n'
            '🏆 World-Class Security Tool\n'
            '══════════════════════════════\n\n'
            '🌐 https://mod-security.com\n'
            '📧 support@mod-security.com\n\n'
            'Enterprise License © 2025'
        )
