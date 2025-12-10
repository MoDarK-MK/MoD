"""
Professional Main Window for MoD Security Scanner
Fullscreen, organized, and clean design
"""

from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QVBoxLayout, QWidget, QLabel, QHBoxLayout,
    QStatusBar, QFrame
)
from PyQt6.QtCore import Qt, QSize, QTimer, pyqtSignal
from PyQt6.QtGui import QFont

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
from .design_system import (
    DesignColors, DesignSpacing, DesignTypography, DesignHeader,
    DesignMainWidget
)
from gui.theme_manager import ThemeManager


class ProfessionalStatusBar(QFrame):
    """Professional status bar"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup status bar UI"""
        self.setFixedHeight(40)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {DesignColors.CARD_BG};
                border-top: 1px solid {DesignColors.BORDER};
            }}
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(DesignSpacing.MD, 0, DesignSpacing.MD, 0)
        layout.setSpacing(DesignSpacing.MD)
        
        # Status label
        self.status_label = QLabel('Ready')
        self.status_label.setFont(DesignTypography.caption())
        self.status_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        # Vulnerabilities count
        self.vuln_label = QLabel('Vulnerabilities: 0')
        self.vuln_label.setFont(DesignTypography.caption())
        self.vuln_label.setStyleSheet(f"color: {DesignColors.DANGER};")
        layout.addWidget(self.vuln_label)
        
        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.VLine)
        divider.setStyleSheet(f"background-color: {DesignColors.BORDER};")
        layout.addWidget(divider)
        
        # Scan status
        self.scan_label = QLabel('Scans: 0')
        self.scan_label.setFont(DesignTypography.caption())
        self.scan_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
        layout.addWidget(self.scan_label)


class MainWindow(QMainWindow):
    """Professional main application window"""
    
    def __init__(self):
        super().__init__()
        
        self.theme_manager = ThemeManager(default_theme='cyber_green')
        
        # Statistics
        self.scan_stats = {
            'total_scans': 0,
            'vulnerabilities_found': 0,
            'bypassed_wafs': 0
        }
        
        self.init_ui()
        self.setup_timer()
    
    def init_ui(self):
        """Initialize UI"""
        
        # Set window properties
        self.setWindowTitle('MoD - Master of Defense v4.0.0.4 | Professional Edition')
        self.showMaximized()  # Fullscreen
        
        # Create central widget
        central_widget = QWidget()
        central_layout = QVBoxLayout(central_widget)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)
        central_widget.setStyleSheet(f"background-color: {DesignColors.DARK_BG};")
        
        # Header
        header = DesignHeader(
            title="🔥 MoD Security Scanner - Professional Edition",
            subtitle="Advanced Vulnerability Assessment Platform"
        )
        central_layout.addWidget(header)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.TabPosition.North)
        self.tab_widget.setDocumentMode(False)
        self.tab_widget.setMovable(False)
        self.tab_widget.setTabsClosable(False)
        
        # Create tabs
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
        
        # Add tabs
        self.tab_widget.addTab(self.scan_tab, '🎯 Vulnerability Scan')
        self.tab_widget.addTab(self.results_tab, '📊 Scan Results')
        self.tab_widget.addTab(self.cve_scanner_tab, '🔍 CVE Scanner')
        self.tab_widget.addTab(self.waf_bypass_tab, '🔥 WAF Bypass')
        self.tab_widget.addTab(self.request_monitor_tab, '📡 Request Monitor')
        self.tab_widget.addTab(self.subdomain_tab, '🌐 Subdomain Scanner')
        self.tab_widget.addTab(self.wayback_tab, '🔙 Wayback Machine')
        self.tab_widget.addTab(self.auth_tab, '🔐 Authentication')
        self.tab_widget.addTab(self.cors_tab, '🔗 CORS Scanner')
        self.tab_widget.addTab(self.discord_tab, '💬 Discord Integration')
        self.tab_widget.addTab(self.settings_tab, '⚙️ Settings')
        self.tab_widget.addTab(self.advanced_settings_tab, '🔧 Advanced Settings')
        self.tab_widget.addTab(self.help_tab, '❓ Help & Documentation')
        
        # Style tab widget
        self.tab_widget.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {DesignColors.DARK_BG};
            }}
            QTabBar {{
                background-color: {DesignColors.DARK_BG};
                border-bottom: 1px solid {DesignColors.BORDER};
            }}
            QTabBar::tab {{
                background-color: {DesignColors.DARK_BG};
                color: {DesignColors.TEXT_SECONDARY};
                border: none;
                padding: {DesignSpacing.MD}px {DesignSpacing.LG}px;
                font-size: 10pt;
                font-weight: bold;
                min-width: 120px;
            }}
            QTabBar::tab:selected {{
                color: {DesignColors.ACCENT};
                border-bottom: 3px solid {DesignColors.ACCENT};
                background-color: {DesignColors.CARD_BG};
            }}
            QTabBar::tab:hover {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.ACCENT_HOVER};
            }}
        """)
        
        central_layout.addWidget(self.tab_widget)
        
        # Status bar
        self.status_bar = ProfessionalStatusBar()
        central_layout.addWidget(self.status_bar)
        
        self.setCentralWidget(central_widget)
    
    def setup_timer(self):
        """Setup timer for status updates"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)
    
    def update_status(self):
        """Update status bar"""
        if hasattr(self, 'status_bar'):
            self.status_bar.vuln_label.setText(
                f"Vulnerabilities: {self.scan_stats['vulnerabilities_found']}"
            )
            self.status_bar.scan_label.setText(
                f"Scans: {self.scan_stats['total_scans']}"
            )
    
    def closeEvent(self, event):
        """Handle close event"""
        self.timer.stop()
        event.accept()
