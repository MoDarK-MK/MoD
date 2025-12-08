"""Help and Documentation Tab - Professional Design."""

from PyQt6.QtWidgets import QVBoxLayout, QLabel, QTextEdit, QTabWidget
from PyQt6.QtGui import QFont
from .design_system import (
    DesignMainWidget, DesignColors, DesignSpacing
)


class HelpTab(DesignMainWidget):
    
    def __init__(self):
        super().__init__()
        self.header.set_title("Help & Documentation")
        self.header.set_subtitle("Learn how to use the security testing features")
        self.init_ui()
    
    def init_ui(self):
        # Create tabbed help sections
        self.help_tabs = QTabWidget()
        self.help_tabs.setStyleSheet(f"""
            QTabWidget {{
                background-color: {DesignColors.DARK_BG};
                border: none;
            }}
            QTabBar::tab {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-bottom: none;
                padding: 8px 16px;
                margin-right: 2px;
                border-radius: 4px 4px 0 0;
            }}
            QTabBar::tab:selected {{
                background-color: {DesignColors.ACCENT};
                color: {DesignColors.DARK_BG};
                font-weight: bold;
            }}
            QTabBar::tab:hover:!selected {{
                background-color: #1A2332;
            }}
        """)
        
        self.help_tabs.addTab(self.create_getting_started(), '🚀 Getting Started')
        self.help_tabs.addTab(self.create_vulnerability_scan(), '🎯 Vulnerability Scan')
        self.help_tabs.addTab(self.create_subdomain_enum(), '🌐 Subdomains')
        self.help_tabs.addTab(self.create_cve_scanner(), '🔍 CVE Scanner')
        self.help_tabs.addTab(self.create_cors_tester(), '🔐 CORS Tester')
        self.help_tabs.addTab(self.create_waf_bypass(), '🔥 WAF Bypass')
        self.help_tabs.addTab(self.create_advanced_features(), '🔧 Advanced')
        self.help_tabs.addTab(self.create_tips_tricks(), '💡 Tips & Tricks')
        
        self.scroll_content.layout().addWidget(self.help_tabs)
        self.add_stretch()
    
    def create_help_section(self, title: str, content: str):
        """Create a help section widget."""
        widget = QTextEdit()
        widget.setReadOnly(True)
        formatted_content = self.format_html_content(content)
        widget.setHtml(formatted_content)
        widget.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DesignColors.CARD_BG};
                color: {DesignColors.TEXT_PRIMARY};
                border: 1px solid {DesignColors.ACCENT};
                border-radius: 4px;
                padding: {DesignSpacing.MD}px;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 11pt;
            }}
            QTextEdit:focus {{
                border: 2px solid {DesignColors.ACCENT};
            }}
        """)
        return widget
    
    def format_html_content(self, content: str) -> str:
        """Format HTML content with proper colors for dark theme."""
        dark_theme_css = f"""
        <style>
            body {{ color: {DesignColors.TEXT_PRIMARY}; font-family: 'Segoe UI', Arial, sans-serif; }}
            h2 {{ color: {DesignColors.ACCENT} !important; margin-top: 20px; margin-bottom: 10px; font-size: 16pt; }}
            h3 {{ color: #58a6ff !important; margin-top: 15px; margin-bottom: 8px; font-size: 13pt; }}
            h4 {{ color: #79c0ff !important; margin-top: 12px; margin-bottom: 6px; }}
            p {{ color: {DesignColors.TEXT_PRIMARY}; line-height: 1.6; }}
            li {{ color: {DesignColors.TEXT_PRIMARY}; line-height: 1.6; }}
            pre {{ background: #0F1419 !important; color: #00ff00 !important; padding: 12px; border-radius: 4px; border: 1px solid {DesignColors.ACCENT}; overflow-x: auto; font-family: 'Courier New', monospace; }}
            code {{ background: #0F1419; color: #00ff00; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }}
            b {{ color: #58a6ff; font-weight: bold; }}
            a {{ color: {DesignColors.ACCENT}; text-decoration: none; }}
            a:hover {{ color: #58a6ff; text-decoration: underline; }}
            ol, ul {{ margin-left: 20px; }}
            hr {{ border: 1px solid {DesignColors.ACCENT}; margin: 20px 0; }}
        </style>
        """
        return dark_theme_css + content
    
    def create_getting_started(self):
        content = """
        <h2>🚀 Getting Started</h2>
        <p>Welcome to the Security Testing Tool! Here's how to get started:</p>
        
        <h3>Step 1: Configure Authentication</h3>
        <p>Navigate to the <b>Authentication</b> tab to set up your credentials:</p>
        <ul>
            <li>Basic Auth: Username and Password</li>
            <li>Bearer Token: API tokens</li>
            <li>JWT: JSON Web Tokens</li>
            <li>OAuth2: OAuth2 tokens</li>
        </ul>
        
        <h3>Step 2: Start a Scan</h3>
        <p>Go to the <b>Scan</b> tab and:</p>
        <ol>
            <li>Enter target URL</li>
            <li>Select scan type</li>
            <li>Configure options</li>
            <li>Click Start Scan</li>
        </ol>
        
        <h3>Step 3: Review Results</h3>
        <p>Check the <b>Results</b> tab to view scan findings and export reports.</p>
        """
        return self.create_help_section("Getting Started", content)
    
    def create_vulnerability_scan(self):
        content = """
        <h2>🎯 Vulnerability Scanning</h2>
        <p>The vulnerability scanner performs comprehensive security testing on web applications.</p>
        
        <h3>How it works</h3>
        <ul>
            <li><b>SQL Injection:</b> Tests for SQL injection vulnerabilities</li>
            <li><b>XSS:</b> Tests for Cross-Site Scripting vulnerabilities</li>
            <li><b>CSRF:</b> Tests for Cross-Site Request Forgery</li>
            <li><b>SSRF:</b> Tests for Server-Side Request Forgery</li>
            <li><b>RCE:</b> Tests for Remote Code Execution</li>
        </ul>
        
        <h3>Best Practices</h3>
        <ol>
            <li>Always get permission before testing</li>
            <li>Start with low-risk scans</li>
            <li>Review results carefully</li>
            <li>Document findings</li>
        </ol>
        """
        return self.create_help_section("Vulnerability Scan", content)
    
    def create_subdomain_enum(self):
        content = """
        <h2>🌐 Subdomain Enumeration</h2>
        <p>Find subdomains associated with a target domain.</p>
        
        <h3>Methods</h3>
        <ul>
            <li><b>Wordlist:</b> Brute-force with wordlists</li>
            <li><b>DNS:</b> DNS resolution and reverse lookup</li>
            <li><b>Wayback Machine:</b> Historical data from web.archive.org</li>
        </ul>
        """
        return self.create_help_section("Subdomain Enum", content)
    
    def create_cve_scanner(self):
        content = """
        <h2>🔍 CVE Scanner</h2>
        <p>Search for known vulnerabilities in your target.</p>
        
        <h3>Usage</h3>
        <ol>
            <li>Enter target or software name</li>
            <li>Select CVE database</li>
            <li>Run scan</li>
            <li>Review findings</li>
        </ol>
        """
        return self.create_help_section("CVE Scanner", content)
    
    def create_cors_tester(self):
        content = """
        <h2>🔐 CORS Tester</h2>
        <p>Test for CORS misconfigurations.</p>
        
        <h3>What is CORS?</h3>
        <p>Cross-Origin Resource Sharing (CORS) allows web servers to specify which origins can access resources.</p>
        
        <h3>Common Issues</h3>
        <ul>
            <li>Overly permissive <code>Access-Control-Allow-Origin: *</code></li>
            <li>Wildcard credentials</li>
            <li>Missing origin validation</li>
        </ul>
        """
        return self.create_help_section("CORS Tester", content)
    
    def create_waf_bypass(self):
        content = """
        <h2>🔥 WAF Bypass</h2>
        <p>Test for Web Application Firewall evasion techniques.</p>
        
        <h3>Techniques</h3>
        <ul>
            <li>Encoding/Obfuscation</li>
            <li>Case sensitivity</li>
            <li>Null bytes</li>
            <li>Alternative representations</li>
        </ul>
        """
        return self.create_help_section("WAF Bypass", content)
    
    def create_advanced_features(self):
        content = """
        <h2>🔧 Advanced Features</h2>
        
        <h3>Request Monitoring</h3>
        <p>Monitor all HTTP/HTTPS requests made by the scanner.</p>
        
        <h3>WebSocket Testing</h3>
        <p>Test WebSocket endpoints for security issues.</p>
        
        <h3>GraphQL Testing</h3>
        <p>Scan GraphQL endpoints for vulnerabilities.</p>
        
        <h3>API Security</h3>
        <p>Comprehensive API security testing.</p>
        """
        return self.create_help_section("Advanced", content)
    
    def create_tips_tricks(self):
        content = """
        <h2>💡 Tips & Tricks</h2>
        
        <h3>Performance</h3>
        <ul>
            <li>Use threading for faster scans</li>
            <li>Adjust timeout settings</li>
            <li>Use caching where possible</li>
        </ul>
        
        <h3>Accuracy</h3>
        <ul>
            <li>Configure proper headers</li>
            <li>Test in isolated environments first</li>
            <li>Verify findings manually</li>
        </ul>
        
        <h3>Reporting</h3>
        <ul>
            <li>Always export detailed reports</li>
            <li>Include timestamps</li>
            <li>Document methodology</li>
        </ul>
        """
        return self.create_help_section("Tips & Tricks", content)
