from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QTabWidget
from PyQt6.QtGui import QFont


class HelpTab(QWidget):
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(15, 15, 15, 8)
        
        title = QLabel('📚 Help & Documentation')
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        main_layout.addLayout(header_layout)
        
        self.help_tabs = QTabWidget()
        
        self.help_tabs.addTab(self.create_getting_started(), '🚀 Getting Started')
        self.help_tabs.addTab(self.create_vulnerability_scan(), '🎯 Vulnerability Scan')
        self.help_tabs.addTab(self.create_subdomain_enum(), '🌐 Subdomain Enumeration')
        self.help_tabs.addTab(self.create_cve_scanner(), '🔍 CVE Scanner')
        self.help_tabs.addTab(self.create_cors_tester(), '🔐 CORS Tester')
        self.help_tabs.addTab(self.create_waf_bypass(), '🔥 WAF Bypass')
        self.help_tabs.addTab(self.create_auth_testing(), '🔐 Authentication')
        self.help_tabs.addTab(self.create_advanced_features(), '🔧 Advanced Features')
        self.help_tabs.addTab(self.create_tips_tricks(), '💡 Tips & Tricks')
        
        main_layout.addWidget(self.help_tabs)
        self.setLayout(main_layout)
    
    def create_help_section(self, title, content):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(8)
        
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        formatted_content = self.format_html_content(content)
        text_edit.setHtml(formatted_content)
        text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #404040;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 11pt;
            }
            QTextEdit:focus {
                border: 1px solid #667eea;
            }
        """)
        
        layout.addWidget(text_edit)
        widget.setLayout(layout)
        return widget
    
    def format_html_content(self, content: str) -> str:
        """Format HTML content with proper colors for dark theme"""
        # Add CSS styles for dark theme
        dark_theme_css = """
        <style>
            body { color: #e0e0e0; }
            h2 { color: #667eea !important; margin-top: 20px; margin-bottom: 10px; }
            h3 { color: #58a6ff !important; margin-top: 15px; margin-bottom: 8px; }
            h4 { color: #79c0ff !important; margin-top: 12px; margin-bottom: 6px; }
            p { color: #e0e0e0; line-height: 1.5; }
            li { color: #e0e0e0; line-height: 1.5; }
            pre { background: #2d2d2d !important; color: #00ff00 !important; padding: 10px; border-radius: 5px; border: 1px solid #404040; overflow-x: auto; }
            code { background: #2d2d2d; color: #00ff00; padding: 2px 6px; border-radius: 3px; }
            b { color: #58a6ff; font-weight: bold; }
            a { color: #667eea; text-decoration: none; }
            a:hover { color: #79c0ff; text-decoration: underline; }
            ol, ul { margin-left: 20px; }
            hr { border: 1px solid #404040; }
        </style>
        """
        return dark_theme_css + content
    
    def create_getting_started(self):
        content = """
        <h2 style="color: #667eea;">🚀 Getting Started</h2>
        
        <h3>Step 1: Initial Setup</h3>
        <ol>
            <li>Launch the application</li>
            <li>Go to <b>Settings</b> tab and configure basic options</li>
            <li>Modify User-Agent if needed</li>
            <li>Enable Proxy if required</li>
        </ol>
        
        <h3>Step 2: First Vulnerability Scan</h3>
        <p><b>Example Configuration:</b></p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        URL: https://example.com
        Scan Types: XSS, SQL, RCE
        Max Workers: 10
        Timeout: 30 seconds
        </pre>
        
        <h3>Step 3: View Results</h3>
        <p>Results will appear in the <b>Scan Results</b> tab where you can:</p>
        <ul>
            <li>Filter vulnerabilities by severity</li>
            <li>View detailed descriptions</li>
            <li>Export findings to JSON/CSV</li>
        </ul>
        
        <h3>Important Security Notes:</h3>
        <ul>
            <li>❌ Never scan websites without explicit permission</li>
            <li>⏱️ Increase timeout for large websites</li>
            <li>🔒 Always use HTTPS for sensitive tests</li>
            <li>📊 Backup results before deletion</li>
        </ul>
        """
        return self.create_help_section('Getting Started', content)
    
    def create_vulnerability_scan(self):
        content = """
        <h2 style="color: #667eea;">🎯 Vulnerability Scanner</h2>
        
        <h3>Scan Types Available:</h3>
        
        <h4>1️⃣ XSS (Cross-Site Scripting)</h4>
        <p>Detects JavaScript injection vulnerabilities</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Example Payload: &lt;script&gt;alert('XSS')&lt;/script&gt;
        Detection: Script tags in response
        </pre>
        
        <h4>2️⃣ SQL Injection</h4>
        <p>Identifies SQL query injection flaws</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Example Payload: ' OR '1'='1
        Detection: SQL error messages
        </pre>
        
        <h4>3️⃣ RCE (Remote Code Execution)</h4>
        <p>Detects ability to execute commands remotely</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Example Payload: id; whoami
        Detection: Shell command output
        </pre>
        
        <h4>4️⃣ Command Injection</h4>
        <p>Finds OS command injection vulnerabilities</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Example Payload: ; ls -la
        Detection: Directory listing in response
        </pre>
        
        <h4>5️⃣ XXE (XML External Entity)</h4>
        <p>Detects XML parser exploitation</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Payload: &lt;?xml version="1.0"?&gt;
        &lt;!DOCTYPE root [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;
        </pre>
        
        <h3>How to Use:</h3>
        <ol>
            <li>Enter target URL</li>
            <li>Select vulnerability types</li>
            <li>Set number of workers (default: 10)</li>
            <li>Click Start Scan button</li>
            <li>Wait for results</li>
        </ol>
        
        <h3>Settings Explained:</h3>
        <ul>
            <li><b>Max Workers:</b> Number of concurrent threads</li>
            <li><b>Timeout:</b> Wait time per request in seconds</li>
            <li><b>Retry Attempts:</b> Retries on failure</li>
            <li><b>Request Delay:</b> Delay between requests</li>
        </ul>
        """
        return self.create_help_section('Vulnerability Scan', content)
    
    def create_subdomain_enum(self):
        content = """
        <h2 style="color: #667eea;">🌐 Subdomain Enumeration</h2>
        
        <h3>What It Does:</h3>
        <p>Discovers all subdomains associated with a domain</p>
        
        <h3>Enumeration Methods:</h3>
        
        <h4>1️⃣ Dictionary Attack</h4>
        <p>Tests common subdomain names</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Common subdomains:
        www, mail, ftp, admin, api, staging, dev
        cdn, vpn, remote, support, blog
        </pre>
        
        <h4>2️⃣ DNS Brute Force</h4>
        <p>Performs DNS resolution to find active subdomains</p>
        
        <h4>3️⃣ Wayback Machine Integration</h4>
        <p>Queries archive.org for historical subdomains</p>
        
        <h3>How to Use:</h3>
        <ol>
            <li>Enter domain: <b>example.com</b></li>
            <li>Select enumeration method</li>
            <li>Click Start button</li>
            <li>Wait for enumeration</li>
            <li>Export results</li>
        </ol>
        
        <h3>Sample Output:</h3>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        www.example.com
        mail.example.com
        ftp.example.com
        api.example.com
        admin.example.com
        staging.example.com
        dev.example.com
        </pre>
        
        <h3>Tips:</h3>
        <ul>
            <li>Enumeration can take time for large domains</li>
            <li>Most results are validated via DNS</li>
            <li>Add custom wordlists for better coverage</li>
            <li>Save results for future reference</li>
        </ul>
        """
        return self.create_help_section('Subdomain Enumeration', content)
    
    def create_cve_scanner(self):
        content = """
        <h2 style="color: #667eea;">🔍 CVE Scanner</h2>
        
        <h3>Purpose:</h3>
        <p>Identifies known vulnerabilities (CVEs) in detected software</p>
        
        <h3>How It Works:</h3>
        
        <h4>1️⃣ Software Detection</h4>
        <p>Identifies server versions and technologies</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Apache/2.4.41
        Nginx/1.18.0
        PHP/7.4.3
        OpenSSL/1.1.1
        </pre>
        
        <h4>2️⃣ CVE Search</h4>
        <p>Queries CVE database for matching vulnerabilities</p>
        
        <h4>3️⃣ Risk Assessment</h4>
        <p>Displays CVSS scores and severity levels</p>
        
        <h3>Usage:</h3>
        <ol>
            <li>Enter URL or IP address</li>
            <li>Click Start Scan</li>
            <li>Scanner detects software versions</li>
            <li>Related CVEs are displayed</li>
            <li>Review and export findings</li>
        </ol>
        
        <h3>Sample Results:</h3>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        CVE-2021-44228 (Log4Shell)
        CVSS Score: 10.0
        Severity: CRITICAL
        Description: Remote code execution in Log4j
        
        CVE-2022-46163
        CVSS Score: 9.8
        Severity: CRITICAL
        </pre>
        
        <h3>CVSS Severity Levels:</h3>
        <ul>
            <li><b>9.0-10.0:</b> CRITICAL - Immediate action required</li>
            <li><b>7.0-8.9:</b> HIGH - Prioritize patching</li>
            <li><b>4.0-6.9:</b> MEDIUM - Plan remediation</li>
            <li><b>0.1-3.9:</b> LOW - Monitor and track</li>
        </ul>
        """
        return self.create_help_section('CVE Scanner', content)
    
    def create_cors_tester(self):
        content = """
        <h2 style="color: #667eea;">🔐 CORS Tester</h2>
        
        <h3>What is CORS?</h3>
        <p>CORS (Cross-Origin Resource Sharing) is a security mechanism that controls which domains can access resources</p>
        
        <h3>Common CORS Misconfigurations:</h3>
        
        <h4>1️⃣ Wildcard Origin (*)</h4>
        <p>Site allows any domain to access resources</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Access-Control-Allow-Origin: *
        </pre>
        
        <h4>2️⃣ Wildcard + Credentials (CRITICAL)</h4>
        <p>⚠️ Any website can access with user credentials</p>
        <pre style="background: #2d2d2d; color: #ff6b6b; padding: 10px; border-radius: 5px;">
        Access-Control-Allow-Origin: *
        Access-Control-Allow-Credentials: true
        </pre>
        
        <h4>3️⃣ Null Origin</h4>
        <p>file:// and data: URLs can request resources</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Access-Control-Allow-Origin: null
        </pre>
        
        <h3>How to Use:</h3>
        <ol>
            <li>Enter target URL: <b>https://example.com</b></li>
            <li>Add custom origins if needed</li>
            <li>Click Start Scan button</li>
            <li>Review results</li>
            <li>Generate PoC HTML if vulnerable</li>
        </ol>
        
        <h3>PoC Generation:</h3>
        <p>Creates interactive HTML to demonstrate vulnerability</p>
        <ul>
            <li>Test CORS configuration</li>
            <li>Fetch data with credentials</li>
            <li>View full HTTP headers</li>
            <li>Copy or save for testing</li>
        </ul>
        
        <h3>Export Options:</h3>
        <ul>
            <li>JSON format for analysis</li>
            <li>HTML PoC file for demonstrations</li>
            <li>Results in table view</li>
        </ul>
        """
        return self.create_help_section('CORS Tester', content)
    
    def create_waf_bypass(self):
        content = """
        <h2 style="color: #667eea;">🔥 WAF Bypass</h2>
        
        <h3>What is WAF?</h3>
        <p>WAF (Web Application Firewall) detects and blocks malicious requests</p>
        
        <h3>Bypass Techniques:</h3>
        
        <h4>1️⃣ Encoding</h4>
        <p>Encodes payload to evade filters</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Original: &lt;script&gt;alert('XSS')&lt;/script&gt;
        Base64: PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
        URL Encoded: %3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E
        </pre>
        
        <h4>2️⃣ Obfuscation</h4>
        <p>Hides payload structure from filters</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        String Concat: &lt;scr&lt;!--&gt;ipt&gt;
        Unicode: \\u003cscript\\u003e
        Case Mixing: &lt;ScRiPt&gt;
        </pre>
        
        <h4>3️⃣ Header Manipulation</h4>
        <p>Adds headers to bypass WAF detection</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        X-Forwarded-For: 127.0.0.1
        X-Original-URL: /admin
        X-Rewrite-URL: /bypass
        </pre>
        
        <h3>Usage Process:</h3>
        <ol>
            <li>Enter target URL</li>
            <li>Select bypass technique</li>
            <li>Prepare payload</li>
            <li>Send request</li>
            <li>Check if blocked</li>
        </ol>
        
        <h3>⚠️ Important Legal Notice:</h3>
        <ul>
            <li>Only use on systems you own or have permission to test</li>
            <li>WAF bypass without authorization may be illegal</li>
            <li>Always obtain written permission from system owner</li>
            <li>Document all activities for compliance</li>
        </ul>
        """
        return self.create_help_section('WAF Bypass', content)
    
    def create_auth_testing(self):
        content = """
        <h2 style="color: #667eea;">🔐 Authentication Testing</h2>
        
        <h3>Authentication Test Types:</h3>
        
        <h4>1️⃣ Brute Force Attack</h4>
        <p>Tests all possible username/password combinations</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        admin : 123456
        admin : password
        admin : admin123
        user : user123
        </pre>
        
        <h4>2️⃣ Credential Stuffing</h4>
        <p>Uses leaked credentials from previous breaches</p>
        
        <h4>3️⃣ Default Credentials</h4>
        <p>Tests manufacturer default passwords</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        admin/admin
        admin/123456
        root/root
        user/user
        guest/guest
        </pre>
        
        <h4>4️⃣ JWT Token Analysis</h4>
        <p>Examines JSON Web Token structure and claims</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        Header: {"alg":"HS256","typ":"JWT"}
        Payload: {"sub":"1234567890","name":"John"}
        </pre>
        
        <h3>How to Use:</h3>
        <ol>
            <li>Enter login URL</li>
            <li>Specify username/password fields</li>
            <li>Select wordlist</li>
            <li>Start authentication test</li>
        </ol>
        
        <h3>Sample Results:</h3>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        ✓ admin:password123 - SUCCESS
        ✓ user:user123 - SUCCESS
        ✗ test:test - FAILED
        ✗ root:toor - FAILED
        </pre>
        
        <h3>Best Practices:</h3>
        <ul>
            <li>Use rate limiting to avoid detection</li>
            <li>Rotate IP addresses</li>
            <li>Monitor for account lockouts</li>
            <li>Always have written authorization</li>
        </ul>
        """
        return self.create_help_section('Authentication Testing', content)
    
    def create_advanced_features(self):
        content = """
        <h2 style="color: #667eea;">🔧 Advanced Features</h2>
        
        <h3>Request Monitor</h3>
        <p>Inspect all HTTP requests and responses in real-time</p>
        <ul>
            <li>View complete HTTP headers</li>
            <li>Examine response body</li>
            <li>Analyze cookies and tokens</li>
            <li>Save requests for replay</li>
        </ul>
        
        <h3>Advanced Settings</h3>
        <p>Fine-grained control over scanning behavior</p>
        <ul>
            <li>Custom wordlists</li>
            <li>Proxy configuration (HTTP/SOCKS5)</li>
            <li>SSL verification options</li>
            <li>Rate limiting controls</li>
            <li>Custom headers</li>
        </ul>
        
        <h3>Results Export</h3>
        <p>Export findings in multiple formats</p>
        <ul>
            <li>JSON - For processing and analysis</li>
            <li>CSV - For spreadsheet import</li>
            <li>HTML - For client presentations</li>
            <li>PDF - For professional reports</li>
        </ul>
        
        <h3>Custom Payloads</h3>
        <p>Create and manage custom attack payloads</p>
        <pre style="background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px;">
        {user_input}'; DROP TABLE users; --
        {fuzz}%27%20or%20%271%27=%271
        &lt;img src=x onerror="{payload}"&gt;
        </pre>
        
        <h3>Automation</h3>
        <p>Schedule and automate scanning tasks</p>
        <ul>
            <li>Scheduled scans</li>
            <li>Batch processing</li>
            <li>Automated reporting</li>
        </ul>
        """
        return self.create_help_section('Advanced Features', content)
    
    def create_tips_tricks(self):
        content = """
        <h2 style="color: #667eea;">💡 Tips & Tricks</h2>
        
        <h3>⚡ Performance Tips</h3>
        <ul>
            <li>Increase workers to 20-30 for large sites</li>
            <li>Reduce request delay but monitor for blocks</li>
            <li>Adjust timeout based on connection speed</li>
            <li>Use caching for repeated scans</li>
        </ul>
        
        <h3>🎯 Accuracy Tips</h3>
        <ul>
            <li>Run all scan types for comprehensive coverage</li>
            <li>Manually verify suspicious results</li>
            <li>Test time-based attacks for RCE confirmation</li>
            <li>Try multiple payload variations</li>
        </ul>
        
        <h3>🔒 Security Best Practices</h3>
        <ul>
            <li>Never scan without explicit permission</li>
            <li>Use VPN to mask your IP address</li>
            <li>Screenshot findings for documentation</li>
            <li>Encrypt sensitive results</li>
        </ul>
        
        <h3>📋 Testing Methodology</h3>
        <ul>
            <li>Start with small test scans</li>
            <li>Validate all findings manually</li>
            <li>Create comprehensive reports</li>
            <li>Document timeline and evidence</li>
        </ul>
        
        <h3>🛠️ Troubleshooting</h3>
        <ul>
            <li>Check Request Monitor for request details</li>
            <li>Review Advanced Settings logs</li>
            <li>Change User-Agent if blocked</li>
            <li>Disable SSL verification for testing (use caution)</li>
        </ul>
        
        <h3>📚 Learning Resources</h3>
        <ul>
            <li><b>OWASP Top 10:</b> Most common vulnerabilities</li>
            <li><b>PayloadsAllTheThings:</b> Payload repository</li>
            <li><b>PortSwigger Academy:</b> Web security training</li>
            <li><b>HackTheBox:</b> Hands-on practice challenges</li>
        </ul>
        
        <h3>🎓 Career Development</h3>
        <ul>
            <li>Participate in CTF competitions</li>
            <li>Join bug bounty programs</li>
            <li>Pursue security certifications</li>
            <li>Study OWASP standards</li>
        </ul>
        """
        return self.create_help_section('Tips & Tricks', content)
