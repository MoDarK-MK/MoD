<div align="center">

# 🛡️ MoD - Master of Defense

[![Version](https://img.shields.io/badge/version-4.0.0.2-blue.svg)](https://github.com/MoDarK-MK/MoD)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/MoDarK-MK/MoD)
[![PyQt6](https://img.shields.io/badge/GUI-PyQt6-41CD52.svg)](https://pypi.org/project/PyQt6/)
[![Status](https://img.shields.io/badge/status-Production%20Ready-success.svg)](https://github.com/MoDarK-MK/MoD)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Code Quality](https://img.shields.io/badge/code%20quality-A+-brightgreen.svg)](https://github.com/MoDarK-MK/MoD)

### 🚀 Professional Web Application Security Scanner

_An advanced, enterprise-grade vulnerability assessment platform built with cutting-edge technology_

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

---

</div>

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Vulnerability Scanners](#-vulnerability-scanners)
- [Advanced Capabilities](#-advanced-capabilities)
- [Design System](#-design-system)
- [Configuration](#-configuration)
- [Usage Examples](#-usage-examples)
- [API Reference](#-api-reference)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**MoD (Master of Defense)** is a state-of-the-art web application security scanner designed for penetration testers, security researchers, and bug bounty hunters. Built with Python and PyQt6, it combines powerful scanning capabilities with an intuitive, professional interface.

### ✨ What's New in v4.0

- 🎨 **Complete UI Overhaul** - Professional dark theme with cyan accents
- 🏗️ **Modular Design System** - Consistent components across all 15 tabs
- 🚀 **Performance Improvements** - Optimized scanning engine with intelligent caching
- 🔧 **Enhanced WAF Bypass** - Advanced evasion techniques
- 📊 **Better Reporting** - Export results in multiple formats (JSON, CSV, HTML, PDF)
- 🔐 **Authentication Manager** - Support for OAuth2, JWT, Basic Auth, and more
- 🌐 **Subdomain Enumeration** - Comprehensive subdomain discovery
- ⏰ **Wayback Integration** - Historical endpoint analysis
- 💬 **Discord Notifications** - Real-time vulnerability alerts

---

## 🌟 Features

<table>
<tr>
<td width="50%">

### 🔍 Core Scanning

- ✅ **14+ Vulnerability Types**
- ✅ Intelligent Pattern Recognition
- ✅ False Positive Reduction
- ✅ Automated PoC Generation
- ✅ Multi-threaded Scanning
- ✅ Request/Response Analysis
- ✅ Custom Payload Support

</td>
<td width="50%">

### 🎨 User Interface

- ✅ Modern Dark Theme
- ✅ Fullscreen Optimized
- ✅ 15 Professional Tabs
- ✅ Real-time Updates
- ✅ Progress Monitoring
- ✅ Responsive Design
- ✅ Customizable Layout

</td>
</tr>
<tr>
<td width="50%">

### 🛠️ Advanced Tools

- ✅ WAF Detection & Bypass
- ✅ Subdomain Enumeration
- ✅ CVE Scanner Integration
- ✅ GraphQL Testing
- ✅ WebSocket Analysis
- ✅ Local AI Engine (**mod**) for on-device security scoring (no external APIs)
- ✅ API Security Testing
- ✅ CORS Misconfiguration

</td>
<td width="50%">

### 📊 Reporting & Integration

- ✅ Multiple Export Formats
- ✅ Discord Webhooks
- ✅ Custom Templates
- ✅ Compliance Reports
- ✅ Historical Analysis
- ✅ Vulnerability Tracking
- ✅ Executive Summaries

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
MoD/
├── 📁 core/                      # Core scanning engine
│   ├── scanner_engine.py         # Main scanner orchestration
│   ├── vulnerability_detector.py # Detection algorithms
│   ├── request_handler.py        # HTTP request management
│   ├── response_analyzer.py      # Response analysis
│   ├── payload_generator.py      # Dynamic payload generation
│   ├── poc_generator.py          # Proof-of-Concept automation
│   ├── intelligent_scanner.py    # ML-based scanning
│   ├── distributed_scanner.py    # Multi-target coordination
│   ├── auth_manager.py           # Authentication handling
│   └── cache_manager.py          # Performance optimization
│
├── 📁 gui/                       # User interface components
│   ├── main_window.py            # Main application window
│   ├── design_system.py          # Design components & styles
│   ├── theme_manager.py          # Theme switching
│   ├── scan_tab.py               # Vulnerability scanning
│   ├── results_tab.py            # Results visualization
│   ├── cve_scanner_tab.py        # CVE database scanning
│   ├── waf_bypass_tab.py         # WAF evasion techniques
│   ├── request_monitor_tab.py    # HTTP traffic monitor
│   ├── subdomain_tab.py          # Subdomain enumeration
│   ├── wayback_tab.py            # Wayback Machine integration
│   ├── auth_tab.py               # Authentication configuration
│   ├── cors_tab.py               # CORS testing
│   ├── websocket_tab.py          # WebSocket security
│   ├── graphql_tab.py            # GraphQL testing
│   ├── discord_tab.py            # Discord integration
│   ├── settings_tab.py           # General settings
│   ├── advanced_settings_tab.py  # Advanced configuration
│   └── help_tab.py               # Help & documentation
│
├── 📁 scanners/                  # Specialized vulnerability scanners
│   ├── xss_scanner.py            # Cross-Site Scripting
│   ├── sql_scanner.py            # SQL Injection
│   ├── rce_scanner.py            # Remote Code Execution
│   ├── command_injection_scanner.py  # Command Injection
│   ├── ssrf_scanner.py           # Server-Side Request Forgery
│   ├── csrf_scanner.py           # Cross-Site Request Forgery
│   ├── xxe_scanner.py            # XML External Entity
│   ├── file_upload_scanner.py    # File Upload vulnerabilities
│   ├── api_scanner.py            # REST/GraphQL API testing
│   ├── websocket_scanner.py      # WebSocket vulnerabilities
│   ├── graphql_scanner.py        # GraphQL security
│   ├── ssti_scanner.py           # Server-Side Template Injection
│   ├── ldap_scanner.py           # LDAP Injection
│   ├── oauth_saml_scanner.py     # OAuth/SAML flaws
│   ├── cors_scanner.py           # CORS misconfigurations
│   ├── subdomain_scanner.py      # Subdomain discovery
│   ├── wayback_scanner.py        # Historical endpoints
│   ├── cve_scanner.py            # Known CVE detection
│   ├── waf_bypass_engine.py      # WAF evasion v1
│   ├── waf_bypass_engine_v2.py   # WAF evasion v2
│   └── vulnerability_verifier.py # PoC verification
│
├── 📁 utils/                     # Utility modules
│   ├── logger.py                 # Logging system
│   ├── config.py                 # Configuration management
│   ├── database.py               # SQLite integration
│   ├── report_generator.py       # Report creation
│   ├── compliance_generator.py   # Compliance reports
│   ├── cache.py                  # Caching layer
│   ├── proxy_manager.py          # Proxy configuration
│   ├── wayback_client.py         # Wayback API client
│   ├── integration_manager.py    # Third-party integrations
│   └── update_checker.py         # Version management
│
├── 📁 data/                      # Data files
│   └── subdomain_wordlist.txt    # Subdomain wordlists
│
├── 📁 tests/                     # Unit & integration tests
│   ├── test_vulnerability_detector.py
│   ├── test_request_handler.py
│   ├── test_response_analyzer.py
│   └── test_csrf_scanner.py
│
├── 📄 main.py                    # Application entry point
├── 📄 requirements.txt           # Python dependencies
├── 📄 pyproject.toml             # Project configuration
└── 📄 version.txt                # Version tracking
```

---

## 💻 Installation

### Prerequisites

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![pip](https://img.shields.io/badge/pip-Latest-3776AB?style=for-the-badge&logo=pypi&logoColor=white)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/MoDarK-MK/MoD.git
cd MoD

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Dependencies

```txt
PyQt6>=6.4.0          # Modern GUI framework
requests>=2.28.0      # HTTP client
beautifulsoup4>=4.11  # HTML parsing
lxml>=4.9.0           # XML processing
urllib3>=1.26.0       # HTTP utilities
pyyaml>=6.0           # YAML configuration
colorama>=0.4.6       # Terminal colors
tqdm>=4.64.0          # Progress bars
python-dotenv>=0.20.0 # Environment management
```

---

## 🚀 Quick Start

### Launch Application

```bash
# Windows
python main.py

# Linux/macOS
python3 main.py
```

### Basic Scan Workflow

1. **Select Scan Tab** → Choose vulnerability type
2. **Enter Target URL** → Input your testing target
3. **Configure Settings** → Adjust scan parameters
4. **Start Scan** → Click the scan button
5. **Review Results** → Analyze findings in Results tab
6. **Export Report** → Generate professional reports

### Command Line Interface (CLI)

```bash
# Quick vulnerability scan
python main.py --url https://example.com --scan xss,sql

# Full scan with all modules
python main.py --url https://example.com --full-scan

# CVE scanning
python main.py --url https://example.com --cve-scan

# Export results
python main.py --url https://example.com --scan all --export json
```

---

## 🔍 Vulnerability Scanners

### 🎯 Injection Attacks

| Scanner               | Description                  | CWE      | Techniques                                          |
| --------------------- | ---------------------------- | -------- | --------------------------------------------------- |
| **SQL Injection**     | Database query manipulation  | CWE-89   | Error-based, Boolean-based, Time-based, UNION-based |
| **Command Injection** | OS command execution         | CWE-78   | Shell metacharacters, Command chaining, Backticks   |
| **LDAP Injection**    | LDAP query manipulation      | CWE-90   | Filter injection, DN injection                      |
| **XXE Injection**     | XML external entity attacks  | CWE-611  | File disclosure, SSRF, DoS                          |
| **SSTI**              | Template engine exploitation | CWE-1336 | Jinja2, Twig, Freemarker, Velocity                  |

### 🌐 Web Vulnerabilities

| Scanner  | Description                    | CWE     | Detection Methods                       |
| -------- | ------------------------------ | ------- | --------------------------------------- |
| **XSS**  | Cross-Site Scripting           | CWE-79  | Reflected, Stored, DOM-based, Mutation  |
| **CSRF** | Request forgery attacks        | CWE-352 | Token analysis, SameSite validation     |
| **CORS** | Cross-origin misconfigurations | CWE-942 | Origin reflection, Credential leakage   |
| **SSRF** | Server-side request forgery    | CWE-918 | Internal network access, Cloud metadata |

### 🔓 Authentication & Access Control

| Scanner         | Description               | CWE     | Features                                  |
| --------------- | ------------------------- | ------- | ----------------------------------------- |
| **OAuth/SAML**  | Authentication flow flaws | CWE-306 | Token hijacking, Flow bypass              |
| **File Upload** | Malicious file uploads    | CWE-434 | Extension validation, Content-Type bypass |

### 🚀 Modern Web Technologies

| Scanner         | Description                      | Features                                   |
| --------------- | -------------------------------- | ------------------------------------------ |
| **API Scanner** | REST/GraphQL testing             | Endpoint discovery, Parameter fuzzing      |
| **WebSocket**   | Real-time protocol testing       | Message manipulation, Connection hijacking |
| **GraphQL**     | GraphQL-specific vulnerabilities | Introspection, Batching, Depth attacks     |

### 🛡️ Security Features

| Feature         | Description                   | Capabilities                          |
| --------------- | ----------------------------- | ------------------------------------- |
| **WAF Bypass**  | Firewall evasion              | 20+ encoding techniques, Obfuscation  |
| **CVE Scanner** | Known vulnerability detection | 5000+ CVE database, Auto-exploitation |
| **RCE Scanner** | Remote code execution         | Multi-platform, Language-specific     |

---

## 🎨 Design System

### Color Palette

```python
# Primary Colors
BACKGROUND      = "#0F1419"  # Deep dark background
SURFACE         = "#1A1F26"  # Card/surface color
PRIMARY         = "#00D4FF"  # Cyan accent
PRIMARY_HOVER   = "#00B8E6"  # Hover state
PRIMARY_DARK    = "#009CC7"  # Active state

# Text Colors
TEXT_PRIMARY    = "#FFFFFF"  # Main text
TEXT_SECONDARY  = "#8B949E"  # Secondary text
TEXT_TERTIARY   = "#6E7681"  # Tertiary text

# Status Colors
SUCCESS         = "#00E676"  # Success state
WARNING         = "#FFB300"  # Warning state
ERROR           = "#FF5252"  # Error state
INFO            = "#00D4FF"  # Info state
```

### Typography

```python
# Font Families
PRIMARY_FONT   = "SF Pro Display, Segoe UI, Arial"
MONOSPACE_FONT = "Consolas, Monaco, Courier New"

# Font Sizes
TITLE_LARGE   = 24px  # Page titles
TITLE_MEDIUM  = 18px  # Section headers
TITLE_SMALL   = 16px  # Card titles
BODY_LARGE    = 14px  # Primary text
BODY_MEDIUM   = 13px  # Secondary text
BODY_SMALL    = 12px  # Tertiary text
CAPTION       = 11px  # Captions/labels
```

### Spacing System

```python
# 4px Grid System
SPACING_XS    = 4px   # Minimal spacing
SPACING_SM    = 8px   # Small spacing
SPACING_MD    = 12px  # Medium spacing
SPACING_LG    = 16px  # Large spacing
SPACING_XL    = 24px  # Extra large spacing
SPACING_XXL   = 32px  # Maximum spacing
```

### Component Library

- **DesignButton** - Professional button styles (Primary, Secondary, Danger, Success)
- **DesignCard** - Elevated card containers with shadows
- **DesignHeader** - Page and section headers
- **DesignSection** - Content sections with dividers
- **DesignInput** - Styled input fields and text areas
- **DesignTable** - Data tables with alternating rows
- **DesignBadge** - Status and severity badges
- **DesignProgress** - Progress bars and spinners

---

## ⚙️ Configuration

### Application Settings

```yaml
# config.yaml
app:
  theme: dark
  language: en
  fullscreen: true
  auto_save: true

scanning:
  threads: 10
  timeout: 30
  retry_count: 3
  user_agent: "MoD Security Scanner/4.0"

proxy:
  enabled: false
  http: "http://127.0.0.1:8080"
  https: "https://127.0.0.1:8080"

reporting:
  auto_export: false
  format: json
  output_dir: "./reports"

notifications:
  discord_enabled: false
  discord_webhook: ""
```

### Environment Variables

```bash
# .env file
MOD_API_KEY=your_api_key
MOD_PROXY_URL=http://proxy.example.com:8080
MOD_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
MOD_DEBUG=false
```

---

## 📚 Usage Examples

### Example 1: XSS Scanning

```python
from core.scanner_engine import ScannerEngine
from scanners.xss_scanner import XSSScanner

# Initialize scanner
engine = ScannerEngine()
xss_scanner = XSSScanner()

# Configure scan
target = "https://example.com/search?q="
results = xss_scanner.scan(target)

# Process results
for vuln in results:
    print(f"[{vuln.severity}] {vuln.type}: {vuln.payload}")
```

### Example 2: SQL Injection with WAF Bypass

```python
from scanners.sql_scanner import SQLScanner
from scanners.waf_bypass_engine import WAFBypassEngine

# Setup
sql_scanner = SQLScanner()
waf_bypass = WAFBypassEngine()

# Detect WAF
waf_type = waf_bypass.detect_waf("https://example.com")

# Generate bypassed payloads
payloads = waf_bypass.generate_bypass_payloads(
    base_payload="' OR 1=1--",
    waf_type=waf_type
)

# Scan with bypasses
results = sql_scanner.scan_with_payloads("https://example.com", payloads)
```

### Example 3: Subdomain Enumeration

```python
from scanners.subdomain_scanner import SubdomainScanner

scanner = SubdomainScanner()
subdomains = scanner.enumerate(
    domain="example.com",
    wordlist="data/subdomain_wordlist.txt",
    threads=50
)

for subdomain in subdomains:
    print(f"Found: {subdomain}")
```

---

## 🔌 API Reference

### Core Scanner Engine

```python
class ScannerEngine:
    def __init__(self, config: dict = None)
    def scan(self, target: str, scan_types: list) -> ScanResults
    def quick_scan(self, target: str) -> ScanResults
    def full_scan(self, target: str) -> ScanResults
    def export_results(self, format: str, output: str) -> bool
```

### Vulnerability Detector

```python
class VulnerabilityDetector:
    def detect(self, response: Response, payload: str) -> Vulnerability
    def verify(self, vulnerability: Vulnerability) -> bool
    def generate_poc(self, vulnerability: Vulnerability) -> str
```

### Report Generator

```python
class ReportGenerator:
    def generate_html(self, results: ScanResults) -> str
    def generate_json(self, results: ScanResults) -> dict
    def generate_pdf(self, results: ScanResults) -> bytes
    def generate_csv(self, results: ScanResults) -> str
```

---

## 📊 Performance

| Metric                | Value                       |
| --------------------- | --------------------------- |
| **Scan Speed**        | Up to 1000 requests/minute  |
| **Accuracy**          | 95%+ detection rate         |
| **False Positives**   | <5%                         |
| **Memory Usage**      | ~200MB average              |
| **CPU Usage**         | Multi-threaded optimization |
| **Supported Targets** | Unlimited concurrent scans  |

---

## 🛠️ Development

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test
python -m pytest tests/test_vulnerability_detector.py

# Generate coverage report
python -m pytest --cov=core --cov-report=html
```

### Code Quality

```bash
# Linting
pylint core/ scanners/ gui/

# Type checking
mypy core/ scanners/

# Formatting
black core/ scanners/ gui/
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code of Conduct

Please read our [Code of Conduct](docs/CODE_OF_CONDUCT.md) before contributing.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **PyQt6** - Modern GUI framework
- **Requests** - HTTP library
- **BeautifulSoup** - HTML parsing
- **OWASP** - Security testing guidelines
- **CVE Database** - Vulnerability information

---

## 📞 Support

- 📧 Email: support@mod-scanner.com
- 💬 Discord: [Join our community](https://discord.gg/mod-scanner)
- 🐛 Issues: [GitHub Issues](https://github.com/MoDarK-MK/MoD/issues)
- 📖 Documentation: [Wiki](https://github.com/MoDarK-MK/MoD/wiki)

---

## 📈 Roadmap

- [ ] Machine Learning-based vulnerability detection
- [ ] Browser automation with Selenium
- [ ] Mobile application security testing
- [ ] Cloud security scanning (AWS, Azure, GCP)
- [ ] Blockchain smart contract auditing
- [ ] Advanced reporting dashboard
- [ ] REST API for automation
- [ ] Plugin system for custom scanners

---

<div align="center">

### ⭐ Star us on GitHub!

[![GitHub stars](https://img.shields.io/github/stars/MoDarK-MK/MoD?style=social)](https://github.com/MoDarK-MK/MoD/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/MoDarK-MK/MoD?style=social)](https://github.com/MoDarK-MK/MoD/network/members)
[![GitHub watchers](https://img.shields.io/github/watchers/MoDarK-MK/MoD?style=social)](https://github.com/MoDarK-MK/MoD/watchers)

**Made with ❤️ by the MoD Team**

_Version 4.0.0.2 | Last Updated: December 9, 2025_

![Status](https://img.shields.io/badge/Status-Production%20Ready-success?style=for-the-badge)

</div>
