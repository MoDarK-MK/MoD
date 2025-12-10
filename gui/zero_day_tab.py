"""
Zero-Day Scanner Tab - Interactive vulnerability detection interface
===================================================================
Provides GUI for scanning target URLs for zero-day vulnerabilities.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QProgressBar, QSplitter, QFrame, QScrollArea, QTabWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QIcon, QColor
import json
from scanners.zero_day_scanner import ZeroDayScanner
from gui.design_system import DesignColors, DesignSpacing, DesignTypography


class ZeroDayScanWorker(QThread):
    """Worker thread for scanning without blocking UI."""
    
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, url: str):
        super().__init__()
        self.url = url
        self.scanner = ZeroDayScanner(verbose=False)
    
    def run(self):
        """Run the scan in background."""
        try:
            self.progress.emit("Initializing scanner...")
            report = self.scanner.scan_target(self.url, verbose_output=False)
            self.finished.emit(report)
        except Exception as e:
            self.error.emit(str(e))


class ZeroDayTab(QWidget):
    """Zero-Day Vulnerability Scanner Tab"""
    
    def __init__(self):
        super().__init__()
        self.scanner = None
        self.is_scanning = False
        self.init_ui()
        self.apply_theme()
    
    def init_ui(self):
        """Initialize UI components."""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(DesignSpacing.MD)
        main_layout.setContentsMargins(DesignSpacing.LG, DesignSpacing.LG, 
                                       DesignSpacing.LG, DesignSpacing.LG)
        
        # ===== INPUT SECTION =====
        input_frame = QFrame()
        input_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {DesignColors.CARD_BG};
                border: 1px solid {DesignColors.BORDER};
                border-radius: 8px;
                padding: {DesignSpacing.MD}px;
            }}
        """)
        input_layout = QVBoxLayout(input_frame)
        
        # Title
        title_label = QLabel("Zero-Day Vulnerability Scanner")
        title_font = QFont("Segoe UI", 12, QFont.Weight.Bold)
        title_label.setFont(title_font)
        title_label.setStyleSheet(f"color: {DesignColors.PRIMARY};")
        input_layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel(
            "Advanced ML-based zero-day detection using behavioral analysis and anomaly detection. "
            "Enter a target URL to scan for unknown vulnerabilities."
        )
        desc_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY}; font-size: 10pt;")
        desc_label.setWordWrap(True)
        input_layout.addWidget(desc_label)
        
        # URL Input
        url_layout = QHBoxLayout()
        url_label = QLabel("Target URL:")
        url_label.setStyleSheet(f"color: {DesignColors.TEXT}; font-weight: bold;")
        url_label.setFixedWidth(100)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.setMinimumHeight(40)
        self.url_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {DesignColors.INPUT_BG};
                border: 2px solid {DesignColors.BORDER};
                border-radius: 6px;
                padding: 8px;
                color: {DesignColors.TEXT};
                font-size: 11pt;
            }}
            QLineEdit:focus {{
                border: 2px solid {DesignColors.PRIMARY};
            }}
        """)
        
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        input_layout.addLayout(url_layout)
        
        # Scan Button
        self.scan_button = QPushButton("🚀 Start Scan")
        self.scan_button.setMinimumHeight(40)
        self.scan_button.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.scan_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {DesignColors.PRIMARY};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {DesignColors.PRIMARY_DARK};
            }}
            QPushButton:pressed {{
                background-color: {DesignColors.PRIMARY_DARKER};
            }}
            QPushButton:disabled {{
                background-color: {DesignColors.BORDER};
                color: {DesignColors.TEXT_SECONDARY};
            }}
        """)
        self.scan_button.clicked.connect(self.start_scan)
        input_layout.addWidget(self.scan_button)
        
        main_layout.addWidget(input_frame)
        
        # ===== PROGRESS SECTION =====
        progress_frame = QFrame()
        progress_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {DesignColors.CARD_BG};
                border: 1px solid {DesignColors.BORDER};
                border-radius: 8px;
                padding: {DesignSpacing.MD}px;
            }}
        """)
        progress_layout = QVBoxLayout(progress_frame)
        
        progress_label = QLabel("Scan Progress")
        progress_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        progress_label.setStyleSheet(f"color: {DesignColors.PRIMARY};")
        progress_layout.addWidget(progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumHeight(25)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid {DesignColors.BORDER};
                border-radius: 6px;
                background-color: {DesignColors.INPUT_BG};
            }}
            QProgressBar::chunk {{
                background-color: {DesignColors.SUCCESS};
                border-radius: 4px;
            }}
        """)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY}; font-size: 9pt;")
        progress_layout.addWidget(self.status_label)
        
        main_layout.addWidget(progress_frame)
        
        # ===== RESULTS SECTION =====
        results_frame = QFrame()
        results_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {DesignColors.CARD_BG};
                border: 1px solid {DesignColors.BORDER};
                border-radius: 8px;
                padding: {DesignSpacing.MD}px;
            }}
        """)
        results_layout = QVBoxLayout(results_frame)
        
        results_label = QLabel("Scan Results")
        results_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        results_label.setStyleSheet(f"color: {DesignColors.PRIMARY};")
        results_layout.addWidget(results_label)
        
        # Create tabs for results
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet(f"""
            QTabBar::tab {{
                background-color: {DesignColors.INPUT_BG};
                color: {DesignColors.TEXT};
                padding: 8px 16px;
                border: 1px solid {DesignColors.BORDER};
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {DesignColors.PRIMARY};
                color: white;
            }}
        """)
        
        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMinimumHeight(300)
        self.summary_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DesignColors.INPUT_BG};
                border: 1px solid {DesignColors.BORDER};
                color: {DesignColors.TEXT};
                padding: 8px;
                border-radius: 4px;
            }}
        """)
        self.results_tabs.addTab(self.summary_text, "📋 Summary")
        
        # Details tab
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMinimumHeight(300)
        self.details_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DesignColors.INPUT_BG};
                border: 1px solid {DesignColors.BORDER};
                color: {DesignColors.TEXT};
                padding: 8px;
                border-radius: 4px;
            }}
        """)
        self.results_tabs.addTab(self.details_text, "🔍 Detailed Analysis")
        
        # Raw JSON tab
        self.json_text = QTextEdit()
        self.json_text.setReadOnly(True)
        self.json_text.setMinimumHeight(300)
        self.json_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DesignColors.INPUT_BG};
                border: 1px solid {DesignColors.BORDER};
                color: {DesignColors.TEXT};
                padding: 8px;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 9pt;
            }}
        """)
        self.results_tabs.addTab(self.json_text, "📄 Raw JSON")
        
        results_layout.addWidget(self.results_tabs)
        
        main_layout.addWidget(results_frame)
        
        # ===== ACTION BUTTONS =====
        action_layout = QHBoxLayout()
        
        self.export_button = QPushButton("💾 Export Report")
        self.export_button.setMinimumHeight(35)
        self.export_button.setEnabled(False)
        self.export_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {DesignColors.SECONDARY};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }}
            QPushButton:hover:!disabled {{
                background-color: {DesignColors.PRIMARY};
            }}
            QPushButton:disabled {{
                background-color: {DesignColors.BORDER};
                color: {DesignColors.TEXT_SECONDARY};
            }}
        """)
        self.export_button.clicked.connect(self.export_report)
        action_layout.addWidget(self.export_button)
        
        self.clear_button = QPushButton("🗑️ Clear Results")
        self.clear_button.setMinimumHeight(35)
        self.clear_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {DesignColors.DANGER};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {DesignColors.DANGER_DARK};
            }}
        """)
        self.clear_button.clicked.connect(self.clear_results)
        action_layout.addWidget(self.clear_button)
        
        action_layout.addStretch()
        main_layout.addLayout(action_layout)
        
        main_layout.addStretch()
    
    def apply_theme(self):
        """Apply theme colors."""
        self.setStyleSheet(f"background-color: {DesignColors.DARK_BG};")
    
    def start_scan(self):
        """Start vulnerability scan on target URL."""
        url = self.url_input.text().strip()
        
        if not url:
            self.status_label.setText("❌ Please enter a valid URL")
            return
        
        self.is_scanning = True
        self.scan_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("🔄 Initializing scan...")
        self.summary_text.clear()
        self.details_text.clear()
        self.json_text.clear()
        
        # Create and start worker thread
        self.worker = ZeroDayScanWorker(url)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()
        
        # Simulate progress
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(lambda: self.progress_bar.setValue(
            min(self.progress_bar.value() + 5, 90)
        ))
        self.progress_timer.start(500)
    
    def update_progress(self, message: str):
        """Update progress message."""
        self.status_label.setText(f"🔄 {message}")
    
    def on_scan_finished(self, report: dict):
        """Handle scan completion."""
        self.progress_timer.stop()
        self.progress_bar.setValue(100)
        self.is_scanning = False
        self.scan_button.setEnabled(True)
        self.export_button.setEnabled(True)
        
        self.last_report = report
        
        # Update UI with results
        self.display_results(report)
        self.status_label.setText("✅ Scan completed successfully!")
    
    def on_scan_error(self, error: str):
        """Handle scan error."""
        self.progress_timer.stop()
        self.progress_bar.setValue(0)
        self.is_scanning = False
        self.scan_button.setEnabled(True)
        self.status_label.setText(f"❌ Scan failed: {error}")
    
    def display_results(self, report: dict):
        """Display scan results in UI."""
        # Summary
        summary = f"""
╔════════════════════════════════════════════════════════════╗
║                     SCAN SUMMARY                           ║
╚════════════════════════════════════════════════════════════╝

🎯 Target: {report.get('url', 'Unknown')}

📊 STATISTICS:
   • Total Requests: {report.get('total_requests', 0)}
   • Parameters Tested: {report.get('parameters_tested', 0)}
   • Payloads Tested: {report.get('payloads_tested', 0)}

🚨 FINDINGS:
   • Critical: {report.get('critical_count', 0)} ⚠️
   • High: {report.get('high_count', 0)}
   • Medium: {report.get('medium_count', 0)}
   • Low: {report.get('low_count', 0)}
   ─────────────────────────────
   • TOTAL: {report.get('total_findings', 0)}

📈 STATUS: {report.get('status', 'Unknown').upper()}
"""
        self.summary_text.setText(summary)
        
        # Detailed findings
        if report.get('findings'):
            details = "╔════════════════════════════════════════════════════════════╗\n"
            details += "║                  DETAILED FINDINGS                          ║\n"
            details += "╚════════════════════════════════════════════════════════════╝\n\n"
            
            for i, finding in enumerate(report['findings'], 1):
                details += f"[{i}] {finding['type']}\n"
                details += f"    Severity: {finding['severity']} | Confidence: {finding['confidence']:.1%}\n"
                details += f"    Indicators:\n"
                for indicator in finding.get('indicators', [])[:3]:
                    details += f"      • {indicator}\n"
                if finding.get('recommendation'):
                    details += f"    Recommendation: {finding['recommendation']}\n"
                details += "\n"
        else:
            details = "✅ No vulnerabilities detected!\n\nThe target appears to be secure based on the scan parameters."
        
        self.details_text.setText(details)
        
        # JSON export
        self.json_text.setText(json.dumps(report, indent=2, ensure_ascii=False))
    
    def export_report(self):
        """Export report to file."""
        if not hasattr(self, 'last_report'):
            self.status_label.setText("❌ No report to export")
            return
        
        from PyQt6.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Zero-Day Scan Report", 
            "zero_day_report.json", "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.last_report, f, indent=2, ensure_ascii=False)
                self.status_label.setText(f"✅ Report exported to {file_path}")
            except Exception as e:
                self.status_label.setText(f"❌ Export failed: {str(e)}")
    
    def clear_results(self):
        """Clear all results."""
        self.summary_text.clear()
        self.details_text.clear()
        self.json_text.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready to scan")
        self.export_button.setEnabled(False)
