import requests
import json
import threading
from typing import Callable, Optional, Dict, Any
from pathlib import Path
import subprocess
import sys
from datetime import datetime
from utils.config import Config


class UpdateChecker:
    
    GITHUB_API_URL = "https://api.github.com/repos/MoDarK-MK/MoD/releases/latest"
    VERSION_FILE = Path(__file__).parent.parent / "version.txt"
    
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.config = Config()
        self.update_available = False
        self.current_version = self._read_current_version()
        self.latest_version = None
        self.update_info = {}
        self.error_message = None
    
    def _read_current_version(self) -> str:
        try:
            if self.VERSION_FILE.exists():
                return self.VERSION_FILE.read_text().strip()
            return "1.0.0"
        except:
            return "1.0.0"
    
    def _parse_version(self, version_str: str) -> tuple:
        try:
            parts = version_str.replace('v', '').split('.')
            return tuple(int(p) for p in parts[:3])
        except:
            return (0, 0, 0)
    
    def check_for_updates(self) -> bool:
        try:
            response = requests.get(self.GITHUB_API_URL, timeout=5)
            response.raise_for_status()
            
            release_data = response.json()
            self.latest_version = release_data.get('tag_name', '').replace('v', '')
            
            current_tuple = self._parse_version(self.current_version)
            latest_tuple = self._parse_version(self.latest_version)
            
            if latest_tuple > current_tuple:
                self.update_available = True
                self.update_info = {
                    'version': self.latest_version,
                    'name': release_data.get('name', 'New Release'),
                    'body': release_data.get('body', 'No description available'),
                    'url': release_data.get('html_url', ''),
                    'download_url': release_data.get('assets', [{}])[0].get('browser_download_url', ''),
                    'published_at': release_data.get('published_at', ''),
                }
                return True
            
            return False
        
        except requests.exceptions.Timeout:
            self.error_message = "Update check timed out (5s)"
            return False
        except requests.exceptions.ConnectionError:
            self.error_message = "No internet connection"
            return False
        except json.JSONDecodeError:
            self.error_message = "Invalid API response"
            return False
        except Exception as e:
            self.error_message = f"Error: {str(e)[:50]}"
            return False
    
    def get_update_status(self) -> Dict[str, Any]:
        return {
            'update_available': self.update_available,
            'current_version': self.current_version,
            'latest_version': self.latest_version,
            'info': self.update_info,
            'error': self.error_message,
        }
    
    def save_check_settings(self, check_on_startup: bool, check_frequency_days: int = 7):
        """Save user's update check preferences"""
        try:
            config_data = self.config.load()
            config_data['updates']['check_on_startup'] = check_on_startup
            config_data['updates']['check_frequency_days'] = check_frequency_days
            config_data['updates']['last_check_date'] = datetime.now().isoformat()
            self.config.save(config_data)
            return True
        except Exception as e:
            print(f"Error saving update settings: {e}")
            return False
    
    def should_check_for_updates(self) -> bool:
        """Check if we should check for updates based on frequency and settings"""
        try:
            config_data = self.config.load()
            if not config_data.get('updates', {}).get('check_on_startup', True):
                return False
            
            last_check = config_data.get('updates', {}).get('last_check_date')
            check_frequency = config_data.get('updates', {}).get('check_frequency_days', 7)
            
            if not last_check:
                return True
            
            last_check_dt = datetime.fromisoformat(last_check)
            days_since_check = (datetime.now() - last_check_dt).days
            
            return days_since_check >= check_frequency
        except:
            return True
    
    def check_async(self):
        thread = threading.Thread(target=self._check_and_callback, daemon=True)
        thread.start()
    
    def _check_and_callback(self):
        self.check_for_updates()
        if self.callback:
            self.callback(self.get_update_status())


class UpdateCheckerWindow:
    
    def __init__(self, parent=None):
        self.parent = parent
        self.checker = UpdateChecker()
        self.window = None
        self.result = None
    
    def show(self):
        try:
            from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                                        QPushButton, QProgressBar, QTextEdit)
            from PyQt6.QtCore import Qt, QTimer
            from PyQt6.QtGui import QFont, QIcon
            
            self.window = QDialog(self.parent)
            self.window.setWindowTitle('🔄 Update Checker')
            self.window.setMinimumWidth(450)
            self.window.setMinimumHeight(250)
            self.window.setModal(True)
            
            layout = QVBoxLayout()
            layout.setContentsMargins(20, 20, 20, 20)
            layout.setSpacing(15)
            
            title = QLabel('🔄 Checking for Updates...')
            title_font = QFont()
            title_font.setPointSize(12)
            title_font.setBold(True)
            title.setFont(title_font)
            layout.addWidget(title)
            
            self.progress = QProgressBar()
            self.progress.setMaximum(0)
            layout.addWidget(self.progress)
            
            self.info_text = QTextEdit()
            self.info_text.setReadOnly(True)
            self.info_text.setText("Connecting to GitHub API...\nPlease wait.")
            layout.addWidget(self.info_text)
            
            button_layout = QHBoxLayout()
            button_layout.addStretch()
            
            self.check_button = QPushButton('✓ Continue')
            self.check_button.clicked.connect(self._on_continue)
            self.check_button.setEnabled(False)
            button_layout.addWidget(self.check_button)
            
            self.skip_button = QPushButton('Skip')
            self.skip_button.clicked.connect(self._on_skip)
            button_layout.addWidget(self.skip_button)
            
            layout.addLayout(button_layout)
            
            self.window.setLayout(layout)
            
            QTimer.singleShot(500, self._perform_check)
            
            self.window.exec()
            
            return self.result
        
        except ImportError:
            print("PyQt6 not available for update checker GUI")
            return None
    
    def _perform_check(self):
        update_available = self.checker.check_for_updates()
        status = self.checker.get_update_status()
        
        self.progress.setMaximum(1)
        self.progress.setValue(1)
        
        if status['error']:
            info_html = f"""
            <h3 style="color: #ff9800;">⚠️ Update Check Failed</h3>
            <p><b>Reason:</b> {status['error']}</p>
            <p>You can continue using the application.</p>
            """
        elif update_available:
            info_html = f"""
            <h3 style="color: #4caf50;">✅ Update Available!</h3>
            <p><b>Current Version:</b> {status['current_version']}</p>
            <p><b>Latest Version:</b> {status['latest_version']}</p>
            <p><b>Release Name:</b> {status['info'].get('name', 'N/A')}</p>
            <p><b>Description:</b></p>
            <p>{status['info'].get('body', 'N/A')[:200]}...</p>
            <p><a href="{status['info'].get('url', '#')}">View on GitHub →</a></p>
            """
        else:
            info_html = f"""
            <h3 style="color: #2196f3;">✓ You're Up to Date</h3>
            <p><b>Current Version:</b> {status['current_version']}</p>
            <p>You are running the latest version of MoD.</p>
            <p>Last checked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            """
        
        self.info_text.setHtml(info_html)
        self.check_button.setEnabled(True)
        self.check_button.setText('✓ Continue' if not update_available else '↓ Download & Continue')
        
        self.result = status
    
    def _on_continue(self):
        if self.checker.update_available and self.checker.update_info.get('url'):
            try:
                import webbrowser
                webbrowser.open(self.checker.update_info['url'])
            except:
                pass
        
        self.window.accept()
    
    def _on_skip(self):
        self.window.reject()


def run_update_checker_sync(parent=None) -> Optional[Dict]:
    checker_window = UpdateCheckerWindow(parent)
    return checker_window.show()


def run_update_checker_async(callback: Callable, timeout: int = 10):
    checker = UpdateChecker(callback)
    checker.check_async()
