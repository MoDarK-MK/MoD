# gui/theme_manager.py
from typing import Dict
import json


class ThemeManager:
    
    def __init__(self):
        self.current_theme = 'dark_github'
        self.themes = {
            'dark_github': self._get_dark_github_theme(),
            'light_github': self._get_light_github_theme(),
            'dark_hacker': self._get_dark_hacker_theme(),
            'light_minimal': self._get_light_minimal_theme(),
            'cyberpunk': self._get_cyberpunk_theme(),
            'nord': self._get_nord_theme(),
            'dracula': self._get_dracula_theme(),
            'monokai': self._get_monokai_theme(),
            'gruvbox': self._get_gruvbox_theme(),
            'solarized_dark': self._get_solarized_dark_theme(),
            'solarized_light': self._get_solarized_light_theme(),
        }
    
    def set_theme(self, theme: str):
        if theme in self.themes:
            self.current_theme = theme
    
    def get_stylesheet(self) -> str:
        return self.themes.get(self.current_theme, self.themes['dark_github'])
    
    def get_available_themes(self) -> list:
        return list(self.themes.keys())
    
    def _get_dark_github_theme(self) -> str:
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #0d1117, stop:1 #010409);
            color: #c9d1d9;
        }

        QWidget {
            background-color: #0d1117;
            color: #c9d1d9;
        }

        QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTextEdit {
            background-color: #161b22;
            color: #c9d1d9;
            border: 2px solid #1f6feb;
            border-radius: 6px;
            padding: 8px;
            font-size: 11pt;
            selection-background-color: #1f6feb;
        }

        QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus, QTextEdit:focus {
            background-color: #0d1117;
            border: 2px solid #58a6ff;
            outline: none;
        }

        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #238636, stop:1 #1a6b2c);
            color: #ffffff;
            border: 1px solid #2d333b;
            border-radius: 6px;
            padding: 12px 24px;
            font-weight: bold;
            font-size: 11pt;
        }

        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #2ea043, stop:1 #238636);
            border: 1px solid #388bfd;
        }

        QPushButton:pressed {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #1a6b2c, stop:1 #0d3817);
        }

        QPushButton:disabled {
            background-color: #21262d;
            color: #6e7681;
            border: 1px solid #30363d;
        }

        QCheckBox, QRadioButton {
            color: #c9d1d9;
            spacing: 8px;
        }

        QCheckBox::indicator:unchecked {
            background-color: #0d1117;
            border: 2px solid #30363d;
            border-radius: 4px;
        }

        QCheckBox::indicator:checked {
            background-color: #1f6feb;
            border: 2px solid #1f6feb;
            border-radius: 4px;
            color: #ffffff;
        }

        QCheckBox::indicator:hover {
            border: 2px solid #58a6ff;
        }

        QGroupBox {
            color: #c9d1d9;
            border: 2px solid #30363d;
            border-radius: 8px;
            margin-top: 12px;
            padding-top: 12px;
            font-weight: bold;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 6px;
            color: #58a6ff;
        }

        QTabWidget::pane {
            border: 2px solid #30363d;
        }

        QTabBar::tab {
            background-color: #161b22;
            color: #8b949e;
            padding: 10px 20px;
            margin: 2px;
            border: 1px solid #30363d;
            border-bottom: 2px solid transparent;
        }

        QTabBar::tab:hover {
            background-color: #21262d;
            color: #c9d1d9;
        }

        QTabBar::tab:selected {
            background-color: #0d1117;
            color: #58a6ff;
            border: 1px solid #30363d;
            border-bottom: 2px solid #1f6feb;
        }

        QProgressBar {
            background-color: #161b22;
            border: 2px solid #30363d;
            border-radius: 6px;
            text-align: center;
            height: 24px;
            color: #c9d1d9;
        }

        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                       stop:0 #238636, stop:1 #2ea043);
            border-radius: 4px;
        }

        QTableWidget {
            background-color: #0d1117;
            alternate-background-color: #161b22;
            gridline-color: #30363d;
            border: 2px solid #30363d;
            border-radius: 4px;
            color: #c9d1d9;
        }

        QTableWidget::item {
            padding: 6px;
        }

        QTableWidget::item:selected {
            background-color: #1f6feb;
            color: #ffffff;
        }

        QHeaderView::section {
            background-color: #161b22;
            color: #c9d1d9;
            padding: 8px;
            border: none;
            border-right: 1px solid #30363d;
            font-weight: bold;
        }

        QMenuBar {
            background-color: #0d1117;
            color: #c9d1d9;
            border-bottom: 2px solid #21262d;
        }

        QMenuBar::item:selected {
            background-color: #161b22;
            color: #58a6ff;
        }

        QMenu {
            background-color: #161b22;
            color: #c9d1d9;
            border: 2px solid #30363d;
            border-radius: 4px;
            padding: 4px;
        }

        QMenu::item:selected {
            background-color: #1f6feb;
            color: #ffffff;
            border-radius: 4px;
        }

        QMenu::separator {
            background-color: #30363d;
            height: 1px;
            margin: 4px 0px;
        }

        QToolBar {
            background-color: #161b22;
            border: none;
            spacing: 8px;
            padding: 8px;
            border-bottom: 1px solid #30363d;
        }

        QToolBar::separator {
            background-color: #30363d;
            width: 2px;
            margin: 0px 4px;
        }

        QStatusBar {
            background-color: #161b22;
            color: #8b949e;
            border-top: 2px solid #30363d;
        }

        QScrollBar:vertical {
            background-color: #0d1117;
            width: 12px;
            border: none;
        }

        QScrollBar::handle:vertical {
            background-color: #30363d;
            border-radius: 6px;
            min-height: 20px;
            margin: 2px;
        }

        QScrollBar::handle:vertical:hover {
            background-color: #484f58;
        }

        QScrollBar:horizontal {
            background-color: #0d1117;
            height: 12px;
            border: none;
        }

        QScrollBar::handle:horizontal {
            background-color: #30363d;
            border-radius: 6px;
            min-width: 20px;
            margin: 2px;
        }

        QLabel {
            color: #c9d1d9;
        }

        QSplitter::handle {
            background-color: #30363d;
            width: 4px;
        }

        QMessageBox {
            background-color: #0d1117;
            color: #c9d1d9;
        }

        QMessageBox QLabel {
            color: #c9d1d9;
        }

        QTextBrowser {
            background-color: #161b22;
            color: #c9d1d9;
            border: 1px solid #30363d;
        }
        """
    
    def _get_light_github_theme(self) -> str:
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #f6f8fa, stop:1 #eaeef2);
            color: #24292f;
        }

        QWidget {
            background-color: #ffffff;
            color: #24292f;
        }

        QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTextEdit {
            background-color: #ffffff;
            color: #24292f;
            border: 2px solid #0969da;
            border-radius: 6px;
            padding: 8px;
            font-size: 11pt;
            selection-background-color: #0969da;
            selection-color: #ffffff;
        }

        QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus, QTextEdit:focus {
            background-color: #ffffff;
            border: 2px solid #0969da;
            outline: none;
        }

        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #1f883d, stop:1 #197c0d);
            color: #ffffff;
            border: 1px solid #dcebe2;
            border-radius: 6px;
            padding: 12px 24px;
            font-weight: bold;
            font-size: 11pt;
        }

        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #2da44e, stop:1 #1f883d);
            border: 1px solid #b3f0b3;
        }

        QTableWidget {
            background-color: #ffffff;
            alternate-background-color: #f6f8fa;
            gridline-color: #d0d7de;
            border: 2px solid #d0d7de;
            border-radius: 4px;
            color: #24292f;
        }

        QTableWidget::item:selected {
            background-color: #0969da;
            color: #ffffff;
        }

        QHeaderView::section {
            background-color: #eaeef2;
            color: #24292f;
            padding: 8px;
            border: none;
            border-right: 1px solid #d0d7de;
            font-weight: bold;
        }

        QMenuBar {
            background-color: #f6f8fa;
            color: #24292f;
            border-bottom: 1px solid #d0d7de;
        }

        QMenu {
            background-color: #ffffff;
            color: #24292f;
            border: 1px solid #d0d7de;
            border-radius: 4px;
        }

        QMenu::item:selected {
            background-color: #0969da;
            color: #ffffff;
        }

        QStatusBar {
            background-color: #f6f8fa;
            color: #57606a;
            border-top: 1px solid #d0d7de;
        }

        QScrollBar:vertical {
            background-color: #f6f8fa;
            width: 12px;
        }

        QScrollBar::handle:vertical {
            background-color: #d0d7de;
            border-radius: 6px;
            min-height: 20px;
        }

        QLabel {
            color: #24292f;
        }

        QGroupBox {
            color: #24292f;
            border: 2px solid #d0d7de;
        }

        QGroupBox::title {
            color: #0969da;
        }

        QCheckBox::indicator:checked {
            background-color: #0969da;
            border: 2px solid #0969da;
        }

        QTextBrowser {
            background-color: #f6f8fa;
            color: #24292f;
            border: 1px solid #d0d7de;
        }
        """
    
    def _get_dark_hacker_theme(self) -> str:
        return """
        QMainWindow {
            background: #0a0e27;
            color: #00ff00;
        }

        QWidget {
            background-color: #0a0e27;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }

        QLineEdit, QSpinBox, QComboBox, QTextEdit {
            background-color: #0d1117;
            color: #00ff00;
            border: 2px solid #00ff00;
            border-radius: 4px;
            padding: 6px;
            font-family: 'Courier New', monospace;
        }

        QLineEdit:focus {
            border: 2px solid #00ff00;
            background-color: #0a0e27;
        }

        QPushButton {
            background: #00ff00;
            color: #000000;
            border: 2px solid #00ff00;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
            font-family: 'Courier New', monospace;
        }

        QPushButton:hover {
            background: #00cc00;
            border: 2px solid #00cc00;
        }

        QPushButton:pressed {
            background: #009900;
            border: 2px solid #009900;
        }

        QPushButton:disabled {
            background: #444444;
            color: #888888;
            border: 2px solid #666666;
        }

        QTableWidget {
            background-color: #0a0e27;
            alternate-background-color: #0d1117;
            gridline-color: #00ff00;
            border: 2px solid #00ff00;
            color: #00ff00;
        }

        QTableWidget::item:selected {
            background-color: #00ff00;
            color: #000000;
        }

        QHeaderView::section {
            background-color: #0d1117;
            color: #00ff00;
            border: 1px solid #00ff00;
            padding: 4px;
            font-weight: bold;
        }

        QProgressBar {
            background-color: #0d1117;
            border: 2px solid #00ff00;
            border-radius: 4px;
            color: #00ff00;
        }

        QProgressBar::chunk {
            background: #00ff00;
            border-radius: 2px;
        }

        QTabBar::tab {
            background-color: #0d1117;
            color: #00ff00;
            border: 2px solid #00ff00;
            padding: 8px 16px;
            margin: 2px;
        }

        QTabBar::tab:selected {
            background-color: #00ff00;
            color: #000000;
        }

        QLabel {
            color: #00ff00;
        }

        QMenuBar {
            background-color: #0a0e27;
            color: #00ff00;
            border: 2px solid #00ff00;
        }

        QMenuBar::item:selected {
            background-color: #00ff00;
            color: #000000;
        }

        QMenu {
            background-color: #0d1117;
            color: #00ff00;
            border: 2px solid #00ff00;
        }

        QMenu::item:selected {
            background-color: #00ff00;
            color: #000000;
        }

        QStatusBar {
            background-color: #0d1117;
            color: #00ff00;
            border: 2px solid #00ff00;
        }

        QScrollBar:vertical {
            background-color: #0a0e27;
            width: 12px;
            border: 2px solid #00ff00;
        }

        QScrollBar::handle:vertical {
            background-color: #00ff00;
            min-height: 20px;
        }
        """
    
    def _get_light_minimal_theme(self) -> str:
        return """
        QMainWindow {
            background: #fafbfc;
            color: #0d1117;
        }

        QWidget {
            background-color: #ffffff;
            color: #0d1117;
        }

        QLineEdit, QSpinBox, QComboBox, QTextEdit {
            background-color: #ffffff;
            color: #0d1117;
            border: 1px solid #e5e7eb;
            border-radius: 4px;
            padding: 6px;
        }

        QLineEdit:focus {
            border: 2px solid #3b82f6;
            background-color: #f9fafb;
        }

        QPushButton {
            background: #3b82f6;
            color: #ffffff;
            border: 1px solid #3b82f6;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }

        QPushButton:hover {
            background: #2563eb;
            border: 1px solid #2563eb;
        }

        QTableWidget {
            background-color: #ffffff;
            alternate-background-color: #f9fafb;
            gridline-color: #e5e7eb;
            border: 1px solid #e5e7eb;
            color: #0d1117;
        }

        QTableWidget::item:selected {
            background-color: #3b82f6;
            color: #ffffff;
        }

        QHeaderView::section {
            background-color: #f3f4f6;
            color: #0d1117;
            border: 1px solid #e5e7eb;
            padding: 6px;
        }

        QLabel {
            color: #0d1117;
        }

        QMenuBar {
            background-color: #fafbfc;
            color: #0d1117;
        }

        QMenu {
            background-color: #ffffff;
            color: #0d1117;
            border: 1px solid #e5e7eb;
        }

        QStatusBar {
            background-color: #f3f4f6;
            color: #0d1117;
            border: 1px solid #e5e7eb;
        }
        """
    
    def _get_cyberpunk_theme(self) -> str:
        return """
        QMainWindow {
            background: #0a0016;
            color: #ff006e;
        }

        QWidget {
            background-color: #0a0016;
            color: #ff006e;
        }

        QLineEdit, QSpinBox, QComboBox, QTextEdit {
            background-color: #1a001a;
            color: #ff006e;
            border: 2px solid #ff006e;
            border-radius: 4px;
            padding: 6px;
        }

        QLineEdit:focus {
            border: 2px solid #00f5ff;
            background-color: #0a0016;
        }

        QPushButton {
            background: #ff006e;
            color: #0a0016;
            border: 2px solid #ff006e;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }

        QPushButton:hover {
            background: #00f5ff;
            border: 2px solid #00f5ff;
        }

        QTableWidget {
            background-color: #0a0016;
            alternate-background-color: #1a001a;
            gridline-color: #ff006e;
            border: 2px solid #ff006e;
            color: #ff006e;
        }

        QTableWidget::item:selected {
            background-color: #ff006e;
            color: #0a0016;
        }

        QProgressBar::chunk {
            background: #ff006e;
        }

        QLabel {
            color: #ff006e;
        }
        """
    
    def _get_nord_theme(self) -> str:
        return """
        QMainWindow {
            background: #2e3440;
            color: #d8dee9;
        }

        QWidget {
            background-color: #2e3440;
            color: #d8dee9;
        }

        QLineEdit, QSpinBox, QComboBox, QTextEdit {
            background-color: #3b4252;
            color: #d8dee9;
            border: 2px solid #88c0d0;
            border-radius: 4px;
            padding: 6px;
        }

        QLineEdit:focus {
            border: 2px solid #81a1c1;
        }

        QPushButton {
            background: #88c0d0;
            color: #2e3440;
            border: 2px solid #88c0d0;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }

        QPushButton:hover {
            background: #81a1c1;
            border: 2px solid #81a1c1;
        }

        QTableWidget {
            background-color: #2e3440;
            alternate-background-color: #3b4252;
            gridline-color: #434c5e;
            border: 2px solid #88c0d0;
            color: #d8dee9;
        }

        QTableWidget::item:selected {
            background-color: #88c0d0;
            color: #2e3440;
        }

        QLabel {
            color: #d8dee9;
        }
        """
    
    def _get_dracula_theme(self) -> str:
        return """
        QMainWindow {
            background: #282a36;
            color: #f8f8f2;
        }

        QWidget {
            background-color: #282a36;
            color: #f8f8f2;
        }

        QLineEdit, QSpinBox, QComboBox, QTextEdit {
            background-color: #44475a;
            color: #f8f8f2;
            border: 2px solid #6272a4;
            border-radius: 4px;
            padding: 6px;
        }

        QLineEdit:focus {
            border: 2px solid #bd93f9;
        }

        QPushButton {
            background: #50fa7b;
            color: #282a36;
            border: 2px solid #50fa7b;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }

        QPushButton:hover {
            background: #bd93f9;
            border: 2px solid #bd93f9;
        }

        QTableWidget {
            background-color: #282a36;
            alternate-background-color: #44475a;
            gridline-color: #6272a4;
            border: 2px solid #bd93f9;
            color: #f8f8f2;
        }

        QTableWidget::item:selected {
            background-color: #bd93f9;
            color: #282a36;
        }

        QLabel {
            color: #f8f8f2;
        }
        """
    
    def _get_monokai_theme(self) -> str:
        return """
        QMainWindow {
            background: #272822;
            color: #f8f8f2;
        }

        QWidget {
            background-color: #272822;
            color: #f8f8f2;
        }

        QLineEdit, QSpinBox, QComboBox, QTextEdit {
            background-color: #3e3d32;
            color: #f8f8f2;
            border: 2px solid #a6e22e;
            border-radius: 4px;
            padding: 6px;
        }

        QLineEdit:focus {
            border: 2px solid #66d9ef;
        }

        QPushButton {
            background: #a6e22e;
            color: #272822;
            border: 2px solid #a6e22e;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }

        QPushButton:hover {
            background: #66d9ef;
            border: 2px solid #66d9ef;
        }

        QTableWidget {
            background-color: #272822;
            alternate-background-color: #3e3d32;
            gridline-color: #75715e;
            border: 2px solid #a6e22e;
            color: #f8f8f2;
        }

        QTableWidget::item:selected {
            background-color: #a6e22e;
            color: #272822;
        }

        QLabel {
            color: #f8f8f2;
        }
        """
    
    def _get_gruvbox_theme(self) -> str:
        return """
        QMainWindow {
            background: #282828;
            color: #ebdbb2;
        }

        QWidget {
            background-color: #282828;
            color: #ebdbb2;
        }

        QLineEdit, QSpinBox, QComboBox, QTextEdit {
            background-color: #3c3836;
            color: #ebdbb2;
            border: 2px solid #b8bb26;
            border-radius: 4px;
            padding: 6px;
        }

        QLineEdit:focus {
            border: 2px solid #83a598;
        }

        QPushButton {
            background: #b8bb26;
            color: #282828;
            border: 2px solid #b8bb26;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }

        QPushButton:hover {
            background: #83a598;
            border: 2px solid #83a598;
        }

        QTableWidget {
            background-color: #282828;
            alternate-background-color: #3c3836;
            gridline-color: #665c54;
            border: 2px solid #b8bb26;
            color: #ebdbb2;
        }

        QTableWidget::item:selected {
            background-color: #b8bb26;
            color: #282828;
        }

        QLabel {
            color: #ebdbb2;
        }
        """
    
    def _get_solarized_dark_theme(self) -> str:
        return """
        QMainWindow {
            background: #002b36;
            color: #93a1a1;
        }

        QWidget {
            background-color: #002b36;
            color: #93a1a1;
        }

        QLineEdit, QSpinBox, QComboBox, QTextEdit {
            background-color: #073642;
            color: #93a1a1;
            border: 2px solid #268bd2;
            border-radius: 4px;
            padding: 6px;
        }

        QLineEdit:focus {
            border: 2px solid #2aa198;
        }

        QPushButton {
            background: #268bd2;
            color: #002b36;
            border: 2px solid #268bd2;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }

        QPushButton:hover {
            background: #2aa198;
            border: 2px solid #2aa198;
        }

        QTableWidget {
            background-color: #002b36;
            alternate-background-color: #073642;
            gridline-color: #586e75;
            border: 2px solid #268bd2;
            color: #93a1a1;
        }

        QTableWidget::item:selected {
            background-color: #268bd2;
            color: #002b36;
        }

        QLabel {
            color: #93a1a1;
        }
        """
    
    def _get_solarized_light_theme(self) -> str:
        return """
        QMainWindow {
            background: #fdf6e3;
            color: #657b83;
        }

        QWidget {
            background-color: #fdf6e3;
            color: #657b83;
        }

        QLineEdit, QSpinBox, QComboBox, QTextEdit {
            background-color: #eee8d5;
            color: #657b83;
            border: 2px solid #268bd2;
            border-radius: 4px;
            padding: 6px;
        }

        QLineEdit:focus {
            border: 2px solid #2aa198;
        }

        QPushButton {
            background: #268bd2;
            color: #fdf6e3;
            border: 2px solid #268bd2;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }

        QPushButton:hover {
            background: #2aa198;
            border: 2px solid #2aa198;
        }

        QTableWidget {
            background-color: #fdf6e3;
            alternate-background-color: #eee8d5;
            gridline-color: #d6d0c8;
            border: 2px solid #268bd2;
            color: #657b83;
        }

        QTableWidget::item:selected {
            background-color: #268bd2;
            color: #fdf6e3;
        }

        QLabel {
            color: #657b83;
        }
        """
