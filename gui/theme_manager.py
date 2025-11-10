# gui/theme_manager.py
from typing import Dict


class ThemeManager:
    def __init__(self):
        self.current_theme = 'dark'
        self.themes = {
            'dark': self._get_dark_theme(),
            'light': self._get_light_theme()
        }

    def set_theme(self, theme: str):
        if theme in self.themes:
            self.current_theme = theme

    def get_stylesheet(self) -> str:
        return self.themes.get(self.current_theme, self.themes['dark'])

    def _get_dark_theme(self) -> str:
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

        QRadioButton::indicator {
            width: 16px;
            height: 16px;
        }

        QRadioButton::indicator:unchecked {
            background-color: #0d1117;
            border: 2px solid #30363d;
            border-radius: 8px;
        }

        QRadioButton::indicator:checked {
            background-color: #1f6feb;
            border: 2px solid #1f6feb;
            border-radius: 8px;
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

        QMenu::item:disabled {
            color: #6e7681;
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
            margin: 0px;
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

        QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
            border: none;
            background: none;
        }

        QScrollBar::sub-line:vertical, QScrollBar::add-line:vertical {
            border: none;
            background: none;
        }

        QScrollBar:horizontal {
            background-color: #0d1117;
            height: 12px;
            border: none;
            margin: 0px;
        }

        QScrollBar::handle:horizontal {
            background-color: #30363d;
            border-radius: 6px;
            min-width: 20px;
            margin: 2px;
        }

        QScrollBar::handle:horizontal:hover {
            background-color: #484f58;
        }

        QScrollBar::left-arrow:horizontal, QScrollBar::right-arrow:horizontal {
            border: none;
            background: none;
        }

        QScrollBar::sub-line:horizontal, QScrollBar::add-line:horizontal {
            border: none;
            background: none;
        }

        QLabel {
            color: #c9d1d9;
        }

        QComboBox::drop-down {
            border: none;
            width: 24px;
            background-color: transparent;
        }

        QComboBox::down-arrow {
            image: none;
            width: 8px;
            height: 8px;
        }

        QSplitter::handle {
            background-color: #30363d;
            width: 4px;
        }

        QSplitter::handle:hover {
            background-color: #484f58;
        }

        QFileDialog {
            background-color: #0d1117;
            color: #c9d1d9;
        }

        QMessageBox {
            background-color: #0d1117;
            color: #c9d1d9;
        }

        QMessageBox QLabel {
            color: #c9d1d9;
        }

        QMessageBox QPushButton {
            min-width: 60px;
        }

        QTextBrowser {
            background-color: #161b22;
            color: #c9d1d9;
            border: 1px solid #30363d;
        }

        QTextEdit {
            background-color: #161b22;
            color: #c9d1d9;
            border: 2px solid #1f6feb;
            border-radius: 6px;
        }
        """

    def _get_light_theme(self) -> str:
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

        QPushButton:pressed {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #197c0d, stop:1 #0d3a06);
        }

        QPushButton:disabled {
            background-color: #eaeef2;
            color: #8b949e;
            border: 1px solid #d0d7de;
        }

        QCheckBox, QRadioButton {
            color: #24292f;
            spacing: 8px;
        }

        QCheckBox::indicator:unchecked {
            background-color: #ffffff;
            border: 2px solid #d0d7de;
            border-radius: 4px;
        }

        QCheckBox::indicator:checked {
            background-color: #0969da;
            border: 2px solid #0969da;
            border-radius: 4px;
            color: #ffffff;
        }

        QCheckBox::indicator:hover {
            border: 2px solid #0969da;
        }

        QRadioButton::indicator:unchecked {
            background-color: #ffffff;
            border: 2px solid #d0d7de;
            border-radius: 8px;
        }

        QRadioButton::indicator:checked {
            background-color: #0969da;
            border: 2px solid #0969da;
            border-radius: 8px;
        }

        QGroupBox {
            color: #24292f;
            border: 2px solid #d0d7de;
            border-radius: 8px;
            margin-top: 12px;
            padding-top: 12px;
            font-weight: bold;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 6px;
            color: #0969da;
        }

        QTabWidget::pane {
            border: 2px solid #d0d7de;
        }

        QTabBar::tab {
            background-color: #eaeef2;
            color: #57606a;
            padding: 10px 20px;
            margin: 2px;
            border: 1px solid #d0d7de;
            border-bottom: 2px solid transparent;
        }

        QTabBar::tab:hover {
            background-color: #f6f8fa;
            color: #24292f;
        }

        QTabBar::tab:selected {
            background-color: #ffffff;
            color: #0969da;
            border: 1px solid #d0d7de;
            border-bottom: 2px solid #0969da;
            font-weight: bold;
        }

        QProgressBar {
            background-color: #eaeef2;
            border: 2px solid #d0d7de;
            border-radius: 6px;
            text-align: center;
            height: 24px;
            color: #24292f;
        }

        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                       stop:0 #1f883d, stop:1 #2da44e);
            border-radius: 4px;
        }

        QTableWidget {
            background-color: #ffffff;
            alternate-background-color: #f6f8fa;
            gridline-color: #d0d7de;
            border: 2px solid #d0d7de;
            border-radius: 4px;
            color: #24292f;
        }

        QTableWidget::item {
            padding: 6px;
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

        QMenuBar::item:selected {
            background-color: #eaeef2;
            color: #0969da;
        }

        QMenu {
            background-color: #ffffff;
            color: #24292f;
            border: 1px solid #d0d7de;
            border-radius: 4px;
            padding: 4px;
        }

        QMenu::item:selected {
            background-color: #0969da;
            color: #ffffff;
            border-radius: 4px;
        }

        QMenu::item:disabled {
            color: #8b949e;
        }

        QMenu::separator {
            background-color: #d0d7de;
            height: 1px;
            margin: 4px 0px;
        }

        QToolBar {
            background-color: #f6f8fa;
            border: none;
            spacing: 8px;
            padding: 8px;
            border-bottom: 1px solid #d0d7de;
        }

        QToolBar::separator {
            background-color: #d0d7de;
            width: 2px;
            margin: 0px 4px;
        }

        QStatusBar {
            background-color: #f6f8fa;
            color: #57606a;
            border-top: 1px solid #d0d7de;
        }

        QScrollBar:vertical {
            background-color: #f6f8fa;
            width: 12px;
            border: none;
            margin: 0px;
        }

        QScrollBar::handle:vertical {
            background-color: #d0d7de;
            border-radius: 6px;
            min-height: 20px;
            margin: 2px;
        }

        QScrollBar::handle:vertical:hover {
            background-color: #b5bcc4;
        }

        QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
            border: none;
            background: none;
        }

        QScrollBar::sub-line:vertical, QScrollBar::add-line:vertical {
            border: none;
            background: none;
        }

        QScrollBar:horizontal {
            background-color: #f6f8fa;
            height: 12px;
            border: none;
            margin: 0px;
        }

        QScrollBar::handle:horizontal {
            background-color: #d0d7de;
            border-radius: 6px;
            min-width: 20px;
            margin: 2px;
        }

        QScrollBar::handle:horizontal:hover {
            background-color: #b5bcc4;
        }

        QScrollBar::left-arrow:horizontal, QScrollBar::right-arrow:horizontal {
            border: none;
            background: none;
        }

        QScrollBar::sub-line:horizontal, QScrollBar::add-line:horizontal {
            border: none;
            background: none;
        }

        QLabel {
            color: #24292f;
        }

        QComboBox::drop-down {
            border: none;
            width: 24px;
            background-color: transparent;
        }

        QComboBox::down-arrow {
            image: none;
            width: 8px;
            height: 8px;
        }

        QSplitter::handle {
            background-color: #d0d7de;
            width: 4px;
        }

        QSplitter::handle:hover {
            background-color: #b5bcc4;
        }

        QFileDialog {
            background-color: #ffffff;
            color: #24292f;
        }

        QMessageBox {
            background-color: #ffffff;
            color: #24292f;
        }

        QMessageBox QLabel {
            color: #24292f;
        }

        QMessageBox QPushButton {
            min-width: 60px;
        }

        QTextBrowser {
            background-color: #f6f8fa;
            color: #24292f;
            border: 1px solid #d0d7de;
        }

        QTextEdit {
            background-color: #ffffff;
            color: #24292f;
            border: 2px solid #0969da;
            border-radius: 6px;
        }
        """
