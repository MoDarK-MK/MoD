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
                                       stop:0 #1a1a2e, stop:1 #16213e);
        }
        
        QWidget {
            background-color: #1a1a2e;
            color: #eaeaea;
        }
        
        QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTextEdit {
            background-color: #0f3460;
            color: #eaeaea;
            border: 2px solid #e94560;
            border-radius: 6px;
            padding: 8px;
            font-size: 11pt;
        }
        
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #e94560, stop:1 #c82f48);
            color: #ffffff;
            border: none;
            border-radius: 6px;
            padding: 12px 24px;
            font-weight: bold;
            font-size: 11pt;
        }
        
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #ff6b81, stop:1 #e94560);
        }
        
        QPushButton:pressed {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #c82f48, stop:1 #b01234);
        }
        
        QCheckBox, QRadioButton {
            color: #eaeaea;
            spacing: 8px;
        }
        
        QCheckBox::indicator:unchecked {
            background-color: #0f3460;
            border: 2px solid #e94560;
            border-radius: 4px;
        }
        
        QCheckBox::indicator:checked {
            background-color: #e94560;
            border: 2px solid #e94560;
            border-radius: 4px;
        }
        
        QGroupBox {
            color: #eaeaea;
            border: 2px solid #e94560;
            border-radius: 8px;
            margin-top: 12px;
            padding-top: 12px;
            font-weight: bold;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 6px;
        }
        
        QTabWidget::pane {
            border: 2px solid #e94560;
        }
        
        QTabBar::tab {
            background-color: #0f3460;
            color: #eaeaea;
            padding: 10px 20px;
            margin: 2px;
        }
        
        QTabBar::tab:selected {
            background-color: #e94560;
            color: #ffffff;
        }
        
        QProgressBar {
            background-color: #0f3460;
            border: 2px solid #e94560;
            border-radius: 6px;
            text-align: center;
            height: 20px;
        }
        
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #e94560, stop:1 #c82f48);
            border-radius: 4px;
        }
        
        QTableWidget {
            background-color: #0f3460;
            alternate-background-color: #16213e;
            gridline-color: #e94560;
            border: 2px solid #e94560;
        }
        
        QHeaderView::section {
            background-color: #e94560;
            color: #ffffff;
            padding: 8px;
            border: none;
            font-weight: bold;
        }
        
        QMenuBar {
            background-color: #1a1a2e;
            color: #eaeaea;
            border-bottom: 2px solid #e94560;
        }
        
        QMenuBar::item:selected {
            background-color: #e94560;
        }
        
        QMenu {
            background-color: #0f3460;
            color: #eaeaea;
            border: 2px solid #e94560;
        }
        
        QMenu::item:selected {
            background-color: #e94560;
        }
        
        QToolBar {
            background-color: #16213e;
            border: none;
            spacing: 8px;
            padding: 8px;
        }
        
        QStatusBar {
            background-color: #0f3460;
            color: #eaeaea;
            border-top: 2px solid #e94560;
        }
        
        QScrollBar:vertical {
            background-color: #0f3460;
            width: 12px;
            border: none;
        }
        
        QScrollBar::handle:vertical {
            background-color: #e94560;
            border-radius: 6px;
            min-height: 20px;
        }
        
        QScrollBar:horizontal {
            background-color: #0f3460;
            height: 12px;
            border: none;
        }
        
        QScrollBar::handle:horizontal {
            background-color: #e94560;
            border-radius: 6px;
            min-width: 20px;
        }
        """
    
    def _get_light_theme(self) -> str:
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #f8f9fa, stop:1 #e9ecef);
        }
        
        QWidget {
            background-color: #ffffff;
            color: #212529;
        }
        
        QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTextEdit {
            background-color: #ffffff;
            color: #212529;
            border: 2px solid #0d6efd;
            border-radius: 6px;
            padding: 8px;
            font-size: 11pt;
        }
        
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #0d6efd, stop:1 #0a58ca);
            color: #ffffff;
            border: none;
            border-radius: 6px;
            padding: 12px 24px;
            font-weight: bold;
            font-size: 11pt;
        }
        
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #0d6efd, stop:1 #0848a0);
        }
        
        QCheckBox, QRadioButton {
            color: #212529;
            spacing: 8px;
        }
        
        QGroupBox {
            color: #212529;
            border: 2px solid #0d6efd;
            border-radius: 8px;
            margin-top: 12px;
            padding-top: 12px;
            font-weight: bold;
        }
        
        QTabBar::tab {
            background-color: #e9ecef;
            color: #212529;
            padding: 10px 20px;
            margin: 2px;
        }
        
        QTabBar::tab:selected {
            background-color: #0d6efd;
            color: #ffffff;
        }
        
        QProgressBar {
            background-color: #e9ecef;
            border: 2px solid #0d6efd;
            border-radius: 6px;
            text-align: center;
            height: 20px;
        }
        
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #0d6efd, stop:1 #0a58ca);
            border-radius: 4px;
        }
        
        QTableWidget {
            background-color: #ffffff;
            gridline-color: #dee2e6;
            border: 2px solid #0d6efd;
        }
        
        QHeaderView::section {
            background-color: #0d6efd;
            color: #ffffff;
            padding: 8px;
            border: none;
            font-weight: bold;
        }
        
        QMenuBar {
            background-color: #f8f9fa;
            color: #212529;
            border-bottom: 2px solid #0d6efd;
        }
        
        QMenuBar::item:selected {
            background-color: #0d6efd;
            color: #ffffff;
        }
        
        QStatusBar {
            background-color: #e9ecef;
            color: #212529;
            border-top: 2px solid #0d6efd;
        }
        """