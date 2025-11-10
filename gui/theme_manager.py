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
        QWidget { background-color: #1a1a2e; color: #eaeaea; }
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #e94560, stop:1 #c82f48);
            color: #ffffff; border: none; border-radius: 6px; padding: 12px 24px;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #ff6b81, stop:1 #e94560);
        }
        """
    
    def _get_light_theme(self) -> str:
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #f8f9fa, stop:1 #e9ecef);
        }
        QWidget { background-color: #ffffff; color: #212529; }
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                       stop:0 #0d6efd, stop:1 #0a58ca);
            color: #ffffff; border: none; border-radius: 6px; padding: 12px 24px;
        }
        """