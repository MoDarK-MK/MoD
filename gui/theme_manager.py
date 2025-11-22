# core/theme_manager.py
from typing import Dict, Optional, List
from dataclasses import dataclass
import json

@dataclass
class ThemeColors:
    primary: str
    secondary: str
    accent: str
    background: str
    surface: str
    text_primary: str
    text_secondary: str
    success: str
    warning: str
    error: str
    info: str
    border: str
    shadow: str
    gradient_start: str
    gradient_end: str
    glass_bg: str
    glass_border: str
    glass_shadow: str

@dataclass
class ThemeStyles:
    border_radius: str
    blur: str
    shadow: str
    transition: str
    font_family: str
    glass_shadow: str
    glass_backdrop: str
    glass_border_width: str

class ThemeManager:
    THEMES = {
        'cyber_green': {
            'name': '🔥 Cyber Green (Matrix)',
            'description': 'Cyber-themed dark green and black - Matrix style',
            'colors': ThemeColors(
                primary='#00FF41',
                secondary='#00D936',
                accent='#39FF14',
                background='#0A0E0A',
                surface='rgba(10, 20, 15, 0.85)',
                text_primary='#00FF41',
                text_secondary='#00D936',
                success='#00FF41',
                warning='#FFD700',
                error='#FF0040',
                info='#00D9FF',
                border='rgba(0, 255, 65, 0.3)',
                shadow='rgba(0, 255, 65, 0.2)',
                gradient_start='#00FF41',
                gradient_end='#00D936',
                glass_bg='rgba(10, 20, 15, 0.7)',
                glass_border='rgba(0, 255, 65, 0.25)',
                glass_shadow='0 8px 32px rgba(0, 255, 65, 0.2)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='25px',
                shadow='0 8px 32px rgba(0, 255, 65, 0.2)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Fira Code", "Courier New", monospace',
                glass_shadow='0 8px 32px 0 rgba(0, 255, 65, 0.2)',
                glass_backdrop='blur(25px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'ios_liquid_glass_dark': {
            'name': 'iOS Dark (Liquid Glass)',
            'description': 'Dark theme with teal-cyan gradients and liquid glass effect',
            'colors': ThemeColors(
                primary='#00D9A3',
                secondary='#00B8D4',
                accent='#00FFC6',
                background='#0A0E1A',
                surface='rgba(15, 23, 42, 0.7)',
                text_primary='#E0F2F1',
                text_secondary='#80CBC4',
                success='#00E676',
                warning='#FFD600',
                error='#FF5252',
                info='#00B8D4',
                border='rgba(0, 217, 163, 0.2)',
                shadow='rgba(0, 217, 163, 0.15)',
                gradient_start='#00D9A3',
                gradient_end='#00B8D4',
                glass_bg='rgba(10, 14, 26, 0.65)',
                glass_border='rgba(0, 217, 163, 0.18)',
                glass_shadow='0 8px 32px rgba(0, 217, 163, 0.15)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='25px',
                shadow='0 8px 32px rgba(0, 217, 163, 0.15)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='-apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, sans-serif',
                glass_shadow='0 8px 32px 0 rgba(0, 217, 163, 0.15)',
                glass_backdrop='blur(25px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'ios_liquid_glass_light': {
            'name': 'iOS Light (Liquid Glass)',
            'description': 'Light theme with teal-cyan gradients and liquid glass effect',
            'colors': ThemeColors(
                primary='#00A67E',
                secondary='#0097B2',
                accent='#00D9A3',
                background='#F5F8FA',
                surface='rgba(255, 255, 255, 0.85)',
                text_primary='#1A202C',
                text_secondary='#4A5568',
                success='#00C853',
                warning='#F59E0B',
                error='#EF4444',
                info='#0097B2',
                border='rgba(0, 166, 126, 0.25)',
                shadow='rgba(0, 166, 126, 0.12)',
                gradient_start='#00A67E',
                gradient_end='#0097B2',
                glass_bg='rgba(255, 255, 255, 0.75)',
                glass_border='rgba(0, 166, 126, 0.2)',
                glass_shadow='0 8px 32px rgba(0, 166, 126, 0.12)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='25px',
                shadow='0 8px 32px rgba(0, 166, 126, 0.12)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='-apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, sans-serif',
                glass_shadow='0 8px 32px 0 rgba(0, 166, 126, 0.12)',
                glass_backdrop='blur(25px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'modern_light': {
            'name': 'Modern Light',
            'description': 'Clean and bright modern light theme',
            'colors': ThemeColors(
                primary='#0EA5E9',
                secondary='#06B6D4',
                accent='#22D3EE',
                background='#FFFFFF',
                surface='rgba(248, 250, 252, 0.95)',
                text_primary='#0F172A',
                text_secondary='#64748B',
                success='#10B981',
                warning='#F59E0B',
                error='#EF4444',
                info='#3B82F6',
                border='rgba(226, 232, 240, 0.8)',
                shadow='rgba(0, 0, 0, 0.08)',
                gradient_start='#0EA5E9',
                gradient_end='#06B6D4',
                glass_bg='rgba(255, 255, 255, 0.85)',
                glass_border='rgba(226, 232, 240, 0.6)',
                glass_shadow='0 4px 24px rgba(0, 0, 0, 0.06)'
            ),
            'styles': ThemeStyles(
                border_radius='16px',
                blur='20px',
                shadow='0 4px 24px rgba(0, 0, 0, 0.06)',
                transition='all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif',
                glass_shadow='0 4px 24px rgba(0, 0, 0, 0.06)',
                glass_backdrop='blur(20px) saturate(150%)',
                glass_border_width='1px'
            )
        }
    }
    
    def __init__(self, default_theme: str = 'cyber_green'):
        self.current_theme = default_theme
        self._theme_cache = {}
        self._custom_themes = {}
    
    def get_theme(self, theme_name: Optional[str] = None) -> Dict:
        """Get theme configuration"""
        theme_name = theme_name or self.current_theme
        
        if theme_name in self._theme_cache:
            return self._theme_cache[theme_name]
        
        if theme_name in self._custom_themes:
            theme = self._custom_themes[theme_name]
        else:
            theme = self.THEMES.get(theme_name, self.THEMES['cyber_green'])
        
        self._theme_cache[theme_name] = theme
        return theme
    
    def set_theme(self, theme_name: str):
        """Set current theme"""
        if theme_name in self.THEMES or theme_name in self._custom_themes:
            self.current_theme = theme_name
            self._theme_cache.clear()
    
    def add_custom_theme(self, theme_name: str, theme_config: Dict):
        """Add custom theme"""
        self._custom_themes[theme_name] = theme_config
    
    def get_available_themes(self) -> List[str]:
        """Get list of available theme keys"""
        return list(self.THEMES.keys()) + list(self._custom_themes.keys())
    
    def get_theme_display_names(self) -> Dict[str, str]:
        """Get human-readable theme names for UI"""
        display_names = {}
        for key, theme in self.THEMES.items():
            display_names[key] = theme['name']
        for key, theme in self._custom_themes.items():
            display_names[key] = theme.get('name', key)
        return display_names
    
    def get_stylesheet(self, theme_name: Optional[str] = None) -> str:
        """Get QSS stylesheet for Qt applications"""
        if theme_name is None:
            theme_name = self.current_theme
        
        theme = self.get_theme(theme_name)
        colors = theme['colors']
        styles = theme['styles']
        
        # Convert rgba to appropriate colors based on theme type
        if 'dark' in theme_name.lower() or 'cyber' in theme_name.lower():
            bg_surface = '#0A1410' if 'cyber' in theme_name.lower() else '#1E293B'
            surface_hex = '#0F1E18' if 'cyber' in theme_name.lower() else '#2D3748'
        else:
            bg_surface = '#F8FAFC'
            surface_hex = '#FFFFFF'
        
        return f'''
/* {theme['name']} - Qt Stylesheet */

QWidget {{
    background-color: {colors.background};
    color: {colors.text_primary};
    font-family: {styles.font_family};
    font-size: 14px;
}}

QMainWindow {{
    background-color: {colors.background};
}}

/* Buttons */
QPushButton {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    color: {'#000000' if 'cyber' in theme_name.lower() else '#FFFFFF'};
    border: none;
    border-radius: 12px;
    padding: 10px 24px;
    font-weight: 600;
    font-size: 14px;
    min-height: 36px;
}}

QPushButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                               stop:0 {colors.gradient_end},
                               stop:1 {colors.gradient_start});
    box-shadow: 0 0 20px {colors.primary};
}}

QPushButton:pressed {{
    padding-top: 12px;
    padding-bottom: 8px;
}}

QPushButton:disabled {{
    background: {surface_hex};
    color: {colors.text_secondary};
}}

/* Inputs */
QLineEdit, QTextEdit, QPlainTextEdit {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 2px solid {colors.border.split(',')[0].replace('rgba(', '').replace(')', '').split()[0]};
    border-radius: 10px;
    padding: 10px 14px;
    selection-background-color: {colors.primary};
    selection-color: {'#000000' if 'cyber' in theme_name.lower() else '#FFFFFF'};
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border: 2px solid {colors.primary};
    background-color: {colors.background};
    box-shadow: 0 0 15px {colors.primary};
}}

/* Tables */
QTableWidget {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 2px solid {bg_surface};
    border-radius: 12px;
    gridline-color: {bg_surface};
}}

QTableWidget::item {{
    padding: 10px;
    border-bottom: 1px solid {bg_surface};
}}

QTableWidget::item:selected {{
    background-color: {colors.primary};
    color: {'#000000' if 'cyber' in theme_name.lower() else '#FFFFFF'};
}}

QTableWidget::item:hover {{
    background-color: {colors.accent};
}}

QHeaderView::section {{
    background-color: {bg_surface};
    color: {colors.text_primary};
    padding: 12px;
    border: none;
    border-bottom: 2px solid {colors.primary};
    font-weight: 700;
    font-size: 13px;
}}

/* Tabs */
QTabWidget::pane {{
    border: 2px solid {bg_surface};
    border-radius: 12px;
    background-color: {surface_hex};
    padding: 8px;
}}

QTabBar::tab {{
    background-color: {bg_surface};
    color: {colors.text_secondary};
    border: none;
    padding: 12px 24px;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    margin-right: 4px;
    min-width: 100px;
    font-weight: 500;
}}

QTabBar::tab:selected {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    color: {'#000000' if 'cyber' in theme_name.lower() else '#FFFFFF'};
    font-weight: 700;
}}

QTabBar::tab:hover:!selected {{
    background-color: {colors.primary};
    color: {'#000000' if 'cyber' in theme_name.lower() else '#FFFFFF'};
}}

/* Progress Bar */
QProgressBar {{
    border: 2px solid {bg_surface};
    border-radius: 10px;
    background-color: {bg_surface};
    text-align: center;
    color: {colors.text_primary};
    height: 24px;
    font-weight: 600;
}}

QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border-radius: 8px;
}}

/* ComboBox */
QComboBox {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 2px solid {bg_surface};
    border-radius: 10px;
    padding: 8px 14px;
    min-height: 36px;
}}

QComboBox:hover {{
    border: 2px solid {colors.primary};
    box-shadow: 0 0 10px {colors.primary};
}}

QComboBox:focus {{
    border: 2px solid {colors.primary};
}}

QComboBox::drop-down {{
    border: none;
    width: 32px;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 6px solid transparent;
    border-right: 6px solid transparent;
    border-top: 6px solid {colors.text_primary};
    margin-right: 12px;
}}

QComboBox QAbstractItemView {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 2px solid {colors.primary};
    border-radius: 10px;
    selection-background-color: {colors.primary};
    selection-color: {'#000000' if 'cyber' in theme_name.lower() else '#FFFFFF'};
    padding: 4px;
}}

/* ScrollBar Vertical */
QScrollBar:vertical {{
    background-color: {bg_surface};
    width: 14px;
    border-radius: 7px;
    margin: 0px;
}}

QScrollBar::handle:vertical {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border-radius: 7px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background: {colors.primary};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: none;
}}

/* ScrollBar Horizontal */
QScrollBar:horizontal {{
    background-color: {bg_surface};
    height: 14px;
    border-radius: 7px;
    margin: 0px;
}}

QScrollBar::handle:horizontal {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border-radius: 7px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {colors.primary};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: none;
}}

/* Label */
QLabel {{
    color: {colors.text_primary};
    background-color: transparent;
}}

/* GroupBox */
QGroupBox {{
    border: 2px solid {bg_surface};
    border-radius: 14px;
    margin-top: 12px;
    padding-top: 12px;
    color: {colors.text_primary};
    font-weight: 700;
    font-size: 15px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 12px;
    color: {colors.primary};
}}

/* CheckBox */
QCheckBox {{
    color: {colors.text_primary};
    spacing: 10px;
    font-size: 14px;
}}

QCheckBox::indicator {{
    width: 22px;
    height: 22px;
    border-radius: 6px;
    border: 2px solid {bg_surface};
    background-color: {surface_hex};
}}

QCheckBox::indicator:hover {{
    border-color: {colors.primary};
    box-shadow: 0 0 8px {colors.primary};
}}

QCheckBox::indicator:checked {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border-color: {colors.primary};
}}

/* RadioButton */
QRadioButton {{
    color: {colors.text_primary};
    spacing: 10px;
    font-size: 14px;
}}

QRadioButton::indicator {{
    width: 22px;
    height: 22px;
    border-radius: 11px;
    border: 2px solid {bg_surface};
    background-color: {surface_hex};
}}

QRadioButton::indicator:hover {{
    border-color: {colors.primary};
    box-shadow: 0 0 8px {colors.primary};
}}

QRadioButton::indicator:checked {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border-color: {colors.primary};
}}

/* StatusBar */
QStatusBar {{
    background-color: {bg_surface};
    color: {colors.text_secondary};
    padding: 4px;
    border-top: 1px solid {colors.primary};
}}

/* SpinBox */
QSpinBox, QDoubleSpinBox {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 2px solid {bg_surface};
    border-radius: 10px;
    padding: 8px 14px;
    min-height: 36px;
}}

QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 2px solid {colors.primary};
    box-shadow: 0 0 10px {colors.primary};
}}

/* Frame */
QFrame {{
    border: 2px solid {bg_surface};
    border-radius: 12px;
    background-color: {surface_hex};
}}
'''
    
    def export_theme_config(self, theme_name: Optional[str] = None, filepath: str = 'theme_config.json'):
        """Export theme configuration to JSON file"""
        if theme_name is None:
            theme_name = self.current_theme
            
        theme = self.get_theme(theme_name)
        
        config = {
            'name': theme['name'],
            'description': theme.get('description', ''),
            'colors': {
                'primary': theme['colors'].primary,
                'secondary': theme['colors'].secondary,
                'accent': theme['colors'].accent,
                'background': theme['colors'].background,
                'text_primary': theme['colors'].text_primary,
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        return config
    
    def get_color_palette(self, theme_name: Optional[str] = None) -> Dict[str, str]:
        """Get color palette of theme"""
        if theme_name is None:
            theme_name = self.current_theme
            
        theme = self.get_theme(theme_name)
        colors = theme['colors']
        
        return {
            'primary': colors.primary,
            'secondary': colors.secondary,
            'accent': colors.accent,
            'background': colors.background,
            'text_primary': colors.text_primary,
        }


if __name__ == '__main__':
    theme_manager = ThemeManager()
    print(f"✅ Default theme: {theme_manager.current_theme}")
    print(f"🎨 Available themes: {list(theme_manager.get_theme_display_names().values())}")
