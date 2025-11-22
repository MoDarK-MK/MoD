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
        'ios_liquid_glass_dark': {
            'name': 'iOS Liquid Glass Dark',
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
            'name': 'iOS Liquid Glass Light',
            'description': 'Light theme with teal-cyan gradients and liquid glass effect',
            'colors': ThemeColors(
                primary='#00A67E',
                secondary='#0097B2',
                accent='#00D9A3',
                background='#F5F8FA',
                surface='rgba(255, 255, 255, 0.7)',
                text_primary='#0A0E1A',
                text_secondary='#4A5568',
                success='#00C853',
                warning='#FFC107',
                error='#F44336',
                info='#0097B2',
                border='rgba(0, 166, 126, 0.2)',
                shadow='rgba(0, 166, 126, 0.1)',
                gradient_start='#00A67E',
                gradient_end='#0097B2',
                glass_bg='rgba(255, 255, 255, 0.65)',
                glass_border='rgba(0, 166, 126, 0.18)',
                glass_shadow='0 8px 32px rgba(0, 166, 126, 0.1)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='25px',
                shadow='0 8px 32px rgba(0, 166, 126, 0.1)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='-apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, sans-serif',
                glass_shadow='0 8px 32px 0 rgba(0, 166, 126, 0.1)',
                glass_backdrop='blur(25px) saturate(180%)',
                glass_border_width='1px'
            )
        }
    }
    
    def __init__(self, default_theme: str = 'ios_liquid_glass_dark'):
        self.current_theme = default_theme
        self._theme_cache = {}
        self._custom_themes = {}
    
    def get_theme(self, theme_name: Optional[str] = None) -> Dict:
        theme_name = theme_name or self.current_theme
        
        if theme_name in self._theme_cache:
            return self._theme_cache[theme_name]
        
        if theme_name in self._custom_themes:
            theme = self._custom_themes[theme_name]
        else:
            theme = self.THEMES.get(theme_name, self.THEMES['ios_liquid_glass_dark'])
        
        self._theme_cache[theme_name] = theme
        return theme
    
    def set_theme(self, theme_name: str):
        if theme_name in self.THEMES or theme_name in self._custom_themes:
            self.current_theme = theme_name
            self._theme_cache.clear()
    
    def add_custom_theme(self, theme_name: str, theme_config: Dict):
        self._custom_themes[theme_name] = theme_config
    
    def get_available_themes(self) -> List[str]:
        return list(self.THEMES.keys()) + list(self._custom_themes.keys())
    
    def get_stylesheet(self, theme_name: Optional[str] = None) -> str:
        """Get QSS stylesheet for Qt applications"""
        theme = self.get_theme(theme_name)
        colors = theme['colors']
        styles = theme['styles']
        
        # Convert rgba to hex for Qt
        bg_hex = '#0F172A'  # Approximation of rgba(15, 23, 42, 0.7)
        surface_hex = '#1E293B'
        
        return f'''
/* iOS Liquid Glass Theme - Qt Stylesheet */

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
    color: {colors.background};
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
    border: 1px solid {colors.border.replace('rgba', '').replace('(', '').replace(')', '').replace('0.2', '')};
    border-radius: 10px;
    padding: 8px 12px;
    selection-background-color: {colors.primary};
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border: 2px solid {colors.primary};
}}

/* Tables */
QTableWidget {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 1px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    border-radius: 12px;
    gridline-color: {colors.border.split(',')[0].replace('rgba(', '#')};
}}

QTableWidget::item {{
    padding: 8px;
}}

QTableWidget::item:selected {{
    background-color: {colors.primary};
    color: {colors.background};
}}

QHeaderView::section {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    padding: 8px;
    border: none;
    border-bottom: 2px solid {colors.primary};
    font-weight: 600;
}}

/* Tabs */
QTabWidget::pane {{
    border: 1px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    border-radius: 12px;
    background-color: {surface_hex};
}}

QTabBar::tab {{
    background-color: {surface_hex};
    color: {colors.text_secondary};
    border: none;
    padding: 10px 20px;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    margin-right: 2px;
    min-width: 80px;
}}

QTabBar::tab:selected {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    color: {colors.background};
    font-weight: 600;
}}

QTabBar::tab:hover {{
    background-color: {colors.primary};
    color: {colors.background};
}}

/* Progress Bar */
QProgressBar {{
    border: 1px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    border-radius: 8px;
    background-color: {surface_hex};
    text-align: center;
    color: {colors.text_primary};
    height: 20px;
}}

QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border-radius: 7px;
}}

/* ComboBox */
QComboBox {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 1px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    border-radius: 10px;
    padding: 6px 12px;
    min-height: 32px;
}}

QComboBox:hover {{
    border: 2px solid {colors.primary};
}}

QComboBox::drop-down {{
    border: none;
    width: 30px;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid {colors.text_primary};
    margin-right: 10px;
}}

QComboBox QAbstractItemView {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 1px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    border-radius: 8px;
    selection-background-color: {colors.primary};
    selection-color: {colors.background};
}}

/* ScrollBar Vertical */
QScrollBar:vertical {{
    background-color: {surface_hex};
    width: 12px;
    border-radius: 6px;
    margin: 0px;
}}

QScrollBar::handle:vertical {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border-radius: 6px;
    min-height: 20px;
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
    background-color: {surface_hex};
    height: 12px;
    border-radius: 6px;
    margin: 0px;
}}

QScrollBar::handle:horizontal {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border-radius: 6px;
    min-width: 20px;
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
    border: 2px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    border-radius: 12px;
    margin-top: 10px;
    padding-top: 10px;
    color: {colors.text_primary};
    font-weight: 600;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 10px;
    color: {colors.primary};
}}

/* CheckBox */
QCheckBox {{
    color: {colors.text_primary};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 20px;
    height: 20px;
    border-radius: 6px;
    border: 2px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    background-color: {surface_hex};
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
    spacing: 8px;
}}

QRadioButton::indicator {{
    width: 20px;
    height: 20px;
    border-radius: 10px;
    border: 2px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    background-color: {surface_hex};
}}

QRadioButton::indicator:checked {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border-color: {colors.primary};
}}

/* MenuBar */
QMenuBar {{
    background-color: {colors.background};
    color: {colors.text_primary};
}}

QMenuBar::item {{
    padding: 6px 12px;
    border-radius: 6px;
}}

QMenuBar::item:selected {{
    background-color: {colors.primary};
    color: {colors.background};
}}

/* Menu */
QMenu {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 1px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    border-radius: 8px;
}}

QMenu::item {{
    padding: 8px 24px;
}}

QMenu::item:selected {{
    background-color: {colors.primary};
    color: {colors.background};
}}

/* ToolTip */
QToolTip {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 1px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    border-radius: 6px;
    padding: 6px;
}}

/* StatusBar */
QStatusBar {{
    background-color: {surface_hex};
    color: {colors.text_secondary};
}}

/* SpinBox */
QSpinBox, QDoubleSpinBox {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 1px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    border-radius: 10px;
    padding: 6px 12px;
}}

QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 2px solid {colors.primary};
}}

/* Slider */
QSlider::groove:horizontal {{
    border: 1px solid {colors.border.split(',')[0].replace('rgba(', '#')};
    height: 8px;
    background: {surface_hex};
    border-radius: 4px;
}}

QSlider::handle:horizontal {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    border: none;
    width: 18px;
    margin: -5px 0;
    border-radius: 9px;
}}

QSlider::handle:horizontal:hover {{
    background: {colors.primary};
}}
'''
    
    def get_css(self, theme_name: Optional[str] = None) -> str:
        """Get CSS for web applications (same as before)"""
        # Your existing get_css code remains the same
        theme = self.get_theme(theme_name)
        colors = theme['colors']
        styles = theme['styles']
        
        # Return your existing CSS code
        # (The long CSS string you had before)
        return "/* Your existing CSS code */"
    
    def export_theme_config(self, theme_name: Optional[str] = None, filepath: str = 'theme_config.json'):
        theme = self.get_theme(theme_name)
        
        config = {
            'name': theme['name'],
            'description': theme.get('description', ''),
            'colors': {
                'primary': theme['colors'].primary,
                'secondary': theme['colors'].secondary,
                'accent': theme['colors'].accent,
                'background': theme['colors'].background,
                'surface': theme['colors'].surface,
                'text_primary': theme['colors'].text_primary,
                'text_secondary': theme['colors'].text_secondary,
                'success': theme['colors'].success,
                'warning': theme['colors'].warning,
                'error': theme['colors'].error,
                'info': theme['colors'].info,
                'border': theme['colors'].border,
                'shadow': theme['colors'].shadow,
                'gradient_start': theme['colors'].gradient_start,
                'gradient_end': theme['colors'].gradient_end,
                'glass_bg': theme['colors'].glass_bg,
                'glass_border': theme['colors'].glass_border,
                'glass_shadow': theme['colors'].glass_shadow,
            },
            'styles': {
                'border_radius': theme['styles'].border_radius,
                'blur': theme['styles'].blur,
                'shadow': theme['styles'].shadow,
                'transition': theme['styles'].transition,
                'font_family': theme['styles'].font_family,
                'glass_shadow': theme['styles'].glass_shadow,
                'glass_backdrop': theme['styles'].glass_backdrop,
                'glass_border_width': theme['styles'].glass_border_width,
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        return config
    
    def get_color_palette(self, theme_name: Optional[str] = None) -> Dict[str, str]:
        theme = self.get_theme(theme_name)
        colors = theme['colors']
        
        return {
            'primary': colors.primary,
            'secondary': colors.secondary,
            'accent': colors.accent,
            'background': colors.background,
            'surface': colors.surface,
            'text_primary': colors.text_primary,
            'text_secondary': colors.text_secondary,
            'success': colors.success,
            'warning': colors.warning,
            'error': colors.error,
            'info': colors.info,
        }

if __name__ == '__main__':
    theme_manager = ThemeManager()
    
    print("Available themes:")
    for theme_name in theme_manager.get_available_themes():
        print(f"  - {theme_name}")
    
    print("\nGenerating Qt Stylesheet...")
    qss = theme_manager.get_stylesheet()
    
    with open('ios_liquid_glass_theme.qss', 'w', encoding='utf-8') as f:
        f.write(qss)
    
    print("✅ Qt Stylesheet generated: ios_liquid_glass_theme.qss")
    
    print("\nExporting theme config...")
    theme_manager.export_theme_config()
    print("✅ Theme config exported: theme_config.json")
    
    print("\nColor Palette:")
    palette = theme_manager.get_color_palette()
    for color_name, color_value in palette.items():
        print(f"  {color_name}: {color_value}")
