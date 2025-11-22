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
        'neon_purple': {
            'name': '💜 Neon Purple (Cyberpunk)',
            'description': 'Vibrant purple neon with dark background',
            'colors': ThemeColors(
                primary='#BB86FC',
                secondary='#9D6FDB',
                accent='#CF6BDD',
                background='#0D0416',
                surface='rgba(25, 10, 40, 0.85)',
                text_primary='#E1BEE7',
                text_secondary='#BB86FC',
                success='#03DAC6',
                warning='#FFB300',
                error='#CF6679',
                info='#BB86FC',
                border='rgba(187, 134, 252, 0.3)',
                shadow='rgba(187, 134, 252, 0.25)',
                gradient_start='#BB86FC',
                gradient_end='#9D6FDB',
                glass_bg='rgba(25, 10, 40, 0.7)',
                glass_border='rgba(187, 134, 252, 0.25)',
                glass_shadow='0 8px 32px rgba(187, 134, 252, 0.25)'
            ),
            'styles': ThemeStyles(
                border_radius='18px',
                blur='22px',
                shadow='0 8px 32px rgba(187, 134, 252, 0.25)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"JetBrains Mono", "Consolas", monospace',
                glass_shadow='0 8px 32px 0 rgba(187, 134, 252, 0.25)',
                glass_backdrop='blur(22px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'electric_blue': {
            'name': '⚡ Electric Blue (Tron)',
            'description': 'Bright electric blue with dark contrast',
            'colors': ThemeColors(
                primary='#00D9FF',
                secondary='#00A8CC',
                accent='#40E0D0',
                background='#000C14',
                surface='rgba(0, 20, 35, 0.85)',
                text_primary='#B3E5FC',
                text_secondary='#80DEEA',
                success='#00E676',
                warning='#FFD740',
                error='#FF5252',
                info='#00D9FF',
                border='rgba(0, 217, 255, 0.3)',
                shadow='rgba(0, 217, 255, 0.25)',
                gradient_start='#00D9FF',
                gradient_end='#00A8CC',
                glass_bg='rgba(0, 20, 35, 0.7)',
                glass_border='rgba(0, 217, 255, 0.25)',
                glass_shadow='0 8px 32px rgba(0, 217, 255, 0.25)'
            ),
            'styles': ThemeStyles(
                border_radius='16px',
                blur='24px',
                shadow='0 8px 32px rgba(0, 217, 255, 0.25)',
                transition='all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Roboto Mono", monospace',
                glass_shadow='0 8px 32px 0 rgba(0, 217, 255, 0.25)',
                glass_backdrop='blur(24px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'blood_red': {
            'name': '🩸 Blood Red (Vampire)',
            'description': 'Deep red theme with dark gothic aesthetic',
            'colors': ThemeColors(
                primary='#FF1744',
                secondary='#D50000',
                accent='#FF4569',
                background='#0F0505',
                surface='rgba(30, 8, 8, 0.85)',
                text_primary='#FFCDD2',
                text_secondary='#EF9A9A',
                success='#66BB6A',
                warning='#FFA726',
                error='#FF1744',
                info='#42A5F5',
                border='rgba(255, 23, 68, 0.3)',
                shadow='rgba(255, 23, 68, 0.3)',
                gradient_start='#FF1744',
                gradient_end='#D50000',
                glass_bg='rgba(30, 8, 8, 0.7)',
                glass_border='rgba(255, 23, 68, 0.25)',
                glass_shadow='0 8px 32px rgba(255, 23, 68, 0.3)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='26px',
                shadow='0 8px 32px rgba(255, 23, 68, 0.3)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Cinzel", serif',
                glass_shadow='0 8px 32px 0 rgba(255, 23, 68, 0.3)',
                glass_backdrop='blur(26px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'golden_luxury': {
            'name': '✨ Golden Luxury (Royal)',
            'description': 'Luxurious gold and black premium theme',
            'colors': ThemeColors(
                primary='#FFD700',
                secondary='#FFA500',
                accent='#FFEB3B',
                background='#0A0A08',
                surface='rgba(20, 18, 10, 0.85)',
                text_primary='#FFF9C4',
                text_secondary='#FFE082',
                success='#76FF03',
                warning='#FFD700',
                error='#FF3D00',
                info='#FFA500',
                border='rgba(255, 215, 0, 0.3)',
                shadow='rgba(255, 215, 0, 0.25)',
                gradient_start='#FFD700',
                gradient_end='#FFA500',
                glass_bg='rgba(20, 18, 10, 0.7)',
                glass_border='rgba(255, 215, 0, 0.25)',
                glass_shadow='0 8px 32px rgba(255, 215, 0, 0.25)'
            ),
            'styles': ThemeStyles(
                border_radius='22px',
                blur='28px',
                shadow='0 8px 32px rgba(255, 215, 0, 0.25)',
                transition='all 0.45s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Playfair Display", serif',
                glass_shadow='0 8px 32px 0 rgba(255, 215, 0, 0.25)',
                glass_backdrop='blur(28px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'ocean_deep': {
            'name': '🌊 Ocean Deep (Aquatic)',
            'description': 'Deep ocean blue with teal accents',
            'colors': ThemeColors(
                primary='#00BCD4',
                secondary='#0097A7',
                accent='#00E5FF',
                background='#001520',
                surface='rgba(0, 30, 45, 0.85)',
                text_primary='#B2EBF2',
                text_secondary='#80DEEA',
                success='#00E676',
                warning='#FFB300',
                error='#FF5252',
                info='#00BCD4',
                border='rgba(0, 188, 212, 0.3)',
                shadow='rgba(0, 188, 212, 0.2)',
                gradient_start='#00BCD4',
                gradient_end='#0097A7',
                glass_bg='rgba(0, 30, 45, 0.7)',
                glass_border='rgba(0, 188, 212, 0.25)',
                glass_shadow='0 8px 32px rgba(0, 188, 212, 0.2)'
            ),
            'styles': ThemeStyles(
                border_radius='18px',
                blur='24px',
                shadow='0 8px 32px rgba(0, 188, 212, 0.2)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Lato", sans-serif',
                glass_shadow='0 8px 32px 0 rgba(0, 188, 212, 0.2)',
                glass_backdrop='blur(24px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'sunset_orange': {
            'name': '🌅 Sunset Orange (Fire)',
            'description': 'Warm sunset colors with orange and pink',
            'colors': ThemeColors(
                primary='#FF5722',
                secondary='#E64A19',
                accent='#FF7043',
                background='#140A05',
                surface='rgba(30, 15, 8, 0.85)',
                text_primary='#FFCCBC',
                text_secondary='#FF8A65',
                success='#8BC34A',
                warning='#FFC107',
                error='#F44336',
                info='#FF9800',
                border='rgba(255, 87, 34, 0.3)',
                shadow='rgba(255, 87, 34, 0.25)',
                gradient_start='#FF5722',
                gradient_end='#E64A19',
                glass_bg='rgba(30, 15, 8, 0.7)',
                glass_border='rgba(255, 87, 34, 0.25)',
                glass_shadow='0 8px 32px rgba(255, 87, 34, 0.25)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='25px',
                shadow='0 8px 32px rgba(255, 87, 34, 0.25)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Nunito", sans-serif',
                glass_shadow='0 8px 32px 0 rgba(255, 87, 34, 0.25)',
                glass_backdrop='blur(25px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'midnight_indigo': {
            'name': '🌙 Midnight Indigo (Night)',
            'description': 'Deep indigo midnight theme',
            'colors': ThemeColors(
                primary='#5C6BC0',
                secondary='#3F51B5',
                accent='#7986CB',
                background='#0A0C1A',
                surface='rgba(15, 18, 35, 0.85)',
                text_primary='#C5CAE9',
                text_secondary='#9FA8DA',
                success='#66BB6A',
                warning='#FFA726',
                error='#EF5350',
                info='#5C6BC0',
                border='rgba(92, 107, 192, 0.3)',
                shadow='rgba(92, 107, 192, 0.2)',
                gradient_start='#5C6BC0',
                gradient_end='#3F51B5',
                glass_bg='rgba(15, 18, 35, 0.7)',
                glass_border='rgba(92, 107, 192, 0.25)',
                glass_shadow='0 8px 32px rgba(92, 107, 192, 0.2)'
            ),
            'styles': ThemeStyles(
                border_radius='18px',
                blur='24px',
                shadow='0 8px 32px rgba(92, 107, 192, 0.2)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Poppins", sans-serif',
                glass_shadow='0 8px 32px 0 rgba(92, 107, 192, 0.2)',
                glass_backdrop='blur(24px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'toxic_green': {
            'name': '☢️ Toxic Green (Radioactive)',
            'description': 'Toxic radioactive green theme',
            'colors': ThemeColors(
                primary='#76FF03',
                secondary='#64DD17',
                accent='#B2FF59',
                background='#050F02',
                surface='rgba(10, 20, 5, 0.85)',
                text_primary='#CCFF90',
                text_secondary='#B2FF59',
                success='#76FF03',
                warning='#FFD600',
                error='#FF1744',
                info='#00E676',
                border='rgba(118, 255, 3, 0.3)',
                shadow='rgba(118, 255, 3, 0.3)',
                gradient_start='#76FF03',
                gradient_end='#64DD17',
                glass_bg='rgba(10, 20, 5, 0.7)',
                glass_border='rgba(118, 255, 3, 0.25)',
                glass_shadow='0 8px 32px rgba(118, 255, 3, 0.3)'
            ),
            'styles': ThemeStyles(
                border_radius='16px',
                blur='22px',
                shadow='0 8px 32px rgba(118, 255, 3, 0.3)',
                transition='all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Share Tech Mono", monospace',
                glass_shadow='0 8px 32px 0 rgba(118, 255, 3, 0.3)',
                glass_backdrop='blur(22px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'pink_candy': {
            'name': '🍭 Pink Candy (Sweet)',
            'description': 'Sweet pink and purple candy theme',
            'colors': ThemeColors(
                primary='#FF4081',
                secondary='#F50057',
                accent='#FF80AB',
                background='#140008',
                surface='rgba(30, 5, 15, 0.85)',
                text_primary='#F8BBD0',
                text_secondary='#F48FB1',
                success='#69F0AE',
                warning='#FFD740',
                error='#FF1744',
                info='#40C4FF',
                border='rgba(255, 64, 129, 0.3)',
                shadow='rgba(255, 64, 129, 0.25)',
                gradient_start='#FF4081',
                gradient_end='#F50057',
                glass_bg='rgba(30, 5, 15, 0.7)',
                glass_border='rgba(255, 64, 129, 0.25)',
                glass_shadow='0 8px 32px rgba(255, 64, 129, 0.25)'
            ),
            'styles': ThemeStyles(
                border_radius='24px',
                blur='26px',
                shadow='0 8px 32px rgba(255, 64, 129, 0.25)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Comic Neue", cursive',
                glass_shadow='0 8px 32px 0 rgba(255, 64, 129, 0.25)',
                glass_backdrop='blur(26px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'ios_liquid_glass_dark': {
            'name': 'iOS Dark (Liquid Glass)',
            'description': 'Dark theme with teal-cyan gradients',
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
                font_family='-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif',
                glass_shadow='0 8px 32px 0 rgba(0, 217, 163, 0.15)',
                glass_backdrop='blur(25px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'ios_liquid_glass_light': {
            'name': 'iOS Light (Liquid Glass)',
            'description': 'Light theme with teal-cyan gradients',
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
                font_family='-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif',
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
                font_family='-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
                glass_shadow='0 4px 24px rgba(0, 0, 0, 0.06)',
                glass_backdrop='blur(20px) saturate(150%)',
                glass_border_width='1px'
            )
        },
        'dracula': {
            'name': '🧛 Dracula (Classic)',
            'description': 'Popular Dracula color scheme',
            'colors': ThemeColors(
                primary='#BD93F9',
                secondary='#8BE9FD',
                accent='#FF79C6',
                background='#282A36',
                surface='rgba(68, 71, 90, 0.85)',
                text_primary='#F8F8F2',
                text_secondary='#6272A4',
                success='#50FA7B',
                warning='#F1FA8C',
                error='#FF5555',
                info='#8BE9FD',
                border='rgba(189, 147, 249, 0.3)',
                shadow='rgba(189, 147, 249, 0.2)',
                gradient_start='#BD93F9',
                gradient_end='#8BE9FD',
                glass_bg='rgba(68, 71, 90, 0.7)',
                glass_border='rgba(189, 147, 249, 0.25)',
                glass_shadow='0 8px 32px rgba(189, 147, 249, 0.2)'
            ),
            'styles': ThemeStyles(
                border_radius='18px',
                blur='24px',
                shadow='0 8px 32px rgba(189, 147, 249, 0.2)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Fira Code", monospace',
                glass_shadow='0 8px 32px 0 rgba(189, 147, 249, 0.2)',
                glass_backdrop='blur(24px) saturate(180%)',
                glass_border_width='1px'
            )
        }
    }
    
    def __init__(self, default_theme: str = 'cyber_green'):
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
            theme = self.THEMES.get(theme_name, self.THEMES['cyber_green'])
        
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
    
    def get_theme_display_names(self) -> Dict[str, str]:
        display_names = {}
        for key, theme in self.THEMES.items():
            display_names[key] = theme['name']
        for key, theme in self._custom_themes.items():
            display_names[key] = theme.get('name', key)
        return display_names
    
    def get_stylesheet(self, theme_name: Optional[str] = None) -> str:
        if theme_name is None:
            theme_name = self.current_theme
        
        theme = self.get_theme(theme_name)
        colors = theme['colors']
        styles = theme['styles']
        
        if 'dark' in theme_name.lower() or 'cyber' in theme_name.lower() or 'neon' in theme_name.lower() or 'blood' in theme_name.lower() or 'midnight' in theme_name.lower() or 'toxic' in theme_name.lower() or 'dracula' in theme_name.lower():
            bg_surface = colors.background
            surface_hex = colors.surface.replace('rgba', '').replace('(', '').replace(')', '').split(',')[0:3]
            surface_hex = f"#{int(float(surface_hex[0])):02x}{int(float(surface_hex[1])):02x}{int(float(surface_hex[2])):02x}"
        else:
            bg_surface = '#F8FAFC'
            surface_hex = '#FFFFFF'
        
        text_color_on_primary = '#000000' if any(x in theme_name.lower() for x in ['cyber', 'toxic', 'golden', 'sunset']) else '#FFFFFF'
        
        return f'''
QWidget {{
    background-color: {colors.background};
    color: {colors.text_primary};
    font-family: {styles.font_family};
    font-size: 14px;
}}

QMainWindow {{
    background-color: {colors.background};
}}

QPushButton {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                               stop:0 {colors.gradient_start},
                               stop:1 {colors.gradient_end});
    color: {text_color_on_primary};
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

QLineEdit, QTextEdit, QPlainTextEdit {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 2px solid {colors.border.split(',')[0].replace('rgba(', '').replace(')', '').split()[0]};
    border-radius: 10px;
    padding: 10px 14px;
    selection-background-color: {colors.primary};
    selection-color: {text_color_on_primary};
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border: 2px solid {colors.primary};
    background-color: {colors.background};
    box-shadow: 0 0 15px {colors.primary};
}}

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
    color: {text_color_on_primary};
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
    color: {text_color_on_primary};
    font-weight: 700;
}}

QTabBar::tab:hover:!selected {{
    background-color: {colors.primary};
    color: {text_color_on_primary};
}}

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
    selection-color: {text_color_on_primary};
    padding: 4px;
}}

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

QLabel {{
    color: {colors.text_primary};
    background-color: transparent;
}}

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

QStatusBar {{
    background-color: {bg_surface};
    color: {colors.text_secondary};
    padding: 4px;
    border-top: 1px solid {colors.primary};
}}

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

QFrame {{
    border: 2px solid {bg_surface};
    border-radius: 12px;
    background-color: {surface_hex};
}}
'''
    
    def export_theme_config(self, theme_name: Optional[str] = None, filepath: str = 'theme_config.json'):
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
    print(f"Default theme: {theme_manager.current_theme}")
    print(f"Available themes: {len(theme_manager.THEMES)}")
    for key, name in theme_manager.get_theme_display_names().items():
        print(f"  - {name}")
