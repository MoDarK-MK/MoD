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
                background='#0D1117',
                surface='rgba(18, 28, 22, 0.90)',
                text_primary='#E6FFE6',
                text_secondary='#9DFFB3',
                success='#00FF41',
                warning='#FFD93D',
                error='#FF3366',
                info='#00E5FF',
                border='rgba(0, 255, 65, 0.25)',
                shadow='rgba(0, 255, 65, 0.3)',
                gradient_start='#00FF41',
                gradient_end='#00D936',
                glass_bg='rgba(18, 28, 22, 0.75)',
                glass_border='rgba(0, 255, 65, 0.3)',
                glass_shadow='0 8px 32px rgba(0, 255, 65, 0.25)'
            ),
            'styles': ThemeStyles(
                border_radius='16px',
                blur='24px',
                shadow='0 8px 32px rgba(0, 255, 65, 0.25)',
                transition='all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Fira Code", "JetBrains Mono", monospace',
                glass_shadow='0 8px 32px 0 rgba(0, 255, 65, 0.25)',
                glass_backdrop='blur(24px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'neon_purple': {
            'name': '💜 Neon Purple (Cyberpunk)',
            'description': 'Vibrant purple neon with dark background',
            'colors': ThemeColors(
                primary='#C77DFF',
                secondary='#9D4EDD',
                accent='#E0AAFF',
                background='#10002B',
                surface='rgba(30, 15, 50, 0.90)',
                text_primary='#F0E6FF',
                text_secondary='#D0B3FF',
                success='#06FFA5',
                warning='#FFBE0B',
                error='#FF006E',
                info='#7209B7',
                border='rgba(199, 125, 255, 0.25)',
                shadow='rgba(199, 125, 255, 0.3)',
                gradient_start='#C77DFF',
                gradient_end='#9D4EDD',
                glass_bg='rgba(30, 15, 50, 0.75)',
                glass_border='rgba(199, 125, 255, 0.3)',
                glass_shadow='0 8px 32px rgba(199, 125, 255, 0.3)'
            ),
            'styles': ThemeStyles(
                border_radius='18px',
                blur='26px',
                shadow='0 8px 32px rgba(199, 125, 255, 0.3)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"JetBrains Mono", "Space Mono", monospace',
                glass_shadow='0 8px 32px 0 rgba(199, 125, 255, 0.3)',
                glass_backdrop='blur(26px) saturate(200%)',
                glass_border_width='1.5px'
            )
        },
        'electric_blue': {
            'name': '⚡ Electric Blue (Tron)',
            'description': 'Bright electric blue with dark contrast',
            'colors': ThemeColors(
                primary='#00D9FF',
                secondary='#0099CC',
                accent='#66E0FF',
                background='#0A1628',
                surface='rgba(15, 30, 50, 0.90)',
                text_primary='#E0F7FF',
                text_secondary='#99E0FF',
                success='#00E676',
                warning='#FFC107',
                error='#FF5252',
                info='#00D9FF',
                border='rgba(0, 217, 255, 0.25)',
                shadow='rgba(0, 217, 255, 0.3)',
                gradient_start='#00D9FF',
                gradient_end='#0099CC',
                glass_bg='rgba(15, 30, 50, 0.75)',
                glass_border='rgba(0, 217, 255, 0.3)',
                glass_shadow='0 8px 32px rgba(0, 217, 255, 0.3)'
            ),
            'styles': ThemeStyles(
                border_radius='14px',
                blur='22px',
                shadow='0 8px 32px rgba(0, 217, 255, 0.3)',
                transition='all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Roboto Mono", "IBM Plex Mono", monospace',
                glass_shadow='0 8px 32px 0 rgba(0, 217, 255, 0.3)',
                glass_backdrop='blur(22px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'blood_red': {
            'name': '🩸 Blood Red (Vampire)',
            'description': 'Deep red theme with dark gothic aesthetic',
            'colors': ThemeColors(
                primary='#DC143C',
                secondary='#A01326',
                accent='#FF4466',
                background='#1A0F0F',
                surface='rgba(40, 15, 15, 0.90)',
                text_primary='#FFE6E6',
                text_secondary='#FFCCCC',
                success='#52B788',
                warning='#FFB703',
                error='#DC143C',
                info='#48CAE4',
                border='rgba(220, 20, 60, 0.25)',
                shadow='rgba(220, 20, 60, 0.35)',
                gradient_start='#DC143C',
                gradient_end='#A01326',
                glass_bg='rgba(40, 15, 15, 0.75)',
                glass_border='rgba(220, 20, 60, 0.3)',
                glass_shadow='0 8px 32px rgba(220, 20, 60, 0.35)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='28px',
                shadow='0 8px 32px rgba(220, 20, 60, 0.35)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Cinzel", "Playfair Display", serif',
                glass_shadow='0 8px 32px 0 rgba(220, 20, 60, 0.35)',
                glass_backdrop='blur(28px) saturate(150%)',
                glass_border_width='1.5px'
            )
        },
        'golden_luxury': {
            'name': '✨ Golden Luxury (Royal)',
            'description': 'Luxurious gold and black premium theme',
            'colors': ThemeColors(
                primary='#FFD700',
                secondary='#D4AF37',
                accent='#FFF3B0',
                background='#1C1810',
                surface='rgba(35, 28, 15, 0.90)',
                text_primary='#FFFBEB',
                text_secondary='#FFE6A0',
                success='#52B788',
                warning='#FB8500',
                error='#D00000',
                info='#219EBC',
                border='rgba(255, 215, 0, 0.25)',
                shadow='rgba(255, 215, 0, 0.3)',
                gradient_start='#FFD700',
                gradient_end='#D4AF37',
                glass_bg='rgba(35, 28, 15, 0.75)',
                glass_border='rgba(255, 215, 0, 0.3)',
                glass_shadow='0 8px 32px rgba(255, 215, 0, 0.3)'
            ),
            'styles': ThemeStyles(
                border_radius='22px',
                blur='30px',
                shadow='0 8px 32px rgba(255, 215, 0, 0.3)',
                transition='all 0.45s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Playfair Display", "Cormorant Garamond", serif',
                glass_shadow='0 8px 32px 0 rgba(255, 215, 0, 0.3)',
                glass_backdrop='blur(30px) saturate(180%)',
                glass_border_width='1.5px'
            )
        },
        'ocean_deep': {
            'name': '🌊 Ocean Deep (Aquatic)',
            'description': 'Deep ocean blue with teal accents',
            'colors': ThemeColors(
                primary='#0FA3B1',
                secondary='#086375',
                accent='#5DD9C1',
                background='#001925',
                surface='rgba(10, 35, 50, 0.90)',
                text_primary='#E0F4F7',
                text_secondary='#A3DDE6',
                success='#06FFA5',
                warning='#FFB627',
                error='#FF4D6D',
                info='#0FA3B1',
                border='rgba(15, 163, 177, 0.25)',
                shadow='rgba(15, 163, 177, 0.25)',
                gradient_start='#0FA3B1',
                gradient_end='#086375',
                glass_bg='rgba(10, 35, 50, 0.75)',
                glass_border='rgba(15, 163, 177, 0.3)',
                glass_shadow='0 8px 32px rgba(15, 163, 177, 0.25)'
            ),
            'styles': ThemeStyles(
                border_radius='18px',
                blur='24px',
                shadow='0 8px 32px rgba(15, 163, 177, 0.25)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Lato", "Open Sans", sans-serif',
                glass_shadow='0 8px 32px 0 rgba(15, 163, 177, 0.25)',
                glass_backdrop='blur(24px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'sunset_orange': {
            'name': '🌅 Sunset Orange (Fire)',
            'description': 'Warm sunset colors with orange and pink',
            'colors': ThemeColors(
                primary='#FF6B35',
                secondary='#D84315',
                accent='#FF9E6D',
                background='#1F1410',
                surface='rgba(40, 25, 18, 0.90)',
                text_primary='#FFF4E6',
                text_secondary='#FFD4A3',
                success='#52B788',
                warning='#FFB627',
                error='#D00000',
                info='#219EBC',
                border='rgba(255, 107, 53, 0.25)',
                shadow='rgba(255, 107, 53, 0.3)',
                gradient_start='#FF6B35',
                gradient_end='#D84315',
                glass_bg='rgba(40, 25, 18, 0.75)',
                glass_border='rgba(255, 107, 53, 0.3)',
                glass_shadow='0 8px 32px rgba(255, 107, 53, 0.3)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='26px',
                shadow='0 8px 32px rgba(255, 107, 53, 0.3)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Nunito", "Quicksand", sans-serif',
                glass_shadow='0 8px 32px 0 rgba(255, 107, 53, 0.3)',
                glass_backdrop='blur(26px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'midnight_indigo': {
            'name': '🌙 Midnight Indigo (Night)',
            'description': 'Deep indigo midnight theme',
            'colors': ThemeColors(
                primary='#6366F1',
                secondary='#4F46E5',
                accent='#818CF8',
                background='#0F0F23',
                surface='rgba(20, 20, 45, 0.90)',
                text_primary='#E0E7FF',
                text_secondary='#C7D2FE',
                success='#10B981',
                warning='#F59E0B',
                error='#EF4444',
                info='#6366F1',
                border='rgba(99, 102, 241, 0.25)',
                shadow='rgba(99, 102, 241, 0.25)',
                gradient_start='#6366F1',
                gradient_end='#4F46E5',
                glass_bg='rgba(20, 20, 45, 0.75)',
                glass_border='rgba(99, 102, 241, 0.3)',
                glass_shadow='0 8px 32px rgba(99, 102, 241, 0.25)'
            ),
            'styles': ThemeStyles(
                border_radius='18px',
                blur='24px',
                shadow='0 8px 32px rgba(99, 102, 241, 0.25)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Poppins", "Inter", sans-serif',
                glass_shadow='0 8px 32px 0 rgba(99, 102, 241, 0.25)',
                glass_backdrop='blur(24px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'toxic_green': {
            'name': '☢️ Toxic Green (Radioactive)',
            'description': 'Toxic radioactive green theme',
            'colors': ThemeColors(
                primary='#7FFF00',
                secondary='#66CC00',
                accent='#9FFF66',
                background='#0A1A08',
                surface='rgba(15, 30, 12, 0.90)',
                text_primary='#E6FFE0',
                text_secondary='#B3FF99',
                success='#7FFF00',
                warning='#FFD600',
                error='#FF3333',
                info='#00E5CC',
                border='rgba(127, 255, 0, 0.25)',
                shadow='rgba(127, 255, 0, 0.35)',
                gradient_start='#7FFF00',
                gradient_end='#66CC00',
                glass_bg='rgba(15, 30, 12, 0.75)',
                glass_border='rgba(127, 255, 0, 0.3)',
                glass_shadow='0 8px 32px rgba(127, 255, 0, 0.35)'
            ),
            'styles': ThemeStyles(
                border_radius='16px',
                blur='22px',
                shadow='0 8px 32px rgba(127, 255, 0, 0.35)',
                transition='all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Share Tech Mono", "Source Code Pro", monospace',
                glass_shadow='0 8px 32px 0 rgba(127, 255, 0, 0.35)',
                glass_backdrop='blur(22px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'pink_candy': {
            'name': '🍭 Pink Candy (Sweet)',
            'description': 'Sweet pink and purple candy theme',
            'colors': ThemeColors(
                primary='#FF6AC2',
                secondary='#FF1B8D',
                accent='#FFB3E6',
                background='#1F0A18',
                surface='rgba(35, 15, 28, 0.90)',
                text_primary='#FFE6F7',
                text_secondary='#FFCCE6',
                success='#5EFC82',
                warning='#FFD60A',
                error='#FF3366',
                info='#66B3FF',
                border='rgba(255, 106, 194, 0.25)',
                shadow='rgba(255, 106, 194, 0.3)',
                gradient_start='#FF6AC2',
                gradient_end='#FF1B8D',
                glass_bg='rgba(35, 15, 28, 0.75)',
                glass_border='rgba(255, 106, 194, 0.3)',
                glass_shadow='0 8px 32px rgba(255, 106, 194, 0.3)'
            ),
            'styles': ThemeStyles(
                border_radius='24px',
                blur='28px',
                shadow='0 8px 32px rgba(255, 106, 194, 0.3)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Comic Neue", "Quicksand", cursive',
                glass_shadow='0 8px 32px 0 rgba(255, 106, 194, 0.3)',
                glass_backdrop='blur(28px) saturate(200%)',
                glass_border_width='1.5px'
            )
        },
        'ios_liquid_glass_dark': {
            'name': '🍎 iOS Dark (Liquid Glass)',
            'description': 'Dark theme with teal-cyan gradients',
            'colors': ThemeColors(
                primary='#30D5C8',
                secondary='#00B4D8',
                accent='#66FFE6',
                background='#0D1117',
                surface='rgba(22, 27, 34, 0.90)',
                text_primary='#F0F6FC',
                text_secondary='#8B949E',
                success='#3FB950',
                warning='#D29922',
                error='#F85149',
                info='#30D5C8',
                border='rgba(48, 213, 200, 0.15)',
                shadow='rgba(48, 213, 200, 0.2)',
                gradient_start='#30D5C8',
                gradient_end='#00B4D8',
                glass_bg='rgba(22, 27, 34, 0.75)',
                glass_border='rgba(48, 213, 200, 0.2)',
                glass_shadow='0 8px 32px rgba(48, 213, 200, 0.2)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='25px',
                shadow='0 8px 32px rgba(48, 213, 200, 0.2)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif',
                glass_shadow='0 8px 32px 0 rgba(48, 213, 200, 0.2)',
                glass_backdrop='blur(25px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'ios_liquid_glass_light': {
            'name': '🍏 iOS Light (Liquid Glass)',
            'description': 'Light theme with teal-cyan gradients',
            'colors': ThemeColors(
                primary='#00A896',
                secondary='#028090',
                accent='#02C39A',
                background='#F8F9FA',
                surface='rgba(255, 255, 255, 0.95)',
                text_primary='#212529',
                text_secondary='#495057',
                success='#2A9D8F',
                warning='#E76F51',
                error='#E63946',
                info='#00A896',
                border='rgba(0, 168, 150, 0.2)',
                shadow='rgba(0, 168, 150, 0.15)',
                gradient_start='#00A896',
                gradient_end='#028090',
                glass_bg='rgba(255, 255, 255, 0.85)',
                glass_border='rgba(0, 168, 150, 0.25)',
                glass_shadow='0 4px 24px rgba(0, 168, 150, 0.15)'
            ),
            'styles': ThemeStyles(
                border_radius='20px',
                blur='25px',
                shadow='0 4px 24px rgba(0, 168, 150, 0.15)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif',
                glass_shadow='0 4px 24px 0 rgba(0, 168, 150, 0.15)',
                glass_backdrop='blur(25px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'modern_light': {
            'name': '☀️ Modern Light',
            'description': 'Clean and bright modern light theme',
            'colors': ThemeColors(
                primary='#0EA5E9',
                secondary='#0284C7',
                accent='#38BDF8',
                background='#FFFFFF',
                surface='rgba(248, 250, 252, 0.98)',
                text_primary='#1E293B',
                text_secondary='#64748B',
                success='#10B981',
                warning='#F59E0B',
                error='#EF4444',
                info='#3B82F6',
                border='rgba(226, 232, 240, 0.8)',
                shadow='rgba(0, 0, 0, 0.1)',
                gradient_start='#0EA5E9',
                gradient_end='#0284C7',
                glass_bg='rgba(255, 255, 255, 0.90)',
                glass_border='rgba(226, 232, 240, 0.7)',
                glass_shadow='0 4px 24px rgba(0, 0, 0, 0.08)'
            ),
            'styles': ThemeStyles(
                border_radius='16px',
                blur='20px',
                shadow='0 4px 24px rgba(0, 0, 0, 0.08)',
                transition='all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
                glass_shadow='0 4px 24px rgba(0, 0, 0, 0.08)',
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
                surface='rgba(68, 71, 90, 0.90)',
                text_primary='#F8F8F2',
                text_secondary='#6272A4',
                success='#50FA7B',
                warning='#F1FA8C',
                error='#FF5555',
                info='#8BE9FD',
                border='rgba(189, 147, 249, 0.25)',
                shadow='rgba(189, 147, 249, 0.25)',
                gradient_start='#BD93F9',
                gradient_end='#8BE9FD',
                glass_bg='rgba(68, 71, 90, 0.75)',
                glass_border='rgba(189, 147, 249, 0.3)',
                glass_shadow='0 8px 32px rgba(189, 147, 249, 0.25)'
            ),
            'styles': ThemeStyles(
                border_radius='18px',
                blur='24px',
                shadow='0 8px 32px rgba(189, 147, 249, 0.25)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Fira Code", "JetBrains Mono", monospace',
                glass_shadow='0 8px 32px 0 rgba(189, 147, 249, 0.25)',
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
        
        is_light_theme = any(x in theme_name.lower() for x in ['light', 'ios_liquid_glass_light'])
        
        if is_light_theme:
            bg_surface = '#F1F5F9'
            surface_hex = '#FFFFFF'
            text_color_on_primary = '#FFFFFF'
        else:
            bg_surface = colors.background
            surface_rgba = colors.surface.replace('rgba', '').replace('(', '').replace(')', '').split(',')
            r, g, b = int(float(surface_rgba[0])), int(float(surface_rgba[1])), int(float(surface_rgba[2]))
            surface_hex = f"#{r:02x}{g:02x}{b:02x}"
            
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
