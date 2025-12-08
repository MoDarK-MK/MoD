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
                surface='rgba(15, 35, 25, 0.95)',
                text_primary='#F0FFEE',
                text_secondary='#A8E6A1',
                success='#00FF41',
                warning='#FFD700',
                error='#FF4455',
                info='#00D9FF',
                border='rgba(0, 255, 65, 0.35)',
                shadow='rgba(0, 255, 65, 0.4)',
                gradient_start='#00FF41',
                gradient_end='#00D936',
                glass_bg='rgba(15, 35, 25, 0.85)',
                glass_border='rgba(0, 255, 65, 0.4)',
                glass_shadow='0 8px 32px rgba(0, 255, 65, 0.3)'
            ),
            'styles': ThemeStyles(
                border_radius='16px',
                blur='24px',
                shadow='0 8px 32px rgba(0, 255, 65, 0.3)',
                transition='all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"Fira Code", "JetBrains Mono", monospace',
                glass_shadow='0 8px 32px 0 rgba(0, 255, 65, 0.3)',
                glass_backdrop='blur(24px) saturate(180%)',
                glass_border_width='1px'
            )
        },
        'neon_purple': {
            'name': '💜 Neon Purple (Cyberpunk)',
            'description': 'Vibrant purple neon with dark background',
            'colors': ThemeColors(
                primary='#D64EF2',
                secondary='#A833D9',
                accent='#E8B4FF',
                background='#15001B',
                surface='rgba(40, 20, 60, 0.95)',
                text_primary='#F5E6FF',
                text_secondary='#D4A8FF',
                success='#06FFA5',
                warning='#FFD100',
                error='#FF2E7E',
                info='#8B5CF6',
                border='rgba(212, 78, 242, 0.4)',
                shadow='rgba(212, 78, 242, 0.4)',
                gradient_start='#D64EF2',
                gradient_end='#A833D9',
                glass_bg='rgba(40, 20, 60, 0.85)',
                glass_border='rgba(212, 78, 242, 0.4)',
                glass_shadow='0 8px 32px rgba(212, 78, 242, 0.35)'
            ),
            'styles': ThemeStyles(
                border_radius='18px',
                blur='26px',
                shadow='0 8px 32px rgba(212, 78, 242, 0.35)',
                transition='all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                font_family='"JetBrains Mono", "Space Mono", monospace',
                glass_shadow='0 8px 32px 0 rgba(212, 78, 242, 0.35)',
                glass_backdrop='blur(26px) saturate(200%)',
                glass_border_width='1.5px'
            )
        },
        'electric_blue': {
            'name': '⚡ Electric Blue (Tron)',
            'description': 'Bright electric blue with dark contrast',
            'colors': ThemeColors(
                primary='#00DDFF',
                secondary='#0099DD',
                accent='#66FFFF',
                background='#05101F',
                surface='rgba(15, 35, 60, 0.95)',
                text_primary='#E3F8FF',
                text_secondary='#A0E0FF',
                success='#00FF77',
                warning='#FFD600',
                error='#FF4466',
                info='#00DDFF',
                border='rgba(0, 221, 255, 0.4)',
                shadow='rgba(0, 221, 255, 0.4)',
                gradient_start='#00DDFF',
                gradient_end='#0099DD',
                glass_bg='rgba(15, 35, 60, 0.85)',
                glass_border='rgba(0, 221, 255, 0.4)',
                glass_shadow='0 8px 32px rgba(0, 221, 255, 0.35)'
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
                primary='#D32F2F',
                secondary='#B71C1C',
                accent='#FF6B6B',
                background='#1A0A0A',
                surface='rgba(45, 15, 15, 0.95)',
                text_primary='#FFDDDD',
                text_secondary='#FFB8B8',
                success='#4CAF50',
                warning='#FFC107',
                error='#D32F2F',
                info='#00BCD4',
                border='rgba(211, 47, 47, 0.4)',
                shadow='rgba(211, 47, 47, 0.4)',
                gradient_start='#D32F2F',
                gradient_end='#B71C1C',
                glass_bg='rgba(45, 15, 15, 0.85)',
                glass_border='rgba(211, 47, 47, 0.4)',
                glass_shadow='0 8px 32px rgba(211, 47, 47, 0.35)'
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
                primary='#FFC107',
                secondary='#E8B923',
                accent='#FFE082',
                background='#1A1410',
                surface='rgba(40, 32, 18, 0.95)',
                text_primary='#FFFAE0',
                text_secondary='#FFD9A3',
                success='#4CAF50',
                warning='#FF9800',
                error='#D32F2F',
                info='#00BCD4',
                border='rgba(255, 193, 7, 0.4)',
                shadow='rgba(255, 193, 7, 0.4)',
                gradient_start='#FFC107',
                gradient_end='#E8B923',
                glass_bg='rgba(40, 32, 18, 0.85)',
                glass_border='rgba(255, 193, 7, 0.4)',
                glass_shadow='0 8px 32px rgba(255, 193, 7, 0.3)'
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
                primary='#00BCD4',
                secondary='#0097A7',
                accent='#4DD0E1',
                background='#000F1F',
                surface='rgba(10, 40, 60, 0.95)',
                text_primary='#E0F7FA',
                text_secondary='#B2DFDB',
                success='#00FF88',
                warning='#FFD600',
                error='#FF4466',
                info='#00BCD4',
                border='rgba(0, 188, 212, 0.4)',
                shadow='rgba(0, 188, 212, 0.4)',
                gradient_start='#00BCD4',
                gradient_end='#0097A7',
                glass_bg='rgba(10, 40, 60, 0.85)',
                glass_border='rgba(0, 188, 212, 0.4)',
                glass_shadow='0 8px 32px rgba(0, 188, 212, 0.35)'
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
                primary='#FF7043',
                secondary='#E64A19',
                accent='#FFAB91',
                background='#1A0F0A',
                surface='rgba(45, 25, 15, 0.95)',
                text_primary='#FFEDDA',
                text_secondary='#FFD1B3',
                success='#4CAF50',
                warning='#FFC107',
                error='#D32F2F',
                info='#00BCD4',
                border='rgba(255, 112, 67, 0.4)',
                shadow='rgba(255, 112, 67, 0.4)',
                gradient_start='#FF7043',
                gradient_end='#E64A19',
                glass_bg='rgba(45, 25, 15, 0.85)',
                glass_border='rgba(255, 112, 67, 0.4)',
                glass_shadow='0 8px 32px rgba(255, 112, 67, 0.35)'
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
                primary='#7C3AED',
                secondary='#6D28D9',
                accent='#A78BFA',
                background='#0F0A2E',
                surface='rgba(25, 20, 50, 0.95)',
                text_primary='#EDE9FE',
                text_secondary='#C4B5FD',
                success='#10B981',
                warning='#F59E0B',
                error='#EF4444',
                info='#7C3AED',
                border='rgba(124, 58, 237, 0.4)',
                shadow='rgba(124, 58, 237, 0.4)',
                gradient_start='#7C3AED',
                gradient_end='#6D28D9',
                glass_bg='rgba(25, 20, 50, 0.85)',
                glass_border='rgba(124, 58, 237, 0.4)',
                glass_shadow='0 8px 32px rgba(124, 58, 237, 0.35)'
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
                primary='#ADFF2F',
                secondary='#7CFC00',
                accent='#BFFF00',
                background='#0B1A05',
                surface='rgba(18, 35, 10, 0.95)',
                text_primary='#F5FFEB',
                text_secondary='#C8E6C9',
                success='#ADFF2F',
                warning='#FFD700',
                error='#FF4444',
                info='#00E5CC',
                border='rgba(173, 255, 47, 0.4)',
                shadow='rgba(173, 255, 47, 0.4)',
                gradient_start='#ADFF2F',
                gradient_end='#7CFC00',
                glass_bg='rgba(18, 35, 10, 0.85)',
                glass_border='rgba(173, 255, 47, 0.4)',
                glass_shadow='0 8px 32px rgba(173, 255, 47, 0.35)'
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
                primary='#E91E8C',
                secondary='#C2185B',
                accent='#FF80AB',
                background='#1A0A12',
                surface='rgba(40, 15, 30, 0.95)',
                text_primary='#FFDDEE',
                text_secondary='#FFB3D9',
                success='#4CAF50',
                warning='#FFC107',
                error='#D32F2F',
                info='#00BCD4',
                border='rgba(233, 30, 140, 0.4)',
                shadow='rgba(233, 30, 140, 0.4)',
                gradient_start='#E91E8C',
                gradient_end='#C2185B',
                glass_bg='rgba(40, 15, 30, 0.85)',
                glass_border='rgba(233, 30, 140, 0.4)',
                glass_shadow='0 8px 32px rgba(233, 30, 140, 0.35)'
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
                primary='#30B0C8',
                secondary='#0099BB',
                accent='#64D9E5',
                background='#0A0E15',
                surface='rgba(20, 28, 40, 0.95)',
                text_primary='#F2F5F9',
                text_secondary='#A0A8B5',
                success='#34C759',
                warning='#FF9500',
                error='#FF3B30',
                info='#30B0C8',
                border='rgba(48, 176, 200, 0.3)',
                shadow='rgba(48, 176, 200, 0.3)',
                gradient_start='#30B0C8',
                gradient_end='#0099BB',
                glass_bg='rgba(20, 28, 40, 0.85)',
                glass_border='rgba(48, 176, 200, 0.3)',
                glass_shadow='0 8px 32px rgba(48, 176, 200, 0.25)'
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
                background='#FAFBFC',
                surface='rgba(255, 255, 255, 0.98)',
                text_primary='#1E293B',
                text_secondary='#64748B',
                success='#16A34A',
                warning='#D97706',
                error='#DC2626',
                info='#0284C7',
                border='rgba(209, 213, 219, 0.8)',
                shadow='rgba(0, 0, 0, 0.08)',
                gradient_start='#0EA5E9',
                gradient_end='#0284C7',
                glass_bg='rgba(255, 255, 255, 0.92)',
                glass_border='rgba(209, 213, 219, 0.7)',
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
                surface='rgba(68, 71, 90, 0.95)',
                text_primary='#F8F8F2',
                text_secondary='#6272A4',
                success='#50FA7B',
                warning='#F1FA8C',
                error='#FF5555',
                info='#8BE9FD',
                border='rgba(189, 147, 249, 0.35)',
                shadow='rgba(189, 147, 249, 0.35)',
                gradient_start='#BD93F9',
                gradient_end='#8BE9FD',
                glass_bg='rgba(68, 71, 90, 0.85)',
                glass_border='rgba(189, 147, 249, 0.35)',
                glass_shadow='0 8px 32px rgba(189, 147, 249, 0.3)'
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
        
        is_light_theme = any(x in theme_name.lower() for x in ['light', 'ios_liquid_glass_light', 'modern_light'])
        
        if is_light_theme:
            bg_surface = '#F1F5F9'
            surface_hex = '#FFFFFF'
            text_color_on_primary = '#FFFFFF'
            button_hover_shadow = f'0 0 20px rgba(14, 165, 233, 0.3)'
        else:
            bg_surface = colors.background
            surface_rgba = colors.surface.replace('rgba', '').replace('(', '').replace(')', '').split(',')
            r, g, b = int(float(surface_rgba[0])), int(float(surface_rgba[1])), int(float(surface_rgba[2]))
            surface_hex = f"#{r:02x}{g:02x}{b:02x}"
            
            text_color_on_primary = '#FFFFFF'
            button_hover_shadow = f'0 0 20px {colors.primary}'
        
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
    box-shadow: {button_hover_shadow};
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
    border: 2px solid {colors.border};
    border-radius: 10px;
    padding: 10px 14px;
    selection-background-color: {colors.primary};
    selection-color: {text_color_on_primary};
    font-size: 13px;
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border: 2px solid {colors.primary};
    background-color: {surface_hex};
    box-shadow: 0 0 12px {colors.primary};
}}

QTableWidget {{
    background-color: {surface_hex};
    color: {colors.text_primary};
    border: 2px solid {colors.border};
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
    font-weight: 600;
}}

QTableWidget::item:hover {{
    background-color: {colors.accent};
    color: {colors.text_primary};
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
    border: 2px solid {colors.border};
    border-radius: 10px;
    padding: 8px 14px;
    min-height: 36px;
    font-size: 13px;
}}

QComboBox:hover {{
    border: 2px solid {colors.primary};
}}

QComboBox:focus {{
    border: 2px solid {colors.primary};
    box-shadow: 0 0 10px {colors.primary};
}}

QComboBox::drop-down {{
    border: none;
    width: 32px;
    background-color: transparent;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 6px solid transparent;
    border-right: 6px solid transparent;
    border-top: 8px solid {colors.primary};
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
    outline: none;
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
    font-size: 14px;
}}

QGroupBox {{
    border: 2px solid {colors.border};
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
    font-weight: 700;
}}

QCheckBox {{
    color: {colors.text_primary};
    spacing: 10px;
    font-size: 14px;
    padding: 4px;
}}

QCheckBox:hover {{
    color: {colors.primary};
}}

QCheckBox::indicator {{
    width: 22px;
    height: 22px;
    border-radius: 6px;
    border: 2px solid {colors.border};
    background-color: {surface_hex};
}}

QCheckBox::indicator:hover {{
    border-color: {colors.primary};
    background-color: {bg_surface};
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
    padding: 4px;
}}

QRadioButton:hover {{
    color: {colors.primary};
}}

QRadioButton::indicator {{
    width: 22px;
    height: 22px;
    border-radius: 11px;
    border: 2px solid {colors.border};
    background-color: {surface_hex};
}}

QRadioButton::indicator:hover {{
    border-color: {colors.primary};
    background-color: {bg_surface};
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
    border: 2px solid {colors.border};
    border-radius: 10px;
    padding: 8px 14px;
    min-height: 36px;
    font-size: 13px;
}}

QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 2px solid {colors.primary};
    box-shadow: 0 0 10px {colors.primary};
}}

QSpinBox::up-button, QDoubleSpinBox::up-button {{
    width: 32px;
    border-left: 1px solid {colors.border};
    background-color: {colors.background};
}}

QSpinBox::down-button, QDoubleSpinBox::down-button {{
    width: 32px;
    border-left: 1px solid {colors.border};
    background-color: {colors.background};
}}

QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
    background-color: {colors.primary};
}}

QFrame {{
    border: 2px solid {colors.border};
    border-radius: 12px;
    background-color: {surface_hex};
    padding: 8px;
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
