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
    
    def get_css(self, theme_name: Optional[str] = None) -> str:
        theme = self.get_theme(theme_name)
        colors = theme['colors']
        styles = theme['styles']
        
        return f'''
/* ==================== iOS Liquid Glass Theme ==================== */
/* Generated by ThemeManager - Teal/Cyan Gradient with Glass Effect */

:root {{
    /* Color Palette */
    --color-primary: {colors.primary};
    --color-secondary: {colors.secondary};
    --color-accent: {colors.accent};
    --color-background: {colors.background};
    --color-surface: {colors.surface};
    --color-text-primary: {colors.text_primary};
    --color-text-secondary: {colors.text_secondary};
    --color-success: {colors.success};
    --color-warning: {colors.warning};
    --color-error: {colors.error};
    --color-info: {colors.info};
    --color-border: {colors.border};
    --color-shadow: {colors.shadow};
    --color-glass-bg: {colors.glass_bg};
    --color-glass-border: {colors.glass_border};
    
    /* Gradients */
    --gradient-primary: linear-gradient(135deg, {colors.gradient_start} 0%, {colors.gradient_end} 100%);
    --gradient-secondary: linear-gradient(135deg, rgba(0, 217, 163, 0.1) 0%, rgba(0, 184, 212, 0.1) 100%);
    --gradient-mesh: radial-gradient(circle at 30% 50%, rgba(0, 217, 163, 0.15) 0%, transparent 50%),
                     radial-gradient(circle at 70% 50%, rgba(0, 184, 212, 0.15) 0%, transparent 50%);
    
    /* Glass Effects */
    --glass-bg: {colors.glass_bg};
    --glass-border: {colors.glass_border};
    --glass-shadow: {colors.glass_shadow};
    --glass-backdrop: {styles.glass_backdrop};
    
    /* Styles */
    --border-radius: {styles.border_radius};
    --border-radius-sm: 12px;
    --border-radius-lg: 24px;
    --blur: {styles.blur};
    --shadow: {styles.shadow};
    --shadow-sm: 0 4px 16px rgba(0, 217, 163, 0.1);
    --shadow-lg: 0 12px 48px rgba(0, 217, 163, 0.25);
    --transition: {styles.transition};
    --transition-fast: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    --font-family: {styles.font_family};
}}

/* ==================== Base Styles ==================== */

* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}

html {{
    font-size: 16px;
    scroll-behavior: smooth;
}}

body {{
    font-family: var(--font-family);
    background: var(--color-background);
    color: var(--color-text-primary);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    overflow-x: hidden;
    position: relative;
}}

/* Animated Gradient Background */
body::before {{
    content: '';
    position: fixed;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: var(--gradient-mesh);
    animation: gradientShift 20s ease infinite;
    z-index: -1;
    opacity: 0.8;
}}

@keyframes gradientShift {{
    0%, 100% {{ transform: translate(0, 0) rotate(0deg); }}
    25% {{ transform: translate(-5%, -5%) rotate(90deg); }}
    50% {{ transform: translate(-10%, 5%) rotate(180deg); }}
    75% {{ transform: translate(-5%, 10%) rotate(270deg); }}
}}

/* ==================== Liquid Glass Components ==================== */

.glass-card {{
    background: var(--glass-bg);
    backdrop-filter: var(--glass-backdrop);
    -webkit-backdrop-filter: var(--glass-backdrop);
    border: 1px solid var(--glass-border);
    border-radius: var(--border-radius);
    padding: 24px;
    box-shadow: var(--glass-shadow), inset 0 1px 0 rgba(255, 255, 255, 0.05);
    transition: var(--transition);
    position: relative;
    overflow: hidden;
}}

.glass-card::before {{
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(0, 217, 163, 0.15), transparent);
    transition: left 0.6s cubic-bezier(0.4, 0, 0.2, 1);
}}

.glass-card:hover {{
    transform: translateY(-4px) scale(1.01);
    box-shadow: var(--shadow-lg), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    border-color: rgba(0, 217, 163, 0.35);
}}

.glass-card:hover::before {{
    left: 100%;
}}

.glass-panel {{
    background: var(--glass-bg);
    backdrop-filter: var(--glass-backdrop);
    -webkit-backdrop-filter: var(--glass-backdrop);
    border: 1px solid var(--glass-border);
    border-radius: var(--border-radius-lg);
    padding: 32px;
    box-shadow: var(--glass-shadow);
}}

/* ==================== Buttons ==================== */

.btn {{
    font-family: var(--font-family);
    font-size: 15px;
    font-weight: 500;
    padding: 12px 28px;
    border: none;
    border-radius: 14px;
    cursor: pointer;
    transition: var(--transition);
    position: relative;
    overflow: hidden;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    white-space: nowrap;
}}

.btn-primary {{
    background: var(--gradient-primary);
    color: var(--color-background);
    box-shadow: 0 4px 16px rgba(0, 217, 163, 0.3);
    font-weight: 600;
}}

.btn-primary::before {{
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    width: 0;
    height: 0;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.25);
    transform: translate(-50%, -50%);
    transition: width 0.6s, height 0.6s;
}}

.btn-primary:hover {{
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(0, 217, 163, 0.45);
}}

.btn-primary:active {{
    transform: translateY(0);
}}

.btn-primary:hover::before {{
    width: 350px;
    height: 350px;
}}

.btn-secondary {{
    background: var(--glass-bg);
    backdrop-filter: blur(15px);
    -webkit-backdrop-filter: blur(15px);
    color: var(--color-primary);
    border: 1px solid var(--glass-border);
    box-shadow: var(--shadow-sm);
}}

.btn-secondary:hover {{
    background: rgba(0, 217, 163, 0.1);
    border-color: var(--color-primary);
    transform: translateY(-2px);
    box-shadow: var(--shadow);
}}

.btn-ghost {{
    background: transparent;
    color: var(--color-primary);
    border: 1px solid transparent;
}}

.btn-ghost:hover {{
    background: rgba(0, 217, 163, 0.08);
    border-color: var(--glass-border);
}}

.btn-icon {{
    width: 44px;
    height: 44px;
    padding: 0;
    border-radius: 12px;
}}

/* ==================== Inputs ==================== */

.input-group {{
    position: relative;
    margin-bottom: 20px;
}}

.input-label {{
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: var(--color-text-secondary);
    margin-bottom: 8px;
    letter-spacing: 0.3px;
}}

.input {{
    width: 100%;
    padding: 14px 20px;
    font-size: 15px;
    font-family: var(--font-family);
    background: var(--glass-bg);
    backdrop-filter: blur(15px);
    -webkit-backdrop-filter: blur(15px);
    border: 1px solid var(--glass-border);
    border-radius: 12px;
    color: var(--color-text-primary);
    transition: var(--transition);
    outline: none;
}}

.input:focus {{
    border-color: var(--color-primary);
    box-shadow: 0 0 0 4px rgba(0, 217, 163, 0.12), var(--shadow-sm);
    background: rgba(10, 14, 26, 0.85);
}}

.input::placeholder {{
    color: var(--color-text-secondary);
    opacity: 0.5;
}}

.input-icon {{
    position: absolute;
    right: 16px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--color-text-secondary);
    pointer-events: none;
}}

/* ==================== Progress Bar ==================== */

.progress-container {{
    width: 100%;
    height: 8px;
    background: var(--glass-bg);
    backdrop-filter: blur(15px);
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid var(--glass-border);
    position: relative;
}}

.progress-bar {{
    height: 100%;
    background: var(--gradient-primary);
    border-radius: 10px;
    transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1);
    position: relative;
    overflow: hidden;
}}

.progress-bar::after {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.4), transparent);
    animation: shimmer 2s infinite;
}}

@keyframes shimmer {{
    0% {{ transform: translateX(-100%); }}
    100% {{ transform: translateX(100%); }}
}}

/* ==================== Modal ==================== */

.modal-overlay {{
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(10, 14, 26, 0.9);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    animation: fadeIn 0.3s;
    padding: 20px;
}}

@keyframes fadeIn {{
    from {{ opacity: 0; }}
    to {{ opacity: 1; }}
}}

.modal {{
    background: var(--glass-bg);
    backdrop-filter: var(--glass-backdrop);
    -webkit-backdrop-filter: var(--glass-backdrop);
    border: 1px solid var(--glass-border);
    border-radius: 24px;
    padding: 32px;
    max-width: 560px;
    width: 100%;
    box-shadow: 0 24px 64px rgba(0, 217, 163, 0.25);
    animation: slideUp 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    position: relative;
}}

@keyframes slideUp {{
    from {{
        opacity: 0;
        transform: translateY(40px) scale(0.95);
    }}
    to {{
        opacity: 1;
        transform: translateY(0) scale(1);
    }}
}}

.modal-header {{
    margin-bottom: 24px;
}}

.modal-title {{
    font-size: 24px;
    font-weight: 700;
    background: var(--gradient-primary);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}}

.modal-close {{
    position: absolute;
    top: 20px;
    right: 20px;
    width: 32px;
    height: 32px;
    background: rgba(255, 255, 255, 0.05);
    border: none;
    border-radius: 8px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: var(--transition-fast);
}}

.modal-close:hover {{
    background: rgba(255, 82, 82, 0.15);
    transform: rotate(90deg);
}}

/* ==================== Table ==================== */

.table-container {{
    background: var(--glass-bg);
    backdrop-filter: var(--glass-backdrop);
    -webkit-backdrop-filter: var(--glass-backdrop);
    border: 1px solid var(--glass-border);
    border-radius: var(--border-radius);
    overflow: hidden;
    box-shadow: var(--glass-shadow);
}}

.table {{
    width: 100%;
    border-collapse: collapse;
}}

.table thead {{
    background: rgba(0, 217, 163, 0.08);
}}

.table th {{
    color: var(--color-text-primary);
    font-weight: 600;
    font-size: 13px;
    padding: 16px 20px;
    text-align: left;
    border-bottom: 1px solid var(--glass-border);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

.table td {{
    padding: 16px 20px;
    color: var(--color-text-secondary);
    border-bottom: 1px solid rgba(0, 217, 163, 0.05);
    font-size: 14px;
}}

.table tbody tr {{
    transition: var(--transition-fast);
}}

.table tbody tr:hover {{
    background: rgba(0, 217, 163, 0.06);
}}

.table tbody tr:last-child td {{
    border-bottom: none;
}}

/* ==================== Badge ==================== */

.badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border-radius: 10px;
    font-size: 13px;
    font-weight: 500;
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    white-space: nowrap;
}}

.badge-success {{
    background: rgba(0, 230, 118, 0.15);
    color: var(--color-success);
    border: 1px solid rgba(0, 230, 118, 0.3);
}}

.badge-warning {{
    background: rgba(255, 214, 0, 0.15);
    color: var(--color-warning);
    border: 1px solid rgba(255, 214, 0, 0.3);
}}

.badge-error {{
    background: rgba(255, 82, 82, 0.15);
    color: var(--color-error);
    border: 1px solid rgba(255, 82, 82, 0.3);
}}

.badge-info {{
    background: rgba(0, 184, 212, 0.15);
    color: var(--color-info);
    border: 1px solid rgba(0, 184, 212, 0.3);
}}

.badge-primary {{
    background: rgba(0, 217, 163, 0.15);
    color: var(--color-primary);
    border: 1px solid rgba(0, 217, 163, 0.3);
}}

/* ==================== Card Variants ==================== */

.card-hover {{
    transition: var(--transition);
}}

.card-hover:hover {{
    transform: translateY(-6px);
    box-shadow: var(--shadow-lg);
}}

.card-gradient {{
    background: var(--gradient-primary);
    color: var(--color-background);
    border: none;
}}

.card-outline {{
    background: transparent;
    border: 2px solid var(--glass-border);
}}

/* ==================== Scrollbar ==================== */

::-webkit-scrollbar {{
    width: 10px;
    height: 10px;
}}

::-webkit-scrollbar-track {{
    background: var(--glass-bg);
    border-radius: 10px;
}}

::-webkit-scrollbar-thumb {{
    background: var(--gradient-primary);
    border-radius: 10px;
    border: 2px solid transparent;
    background-clip: padding-box;
}}

::-webkit-scrollbar-thumb:hover {{
    background: var(--color-primary);
    background-clip: padding-box;
}}

/* ==================== Tooltip ==================== */

.tooltip {{
    position: relative;
    display: inline-block;
}}

.tooltip-text {{
    visibility: hidden;
    background: var(--glass-bg);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    color: var(--color-text-primary);
    text-align: center;
    border-radius: 10px;
    padding: 8px 14px;
    position: absolute;
    z-index: 1;
    bottom: 125%;
    left: 50%;
    transform: translateX(-50%);
    opacity: 0;
    transition: opacity 0.3s, transform 0.3s;
    border: 1px solid var(--glass-border);
    font-size: 13px;
    white-space: nowrap;
    box-shadow: var(--shadow-sm);
}}

.tooltip-text::after {{
    content: '';
    position: absolute;
    top: 100%;
    left: 50%;
    margin-left: -5px;
    border-width: 5px;
    border-style: solid;
    border-color: var(--glass-border) transparent transparent transparent;
}}

.tooltip:hover .tooltip-text {{
    visibility: visible;
    opacity: 1;
    transform: translateX(-50%) translateY(-4px);
}}

/* ==================== Loading Spinner ==================== */

.spinner {{
    width: 50px;
    height: 50px;
    border: 4px solid var(--glass-border);
    border-top: 4px solid var(--color-primary);
    border-radius: 50%;
    animation: spin 1s cubic-bezier(0.68, -0.55, 0.265, 1.55) infinite;
}}

@keyframes spin {{
    0% {{ transform: rotate(0deg); }}
    100% {{ transform: rotate(360deg); }}
}}

.spinner-gradient {{
    width: 50px;
    height: 50px;
    border: 4px solid transparent;
    border-radius: 50%;
    background: var(--gradient-primary);
    -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
    animation: spin 1s linear infinite;
    padding: 4px;
}}

/* ==================== Switch Toggle ==================== */

.switch {{
    position: relative;
    display: inline-block;
    width: 52px;
    height: 30px;
}}

.switch input {{
    opacity: 0;
    width: 0;
    height: 0;
}}

.slider {{
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: var(--glass-bg);
    backdrop-filter: blur(10px);
    border: 1px solid var(--glass-border);
    transition: var(--transition);
    border-radius: 30px;
}}

.slider:before {{
    position: absolute;
    content: "";
    height: 22px;
    width: 22px;
    left: 4px;
    bottom: 3px;
    background: var(--color-text-secondary);
    transition: var(--transition);
    border-radius: 50%;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
}}

input:checked + .slider {{
    background: var(--gradient-primary);
    border-color: transparent;
}}

input:checked + .slider:before {{
    transform: translateX(22px);
    background: white;
}}

/* ==================== Alert ==================== */

.alert {{
    padding: 16px 20px;
    border-radius: 12px;
    margin-bottom: 16px;
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border: 1px solid;
    display: flex;
    align-items: center;
    gap: 12px;
}}

.alert-success {{
    background: rgba(0, 230, 118, 0.12);
    border-color: rgba(0, 230, 118, 0.3);
    color: var(--color-success);
}}

.alert-warning {{
    background: rgba(255, 214, 0, 0.12);
    border-color: rgba(255, 214, 0, 0.3);
    color: var(--color-warning);
}}

.alert-error {{
    background: rgba(255, 82, 82, 0.12);
    border-color: rgba(255, 82, 82, 0.3);
    color: var(--color-error);
}}

.alert-info {{
    background: rgba(0, 184, 212, 0.12);
    border-color: rgba(0, 184, 212, 0.3);
    color: var(--color-info);
}}

/* ==================== Container & Layout ==================== */

.container {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}}

.section {{
    margin-bottom: 48px;
}}

.section-title {{
    font-size: 32px;
    font-weight: 700;
    margin-bottom: 24px;
    background: var(--gradient-primary);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: -0.5px;
}}

.section-subtitle {{
    font-size: 16px;
    color: var(--color-text-secondary);
    margin-bottom: 32px;
    line-height: 1.6;
}}

/* ==================== Grid System ==================== */

.grid {{
    display: grid;
    gap: 24px;
}}

.grid-2 {{
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
}}

.grid-3 {{
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}}

.grid-4 {{
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
}}

/* ==================== Flex Utilities ==================== */

.flex {{
    display: flex;
}}

.flex-col {{
    flex-direction: column;
}}

.items-center {{
    align-items: center;
}}

.justify-center {{
    justify-content: center;
}}

.justify-between {{
    justify-content: space-between;
}}

.gap-2 {{
    gap: 8px;
}}

.gap-4 {{
    gap: 16px;
}}

.gap-6 {{
    gap: 24px;
}}

/* ==================== Spacing Utilities ==================== */

.mt-2 {{ margin-top: 8px; }}
.mt-4 {{ margin-top: 16px; }}
.mt-6 {{ margin-top: 24px; }}
.mb-2 {{ margin-bottom: 8px; }}
.mb-4 {{ margin-bottom: 16px; }}
.mb-6 {{ margin-bottom: 24px; }}
.p-2 {{ padding: 8px; }}
.p-4 {{ padding: 16px; }}
.p-6 {{ padding: 24px; }}

/* ==================== Text Utilities ==================== */

.text-center {{ text-align: center; }}
.text-left {{ text-align: left; }}
.text-right {{ text-align: right; }}

.text-sm {{ font-size: 13px; }}
.text-base {{ font-size: 15px; }}
.text-lg {{ font-size: 18px; }}
.text-xl {{ font-size: 24px; }}

.font-normal {{ font-weight: 400; }}
.font-medium {{ font-weight: 500; }}
.font-semibold {{ font-weight: 600; }}
.font-bold {{ font-weight: 700; }}

/* ==================== Animations ==================== */

@keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.6; }}
}}

@keyframes bounce {{
    0%, 100% {{ transform: translateY(0); }}
    50% {{ transform: translateY(-10px); }}
}}

.animate-pulse {{
    animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}}

.animate-bounce {{
    animation: bounce 1s infinite;
}}

/* ==================== Hover Effects ==================== */

.hover-lift {{
    transition: var(--transition);
}}

.hover-lift:hover {{
    transform: translateY(-4px);
}}

.hover-glow {{
    transition: var(--transition);
}}

.hover-glow:hover {{
    box-shadow: 0 0 30px rgba(0, 217, 163, 0.4);
}}

/* ==================== Responsive Design ==================== */

@media (max-width: 768px) {{
    .glass-card {{
        padding: 20px;
    }}
    
    .glass-panel {{
        padding: 24px;
    }}
    
    .btn {{
        padding: 10px 20px;
        font-size: 14px;
    }}
    
    .section-title {{
        font-size: 24px;
    }}
    
    .modal {{
        padding: 24px;
        margin: 16px;
    }}
    
    .grid-2,
    .grid-3,
    .grid-4 {{
        grid-template-columns: 1fr;
    }}
    
    .table {{
        font-size: 13px;
    }}
    
    .table th,
    .table td {{
        padding: 12px 16px;
    }}
}}

@media (max-width: 480px) {{
    body {{
        font-size: 14px;
    }}
    
    .glass-card {{
        padding: 16px;
    }}
    
    .section-title {{
        font-size: 20px;
    }}
    
    .btn {{
        padding: 8px 16px;
        font-size: 13px;
    }}
}}

/* ==================== Print Styles ==================== */

@media print {{
    body::before {{
        display: none;
    }}
    
    .glass-card,
    .glass-panel {{
        background: white;
        border: 1px solid #ddd;
        box-shadow: none;
    }}
    
    .btn {{
        border: 1px solid #333;
    }}
}}

/* ==================== Accessibility ==================== */

.sr-only {{
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
}}

:focus-visible {{
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
}}

/* High contrast mode support */
@media (prefers-contrast: high) {{
    .glass-card,
    .glass-panel {{
        border-width: 2px;
    }}
}}

/* Reduced motion support */
@media (prefers-reduced-motion: reduce) {{
    *,
    *::before,
    *::after {{
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
    }}
}}

/* ==================== END iOS Liquid Glass Theme ==================== */
'''
    
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
    
    print("\nGenerating CSS...")
    css = theme_manager.get_css()
    
    with open('ios_liquid_glass_theme.css', 'w', encoding='utf-8') as f:
        f.write(css)
    
    print("✅ CSS file generated: ios_liquid_glass_theme.css")
    
    print("\nExporting theme config...")
    theme_manager.export_theme_config()
    print("✅ Theme config exported: theme_config.json")
    
    print("\nColor Palette:")
    palette = theme_manager.get_color_palette()
    for color_name, color_value in palette.items():
        print(f"  {color_name}: {color_value}")
