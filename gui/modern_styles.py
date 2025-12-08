"""
Modern iOS-inspired design system with precise pixel grid (8px base unit)
Provides consistent, professional styling across all application components
"""

class ModernDesignSystem:
    """iOS-like design system with 8px grid, rounded corners, shadows, and smooth animations"""
    
    # 8px Grid System (8, 16, 24, 32, 40, 48, 56, 64px)
    SPACING = {
        'xs': '4px',    # Extra small
        'sm': '8px',    # Small
        'md': '16px',   # Medium
        'lg': '24px',   # Large
        'xl': '32px',   # Extra large
        'xxl': '40px',  # 2x large
        '3xl': '48px',  # 3x large
        '4xl': '56px',  # 4x large
        '5xl': '64px',  # 5x large
    }
    
    # Border radius (rounded corners like iOS)
    RADIUS = {
        'none': '0px',
        'sm': '6px',    # Subtle
        'md': '12px',   # Standard
        'lg': '16px',   # Large
        'xl': '20px',   # Extra large
        'full': '9999px'  # Pill-shaped
    }
    
    # Component heights (8px grid alignment)
    SIZES = {
        'button_sm': '32px',    # 4x8px
        'button_md': '40px',    # 5x8px
        'button_lg': '48px',    # 6x8px
        'input': '40px',        # 5x8px
        'label': '20px',        # 2.5x8px
        'progress': '4px',      # Thin progress bar
        'icon_sm': '16px',
        'icon_md': '24px',
        'icon_lg': '32px',
    }
    
    # Shadows (iOS-style, subtle and layered)
    SHADOWS = {
        'sm': '0 2px 8px rgba(0, 0, 0, 0.12)',
        'md': '0 4px 16px rgba(0, 0, 0, 0.15)',
        'lg': '0 8px 24px rgba(0, 0, 0, 0.18)',
        'xl': '0 12px 32px rgba(0, 0, 0, 0.2)',
        'inset': 'inset 0 1px 3px rgba(0, 0, 0, 0.1)',
    }
    
    # Animations/Transitions (smooth, modern)
    TRANSITIONS = {
        'fast': 'all 0.15s cubic-bezier(0.4, 0, 0.2, 1)',
        'normal': 'all 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
        'slow': 'all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
        'slowest': 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)',
    }
    
    # Font sizes (8px base rhythm)
    FONT_SIZES = {
        'xs': '11px',    # Extra small
        'sm': '12px',    # Small
        'base': '13px',  # Base
        'md': '14px',    # Medium
        'lg': '15px',    # Large
        'xl': '17px',    # Extra large
        '2xl': '19px',   # 2x large
        '3xl': '22px',   # 3x large
        'title': '28px',  # Title
        'hero': '32px',   # Hero
    }
    
    # Font weights (iOS standard)
    FONT_WEIGHT = {
        'thin': '100',
        'light': '300',
        'normal': '400',
        'medium': '500',
        'semibold': '600',
        'bold': '700',
        'extrabold': '800',
    }

def create_ios_button_style(bg_color: str, text_color: str, hover_color: str, primary: bool = False) -> str:
    """Generate iOS-style button stylesheet"""
    if primary:
        # Primary button - filled background
        return f"""
            QPushButton {{
                background: linear-gradient(135deg, {bg_color}, {hover_color});
                color: {text_color};
                border: none;
                border-radius: 12px;
                padding: 8px 16px;
                font-weight: 600;
                font-size: 14px;
                min-height: 40px;
                outline: none;
                transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            }}
            QPushButton:hover {{
                background: linear-gradient(135deg, {hover_color}, {bg_color});
                transform: translateY(-2px);
                box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
            }}
            QPushButton:pressed {{
                transform: translateY(0px);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            }}
        """
    else:
        # Secondary button - ghost style
        return f"""
            QPushButton {{
                background: rgba(255, 255, 255, 0.08);
                color: {text_color};
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                padding: 8px 16px;
                font-weight: 500;
                font-size: 14px;
                min-height: 40px;
                outline: none;
                transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            }}
            QPushButton:hover {{
                background: rgba(255, 255, 255, 0.12);
                border: 1px solid rgba(255, 255, 255, 0.3);
                transform: translateY(-2px);
            }}
            QPushButton:pressed {{
                background: rgba(255, 255, 255, 0.1);
                transform: translateY(0px);
            }}
        """

def create_ios_input_style(primary_color: str, text_color: str, bg_color: str) -> str:
    """Generate iOS-style input field stylesheet"""
    return f"""
        QLineEdit, QTextEdit, QSpinBox, QDoubleSpinBox {{
            background: rgba(255, 255, 255, 0.06);
            color: {text_color};
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 12px;
            padding: 8px 12px;
            font-size: 13px;
            selection-background-color: {primary_color};
            selection-color: white;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
            background: rgba(255, 255, 255, 0.08);
            border: 1.5px solid {primary_color};
            box-shadow: 0 0 0 3px rgba({primary_color[1:3]}, {primary_color[3:5]}, {primary_color[5:7]}, 0.1);
        }}
        QLineEdit::placeholder {{
            color: rgba(255, 255, 255, 0.4);
        }}
    """

def create_ios_combobox_style(primary_color: str, text_color: str) -> str:
    """Generate iOS-style combo box stylesheet"""
    return f"""
        QComboBox {{
            background: rgba(255, 255, 255, 0.06);
            color: {text_color};
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 12px;
            padding: 8px 12px;
            font-size: 13px;
            min-height: 40px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        QComboBox:focus {{
            background: rgba(255, 255, 255, 0.08);
            border: 1.5px solid {primary_color};
        }}
        QComboBox::drop-down {{
            border: none;
            width: 20px;
        }}
        QComboBox::down-arrow {{
            image: none;
            width: 12px;
            height: 12px;
        }}
    """

def create_ios_group_style(primary_color: str, text_color: str, surface_color: str) -> str:
    """Generate iOS-style group box stylesheet"""
    return f"""
        QGroupBox {{
            color: {text_color};
            font-weight: 600;
            font-size: 14px;
            border: none;
            background: {surface_color};
            border-radius: 16px;
            padding: 0px;
            margin-top: 8px;
            padding-top: 20px;
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 16px;
            padding: 0 4px;
            color: {primary_color};
        }}
    """

def create_ios_tab_style(primary_color: str, text_color: str, bg_color: str) -> str:
    """Generate iOS-style tab widget stylesheet"""
    return f"""
        QTabWidget::pane {{
            border: none;
            background: {bg_color};
            border-radius: 16px;
        }}
        QTabBar::tab {{
            background: rgba(255, 255, 255, 0.05);
            color: {text_color};
            border: none;
            padding: 8px 16px;
            margin: 2px;
            border-radius: 8px;
            font-weight: 500;
            font-size: 13px;
            min-width: 80px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        QTabBar::tab:hover {{
            background: rgba(255, 255, 255, 0.08);
        }}
        QTabBar::tab:selected {{
            background: linear-gradient(135deg, {primary_color}, {primary_color}dd);
            color: white;
            border-bottom: 3px solid {primary_color};
        }}
    """

def create_ios_scrollbar_style(primary_color: str) -> str:
    """Generate iOS-style scrollbar stylesheet"""
    return f"""
        QScrollBar:vertical {{
            background: transparent;
            width: 8px;
            margin: 0px;
        }}
        QScrollBar::handle:vertical {{
            background: {primary_color};
            border-radius: 4px;
            min-height: 24px;
            margin: 2px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        QScrollBar::handle:vertical:hover {{
            background: {primary_color}dd;
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            background: none;
            border: none;
        }}
        
        QScrollBar:horizontal {{
            background: transparent;
            height: 8px;
            margin: 0px;
        }}
        QScrollBar::handle:horizontal {{
            background: {primary_color};
            border-radius: 4px;
            min-width: 24px;
            margin: 2px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        QScrollBar::handle:horizontal:hover {{
            background: {primary_color}dd;
        }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            background: none;
            border: none;
        }}
    """

def create_ios_card_style(surface_color: str, border_color: str, shadow: str) -> str:
    """Generate iOS-style card/frame stylesheet"""
    return f"""
        QFrame {{
            background: {surface_color};
            border: 1px solid {border_color};
            border-radius: 16px;
            padding: 16px;
            box-shadow: {shadow};
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        QFrame:hover {{
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            transform: translateY(-4px);
        }}
    """

def create_ios_dialog_style(primary_color: str, text_color: str, bg_color: str) -> str:
    """Generate iOS-style dialog stylesheet"""
    return f"""
        QDialog {{
            background: {bg_color};
            border-radius: 24px;
        }}
        QDialog > QLabel {{
            color: {text_color};
        }}
    """

def create_ios_label_style(text_color: str, secondary_color: str) -> str:
    """Generate iOS-style label stylesheet"""
    return f"""
        QLabel {{
            color: {text_color};
            font-size: 13px;
            background: transparent;
        }}
        QLabel[secondary="true"] {{
            color: {secondary_color};
            font-size: 12px;
            opacity: 0.7;
        }}
    """

def create_ios_checkbox_style(primary_color: str, text_color: str) -> str:
    """Generate iOS-style checkbox stylesheet"""
    return f"""
        QCheckBox {{
            color: {text_color};
            font-size: 13px;
            spacing: 8px;
            background: transparent;
        }}
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border-radius: 5px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        QCheckBox::indicator:hover {{
            background: rgba(255, 255, 255, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }}
        QCheckBox::indicator:checked {{
            background: linear-gradient(135deg, {primary_color}, {primary_color}dd);
            border: 1px solid {primary_color};
            image: url(none);
        }}
    """

def create_ios_progressbar_style(primary_color: str, bg_color: str) -> str:
    """Generate iOS-style progress bar stylesheet"""
    return f"""
        QProgressBar {{
            background: {bg_color};
            border: none;
            border-radius: 4px;
            height: 4px;
            text-align: center;
            color: transparent;
        }}
        QProgressBar::chunk {{
            background: linear-gradient(90deg, {primary_color}, {primary_color}dd);
            border-radius: 4px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }}
    """
