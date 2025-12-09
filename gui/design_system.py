"""
Professional Design System for MoD Security Scanner v4.0.0.2
Organized, clean, and maintainable design patterns with consistent theming.
"""

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QScrollArea
)


class DesignColors:
    """Professional color palette with MoD branding."""
    
    # Primary colors
    DARK_BG = "#0F1419"       # Deep dark background
    CARD_BG = "#1A1F26"       # Card/surface background
    SURFACE = "#252A32"       # Elevated surface
    ACCENT = "#00D4FF"        # Cyan primary accent
    ACCENT_HOVER = "#00E5FF"  # Hover state
    ACCENT_DARK = "#00B8E6"   # Active/pressed state
    
    # Status colors
    DANGER = "#FF5252"        # Red for critical/danger
    SUCCESS = "#00E676"       # Green for success
    WARNING = "#FFB300"       # Orange for warning
    INFO = "#00D4FF"          # Cyan for info
    
    # Text colors
    TEXT_PRIMARY = "#FFFFFF"       # Main text (white)
    TEXT_SECONDARY = "#8B949E"     # Secondary text (gray)
    TEXT_TERTIARY = "#6E7681"      # Tertiary text (darker gray)
    TEXT_DISABLED = "#484F58"      # Disabled text
    
    # Borders and dividers
    BORDER = "#30363D"        # Default border
    BORDER_LIGHT = "#3D444D"  # Lighter border
    DIVIDER = "#21262D"       # Divider line


class DesignSpacing:
    """Consistent 4px-based spacing system."""
    
    XS = 4      # Extra small spacing
    SM = 8      # Small spacing
    MD = 12     # Medium spacing (default)
    LG = 16     # Large spacing
    XL = 24     # Extra large spacing
    XXL = 32    # Double extra large spacing
    
    # Component-specific heights
    INPUT_HEIGHT = 40
    BUTTON_HEIGHT = 40
    SECTION_HEIGHT = 50
    ITEM_SPACING = 8
    CARD_PADDING = 16
    PAGE_MARGIN = 24


class DesignTypography:
    """Typography system with consistent font hierarchy."""
    
    FONT_FAMILY = "Segoe UI, SF Pro Display, Arial, sans-serif"
    MONOSPACE_FAMILY = "Consolas, Monaco, Courier New, monospace"
    
    @staticmethod
    def title_large() -> QFont:
        """Large title font (24px, bold)."""
        font = QFont(DesignTypography.FONT_FAMILY)
        font.setPointSize(18)
        font.setBold(True)
        return font
    
    @staticmethod
    def title_medium() -> QFont:
        """Medium title font (18px, bold)."""
        font = QFont(DesignTypography.FONT_FAMILY)
        font.setPointSize(14)
        font.setBold(True)
        return font
    
    @staticmethod
    def title_small() -> QFont:
        """Small title font (16px, bold)."""
        font = QFont(DesignTypography.FONT_FAMILY)
        font.setPointSize(12)
        font.setBold(True)
        return font
    
    @staticmethod
    def body() -> QFont:
        """Body text font (14px, normal)."""
        font = QFont(DesignTypography.FONT_FAMILY)
        font.setPointSize(10)
        font.setWeight(QFont.Weight.Normal)
        return font
    
    @staticmethod
    def caption() -> QFont:
        """Caption text font (12px, normal)."""
        font = QFont(DesignTypography.FONT_FAMILY)
        font.setPointSize(9)
        font.setWeight(QFont.Weight.Normal)
        return font
    
    @staticmethod
    def monospace() -> QFont:
        """Monospace font for code (13px)."""
        font = QFont(DesignTypography.MONOSPACE_FAMILY)
        font.setPointSize(10)
        return font


class DesignButton(QPushButton):
    """Professional button component with multiple variants."""
    
    BUTTON_TYPES = {'primary', 'secondary', 'danger', 'success', 'ghost'}
    
    def __init__(self, text: str, button_type: str = "primary", parent=None):
        """Initialize styled button.
        
        Args:
            text: Button label text.
            button_type: Button style variant (primary, secondary, danger, success, ghost).
            parent: Parent widget.
        """
        super().__init__(text, parent)
        
        if button_type not in self.BUTTON_TYPES:
            raise ValueError(f"Invalid button_type: {button_type}. Must be one of {self.BUTTON_TYPES}")
        
        self.button_type = button_type
        self.setup_style()
    
    def setup_style(self) -> None:
        """Apply styling based on button type."""
        if self.button_type == "primary":
            bg = DesignColors.ACCENT
            text = DesignColors.DARK_BG
            hover_bg = DesignColors.ACCENT_HOVER
        elif self.button_type == "danger":
            bg = DesignColors.DANGER
            text = DesignColors.TEXT_PRIMARY
            hover_bg = "#FF5555"
        elif self.button_type == "success":
            bg = DesignColors.SUCCESS
            text = DesignColors.DARK_BG
            hover_bg = "#00FF66"
        else:  # secondary
            bg = DesignColors.CARD_BG
            text = DesignColors.TEXT_PRIMARY
            hover_bg = DesignColors.BORDER
        
        self.setMinimumHeight(40)
        self.setFont(DesignTypography.body())
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                color: {text};
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 10pt;
            }}
            QPushButton:hover {{
                background-color: {hover_bg};
            }}
            QPushButton:pressed {{
                background-color: {bg};
                opacity: 0.8;
            }}
        """)


class DesignCard(QFrame):
    """Professional card component"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_style()
    
    def setup_style(self):
        """Setup card styling"""
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {DesignColors.CARD_BG};
                border: 1px solid {DesignColors.BORDER};
                border-radius: 8px;
                padding: {DesignSpacing.MD}px;
            }}
        """)


class DesignHeader(QFrame):
    """Professional header component"""
    
    def __init__(self, title="", subtitle="", parent=None):
        super().__init__(parent)
        self.title_label = None
        self.subtitle_label = None
        self.setup_ui(title, subtitle)
    
    def setup_ui(self, title, subtitle):
        """Setup header UI"""
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {DesignColors.DARK_BG};
                border-bottom: 1px solid {DesignColors.BORDER};
                padding: {DesignSpacing.MD}px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(DesignSpacing.LG, DesignSpacing.MD, DesignSpacing.LG, DesignSpacing.MD)
        layout.setSpacing(DesignSpacing.SM)
        
        if title:
            self.title_label = QLabel(title)
            self.title_label.setFont(DesignTypography.title_medium())
            self.title_label.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
            layout.addWidget(self.title_label)
        
        if subtitle:
            self.subtitle_label = QLabel(subtitle)
            self.subtitle_label.setFont(DesignTypography.caption())
            self.subtitle_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
            layout.addWidget(self.subtitle_label)
    
    def set_title(self, title):
        """Set header title"""
        if not self.title_label:
            self.title_label = QLabel(title)
            self.title_label.setFont(DesignTypography.title_medium())
            self.title_label.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
            self.layout().insertWidget(0, self.title_label)
        else:
            self.title_label.setText(title)
    
    def set_subtitle(self, subtitle):
        """Set header subtitle"""
        if not self.subtitle_label:
            self.subtitle_label = QLabel(subtitle)
            self.subtitle_label.setFont(DesignTypography.caption())
            self.subtitle_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
            self.layout().addWidget(self.subtitle_label)
        else:
            self.subtitle_label.setText(subtitle)


class DesignDivider(QFrame):
    """Professional divider component"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.HLine)
        self.setFrameShadow(QFrame.Shadow.Plain)
        self.setMaximumHeight(1)
        self.setStyleSheet(f"background-color: {DesignColors.BORDER};")


class DesignSection(QFrame):
    """Professional section container"""
    
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.setup_ui(title)
    
    def setup_ui(self, title):
        """Setup section UI"""
        self.setStyleSheet("background-color: transparent; border: none;")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, DesignSpacing.LG, 0, DesignSpacing.MD)
        layout.setSpacing(DesignSpacing.MD)
        
        if title:
            title_label = QLabel(title)
            title_label.setFont(DesignTypography.title_small())
            title_label.setStyleSheet(f"""
                color: {DesignColors.ACCENT};
                padding: 0px {DesignSpacing.MD}px;
            """)
            layout.addWidget(title_label)
        
        self.content_layout = QVBoxLayout()
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(DesignSpacing.MD)
        layout.addLayout(self.content_layout)
    
    def add_widget(self, label_or_widget, widget=None):
        """Add widget to section with optional label"""
        if widget is None:
            # Single argument: just a widget
            self.content_layout.addWidget(label_or_widget)
        else:
            # Two arguments: label text and widget
            label_text = label_or_widget
            item_layout = QHBoxLayout()
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(DesignSpacing.MD)
            
            label = QLabel(label_text)
            label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
            label.setMinimumWidth(150)
            
            item_layout.addWidget(label)
            item_layout.addWidget(widget, 1)
            self.content_layout.addLayout(item_layout)
    
    def add_layout(self, layout):
        """Add layout to section"""
        self.content_layout.addLayout(layout)
    
    def layout(self):
        """Return the content layout"""
        return self.content_layout
    def add_layout(self, layout):
        """Add layout to section"""
        self.content_layout.addLayout(layout)


class DesignMainWidget(QWidget):
    """Professional main widget base class"""
    
    # Constants for spacing
    INPUT_HEIGHT = 40
    ITEM_SPACING = 8
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_background()
        self.setup_ui()
    
    def setup_background(self):
        """Setup main background"""
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {DesignColors.DARK_BG};
                color: {DesignColors.TEXT_PRIMARY};
            }}
        """)
    
    def setup_ui(self):
        """Setup the main UI structure"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header
        self.header = DesignHeader()
        main_layout.addWidget(self.header)
        
        # Scrollable content area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet(f"""
            QScrollArea {{
                background-color: {DesignColors.DARK_BG};
                border: none;
            }}
            {get_scrollbar_stylesheet()}
        """)
        
        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet(f"background-color: {DesignColors.DARK_BG};")
        scroll_layout = QVBoxLayout(self.scroll_content)
        scroll_layout.setContentsMargins(DesignSpacing.LG, DesignSpacing.LG, DesignSpacing.LG, DesignSpacing.LG)
        scroll_layout.setSpacing(DesignSpacing.LG)
        
        scroll_area.setWidget(self.scroll_content)
        main_layout.addWidget(scroll_area)
    
    def add_section(self, title=""):
        """Add a design section to the widget"""
        section = DesignSection(title)
        self.scroll_content.layout().addWidget(section)
        return section
    
    def add_stretch(self):
        """Add stretch at the end of content"""
        self.scroll_content.layout().addStretch()


def get_scrollbar_stylesheet():
    """Get scrollbar stylesheet"""
    return f"""
    QScrollBar:vertical {{
        background-color: {DesignColors.DARK_BG};
        width: 8px;
        border: none;
    }}
    QScrollBar::handle:vertical {{
        background-color: {DesignColors.BORDER};
        border-radius: 4px;
        min-height: 40px;
    }}
    QScrollBar::handle:vertical:hover {{
        background-color: {DesignColors.ACCENT};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        border: none;
        background: none;
    }}
    QScrollBar:horizontal {{
        background-color: {DesignColors.DARK_BG};
        height: 8px;
        border: none;
    }}
    QScrollBar::handle:horizontal {{
        background-color: {DesignColors.BORDER};
        border-radius: 4px;
        min-width: 40px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background-color: {DesignColors.ACCENT};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        border: none;
        background: none;
    }}
    """


def get_table_stylesheet():
    """Get table view stylesheet"""
    return f"""
    QTableWidget {{
        background-color: {DesignColors.DARK_BG};
        alternate-background-color: {DesignColors.CARD_BG};
        gridline-color: {DesignColors.BORDER};
        border: none;
    }}
    QTableWidget::item {{
        padding: {DesignSpacing.SM}px {DesignSpacing.MD}px;
        background-color: {DesignColors.DARK_BG};
        color: {DesignColors.TEXT_PRIMARY};
    }}
    QTableWidget::item:alternate {{
        background-color: {DesignColors.CARD_BG};
    }}
    QTableWidget::item:selected {{
        background-color: {DesignColors.ACCENT};
        color: {DesignColors.DARK_BG};
    }}
    QHeaderView::section {{
        background-color: {DesignColors.CARD_BG};
        color: {DesignColors.TEXT_PRIMARY};
        padding: {DesignSpacing.MD}px;
        border: none;
        border-bottom: 1px solid {DesignColors.BORDER};
        font-weight: bold;
    }}
    """


def get_input_stylesheet():
    """Get input field stylesheet"""
    return f"""
    QLineEdit, QTextEdit {{
        background-color: {DesignColors.CARD_BG};
        color: {DesignColors.TEXT_PRIMARY};
        border: 1px solid {DesignColors.BORDER};
        border-radius: 4px;
        padding: {DesignSpacing.MD}px;
        font-size: 10pt;
        selection-background-color: {DesignColors.ACCENT};
        selection-color: {DesignColors.DARK_BG};
    }}
    QLineEdit:focus, QTextEdit:focus {{
        border: 2px solid {DesignColors.ACCENT};
        padding: {DesignSpacing.MD - 1}px;
    }}
    """


def get_combobox_stylesheet():
    """Get combobox stylesheet"""
    return f"""
    QComboBox {{
        background-color: {DesignColors.CARD_BG};
        color: {DesignColors.TEXT_PRIMARY};
        border: 1px solid {DesignColors.BORDER};
        border-radius: 4px;
        padding: {DesignSpacing.SM}px {DesignSpacing.MD}px;
        min-height: 32px;
    }}
    QComboBox:focus {{
        border: 2px solid {DesignColors.ACCENT};
    }}
    QAbstractItemView {{
        background-color: {DesignColors.CARD_BG};
        color: {DesignColors.TEXT_PRIMARY};
        border: 1px solid {DesignColors.BORDER};
        selection-background-color: {DesignColors.ACCENT};
        selection-color: {DesignColors.DARK_BG};
    }}
    """
