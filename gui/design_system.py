"""
Professional Design System for MoD Security Scanner
Organized, clean, and maintainable design patterns
"""

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QFrame, QScrollArea)


class DesignColors:
    """Professional color palette"""
    # Primary colors
    DARK_BG = "#0F1419"      # Dark background
    CARD_BG = "#1A1F26"      # Card background
    ACCENT = "#00D4FF"        # Cyan accent
    ACCENT_HOVER = "#00E5FF"  # Lighter cyan
    DANGER = "#FF3D3D"        # Red for danger
    SUCCESS = "#00FF41"       # Green for success
    WARNING = "#FFB800"       # Orange for warning
    
    # Text colors
    TEXT_PRIMARY = "#FFFFFF"
    TEXT_SECONDARY = "#B0B8C1"
    TEXT_TERTIARY = "#7A8290"
    
    # Borders and dividers
    BORDER = "#2A3139"
    DIVIDER = "#1F2530"


class DesignSpacing:
    """Consistent spacing system"""
    XS = 4
    SM = 8
    MD = 12
    LG = 16
    XL = 24
    XXL = 32


class DesignTypography:
    """Typography system"""
    
    @staticmethod
    def title_large():
        """Large title font"""
        font = QFont()
        font.setPointSize(18)
        font.setBold(True)
        return font
    
    @staticmethod
    def title_medium():
        """Medium title font"""
        font = QFont()
        font.setPointSize(14)
        font.setBold(True)
        return font
    
    @staticmethod
    def title_small():
        """Small title font"""
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        return font
    
    @staticmethod
    def body():
        """Body text font"""
        font = QFont()
        font.setPointSize(10)
        font.setWeight(QFont.Weight.Normal)
        return font
    
    @staticmethod
    def caption():
        """Caption text font"""
        font = QFont()
        font.setPointSize(8)
        font.setWeight(QFont.Weight.Normal)
        return font


class DesignButton(QPushButton):
    """Professional button component"""
    
    def __init__(self, text, button_type="primary", parent=None):
        super().__init__(text, parent)
        self.button_type = button_type
        self.setup_style()
    
    def setup_style(self):
        """Setup button styling"""
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
            title_label = QLabel(title)
            title_label.setFont(DesignTypography.title_medium())
            title_label.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
            layout.addWidget(title_label)
        
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setFont(DesignTypography.caption())
            subtitle_label.setStyleSheet(f"color: {DesignColors.TEXT_SECONDARY};")
            layout.addWidget(subtitle_label)


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
    
    def add_widget(self, widget):
        """Add widget to section"""
        self.content_layout.addWidget(widget)
    
    def add_layout(self, layout):
        """Add layout to section"""
        self.content_layout.addLayout(layout)


class DesignMainWidget(QWidget):
    """Professional main widget base class"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_background()
    
    def setup_background(self):
        """Setup main background"""
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {DesignColors.DARK_BG};
                color: {DesignColors.TEXT_PRIMARY};
            }}
        """)


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
