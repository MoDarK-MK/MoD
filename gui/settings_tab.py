# gui/settings_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QGroupBox, QComboBox, QCheckBox, QTextEdit,
                             QMessageBox, QTabWidget, QSpinBox, QFrame)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from gui.theme_manager import ThemeManager


class SettingsTab(QWidget):
    theme_changed = pyqtSignal(str)
    settings_changed = pyqtSignal(dict)
    
    def __init__(self, theme_manager: ThemeManager):
        super().__init__()
        self.theme_manager = theme_manager
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        title = QLabel('⚙️ APPLICATION SETTINGS')
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        main_layout.addWidget(title)
        
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        main_layout.addWidget(separator)
        
        tabs = QTabWidget()
        
        tabs.addTab(self.create_general_settings_tab(), '🎨 GENERAL')
        tabs.addTab(self.create_ai_settings_tab(), '🤖 AI INTEGRATION')
        tabs.addTab(self.create_scanner_settings_tab(), '🔍 SCANNER CONFIG')
        
        main_layout.addWidget(tabs, 1)
        
        self.setLayout(main_layout)
    
    def get_stylesheet_for_theme(self):
        current_theme = self.theme_manager.current_theme
        colors = self.theme_manager.get_theme(current_theme)['colors']
        
        is_dark = any(x in current_theme.lower() for x in ['dark', 'cyber', 'neon', 'blood', 'ocean', 'midnight', 'toxic', 'dracula', 'electric', 'pink'])
        
        if is_dark:
            primary_color = colors.primary
            bg_color = colors.background
            surface_color = colors.surface.split('(')[1].split(')')[0] if 'rgba' in colors.surface else colors.surface
            if 'rgba' in colors.surface:
                rgba_parts = surface_color.split(',')
                surface_color = f"#{int(float(rgba_parts[0])):02x}{int(float(rgba_parts[1])):02x}{int(float(rgba_parts[2])):02x}"
            text_color = colors.text_primary
            text_secondary = colors.text_secondary
            border_color = colors.border.split('(')[0] if 'rgba' in colors.border else colors.border
            if 'rgba' in colors.border:
                border_parts = colors.border.split('(')[1].split(')')[0].split(',')
                border_color = f"#{int(float(border_parts[0])):02x}{int(float(border_parts[1])):02x}{int(float(border_parts[2])):02x}"
            hover_color = colors.accent
        else:
            primary_color = colors.primary
            bg_color = colors.background
            surface_color = colors.surface.split('(')[1].split(')')[0] if 'rgba' in colors.surface else colors.surface
            if 'rgba' in colors.surface:
                rgba_parts = surface_color.split(',')
                surface_color = f"#{int(float(rgba_parts[0])):02x}{int(float(rgba_parts[1])):02x}{int(float(rgba_parts[2])):02x}"
            else:
                surface_color = '#F8FAFC'
            text_color = colors.text_primary
            text_secondary = colors.text_secondary
            border_color = colors.border.split('(')[0] if 'rgba' in colors.border else colors.border
            if 'rgba' in colors.border:
                border_parts = colors.border.split('(')[1].split(')')[0].split(',')
                border_color = f"#{int(float(border_parts[0])):02x}{int(float(border_parts[1])):02x}{int(float(border_parts[2])):02x}"
            else:
                border_color = '#D0D7DE'
            hover_color = colors.accent
        
        return {
            'primary': primary_color,
            'background': bg_color,
            'surface': surface_color,
            'text': text_color,
            'text_secondary': text_secondary,
            'border': border_color,
            'hover': hover_color,
            'is_dark': is_dark
        }
    
    def create_general_settings_tab(self):
        widget = QWidget()
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        styles = self.get_stylesheet_for_theme()
        
        widget.setStyleSheet(f"background: {styles['background']};")
        
        theme_group = QGroupBox('🎨 APPLICATION THEME')
        theme_group.setStyleSheet(f"""
            QGroupBox {{
                color: {styles['text']};
                font-weight: bold;
                border: 2px solid {styles['border']};
                border-radius: 8px;
                padding-top: 12px;
                background: {styles['surface']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: {styles['primary']};
            }}
        """)
        
        theme_layout = QVBoxLayout()
        theme_layout.setSpacing(12)
        
        theme_select_layout = QHBoxLayout()
        theme_label = QLabel('Current Theme:')
        theme_label.setStyleSheet(f'color: {styles["text"]}; font-weight: bold; min-width: 120px;')
        theme_label.setMinimumHeight(36)
        
        self.theme_combo = QComboBox()
        self.theme_combo.setMinimumHeight(40)
        
        theme_display_names = self.theme_manager.get_theme_display_names()
        for theme_key, theme_name in theme_display_names.items():
            self.theme_combo.addItem(theme_name, theme_key)
        
        current_theme = self.theme_manager.current_theme
        index = self.theme_combo.findData(current_theme)
        if index >= 0:
            self.theme_combo.setCurrentIndex(index)
        
        combo_stylesheet = f"""
            QComboBox {{
                background: {styles['background']};
                color: {styles['text']};
                border: 2px solid {styles['border']};
                border-radius: 6px;
                padding: 8px 12px;
                font-weight: bold;
                font-size: 12pt;
            }}
            QComboBox:hover {{
                border: 2px solid {styles['primary']};
            }}
            QComboBox:focus {{
                border: 2px solid {styles['primary']};
                background: {styles['surface']};
            }}
            QComboBox::drop-down {{
                border: none;
                width: 30px;
            }}
            QComboBox::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid {styles['text']};
                margin-right: 10px;
            }}
            QComboBox QAbstractItemView {{
                background: {styles['surface']};
                color: {styles['text']};
                border: 2px solid {styles['primary']};
                border-radius: 6px;
                selection-background-color: {styles['primary']};
                selection-color: #ffffff;
                padding: 4px;
            }}
        """
        self.theme_combo.setStyleSheet(combo_stylesheet)
        self.theme_combo.currentIndexChanged.connect(self.on_theme_changed)
        
        theme_select_layout.addWidget(theme_label)
        theme_select_layout.addWidget(self.theme_combo, 1)
        theme_layout.addLayout(theme_select_layout)
        
        theme_desc_layout = QHBoxLayout()
        self.theme_desc_label = QLabel('Select a theme to change the application appearance')
        self.theme_desc_label.setStyleSheet(f'color: {styles["text_secondary"]}; font-size: 10pt;')
        self.theme_desc_label.setWordWrap(True)
        theme_desc_layout.addWidget(self.theme_desc_label)
        theme_layout.addLayout(theme_desc_layout)
        
        preview_layout = QHBoxLayout()
        preview_info = QLabel('💡 Changes will be applied immediately')
        preview_info.setStyleSheet(f'color: {styles["primary"]}; font-size: 10pt; font-weight: bold;')
        preview_layout.addWidget(preview_info)
        preview_layout.addStretch()
        theme_layout.addLayout(preview_layout)
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        display_group = QGroupBox('🖥️ DISPLAY SETTINGS')
        display_group.setStyleSheet(f"""
            QGroupBox {{
                color: {styles['text']};
                font-weight: bold;
                border: 2px solid {styles['border']};
                border-radius: 8px;
                padding-top: 12px;
                background: {styles['surface']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: {styles['primary']};
            }}
        """)
        
        display_layout = QVBoxLayout()
        display_layout.setSpacing(12)
        
        auto_minimize_check = QCheckBox('Minimize to system tray')
        auto_minimize_check.setChecked(True)
        auto_minimize_check.setStyleSheet(f"""
            QCheckBox {{
                color: {styles['text']};
                font-weight: bold;
                font-size: 11pt;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid {styles['border']};
                background: {styles['background']};
            }}
            QCheckBox::indicator:checked {{
                background: {styles['primary']};
                border: 2px solid {styles['primary']};
            }}
        """)
        self.auto_minimize_check = auto_minimize_check
        display_layout.addWidget(auto_minimize_check)
        
        notifications_check = QCheckBox('Show desktop notifications')
        notifications_check.setChecked(True)
        notifications_check.setStyleSheet(f"""
            QCheckBox {{
                color: {styles['text']};
                font-weight: bold;
                font-size: 11pt;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid {styles['border']};
                background: {styles['background']};
            }}
            QCheckBox::indicator:checked {{
                background: {styles['primary']};
                border: 2px solid {styles['primary']};
            }}
        """)
        self.notifications_check = notifications_check
        display_layout.addWidget(notifications_check)
        
        auto_update_check = QCheckBox('Check for updates automatically')
        auto_update_check.setChecked(True)
        auto_update_check.setStyleSheet(f"""
            QCheckBox {{
                color: {styles['text']};
                font-weight: bold;
                font-size: 11pt;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid {styles['border']};
                background: {styles['background']};
            }}
            QCheckBox::indicator:checked {{
                background: {styles['primary']};
                border: 2px solid {styles['primary']};
            }}
        """)
        self.auto_update_check = auto_update_check
        display_layout.addWidget(auto_update_check)
        
        display_group.setLayout(display_layout)
        layout.addWidget(display_group)
        
        layout.addStretch()
        
        save_layout = QHBoxLayout()
        save_layout.addStretch()
        
        save_btn = QPushButton('💾 SAVE SETTINGS')
        save_btn.setMinimumHeight(40)
        save_btn.setMinimumWidth(180)
        save_btn.clicked.connect(self.save_settings)
        save_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 {styles['primary']},
                                           stop:1 rgba(0, 0, 0, 0.2));
                color: white;
                border: 2px solid {styles['primary']};
                border-radius: 6px;
                font-weight: bold;
                font-size: 11pt;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 rgba(255, 255, 255, 0.1),
                                           stop:1 {styles['primary']});
            }}
            QPushButton:pressed {{
                padding-top: 2px;
            }}
        """)
        save_layout.addWidget(save_btn)
        
        layout.addLayout(save_layout)
        
        return widget
    
    def create_ai_settings_tab(self):
        widget = QWidget()
        
        styles = self.get_stylesheet_for_theme()
        widget.setStyleSheet(f"background: {styles['background']};")
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        ai_group = QGroupBox('🤖 AI MODEL CONFIGURATION')
        ai_group.setStyleSheet(f"""
            QGroupBox {{
                color: {styles['text']};
                font-weight: bold;
                border: 2px solid {styles['border']};
                border-radius: 8px;
                padding-top: 12px;
                background: {styles['surface']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: {styles['primary']};
            }}
        """)
        
        ai_layout = QVBoxLayout()
        ai_layout.setSpacing(12)
        
        provider_layout = QHBoxLayout()
        provider_label = QLabel('AI PROVIDER:')
        provider_label.setStyleSheet(f'color: {styles["text"]}; font-weight: bold; min-width: 150px;')
        provider_label.setMinimumHeight(40)
        
        self.ai_provider_combo = QComboBox()
        self.ai_provider_combo.addItems(['None', 'OpenAI (GPT-4)', 'Anthropic (Claude)', 'Google Gemini'])
        self.ai_provider_combo.setMinimumHeight(40)
        
        combo_stylesheet = f"""
            QComboBox {{
                background: {styles['background']};
                color: {styles['text']};
                border: 2px solid {styles['border']};
                border-radius: 6px;
                padding: 8px 12px;
                font-weight: bold;
                font-size: 11pt;
            }}
            QComboBox:hover {{
                border: 2px solid {styles['primary']};
            }}
            QComboBox QAbstractItemView {{
                background: {styles['surface']};
                color: {styles['text']};
                border: 2px solid {styles['primary']};
                selection-background-color: {styles['primary']};
                selection-color: white;
            }}
        """
        self.ai_provider_combo.setStyleSheet(combo_stylesheet)
        self.ai_provider_combo.currentTextChanged.connect(self.on_provider_changed)
        
        provider_layout.addWidget(provider_label)
        provider_layout.addWidget(self.ai_provider_combo, 1)
        ai_layout.addLayout(provider_layout)
        
        api_key_layout = QHBoxLayout()
        api_key_label = QLabel('API KEY:')
        api_key_label.setStyleSheet(f'color: {styles["text"]}; font-weight: bold; min-width: 150px;')
        api_key_label.setMinimumHeight(40)
        
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText('Enter your API key here...')
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setMinimumHeight(40)
        self.api_key_input.setStyleSheet(f"""
            QLineEdit {{
                background: {styles['background']};
                color: {styles['text']};
                border: 2px solid {styles['border']};
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 11pt;
                font-weight: bold;
            }}
            QLineEdit:focus {{
                border: 2px solid {styles['primary']};
                background: {styles['surface']};
            }}
        """)
        
        api_key_layout.addWidget(api_key_label)
        api_key_layout.addWidget(self.api_key_input, 1)
        ai_layout.addLayout(api_key_layout)
        
        test_layout = QHBoxLayout()
        test_layout.addStretch()
        
        test_btn = QPushButton('🧪 TEST CONNECTION')
        test_btn.setMinimumHeight(40)
        test_btn.setMinimumWidth(160)
        test_btn.clicked.connect(self.test_ai_connection)
        test_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 {styles['primary']},
                                           stop:1 rgba(0, 0, 0, 0.2));
                color: white;
                border: 2px solid {styles['primary']};
                border-radius: 6px;
                font-weight: bold;
                font-size: 11pt;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                           stop:0 rgba(255, 255, 255, 0.1),
                                           stop:1 {styles['primary']});
            }}
        """)
        test_layout.addWidget(test_btn)
        
        ai_layout.addLayout(test_layout)
        
        ai_group.setLayout(ai_layout)
        layout.addWidget(ai_group)
        
        info_group = QGroupBox('📚 SUPPORTED AI PROVIDERS')
        info_group.setStyleSheet(f"""
            QGroupBox {{
                color: {styles['text']};
                font-weight: bold;
                border: 2px solid {styles['border']};
                border-radius: 8px;
                padding-top: 12px;
                background: {styles['surface']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: {styles['primary']};
            }}
        """)
        
        info_layout = QVBoxLayout()
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setStyleSheet(f"""
            QTextEdit {{
                background: {styles['background']};
                color: {styles['text']};
                border: 1px solid {styles['border']};
                border-radius: 6px;
                padding: 12px;
                font-size: 10pt;
                font-family: 'Courier New';
            }}
        """)
        
        info_content = """
🔹 OpenAI (GPT-4)
   Website: [https://openai.com/api/](https://openai.com/api/)
   API Key: [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
   Model: gpt-4


🔹 Anthropic (Claude)
   Website: [https://www.anthropic.com/](https://www.anthropic.com/)
   API Key: [https://console.anthropic.com/](https://console.anthropic.com/)
   Model: claude-3-opus-20240229


🔹 Google Gemini
   Website: [https://ai.google.dev/](https://ai.google.dev/)
   API Key: [https://makersuite.google.com/app/apikey](https://makersuite.google.com/app/apikey)
   Model: gemini-pro


💡 Without an API key, basic POC templates will be used.
With a valid API key, advanced POC generation and analysis will be available.
        """
        
        info_text.setText(info_content)
        info_layout.addWidget(info_text)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        layout.addStretch()
        return widget
    
    def create_scanner_settings_tab(self):
        widget = QWidget()
        
        styles = self.get_stylesheet_for_theme()
        widget.setStyleSheet(f"background: {styles['background']};")
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        scan_group = QGroupBox('🔍 SCANNER VERIFICATION SETTINGS')
        scan_group.setStyleSheet(f"""
            QGroupBox {{
                color: {styles['text']};
                font-weight: bold;
                border: 2px solid {styles['border']};
                border-radius: 8px;
                padding-top: 12px;
                background: {styles['surface']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: {styles['primary']};
            }}
        """)
        
        scan_layout = QVBoxLayout()
        scan_layout.setSpacing(12)
        
        verify_check = QCheckBox('✓ Enable Real Vulnerability Verification')
        verify_check.setChecked(True)
        verify_check.setStyleSheet(f"""
            QCheckBox {{
                color: {styles['text']};
                font-weight: bold;
                font-size: 11pt;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 20px;
                height: 20px;
                border-radius: 4px;
                border: 2px solid {styles['border']};
                background: {styles['background']};
            }}
            QCheckBox::indicator:checked {{
                background: {styles['primary']};
                border: 2px solid {styles['primary']};
            }}
        """)
        self.verify_check = verify_check
        scan_layout.addWidget(verify_check)
        
        info_label = QLabel('When enabled, the scanner will verify each detected vulnerability by testing actual parameters and payloads.')
        info_label.setStyleSheet(f'color: {styles["text_secondary"]}; font-size: 10pt; margin-left: 20px;')
        info_label.setWordWrap(True)
        scan_layout.addWidget(info_label)
        
        scan_layout.addSpacing(15)
        
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel('Verification Timeout:')
        timeout_label.setStyleSheet(f'color: {styles["text"]}; font-weight: bold; min-width: 200px;')
        timeout_label.setMinimumHeight(40)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        self.timeout_spin.setValue(10)
        self.timeout_spin.setSuffix(' seconds')
        self.timeout_spin.setMinimumHeight(40)
        self.timeout_spin.setMinimumWidth(120)
        self.timeout_spin.setStyleSheet(f"""
            QSpinBox {{
                background: {styles['background']};
                color: {styles['text']};
                border: 2px solid {styles['border']};
                border-radius: 6px;
                padding: 6px 10px;
                font-weight: bold;
            }}
            QSpinBox:focus {{
                border: 2px solid {styles['primary']};
            }}
        """)
        
        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_spin)
        timeout_layout.addStretch()
        scan_layout.addLayout(timeout_layout)
        
        retries_layout = QHBoxLayout()
        retries_label = QLabel('Max Verification Retries:')
        retries_label.setStyleSheet(f'color: {styles["text"]}; font-weight: bold; min-width: 200px;')
        retries_label.setMinimumHeight(40)
        
        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 10)
        self.retries_spin.setValue(3)
        self.retries_spin.setMinimumHeight(40)
        self.retries_spin.setMinimumWidth(120)
        self.retries_spin.setStyleSheet(f"""
            QSpinBox {{
                background: {styles['background']};
                color: {styles['text']};
                border: 2px solid {styles['border']};
                border-radius: 6px;
                padding: 6px 10px;
                font-weight: bold;
            }}
            QSpinBox:focus {{
                border: 2px solid {styles['primary']};
            }}
        """)
        
        retries_layout.addWidget(retries_label)
        retries_layout.addWidget(self.retries_spin)
        retries_layout.addStretch()
        scan_layout.addLayout(retries_layout)
        
        threads_layout = QHBoxLayout()
        threads_label = QLabel('Worker Threads:')
        threads_label.setStyleSheet(f'color: {styles["text"]}; font-weight: bold; min-width: 200px;')
        threads_label.setMinimumHeight(40)
        
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(5, 50)
        self.threads_spin.setValue(20)
        self.threads_spin.setMinimumHeight(40)
        self.threads_spin.setMinimumWidth(120)
        self.threads_spin.setStyleSheet(f"""
            QSpinBox {{
                background: {styles['background']};
                color: {styles['text']};
                border: 2px solid {styles['border']};
                border-radius: 6px;
                padding: 6px 10px;
                font-weight: bold;
            }}
            QSpinBox:focus {{
                border: 2px solid {styles['primary']};
            }}
        """)
        
        threads_layout.addWidget(threads_label)
        threads_layout.addWidget(self.threads_spin)
        threads_layout.addStretch()
        scan_layout.addLayout(threads_layout)
        
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)
        
        advanced_group = QGroupBox('⚡ ADVANCED OPTIONS')
        advanced_group.setStyleSheet(f"""
            QGroupBox {{
                color: {styles['text']};
                font-weight: bold;
                border: 2px solid {styles['border']};
                border-radius: 8px;
                padding-top: 12px;
                background: {styles['surface']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: {styles['primary']};
            }}
        """)
        
        advanced_layout = QVBoxLayout()
        advanced_layout.setSpacing(10)
        
        verify_ssl_check = QCheckBox('🔒 Verify SSL certificates')
        verify_ssl_check.setChecked(False)
        verify_ssl_check.setStyleSheet(f"""
            QCheckBox {{
                color: {styles['text']};
                font-weight: bold;
                font-size: 11pt;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid {styles['border']};
                background: {styles['background']};
            }}
            QCheckBox::indicator:checked {{
                background: {styles['primary']};
                border: 2px solid {styles['primary']};
            }}
        """)
        self.verify_ssl_check = verify_ssl_check
        advanced_layout.addWidget(verify_ssl_check)
        
        follow_redirects_check = QCheckBox('🔄 Follow HTTP redirects')
        follow_redirects_check.setChecked(True)
        follow_redirects_check.setStyleSheet(f"""
            QCheckBox {{
                color: {styles['text']};
                font-weight: bold;
                font-size: 11pt;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid {styles['border']};
                background: {styles['background']};
            }}
            QCheckBox::indicator:checked {{
                background: {styles['primary']};
                border: 2px solid {styles['primary']};
            }}
        """)
        self.follow_redirects_check = follow_redirects_check
        advanced_layout.addWidget(follow_redirects_check)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        layout.addStretch()
        return widget
    
    def on_theme_changed(self, index: int):
        theme_key = self.theme_combo.itemData(index)
        if theme_key:
            self.theme_manager.set_theme(theme_key)
            theme_name = self.theme_manager.THEMES[theme_key]['name']
            self.theme_desc_label.setText(f'Theme: {theme_name}')
            self.theme_changed.emit(theme_key)
    
    def on_provider_changed(self, provider: str):
        if provider == 'None':
            self.api_key_input.setEnabled(False)
            self.api_key_input.setText('')
        else:
            self.api_key_input.setEnabled(True)
    
    def test_ai_connection(self):
        provider = self.ai_provider_combo.currentText()
        api_key = self.api_key_input.text().strip()
        
        if provider == 'None':
            QMessageBox.warning(self, '⚠️ No Provider', 'Please select an AI provider first.')
            return
        
        if not api_key:
            QMessageBox.warning(self, '⚠️ Missing API Key', 'Please enter your API key.')
            return
        
        QMessageBox.information(
            self, 
            '🧪 Connection Test', 
            f'Testing connection to {provider}...\n\nThis feature requires active API configuration.'
        )
    
    def save_settings(self):
        settings = {
            'theme': self.theme_combo.itemData(self.theme_combo.currentIndex()),
            'ai_provider': self.ai_provider_combo.currentText(),
            'api_key': self.api_key_input.text(),
            'verify_vulnerabilities': self.verify_check.isChecked(),
            'verification_timeout': self.timeout_spin.value(),
            'verification_retries': self.retries_spin.value(),
            'worker_threads': self.threads_spin.value(),
            'verify_ssl': self.verify_ssl_check.isChecked(),
            'follow_redirects': self.follow_redirects_check.isChecked(),
            'auto_minimize': self.auto_minimize_check.isChecked(),
            'show_notifications': self.notifications_check.isChecked(),
            'auto_update': self.auto_update_check.isChecked(),
        }
        
        self.settings_changed.emit(settings)
        QMessageBox.information(self, '✅ Success', 'Settings saved successfully!')
