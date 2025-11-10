from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QComboBox, QCheckBox, QSpinBox,
                             QGroupBox, QFormLayout)
from PyQt6.QtCore import pyqtSignal
from utils.config import Config

class SettingsTab(QWidget):
    theme_changed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.config = Config()
        self.init_ui()
    
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)
        
        display_group = QGroupBox('Display Settings')
        display_layout = QFormLayout()
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(['Dark', 'Light'])
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        display_layout.addRow('Theme:', self.theme_combo)
        
        display_group.setLayout(display_layout)
        main_layout.addWidget(display_group)
        
        scan_group = QGroupBox('Scan Settings')
        scan_layout = QFormLayout()
        
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(5, 300)
        self.timeout_spinbox.setValue(30)
        self.timeout_spinbox.setSuffix(' seconds')
        scan_layout.addRow('Timeout:', self.timeout_spinbox)
        
        self.max_threads_spinbox = QSpinBox()
        self.max_threads_spinbox.setRange(1, 100)
        self.max_threads_spinbox.setValue(10)
        scan_layout.addRow('Max Threads:', self.max_threads_spinbox)
        
        self.verify_ssl_checkbox = QCheckBox('Verify SSL')
        self.verify_ssl_checkbox.setChecked(False)
        scan_layout.addRow('', self.verify_ssl_checkbox)
        
        scan_group.setLayout(scan_layout)
        main_layout.addWidget(scan_group)
        
        button_layout = QHBoxLayout()
        
        save_button = QPushButton('💾 Save Settings')
        save_button.clicked.connect(self.save_settings)
        button_layout.addWidget(save_button)
        
        reset_button = QPushButton('🔄 Reset to Defaults')
        reset_button.clicked.connect(self.reset_settings)
        button_layout.addWidget(reset_button)
        
        main_layout.addLayout(button_layout)
        main_layout.addStretch()
        
        self.setLayout(main_layout)
    
    def on_theme_changed(self, theme: str):
        self.theme_changed.emit(theme.lower())
    
    def save_settings(self):
        settings = {
            'theme': self.theme_combo.currentText().lower(),
            'timeout': self.timeout_spinbox.value(),
            'max_threads': self.max_threads_spinbox.value(),
            'verify_ssl': self.verify_ssl_checkbox.isChecked()
        }
        self.config.save(settings)
    
    def reset_settings(self):
        self.config.reset()