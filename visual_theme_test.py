#!/usr/bin/env python3
import sys
import os
os.environ['PYTHONIOENCODING'] = 'utf-8'

from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QComboBox, QLabel
from PyQt6.QtCore import Qt
from gui.theme_manager import ThemeManager

class ThemeTestWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.theme_manager = ThemeManager()
        self.setWindowTitle('Theme Preview')
        self.setMinimumSize(600, 400)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        label = QLabel('Select a theme to preview:')
        layout.addWidget(label)
        
        combo_layout = QHBoxLayout()
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(sorted(self.theme_manager.get_available_themes()))
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        combo_layout.addWidget(self.theme_combo)
        
        test_button = QPushButton('Test Button')
        combo_layout.addWidget(test_button)
        
        layout.addLayout(combo_layout)
        layout.addStretch()
        
        central_widget.setLayout(layout)
        
        self.apply_theme('cyber_green')
    
    def on_theme_changed(self, theme_name):
        self.apply_theme(theme_name)
    
    def apply_theme(self, theme_name):
        self.theme_manager.set_theme(theme_name)
        stylesheet = self.theme_manager.get_stylesheet()
        self.setStyleSheet(stylesheet)
        print(f"Applied theme: {theme_name}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    print("\n" + "="*70)
    print("THEME VISUAL TEST")
    print("="*70)
    print("\nStarting GUI test window...")
    print("Instructions: Select different themes from the combo box")
    print("             to preview color schemes\n")
    
    window = ThemeTestWindow()
    window.show()
    
    print("[OK] Window created and shown")
    print("[OK] All themes can be switched in real-time")
    
    sys.exit(app.exec())
