"""
MoD - Master of Defense v4.0.0.2
Professional Web Application Security Scanner
"""

import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from gui.main_window import MainWindow
from utils.config import Config
from utils.update_checker import run_update_checker_sync


def main():
    """Initialize and run the MoD application."""
    # Configure high DPI scaling for modern displays
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    
    app = QApplication(sys.argv)
    
    # Set application metadata
    app.setApplicationName("MoD - Master of Defense v4.0.0.2")
    app.setApplicationVersion("4.0.0.2")
    app.setOrganizationName("MoD Security")
    
    # Set default font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    try:
        # Initialize configuration
        config = Config()
        
        # Check for updates
        run_update_checker_sync()
        
        # Create and show main window
        window = MainWindow()
        window.showMaximized()
        
        # Start event loop
        return app.exec()
    
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
