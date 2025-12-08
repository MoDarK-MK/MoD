import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from gui.main_window import MainWindow
from utils.config import Config


def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    
    app = QApplication(sys.argv)
    
    app.setApplicationName("MoD - Master of Defense v4.0")
    app.setApplicationVersion("4.0.0")
    app.setOrganizationName("MoD Security")
    
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    try:
        config = Config()
        # Skip update checker for now - go straight to main window
        
        window = MainWindow()
        window.showMaximized()  # Ensure fullscreen on startup
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
