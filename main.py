import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from gui.main_window import MainWindow
from utils.config import Config
from utils.update_checker import UpdateChecker, run_update_checker_sync


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
        checker = UpdateChecker()
        
        if checker.should_check_for_updates():
            run_update_checker_sync()
        
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
