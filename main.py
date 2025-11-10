import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from gui.main_window import MainWindow
from utils.config import Config

def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps)
    
    app = QApplication(sys.argv)
    app.setApplicationName("MoD - Master of Defense v3.0")
    app.setOrganizationName("MoD Security")
    
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    config = Config()
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()