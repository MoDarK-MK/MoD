import sys
from PyQt6.QtWidgets import QApplication, QToolBar, QWidget, QSizePolicy
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from gui.main_window import MainWindow
from utils.config import Config

spacer = QWidget()
spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
toolbar.addWidget(spacer)

def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    
    app = QApplication(sys.argv)
    
    app.setApplicationName("MoD - Master of Defense v3.0")
    app.setApplicationVersion("3.0.0")
    app.setOrganizationName("MoD Security")
    
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    try:
        config = Config()
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
