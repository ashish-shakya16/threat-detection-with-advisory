#!/usr/bin/env python3
"""
SecureX Threat Advisor - Desktop Application Launcher

Run with: python desktop_app.py
"""

import sys
import os

# Check dependencies
try:
    from PyQt6.QtWidgets import QApplication, QMessageBox
    from PyQt6.QtCharts import QChart
except ImportError:
    print("Error: PyQt6 not installed")
    print("\nInstall dependencies:")
    print("  pip install PyQt6 PyQt6-Charts")
    print("\nOr install all desktop requirements:")
    print("  pip install -r requirements-desktop.txt")
    sys.exit(1)

# Add src to path
sys.path.insert(0, os.path.dirname(__file__))

from src.desktop.main_window import MainWindow


def main():
    """Launch the desktop application"""
    app = QApplication(sys.argv)

    # Application metadata
    app.setApplicationName("SecureX Threat Advisor")
    app.setApplicationVersion("1.2.0")

    # Create and show main window
    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
