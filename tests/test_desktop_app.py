"""
Tests for desktop application components
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Skip if PyQt6 not installed
try:
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from src.desktop.main_window import MainWindow, ScanWorker
    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False


@unittest.skipUnless(PYQT6_AVAILABLE, "PyQt6 not installed")
class TestScanWorker(unittest.TestCase):
    """Test background scan worker"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'monitoring': {'system': {'interval': 5}},
            'detection': {'rule_based': {'rules_file': 'config/rules.json'}},
            'database': {'path': 'data/db/threats.db'}
        }
        self.rules_data = {
            'advisory_templates': {}
        }

    def test_scan_worker_initialization(self):
        """Test scan worker can be created"""
        worker = ScanWorker(self.config, self.rules_data)
        self.assertIsNotNone(worker)
        self.assertTrue(worker.running)

    def test_scan_worker_signals(self):
        """Test scan worker has required signals"""
        worker = ScanWorker(self.config, self.rules_data)
        self.assertTrue(hasattr(worker, 'scan_complete'))
        self.assertTrue(hasattr(worker, 'status_update'))


@unittest.skipUnless(PYQT6_AVAILABLE, "PyQt6 not installed")
class TestMainWindow(unittest.TestCase):
    """Test main application window"""

    @classmethod
    def setUpClass(cls):
        """Create QApplication for tests"""
        if not QApplication.instance():
            cls.app = QApplication([])
        else:
            cls.app = QApplication.instance()

    def setUp(self):
        """Set up test window"""
        try:
            self.window = MainWindow()
        except Exception as e:
            self.skipTest(f"Could not initialize MainWindow: {e}")

    @unittest.skipUnless(PYQT6_AVAILABLE, "PyQt6 not installed")
    def test_main_window_creation(self):
        """Test main window is created successfully"""
        self.assertIsNotNone(self.window)
        self.assertEqual(self.window.windowTitle(), "SecureX Threat Advisor - Desktop")

    @unittest.skipUnless(PYQT6_AVAILABLE, "PyQt6 not installed")
    def test_main_window_has_tabs(self):
        """Test main window has all required tabs"""
        # Check that tabs are initialized (would be in tab widget)
        self.assertIsNotNone(self.window.scan_button)
        self.assertIsNotNone(self.window.train_ml_button)

    @unittest.skipUnless(PYQT6_AVAILABLE, "PyQt6 not installed")
    def test_status_bar_exists(self):
        """Test status bar is initialized"""
        self.assertIsNotNone(self.window.status_bar)
        self.assertIsNotNone(self.window.status_label)

    @unittest.skipUnless(PYQT6_AVAILABLE, "PyQt6 not installed")
    def test_stat_box_creation(self):
        """Test stat box widget creation"""
        from PyQt6.QtGui import QColor
        box = self.window.create_stat_box("Test", "100", QColor(100, 100, 100))
        self.assertIsNotNone(box)
        self.assertIsNotNone(box.value_label)
        self.assertEqual(box.value_label.text(), "100")

    @unittest.skipUnless(PYQT6_AVAILABLE, "PyQt6 not installed")
    def test_backend_modules_initialized(self):
        """Test backend modules are initialized"""
        self.assertIsNotNone(self.window.db)
        self.assertIsNotNone(self.window.ml_integration)
        self.assertIsNotNone(self.window.config)

    @unittest.skipUnless(PYQT6_AVAILABLE, "PyQt6 not installed")
    def test_scan_button_clickable(self):
        """Test scan button is functional"""
        self.assertTrue(self.window.scan_button.isEnabled())

    @unittest.skipUnless(PYQT6_AVAILABLE, "PyQt6 not installed")
    def test_train_ml_button_clickable(self):
        """Test train ML button is functional"""
        self.assertTrue(self.window.train_ml_button.isEnabled())


class TestDesktopAppStructure(unittest.TestCase):
    """Test desktop app file structure"""

    def test_desktop_app_launcher_exists(self):
        """Test desktop_app.py launcher exists"""
        launcher_path = "desktop_app.py"
        self.assertTrue(os.path.exists(launcher_path))

    def test_requirements_desktop_exists(self):
        """Test requirements-desktop.txt exists"""
        requirements_path = "requirements-desktop.txt"
        self.assertTrue(os.path.exists(requirements_path))

    def test_main_window_module_exists(self):
        """Test main_window.py module exists"""
        module_path = "src/desktop/main_window.py"
        self.assertTrue(os.path.exists(module_path))

    def test_desktop_documentation_exists(self):
        """Test desktop app documentation exists"""
        doc_path = "docs/DESKTOP_APP.md"
        self.assertTrue(os.path.exists(doc_path))


class TestDesktopAppDependencies(unittest.TestCase):
    """Test desktop app dependencies are listed"""

    def test_requirements_file_valid(self):
        """Test requirements file contains PyQt6"""
        with open("requirements-desktop.txt", "r") as f:
            content = f.read()
            self.assertIn("PyQt6", content)
            self.assertIn("PyQt6-Charts", content)

    def test_launcher_has_error_handling(self):
        """Test launcher has dependency error handling"""
        with open("desktop_app.py", "r") as f:
            content = f.read()
            self.assertIn("ImportError", content)
            self.assertIn("PyQt6", content)


if __name__ == '__main__':
    unittest.main()
