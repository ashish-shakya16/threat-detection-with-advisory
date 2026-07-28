"""
Tests for the desktop application launcher.

The desktop app embeds the real Flask/React dashboard in a native
QWebEngineView rather than reimplementing the UI in PyQt6 widgets, so there
is no separate widget tree to unit test here — these tests cover the
launcher's own logic (secret-key persistence, port-readiness checking) and
basic structural/dependency checks.
"""

import importlib
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestDesktopAppStructure(unittest.TestCase):
    """Test desktop app file structure"""

    def test_desktop_app_launcher_exists(self):
        self.assertTrue(os.path.exists("desktop_app.py"))

    def test_requirements_desktop_exists(self):
        self.assertTrue(os.path.exists("requirements-desktop.txt"))

    def test_no_leftover_widget_ui_module(self):
        """main_window.py/theme.py were removed when the desktop app switched
        to embedding the web dashboard; they must not silently reappear."""
        self.assertFalse(os.path.exists("src/desktop/main_window.py"))
        self.assertFalse(os.path.exists("src/desktop/theme.py"))


class TestDesktopAppDependencies(unittest.TestCase):
    """Test desktop app dependencies are listed"""

    def test_requirements_file_valid(self):
        with open("requirements-desktop.txt", "r") as f:
            content = f.read()
            self.assertIn("PyQt6", content)
            self.assertIn("PyQt6-WebEngine", content)

    def test_launcher_has_error_handling(self):
        with open("desktop_app.py", "r") as f:
            content = f.read()
            self.assertIn("ImportError", content)
            self.assertIn("PyQt6", content)


class TestSecretKeyPersistence(unittest.TestCase):
    """
    src.dashboard.app requires SECRET_KEY at import time. The desktop app has
    no shell for an operator to export it in, so it must generate and persist
    one to .env on first run, and reuse the same key on subsequent runs.
    """

    def setUp(self):
        self.desktop_app = importlib.import_module("desktop_app")
        self.env_backup = os.environ.pop("SECRET_KEY", None)

    def tearDown(self):
        if self.env_backup is not None:
            os.environ["SECRET_KEY"] = self.env_backup
        else:
            os.environ.pop("SECRET_KEY", None)

    def test_generates_and_persists_key_when_env_file_missing(self):
        with patch("os.path.exists", return_value=False), \
             patch("builtins.open", unittest.mock.mock_open()) as mocked_open:
            self.desktop_app._ensure_secret_key()

        self.assertIn("SECRET_KEY", os.environ)
        self.assertEqual(len(os.environ["SECRET_KEY"]), 64)  # secrets.token_hex(32)
        mocked_open.assert_called_once()

    def test_reuses_existing_key_from_env_file(self):
        fake_env_content = "OTHER_VAR=1\nSECRET_KEY=existing-key-value\n"
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", unittest.mock.mock_open(read_data=fake_env_content)):
            self.desktop_app._ensure_secret_key()

        self.assertEqual(os.environ["SECRET_KEY"], "existing-key-value")

    def test_does_nothing_when_env_var_already_set(self):
        os.environ["SECRET_KEY"] = "already-set"
        with patch("builtins.open") as mocked_open:
            self.desktop_app._ensure_secret_key()

        mocked_open.assert_not_called()
        self.assertEqual(os.environ["SECRET_KEY"], "already-set")


class TestPortIsOpen(unittest.TestCase):
    """_port_is_open is what the launcher uses to detect an already-running
    backend and to poll readiness after starting one."""

    def setUp(self):
        self.desktop_app = importlib.import_module("desktop_app")

    def test_returns_false_for_a_port_nothing_is_listening_on(self):
        # Port 1 is a reserved/privileged port essentially never bound in tests.
        self.assertFalse(self.desktop_app._port_is_open("127.0.0.1", 1))


if __name__ == "__main__":
    unittest.main()
