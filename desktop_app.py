#!/usr/bin/env python3
"""
SecureX Threat Advisor - Desktop Application Launcher

Runs the real Flask + React dashboard in a background thread and displays it
in a native window via QWebEngineView, so the desktop app is pixel-identical
to the web dashboard with zero UI re-implementation.

Run with: python desktop_app.py
"""

import os
import secrets
import socket
import sys
import threading
import time

try:
    from PyQt6.QtCore import QUrl
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMessageBox
    from PyQt6.QtWebEngineWidgets import QWebEngineView
except ImportError:
    print("Error: PyQt6 (with WebEngine) not installed")
    print("\nInstall dependencies:")
    print("  pip install -r requirements-desktop.txt")
    sys.exit(1)

# When frozen by PyInstaller (--onedir):
#   - bundled read-only resources (config/, frontend/dist/, assets_build/)
#     live under _internal/, exposed at runtime as sys._MEIPASS
#   - the exe's own folder (sys.executable's directory) is where writable
#     state (.env, and the sqlite database via THREAT_DB_PATH below) should
#     live, since _internal is conceptually read-only bundle content
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
    RESOURCE_DIR = sys._MEIPASS
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    RESOURCE_DIR = APP_DIR
sys.path.insert(0, RESOURCE_DIR)

HOST = "127.0.0.1"
PORT = 5000


def _ensure_secret_key():
    """
    src.dashboard.app requires SECRET_KEY at import time. The web dashboard is
    normally launched from a shell where the operator has already exported it;
    the desktop app has no such shell, so generate one on first run and persist
    it to .env (created if missing) so sessions survive app restarts.
    """
    if os.environ.get("SECRET_KEY"):
        return

    env_path = os.path.join(APP_DIR, ".env")
    existing_lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            existing_lines = f.readlines()

    for line in existing_lines:
        if line.strip().startswith("SECRET_KEY=") and line.strip() != "SECRET_KEY=":
            os.environ["SECRET_KEY"] = line.strip().split("=", 1)[1]
            return

    new_key = secrets.token_hex(32)
    os.environ["SECRET_KEY"] = new_key

    with open(env_path, "a", encoding="utf-8") as f:
        if existing_lines and not existing_lines[-1].endswith("\n"):
            f.write("\n")
        f.write(f"SECRET_KEY={new_key}\n")


def _port_is_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex((host, port)) == 0


def _start_backend() -> threading.Thread:
    """Import and run the Flask/SocketIO app in a daemon thread."""
    from src.dashboard.app import app, socketio

    def _run():
        socketio.run(app, host=HOST, port=PORT, debug=False, use_reloader=False, log_output=False)

    thread = threading.Thread(target=_run, name="secureX-backend", daemon=True)
    thread.start()
    return thread


def _wait_for_backend(timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_is_open(HOST, PORT):
            return True
        time.sleep(0.2)
    return False


def main():
    # app.py resolves config/data paths relative to the process CWD, which a
    # double-clicked shortcut won't guarantee — pin it to where the bundled
    # (or, when not frozen, source-tree) resources actually live.
    os.chdir(RESOURCE_DIR)

    # The database is writable state, not bundle content — keep it next to
    # the exe (APP_DIR) so it survives reinstalls/updates of the bundle,
    # rather than defaulting into the read-only _internal folder.
    if getattr(sys, "frozen", False) and not os.environ.get("THREAT_DB_PATH"):
        data_dir = os.path.join(APP_DIR, "data", "db")
        os.makedirs(data_dir, exist_ok=True)
        os.environ["THREAT_DB_PATH"] = os.path.join(data_dir, "threats.db")

    _ensure_secret_key()

    dist_index = os.path.join(RESOURCE_DIR, "frontend", "dist", "index.html")
    if not os.path.exists(dist_index):
        print("Error: frontend build not found.")
        print(f"  Expected: {dist_index}")
        print("  Run `npm run build` inside the frontend/ directory first.")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("SecureX Threat Advisor")
    app.setApplicationVersion("1.2.0")

    icon_path = os.path.join(RESOURCE_DIR, "assets_build", "securex.ico")
    if not os.path.exists(icon_path):
        icon_path = os.path.join(RESOURCE_DIR, "frontend", "public", "favicon.svg")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    if not _port_is_open(HOST, PORT):
        _start_backend()
        if not _wait_for_backend():
            QMessageBox.critical(
                None,
                "SecureX Threat Advisor",
                f"The backend server did not start on {HOST}:{PORT} in time.",
            )
            sys.exit(1)

    view = QWebEngineView()
    view.setWindowTitle("SecureX Threat Advisor")
    if os.path.exists(icon_path):
        view.setWindowIcon(QIcon(icon_path))
    view.resize(1440, 900)
    view.load(QUrl(f"http://{HOST}:{PORT}/"))
    view.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
