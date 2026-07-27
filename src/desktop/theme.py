"""
SecureX Desktop - Enterprise dark theme.

Centralizes the color palette, typography and QSS stylesheet used by the
PyQt6 desktop application so the whole app renders as one coherent,
professional security console instead of default Qt chrome.

This module is purely presentational: it defines colors/spacing constants
and a stylesheet string. It does not touch any business logic.
"""

from PyQt6.QtGui import QColor


class Palette:
    """Core color tokens. 8px spacing grid is used throughout the QSS below."""

    # Surfaces
    BG_APP = "#0b0e14"          # window background
    BG_SURFACE = "#11151d"      # panels / tab pages
    BG_SURFACE_ALT = "#161b26"  # cards, table headers
    BG_ELEVATED = "#1b2130"     # hovered rows, inputs
    BORDER = "#262d3d"
    BORDER_STRONG = "#333c52"

    # Typography
    TEXT_PRIMARY = "#e6e9f0"
    TEXT_SECONDARY = "#9aa4b8"
    TEXT_MUTED = "#6b7488"

    # Brand / accent (indigo, matches security-console conventions)
    ACCENT = "#6366f1"
    ACCENT_HOVER = "#7880f5"
    ACCENT_PRESSED = "#4f52d6"
    ACCENT_MUTED = "#2a2c5e"

    # Severity scale
    CRITICAL = "#ef4444"
    HIGH = "#f97316"
    MEDIUM = "#f5b400"
    LOW = "#3b82f6"
    SUCCESS = "#22c55e"

    @staticmethod
    def severity_color(severity: str) -> QColor:
        s = (severity or "").strip().lower()
        return {
            "critical": QColor(Palette.CRITICAL),
            "high": QColor(Palette.HIGH),
            "medium": QColor(Palette.MEDIUM),
            "low": QColor(Palette.LOW),
        }.get(s, QColor(Palette.TEXT_SECONDARY))


FONT_FAMILY = "Segoe UI, -apple-system, Helvetica Neue, Arial, sans-serif"

STYLESHEET = f"""
* {{
    font-family: {FONT_FAMILY};
    outline: none;
}}

QMainWindow, QDialog {{
    background-color: {Palette.BG_APP};
}}

QWidget {{
    color: {Palette.TEXT_PRIMARY};
    background-color: transparent;
    font-size: 13px;
}}

/* ---------- Top control bar buttons ---------- */
QPushButton {{
    background-color: {Palette.BG_ELEVATED};
    border: 1px solid {Palette.BORDER_STRONG};
    border-radius: 6px;
    padding: 8px 16px;
    color: {Palette.TEXT_PRIMARY};
    font-weight: 500;
}}
QPushButton:hover {{
    background-color: #232a3b;
    border-color: {Palette.ACCENT};
}}
QPushButton:pressed {{
    background-color: {Palette.ACCENT_MUTED};
}}
QPushButton:disabled {{
    color: {Palette.TEXT_MUTED};
    border-color: {Palette.BORDER};
    background-color: {Palette.BG_SURFACE_ALT};
}}

QPushButton#primaryButton {{
    background-color: {Palette.ACCENT};
    border: 1px solid {Palette.ACCENT};
    color: #ffffff;
}}
QPushButton#primaryButton:hover {{
    background-color: {Palette.ACCENT_HOVER};
    border-color: {Palette.ACCENT_HOVER};
}}
QPushButton#primaryButton:pressed {{
    background-color: {Palette.ACCENT_PRESSED};
    border-color: {Palette.ACCENT_PRESSED};
}}
QPushButton#dangerButton:hover {{
    background-color: #3a1f22;
    border-color: {Palette.CRITICAL};
}}

/* ---------- Tabs ---------- */
QTabWidget::pane {{
    border: 1px solid {Palette.BORDER};
    border-top: none;
    background-color: {Palette.BG_SURFACE};
    top: -1px;
}}
QTabBar {{
    background-color: {Palette.BG_APP};
}}
QTabBar::tab {{
    background-color: transparent;
    color: {Palette.TEXT_SECONDARY};
    padding: 10px 20px;
    margin-right: 2px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 500;
}}
QTabBar::tab:hover {{
    color: {Palette.TEXT_PRIMARY};
}}
QTabBar::tab:selected {{
    color: {Palette.TEXT_PRIMARY};
    border-bottom: 2px solid {Palette.ACCENT};
}}

/* ---------- Labels ---------- */
QLabel {{
    color: {Palette.TEXT_PRIMARY};
    background: transparent;
}}
QLabel[role="sectionHeader"] {{
    font-size: 15px;
    font-weight: 600;
    color: {Palette.TEXT_PRIMARY};
    padding-top: 8px;
    padding-bottom: 4px;
}}
QLabel[role="statTitle"] {{
    color: {Palette.TEXT_SECONDARY};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}}
QLabel[role="statValue"] {{
    font-size: 22px;
    font-weight: 700;
}}
QLabel[role="caption"] {{
    color: {Palette.TEXT_MUTED};
    font-size: 12px;
}}

/* ---------- Stat card ---------- */
QFrame#statCard {{
    background-color: {Palette.BG_SURFACE_ALT};
    border: 1px solid {Palette.BORDER};
    border-radius: 8px;
}}
QFrame#statCard:hover {{
    border-color: {Palette.BORDER_STRONG};
}}

QFrame#panel {{
    background-color: {Palette.BG_SURFACE_ALT};
    border: 1px solid {Palette.BORDER};
    border-radius: 8px;
}}

/* ---------- Tables ---------- */
QTableWidget {{
    background-color: {Palette.BG_SURFACE};
    alternate-background-color: {Palette.BG_SURFACE_ALT};
    gridline-color: {Palette.BORDER};
    border: 1px solid {Palette.BORDER};
    border-radius: 6px;
    selection-background-color: {Palette.ACCENT_MUTED};
    selection-color: {Palette.TEXT_PRIMARY};
}}
QTableWidget::item {{
    padding: 6px 8px;
    border-bottom: 1px solid {Palette.BORDER};
}}
QTableWidget::item:selected {{
    background-color: {Palette.ACCENT_MUTED};
}}
QHeaderView::section {{
    background-color: {Palette.BG_SURFACE_ALT};
    color: {Palette.TEXT_SECONDARY};
    padding: 8px;
    border: none;
    border-bottom: 1px solid {Palette.BORDER_STRONG};
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
QTableCornerButton::section {{
    background-color: {Palette.BG_SURFACE_ALT};
    border: none;
}}

/* ---------- Inputs ---------- */
QComboBox, QSpinBox, QLineEdit {{
    background-color: {Palette.BG_ELEVATED};
    border: 1px solid {Palette.BORDER_STRONG};
    border-radius: 6px;
    padding: 6px 10px;
    min-height: 20px;
    color: {Palette.TEXT_PRIMARY};
}}
QComboBox:hover, QSpinBox:hover, QLineEdit:hover {{
    border-color: {Palette.ACCENT};
}}
QComboBox:focus, QSpinBox:focus, QLineEdit:focus {{
    border-color: {Palette.ACCENT};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox QAbstractItemView {{
    background-color: {Palette.BG_ELEVATED};
    border: 1px solid {Palette.BORDER_STRONG};
    selection-background-color: {Palette.ACCENT_MUTED};
    color: {Palette.TEXT_PRIMARY};
    outline: none;
}}

/* ---------- Lists ---------- */
QListWidget {{
    background-color: {Palette.BG_SURFACE};
    border: 1px solid {Palette.BORDER};
    border-radius: 6px;
    padding: 4px;
}}
QListWidget::item {{
    padding: 6px 8px;
    border-radius: 4px;
}}
QListWidget::item:selected {{
    background-color: {Palette.ACCENT_MUTED};
}}
QListWidget::item:hover {{
    background-color: {Palette.BG_ELEVATED};
}}

/* ---------- Scrollbars ---------- */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {Palette.BORDER_STRONG};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {Palette.ACCENT};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
}}
QScrollBar::handle:horizontal {{
    background: {Palette.BORDER_STRONG};
    border-radius: 5px;
    min-width: 24px;
}}

/* ---------- Status bar ---------- */
QStatusBar {{
    background-color: {Palette.BG_SURFACE};
    border-top: 1px solid {Palette.BORDER};
    color: {Palette.TEXT_SECONDARY};
}}
QStatusBar QLabel {{
    color: {Palette.TEXT_SECONDARY};
    padding: 2px 4px;
}}

QProgressBar {{
    background-color: {Palette.BG_ELEVATED};
    border: 1px solid {Palette.BORDER};
    border-radius: 4px;
    text-align: center;
    color: {Palette.TEXT_PRIMARY};
    height: 14px;
}}
QProgressBar::chunk {{
    background-color: {Palette.ACCENT};
    border-radius: 3px;
}}

/* ---------- Group/Form ---------- */
QFrame#formGroup {{
    background-color: {Palette.BG_SURFACE_ALT};
    border: 1px solid {Palette.BORDER};
    border-radius: 8px;
}}

/* ---------- Message boxes / dialogs ---------- */
QMessageBox {{
    background-color: {Palette.BG_SURFACE};
}}

QToolTip {{
    background-color: {Palette.BG_ELEVATED};
    color: {Palette.TEXT_PRIMARY};
    border: 1px solid {Palette.BORDER_STRONG};
    padding: 4px 8px;
    border-radius: 4px;
}}
"""


def severity_badge_style(severity: str) -> str:
    """Inline style fragment for a QLabel used as a severity pill/badge."""
    color = Palette.severity_color(severity).name()
    return (
        f"color: {color}; font-weight: 600; padding: 2px 8px; "
        f"border: 1px solid {color}; border-radius: 4px; background-color: transparent;"
    )
