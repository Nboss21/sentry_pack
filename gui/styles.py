"""
SentryPack "Cyber Dark" Design System & Styling.

Provides unified styling, color tokens, and Qt Style Sheets (QSS) inspired by
modern cybersecurity platforms, Armitage, and Metasploit Pro.
"""

from __future__ import annotations

from typing import Optional
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import QApplication, QWidget

# ---------------------------------------------------------------------------
# Color Palette Tokens
# ---------------------------------------------------------------------------

COLOR_BG_CANVAS = "#0B0F19"       # Deep black/blue background
COLOR_BG_PANEL = "#111827"        # Sidebar & container surface
COLOR_BG_CARD = "#1F2937"         # Card, input & item surface
COLOR_BG_ELEVATED = "#283141"     # Elevated card / hover state
COLOR_BORDER = "#374151"          # Subtle structural borders
COLOR_BORDER_LIGHT = "#4B5563"    # Focused / highlighted borders

COLOR_TEXT_PRIMARY = "#F9FAFB"    # Crisp high-contrast white
COLOR_TEXT_SECONDARY = "#9CA3AF"  # Soft metadata grey
COLOR_TEXT_MUTED = "#6B7280"      # Disabled / placeholder grey

COLOR_CYAN = "#00E5FF"            # Primary cyber accent
COLOR_PURPLE = "#8B5CF6"          # Offensive / exploit accent
COLOR_GREEN = "#10B981"           # Online / beacon active / success
COLOR_YELLOW = "#F59E0B"          # Warning / scanned state
COLOR_RED = "#EF4444"             # Critical / compromised alert

# Severity Colors
SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#D97706",
    "low": "#2563EB",
    "info": "#4B5563",
    "unknown": "#6B7280",
}

# Status Colors for Target Nodes
TARGET_STATUS_COLORS = {
    "idle": QColor("#4B5563"),
    "scanned": QColor("#10B981"),
    "running": QColor("#00E5FF"),
    "vulnerable": QColor("#F59E0B"),
    "compromised": QColor("#EF4444"),
    "error": QColor("#DC2626"),
    "unknown": QColor("#374151"),
}


def get_severity_color(severity: Optional[str]) -> str:
    """Return hex color code for a severity label."""
    if not severity:
        return SEVERITY_COLORS["unknown"]
    return SEVERITY_COLORS.get(severity.lower(), SEVERITY_COLORS["unknown"])


def get_severity_badge_style(severity: Optional[str]) -> str:
    """Return inline CSS stylesheet for a severity badge label."""
    bg_color = get_severity_color(severity)
    return (
        f"background-color: {bg_color}; "
        f"color: #FFFFFF; "
        f"font-weight: bold; "
        f"font-size: 11px; "
        f"padding: 3px 8px; "
        f"border-radius: 4px; "
        f"text-transform: uppercase;"
    )


def get_pill_style(bg: str = COLOR_BG_CARD, fg: str = COLOR_CYAN, border: str = COLOR_BORDER) -> str:
    """Return inline CSS stylesheet for a metadata pill."""
    return (
        f"background-color: {bg}; "
        f"color: {fg}; "
        f"border: 1px solid {border}; "
        f"font-family: 'Consolas', 'Courier New', monospace; "
        f"font-size: 11px; "
        f"font-weight: 600; "
        f"padding: 2px 6px; "
        f"border-radius: 3px;"
    )


def get_exploit_rank(rec: dict) -> tuple[str, str]:
    """Calculate Metasploit-style reliability rating and color for an exploit recommendation."""
    module_id = rec.get("module_id")
    cvss = rec.get("cvss_score") or rec.get("cvss") or 0.0
    has_public = rec.get("has_public_exploit", True)

    try:
        cvss_f = float(cvss)
    except (ValueError, TypeError):
        cvss_f = 0.0

    if module_id and cvss_f >= 9.0:
        return ("EXCELLENT (SAFE RCE)", "#059669")
    elif module_id or (has_public and cvss_f >= 7.5):
        return ("GREAT", "#0284C7")
    elif has_public and cvss_f >= 5.0:
        return ("NORMAL", "#D97706")
    elif cvss_f > 0:
        return ("AVERAGE", "#6B7280")
    return ("MANUAL", "#DC2626")


def get_mitre_technique(rec: dict) -> tuple[str, str]:
    """Map a recommendation to its primary MITRE ATT&CK technique."""
    title = (rec.get("title") or rec.get("description") or "").lower()
    service = str(rec.get("service_name") or "").lower()

    if any(k in title for k in ("privilege", "privesc", "root", "elevation", "local")):
        return ("T1068", "Privilege Escalation")
    elif any(k in title or k in service for k in ("auth", "password", "brute", "login", "credential")):
        return ("T1110", "Brute Force / Auth Bypass")
    elif any(k in title for k in ("command", "execution", "rce", "remote")):
        return ("T1190", "Exploit Public Application")
    elif any(k in service for k in ("smb", "ssh", "rdp", "vnc", "winrm")):
        return ("T1210", "Exploitation of Remote Services")
    return ("T1190", "Exploit Public Application")


def get_rank_badge_style(color: str) -> str:
    """Return inline CSS stylesheet for an exploit rank badge."""
    return (
        f"background-color: {color}; "
        f"color: #FFFFFF; "
        f"font-weight: 700; "
        f"font-size: 10px; "
        f"padding: 2px 7px; "
        f"border-radius: 4px; "
        f"letter-spacing: 0.05em;"
    )


# ---------------------------------------------------------------------------
# Global Application Qt Style Sheet (QSS)
# ---------------------------------------------------------------------------

CYBER_DARK_QSS = f"""
/* ── Global Window & Base ────────────────────────────────────────── */
QMainWindow, QDialog, QWidget {{
    background-color: {COLOR_BG_CANVAS};
    color: {COLOR_TEXT_PRIMARY};
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}}

/* ── Panels & GroupBoxes ─────────────────────────────────────────── */
QGroupBox {{
    background-color: {COLOR_BG_PANEL};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 18px;
    padding-bottom: 12px;
    padding-left: 12px;
    padding-right: 12px;
    font-weight: bold;
    color: {COLOR_CYAN};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 16px;
    padding: 0 6px;
    background-color: {COLOR_BG_PANEL};
}}

/* ── Typography & Labels ─────────────────────────────────────────── */
QLabel {{
    color: {COLOR_TEXT_PRIMARY};
}}
QLabel[dimmed="true"] {{
    color: {COLOR_TEXT_SECONDARY};
}}

/* ── Inputs, LineEdits, SpinBoxes & Combos ───────────────────────── */
QLineEdit, QSpinBox, QComboBox {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {COLOR_CYAN};
    selection-color: {COLOR_BG_CANVAS};
}}

QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border: 1px solid {COLOR_CYAN};
    background-color: {COLOR_BG_ELEVATED};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid {COLOR_BORDER};
}}

QComboBox QAbstractItemView {{
    background-color: {COLOR_BG_PANEL};
    color: {COLOR_TEXT_PRIMARY};
    selection-background-color: {COLOR_CYAN};
    selection-color: {COLOR_BG_CANVAS};
    border: 1px solid {COLOR_BORDER};
}}

/* ── Buttons ─────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 7px 14px;
    font-weight: 600;
}}

QPushButton:hover {{
    background-color: {COLOR_BG_ELEVATED};
    border-color: {COLOR_BORDER_LIGHT};
    color: {COLOR_CYAN};
}}

QPushButton:pressed {{
    background-color: {COLOR_BG_CANVAS};
}}

QPushButton[primary="true"] {{
    background-color: #0369a1;
    color: #ffffff;
    border: 1px solid {COLOR_CYAN};
}}

QPushButton[primary="true"]:hover {{
    background-color: #0284c7;
}}

QPushButton[danger="true"] {{
    background-color: #991b1b;
    color: #ffffff;
    border: 1px solid #ef4444;
}}

QPushButton[danger="true"]:hover {{
    background-color: #b91c1c;
}}

/* ── Lists & Trees ───────────────────────────────────────────────── */
QListWidget, QTreeWidget, QTableWidget {{
    background-color: {COLOR_BG_PANEL};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 4px;
    outline: none;
}}

QListWidget::item, QTreeWidget::item {{
    padding: 8px 10px;
    border-radius: 4px;
    margin-bottom: 2px;
}}

QListWidget::item:hover, QTreeWidget::item:hover {{
    background-color: {COLOR_BG_CARD};
}}

QListWidget::item:selected, QTreeWidget::item:selected {{
    background-color: {COLOR_BG_ELEVATED};
    color: {COLOR_CYAN};
    border-left: 3px solid {COLOR_CYAN};
}}

/* ── Tables ──────────────────────────────────────────────────────── */
QTableWidget {{
    gridline-color: {COLOR_BORDER};
}}

QHeaderView::section {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_TEXT_SECONDARY};
    padding: 6px 10px;
    border: 1px solid {COLOR_BORDER};
    font-weight: bold;
    font-size: 11px;
    text-transform: uppercase;
}}

/* ── Tabs ────────────────────────────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    background-color: {COLOR_BG_PANEL};
    top: -1px;
}}

QTabBar::tab {{
    background-color: {COLOR_BG_CANVAS};
    color: {COLOR_TEXT_SECONDARY};
    border: 1px solid {COLOR_BORDER};
    padding: 8px 16px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
}}

QTabBar::tab:selected {{
    background-color: {COLOR_BG_PANEL};
    color: {COLOR_CYAN};
    border-bottom: 2px solid {COLOR_CYAN};
}}

QTabBar::tab:hover:!selected {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_TEXT_PRIMARY};
}}

/* ── Scrollbars ──────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: {COLOR_BG_CANVAS};
    width: 10px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background: {COLOR_BORDER};
    min-height: 24px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical:hover {{
    background: {COLOR_BORDER_LIGHT};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: {COLOR_BG_CANVAS};
    height: 10px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background: {COLOR_BORDER};
    min-width: 24px;
    border-radius: 5px;
}}

/* ── Context Menus ───────────────────────────────────────────────── */
QMenu {{
    background-color: {COLOR_BG_PANEL};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER_LIGHT};
    border-radius: 6px;
    padding: 4px 0;
}}

QMenu::item {{
    padding: 6px 24px;
}}

QMenu::item:selected {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_CYAN};
}}

QMenu::separator {{
    height: 1px;
    background-color: {COLOR_BORDER};
    margin: 4px 8px;
}}

/* ── Terminal & Text Edits ───────────────────────────────────────── */
QPlainTextEdit, QTextEdit {{
    background-color: #030712;
    color: #e5e7eb;
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    font-family: "JetBrains Mono", "Consolas", "Courier New", monospace;
    font-size: 12px;
}}
"""


def apply_cyber_theme(app_or_widget: QApplication | QWidget) -> None:
    """Apply the unified SentryPack Cyber Dark theme to the app or window."""
    app_or_widget.setStyleSheet(CYBER_DARK_QSS)
