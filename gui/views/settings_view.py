"""
Platform settings and environment configuration view.
"""

from __future__ import annotations

from typing import Optional

import requests
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from gui.styles import (
    COLOR_BG_CARD,
    COLOR_BORDER,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
)


class SettingsView(QWidget):
    """Platform Settings & Configuration View."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(14)

        # ── Header ──────────────────────────────────────────────────────
        header = QHBoxLayout()
        title = QLabel("Platform Settings")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLOR_CYAN};")
        header.addWidget(title)
        header.addStretch()
        main_layout.addLayout(header)

        # ── Settings Form Card ──────────────────────────────────────────
        card = QFrame()
        card.setStyleSheet(
            f"background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; padding: 16px;"
        )
        form = QFormLayout(card)
        form.setSpacing(12)

        self.api_url_input = QLineEdit("http://127.0.0.1:8000")
        test_api_row = QHBoxLayout()
        test_api_row.addWidget(self.api_url_input, 3)
        self.test_api_btn = QPushButton("Test API")
        self.test_api_btn.clicked.connect(self._test_api_connection)
        test_api_row.addWidget(self.test_api_btn, 1)
        form.addRow("Backend API Base URL:", test_api_row)

        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(5, 3600)
        self.timeout_input.setValue(60)
        form.addRow("Default Module Timeout (seconds):", self.timeout_input)

        self.ports_input = QLineEdit("1-1024")
        form.addRow("Default Recon Port Range:", self.ports_input)

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Cyber Dark (Armitage High Contrast)", "Midnight Blue", "Classic Grey"])
        form.addRow("Visual Desktop Theme:", self.theme_combo)

        main_layout.addWidget(card)

        # ── System Info Card ────────────────────────────────────────────
        info_card = QFrame()
        info_card.setStyleSheet(
            f"background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; padding: 16px;"
        )
        info_layout = QVBoxLayout(info_card)
        info_layout.setSpacing(6)

        sys_title = QLabel("System & Engine Status:")
        sys_title.setStyleSheet(f"font-weight: bold; color: {COLOR_CYAN};")
        info_layout.addWidget(sys_title)

        info_layout.addWidget(QLabel("Platform: SentryPack v0.1.0-alpha"))
        info_layout.addWidget(QLabel("Recommendation Engine: Hybrid StringMatcher + CPEMatcher (Active)"))
        info_layout.addWidget(QLabel("Database: SQLite FTS5 Exploit Index (Active)"))
        info_layout.addWidget(QLabel("Reporting: Dual WeasyPrint / ReportLab Engine (Active)"))

        main_layout.addWidget(info_card)
        main_layout.addStretch()

    def _test_api_connection(self) -> None:
        url = self.api_url_input.text().strip().rstrip("/")
        try:
            resp = requests.get(f"{url}/api/projects/", timeout=3.0)
            if resp.status_code == 200:
                QMessageBox.information(self, "API Online", f"Successfully connected to SentryPack API at {url}!")
            else:
                QMessageBox.warning(self, "API Status", f"API reached but returned HTTP status {resp.status_code}.")
        except Exception as exc:
            QMessageBox.critical(self, "API Offline", f"Could not connect to {url}: {exc}")