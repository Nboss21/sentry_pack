"""
Project Vulnerability Matrix & Findings Browser.

Features:
  - Executive stat cards (Total, Critical, High, Medium, Low, Info)
  - Full-text search and multi-criteria severity/target filtering
  - Formatted vulnerability data grid with colored badges
  - Export capabilities (JSON & CSV)
"""

from __future__ import annotations

import csv
import json
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.api_client import SentryPackAPIClient
from gui.styles import (
    COLOR_BG_CARD,
    COLOR_BORDER,
    COLOR_CYAN,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    get_pill_style,
    get_severity_badge_style,
    get_severity_color,
)


class StatCard(QFrame):
    """Mini executive summary card displaying count and severity label."""

    def __init__(self, label: str, count: int, color: str = COLOR_CYAN, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(
            f"QFrame {{ background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; "
            f"border-radius: 6px; padding: 6px 12px; }} "
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(2)

        self.count_lbl = QLabel(str(count))
        self.count_lbl.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {color};")
        self.count_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.count_lbl)

        self.text_lbl = QLabel(label.upper())
        self.text_lbl.setStyleSheet(f"font-size: 10px; font-weight: 600; color: {COLOR_TEXT_SECONDARY};")
        self.text_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.text_lbl)

    def set_count(self, count: int) -> None:
        self.count_lbl.setText(str(count))


class FindingsView(QWidget):
    """Comprehensive Vulnerabilities & Findings View."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.api_client = SentryPackAPIClient()
        self.all_findings: List[Dict[str, Any]] = []
        self._current_project_id: Optional[int] = None

        self._build_ui()
        self.load_findings()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # ── Top Title & Export ──────────────────────────────────────────
        header = QHBoxLayout()

        title = QLabel("Findings & Vulnerability Matrix")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLOR_CYAN};")
        header.addWidget(title)

        header.addStretch()

        self.export_csv_btn = QPushButton("📥 Export CSV")
        self.export_csv_btn.clicked.connect(self._export_csv)
        header.addWidget(self.export_csv_btn)

        self.export_json_btn = QPushButton("📥 Export JSON")
        self.export_json_btn.clicked.connect(self._export_json)
        header.addWidget(self.export_json_btn)

        self.refresh_btn = QPushButton("⟳ Refresh")
        self.refresh_btn.clicked.connect(self.load_findings)
        header.addWidget(self.refresh_btn)

        main_layout.addLayout(header)

        # ── Executive Stat Cards ────────────────────────────────────────
        stats_row = QHBoxLayout()
        stats_row.setSpacing(8)

        self.card_total = StatCard("Total Findings", 0, COLOR_CYAN)
        self.card_crit = StatCard("Critical", 0, "#DC2626")
        self.card_high = StatCard("High", 0, "#EA580C")
        self.card_med = StatCard("Medium", 0, "#D97706")
        self.card_low = StatCard("Low", 0, "#2563EB")
        self.card_info = StatCard("Info", 0, "#4B5563")

        stats_row.addWidget(self.card_total)
        stats_row.addWidget(self.card_crit)
        stats_row.addWidget(self.card_high)
        stats_row.addWidget(self.card_med)
        stats_row.addWidget(self.card_low)
        stats_row.addWidget(self.card_info)

        main_layout.addLayout(stats_row)

        # ── Filter Bar ──────────────────────────────────────────────────
        filter_bar = QHBoxLayout()

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍 Search by finding title, CVE, or host...")
        self.search_box.textChanged.connect(self._apply_filters)
        filter_bar.addWidget(self.search_box, 3)

        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Info"])
        self.sev_filter.currentTextChanged.connect(self._apply_filters)
        filter_bar.addWidget(self.sev_filter, 1)

        main_layout.addLayout(filter_bar)

        # ── Findings Table Grid ─────────────────────────────────────────
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Severity", "Vulnerability Title", "CVE", "Target Host", "Remediation", "Date"
        ])
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        main_layout.addWidget(self.table)

    def set_project(self, project_id: Optional[int]) -> None:
        """Filter findings to the given project."""
        self._current_project_id = project_id
        self.load_findings()

    def load_findings(self) -> None:
        """Fetch findings across targets from the API."""
        try:
            self.all_findings = self.api_client.get_all_findings(self._current_project_id)
            self._update_stat_cards()
            self._apply_filters()
        except Exception as exc:
            self.table.setRowCount(0)

    def _update_stat_cards(self) -> None:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.all_findings:
            sev = str(f.get("severity", "Info")).capitalize()
            if sev in counts:
                counts[sev] += 1

        self.card_total.set_count(len(self.all_findings))
        self.card_crit.set_count(counts["Critical"])
        self.card_high.set_count(counts["High"])
        self.card_med.set_count(counts["Medium"])
        self.card_low.set_count(counts["Low"])
        self.card_info.set_count(counts["Info"])

    def _apply_filters(self) -> None:
        query = self.search_box.text().strip().lower()
        sev_filter = self.sev_filter.currentText()

        filtered: List[Dict[str, Any]] = []
        for f in self.all_findings:
            sev = str(f.get("severity", "Info")).capitalize()
            if sev_filter != "All Severities" and sev.lower() != sev_filter.lower():
                continue

            title = str(f.get("title", "")).lower()
            cve = str(f.get("cve", "")).lower()
            ip = str(f.get("target_ip", "")).lower()
            target_name = str(f.get("target_name", "")).lower()

            if query and not (query in title or query in cve or query in ip or query in target_name):
                continue

            filtered.append(f)

        self._render_table(filtered)

    def _render_table(self, findings: List[Dict[str, Any]]) -> None:
        self.table.setRowCount(len(findings))

        for row_idx, f in enumerate(findings):
            # 0. Severity
            sev = str(f.get("severity", "Info")).upper()
            sev_item = QTableWidgetItem(sev)
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            sev_item.setForeground(Qt.GlobalColor.white)
            # Background color hint
            sev_item.setData(Qt.ItemDataRole.UserRole, sev)
            self.table.setItem(row_idx, 0, sev_item)

            # 1. Title
            title_item = QTableWidgetItem(f.get("title", "Untitled finding"))
            self.table.setItem(row_idx, 1, title_item)

            # 2. CVE
            cve_str = f.get("cve") or "—"
            cve_item = QTableWidgetItem(cve_str)
            cve_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_idx, 2, cve_item)

            # 3. Target Host
            host_str = f"{f.get('target_name', 'Host')} ({f.get('target_ip', '')})"
            host_item = QTableWidgetItem(host_str)
            self.table.setItem(row_idx, 3, host_item)

            # 4. Remediation
            rem_str = f.get("remediation") or "—"
            rem_item = QTableWidgetItem(rem_str)
            self.table.setItem(row_idx, 4, rem_item)

            # 5. Date
            date_str = str(f.get("created_at") or "")[:10]
            date_item = QTableWidgetItem(date_str)
            date_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_idx, 5, date_item)

    def _export_csv(self) -> None:
        if not self.all_findings:
            QMessageBox.information(self, "Export", "No findings to export.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export Findings to CSV", "sentrypack_findings.csv", "CSV Files (*.csv)")
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Severity", "Title", "CVE", "Target Name", "Target IP", "Remediation", "Description"])
                for item in self.all_findings:
                    writer.writerow([
                        item.get("id", ""),
                        item.get("severity", ""),
                        item.get("title", ""),
                        item.get("cve", ""),
                        item.get("target_name", ""),
                        item.get("target_ip", ""),
                        item.get("remediation", ""),
                        item.get("description", ""),
                    ])
            QMessageBox.information(self, "Export Complete", f"Exported {len(self.all_findings)} findings to {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def _export_json(self) -> None:
        if not self.all_findings:
            QMessageBox.information(self, "Export", "No findings to export.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export Findings to JSON", "sentrypack_findings.json", "JSON Files (*.json)")
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.all_findings, f, indent=2)
            QMessageBox.information(self, "Export Complete", f"Exported {len(self.all_findings)} findings to {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))