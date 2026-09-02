"""
Armitage-style C2 Sessions & Beacon Manager with interactive terminal.

Features:
  - Live session table (Session ID, Session Key, Target, Transport, Status, Last Seen)
  - Interactive command execution terminal (whoami, shell, sysinfo)
  - Task execution history & output viewing
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
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
    COLOR_GREEN,
    COLOR_RED,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    get_pill_style,
)


class SessionsView(QWidget):
    """Armitage-style active C2 sessions manager and interactive shell."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.api_client = SentryPackAPIClient()
        self.sessions: List[Dict[str, Any]] = []
        self.selected_session_id: Optional[str] = None

        self._build_ui()
        self.load_sessions()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # ── Top Bar ─────────────────────────────────────────────────────
        top_bar = QHBoxLayout()

        title = QLabel("C2 Sessions & Beacons")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLOR_CYAN};")
        top_bar.addWidget(title)

        top_bar.addStretch()

        self.status_lbl = QLabel("0 active sessions")
        self.status_lbl.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; margin-right: 8px;")
        top_bar.addWidget(self.status_lbl)

        self.refresh_btn = QPushButton("⟳ Refresh Sessions")
        self.refresh_btn.clicked.connect(self.load_sessions)
        top_bar.addWidget(self.refresh_btn)

        main_layout.addLayout(top_bar)

        # ── Vertical Splitter: Sessions Table (Top) & Shell Console (Bottom) ─
        splitter = QSplitter(Qt.Orientation.Vertical)

        # 1. Sessions Table
        table_container = QWidget()
        t_layout = QVBoxLayout(table_container)
        t_layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Session ID", "Target ID", "Transport", "Status", "Last Seen", "Session Key"
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_session_selected)
        t_layout.addWidget(self.table)

        splitter.addWidget(table_container)

        # 2. Interactive Terminal Console
        terminal_container = QWidget()
        term_layout = QVBoxLayout(terminal_container)
        term_layout.setContentsMargins(0, 8, 0, 0)
        term_layout.setSpacing(6)

        term_header = QHBoxLayout()
        self.terminal_title = QLabel("Session Shell: None Selected")
        self.terminal_title.setStyleSheet(f"font-weight: bold; color: {COLOR_CYAN};")
        term_header.addWidget(self.terminal_title)

        term_header.addStretch()

        # Quick Commands
        for cmd in ("whoami", "ipconfig", "id", "uname -a", "pwd"):
            btn = QPushButton(cmd)
            btn.setFixedHeight(24)
            btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
            btn.clicked.connect(lambda checked, c=cmd: self._send_command_str(c))
            term_header.addWidget(btn)

        term_layout.addLayout(term_header)

        self.console_output = QPlainTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setPlaceholderText("Select an active C2 session above to interact and dispatch tasks.")
        term_layout.addWidget(self.console_output)

        # Command Input Bar
        input_bar = QHBoxLayout()
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("Enter command to execute on session (e.g. whoami, ls -la, ps)...")
        self.cmd_input.returnPressed.connect(self._send_command)
        input_bar.addWidget(self.cmd_input)

        self.send_btn = QPushButton("⚡ Execute Command")
        self.send_btn.setProperty("primary", True)
        self.send_btn.clicked.connect(self._send_command)
        input_bar.addWidget(self.send_btn)

        term_layout.addLayout(input_bar)
        splitter.addWidget(terminal_container)

        splitter.setSizes([260, 360])
        main_layout.addWidget(splitter)

    def load_sessions(self) -> None:
        """Fetch all C2 sessions from backend."""
        try:
            data = self.api_client.get_c2_sessions()
            self.sessions = data.get("sessions", [])
            self._render_table()
            active_count = sum(1 for s in self.sessions if s.get("status") == "active")
            self.status_lbl.setText(f"{active_count} active / {len(self.sessions)} total session(s)")
        except Exception as exc:
            self.table.setRowCount(0)
            self.status_lbl.setText(f"Error loading sessions: {exc}")

    def _render_table(self) -> None:
        self.table.setRowCount(len(self.sessions))

        for row_idx, sess in enumerate(self.sessions):
            sid = str(sess.get("id", ""))
            tid = str(sess.get("target_id", "—"))
            transport = str(sess.get("transport", "tls")).upper()
            status = str(sess.get("status", "unknown")).upper()
            last_seen = str(sess.get("last_seen", "—"))
            key = str(sess.get("session_key", "—"))

            item_sid = QTableWidgetItem(sid)
            item_tid = QTableWidgetItem(f"Target #{tid}")
            item_trans = QTableWidgetItem(transport)
            item_status = QTableWidgetItem(status)
            item_seen = QTableWidgetItem(last_seen)
            item_key = QTableWidgetItem(key)

            if status == "ACTIVE":
                item_status.setForeground(Qt.GlobalColor.green)
            else:
                item_status.setForeground(Qt.GlobalColor.gray)

            self.table.setItem(row_idx, 0, item_sid)
            self.table.setItem(row_idx, 1, item_tid)
            self.table.setItem(row_idx, 2, item_trans)
            self.table.setItem(row_idx, 3, item_status)
            self.table.setItem(row_idx, 4, item_seen)
            self.table.setItem(row_idx, 5, item_key)

    def _on_session_selected(self) -> None:
        selected_rows = self.table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if row < len(self.sessions):
            sess = self.sessions[row]
            self.selected_session_id = str(sess.get("id"))
            transport = sess.get("transport", "tls")
            self.terminal_title.setText(f"Interactive Shell: Session {self.selected_session_id} ({transport.upper()})")
            self._load_session_history()

    def _load_session_history(self) -> None:
        if not self.selected_session_id:
            return

        try:
            data = self.api_client.get_session_tasks(self.selected_session_id)
            tasks = data.get("tasks", [])
            self.console_output.clear()
            self.console_output.appendPlainText(f"=== Connected to Session {self.selected_session_id} ===")

            for t in tasks:
                cmd = t.get("command", "")
                status = t.get("status", "")
                output = t.get("output") or "(no output returned)"
                self.console_output.appendPlainText(f"\n[session:{self.selected_session_id}]$ {cmd} [{status}]")
                self.console_output.appendPlainText(output)

        except Exception as exc:
            self.console_output.appendPlainText(f"Error fetching task history: {exc}")

    def _send_command_str(self, command: str) -> None:
        self.cmd_input.setText(command)
        self._send_command()

    def _send_command(self) -> None:
        command = self.cmd_input.text().strip()
        if not command:
            return

        if not self.selected_session_id:
            QMessageBox.warning(self, "No Session", "Select a C2 session from the table first.")
            return

        self.console_output.appendPlainText(f"\n[dispatching] -> {command}")
        self.cmd_input.clear()

        try:
            res = self.api_client.create_session_task(self.selected_session_id, command)
            task_id = res.get("task_id", "")
            self.console_output.appendPlainText(f"[task queued: #{task_id}] Waiting for agent beacon pickup...")
            # Schedule refresh
            QTimer.singleShot(1500, self._load_session_history)
        except Exception as exc:
            self.console_output.appendPlainText(f"[error] Failed to enqueue task: {exc}")
