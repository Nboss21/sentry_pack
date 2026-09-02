"""
Live module execution console with Metasploit-style semantic cyber highlighting,
log level filtering, smart auto-scroll lock, search bar, and log export.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import urllib.parse

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtGui import QTextCursor, QTextDocument
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
import websockets

from gui.styles import (
    COLOR_BG_CANVAS,
    COLOR_BG_CARD,
    COLOR_BORDER,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_RED,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    COLOR_YELLOW,
)


class RunStreamWorker(QThread):
    """Worker thread that streams WebSocket events for a module run."""

    event_received = pyqtSignal(dict)
    connection_error = pyqtSignal(str)
    finished_stream = pyqtSignal()

    def __init__(
        self,
        run_id: str,
        base_url: str = "http://127.0.0.1:8000",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.run_id = run_id
        self.base_url = base_url
        self._stopped = False

    def stop(self) -> None:
        self._stopped = True

    def _build_ws_url(self) -> str:
        parsed = urllib.parse.urlparse(self.base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        netloc = parsed.netloc or "127.0.0.1:8000"
        return f"{scheme}://{netloc}/api/runs/{self.run_id}/stream"

    async def _stream(self) -> None:
        url = self._build_ws_url()
        try:
            async with websockets.connect(url) as websocket:
                while not self._stopped:
                    try:
                        message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    except asyncio.TimeoutError:
                        continue
                    except websockets.ConnectionClosed:
                        break

                    try:
                        payload = json.loads(message)
                    except json.JSONDecodeError:
                        payload = {"type": "log", "message": message}

                    self.event_received.emit(payload)

                    if payload.get("type") in {"complete", "error", "timeout"}:
                        break

        except Exception as exc:
            if not self._stopped:
                self.connection_error.emit(str(exc))
        finally:
            self.finished_stream.emit()

    def run(self) -> None:
        asyncio.run(self._stream())


class LiveConsoleView(QWidget):
    """Display live output with semantic cyber highlighting, filtering, and search."""

    def __init__(
        self,
        run_id: Optional[str] = None,
        base_url: str = "http://127.0.0.1:8000",
    ) -> None:
        super().__init__()
        self.run_id = run_id
        self.base_url = base_url
        self.worker: Optional[RunStreamWorker] = None
        self._log_history: List[Dict[str, Any]] = []
        self._current_filter: str = "all"
        self._autoscroll: bool = True

        self._build_ui()

        if run_id:
            self.start_run_stream(run_id)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        # ── Top Toolbar ─────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet(f"font-weight: bold; color: {COLOR_CYAN}; font-size: 13px;")
        toolbar.addWidget(self.status_label)

        toolbar.addSpacing(12)

        # Filter buttons
        self.filter_all_btn = QPushButton("All")
        self.filter_all_btn.setCheckable(True)
        self.filter_all_btn.setChecked(True)
        self.filter_all_btn.clicked.connect(lambda: self._set_filter("all"))
        toolbar.addWidget(self.filter_all_btn)

        self.filter_findings_btn = QPushButton("⚔ Findings")
        self.filter_findings_btn.setCheckable(True)
        self.filter_findings_btn.clicked.connect(lambda: self._set_filter("finding"))
        toolbar.addWidget(self.filter_findings_btn)

        self.filter_errors_btn = QPushButton("❌ Errors")
        self.filter_errors_btn.setCheckable(True)
        self.filter_errors_btn.clicked.connect(lambda: self._set_filter("error"))
        toolbar.addWidget(self.filter_errors_btn)

        self.filter_logs_btn = QPushButton("ℹ Info")
        self.filter_logs_btn.setCheckable(True)
        self.filter_logs_btn.clicked.connect(lambda: self._set_filter("log"))
        toolbar.addWidget(self.filter_logs_btn)

        toolbar.addStretch()

        # In-Console Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Find in log...")
        self.search_input.setFixedWidth(160)
        self.search_input.returnPressed.connect(self._find_next)
        toolbar.addWidget(self.search_input)

        self.find_prev_btn = QPushButton("▲")
        self.find_prev_btn.setFixedSize(26, 26)
        self.find_prev_btn.clicked.connect(self._find_prev)
        toolbar.addWidget(self.find_prev_btn)

        self.find_next_btn = QPushButton("▼")
        self.find_next_btn.setFixedSize(26, 26)
        self.find_next_btn.clicked.connect(self._find_next)
        toolbar.addWidget(self.find_next_btn)

        toolbar.addSpacing(8)

        # Autoscroll lock toggle
        self.autoscroll_btn = QPushButton("🔒 Auto-Scroll")
        self.autoscroll_btn.setCheckable(True)
        self.autoscroll_btn.setChecked(True)
        self.autoscroll_btn.clicked.connect(self._toggle_autoscroll)
        toolbar.addWidget(self.autoscroll_btn)

        # Export & Copy
        self.export_btn = QPushButton("💾 Save Log")
        self.export_btn.clicked.connect(self._export_log)
        toolbar.addWidget(self.export_btn)

        self.copy_btn = QPushButton("📋 Copy All")
        self.copy_btn.clicked.connect(self._copy_all)
        toolbar.addWidget(self.copy_btn)

        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_console)
        toolbar.addWidget(self.clear_button)

        layout.addLayout(toolbar)

        # ── Rich Terminal Console ───────────────────────────────────────
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.console.setStyleSheet(
            f"background-color: #060913; "
            f"color: #E2E8F0; "
            f"font-family: 'Consolas', 'Courier New', monospace; "
            f"font-size: 12px; "
            f"border: 1px solid {COLOR_BORDER}; "
            f"border-radius: 6px; "
            f"padding: 8px;"
        )
        layout.addWidget(self.console)

    def _toggle_autoscroll(self) -> None:
        self._autoscroll = self.autoscroll_btn.isChecked()

    def _set_filter(self, filter_name: str) -> None:
        self._current_filter = filter_name
        for btn in (self.filter_all_btn, self.filter_findings_btn, self.filter_errors_btn, self.filter_logs_btn):
            btn.setChecked(False)

        if filter_name == "all":
            self.filter_all_btn.setChecked(True)
        elif filter_name == "finding":
            self.filter_findings_btn.setChecked(True)
        elif filter_name == "error":
            self.filter_errors_btn.setChecked(True)
        elif filter_name == "log":
            self.filter_logs_btn.setChecked(True)

        self._refresh_console_view()

    def _refresh_console_view(self) -> None:
        """Re-render console text based on active filter."""
        self.console.clear()
        for item in self._log_history:
            ev_type = item["type"]
            if self._current_filter == "all":
                self._append_html(item["html"])
            elif self._current_filter == "finding" and ev_type == "finding":
                self._append_html(item["html"])
            elif self._current_filter == "error" and ev_type in ("error", "timeout"):
                self._append_html(item["html"])
            elif self._current_filter == "log" and ev_type in ("log", "info"):
                self._append_html(item["html"])

    def _append_html(self, html: str) -> None:
        self.console.append(html)
        if self._autoscroll:
            sb = self.console.verticalScrollBar()
            sb.setValue(sb.maximum())

    def _format_event_html(self, event_type: str, message: str) -> str:
        ts = datetime.now().strftime("%H:%M:%S")
        time_tag = f'<span style="color: #475569;">[{ts}]</span>'

        if event_type == "complete":
            badge = '<span style="color: #10B981; font-weight: bold;">[+] [SUCCESS]</span>'
            body = f'<span style="color: #A7F3D0; font-weight: bold;">{message}</span>'
        elif event_type == "finding":
            badge = '<span style="color: #C084FC; font-weight: bold;">[⚔] [FINDING]</span>'
            body = f'<span style="color: #F3E8FF; font-weight: 600;">{message}</span>'
        elif event_type in ("error", "timeout"):
            badge = f'<span style="color: #EF4444; font-weight: bold;">[-] [{event_type.upper()}]</span>'
            body = f'<span style="color: #FCA5A5;">{message}</span>'
        elif event_type == "warning":
            badge = '<span style="color: #F59E0B; font-weight: bold;">[!] [WARN]</span>'
            body = f'<span style="color: #FDE68A;">{message}</span>'
        else:
            badge = '<span style="color: #00E5FF; font-weight: bold;">[*]</span>'
            body = f'<span style="color: #E2E8F0;">{message}</span>'

        return f"{time_tag} {badge} {body}"

    def start_run_stream(self, run_id: str) -> None:
        """Connect to the WebSocket for a run."""
        self.stop_run_stream()

        self.run_id = run_id
        self.clear_console()
        self.status_label.setText(f"Status: Running [{run_id[:8]}...]")
        self.status_label.setStyleSheet(f"font-weight: bold; color: {COLOR_CYAN};")

        self.worker = RunStreamWorker(run_id=run_id, base_url=self.base_url)
        self.worker.event_received.connect(self.handle_event)
        self.worker.connection_error.connect(self.handle_connection_error)
        self.worker.finished_stream.connect(self.handle_stream_finished)
        self.worker.start()

    def handle_event(self, event: Dict[str, Any]) -> None:
        """Handle incoming WebSocket run event."""
        event_type = event.get("type", "log")
        message = event.get("message", "")

        if event_type == "complete":
            self.status_label.setText("Status: COMPLETED")
            self.status_label.setStyleSheet(f"font-weight: bold; color: {COLOR_GREEN};")
            if not message:
                message = "Module run finished successfully."
            html = self._format_event_html(event_type, message)
            self._record_and_render(event_type, message, html)

            findings = event.get("findings", [])
            if findings:
                finding_msg = f"Run discovered {len(findings)} vulnerability finding(s)."
                f_html = self._format_event_html("finding", finding_msg)
                self._record_and_render("finding", finding_msg, f_html)
            return

        if event_type == "error":
            self.status_label.setText("Status: ERROR")
            self.status_label.setStyleSheet(f"font-weight: bold; color: {COLOR_RED};")
            html = self._format_event_html(event_type, message)
            self._record_and_render(event_type, message, html)
            return

        if event_type == "timeout":
            self.status_label.setText("Status: TIMEOUT")
            self.status_label.setStyleSheet(f"font-weight: bold; color: {COLOR_YELLOW};")
            html = self._format_event_html(event_type, message)
            self._record_and_render(event_type, message, html)
            return

        if message:
            html = self._format_event_html(event_type, message)
            self._record_and_render(event_type, message, html)

    def _record_and_render(self, event_type: str, raw_msg: str, html: str) -> None:
        item = {"type": event_type, "message": raw_msg, "html": html}
        self._log_history.append(item)

        # Only append if matching current filter
        if self._current_filter == "all":
            self._append_html(html)
        elif self._current_filter == "finding" and event_type == "finding":
            self._append_html(html)
        elif self._current_filter == "error" and event_type in ("error", "timeout"):
            self._append_html(html)
        elif self._current_filter == "log" and event_type in ("log", "info"):
            self._append_html(html)

    def handle_connection_error(self, message: str) -> None:
        self.status_label.setText("Status: CONNECTION ERROR")
        self.status_label.setStyleSheet(f"font-weight: bold; color: {COLOR_RED};")
        err_msg = f"WebSocket stream disconnected: {message}"
        html = self._format_event_html("error", err_msg)
        self._record_and_render("error", err_msg, html)

    def handle_stream_finished(self) -> None:
        if self.worker is not None and self.worker._stopped:
            return
        if self.status_label.text().startswith("Status: Running"):
            self.status_label.setText("Status: Finished")

    def _find_next(self) -> None:
        query = self.search_input.text().strip()
        if not query:
            return
        found = self.console.find(query)
        if not found:
            # Wrap around from top
            cursor = self.console.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            self.console.setTextCursor(cursor)
            self.console.find(query)

    def _find_prev(self) -> None:
        query = self.search_input.text().strip()
        if not query:
            return
        found = self.console.find(query, QTextDocument.FindFlag.FindBackward)
        if not found:
            # Wrap around from bottom
            cursor = self.console.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.console.setTextCursor(cursor)
            self.console.find(query, QTextDocument.FindFlag.FindBackward)

    def _export_log(self) -> None:
        text = self.console.toPlainText()
        if not text:
            QMessageBox.information(self, "Export Log", "Console log is currently empty.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Console Output",
            f"sentrypack_run_{self.run_id or 'log'}.txt",
            "Text Files (*.txt);;All Files (*)",
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(text)
                QMessageBox.information(self, "Saved", f"Log successfully exported to:\n{file_path}")
            except Exception as exc:
                QMessageBox.critical(self, "Export Error", f"Failed to save log: {exc}")

    def _copy_all(self) -> None:
        text = self.console.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", "Console output copied to clipboard.")

    def clear_console(self) -> None:
        self.console.clear()
        self._log_history.clear()

    def stop_run_stream(self) -> None:
        if self.worker is None:
            return
        if self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2000)
        self.worker.deleteLater()
        self.worker = None

    def closeEvent(self, event) -> None:
        self.stop_run_stream()
        super().closeEvent(event)
