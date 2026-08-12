
"""
Live console view for streaming module run output.
"""

import asyncio
import json
from typing import Any, Dict, Optional

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from websockets.asyncio.client import connect


class RunStreamWorker(QThread):
    """Background worker that consumes a run WebSocket."""

    event_received = pyqtSignal(dict)
    connection_error = pyqtSignal(str)
    finished_stream = pyqtSignal()

    def __init__(
        self,
        run_id: str,
        base_url: str = "http://127.0.0.1:8000",
    ) -> None:
        super().__init__()

        self.run_id = run_id
        self.base_url = base_url.rstrip("/")
        self._stopped = False

    def stop(self) -> None:
        """Request that the worker stop."""
        self._stopped = True

    def _websocket_url(self) -> str:
        """Convert the HTTP API URL to the WebSocket URL."""
        if self.base_url.startswith("https://"):
            ws_base = "wss://" + self.base_url[len("https://"):]
        elif self.base_url.startswith("http://"):
            ws_base = "ws://" + self.base_url[len("http://"):]
        else:
            ws_base = "ws://" + self.base_url

        return f"{ws_base}/ws/runs/{self.run_id}"

    async def _stream(self) -> None:
        """Connect to the run WebSocket and consume events."""
        url = self._websocket_url()

        try:
            async with connect(url) as websocket:
                async for raw_message in websocket:
                    if self._stopped:
                        break

                    if isinstance(raw_message, bytes):
                        raw_message = raw_message.decode("utf-8")

                    event = json.loads(raw_message)

                    if isinstance(event, dict):
                        self.event_received.emit(event)

                        event_type = event.get("type")

                        if event_type in {"complete", "error"}:
                            break

        except Exception as exc:
            if not self._stopped:
                self.connection_error.emit(str(exc))

        finally:
            self.finished_stream.emit()

    def run(self) -> None:
        """Start the asyncio event loop in this worker thread."""
        asyncio.run(self._stream())


class LiveConsoleView(QWidget):
    """Display live output and final status for a module run."""

    def __init__(
        self,
        run_id: Optional[str] = None,
        base_url: str = "http://127.0.0.1:8000",
    ) -> None:
        super().__init__()

        self.run_id = run_id
        self.base_url = base_url
        self.worker: Optional[RunStreamWorker] = None

        self._build_ui()

        if run_id:
            self.start_run_stream(run_id)

    def _build_ui(self) -> None:
        """Create the console UI."""
        layout = QVBoxLayout(self)

        header_layout = QHBoxLayout()

        self.status_label = QLabel("Status: Idle")
        header_layout.addWidget(self.status_label)

        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_console)
        header_layout.addWidget(self.clear_button)

        layout.addLayout(header_layout)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        layout.addWidget(self.console)

    def start_run_stream(self, run_id: str) -> None:
        """Connect to the WebSocket for a run."""
        self.stop_run_stream()

        self.run_id = run_id
        self.console.clear()
        self.status_label.setText("Status: Connecting...")

        self.worker = RunStreamWorker(
            run_id=run_id,
            base_url=self.base_url,
        )

        self.worker.event_received.connect(self.handle_event)
        self.worker.connection_error.connect(self.handle_connection_error)
        self.worker.finished_stream.connect(self.handle_stream_finished)

        self.worker.start()

    def handle_event(self, event: Dict[str, Any]) -> None:
        """Handle one event received from the run WebSocket."""
        event_type = event.get("type", "")
        message = event.get("message", "")

        if event_type == "complete":
            self.status_label.setText("Status: COMPLETED")

            if message:
                self.append_line(message)

            findings = event.get("findings", [])

            if findings:
                self.append_line(
                    f"Run completed with {len(findings)} finding(s)."
                )

            return

        if event_type == "error":
            self.status_label.setText("Status: ERROR")

            if message:
                self.append_line(f"[ERROR] {message}")

            return

        if event_type == "timeout":
            self.status_label.setText("Status: TIMEOUT")

            if message:
                self.append_line(f"[TIMEOUT] {message}")

            return

        if event_type in {"log", "info", "warning", "finding", "skipped"}:
            if message:
                prefix = event_type.upper()
                self.append_line(f"[{prefix}] {message}")
            return

        # Unknown event types are still displayed rather than discarded.
        if message:
            self.append_line(f"[{event_type.upper()}] {message}")

    def handle_connection_error(self, message: str) -> None:
        """Display a WebSocket connection error."""
        self.status_label.setText("Status: CONNECTION ERROR")
        self.append_line(f"[ERROR] WebSocket connection failed: {message}")

    def handle_stream_finished(self) -> None:
        """Handle the WebSocket worker finishing."""
        if self.worker is not None and self.worker._stopped:
            return

        current_status = self.status_label.text()

        if current_status == "Status: Connecting...":
            self.status_label.setText("Status: Disconnected")

    def append_line(self, message: str) -> None:
        """Append one line to the console."""
        self.console.appendPlainText(message)

    def clear_console(self) -> None:
        """Clear the console output."""
        self.console.clear()

    def stop_run_stream(self) -> None:
        """Stop an active WebSocket worker."""
        if self.worker is None:
            return

        if self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2000)

        self.worker.deleteLater()
        self.worker = None

    def closeEvent(self, event) -> None:
        """Stop the WebSocket worker when the view closes."""
        self.stop_run_stream()
        super().closeEvent(event)

