"""
C2 listener management GUI view.
"""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from gui.api_client import SentryPackAPIClient


class TLSConfigDialog(QDialog):
    """Configuration dialog for the TLS listener."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.setWindowTitle("Start TLS Listener")

        layout = QFormLayout(self)

        self.host = QLineEdit("127.0.0.1")

        self.port = QSpinBox()
        self.port.setRange(0, 65535)
        self.port.setValue(4443)

        self.certfile = QLineEdit()
        self.keyfile = QLineEdit()

        layout.addRow("Host:", self.host)
        layout.addRow("Port:", self.port)
        layout.addRow("Certificate:", self.certfile)
        layout.addRow("Private key:", self.keyfile)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )

        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout.addRow(buttons)

    def config(self) -> dict[str, Any]:
        """Return listener configuration."""

        return {
            "host": self.host.text().strip(),
            "port": self.port.value(),
            "certfile": self.certfile.text().strip(),
            "keyfile": self.keyfile.text().strip(),
        }


class ListenersView(QWidget):
    """Display and control registered C2 listeners."""

    def __init__(
        self,
        api_client: SentryPackAPIClient | None = None,
    ) -> None:
        super().__init__()

        self.api_client = api_client or SentryPackAPIClient()

        self.listener_list = QListWidget()

        self.status_label = QLabel("No listener selected")

        self.refresh_button = QPushButton("Refresh")
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("C2 Listeners"))
        layout.addWidget(self.listener_list)

        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()

        layout.addLayout(status_layout)

        buttons = QHBoxLayout()
        buttons.addWidget(self.refresh_button)
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch()

        layout.addLayout(buttons)

        self.refresh_button.clicked.connect(self.refresh)
        self.start_button.clicked.connect(self.start_selected)
        self.stop_button.clicked.connect(self.stop_selected)

        self.listener_list.currentItemChanged.connect(
            self.listener_selected
        )

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(False)

        self.refresh()

    def refresh(self) -> None:
        """Refresh listener state from the API."""

        try:
            data = self.api_client.get_listeners()
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Listener Error",
                f"Failed to load listeners:\n{exc}",
            )
            return

        self.listener_list.clear()

        for listener in data.get("listeners", []):
            listener_id = listener["id"]
            running = listener["running"]

            state = "Running" if running else "Stopped"

            item = QListWidgetItem(
                f"{listener_id} — {state}"
            )

            item.setData(
                Qt.ItemDataRole.UserRole,
                listener,
            )

            self.listener_list.addItem(item)

        self.update_controls()

    def listener_selected(
        self,
        current: QListWidgetItem | None,
        previous: QListWidgetItem | None,
    ) -> None:
        """Update the UI when a listener is selected."""

        del previous

        if current is None:
            self.status_label.setText("No listener selected")
            self.update_controls()
            return

        listener = current.data(
            Qt.ItemDataRole.UserRole
        )

        if listener is None:
            return

        running = bool(listener["running"])

        self.status_label.setText(
            "Running" if running else "Stopped"
        )

        self.update_controls()

    def update_controls(self) -> None:
        """Update Start/Stop button state."""

        item = self.listener_list.currentItem()

        if item is None:
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            return

        listener = item.data(
            Qt.ItemDataRole.UserRole
        )

        if listener is None:
            return

        running = bool(listener["running"])

        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)

    def start_selected(self) -> None:
        """Start the selected listener."""

        item = self.listener_list.currentItem()

        if item is None:
            return

        listener = item.data(
            Qt.ItemDataRole.UserRole
        )

        listener_id = listener["id"]

        if listener_id == "tls":
            dialog = TLSConfigDialog(self)

            if dialog.exec() != QDialog.DialogCode.Accepted:
                return

            config = dialog.config()

        else:
            config = {}

        try:
            self.api_client.start_listener(
                listener_id,
                config,
            )
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Listener Error",
                f"Failed to start '{listener_id}':\n{exc}",
            )
            return

        self.refresh()

    def stop_selected(self) -> None:
        """Stop the selected listener."""

        item = self.listener_list.currentItem()

        if item is None:
            return

        listener = item.data(
            Qt.ItemDataRole.UserRole
        )

        listener_id = listener["id"]

        try:
            self.api_client.stop_listener(listener_id)
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Listener Error",
                f"Failed to stop '{listener_id}':\n{exc}",
            )
            return

        self.refresh()