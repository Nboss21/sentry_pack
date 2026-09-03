
"""
Unified C2 Sessions & Beacons workspace.

Features:
    - Up to 15 draggable PC session cards
    - Session selection and details panel
    - Session task history
    - Interactive command terminal
    - Quick commands
    - C2 activity log
    - Listener management
    - TLS listener configuration
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import (
    QPoint,
    QSize,
    Qt,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from gui.api_client import SentryPackAPIClient
from gui.styles import (
    COLOR_BG_CANVAS,
    COLOR_BG_CARD,
    COLOR_BG_ELEVATED,
    COLOR_BG_PANEL,
    COLOR_BORDER,
    COLOR_BORDER_LIGHT,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_RED,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
)


# ============================================================================
# TLS CONFIGURATION
# ============================================================================


class TLSConfigDialog(QDialog):
    """Dialog for configuring a TLS listener."""

    def __init__(
        self,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self.setWindowTitle("Start TLS Listener")
        self.setMinimumWidth(460)

        layout = QFormLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.host = QLineEdit("127.0.0.1")
        self.host.setPlaceholderText("Listener bind address")

        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(4443)

        self.certfile = QLineEdit()
        self.certfile.setPlaceholderText(
            "Path to certificate"
        )

        self.keyfile = QLineEdit()
        self.keyfile.setPlaceholderText(
            "Path to private key"
        )

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
        """Return TLS listener configuration."""

        return {
            "host": self.host.text().strip(),
            "port": self.port.value(),
            "certfile": self.certfile.text().strip(),
            "keyfile": self.keyfile.text().strip(),
        }


# ============================================================================
# SESSION CARD
# ============================================================================


class SessionCard(QFrame):
    """Draggable PC card representing one C2 session."""

    clicked = pyqtSignal(object)

    CARD_WIDTH = 118
    CARD_HEIGHT = 112

    def __init__(
        self,
        session: Dict[str, Any],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self.session = session
        self.drag_offset = QPoint()
        self.dragging = False

        self.setObjectName("sessionCard")
        self.setFixedSize(
            self.CARD_WIDTH,
            self.CARD_HEIGHT,
        )

        self._build_ui()
        self._update_style()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 7, 8, 7)
        layout.setSpacing(3)

        # --------------------------------------------------------------
        # PC image
        # --------------------------------------------------------------

        self.pc_label = QLabel()
        self.pc_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.pc_label.setFixedHeight(58)

        asset_path = (
            Path(__file__).resolve().parent.parent
            / "assets"
            / "pc.png"
        )

        if asset_path.exists():
            pixmap = QPixmap(str(asset_path))

            if not pixmap.isNull():
                pixmap = pixmap.scaled(
                    QSize(52, 52),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )

                self.pc_label.setPixmap(pixmap)
        else:
            self.pc_label.setText("🖥")
            self.pc_label.setStyleSheet(
                "font-size: 36px;"
            )

        layout.addWidget(self.pc_label)

        # --------------------------------------------------------------
        # Session ID
        # --------------------------------------------------------------

        session_id = str(
            self.session.get("id", "unknown")
        )

        self.id_label = QLabel(
            self._short_id(session_id)
        )

        self.id_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.id_label.setToolTip(session_id)

        self.id_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_PRIMARY};
                font-weight: 700;
                font-size: 11px;
            }}
            """
        )

        layout.addWidget(self.id_label)

        # --------------------------------------------------------------
        # Status
        # --------------------------------------------------------------

        status = str(
            self.session.get(
                "status",
                "unknown",
            )
        ).upper()

        self.status_label = QLabel(status)

        self.status_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {self._status_color(status)};
                font-size: 9px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(self.status_label)

    @staticmethod
    def _short_id(session_id: str) -> str:
        """Create a compact display ID."""

        if len(session_id) <= 16:
            return session_id

        return (
            session_id[:7]
            + "..."
            + session_id[-5:]
        )

    @staticmethod
    def _status_color(status: str) -> str:
        """Return status color."""

        status = status.lower()

        if status == "active":
            return COLOR_GREEN

        if status == "error":
            return COLOR_RED

        if status in {
            "inactive",
            "terminated",
        }:
            return COLOR_TEXT_MUTED

        return COLOR_TEXT_SECONDARY

    def _update_style(self) -> None:
        """Update card appearance."""

        self.setStyleSheet(
            f"""
            QFrame#sessionCard {{
                background-color: {COLOR_BG_CARD};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
            }}

            QFrame#sessionCard:hover {{
                background-color: {COLOR_BG_ELEVATED};
                border: 1px solid {COLOR_BORDER_LIGHT};
            }}
            """
        )

    def set_selected(
        self,
        selected: bool,
    ) -> None:
        """Change the visual selection state."""

        if selected:
            self.setStyleSheet(
                f"""
                QFrame#sessionCard {{
                    background-color: {COLOR_BG_ELEVATED};
                    border: 2px solid {COLOR_CYAN};
                    border-radius: 8px;
                }}
                """
            )
        else:
            self._update_style()

    # ------------------------------------------------------------------
    # Mouse interaction
    # ------------------------------------------------------------------

    def mousePressEvent(self, event) -> None:
        """Select the card and begin dragging."""

        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = True
            self.drag_offset = (
                event.position().toPoint()
            )

            self.clicked.emit(self.session)

        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        """Move the card freely inside its parent canvas."""

        if (
            self.dragging
            and event.buttons()
            & Qt.MouseButton.LeftButton
        ):
            parent = self.parentWidget()

            if parent is None:
                return

            new_pos = (
                self.pos()
                + event.position().toPoint()
                - self.drag_offset
            )

            max_x = max(
                0,
                parent.width()
                - self.width(),
            )

            max_y = max(
                0,
                parent.height()
                - self.height(),
            )

            new_pos.setX(
                max(0, min(new_pos.x(), max_x))
            )

            new_pos.setY(
                max(0, min(new_pos.y(), max_y))
            )

            self.move(new_pos)

        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        """Finish dragging."""

        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = False

        super().mouseReleaseEvent(event)


# ============================================================================
# SESSION CANVAS
# ============================================================================


class SessionCanvas(QFrame):
    """Free-positioned workspace containing session cards."""

    session_selected = pyqtSignal(object)

    def __init__(
        self,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self.cards: List[SessionCard] = []

        self.setObjectName("sessionCanvas")
        self.setMinimumSize(500, 330)

        self.setStyleSheet(
            f"""
            QFrame#sessionCanvas {{
                background-color: {COLOR_BG_CANVAS};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
            }}
            """
        )

    def clear_sessions(self) -> None:
        """Remove all session cards."""

        for card in self.cards:
            card.deleteLater()

        self.cards.clear()

    def set_sessions(
        self,
        sessions: List[Dict[str, Any]],
    ) -> None:
        """Render at most 15 sessions."""

        self.clear_sessions()

        sessions = sessions[:15]

        positions = self._generate_positions(
            len(sessions)
        )

        for index, session in enumerate(sessions):
            card = SessionCard(
                session,
                self,
            )

            card.move(*positions[index])

            card.clicked.connect(
                self._card_clicked
            )

            card.show()

            self.cards.append(card)

    def _card_clicked(
        self,
        session: Dict[str, Any],
    ) -> None:
        """Select a session card."""

        selected_id = str(
            session.get("id", "")
        )

        for card in self.cards:
            card_id = str(
                card.session.get("id", "")
            )

            card.set_selected(
                card_id == selected_id
            )

        self.session_selected.emit(session)

    def _generate_positions(
        self,
        count: int,
    ) -> List[tuple[int, int]]:
        """Generate initial positions for session cards."""

        if count <= 0:
            return []

        margin = 18
        gap_x = 22
        gap_y = 22

        usable_width = max(
            self.width(),
            700,
        )

        columns = max(
            1,
            usable_width
            // (
                SessionCard.CARD_WIDTH
                + gap_x
            ),
        )

        columns = min(columns, 6)

        positions: List[tuple[int, int]] = []

        for index in range(count):
            row = index // columns
            column = index % columns

            x = (
                margin
                + column
                * (
                    SessionCard.CARD_WIDTH
                    + gap_x
                )
            )

            y = (
                margin
                + row
                * (
                    SessionCard.CARD_HEIGHT
                    + gap_y
                )
            )

            positions.append((x, y))

        return positions


# ============================================================================
# SESSION DETAILS
# ============================================================================


class SessionDetailsPanel(QFrame):
    """Display information about the selected session."""

    def __init__(
        self,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self.setObjectName("sessionDetails")

        self.setMinimumWidth(250)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("SESSION DETAILS")
        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 13px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            """
        )

        layout.addWidget(title)

        self.session_name = QLabel(
            "No session selected"
        )

        self.session_name.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_PRIMARY};
                font-size: 16px;
                font-weight: 700;
            }}
            """
        )

        layout.addWidget(self.session_name)

        layout.addSpacing(8)

        self.fields: Dict[str, QLabel] = {}

        for key, label in (
            ("id", "Session ID"),
            ("target_id", "Target"),
            ("transport", "Transport"),
            ("status", "Status"),
            ("last_seen", "Last Seen"),
            ("session_key", "Session Key"),
            ("hostname", "Hostname"),
            ("platform", "Platform"),
        ):
            row = QVBoxLayout()
            row.setSpacing(2)

            label_widget = QLabel(label.upper())
            label_widget.setStyleSheet(
                f"""
                QLabel {{
                    color: {COLOR_TEXT_MUTED};
                    font-size: 9px;
                    font-weight: 700;
                }}
                """
            )

            value_widget = QLabel("—")
            value_widget.setWordWrap(True)
            value_widget.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )

            value_widget.setStyleSheet(
                f"""
                QLabel {{
                    color: {COLOR_TEXT_PRIMARY};
                    font-family: Consolas, monospace;
                    font-size: 11px;
                }}
                """
            )

            row.addWidget(label_widget)
            row.addWidget(value_widget)

            layout.addLayout(row)

            self.fields[key] = value_widget

        layout.addStretch()

        self.setStyleSheet(
            f"""
            QFrame#sessionDetails {{
                background-color: {COLOR_BG_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
            }}
            """
        )

    def clear(self) -> None:
        """Clear session information."""

        self.session_name.setText(
            "No session selected"
        )

        for label in self.fields.values():
            label.setText("—")

    def set_session(
        self,
        session: Dict[str, Any],
    ) -> None:
        """Display session details."""

        session_id = str(
            session.get("id", "unknown")
        )

        self.session_name.setText(
            self._short_id(session_id)
        )

        for key, label in self.fields.items():
            value = session.get(key)

            if value is None:
                value = "—"

            if key == "target_id" and value != "—":
                value = f"Target #{value}"

            if key == "transport":
                value = str(value).upper()

            if key == "status":
                value = str(value).upper()

            label.setText(str(value))

    @staticmethod
    def _short_id(value: str) -> str:
        if len(value) <= 24:
            return value

        return (
            value[:12]
            + "..."
            + value[-8:]
        )


# ============================================================================
# LISTENER CARD
# ============================================================================
# class TLSConfigDialog(QDialog):
#     """Dialog used to configure a listener in the GUI."""

#     def __init__(self, parent: QWidget | None = None) -> None:
#         super().__init__(parent)

#         self.setWindowTitle("Create Listener")
#         self.setMinimumWidth(420)

#         layout = QFormLayout(self)

#         self.transport = QComboBox()
#         self.transport.addItems([
#             "TLS",
#             "HTTP",
#             "HTTPS",
#             "TCP",
#             "DNS",
#         ])

#         self.host = QLineEdit("127.0.0.1")

#         self.port = QSpinBox()
#         self.port.setRange(1, 65535)
#         self.port.setValue(4443)

#         self.certfile = QLineEdit()
#         self.certfile.setPlaceholderText("Certificate path")

#         self.keyfile = QLineEdit()
#         self.keyfile.setPlaceholderText("Private key path")

#         layout.addRow("Transport:", self.transport)
#         layout.addRow("Host:", self.host)
#         layout.addRow("Port:", self.port)
#         layout.addRow("Certificate:", self.certfile)
#         layout.addRow("Private key:", self.keyfile)

#         self.transport.currentTextChanged.connect(
#             self._transport_changed
#         )

#         buttons = QDialogButtonBox(
#             QDialogButtonBox.StandardButton.Ok
#             | QDialogButtonBox.StandardButton.Cancel
#         )

#         buttons.accepted.connect(self.accept)
#         buttons.rejected.connect(self.reject)

#         layout.addRow(buttons)

#         self._transport_changed(self.transport.currentText())

#     def _transport_changed(self, transport: str) -> None:
#         is_tls = transport == "TLS"

#         self.certfile.setEnabled(is_tls)
#         self.keyfile.setEnabled(is_tls)

#         if transport == "TLS":
#             self.port.setValue(4443)
#         elif transport == "HTTP":
#             self.port.setValue(8080)
#         elif transport == "HTTPS":
#             self.port.setValue(8443)
#         elif transport == "TCP":
#             self.port.setValue(9001)
#         elif transport == "DNS":
#             self.port.setValue(53)

#     def config(self) -> dict[str, Any]:
#         return {
#             "transport": self.transport.currentText(),
#             "host": self.host.text().strip(),
#             "port": self.port.value(),
#             "certfile": self.certfile.text().strip(),
#             "keyfile": self.keyfile.text().strip(),
#         }

class ListenerCard(QFrame):
    """Visual listener entry."""

    action_clicked = pyqtSignal(object)

    def __init__(
        self,
        listener: Dict[str, Any],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self.listener = listener

        self.setObjectName("listenerCard")
        self.setMinimumHeight(84)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(
            14,
            10,
            14,
            10,
        )
        layout.setSpacing(12)

        running = bool(
            listener.get("running", False)
        )

        self.dot = QLabel()
        self.dot.setFixedSize(11, 11)

        self.dot.setStyleSheet(
            f"""
            QLabel {{
                background-color: {
                    COLOR_GREEN
                    if running
                    else COLOR_TEXT_MUTED
                };
                border-radius: 5px;
            }}
            """
        )

        layout.addWidget(self.dot)

        info = QVBoxLayout()
        info.setSpacing(2)

        listener_id = str(
            listener.get("id", "unknown")
        )

        name = QLabel(
            listener_id.upper()
        )

        name.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_PRIMARY};
                font-size: 13px;
                font-weight: 700;
            }}
            """
        )

        status = QLabel(
            "RUNNING" if running else "STOPPED"
        )

        status.setStyleSheet(
            f"""
            QLabel {{
                color: {
                    COLOR_GREEN
                    if running
                    else COLOR_TEXT_SECONDARY
                };
                font-size: 10px;
                font-weight: 700;
            }}
            """
        )

        info.addWidget(name)
        info.addWidget(status)

        layout.addLayout(info)
        layout.addStretch()

        self.action_button = QPushButton(
            "Stop" if running else "Start"
        )

        self.action_button.setMinimumWidth(78)

        if running:
            self.action_button.setProperty(
                "danger",
                True,
            )
        else:
            self.action_button.setProperty(
                "primary",
                True,
            )

        self.action_button.clicked.connect(
            lambda checked=False:
            self.action_clicked.emit(
                self.listener
            )
        )

        layout.addWidget(
            self.action_button
        )

        self.setStyleSheet(
            f"""
            QFrame#listenerCard {{
                background-color: {COLOR_BG_CARD};
                border: 1px solid {COLOR_BORDER};
                border-radius: 7px;
            }}

            QFrame#listenerCard:hover {{
                background-color: {COLOR_BG_ELEVATED};
                border-color: {COLOR_BORDER_LIGHT};
            }}
            """
        )
# class ListenerCard(QFrame):
#     """Visual representation of one listener."""

#     start_requested = pyqtSignal(str)
#     stop_requested = pyqtSignal(str)

#     def __init__(
#         self,
#         listener_id: str,
#         transport: str,
#         running: bool = False,
#         real_backend: bool = False,
#         parent: QWidget | None = None,
#     ) -> None:
#         super().__init__(parent)

#         self.listener_id = listener_id
#         self.transport = transport
#         self.running = running
#         self.real_backend = real_backend

#         self.setObjectName("listenerCard")
#         self.setFrameShape(QFrame.Shape.StyledPanel)

#         layout = QVBoxLayout(self)

#         header = QHBoxLayout()

#         title = QLabel(
#             f"<b>{self.listener_id}</b>"
#         )

#         transport_label = QLabel(
#             f"{self._transport_name()} Transport"
#         )

#         header.addWidget(title)
#         header.addStretch()
#         header.addWidget(transport_label)

#         layout.addLayout(header)

#         self.status_label = QLabel()
#         layout.addWidget(self.status_label)

#         buttons = QHBoxLayout()

#         self.start_button = QPushButton("Start")
#         self.stop_button = QPushButton("Stop")

#         self.start_button.clicked.connect(
#             lambda: self.start_requested.emit(self.listener_id)
#         )

#         self.stop_button.clicked.connect(
#             lambda: self.stop_requested.emit(self.listener_id)
#         )

#         buttons.addWidget(self.start_button)
#         buttons.addWidget(self.stop_button)
#         buttons.addStretch()

#         layout.addLayout(buttons)

#         self._update_state()

#     def _transport_name(self) -> str:
#         names = {
#             "TLS": "TLS Encrypted",
#             "HTTP": "HTTP",
#             "HTTPS": "HTTPS",
#             "TCP": "TCP",
#             "DNS": "DNS",
#         }

#         return names.get(
#             self.transport.upper(),
#             self.transport,
#         )

#     def set_running(self, running: bool) -> None:
#         self.running = running
#         self._update_state()

#     def _update_state(self) -> None:
#         if self.running:
#             self.status_label.setText(
#                 "Status: RUNNING"
#             )
#             self.stop_button.setEnabled(True)
#             self.start_button.setEnabled(False)
#         else:
#             self.status_label.setText(
#                 "Status: STOPPED"
#             )
#             self.stop_button.setEnabled(False)
#             self.start_button.setEnabled(True)

# ============================================================================
# LISTENER PANEL
# ============================================================================


class ListenerPanel(QWidget):
    """Listener management panel."""

    listener_event = pyqtSignal(str)

    def __init__(
        self,
        api_client: SentryPackAPIClient,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self.api_client = api_client

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            14,
            14,
            14,
            14,
        )
        layout.setSpacing(10)

        # --------------------------------------------------------------
        # Header
        # --------------------------------------------------------------

        header = QHBoxLayout()

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        title = QLabel(
            "C2 LISTENERS"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 14px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            """
        )

        self.count_label = QLabel(
            "0 listeners"
        )

        self.count_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_SECONDARY};
                font-size: 11px;
            }}
            """
        )

        title_layout.addWidget(title)
        title_layout.addWidget(
            self.count_label
        )

        header.addLayout(title_layout)
        header.addStretch()

        self.refresh_button = QPushButton(
            "⟳  Refresh"
        )

        self.refresh_button.clicked.connect(
            self.refresh
        )

        header.addWidget(
            self.refresh_button
        )

        layout.addLayout(header)

        # --------------------------------------------------------------
        # Listener list
        # --------------------------------------------------------------

        self.listener_list = QListWidget()

        self.listener_list.setObjectName(
            "listenerList"
        )

        self.listener_list.setSpacing(6)

        layout.addWidget(
            self.listener_list,
            1,
        )

        # --------------------------------------------------------------
        # Selection
        # --------------------------------------------------------------

        self.selection_label = QLabel(
            "No listener selected"
        )

        self.selection_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_SECONDARY};
                background-color: {COLOR_BG_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding: 7px 10px;
            }}
            """
        )

        layout.addWidget(
            self.selection_label
        )

        # --------------------------------------------------------------
        # Bottom controls
        # --------------------------------------------------------------

        controls = QHBoxLayout()

        self.start_button = QPushButton(
            "Start"
        )

        self.start_button.setProperty(
            "primary",
            True,
        )

        self.stop_button = QPushButton(
            "Stop"
        )

        self.stop_button.setProperty(
            "danger",
            True,
        )

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(False)

        self.start_button.clicked.connect(
            self.start_selected
        )

        self.stop_button.clicked.connect(
            self.stop_selected
        )

        controls.addWidget(
            self.start_button
        )

        controls.addWidget(
            self.stop_button
        )

        controls.addStretch()

        layout.addLayout(controls)

        self.listener_list.currentItemChanged.connect(
            self._listener_selected
        )

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Reload listeners from the backend."""

        try:
            data = (
                self.api_client
                .get_listeners()
            )
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Listener Error",
                f"Failed to load listeners:\n{exc}",
            )
            return

        listeners = data.get(
            "listeners",
            [],
        )

        self.listener_list.clear()

        self.count_label.setText(
            f"{len(listeners)} listener"
            + (
                ""
                if len(listeners) == 1
                else "s"
            )
        )

        for listener in listeners:
            item = QListWidgetItem()

            item.setData(
                Qt.ItemDataRole.UserRole,
                listener,
            )

            card = ListenerCard(
                listener
            )

            item.setSizeHint(
                card.sizeHint()
            )

            self.listener_list.addItem(
                item
            )

            self.listener_list.setItemWidget(
                item,
                card,
            )

            card.action_clicked.connect(
                self._card_action
            )

        self._update_controls()

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def _listener_selected(
        self,
        current: QListWidgetItem | None,
        previous: QListWidgetItem | None,
    ) -> None:
        del previous

        if current is None:
            self.selection_label.setText(
                "No listener selected"
            )

            self._update_controls()
            return

        listener = current.data(
            Qt.ItemDataRole.UserRole
        )

        if not listener:
            return

        listener_id = str(
            listener.get("id", "unknown")
        )

        running = bool(
            listener.get(
                "running",
                False,
            )
        )

        self.selection_label.setText(
            f"Selected: {listener_id}  •  "
            f"{'RUNNING' if running else 'STOPPED'}"
        )

        self._update_controls()

    def _update_controls(self) -> None:
        item = (
            self.listener_list.currentItem()
        )

        if item is None:
            self.start_button.setEnabled(
                False
            )
            self.stop_button.setEnabled(
                False
            )
            return

        listener = item.data(
            Qt.ItemDataRole.UserRole
        )

        if not listener:
            return

        running = bool(
            listener.get(
                "running",
                False,
            )
        )

        self.start_button.setEnabled(
            not running
        )

        self.stop_button.setEnabled(
            running
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _card_action(
        self,
        listener: Dict[str, Any],
    ) -> None:
        running = bool(
            listener.get(
                "running",
                False,
            )
        )

        if running:
            self.stop_listener(
                listener
            )
        else:
            self.start_listener(
                listener
            )

    def start_selected(self) -> None:
        item = (
            self.listener_list.currentItem()
        )

        if item is None:
            return

        listener = item.data(
            Qt.ItemDataRole.UserRole
        )

        if listener:
            self.start_listener(
                listener
            )

    def stop_selected(self) -> None:
        item = (
            self.listener_list.currentItem()
        )

        if item is None:
            return

        listener = item.data(
            Qt.ItemDataRole.UserRole
        )

        if listener:
            self.stop_listener(
                listener
            )

    def start_listener(
        self,
        listener: Dict[str, Any],
    ) -> None:
        """Start a listener."""

        listener_id = str(
            listener.get("id", "")
        )

        if not listener_id:
            return

        config: Dict[str, Any] = {}

        if listener_id.lower() == "tls":
            dialog = TLSConfigDialog(
                self
            )

            if (
                dialog.exec()
                != QDialog.DialogCode.Accepted
            ):
                return

            config = dialog.config()

        try:
            self.api_client.start_listener(
                listener_id,
                config,
            )
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Listener Error",
                f"Failed to start "
                f"'{listener_id}':\n{exc}",
            )
            return

        self.listener_event.emit(
            f"Listener '{listener_id}' started"
        )

        self.refresh()

    def stop_listener(
        self,
        listener: Dict[str, Any],
    ) -> None:
        """Stop a listener."""

        listener_id = str(
            listener.get("id", "")
        )

        if not listener_id:
            return

        try:
            self.api_client.stop_listener(
                listener_id
            )
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Listener Error",
                f"Failed to stop "
                f"'{listener_id}':\n{exc}",
            )
            return

        self.listener_event.emit(
            f"Listener '{listener_id}' stopped"
        )

        self.refresh()
# class TLSConfigDialog(QDialog):
#     """Dialog used to configure a listener in the GUI."""

#     def __init__(self, parent: QWidget | None = None) -> None:
#         super().__init__(parent)

#         self.setWindowTitle("Create Listener")
#         self.setMinimumWidth(420)

#         layout = QFormLayout(self)

#         self.transport = QComboBox()
#         self.transport.addItems([
#             "TLS",
#             "HTTP",
#             "HTTPS",
#             "TCP",
#             "DNS",
#         ])

#         self.host = QLineEdit("127.0.0.1")

#         self.port = QSpinBox()
#         self.port.setRange(1, 65535)
#         self.port.setValue(4443)

#         self.certfile = QLineEdit()
#         self.certfile.setPlaceholderText("Certificate path")

#         self.keyfile = QLineEdit()
#         self.keyfile.setPlaceholderText("Private key path")

#         layout.addRow("Transport:", self.transport)
#         layout.addRow("Host:", self.host)
#         layout.addRow("Port:", self.port)
#         layout.addRow("Certificate:", self.certfile)
#         layout.addRow("Private key:", self.keyfile)

#         self.transport.currentTextChanged.connect(
#             self._transport_changed
#         )

#         buttons = QDialogButtonBox(
#             QDialogButtonBox.StandardButton.Ok
#             | QDialogButtonBox.StandardButton.Cancel
#         )

#         buttons.accepted.connect(self.accept)
#         buttons.rejected.connect(self.reject)

#         layout.addRow(buttons)

#         self._transport_changed(self.transport.currentText())

#     def _transport_changed(self, transport: str) -> None:
#         is_tls = transport == "TLS"

#         self.certfile.setEnabled(is_tls)
#         self.keyfile.setEnabled(is_tls)

#         if transport == "TLS":
#             self.port.setValue(4443)
#         elif transport == "HTTP":
#             self.port.setValue(8080)
#         elif transport == "HTTPS":
#             self.port.setValue(8443)
#         elif transport == "TCP":
#             self.port.setValue(9001)
#         elif transport == "DNS":
#             self.port.setValue(53)

#     def config(self) -> dict[str, Any]:
#         return {
#             "transport": self.transport.currentText(),
#             "host": self.host.text().strip(),
#             "port": self.port.value(),
#             "certfile": self.certfile.text().strip(),
#             "keyfile": self.keyfile.text().strip(),
#         }
# class ListenerPanel(QWidget):
#     """Listener management panel inside the C2 workspace."""

#     def __init__(
#         self,
#         api_client: SentryPackAPIClient | None = None,
#         parent: QWidget | None = None,
#     ) -> None:
#         super().__init__(parent)

#         self.api_client = api_client or SentryPackAPIClient()

#         self.listener_cards: dict[str, ListenerCard] = {}

#         self._fake_counter = 0

#         self._build_ui()

#         self.refresh()

#     def _build_ui(self) -> None:
#         layout = QVBoxLayout(self)

#         # --------------------------------------------------------------
#         # Header
#         # --------------------------------------------------------------

#         header = QHBoxLayout()

#         title = QLabel("Listeners")
#         title.setObjectName("sectionTitle")

#         header.addWidget(title)
#         header.addStretch()

#         self.new_button = QPushButton("+ New Listener")
#         self.refresh_button = QPushButton("Refresh")

#         self.new_button.clicked.connect(
#             self.create_listener
#         )

#         self.refresh_button.clicked.connect(
#             self.refresh
#         )

#         header.addWidget(self.new_button)
#         header.addWidget(self.refresh_button)

#         layout.addLayout(header)

#         # --------------------------------------------------------------
#         # Listener list
#         # --------------------------------------------------------------

#         self.scroll = QScrollArea()
#         self.scroll.setWidgetResizable(True)
#         self.scroll.setFrameShape(QFrame.Shape.NoFrame)

#         self.container = QWidget()

#         self.listener_layout = QVBoxLayout(
#             self.container
#         )

#         self.listener_layout.setAlignment(
#             Qt.AlignmentFlag.AlignTop
#         )

#         self.scroll.setWidget(self.container)

#         layout.addWidget(self.scroll)

#     # ------------------------------------------------------------------
#     # Backend listeners
#     # ------------------------------------------------------------------

#     def refresh(self) -> None:
#         """Refresh real listeners from the API."""

#         try:
#             data = self.api_client.get_listeners()

#         except Exception as exc:
#             QMessageBox.warning(
#                 self,
#                 "Listener Error",
#                 f"Failed to load listeners:\n{exc}",
#             )
#             return

#         listeners = data.get("listeners", [])

#         # Don't destroy UI-only listeners.
#         fake_cards = {
#             key: card
#             for key, card in self.listener_cards.items()
#             if not card.real_backend
#         }

#         # Remove all cards from layout.
#         while self.listener_layout.count():
#             item = self.listener_layout.takeAt(0)

#             widget = item.widget()

#             if widget is not None:
#                 widget.deleteLater()

#         self.listener_cards.clear()

#         # Recreate backend listeners.
#         for listener in listeners:
#             listener_id = str(
#                 listener.get("id", "")
#             )

#             running = bool(
#                 listener.get("running", False)
#             )

#             card = ListenerCard(
#                 listener_id=listener_id,
#                 transport="TLS",
#                 running=running,
#                 real_backend=True,
#             )

#             card.start_requested.connect(
#                 self.start_listener
#             )

#             card.stop_requested.connect(
#                 self.stop_listener
#             )

#             self.listener_cards[listener_id] = card

#             self.listener_layout.addWidget(card)

#         # Put UI-only listeners back.
#         for listener_id, card in fake_cards.items():
#             self.listener_cards[listener_id] = card

#             self.listener_layout.addWidget(card)

#         if not listeners and not fake_cards:
#             empty = QLabel(
#                 "No listeners available."
#             )

#             empty.setAlignment(
#                 Qt.AlignmentFlag.AlignCenter
#             )

#             self.listener_layout.addWidget(empty)

#     # ------------------------------------------------------------------
#     # Create listener - UI only for now
#     # ------------------------------------------------------------------

#     def create_listener(self) -> None:
#         dialog = TLSConfigDialog(self)

#         if dialog.exec() != QDialog.DialogCode.Accepted:
#             return

#         config = dialog.config()

#         self._fake_counter += 1

#         transport = config["transport"]

#         listener_id = (
#             f"{transport.lower()}-"
#             f"listener-{self._fake_counter}"
#         )

#         card = ListenerCard(
#             listener_id=listener_id,
#             transport=transport,
#             running=False,
#             real_backend=False,
#         )

#         card.start_requested.connect(
#             self.start_listener
#         )

#         card.stop_requested.connect(
#             self.stop_listener
#         )

#         self.listener_cards[listener_id] = card

#         self.listener_layout.addWidget(card)

#     # ------------------------------------------------------------------
#     # Start
#     # ------------------------------------------------------------------

#     def start_listener(
#         self,
#         listener_id: str,
#     ) -> None:
#         card = self.listener_cards.get(listener_id)

#         if card is None:
#             return

#         # --------------------------------------------------------------
#         # Real backend listener
#         # --------------------------------------------------------------

#         if card.real_backend:
#             try:
#                 self.api_client.start_listener(
#                     listener_id,
#                     {
#                         "host": "127.0.0.1",
#                         "port": 4443,
#                     },
#                 )

#                 card.set_running(True)

#             except Exception as exc:
#                 QMessageBox.warning(
#                     self,
#                     "Listener Error",
#                     f"Failed to start listener:\n{exc}",
#                 )

#             return

#         # --------------------------------------------------------------
#         # UI-only listener
#         # --------------------------------------------------------------

#         card.set_running(True)

#     # ------------------------------------------------------------------
#     # Stop
#     # ------------------------------------------------------------------

#     def stop_listener(
#         self,
#         listener_id: str,
#     ) -> None:
#         card = self.listener_cards.get(listener_id)

#         if card is None:
#             return

#         # --------------------------------------------------------------
#         # Real backend listener
#         # --------------------------------------------------------------

#         if card.real_backend:
#             try:
#                 self.api_client.stop_listener(
#                     listener_id
#                 )

#                 card.set_running(False)

#             except Exception as exc:
#                 QMessageBox.warning(
#                     self,
#                     "Listener Error",
#                     f"Failed to stop listener:\n{exc}",
#                 )

#             return

#         # --------------------------------------------------------------
#         # UI-only listener
#         # --------------------------------------------------------------

#         card.set_running(False)
# ============================================================================
# MAIN C2 WORKSPACE
# ============================================================================


class SessionsView(QWidget):
    """
    Unified C2 operator workspace.

    Layout:

        ┌───────────────────────────────────────────────┐
        │ C2 Sessions & Beacons                         │
        ├──────────────────────────────┬────────────────┤
        │                              │                │
        │       Session Canvas         │ Session        │
        │       PC cards               │ Details        │
        │                              │                │
        ├──────────────────────────────┴────────────────┤
        │ Activity | Terminal | Listeners               │
        ├────────────────────────────────────────────────┤
        │ Selected bottom-tab content                    │
        └────────────────────────────────────────────────┘
    """

    MAX_SESSIONS = 15

    def __init__(
        self,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)

        self.api_client = (
            SentryPackAPIClient()
        )

        self.sessions: List[
            Dict[str, Any]
        ] = []

        self.selected_session_id: (
            Optional[str]
        ) = None

        self._build_ui()
        self.load_sessions()

    # ==================================================================
    # UI
    # ==================================================================

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)

        main_layout.setContentsMargins(
            14,
            14,
            14,
            14,
        )

        main_layout.setSpacing(10)

        # --------------------------------------------------------------
        # Top bar
        # --------------------------------------------------------------

        top_bar = QHBoxLayout()

        title = QLabel(
            "C2 Sessions & Beacons"
        )

        title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-size: 18px;
                font-weight: 700;
            }}
            """
        )

        top_bar.addWidget(title)

        top_bar.addStretch()

        self.session_count_label = QLabel(
            "0 active / 0 total"
        )

        self.session_count_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_SECONDARY};
                margin-right: 8px;
            }}
            """
        )

        top_bar.addWidget(
            self.session_count_label
        )

        self.refresh_sessions_button = (
            QPushButton(
                "⟳  Refresh"
            )
        )

        self.refresh_sessions_button.clicked.connect(
            self.load_sessions
        )

        top_bar.addWidget(
            self.refresh_sessions_button
        )

        main_layout.addLayout(
            top_bar
        )

        # --------------------------------------------------------------
        # Workspace
        # --------------------------------------------------------------

        workspace_splitter = QSplitter(
            Qt.Orientation.Horizontal
        )

        self.session_canvas = (
            SessionCanvas()
        )

        self.session_canvas.session_selected.connect(
            self._on_session_selected
        )

        workspace_splitter.addWidget(
            self.session_canvas
        )

        self.details_panel = (
            SessionDetailsPanel()
        )

        workspace_splitter.addWidget(
            self.details_panel
        )

        workspace_splitter.setSizes(
            [760, 280]
        )

        main_layout.addWidget(
            workspace_splitter,
            3,
        )

        # --------------------------------------------------------------
        # Bottom dock
        # --------------------------------------------------------------

        self.bottom_tabs = QTabWidget()

        self.bottom_tabs.setObjectName(
            "c2BottomDock"
        )

        # Activity
        self.activity_log = (
            QPlainTextEdit()
        )

        self.activity_log.setReadOnly(
            True
        )

        self.activity_log.setPlaceholderText(
            "C2 activity will appear here..."
        )

        self.bottom_tabs.addTab(
            self.activity_log,
            "Activity",
        )

        # Terminal
        terminal = (
            self._build_terminal()
        )

        self.bottom_tabs.addTab(
            terminal,
            "Terminal",
        )

        # Listeners
        self.listener_panel = (
            ListenerPanel(
                self.api_client,
            )
        )

        self.listener_panel.listener_event.connect(
            self._on_listener_event
        )

        self.bottom_tabs.addTab(
            self.listener_panel,
            "Listeners",
        )

        main_layout.addWidget(
            self.bottom_tabs,
            2,
        )

    # ==================================================================
    # Terminal
    # ==================================================================

    def _build_terminal(self) -> QWidget:
        terminal = QWidget()

        layout = QVBoxLayout(
            terminal
        )

        layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )

        layout.setSpacing(7)

        # --------------------------------------------------------------
        # Terminal header
        # --------------------------------------------------------------

        header = QHBoxLayout()

        self.terminal_title = QLabel(
            "Interactive Shell: No Session Selected"
        )

        self.terminal_title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CYAN};
                font-weight: 700;
            }}
            """
        )

        header.addWidget(
            self.terminal_title
        )

        header.addStretch()

        for command in (
            "whoami",
            "ipconfig",
            "id",
            "uname -a",
            "pwd",
        ):
            button = QPushButton(
                command
            )

            button.setFixedHeight(25)

            button.setStyleSheet(
                """
                QPushButton {
                    font-size: 11px;
                    padding: 2px 8px;
                }
                """
            )

            button.clicked.connect(
                lambda checked=False,
                cmd=command:
                self._send_command_str(cmd)
            )

            header.addWidget(
                button
            )

        layout.addLayout(
            header
        )

        # --------------------------------------------------------------
        # Console
        # --------------------------------------------------------------

        self.console_output = (
            QPlainTextEdit()
        )

        self.console_output.setReadOnly(
            True
        )

        self.console_output.setPlaceholderText(
            "Select a C2 session to view "
            "task history and dispatch commands."
        )

        layout.addWidget(
            self.console_output,
            1,
        )

        # --------------------------------------------------------------
        # Command input
        # --------------------------------------------------------------

        input_bar = QHBoxLayout()

        self.cmd_input = QLineEdit()

        self.cmd_input.setPlaceholderText(
            "Enter command..."
        )

        self.cmd_input.returnPressed.connect(
            self._send_command
        )

        input_bar.addWidget(
            self.cmd_input
        )

        self.send_button = QPushButton(
            "⚡ Execute"
        )

        self.send_button.setProperty(
            "primary",
            True,
        )

        self.send_button.clicked.connect(
            self._send_command
        )

        input_bar.addWidget(
            self.send_button
        )

        layout.addLayout(
            input_bar
        )

        return terminal

    # ==================================================================
    # Sessions
    # ==================================================================

    def load_sessions(self) -> None:
        """Load sessions from the backend."""

        try:
            data = (
                self.api_client
                .get_c2_sessions()
            )

            sessions = data.get(
                "sessions",
                [],
            )

            self.sessions = (
                sessions[: self.MAX_SESSIONS]
            )

            self.session_canvas.set_sessions(
                self.sessions
            )

            active_count = sum(
                1
                for session in self.sessions
                if str(
                    session.get(
                        "status",
                        "",
                    )
                ).lower()
                == "active"
            )

            self.session_count_label.setText(
                f"{active_count} active / "
                f"{len(self.sessions)} total"
            )

            self._log_activity(
                f"Session list refreshed "
                f"({len(self.sessions)} session(s))"
            )

        except Exception as exc:
            self.sessions = []

            self.session_canvas.clear_sessions()

            self.session_count_label.setText(
                "Unable to load sessions"
            )

            self._log_activity(
                f"Failed to load sessions: {exc}"
            )

    def _on_session_selected(
        self,
        session: Dict[str, Any],
    ) -> None:
        """Handle session selection."""

        session_id = str(
            session.get("id", "")
        )

        if not session_id:
            return

        self.selected_session_id = (
            session_id
        )

        self.details_panel.set_session(
            session
        )

        transport = str(
            session.get(
                "transport",
                "unknown",
            )
        ).upper()

        self.terminal_title.setText(
            "Interactive Shell: "
            f"Session {session_id} "
            f"({transport})"
        )

        self._log_activity(
            f"Session selected: "
            f"{session_id}"
        )

        self._load_session_history()

        # Automatically show terminal.
        self.bottom_tabs.setCurrentIndex(
            1
        )

    # ==================================================================
    # Session history
    # ==================================================================

    def _load_session_history(self) -> None:
        """Load task history for selected session."""

        if not self.selected_session_id:
            return

        try:
            data = (
                self.api_client
                .get_session_tasks(
                    self.selected_session_id
                )
            )

            tasks = data.get(
                "tasks",
                [],
            )

            self.console_output.clear()

            self.console_output.appendPlainText(
                f"=== Session "
                f"{self.selected_session_id} ==="
            )

            if not tasks:
                self.console_output.appendPlainText(
                    "\nNo task history."
                )
                return

            for task in tasks:
                command = str(
                    task.get(
                        "command",
                        task.get(
                            "payload",
                            "",
                        ),
                    )
                )

                status = str(
                    task.get(
                        "status",
                        "unknown",
                    )
                )

                output = (
                    task.get("output")
                    or "(no output returned)"
                )

                self.console_output.appendPlainText(
                    f"\n"
                    f"[session:"
                    f"{self.selected_session_id}]$ "
                    f"{command}"
                )

                self.console_output.appendPlainText(
                    f"[{status}]"
                )

                self.console_output.appendPlainText(
                    str(output)
                )

        except Exception as exc:
            self.console_output.appendPlainText(
                f"[error] "
                f"Failed to fetch task history: "
                f"{exc}"
            )

    # ==================================================================
    # Commands
    # ==================================================================

    def _send_command_str(
        self,
        command: str,
    ) -> None:
        """Put a quick command into the input."""

        self.cmd_input.setText(
            command
        )

        self._send_command()

    def _send_command(self) -> None:
        """Queue a command for the selected session."""

        command = (
            self.cmd_input.text().strip()
        )

        if not command:
            return

        if not self.selected_session_id:
            QMessageBox.warning(
                self,
                "No Session",
                "Select a C2 session first.",
            )
            return

        self.console_output.appendPlainText(
            f"\n[dispatching] -> {command}"
        )

        self.cmd_input.clear()

        try:
            result = (
                self.api_client
                .create_session_task(
                    self.selected_session_id,
                    command,
                )
            )

            task_id = result.get(
                "task_id",
                "",
            )

            self.console_output.appendPlainText(
                f"[task queued: #{task_id}] "
                "Waiting for agent..."
            )

            self._log_activity(
                f"Task queued on session "
                f"{self.selected_session_id}: "
                f"{command}"
            )

            QTimer.singleShot(
                1500,
                self._load_session_history,
            )

        except Exception as exc:
            self.console_output.appendPlainText(
                f"[error] "
                f"Failed to enqueue task: "
                f"{exc}"
            )

            self._log_activity(
                f"Task dispatch failed on "
                f"session "
                f"{self.selected_session_id}: "
                f"{exc}"
            )

    # ==================================================================
    # Activity
    # ==================================================================

    def _log_activity(
        self,
        message: str,
    ) -> None:
        """Add a timestamped C2 event to the activity log."""

        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )

        self.activity_log.appendPlainText(
            f"[{timestamp}] {message}"
        )

        scrollbar = (
            self.activity_log.verticalScrollBar()
        )

        scrollbar.setValue(
            scrollbar.maximum()
        )

    def _on_listener_event(
        self,
        message: str,
    ) -> None:
        """Receive listener activity events."""

        self._log_activity(
            message
        )
