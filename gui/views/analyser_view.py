"""
Connection & Transport Analyser view.

Features:
  - Transport protocol listener status (TLS, HTTPS, WebSocket)
  - Interactive network socket probe (TCP connectivity & latency test)
  - Channel diagnostics and active egress telemetry
"""

from __future__ import annotations

import socket
import time
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTextEdit,
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
    get_pill_style,
)


class ListenerCard(QFrame):
    """Status card for a transport listener."""

    def __init__(self, name: str, port: int, protocol: str, status: str = "LISTENING", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(
            f"QFrame {{ background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; "
            f"border-radius: 8px; padding: 12px; }}"
        )
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        header = QHBoxLayout()
        title = QLabel(name)
        title.setStyleSheet(f"font-weight: bold; color: {COLOR_TEXT_PRIMARY}; font-size: 14px;")
        header.addWidget(title)

        header.addStretch()

        status_lbl = QLabel(f"● {status}")
        status_lbl.setStyleSheet(f"color: {COLOR_GREEN}; font-weight: bold; font-size: 11px;")
        header.addWidget(status_lbl)
        layout.addLayout(header)

        detail_lbl = QLabel(f"Protocol: {protocol.upper()}  |  Port: {port}  |  Bind: 0.0.0.0")
        detail_lbl.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; font-family: monospace; font-size: 11px;")
        layout.addWidget(detail_lbl)


class AnalyserView(QWidget):
    """Connection & Transport Analyser View."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(12)

        # ── Header ──────────────────────────────────────────────────────
        header = QHBoxLayout()
        title = QLabel("Connection & Listener Analyser")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLOR_CYAN};")
        header.addWidget(title)
        header.addStretch()
        main_layout.addLayout(header)

        # ── Listener Status Cards ───────────────────────────────────────
        listeners_label = QLabel("Active C2 Transport Listeners:")
        listeners_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        main_layout.addWidget(listeners_label)

        grid = QGridLayout()
        grid.addWidget(ListenerCard("TLS Encrypted Beacon Listener", 8443, "TLS v1.3 / TCP"), 0, 0)
        grid.addWidget(ListenerCard("HTTPS Proxy Channel Listener", 8080, "HTTP/1.1 over TLS"), 0, 1)
        grid.addWidget(ListenerCard("WebSocket Live Telemetry Channel", 8000, "WSS / ASGI"), 1, 0)
        grid.addWidget(ListenerCard("Raw TCP Reverse Shell Listener", 4444, "Raw TCP Socket"), 1, 1)
        main_layout.addLayout(grid)

        # ── Interactive Network Diagnostic Probe ─────────────────────────
        probe_card = QFrame()
        probe_card.setStyleSheet(
            f"background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; padding: 14px;"
        )
        p_layout = QVBoxLayout(probe_card)

        probe_title = QLabel("Target Network Connectivity Probe (Socket Test):")
        probe_title.setStyleSheet(f"font-weight: bold; color: {COLOR_CYAN}; font-size: 13px;")
        p_layout.addWidget(probe_title)

        input_row = QHBoxLayout()
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setPlaceholderText("Target Host or IP (e.g. 192.168.1.10)")
        input_row.addWidget(self.host_input, 3)

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(80)
        input_row.addWidget(self.port_input, 1)

        self.test_btn = QPushButton("📡 Probe Connection")
        self.test_btn.setProperty("primary", True)
        self.test_btn.clicked.connect(self._probe_connection)
        input_row.addWidget(self.test_btn)
        p_layout.addLayout(input_row)

        self.probe_output = QTextEdit()
        self.probe_output.setReadOnly(True)
        self.probe_output.setFixedHeight(120)
        self.probe_output.setStyleSheet(
            "background-color: #030712; color: #10B981; font-family: monospace; font-size: 11px;"
        )
        self.probe_output.setPlaceholderText("Probe output and RTT latency will appear here...")
        p_layout.addWidget(self.probe_output)

        main_layout.addWidget(probe_card)

    def _probe_connection(self) -> None:
        host = self.host_input.text().strip()
        port = self.port_input.value()
        self.probe_output.append(f"\n[probe] Connecting to {host}:{port} via TCP socket...")

        start = time.perf_counter()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.5)
            res = sock.connect_ex((host, port))
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            sock.close()

            if res == 0:
                self.probe_output.append(f"[SUCCESS] {host}:{port} is OPEN — Latency: {elapsed_ms:.1f}ms")
            else:
                self.probe_output.append(f"[CLOSED/FILTERED] {host}:{port} returned code {res} — Latency: {elapsed_ms:.1f}ms")
        except Exception as exc:
            self.probe_output.append(f"[ERROR] Socket error: {exc}")
