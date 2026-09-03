"""
PyQt main application shell, Armitage-inspired navigation, and status telemetry.
"""

from __future__ import annotations

import sys
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from gui.styles import (
    COLOR_BG_CARD,
    COLOR_BG_PANEL,
    COLOR_BORDER,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_PURPLE,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    apply_cyber_theme,
    get_pill_style,
)
from gui.views.analyser_view import AnalyserView
from gui.views.findings_view import FindingsView
from gui.views.host_graph_view import HostGraphView
from gui.views.live_console_view import LiveConsoleView
from gui.views.module_browser_view import ModuleBrowserView
from gui.views.projects_view import ProjectsView
from gui.views.sessions_view import SessionsView
from gui.views.settings_view import SettingsView
from gui.views.target_detail_view import TargetDetailView


class MainWindow(QMainWindow):
    """Main application shell window for SentryPack Desktop GUI."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SentryPack Platform — Adversary Simulation & Vulnerability Assessment")
        self.resize(1300, 800)

        # Apply global Cyber Dark styling
        apply_cyber_theme(self)

        self._active_project_id: Optional[int] = None
        self._build_ui()
        self._wire_signals()

    def _build_ui(self) -> None:
        root_widget = QWidget()
        self.setCentralWidget(root_widget)
        root_layout = QVBoxLayout(root_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── 1. Top Header Banner ────────────────────────────────────────
        header_bar = QFrame()
        header_bar.setFixedHeight(54)
        header_bar.setStyleSheet(
            f"background-color: {COLOR_BG_PANEL}; border-bottom: 1px solid {COLOR_BORDER}; padding: 0 16px;"
        )
        header_layout = QHBoxLayout(header_bar)
        header_layout.setContentsMargins(12, 0, 16, 0)

        logo_label = QLabel("🛡 SENTRYPACK")
        logo_label.setStyleSheet(
            f"font-size: 16px; font-weight: 900; letter-spacing: 0.1em; color: {COLOR_CYAN};"
        )
        header_layout.addWidget(logo_label)

        sub_label = QLabel("ENTERPRISE PLATFORM")
        sub_label.setStyleSheet(
            f"font-size: 10px; font-weight: 700; letter-spacing: 0.15em; color: {COLOR_TEXT_SECONDARY}; margin-left: 6px;"
        )
        header_layout.addWidget(sub_label)

        header_layout.addStretch()

        # Active Project Indicator Pill
        self.proj_indicator = QLabel("Project: None Selected")
        self.proj_indicator.setStyleSheet(get_pill_style(fg=COLOR_CYAN))
        header_layout.addWidget(self.proj_indicator)

        # C2 Sessions Pill
        self.c2_indicator = QLabel("C2 Sessions: Active")
        self.c2_indicator.setStyleSheet(get_pill_style(fg=COLOR_GREEN))
        header_layout.addWidget(self.c2_indicator)

        root_layout.addWidget(header_bar)

        # ── 2. Middle Body (Sidebar + Views Stack) ──────────────────────
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Armitage-style Sidebar
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(210)
        self.sidebar.setStyleSheet(
            f"QListWidget {{ background-color: {COLOR_BG_PANEL}; border: none; border-right: 1px solid {COLOR_BORDER}; }}"
        )

        nav_items = [
            ("📁 Projects & Targets", "Manage projects and define target hosts"),
            ("🌐 Host Graph (Map)", "Armitage-style network topology & visual attack map"),
            ("⚡ Module Browser", "Browse offensive exploits, recon, and C2 modules"),
            ("💻 Console Output", "Stream live module run logs and terminal outputs"),
            ("📡 C2 Sessions", "Interact with live reverse shells and beacons"),
            ("📊 Vulnerabilities", "Global project findings & vulnerability matrix"),
            ("🔍 Connection Analyser", "Listener status, port diagnostic socket probes"),
            ("⚙ Settings", "API base URL, timeouts, and theme configuration"),
        ]

        for title, tooltip in nav_items:
            self.sidebar.addItem(title)
            item = self.sidebar.item(self.sidebar.count() - 1)
            item.setToolTip(tooltip)

        body_layout.addWidget(self.sidebar)

        # View Stack Container
        self.views_stack = QStackedWidget()

        # View 0: Projects View
        self.projects_view = ProjectsView()
        self.views_stack.addWidget(self.projects_view)

        # View 1: Host Graph + Target Detail Splitter (Armitage Layout)
        host_graph_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.host_graph_view = HostGraphView()
        self.target_detail_view = TargetDetailView()

        host_graph_splitter.addWidget(self.host_graph_view)
        host_graph_splitter.addWidget(self.target_detail_view)
        host_graph_splitter.setSizes([750, 350])
        self.views_stack.addWidget(host_graph_splitter)

        # View 2: Module Browser
        self.module_browser_view = ModuleBrowserView()
        self.views_stack.addWidget(self.module_browser_view)

        # View 3: Live Console
        self.live_console_view = LiveConsoleView()
        self.views_stack.addWidget(self.live_console_view)

        # View 4: C2 Sessions
        self.sessions_view = SessionsView()
        self.views_stack.addWidget(self.sessions_view)

        # View 5: Findings View
        self.findings_view = FindingsView()
        self.views_stack.addWidget(self.findings_view)

        # View 6: Connection Analyser
        self.analyser_view = AnalyserView()
        self.views_stack.addWidget(self.analyser_view)

        # View 7: Platform Settings
        self.settings_view = SettingsView()
        self.views_stack.addWidget(self.settings_view)

        body_layout.addWidget(self.views_stack)
        root_layout.addWidget(body_widget)

        # ── 3. Bottom Cyber Status Bar ──────────────────────────────────
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet(
            f"background-color: {COLOR_BG_PANEL}; border-top: 1px solid {COLOR_BORDER}; color: {COLOR_TEXT_SECONDARY};"
        )
        self.setStatusBar(self.status_bar)

        self.api_status_label = QLabel("● API Online: http://127.0.0.1:8000")
        self.api_status_label.setStyleSheet(f"color: {COLOR_GREEN}; font-weight: bold; padding-left: 8px;")
        self.status_bar.addWidget(self.api_status_label)

        self.current_view_label = QLabel("Active View: Projects & Targets")
        self.current_view_label.setStyleSheet("padding-left: 20px;")
        self.status_bar.addWidget(self.current_view_label)

        version_label = QLabel("SentryPack v0.1.0-alpha")
        version_label.setStyleSheet("padding-right: 12px; color: #6B7280;")
        self.status_bar.addPermanentWidget(version_label)

    def _wire_signals(self) -> None:
        # Navigation
        self.sidebar.currentRowChanged.connect(self._on_nav_changed)
        self.sidebar.setCurrentRow(0)

        # Project Selection -> Updates Host Graph, Findings, and Header
        self.projects_view.project_selected.connect(self._on_project_selected)

        # Host Graph Selection -> Updates Target Detail View
        self.host_graph_view.target_selected.connect(self.target_detail_view.set_target)

        # Host Graph Attack Action -> Switch to Host Graph tab & show attacks
        self.host_graph_view.attack_requested.connect(self._on_attack_requested)

        # Exploit Execution Launched from TargetDetail or ModuleBrowser -> Switch to Console
        self.target_detail_view.module_run_started.connect(self._on_module_run_dispatched)
        self.module_browser_view.module_run_started.connect(self._on_module_run_dispatched)

    def _on_nav_changed(self, index: int) -> None:
        self.views_stack.setCurrentIndex(index)
        view_names = [
            "Projects & Targets",
            "Host Graph (Network Map)",
            "Module Catalogue",
            "Console Output",
            "C2 Sessions & Beacons",
            "Vulnerabilities & Findings",
            "Connection Analyser",
            "Platform Settings",
        ]
        if index < len(view_names):
            self.current_view_label.setText(f"Active View: {view_names[index]}")

    def _on_project_selected(self, project_id: int) -> None:
        self._active_project_id = project_id
        self.proj_indicator.setText(f"Active Project: #{project_id}")
        self.host_graph_view.set_project(project_id)
        self.findings_view.set_project(project_id)

    def _on_attack_requested(self, target: dict) -> None:
        self.sidebar.setCurrentRow(1)
        self.target_detail_view.set_target(target)
        self.target_detail_view.tabs.setCurrentIndex(0)

    def _on_module_run_dispatched(self, run_id: str, target_id: int, module_id: str) -> None:
        # Switch to Console Output view and start streaming
        self.sidebar.setCurrentRow(3)
        self.live_console_view.start_run_stream(run_id)


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
