"""
Target detail panel with rich recommendations, exploit launching, and findings.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
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
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from gui.api_client import SentryPackAPIClient
from gui.styles import (
    COLOR_BG_CARD,
    COLOR_BG_ELEVATED,
    COLOR_BORDER,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_PURPLE,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    get_exploit_rank,
    get_mitre_technique,
    get_pill_style,
    get_rank_badge_style,
    get_severity_badge_style,
)


class ExploitLaunchDialog(QDialog):
    """Modal dialog to review options, select C2 payload, and launch an exploit module."""

    def __init__(
        self,
        target_id: int,
        target_ip: str,
        module_id: str,
        cve_id: Optional[str] = None,
        default_port: Optional[int] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Launch Exploit — {module_id}")
        self.resize(520, 340)
        self.target_id = target_id
        self.module_id = module_id

        layout = QVBoxLayout(self)

        title = QLabel(f"Configure & Execute Exploit: {module_id}")
        title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {COLOR_CYAN};")
        layout.addWidget(title)

        if cve_id:
            cve_label = QLabel(f"Target Vulnerability: {cve_id}")
            cve_label.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; font-family: monospace;")
            layout.addWidget(cve_label)

        form_frame = QFrame()
        form_frame.setStyleSheet(f"background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; border-radius: 6px;")
        form_layout = QFormLayout(form_frame)

        self.target_input = QLineEdit(target_ip)
        form_layout.addRow("TARGET (RHOST):", self.target_input)

        port_str = str(default_port) if default_port else "80"
        self.port_input = QLineEdit(port_str)
        form_layout.addRow("PORT (RPORT):", self.port_input)

        # ── Payload / C2 Beacon Pairing ─────────────────────────────────
        self.payload_combo = QComboBox()
        self.payload_combo.addItem("Default (Module Execution)", "default")
        self.payload_combo.addItem("Drop SentryPack TLS Beacon (C2 Listener :8443)", "tls_beacon")
        self.payload_combo.addItem("Drop HTTPS Proxy Beacon (C2 Listener :8080)", "https_beacon")
        self.payload_combo.addItem("Interactive Reverse Shell Task", "reverse_shell")
        form_layout.addRow("Payload / C2 Beacon:", self.payload_combo)

        layout.addWidget(form_frame)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("⚡ Execute Exploit")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("primary", True)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_options(self) -> Dict[str, Any]:
        """Return the options dict to send to the runner."""
        opts: Dict[str, Any] = {
            "TARGET": self.target_input.text().strip(),
        }
        if self.port_input.text().strip():
            opts["PORT"] = self.port_input.text().strip()
            opts["PORTS"] = self.port_input.text().strip()

        payload_type = self.payload_combo.currentData()
        if payload_type and payload_type != "default":
            opts["PAYLOAD"] = payload_type
            if payload_type == "tls_beacon":
                opts["C2_PORT"] = 8443
                opts["TRANSPORT"] = "tls"
            elif payload_type == "https_beacon":
                opts["C2_PORT"] = 8080
                opts["TRANSPORT"] = "https_proxy"

        return opts


class RecommendationCardWidget(QFrame):
    """Custom rich card widget displaying an exploit recommendation with Metasploit-style reliability and MITRE tags."""

    launch_requested = pyqtSignal(dict)
    check_requested = pyqtSignal(dict)

    def __init__(self, rec: Dict[str, Any], target_ip: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.rec = rec
        self.target_ip = target_ip
        self.setStyleSheet(
            f"QFrame {{ background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; "
            f"border-radius: 6px; padding: 10px; }} "
            f"QFrame:hover {{ border-color: {COLOR_CYAN}; background-color: {COLOR_BG_ELEVATED}; }}"
        )
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        # ── Header: Badges, Severity, Rank & MITRE ──────────────────────
        header = QHBoxLayout()
        header.setSpacing(6)

        # 1. Metasploit Reliability Rank
        rank_text, rank_color = get_exploit_rank(self.rec)
        rank_label = QLabel(rank_text)
        rank_label.setStyleSheet(get_rank_badge_style(rank_color))
        header.addWidget(rank_label)

        # 2. Severity Badge
        severity = str(self.rec.get("severity", "Medium"))
        sev_label = QLabel(severity.upper())
        sev_label.setStyleSheet(get_severity_badge_style(severity))
        header.addWidget(sev_label)

        # 3. CVE Pill
        cve = self.rec.get("cve_id") or self.rec.get("cve") or "No CVE"
        cve_label = QLabel(cve)
        cve_label.setStyleSheet(get_pill_style(fg=COLOR_CYAN))
        header.addWidget(cve_label)

        # 4. CVSS Score Pill
        cvss = self.rec.get("cvss_score") or self.rec.get("cvss")
        if cvss is not None:
            cvss_label = QLabel(f"CVSS {cvss}")
            cvss_label.setStyleSheet(get_pill_style(fg="#F59E0B"))
            header.addWidget(cvss_label)

        # 5. MITRE ATT&CK Pill
        mitre_id, mitre_desc = get_mitre_technique(self.rec)
        mitre_label = QLabel(f"ATT&CK: {mitre_id}")
        mitre_label.setToolTip(f"MITRE ATT&CK: {mitre_desc}")
        mitre_label.setStyleSheet(get_pill_style(fg="#10B981"))
        header.addWidget(mitre_label)

        header.addStretch()

        # 6. Service / Port Pill
        svc = self.rec.get("target_service") or {}
        port = svc.get("port")
        proto = svc.get("protocol", "tcp")
        service_name = svc.get("service") or self.rec.get("service_name") or ""
        if port:
            svc_label = QLabel(f"{port}/{proto} {service_name}".strip())
            svc_label.setStyleSheet(get_pill_style(fg="#A78BFA"))
            header.addWidget(svc_label)

        layout.addLayout(header)

        # ── Title & Description ─────────────────────────────────────────
        title_text = self.rec.get("title") or self.rec.get("description") or "Exploit Recommendation"
        title_label = QLabel(title_text)
        title_label.setWordWrap(True)
        title_label.setStyleSheet(f"font-weight: 600; color: {COLOR_TEXT_PRIMARY}; font-size: 13px;")
        layout.addWidget(title_label)

        # ── Expandable PoC & Details Drawer ─────────────────────────────
        self.details_drawer = QFrame()
        self.details_drawer.setVisible(False)
        self.details_drawer.setStyleSheet(
            f"background-color: #030712; border: 1px dashed {COLOR_BORDER}; border-radius: 4px; padding: 8px;"
        )
        drawer_layout = QVBoxLayout(self.details_drawer)
        drawer_layout.setContentsMargins(6, 6, 6, 6)
        drawer_layout.setSpacing(4)

        match_type = self.rec.get("match_type", "direct")
        matched_field = self.rec.get("matched_field", "service")
        drawer_layout.addWidget(
            QLabel(f"Match Criteria: {match_type} (triggered by field '{matched_field}')")
        )

        refs = self.rec.get("references") or []
        if refs:
            ref_title = QLabel("Exploit PoC & Security References:")
            ref_title.setStyleSheet("font-weight: bold; color: #38BDF8;")
            drawer_layout.addWidget(ref_title)
            for r in refs[:3]:
                link_lbl = QLabel(f"• {r}")
                link_lbl.setStyleSheet("color: #94A3B8; font-family: monospace; font-size: 11px;")
                drawer_layout.addWidget(link_lbl)

        layout.addWidget(self.details_drawer)

        # ── Action Footer ───────────────────────────────────────────────
        footer = QHBoxLayout()
        module_id = self.rec.get("module_id")

        self.toggle_details_btn = QPushButton("📋 Details / PoC")
        self.toggle_details_btn.setFixedHeight(26)
        self.toggle_details_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        self.toggle_details_btn.clicked.connect(self._toggle_details)
        footer.addWidget(self.toggle_details_btn)

        if module_id:
            mod_pill = QLabel(f"Module: {module_id}")
            mod_pill.setStyleSheet(get_pill_style(fg=COLOR_PURPLE))
            footer.addWidget(mod_pill)

            footer.addStretch()

            check_btn = QPushButton("🔍 Pre-flight Check")
            check_btn.setFixedHeight(28)
            check_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
            check_btn.clicked.connect(lambda: self.check_requested.emit(self.rec))
            footer.addWidget(check_btn)

            launch_btn = QPushButton("⚡ Launch Exploit")
            launch_btn.setProperty("primary", True)
            launch_btn.setFixedHeight(28)
            launch_btn.clicked.connect(lambda: self.launch_requested.emit(self.rec))
            footer.addWidget(launch_btn)
        else:
            has_pub = self.rec.get("has_public_exploit", False)
            exploit_info = "Public PoC Available" if has_pub else "Known Vulnerability"
            info_label = QLabel(exploit_info)
            info_label.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; font-size: 11px; margin-left: 8px;")
            footer.addWidget(info_label)
            footer.addStretch()

        layout.addLayout(footer)

    def _toggle_details(self) -> None:
        is_visible = self.details_drawer.isVisible()
        self.details_drawer.setVisible(not is_visible)
        self.toggle_details_btn.setText("▲ Hide Details" if not is_visible else "📋 Details / PoC")


class FindingCardWidget(QFrame):
    """Custom rich card widget displaying a target finding/vulnerability."""

    def __init__(self, finding: Dict[str, Any], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.finding = finding
        self.setStyleSheet(
            f"QFrame {{ background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; "
            f"border-radius: 6px; padding: 10px; }} "
            f"QFrame:hover {{ border-color: {COLOR_BORDER}; background-color: {COLOR_BG_ELEVATED}; }}"
        )
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        header = QHBoxLayout()
        severity = str(self.finding.get("severity", "Info"))
        sev_label = QLabel(severity.upper())
        sev_label.setStyleSheet(get_severity_badge_style(severity))
        header.addWidget(sev_label)

        title = QLabel(self.finding.get("title", "Untitled finding"))
        title.setStyleSheet(f"font-weight: bold; color: {COLOR_TEXT_PRIMARY};")
        header.addWidget(title)

        header.addStretch()

        cve = self.finding.get("cve")
        if cve:
            cve_label = QLabel(cve)
            cve_label.setStyleSheet(get_pill_style(fg=COLOR_CYAN))
            header.addWidget(cve_label)

        layout.addLayout(header)

        desc = self.finding.get("description", "")
        if desc:
            desc_label = QLabel(desc)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; font-size: 12px;")
            layout.addWidget(desc_label)

        remediation = self.finding.get("remediation")
        if remediation:
            rem_label = QLabel(f"Remediation: {remediation}")
            rem_label.setWordWrap(True)
            rem_label.setStyleSheet("color: #34D399; font-size: 11px;")
            layout.addWidget(rem_label)


class TargetDetailView(QWidget):
    """Display details, actionable recommendations, and findings for a target."""

    module_run_started = pyqtSignal(str, int, str)  # run_id, target_id, module_id

    def __init__(self) -> None:
        super().__init__()
        self.api_client = SentryPackAPIClient()
        self.target: Optional[Dict[str, Any]] = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # ── Header Banner ───────────────────────────────────────────────
        header_frame = QFrame()
        header_frame.setStyleSheet(
            f"background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; "
            f"border-radius: 8px; padding: 12px;"
        )
        header_layout = QVBoxLayout(header_frame)
        header_layout.setContentsMargins(8, 8, 8, 8)
        header_layout.setSpacing(4)

        self.title_label = QLabel("Target Details")
        self.title_label.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLOR_CYAN};")
        header_layout.addWidget(self.title_label)

        self.info_label = QLabel("Select a host on the map to view attacks and findings.")
        self.info_label.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; font-size: 12px;")
        header_layout.addWidget(self.info_label)

        layout.addWidget(header_frame)

        # ── Tabs (Recommendations & Findings) ───────────────────────────
        self.tabs = QTabWidget()

        # Tab 1: Recommendations scroll area
        self.rec_scroll = QScrollArea()
        self.rec_scroll.setWidgetResizable(True)
        self.rec_container = QWidget()
        self.rec_layout = QVBoxLayout(self.rec_container)
        self.rec_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.rec_layout.setSpacing(8)
        self.rec_scroll.setWidget(self.rec_container)
        self.tabs.addTab(self.rec_scroll, "⚡ Attacks & Recommendations")

        # Tab 2: Findings scroll area
        self.findings_scroll = QScrollArea()
        self.findings_scroll.setWidgetResizable(True)
        self.findings_container = QWidget()
        self.findings_layout = QVBoxLayout(self.findings_container)
        self.findings_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.findings_layout.setSpacing(8)
        self.findings_scroll.setWidget(self.findings_container)
        self.tabs.addTab(self.findings_scroll, "🔍 Discovered Findings")

        layout.addWidget(self.tabs)

    def set_target(self, target: Optional[Dict[str, Any]]) -> None:
        """Set the target displayed by this panel."""
        self.target = target
        self._clear_containers()

        if not target:
            self.title_label.setText("Target Details")
            self.info_label.setText("Select a host on the map to view attacks and findings.")
            return

        target_id = target.get("id")
        name = target.get("name", "Unnamed")
        ip_address = target.get("ip_address", "Unknown")
        status = target.get("status", "idle")

        self.title_label.setText(f"Target: {name} ({ip_address})")
        self.info_label.setText(f"ID: {target_id}  |  IP: {ip_address}  |  Status: {status.upper()}")

        self.load_recommendations()
        self.load_findings()

    def _clear_containers(self) -> None:
        """Clear all recommendation and finding card widgets."""
        while self.rec_layout.count():
            item = self.rec_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        while self.findings_layout.count():
            item = self.findings_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def load_recommendations(self) -> None:
        """Load recommendations for the selected target with robust key mapping."""
        if not self.target or self.target.get("id") is None:
            return

        target_id = int(self.target["id"])
        target_ip = self.target.get("ip_address", "127.0.0.1")

        try:
            data = self.api_client.get_target_recommendations(target_id)
            recommendations = data.get("recommendations", [])

            self.tabs.setTabText(0, f"⚡ Attacks & Recommendations ({len(recommendations)})")

            if not recommendations:
                empty_lbl = QLabel("No exploit recommendations matched. Run a recon scan first.")
                empty_lbl.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; padding: 16px;")
                self.rec_layout.addWidget(empty_lbl)
                return

            for rec in recommendations:
                card = RecommendationCardWidget(rec, target_ip)
                card.launch_requested.connect(self._handle_launch_request)
                card.check_requested.connect(self._handle_check_request)
                self.rec_layout.addWidget(card)

        except Exception as exc:
            err_lbl = QLabel(f"Failed to load recommendations: {exc}")
            err_lbl.setStyleSheet("color: #EF4444; padding: 16px;")
            self.rec_layout.addWidget(err_lbl)

    def load_findings(self) -> None:
        """Load findings for the selected target."""
        if not self.target or self.target.get("id") is None:
            return

        target_id = int(self.target["id"])

        try:
            data = self.api_client.get_target_findings(target_id)
            findings = data.get("findings", [])

            self.tabs.setTabText(1, f"🔍 Discovered Findings ({len(findings)})")

            if not findings:
                empty_lbl = QLabel("No findings recorded for this target yet.")
                empty_lbl.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; padding: 16px;")
                self.findings_layout.addWidget(empty_lbl)
                return

            for finding in findings:
                card = FindingCardWidget(finding)
                self.findings_layout.addWidget(card)

        except Exception as exc:
            err_lbl = QLabel(f"Failed to load findings: {exc}")
            err_lbl.setStyleSheet("color: #EF4444; padding: 16px;")
            self.findings_layout.addWidget(err_lbl)

    def _handle_launch_request(self, rec: Dict[str, Any]) -> None:
        """Handle 1-click exploit launch request from a recommendation card."""
        if not self.target:
            return

        target_id = int(self.target["id"])
        target_ip = self.target.get("ip_address", "127.0.0.1")
        module_id = rec.get("module_id")
        if not module_id:
            return

        cve = rec.get("cve_id") or rec.get("cve")
        svc = rec.get("target_service") or {}
        port = svc.get("port")

        dialog = ExploitLaunchDialog(
            target_id=target_id,
            target_ip=target_ip,
            module_id=module_id,
            cve_id=cve,
            default_port=port,
            parent=self,
        )

        if dialog.exec() == QDialog.DialogCode.Accepted:
            opts = dialog.get_options()
            try:
                result = self.api_client.run_module(target_id, module_id, opts)
                run_id = result.get("run_id", "")
                QMessageBox.information(
                    self,
                    "Module Launched",
                    f"Exploit module '{module_id}' started!\nRun ID: {run_id}\n\n"
                    "Check the Live Console View to watch live execution.",
                )
                self.module_run_started.emit(run_id, target_id, module_id)
            except Exception as exc:
                QMessageBox.critical(
                    self,
                    "Launch Failed",
                    f"Failed to trigger module run: {exc}",
                )

    def _handle_check_request(self, rec: Dict[str, Any]) -> None:
        """Perform a pre-flight non-destructive vulnerability check."""
        if not self.target:
            return

        target_id = int(self.target["id"])
        target_ip = self.target.get("ip_address", "127.0.0.1")
        module_id = rec.get("module_id")
        if not module_id:
            return

        cve = rec.get("cve_id") or rec.get("cve") or "N/A"
        svc = rec.get("target_service") or {}
        port = svc.get("port", 80)

        opts = {"TARGET": target_ip, "PORT": str(port), "CHECK_ONLY": True}
        try:
            result = self.api_client.run_module(target_id, module_id, opts)
            run_id = result.get("run_id", "")
            QMessageBox.information(
                self,
                "Pre-flight Check Dispatched",
                f"Vulnerability verification check dispatched for {module_id} against {target_ip}:{port}!\n"
                f"Run ID: {run_id}\n\nLive stream will report check findings.",
            )
            self.module_run_started.emit(run_id, target_id, module_id)
        except Exception as exc:
            QMessageBox.critical(self, "Check Failed", f"Failed to dispatch check: {exc}")