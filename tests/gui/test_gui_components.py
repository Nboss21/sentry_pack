"""
Headless automated test suite for SentryPack PyQt6 GUI components.

Verifies:
  - styles.py color tokens and badge generation
  - target_detail_view.py key mapping (cve_id and cvss_score bug fix verification)
  - host_graph_view.py Armitage target card nodes and status indicators
  - module_browser_view.py category tree and filtering
  - findings_view.py vulnerability matrix & stat cards
  - sessions_view.py C2 sessions table and interactive shell
  - main_window.py application shell, theme application, and zero placeholders
"""

from __future__ import annotations

import sys
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtWidgets import QApplication

from gui.styles import (
    SEVERITY_COLORS,
    apply_cyber_theme,
    get_pill_style,
    get_severity_badge_style,
    get_severity_color,
)


@pytest.fixture(scope="session")
def qapp():
    """Ensure a headless QApplication instance is active for all GUI tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["sentrypack_test", "-platform", "offscreen"])
    return app


# ===========================================================================
# 1. Styles & Design System Tests
# ===========================================================================


class TestGuiStyles:
    def test_get_severity_color_mappings(self):
        assert get_severity_color("Critical") == SEVERITY_COLORS["critical"]
        assert get_severity_color("High") == SEVERITY_COLORS["high"]
        assert get_severity_color("Medium") == SEVERITY_COLORS["medium"]
        assert get_severity_color("Low") == SEVERITY_COLORS["low"]
        assert get_severity_color("Info") == SEVERITY_COLORS["info"]
        assert get_severity_color("Nonexistent") == SEVERITY_COLORS["unknown"]
        assert get_severity_color(None) == SEVERITY_COLORS["unknown"]

    def test_get_severity_badge_style_contains_color(self):
        style = get_severity_badge_style("Critical")
        assert SEVERITY_COLORS["critical"] in style
        assert "border-radius" in style
        assert "uppercase" in style

    def test_get_pill_style_format(self):
        pill = get_pill_style(fg="#00E5FF")
        assert "#00E5FF" in pill
        assert "monospace" in pill

    def test_apply_cyber_theme_to_widget(self, qapp):
        from PyQt6.QtWidgets import QWidget
        w = QWidget()
        apply_cyber_theme(w)
        assert len(w.styleSheet()) > 500

    def test_exploit_reliability_rank_calculation(self):
        from gui.styles import get_exploit_rank
        rank_crit, color = get_exploit_rank({"module_id": "exploit.test", "cvss_score": 9.5})
        assert "EXCELLENT" in rank_crit
        assert color == "#059669"

        rank_manual, _ = get_exploit_rank({"cvss_score": 0.0})
        assert "MANUAL" in rank_manual

    def test_mitre_technique_mapping(self):
        from gui.styles import get_mitre_technique
        tid, desc = get_mitre_technique({"title": "Remote Code Execution in Apache", "service_name": "http"})
        assert tid == "T1190"

        tid_pe, _ = get_mitre_technique({"title": "Local Privilege Escalation in Kernel"})
        assert tid_pe == "T1068"


# ===========================================================================
# 2. TargetDetailView & Bug Fix Verification
# ===========================================================================


class TestTargetDetailView:
    def test_recommendation_card_renders_cve_id_and_cvss(self, qapp):
        """Verifies the bug fix: cve_id and cvss_score are correctly parsed and displayed."""
        from PyQt6.QtWidgets import QLabel
        from gui.views.target_detail_view import RecommendationCardWidget

        sample_rec: Dict[str, Any] = {
            "id": 1,
            "cve_id": "CVE-2023-38408",
            "cvss_score": 9.8,
            "severity": "Critical",
            "module_id": "exploit.ssh_cve_2023_38408",
            "title": "OpenSSH RCE Exploit",
            "target_service": {"port": 22, "protocol": "tcp", "service": "ssh"},
        }

        card = RecommendationCardWidget(sample_rec, "192.168.1.100")
        all_texts = [lbl.text() for lbl in card.findChildren(QLabel)]
        card_text = " ".join(all_texts)

        # Confirm cve_id and cvss_score are present and NOT "No CVE" or "CVSS: N/A"
        assert "CVE-2023-38408" in card_text
        assert "9.8" in card_text
        assert "CRITICAL" in card_text
        assert "22/tcp" in card_text

    def test_recommendation_card_fallback_keys(self, qapp):
        """Card should handle legacy 'cve' and 'cvss' keys gracefully."""
        from PyQt6.QtWidgets import QLabel
        from gui.views.target_detail_view import RecommendationCardWidget

        sample_rec: Dict[str, Any] = {
            "id": 2,
            "cve": "CVE-2021-44228",
            "cvss": 10.0,
            "severity": "Critical",
            "title": "Log4Shell",
        }

        card = RecommendationCardWidget(sample_rec, "10.0.0.1")
        all_texts = [lbl.text() for lbl in card.findChildren(QLabel)]
        card_text = " ".join(all_texts)
        assert "CVE-2021-44228" in card_text
        assert "10.0" in card_text

    def test_target_detail_view_set_target(self, qapp):
        from gui.views.target_detail_view import TargetDetailView

        view = TargetDetailView()
        with patch.object(view.api_client, "get_target_recommendations", return_value={"recommendations": []}):
            with patch.object(view.api_client, "get_target_findings", return_value={"findings": []}):
                view.set_target({"id": 42, "name": "web-srv", "ip_address": "10.0.0.5", "status": "scanned"})
                assert "web-srv" in view.title_label.text()
                assert "10.0.0.5" in view.title_label.text()

    def test_target_detail_view_cleared_on_none(self, qapp):
        from gui.views.target_detail_view import TargetDetailView

        view = TargetDetailView()
        view.set_target(None)
        assert "Select a host" in view.info_label.text()

    def test_exploit_launch_dialog_payload_selection(self, qapp):
        from gui.views.target_detail_view import ExploitLaunchDialog

        dlg = ExploitLaunchDialog(
            target_id=1,
            target_ip="192.168.1.50",
            module_id="exploit.test_rce",
            default_port=8080,
        )
        # Select TLS Beacon payload
        idx = dlg.payload_combo.findData("tls_beacon")
        assert idx >= 0
        dlg.payload_combo.setCurrentIndex(idx)

        opts = dlg.get_options()
        assert opts["TARGET"] == "192.168.1.50"
        assert opts["PAYLOAD"] == "tls_beacon"
        assert opts["TRANSPORT"] == "tls"
        assert opts["C2_PORT"] == 8443


# ===========================================================================
# 3. HostGraphView (Armitage Topology)
# ===========================================================================


class TestHostGraphView:
    def test_target_node_compromised_state(self, qapp):
        from gui.views.host_graph_view import TargetNode

        target = {"id": 1, "name": "dc-server", "ip_address": "10.0.0.1", "status": "compromised"}
        node = TargetNode(target)
        assert node.target["status"] == "compromised"
        assert node.boundingRect().width() > 100

    def test_host_graph_renders_targets(self, qapp):
        from gui.views.host_graph_view import HostGraphView, TargetNode

        view = HostGraphView()
        sample_targets = [
            {"id": 1, "name": "t1", "ip_address": "10.0.0.1", "status": "scanned"},
            {"id": 2, "name": "t2", "ip_address": "10.0.0.2", "status": "compromised"},
        ]
        with patch.object(view.api_client, "get_targets", return_value={"targets": sample_targets}):
            view.load_targets()
            nodes = [item for item in view.scene.items() if isinstance(item, TargetNode)]
            assert len(nodes) == 2

    def test_host_graph_subnet_clustering(self, qapp):
        from gui.views.host_graph_view import HostGraphView, SubnetEnclosureItem

        view = HostGraphView()
        sample_targets = [
            {"id": 1, "name": "t1", "ip_address": "10.0.0.10", "status": "scanned"},
            {"id": 2, "name": "t2", "ip_address": "10.0.0.20", "status": "scanned"},
            {"id": 3, "name": "t3", "ip_address": "192.168.1.5", "status": "idle"},
        ]
        with patch.object(view.api_client, "get_targets", return_value={"targets": sample_targets}):
            view.load_targets()
            enclosures = [item for item in view.scene.items() if isinstance(item, SubnetEnclosureItem)]
            assert len(enclosures) == 2  # 10.0.0.0/24 and 192.168.1.0/24


# ===========================================================================
# 4. ModuleBrowserView (Metasploit Tree)
# ===========================================================================


class TestModuleBrowserView:
    def test_module_tree_groups_by_category(self, qapp):
        from gui.views.module_browser_view import ModuleBrowserView

        view = ModuleBrowserView()
        sample_modules = [
            {"id": "recon.nmap_scan", "name": "Nmap Port Scanner", "category": "recon", "version": "0.1.0"},
            {"id": "exploit.smb_ms17_010", "name": "EternalBlue Exploit", "category": "exploit/smb", "version": "1.0.0"},
        ]
        with patch.object(view.api_client, "get_modules", return_value={"modules": sample_modules}):
            with patch.object(view.api_client, "get_targets", return_value={"targets": []}):
                view.load_data()
                top_items = [view.module_tree.topLevelItem(i).text(0) for i in range(view.module_tree.topLevelItemCount())]
                assert any("RECON" in t for t in top_items)
                assert any("EXPLOIT" in t for t in top_items)

    def test_module_browser_search_filter(self, qapp):
        from gui.views.module_browser_view import ModuleBrowserView

        view = ModuleBrowserView()
        sample_modules = [
            {"id": "recon.nmap_scan", "name": "Nmap Port Scanner", "category": "recon", "version": "0.1.0"},
            {"id": "exploit.log4shell", "name": "Log4Shell Exploit", "category": "exploit/http", "version": "1.0.0"},
        ]
        with patch.object(view.api_client, "get_modules", return_value={"modules": sample_modules}):
            with patch.object(view.api_client, "get_targets", return_value={"targets": []}):
                view.load_data()
                view.search_box.setText("Log4Shell")
                # Top level items should adapt
                top_items = [view.module_tree.topLevelItem(i) for i in range(view.module_tree.topLevelItemCount())]
                exploit_item = [it for it in top_items if "EXPLOIT" in it.text(0)][0]
                assert not exploit_item.isHidden()


# ===========================================================================
# 5. LiveConsoleView (Semantic Cyber Terminal)
# ===========================================================================


class TestLiveConsoleView:
    def test_console_semantic_html_formatting(self, qapp):
        from gui.views.live_console_view import LiveConsoleView

        console = LiveConsoleView()
        console.handle_event({"type": "info", "message": "Probing target host..."})
        console.handle_event({"type": "finding", "message": "Discovered Log4Shell vulnerability!"})
        console.handle_event({"type": "complete", "message": "Run finished successfully."})

        full_html = console.console.toHtml()
        assert "Probing target host" in full_html
        assert "Discovered Log4Shell" in full_html
        assert "Run finished successfully" in full_html
        assert len(console._log_history) == 3

    def test_console_filtering(self, qapp):
        from gui.views.live_console_view import LiveConsoleView

        console = LiveConsoleView()
        console.handle_event({"type": "info", "message": "Standard log 1"})
        console.handle_event({"type": "finding", "message": "Critical Finding A"})
        console.handle_event({"type": "error", "message": "Connection error occurred"})

        # Switch to findings only
        console._set_filter("finding")
        text = console.console.toPlainText()
        assert "Critical Finding A" in text
        assert "Standard log 1" not in text
        assert "Connection error" not in text

        # Switch to error only
        console._set_filter("error")
        text_err = console.console.toPlainText()
        assert "Connection error" in text_err
        assert "Critical Finding A" not in text_err

    def test_console_search_navigation(self, qapp):
        from gui.views.live_console_view import LiveConsoleView

        console = LiveConsoleView()
        console.handle_event({"type": "info", "message": "Target 10.0.0.10 scanning"})
        console.handle_event({"type": "info", "message": "Target 10.0.0.20 scanning"})

        console.search_input.setText("10.0.0.20")
        console._find_next()
        cursor = console.console.textCursor()
        assert cursor.hasSelection()
        assert cursor.selectedText() == "10.0.0.20"


# ===========================================================================
# 5. FindingsView (Vulnerability Matrix)
# ===========================================================================


class TestFindingsView:
    def test_findings_view_populates_table(self, qapp):
        from gui.views.findings_view import FindingsView

        view = FindingsView()
        sample_findings = [
            {"id": 1, "title": "Log4Shell", "severity": "Critical", "cve": "CVE-2021-44228", "target_name": "srv1", "target_ip": "10.0.0.1"},
            {"id": 2, "title": "Weak TLS", "severity": "Medium", "cve": None, "target_name": "srv2", "target_ip": "10.0.0.2"},
        ]
        with patch.object(view.api_client, "get_all_findings", return_value=sample_findings):
            view.load_findings()
            assert view.table.rowCount() == 2
            assert view.card_total.count_lbl.text() == "2"
            assert view.card_crit.count_lbl.text() == "1"
            assert view.card_med.count_lbl.text() == "1"


# ===========================================================================
# 6. SessionsView (C2 Beacon Manager)
# ===========================================================================


class TestSessionsView:
    def test_sessions_view_renders_sessions(self, qapp):
        from gui.views.sessions_view import SessionsView

        view = SessionsView()
        sample_sessions = [
            {"id": "sess-001", "session_key": "k-123", "target_id": 1, "transport": "tls", "status": "active", "last_seen": "2026-09-02"},
        ]
        with patch.object(view.api_client, "get_c2_sessions", return_value={"sessions": sample_sessions}):
            view.load_sessions()
            assert view.table.rowCount() == 1
            assert "1 active" in view.status_lbl.text()


# ===========================================================================
# 7. MainWindow Shell & Zero Placeholder Verification
# ===========================================================================


class TestMainWindow:
    def test_main_window_has_zero_placeholders(self, qapp):
        """Confirm no QLabel('... Placeholder') widgets remain in MainWindow."""
        from PyQt6.QtWidgets import QLabel
        from gui.main_window import MainWindow

        with patch("gui.api_client.SentryPackAPIClient.get_projects", return_value={"projects": []}):
            with patch("gui.api_client.SentryPackAPIClient.get_targets", return_value={"targets": []}):
                with patch("gui.api_client.SentryPackAPIClient.get_modules", return_value={"modules": []}):
                    with patch("gui.api_client.SentryPackAPIClient.get_c2_sessions", return_value={"sessions": []}):
                        with patch("gui.api_client.SentryPackAPIClient.get_all_findings", return_value=[]):
                            window = MainWindow()
                            # Check all stacked widgets
                            count = window.views_stack.count()
                            assert count == 8, f"Expected 8 real views in MainWindow, got {count}"

                            for i in range(count):
                                widget = window.views_stack.widget(i)
                                # None of the main stacked views should be a raw QLabel
                                assert not isinstance(widget, QLabel), f"View {i} is still a raw QLabel placeholder!"

    def test_main_window_navigation_switches_views(self, qapp):
        from gui.main_window import MainWindow

        with patch("gui.api_client.SentryPackAPIClient.get_projects", return_value={"projects": []}):
            with patch("gui.api_client.SentryPackAPIClient.get_targets", return_value={"targets": []}):
                with patch("gui.api_client.SentryPackAPIClient.get_modules", return_value={"modules": []}):
                    with patch("gui.api_client.SentryPackAPIClient.get_c2_sessions", return_value={"sessions": []}):
                        with patch("gui.api_client.SentryPackAPIClient.get_all_findings", return_value=[]):
                            window = MainWindow()
                            # Change sidebar row
                            window.sidebar.setCurrentRow(2)
                            assert window.views_stack.currentIndex() == 2
                            window.sidebar.setCurrentRow(4)
                            assert window.views_stack.currentIndex() == 4
