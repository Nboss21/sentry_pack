"""
Target detail panel with recommendations and findings.
"""

from typing import Any, Dict, Optional

from PyQt6.QtWidgets import (
    QLabel,
    QListWidget,
    QListWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from gui.api_client import SentryPackAPIClient


class TargetDetailView(QWidget):
    """Display details, recommendations, and findings for a target."""

    def __init__(self) -> None:
        super().__init__()

        self.api_client = SentryPackAPIClient()
        self.target: Optional[Dict[str, Any]] = None

        self._build_ui()

    def _build_ui(self) -> None:
        
        layout = QVBoxLayout(self)

        self.title_label = QLabel("Target Details")
        layout.addWidget(self.title_label)

        self.info_label = QLabel("No target selected.")
        layout.addWidget(self.info_label)

        self.tabs = QTabWidget()

        self.recommendations_list = QListWidget()
        self.findings_list = QListWidget()

        self.tabs.addTab(
            self.recommendations_list,
            "Recommendations",
        )

        self.tabs.addTab(
            self.findings_list,
            "Findings",
        )

        layout.addWidget(self.tabs)

    def set_target(
        self,
        target: Optional[Dict[str, Any]],
    ) -> None:
        """Set the target displayed by this panel."""

        self.target = target

        self.recommendations_list.clear()
        self.findings_list.clear()

        if not target:
            self.title_label.setText("Target Details")
            self.info_label.setText("No target selected.")
            return

        target_id = target.get("id")
        name = target.get("name", "Unnamed")
        ip_address = target.get("ip_address", "Unknown")
        status = target.get("status", "unknown")

        self.title_label.setText(
            f"Target: {name}"
        )

        self.info_label.setText(
            f"ID: {target_id}    "
            f"IP: {ip_address}    "
            f"Status: {status}"
        )

        self.load_recommendations()
        self.load_findings()

    def load_recommendations(self) -> None:
        """Load recommendations for the selected target."""

        if not self.target:
            return

        target_id = self.target.get("id")

        if target_id is None:
            return

        try:
            data = self.api_client.get_target_recommendations(
                int(target_id)
            )

            recommendations = data.get(
                "recommendations",
                [],
            )

            if not recommendations:
                self.recommendations_list.addItem(
                    "No recommendations found."
                )
                return

            for recommendation in recommendations:
                self._add_recommendation(
                    recommendation
                )

        except Exception as exc:
            self.recommendations_list.addItem(
                f"Failed to load recommendations: {exc}"
            )

    def load_findings(self) -> None:
        """Load findings for the selected target."""

        if not self.target:
            return

        target_id = self.target.get("id")

        if target_id is None:
            return

        try:
            data = self.api_client.get_target_findings(
                int(target_id)
            )

            findings = data.get(
                "findings",
                [],
            )

            if not findings:
                self.findings_list.addItem(
                    "No findings found."
                )
                return

            for finding in findings:
                title = finding.get(
                    "title",
                    "Untitled finding",
                )

                severity = finding.get(
                    "severity",
                    "unknown",
                )

                cve = finding.get(
                    "cve",
                    "N/A",
                )

                item = QListWidgetItem(
                    f"{title} | "
                    f"Severity: {severity} | "
                    f"CVE: {cve}"
                )

                self.findings_list.addItem(item)

        except Exception as exc:
            self.findings_list.addItem(
                f"Failed to load findings: {exc}"
            )
            
    def _add_recommendation(
        self,
        recommendation: Dict[str, Any],
    ) -> None:
        """Display a single recommendation."""

        cve = recommendation.get(
            "cve",
            "No CVE",
        )

        severity = recommendation.get(
            "severity",
            "unknown",
        )

        cvss = recommendation.get(
            "cvss",
            "N/A",
        )

        module_id = recommendation.get(
            "module_id",
            "Unknown",
        )

        match_type = recommendation.get(
            "match_type",
            "unknown",
        )

        item = QListWidgetItem(
            f"{cve} | "
            f"Severity: {severity} | "
            f"CVSS: {cvss} | "
            f"Module: {module_id} | "
            f"Match: {match_type}"
        )

        self.recommendations_list.addItem(item)