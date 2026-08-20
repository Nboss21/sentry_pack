"""
Projects and targets management view.
"""

from typing import Any, Dict, List, Optional

from PyQt6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.api_client import SentryPackAPIClient


class ProjectsView(QWidget):
    """Display projects and the targets belonging to each project."""

    def __init__(self) -> None:
        super().__init__()

        self.api_client = SentryPackAPIClient()

        self.projects: List[Dict[str, Any]] = []
        self.targets: List[Dict[str, Any]] = []
        self.selected_project_id: Optional[int] = None

        self._build_ui()
        self.load_projects()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        title = QLabel("Projects & Targets")
        layout.addWidget(title)

        # --------------------------------------------------------------
        # Project section
        # --------------------------------------------------------------

        project_group = QGroupBox("Projects")
        project_layout = QVBoxLayout(project_group)

        self.project_list = QListWidget()
        self.project_list.currentItemChanged.connect(
            self._project_selected
        )

        project_layout.addWidget(self.project_list)

        project_buttons = QHBoxLayout()

        self.add_project_button = QPushButton("Add Project")
        self.refresh_projects_button = QPushButton("Refresh")

        self.add_project_button.clicked.connect(self.create_project)
        self.refresh_projects_button.clicked.connect(self.load_projects)

        project_buttons.addWidget(self.add_project_button)
        project_buttons.addWidget(self.refresh_projects_button)

        project_layout.addLayout(project_buttons)

        layout.addWidget(project_group)

        # --------------------------------------------------------------
        # Target section
        # --------------------------------------------------------------

        target_group = QGroupBox("Targets")
        target_layout = QVBoxLayout(target_group)

        self.target_list = QListWidget()
        target_layout.addWidget(self.target_list)

        self.add_target_button = QPushButton("Add Target")
        self.refresh_targets_button = QPushButton("Refresh Targets")

        self.add_target_button.clicked.connect(self.create_target)
        self.refresh_targets_button.clicked.connect(self.load_targets)

        target_buttons = QHBoxLayout()
        target_buttons.addWidget(self.add_target_button)
        target_buttons.addWidget(self.refresh_targets_button)

        target_layout.addLayout(target_buttons)

        layout.addWidget(target_group)

        self.status_label = QLabel("Select a project.")

        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------

    def load_projects(self) -> None:
        """Load projects from the API."""
        try:
            data = self.api_client.get_projects()

            self.projects = data.get("projects", [])

            self.project_list.blockSignals(True)
            self.project_list.clear()

            for project in self.projects:
                item = QListWidgetItem(
                    f"{project.get('name', 'Unnamed')} "
                    f"(ID: {project.get('id')})"
                )

                item.setData(
                    32,
                    project.get("id"),
                )

                self.project_list.addItem(item)

            self.project_list.blockSignals(False)

            if self.projects:
                self.project_list.setCurrentRow(0)
            else:
                self.selected_project_id = None
                self.target_list.clear()
                self.status_label.setText("No projects found.")

        except Exception as exc:
            self._show_error(
                "Failed to load projects",
                exc,
            )

    def _project_selected(
        self,
        current: Optional[QListWidgetItem],
        previous: Optional[QListWidgetItem],
    ) -> None:
        """Handle project selection."""
        del previous

        if current is None:
            self.selected_project_id = None
            self.target_list.clear()
            self.status_label.setText("Select a project.")
            return

        project_id = current.data(32)

        if project_id is None:
            return

        self.selected_project_id = int(project_id)

        project = self._find_project(self.selected_project_id)

        if project:
            name = project.get("name", "Unnamed")
            self.status_label.setText(
                f"Selected project: {name} "
                f"(ID: {self.selected_project_id})"
            )

        self.load_targets()

    def create_project(self) -> None:
        """Create a new project using a simple dialog."""
        name, accepted = QInputDialog.getText(
            self,
            "Create Project",
            "Project name:",
        )

        if not accepted or not name.strip():
            return

        description, accepted = QInputDialog.getText(
            self,
            "Create Project",
            "Description:",
        )

        if not accepted:
            return

        try:
            self.api_client.create_project(
                name=name.strip(),
                description=description.strip(),
            )

            self.load_projects()

        except Exception as exc:
            self._show_error(
                "Failed to create project",
                exc,
            )

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def load_targets(self) -> None:
        """Load targets and display only those belonging to the selected project."""
        self.target_list.clear()

        if self.selected_project_id is None:
            return

        try:
            data = self.api_client.get_targets()

            all_targets = data.get("targets", [])

            self.targets = [
                target
                for target in all_targets
                if target.get("project_id") == self.selected_project_id
            ]

            for target in self.targets:
                name = target.get("name", "Unnamed")
                ip_address = target.get("ip_address", "Unknown")
                status = target.get("status", "unknown")

                item = QListWidgetItem(
                    f"{name} — {ip_address} [{status}]"
                )

                item.setData(
                    32,
                    target.get("id"),
                )

                self.target_list.addItem(item)

            if not self.targets:
                self.target_list.addItem("No targets in this project.")

        except Exception as exc:
            self._show_error(
                "Failed to load targets",
                exc,
            )

    def create_target(self) -> None:
        """Create a target under the currently selected project."""
        if self.selected_project_id is None:
            QMessageBox.information(
                self,
                "No Project Selected",
                "Select a project before creating a target.",
            )
            return

        name, accepted = QInputDialog.getText(
            self,
            "Create Target",
            "Target name:",
        )

        if not accepted or not name.strip():
            return

        ip_address, accepted = QInputDialog.getText(
            self,
            "Create Target",
            "IP address:",
        )

        if not accepted or not ip_address.strip():
            return

        try:
            self.api_client.create_target(
                project_id=self.selected_project_id,
                name=name.strip(),
                ip_address=ip_address.strip(),
            )

            self.load_targets()

        except Exception as exc:
            self._show_error(
                "Failed to create target",
                exc,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_project(
        self,
        project_id: int,
    ) -> Optional[Dict[str, Any]]:
        """Find a loaded project by ID."""
        for project in self.projects:
            if project.get("id") == project_id:
                return project

        return None

    def _show_error(
        self,
        title: str,
        error: Exception,
    ) -> None:
        """Display an API error to the user."""
        QMessageBox.critical(
            self,
            title,
            str(error),
        )