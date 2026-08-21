"""
Armitage-style visual target graph view.
"""

from typing import Any, Dict, List

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QBrush, QColor, QPen
from PyQt6.QtWidgets import (
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.api_client import SentryPackAPIClient


class TargetNode(QGraphicsEllipseItem):
    """Visual node representing a SentryPack target."""

    NODE_SIZE = 110

    STATUS_COLORS = {
        "idle": QColor("#808080"),
        "scanned": QColor("#4CAF50"),
        "running": QColor("#2196F3"),
        "error": QColor("#F44336"),
        "unknown": QColor("#9E9E9E"),
    }

    def __init__(self, target: Dict[str, Any]) -> None:
        super().__init__(
            0,
            0,
            self.NODE_SIZE,
            self.NODE_SIZE,
        )

        self.target = target

        status = str(
            target.get("status", "unknown")
        ).lower()

        color = self.STATUS_COLORS.get(
            status,
            self.STATUS_COLORS["unknown"],
        )

        self.setBrush(QBrush(color))
        self.setPen(QPen(Qt.GlobalColor.black, 2))

        self.setFlag(
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable,
            True,
        )

        self.setToolTip(
            f"Target: {target.get('name', 'Unnamed')}\n"
            f"IP: {target.get('ip_address', 'Unknown')}\n"
            f"Status: {status}"
        )

        self._add_text()

    def _add_text(self) -> None:
        """Add target name and IP text inside the node."""

        name = str(
            self.target.get("name", "Unnamed")
        )

        ip_address = str(
            self.target.get("ip_address", "Unknown")
        )

        name_text = QGraphicsSimpleTextItem(
            name,
            self,
        )

        ip_text = QGraphicsSimpleTextItem(
            ip_address,
            self,
        )

        name_rect = name_text.boundingRect()
        ip_rect = ip_text.boundingRect()

        name_text.setPos(
            (self.NODE_SIZE - name_rect.width()) / 2,
            35,
        )

        ip_text.setPos(
            (self.NODE_SIZE - ip_rect.width()) / 2,
            60,
        )

    def itemChange(self, change, value):
        """Highlight selected nodes."""

        if (
            change
            == QGraphicsItem.GraphicsItemChange.ItemSelectedChange
        ):
            if value:
                self.setPen(
                    QPen(Qt.GlobalColor.white, 4)
                )
            else:
                self.setPen(
                    QPen(Qt.GlobalColor.black, 2)
                )

        return super().itemChange(change, value)


class HostGraphView(QWidget):
    """Visual graph of all SentryPack targets."""

    def __init__(self) -> None:
        super().__init__()

        self.api_client = SentryPackAPIClient()

        self.targets: List[Dict[str, Any]] = []

        self._build_ui()
        self.load_targets()

    def _build_ui(self) -> None:
        """Build the graph UI."""

        layout = QVBoxLayout(self)

        title = QLabel("Host Graph")
        layout.addWidget(title)

        controls = QHBoxLayout()

        self.refresh_button = QPushButton(
            "Refresh"
        )

        self.refresh_button.clicked.connect(
            self.load_targets
        )

        controls.addWidget(
            self.refresh_button
        )

        controls.addStretch()

        self.status_label = QLabel(
            "Loading targets..."
        )

        controls.addWidget(
            self.status_label
        )

        layout.addLayout(controls)

        self.scene = QGraphicsScene()

        self.graph_view = QGraphicsView(
            self.scene
        )

        self.graph_view.setRenderHints(
            self.graph_view.renderHints()
        )

        layout.addWidget(
            self.graph_view
        )

    def load_targets(self) -> None:
        """Load targets from the API and rebuild the graph."""

        try:
            data = self.api_client.get_targets()

            self.targets = data.get(
                "targets",
                [],
            )

            self._build_graph()

            self.status_label.setText(
                f"{len(self.targets)} target(s)"
            )

        except Exception as exc:
            self.scene.clear()

            self.status_label.setText(
                f"Failed to load targets: {exc}"
            )
    def set_project(self, project_id: int) -> None:
   # """Display only targets belonging to the selected project."""

        try:
            data = self.api_client.get_targets()

            all_targets = data.get("targets", [])

            self.targets = [
                target
                for target in all_targets
                if target.get("project_id") == project_id
            ]

            self._build_graph()

            self.status_label.setText(
                f"{len(self.targets)} target(s) in project {project_id}"
            )

        except Exception as exc:
            self.scene.clear()
            self.status_label.setText(
                f"Failed to load targets: {exc}"
            )

    def _build_graph(self) -> None:
        """Create target nodes and arrange them in the scene."""

        self.scene.clear()

        if not self.targets:
            self.status_label.setText(
                "No targets found"
            )
            return

        columns = 4
        horizontal_spacing = 180
        vertical_spacing = 160

        for index, target in enumerate(
            self.targets
        ):
            node = TargetNode(target)

            row = index // columns
            column = index % columns

            x = column * horizontal_spacing
            y = row * vertical_spacing

            node.setPos(x, y)

            self.scene.addItem(node)

        self.scene.setSceneRect(
            self.scene.itemsBoundingRect().adjusted(
                -50,
                -50,
                50,
                50,
            )
        )
