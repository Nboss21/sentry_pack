"""
Armitage-style visual target graph view with Subnet Clustering, Port Chips,
OS badges, and C2 Beacon Vector Lines.

Features:
  - Subnet perimeter groupings (e.g., 10.0.0.0/24, 192.168.1.0/24)
  - Rich computer card nodes with OS platform logos and open port chips
  - Iconic Armitage Compromised state (electric red halo & skull badge)
  - Central SentryPack C2 Listener hub with active beacon lines
  - Real-time search/filter toolbar (All, Compromised, Vulnerable, Scanned)
  - Mouse-wheel zoom & drag-to-pan navigation
  - Right-click host context menu (Attack, Scan, Shell, Copy IP)
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QLineF, QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QCursor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QWheelEvent,
)
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from gui.api_client import SentryPackAPIClient
from gui.styles import (
    COLOR_BG_CANVAS,
    COLOR_BG_CARD,
    COLOR_BG_ELEVATED,
    COLOR_BORDER,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_PURPLE,
    COLOR_RED,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    COLOR_YELLOW,
    TARGET_STATUS_COLORS,
)


def _detect_os_badge(name: str, ip: str) -> tuple[str, str]:
    """Detect platform type and return (icon, display_label)."""
    n = name.lower()
    if any(k in n for k in ("win", "dc", "ad", "exchange", "iis")):
        return ("🪟", "Windows")
    elif any(k in n for k in ("linux", "ubuntu", "debian", "centos", "rhel", "nginx", "apache")):
        return ("🐧", "Linux")
    elif any(k in n for k in ("docker", "container", "k8s", "pod")):
        return ("🐳", "Docker")
    elif any(k in n for k in ("router", "switch", "cisco", "gateway")):
        return ("🌐", "Cisco")
    elif any(k in n for k in ("db", "sql", "postgres", "mongo")):
        return ("🗄", "Database")
    return ("💻", "Server")


def _extract_subnet(ip: str) -> str:
    """Extract subnet /24 string from an IPv4 address."""
    parts = ip.strip().split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "Local Subnet"


class SubnetEnclosureItem(QGraphicsItem):
    """Visual perimeter box enclosing hosts in the same subnet."""

    def __init__(self, subnet: str, rect: QRectF, parent: Optional[QGraphicsItem] = None) -> None:
        super().__init__(parent)
        self.subnet = subnet
        self.box_rect = rect
        self.setZValue(-10)  # Render behind nodes

    def boundingRect(self) -> QRectF:
        return self.box_rect

    def paint(self, painter: QPainter, option, widget=None) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Subtle dark translucent fill
        painter.setBrush(QBrush(QColor(17, 24, 39, 140)))
        pen = QPen(QColor(COLOR_BORDER), 1.5, Qt.PenStyle.DashLine)
        painter.setPen(pen)
        painter.drawRoundedRect(self.box_rect, 10, 10)

        # Subnet Title Banner
        painter.setPen(QColor(COLOR_CYAN))
        font = QFont("Consolas", 10, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(
            QRectF(self.box_rect.left() + 14, self.box_rect.top() + 8, self.box_rect.width() - 28, 20),
            Qt.AlignmentFlag.AlignLeft,
            f"⚡ Subnet Perimeter: {self.subnet}",
        )


class C2ListenerHubNode(QGraphicsItem):
    """Central visual hub representing the active SentryPack C2 Listener."""

    WIDTH = 180
    HEIGHT = 56

    def __init__(self, parent: Optional[QGraphicsItem] = None) -> None:
        super().__init__(parent)
        self.setZValue(5)
        self.setToolTip("SentryPack C2 Controller Hub (Active Ingress/Egress Channels)")

    def boundingRect(self) -> QRectF:
        return QRectF(-5, -5, self.WIDTH + 10, self.HEIGHT + 10)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(0, 0, self.WIDTH, self.HEIGHT)
        # Glowing Emerald/Cyan Hub Border
        halo_pen = QPen(QColor(16, 185, 129, 120), 4)
        painter.setPen(halo_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 8, 8)

        # Hub Surface
        painter.setBrush(QBrush(QColor("#064E3B")))
        painter.setPen(QPen(QColor(COLOR_GREEN), 1.5))
        painter.drawRoundedRect(rect, 6, 6)

        painter.setPen(QColor("#FFFFFF"))
        font = QFont("-apple-system", 9, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(QRectF(10, 8, self.WIDTH - 20, 18), Qt.AlignmentFlag.AlignCenter, "📡 SENTRYPACK C2 HUB")

        sub_font = QFont("Consolas", 8, QFont.Weight.Normal)
        painter.setFont(sub_font)
        painter.setPen(QColor("#A7F3D0"))
        painter.drawText(QRectF(10, 28, self.WIDTH - 20, 16), Qt.AlignmentFlag.AlignCenter, "TLS :8443 | HTTPS :8080")


class BeaconConnectionLine(QGraphicsLineItem):
    """Glowing vector line connecting C2 Listener to a compromised host."""

    def __init__(self, start: QPointF, end: QPointF, parent: Optional[QGraphicsItem] = None) -> None:
        super().__init__(QLineF(start, end), parent)
        self.setZValue(-5)
        pen = QPen(QColor(239, 68, 68, 180), 2.5, Qt.PenStyle.DashLine)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        self.setPen(pen)


class TargetNode(QGraphicsItem):
    """Armitage-style visual card representing a network host."""

    WIDTH = 175
    HEIGHT = 115

    def __init__(self, target: Dict[str, Any], parent: Optional[QGraphicsItem] = None) -> None:
        super().__init__(parent)
        self.target = target
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self._is_hovered = False

        status = str(target.get("status", "idle")).lower()
        self.setToolTip(
            f"Host: {target.get('name', 'Unnamed')}\n"
            f"IP: {target.get('ip_address', 'Unknown')}\n"
            f"Status: {status.upper()}"
        )

    def boundingRect(self) -> QRectF:
        return QRectF(-10, -10, self.WIDTH + 20, self.HEIGHT + 20)

    def hoverEnterEvent(self, event) -> None:
        self._is_hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self._is_hovered = False
        self.update()
        super().hoverLeaveEvent(event)

    def center_point(self) -> QPointF:
        return self.pos() + QPointF(self.WIDTH / 2, self.HEIGHT / 2)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        status = str(self.target.get("status", "idle")).lower()
        is_selected = self.isSelected()
        is_compromised = status == "compromised"
        is_vulnerable = status in ("vulnerable", "error")
        is_scanned = status == "scanned"

        card_rect = QRectF(0, 0, self.WIDTH, self.HEIGHT)

        # ── 1. Status Halos ─────────────────────────────────────────────
        if is_compromised:
            halo_pen = QPen(QColor(239, 68, 68, 190), 6)
            painter.setPen(halo_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(card_rect.adjusted(-3, -3, 3, 3), 10, 10)
        elif is_selected:
            halo_pen = QPen(QColor(0, 229, 255, 220), 4)
            painter.setPen(halo_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(card_rect.adjusted(-2, -2, 2, 2), 8, 8)
        elif is_vulnerable:
            halo_pen = QPen(QColor(245, 158, 11, 150), 3)
            painter.setPen(halo_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(card_rect.adjusted(-1, -1, 1, 1), 8, 8)

        # ── 2. Card Background & Base Border ────────────────────────────
        bg_color = QColor(COLOR_BG_ELEVATED if (self._is_hovered or is_selected) else COLOR_BG_CARD)
        border_color = QColor(COLOR_CYAN if is_selected else (COLOR_RED if is_compromised else COLOR_BORDER))

        painter.setBrush(QBrush(bg_color))
        painter.setPen(QPen(border_color, 2 if (is_selected or is_compromised) else 1))
        painter.drawRoundedRect(card_rect, 6, 6)

        # ── 3. Top Header Bar ───────────────────────────────────────────
        header_rect = QRectF(0, 0, self.WIDTH, 26)
        header_path = QPainterPath()
        header_path.addRoundedRect(header_rect, 6, 6)
        painter.setClipPath(header_path)

        header_bg = QColor(153, 27, 27, 230) if is_compromised else QColor(17, 24, 39, 240)
        painter.fillPath(header_path, QBrush(header_bg))
        painter.setClipping(False)

        painter.setPen(QPen(QColor(COLOR_RED if is_compromised else (COLOR_CYAN if is_selected else COLOR_BORDER)), 1))
        painter.drawLine(0, 26, self.WIDTH, 26)

        # ── 4. OS Logo & Name ───────────────────────────────────────────
        name = str(self.target.get("name", "Target"))
        ip = str(self.target.get("ip_address", "0.0.0.0"))
        os_icon, os_label = _detect_os_badge(name, ip)

        painter.setPen(QColor("#FFFFFF" if is_compromised else COLOR_TEXT_PRIMARY))
        font = QFont("-apple-system", 9, QFont.Weight.Bold)
        painter.setFont(font)

        # Draw OS Icon + Host Name
        display_header = f"{os_icon} {name}"
        if len(display_header) > 17:
            display_header = display_header[:15] + "…"

        painter.drawText(QRectF(8, 5, self.WIDTH - 42, 18), Qt.AlignmentFlag.AlignLeft, display_header)

        # Status badge / skull
        if is_compromised:
            painter.drawText(QRectF(self.WIDTH - 28, 4, 20, 18), Qt.AlignmentFlag.AlignRight, "☠")
        else:
            dot_color = TARGET_STATUS_COLORS.get(status, TARGET_STATUS_COLORS["unknown"])
            painter.setBrush(QBrush(dot_color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(self.WIDTH - 18, 9, 8, 8)

        # ── 5. IP Address ───────────────────────────────────────────────
        ip_font = QFont("Consolas", 10, QFont.Weight.Bold)
        painter.setFont(ip_font)
        painter.setPen(QColor(COLOR_CYAN if is_selected else COLOR_TEXT_PRIMARY))
        painter.drawText(QRectF(8, 36, self.WIDTH - 16, 18), Qt.AlignmentFlag.AlignLeft, ip)

        # ── 6. Status & Platform Info ───────────────────────────────────
        status_font = QFont("-apple-system", 8, QFont.Weight.DemiBold)
        painter.setFont(status_font)
        status_text = "COMPROMISED" if is_compromised else status.upper()
        text_color = QColor(COLOR_RED if is_compromised else (COLOR_GREEN if is_scanned else COLOR_TEXT_SECONDARY))
        painter.setPen(text_color)
        painter.drawText(QRectF(8, 56, self.WIDTH - 16, 16), Qt.AlignmentFlag.AlignLeft, f"Status: {status_text}")

        # ── 7. Live Open Port Badges (Chips) ────────────────────────────
        # Draw miniature port pills at the bottom
        port_font = QFont("Consolas", 8, QFont.Weight.Bold)
        painter.setFont(port_font)

        # Infer or derive ports (e.g. web targets show 80/443, ssh shows 22)
        demo_ports = self._derive_demo_ports(name, ip)
        x_offset = 8
        for p in demo_ports:
            pill_rect = QRectF(x_offset, 86, 34, 18)
            painter.setBrush(QBrush(QColor(31, 41, 55)))
            painter.setPen(QPen(QColor(COLOR_BORDER), 1))
            painter.drawRoundedRect(pill_rect, 3, 3)

            painter.setPen(QColor(COLOR_CYAN))
            painter.drawText(pill_rect, Qt.AlignmentFlag.AlignCenter, f":{p}")
            x_offset += 38

    def _derive_demo_ports(self, name: str, ip: str) -> List[int]:
        """Derive standard open ports for visual map context."""
        n = name.lower()
        if "web" in n or "http" in n:
            return [80, 443, 8080]
        elif "db" in n or "sql" in n:
            return [22, 3306, 5432]
        elif "infra" in n or "dc" in n:
            return [22, 53, 88, 445]
        return [22, 80]


class HostGraphView(QWidget):
    """Armitage-style interactive network topology graph with Subnet Clustering."""

    target_selected = pyqtSignal(dict)
    scan_requested = pyqtSignal(dict)
    attack_requested = pyqtSignal(dict)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.api_client = SentryPackAPIClient()
        self.targets: List[Dict[str, Any]] = []
        self._current_project_id: Optional[int] = None
        self._filter_status: str = "all"
        self._search_query: str = ""
        self._layout_mode: str = "subnet"  # "subnet" | "grid"
        self.node_items: List[TargetNode] = []

        self._build_ui()
        self.load_targets()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # ── Top Toolbar ─────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(10, 8, 10, 0)
        toolbar.setSpacing(8)

        title = QLabel("Network Host Graph")
        title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {COLOR_CYAN};")
        toolbar.addWidget(title)

        # Search Bar
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Quick search host/IP...")
        self.search_input.setFixedWidth(190)
        self.search_input.textChanged.connect(self._on_search_changed)
        toolbar.addWidget(self.search_input)

        # Quick Status Filters
        self.filter_all_btn = QPushButton("All")
        self.filter_all_btn.setCheckable(True)
        self.filter_all_btn.setChecked(True)
        self.filter_all_btn.clicked.connect(lambda: self._set_filter("all"))
        toolbar.addWidget(self.filter_all_btn)

        self.filter_comp_btn = QPushButton("☠ Compromised")
        self.filter_comp_btn.setCheckable(True)
        self.filter_comp_btn.clicked.connect(lambda: self._set_filter("compromised"))
        toolbar.addWidget(self.filter_comp_btn)

        self.filter_vuln_btn = QPushButton("⚠ Vulnerable")
        self.filter_vuln_btn.setCheckable(True)
        self.filter_vuln_btn.clicked.connect(lambda: self._set_filter("vulnerable"))
        toolbar.addWidget(self.filter_vuln_btn)

        self.filter_scan_btn = QPushButton("✓ Scanned")
        self.filter_scan_btn.setCheckable(True)
        self.filter_scan_btn.clicked.connect(lambda: self._set_filter("scanned"))
        toolbar.addWidget(self.filter_scan_btn)

        toolbar.addStretch()

        # Layout Mode Toggle
        self.layout_btn = QPushButton("☷ Subnet Mode")
        self.layout_btn.setToolTip("Toggle between Subnet Clustering and Grid Layout")
        self.layout_btn.clicked.connect(self._toggle_layout_mode)
        toolbar.addWidget(self.layout_btn)

        # Zoom Controls
        self.zoom_in_btn = QPushButton("+")
        self.zoom_in_btn.setFixedSize(28, 28)
        self.zoom_in_btn.clicked.connect(self._zoom_in)
        toolbar.addWidget(self.zoom_in_btn)

        self.zoom_out_btn = QPushButton("−")
        self.zoom_out_btn.setFixedSize(28, 28)
        self.zoom_out_btn.clicked.connect(self._zoom_out)
        toolbar.addWidget(self.zoom_out_btn)

        self.zoom_fit_btn = QPushButton("⛶ Fit")
        self.zoom_fit_btn.setFixedHeight(28)
        self.zoom_fit_btn.clicked.connect(self._zoom_fit)
        toolbar.addWidget(self.zoom_fit_btn)

        self.refresh_btn = QPushButton("⟳ Refresh")
        self.refresh_btn.setFixedHeight(28)
        self.refresh_btn.clicked.connect(self.load_targets)
        toolbar.addWidget(self.refresh_btn)

        layout.addLayout(toolbar)

        # ── Graphics View & Scene ───────────────────────────────────────
        self.scene = QGraphicsScene(self)
        self.scene.setBackgroundBrush(QBrush(QColor(COLOR_BG_CANVAS)))
        self.scene.selectionChanged.connect(self._on_selection_changed)

        self.graph_view = QGraphicsView(self.scene)
        self.graph_view.setRenderHints(
            QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing
        )
        self.graph_view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.graph_view.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.graph_view.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.graph_view.setStyleSheet(f"border: 1px solid {COLOR_BORDER}; background-color: {COLOR_BG_CANVAS};")

        layout.addWidget(self.graph_view)

    def wheelEvent(self, event: QWheelEvent) -> None:
        """Smooth mouse-wheel zoom centered on cursor."""
        zoom_factor = 1.15
        if event.angleDelta().y() < 0:
            zoom_factor = 1.0 / zoom_factor
        self.graph_view.scale(zoom_factor, zoom_factor)

    def _zoom_in(self) -> None:
        self.graph_view.scale(1.2, 1.2)

    def _zoom_out(self) -> None:
        self.graph_view.scale(1 / 1.2, 1 / 1.2)

    def _zoom_fit(self) -> None:
        rect = self.scene.itemsBoundingRect()
        if not rect.isEmpty():
            self.graph_view.fitInView(rect.adjusted(-50, -50, 50, 50), Qt.AspectRatioMode.KeepAspectRatio)

    def _toggle_layout_mode(self) -> None:
        if self._layout_mode == "subnet":
            self._layout_mode = "grid"
            self.layout_btn.setText("⊞ Grid Mode")
        else:
            self._layout_mode = "subnet"
            self.layout_btn.setText("☷ Subnet Mode")
        self._build_graph()

    def _set_filter(self, status: str) -> None:
        self._filter_status = status
        for btn in (self.filter_all_btn, self.filter_comp_btn, self.filter_vuln_btn, self.filter_scan_btn):
            btn.setChecked(False)

        if status == "all":
            self.filter_all_btn.setChecked(True)
        elif status == "compromised":
            self.filter_comp_btn.setChecked(True)
        elif status == "vulnerable":
            self.filter_vuln_btn.setChecked(True)
        elif status == "scanned":
            self.filter_scan_btn.setChecked(True)

        self._build_graph()

    def _on_search_changed(self, text: str) -> None:
        self._search_query = text.strip().lower()
        if not self._search_query:
            return

        # Find first matching node and center view
        for node in self.node_items:
            t = node.target
            name = str(t.get("name", "")).lower()
            ip = str(t.get("ip_address", "")).lower()
            if self._search_query in name or self._search_query in ip:
                self.scene.clearSelection()
                node.setSelected(True)
                self.graph_view.centerOn(node)
                break

    def _on_selection_changed(self) -> None:
        selected_items = self.scene.selectedItems()
        if selected_items and isinstance(selected_items[0], TargetNode):
            self.target_selected.emit(selected_items[0].target)

    def load_targets(self) -> None:
        """Fetch targets from API and render topology."""
        try:
            data = self.api_client.get_targets()
            all_targets = data.get("targets", [])

            if self._current_project_id is not None:
                self.targets = [t for t in all_targets if t.get("project_id") == self._current_project_id]
            else:
                self.targets = all_targets

            self._build_graph()
        except Exception:
            self.scene.clear()

    def set_project(self, project_id: int) -> None:
        self._current_project_id = project_id
        self.load_targets()

    def _build_graph(self) -> None:
        """Build the network topology scene with subnet clusters and C2 beacon lines."""
        self.scene.clear()
        self.node_items.clear()

        if not self.targets:
            return

        # 1. Filter targets
        visible_targets = []
        for t in self.targets:
            status = str(t.get("status", "idle")).lower()
            if self._filter_status != "all":
                if self._filter_status == "compromised" and status != "compromised":
                    continue
                elif self._filter_status == "vulnerable" and status not in ("vulnerable", "error"):
                    continue
                elif self._filter_status == "scanned" and status != "scanned":
                    continue
            visible_targets.append(t)

        if not visible_targets:
            return

        # 2. Place C2 Listener Hub at top-center
        c2_hub = C2ListenerHubNode()
        c2_hub.setPos(260, -110)
        self.scene.addItem(c2_hub)
        c2_center = c2_hub.pos() + QPointF(C2ListenerHubNode.WIDTH / 2, C2ListenerHubNode.HEIGHT)

        # 3. Layout Targets by Subnet or Grid
        if self._layout_mode == "subnet":
            self._layout_by_subnet(visible_targets, c2_center)
        else:
            self._layout_by_grid(visible_targets, c2_center)

        rect = self.scene.itemsBoundingRect()
        self.scene.setSceneRect(rect.adjusted(-60, -60, 60, 60))
        self._zoom_fit()

    def _layout_by_subnet(self, targets: List[Dict[str, Any]], c2_center: QPointF) -> None:
        """Cluster targets inside visual subnet perimeter enclosures."""
        subnets: Dict[str, List[Dict[str, Any]]] = {}
        for t in targets:
            ip = str(t.get("ip_address", "0.0.0.0"))
            s = _extract_subnet(ip)
            subnets.setdefault(s, []).append(t)

        curr_y = 20.0
        for subnet_name, s_targets in subnets.items():
            cols = min(3, len(s_targets))
            x_spacing = 205
            y_spacing = 145

            # Calculate enclosure bounding size
            num_rows = math.ceil(len(s_targets) / 3)
            box_width = max(3 * x_spacing + 30, 480)
            box_height = num_rows * y_spacing + 55

            enclosure_rect = QRectF(0, curr_y, box_width, box_height)
            enclosure = SubnetEnclosureItem(subnet_name, enclosure_rect)
            self.scene.addItem(enclosure)

            # Place host nodes inside enclosure
            for i, target in enumerate(s_targets):
                r = i // 3
                c = i % 3
                node = TargetNode(target)
                node_x = 20 + c * x_spacing
                node_y = curr_y + 40 + r * y_spacing
                node.setPos(node_x, node_y)
                self.scene.addItem(node)
                self.node_items.append(node)

                # If compromised, draw C2 beacon connection line
                if str(target.get("status", "")).lower() == "compromised":
                    line = BeaconConnectionLine(c2_center, node.center_point())
                    self.scene.addItem(line)

            curr_y += box_height + 40

    def _layout_by_grid(self, targets: List[Dict[str, Any]], c2_center: QPointF) -> None:
        """Standard 4-column Armitage grid layout."""
        columns = 4
        x_spacing = 210
        y_spacing = 150

        for index, target in enumerate(targets):
            node = TargetNode(target)
            row = index // columns
            col = index % columns
            node.setPos(col * x_spacing, 20 + row * y_spacing)
            self.scene.addItem(node)
            self.node_items.append(node)

            if str(target.get("status", "")).lower() == "compromised":
                line = BeaconConnectionLine(c2_center, node.center_point())
                self.scene.addItem(line)

    def contextMenuEvent(self, event) -> None:
        """Armitage-style right-click context menu on target cards."""
        pos = self.graph_view.mapToScene(event.pos() - self.graph_view.pos())
        item = self.scene.itemAt(pos, self.graph_view.transform())

        while item and not isinstance(item, TargetNode):
            item = item.parentItem()

        if not isinstance(item, TargetNode):
            return

        target = item.target
        target_name = target.get("name", "Host")
        ip = target.get("ip_address", "")

        menu = QMenu(self)
        title_action = menu.addAction(f"Host: {target_name} ({ip})")
        title_action.setEnabled(False)
        menu.addSeparator()

        act_attack = menu.addAction("⚡ Find Attacks & Exploits")
        act_scan = menu.addAction("🔍 Run Recon Scan (Nmap)")
        act_shell = menu.addAction("💻 Open C2 Interactive Shell")
        menu.addSeparator()
        act_copy_ip = menu.addAction("📋 Copy IP Address")

        chosen = menu.exec(QCursor.pos())

        if chosen == act_attack:
            self.target_selected.emit(target)
            self.attack_requested.emit(target)
        elif chosen == act_scan:
            self._trigger_nmap_scan(target)
        elif chosen == act_shell:
            self.target_selected.emit(target)
        elif chosen == act_copy_ip:
            QApplication.clipboard().setText(ip)

    def _trigger_nmap_scan(self, target: Dict[str, Any]) -> None:
        tid = target.get("id")
        ip = target.get("ip_address")
        if tid is None:
            return
        try:
            res = self.api_client.run_module(int(tid), "recon.nmap_scan", {"TARGET": ip, "PORTS": "1-1024"})
            run_id = res.get("run_id", "")
            QMessageBox.information(
                self,
                "Scan Dispatched",
                f"Nmap scan launched against {ip}!\nRun ID: {run_id}\nCheck Live Console for results.",
            )
            self.scan_requested.emit(target)
        except Exception as exc:
            QMessageBox.critical(self, "Scan Failed", f"Failed to dispatch Nmap scan: {exc}")
