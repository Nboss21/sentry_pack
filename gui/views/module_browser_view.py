"""
Metasploit-style module catalogue browser with 480+ Exploit Pack integration,
target-contextual filtering, reliability rankings, and live parameter validation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.base_module import ModuleOption, OptionType
from gui.api_client import SentryPackAPIClient
from gui.styles import (
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
    get_exploit_rank,
    get_pill_style,
    get_rank_badge_style,
)
from gui.widgets.config_form_generator import ConfigFormGenerator


class ModuleBrowserView(QWidget):
    """Metasploit-style module catalogue browser and execution orchestrator."""

    module_run_started = pyqtSignal(str, int, str)  # run_id, target_id, module_id

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.api_client = SentryPackAPIClient()
        self.modules_cache: List[Dict[str, Any]] = []
        self.targets_cache: List[Dict[str, Any]] = []
        self.selected_module: Optional[Dict[str, Any]] = None
        self.config_form: Optional[ConfigFormGenerator] = None
        self._last_run_info: Dict[str, str] = {}  # module_id -> status

        self._build_ui()
        self.load_data()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # ── Top Bar ─────────────────────────────────────────────────────
        top_bar = QHBoxLayout()

        title = QLabel("Module Catalogue")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLOR_CYAN};")
        top_bar.addWidget(title)

        self.module_count_lbl = QLabel("(Loading...)")
        self.module_count_lbl.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; font-size: 12px;")
        top_bar.addWidget(self.module_count_lbl)

        top_bar.addStretch()

        # Contextual filter for selected target
        self.filter_compatible_chk = QCheckBox("Show Target Compatible Only")
        self.filter_compatible_chk.setToolTip("Only show modules that match open services on the chosen target")
        self.filter_compatible_chk.stateChanged.connect(self._filter_modules)
        top_bar.addWidget(self.filter_compatible_chk)

        # Real-time search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍 Search modules by name, CVE, service...")
        self.search_box.setFixedWidth(280)
        self.search_box.textChanged.connect(self._filter_modules)
        top_bar.addWidget(self.search_box)

        self.refresh_btn = QPushButton("⟳ Refresh")
        self.refresh_btn.clicked.connect(self.load_data)
        top_bar.addWidget(self.refresh_btn)

        main_layout.addLayout(top_bar)

        # ── Splitter: Category Tree (Left) & Inspector/Runner (Right) ────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Tree
        tree_container = QWidget()
        tree_layout = QVBoxLayout(tree_container)
        tree_layout.setContentsMargins(0, 0, 0, 0)

        self.module_tree = QTreeWidget()
        self.module_tree.setHeaderLabels(["Category / Module", "Reliability"])
        self.module_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.module_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.module_tree.itemSelectionChanged.connect(self._on_module_selected)
        tree_layout.addWidget(self.module_tree)

        splitter.addWidget(tree_container)

        # Right: Module Details & Form
        self.inspector_scroll = QScrollArea()
        self.inspector_scroll.setWidgetResizable(True)
        self.inspector_container = QWidget()
        self.inspector_layout = QVBoxLayout(self.inspector_container)
        self.inspector_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.inspector_layout.setSpacing(12)
        self.inspector_scroll.setWidget(self.inspector_container)

        # Placeholder message initially
        self.empty_inspector_label = QLabel("Select a module from the catalogue to configure and execute.")
        self.empty_inspector_label.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; padding: 30px; font-size: 14px;")
        self.empty_inspector_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.inspector_layout.addWidget(self.empty_inspector_label)

        splitter.addWidget(self.inspector_scroll)
        splitter.setSizes([340, 560])

        main_layout.addWidget(splitter)

    def load_data(self) -> None:
        """Fetch available modules and active targets from backend."""
        try:
            mod_data = self.api_client.get_modules()
            self.modules_cache = mod_data.get("modules", [])
            self.module_count_lbl.setText(f"({len(self.modules_cache)} modules available)")
        except Exception:
            self.modules_cache = []
            self.module_count_lbl.setText("(0 modules)")

        try:
            tgt_data = self.api_client.get_targets()
            self.targets_cache = tgt_data.get("targets", [])
        except Exception:
            self.targets_cache = []

        self._populate_tree()

    def _populate_tree(self) -> None:
        """Group modules hierarchically by category and subcategory."""
        self.module_tree.clear()
        categories: Dict[str, QTreeWidgetItem] = {}

        for mod in self.modules_cache:
            cat_path = mod.get("category", "general")
            # Split nested categories e.g. exploit/http -> top: exploit, sub: http
            cat_parts = cat_path.split("/")
            top_cat = cat_parts[0]

            if top_cat not in categories:
                top_item = QTreeWidgetItem(self.module_tree)
                top_icon = "💣" if top_cat == "exploit" else ("🔍" if top_cat == "recon" else "⚙")
                top_item.setText(0, f"{top_icon} {top_cat.upper()}")
                top_item.setFont(0, QFont("-apple-system", 10, QFont.Weight.Bold))
                top_item.setForeground(0, QColor(COLOR_CYAN))
                top_item.setExpanded(True)
                categories[top_cat] = top_item

            parent_item = categories[top_cat]
            if len(cat_parts) > 1:
                sub_key = f"{top_cat}/{cat_parts[1]}"
                if sub_key not in categories:
                    sub_item = QTreeWidgetItem(parent_item)
                    sub_item.setText(0, f"📁 {cat_parts[1]}")
                    sub_item.setForeground(0, QColor(COLOR_TEXT_PRIMARY))
                    sub_item.setExpanded(True)
                    categories[sub_key] = sub_item
                parent_item = categories[sub_key]

            # Module Leaf Item
            leaf = QTreeWidgetItem(parent_item)
            name = mod.get("name") or mod.get("id", "Unnamed")
            leaf.setText(0, name)
            leaf.setData(0, Qt.ItemDataRole.UserRole, mod)

            # Reliability rank
            rank, _ = get_exploit_rank(mod)
            leaf.setText(1, rank.split()[0])
            leaf.setForeground(1, QColor("#10B981" if "EXCELLENT" in rank else "#38BDF8"))

    def _filter_modules(self) -> None:
        """Filter tree items by search query and target compatibility."""
        query = self.search_box.text().strip().lower()
        only_compatible = self.filter_compatible_chk.isChecked()

        # Gather target services if compatibility filter is active
        target_services: set[str] = set()
        if only_compatible and hasattr(self, "target_combo") and self.target_combo:
            selected_target = self.target_combo.currentData()
            if selected_target and isinstance(selected_target, dict):
                target_name = (selected_target.get("name") or "").lower()
                if "web" in target_name:
                    target_services.update(["http", "apache", "nginx", "web"])
                elif "db" in target_name:
                    target_services.update(["postgres", "mysql", "sql", "redis"])
                elif "infra" in target_name:
                    target_services.update(["smb", "rdp", "ssh", "dns"])

        def filter_item(item: QTreeWidgetItem) -> bool:
            mod_data = item.data(0, Qt.ItemDataRole.UserRole)
            if mod_data is not None:
                # Match query
                name = str(mod_data.get("name", "")).lower()
                mod_id = str(mod_data.get("id", "")).lower()
                desc = str(mod_data.get("description", "")).lower()
                service = str(mod_data.get("service", "")).lower()

                matches_query = not query or (
                    query in name or query in mod_id or query in desc or query in service
                )

                # Match target compatibility
                matches_target = True
                if only_compatible and target_services:
                    matches_target = any(s in name or s in service or s in mod_id for s in target_services)

                visible = matches_query and matches_target
                item.setHidden(not visible)
                return visible

            # It's a category/folder
            child_visible = False
            for i in range(item.childCount()):
                child = item.child(i)
                if filter_item(child):
                    child_visible = True

            item.setHidden(not child_visible)
            return child_visible

        for i in range(self.module_tree.topLevelItemCount()):
            filter_item(self.module_tree.topLevelItem(i))

    def _on_module_selected(self) -> None:
        selected_items = self.module_tree.selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        mod_data = item.data(0, Qt.ItemDataRole.UserRole)
        if not mod_data:
            return

        self.selected_module = mod_data
        self._build_inspector(mod_data)

    def _build_inspector(self, module: Dict[str, Any]) -> None:
        """Render details, dynamic options form, and execute controls."""
        while self.inspector_layout.count():
            child = self.inspector_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        # ── 1. Header Card ──────────────────────────────────────────────
        header_card = QFrame()
        header_card.setStyleSheet(
            f"background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; padding: 14px;"
        )
        h_layout = QVBoxLayout(header_card)
        h_layout.setSpacing(6)

        title_lbl = QLabel(module.get("name", module.get("id", "")))
        title_lbl.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLOR_CYAN};")
        h_layout.addWidget(title_lbl)

        badges_row = QHBoxLayout()
        badges_row.setSpacing(6)

        # Reliability rank badge
        rank_text, rank_color = get_exploit_rank(module)
        rank_badge = QLabel(rank_text)
        rank_badge.setStyleSheet(get_rank_badge_style(rank_color))
        badges_row.addWidget(rank_badge)

        # Category pill
        cat_pill = QLabel(module.get("category", "exploit"))
        cat_pill.setStyleSheet(get_pill_style(fg=COLOR_PURPLE))
        badges_row.addWidget(cat_pill)

        # Module ID pill
        id_pill = QLabel(module.get("id", ""))
        id_pill.setStyleSheet(get_pill_style(fg=COLOR_CYAN))
        badges_row.addWidget(id_pill)

        # Version pill
        ver_pill = QLabel(f"v{module.get('version', '1.0.0')}")
        ver_pill.setStyleSheet(get_pill_style(fg=COLOR_TEXT_SECONDARY))
        badges_row.addWidget(ver_pill)

        badges_row.addStretch()
        h_layout.addLayout(badges_row)

        desc = QLabel(module.get("description", "No description provided."))
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; margin-top: 6px;")
        h_layout.addWidget(desc)

        author = QLabel(f"Author: {module.get('author', 'SentryPack Team')}")
        author.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; font-size: 11px;")
        h_layout.addWidget(author)

        # Last run indicator
        mod_id = module.get("id", "")
        last_status = self._last_run_info.get(mod_id, "Never executed in this session")
        last_run_lbl = QLabel(f"Last Execution: {last_status}")
        last_run_lbl.setStyleSheet("color: #64748B; font-size: 11px; font-style: italic;")
        h_layout.addWidget(last_run_lbl)

        self.inspector_layout.addWidget(header_card)

        # ── 2. Target Selector ──────────────────────────────────────────
        target_card = QFrame()
        target_card.setStyleSheet(
            f"background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; padding: 12px;"
        )
        t_layout = QVBoxLayout(target_card)
        t_layout.setSpacing(6)

        t_lbl = QLabel("Execution Target (RHOST):")
        t_lbl.setStyleSheet(f"font-weight: bold; color: {COLOR_TEXT_PRIMARY};")
        t_layout.addWidget(t_lbl)

        self.target_combo = QComboBox()
        if not self.targets_cache:
            self.target_combo.addItem("No targets available — add target in Projects view", None)
        else:
            for t in self.targets_cache:
                display = f"#{t.get('id')} — {t.get('name', 'Target')} ({t.get('ip_address', '')})"
                self.target_combo.addItem(display, t)

        t_layout.addWidget(self.target_combo)
        self.inspector_layout.addWidget(target_card)

        # ── 3. Module Options Form ──────────────────────────────────────
        form_card = QFrame()
        form_card.setStyleSheet(
            f"background-color: {COLOR_BG_CARD}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; padding: 12px;"
        )
        form_layout = QVBoxLayout(form_card)

        form_title = QLabel("Module Options:")
        form_title.setStyleSheet(f"font-weight: bold; color: {COLOR_TEXT_PRIMARY}; margin-bottom: 6px;")
        form_layout.addWidget(form_title)

        # Build options list from module dict
        raw_options = module.get("options", [])
        parsed_options: List[ModuleOption] = []
        for opt in raw_options:
            opt_type_str = opt.get("option_type") or opt.get("type") or "string"
            try:
                opt_type = OptionType(opt_type_str)
            except ValueError:
                opt_type = OptionType.STRING

            parsed_options.append(
                ModuleOption(
                    name=opt.get("name", ""),
                    description=opt.get("description", ""),
                    option_type=opt_type,
                    required=opt.get("required", True),
                    default=opt.get("default"),
                    choices=opt.get("choices"),
                )
            )

        self.config_form = ConfigFormGenerator(parsed_options)
        form_layout.addWidget(self.config_form)
        self.inspector_layout.addWidget(form_card)

        # ── 4. Execute Action Button ────────────────────────────────────
        execute_btn = QPushButton("⚡ Execute Module Against Target")
        execute_btn.setProperty("primary", True)
        execute_btn.setFixedHeight(38)
        execute_btn.setStyleSheet("font-size: 13px; font-weight: bold; background-color: #0284c7;")
        execute_btn.clicked.connect(self._execute_current_module)
        self.inspector_layout.addWidget(execute_btn)

    def _execute_current_module(self) -> None:
        """Validate options and dispatch module execution."""
        if not self.selected_module:
            return

        selected_target = self.target_combo.currentData()
        if not selected_target or not isinstance(selected_target, dict):
            QMessageBox.warning(self, "No Target Selected", "Please select a valid target host from the dropdown.")
            return

        target_id = selected_target.get("id")
        target_ip = selected_target.get("ip_address", "127.0.0.1")
        module_id = self.selected_module.get("id", "")

        options = self.config_form.get_values() if self.config_form else {}
        if "TARGET" not in options or not str(options["TARGET"]).strip():
            options["TARGET"] = target_ip

        # Live parameter validation
        target_val = str(options.get("TARGET", "")).strip()
        if not target_val:
            QMessageBox.warning(self, "Validation Error", "Target IP/Hostname (TARGET) cannot be blank.")
            return

        if "PORT" in options and options["PORT"]:
            try:
                p = int(options["PORT"])
                if not (1 <= p <= 65535):
                    raise ValueError()
            except ValueError:
                QMessageBox.warning(self, "Validation Error", "PORT must be an integer between 1 and 65535.")
                return

        try:
            res = self.api_client.run_module(int(target_id), module_id, options)
            run_id = res.get("run_id", "")
            self._last_run_info[module_id] = f"Active [Run {run_id[:8]}]"
            QMessageBox.information(
                self,
                "Module Dispatched",
                f"Module '{module_id}' has been launched!\nRun ID: {run_id}\n\n"
                "Live output will stream in the Live Console View.",
            )
            self.module_run_started.emit(run_id, int(target_id), module_id)
        except Exception as exc:
            QMessageBox.critical(self, "Execution Failed", f"Failed to run module: {exc}")