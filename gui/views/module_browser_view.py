

# from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


# class ModuleBrowserView(QWidget):

#     def __init__(self):
#         super().__init__()
#         layout = QVBoxLayout(self)
#         layout.addWidget(QLabel("Module Browser View"))
"""
Module Browser and selection view.
"""

from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
)

from gui.api_client import SentryPackAPIClient


class ModuleBrowserView(QWidget):
    """Display the modules available from the SentryPack API."""

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Module Browser"))

        self.module_list = QListWidget()
        layout.addWidget(self.module_list)

        self.api_client = SentryPackAPIClient()

        self.load_modules()

    def load_modules(self):
        """Fetch modules from the API and display them."""
        try:
            data = self.api_client.get_modules()

            for module in data.get("modules", []):
                name = module.get("name", module.get("id", "Unknown"))
                description = module.get("description", "")

                item = QListWidgetItem(
                    f"{name} — {description}"
                )

                self.module_list.addItem(item)

        except Exception as exc:
            self.module_list.addItem(
                f"Failed to load modules: {exc}"
            )