"""
Settings and configuration view.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class SettingsView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Settings & Preferences View"))
