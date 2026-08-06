"""
Module Browser and selection view.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class ModuleBrowserView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Module Browser View"))
