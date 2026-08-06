"""
Projects View for project workspace management.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class ProjectsView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Projects Management View"))
