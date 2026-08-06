"""
C2 Sessions manager view.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class SessionsView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("C2 Sessions Management View"))
