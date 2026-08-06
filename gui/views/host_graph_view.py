"""
Armitage-style visual target graph view.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class HostGraphView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Host Graph Visual Target View"))
