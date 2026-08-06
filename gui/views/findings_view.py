"""
Findings and Vulnerabilities view.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class FindingsView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Findings & Vulnerabilities View"))
