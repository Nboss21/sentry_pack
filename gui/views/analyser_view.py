"""
Connection Analyser results view.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class AnalyserView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Connection Analyser View"))
