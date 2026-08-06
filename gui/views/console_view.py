"""
Live WebSocket console output stream view.
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit


class ConsoleView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Live Execution Console Output"))
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)
