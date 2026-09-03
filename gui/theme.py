"""
Global application themes.
"""

from PyQt6.QtWidgets import QApplication


LIGHT_THEME = """
QWidget {
    background-color: #f5f5f5;
    color: #111111;
}

QMainWindow {
    background-color: #f5f5f5;
}

QLabel {
    color: #111111;
}

QPushButton {
    background-color: #e5e5e5;
    color: #111111;
    border: 1px solid #aaaaaa;
    padding: 6px 10px;
}

QPushButton:hover {
    background-color: #dcdcdc;
}

QListWidget {
    background-color: #ffffff;
    color: #111111;
    border: 1px solid #aaaaaa;
}

QListWidget::item {
    color: #111111;
    padding: 4px;
}

QListWidget::item:selected {
    background-color: #3b82f6;
    color: #ffffff;
}

QFrame {
    color: #111111;
}
"""


DARK_THEME = """
QWidget {
    background-color: #1e1e1e;
    color: #eeeeee;
}

QMainWindow {
    background-color: #1e1e1e;
}

QLabel {
    color: #eeeeee;
}

QPushButton {
    background-color: #2d2d2d;
    color: #eeeeee;
    border: 1px solid #555555;
    padding: 6px 10px;
}

QPushButton:hover {
    background-color: #3a3a3a;
}

QListWidget {
    background-color: #252525;
    color: #eeeeee;
    border: 1px solid #555555;
}

QListWidget::item {
    color: #eeeeee;
    padding: 4px;
}

QListWidget::item:selected {
    background-color: #3b82f6;
    color: #ffffff;
}

QFrame {
    color: #eeeeee;
}
"""


def apply_light_theme(app: QApplication):
    app.setStyleSheet(LIGHT_THEME)


def apply_dark_theme(app: QApplication):
    app.setStyleSheet(DARK_THEME)