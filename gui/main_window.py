"""
PyQt main application shell and navigation layout.
"""

#import sys
#from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QStackedWidget, QLabel
#from gui.views.module_browser_view import ModuleBrowserView
import sys

from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QStackedWidget,
    QWidget,
)

from gui.views.module_browser_view import ModuleBrowserView
class MainWindow(QMainWindow):
    """Main application shell window for SentryPack Desktop GUI."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SentryPack Platform")
        self.resize(1100, 700)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout(main_widget)

        self.sidebar = QListWidget()
        self.sidebar.addItem("Projects")
        self.sidebar.addItem("Host Graph")
        self.sidebar.addItem("Module Browser")
        self.sidebar.addItem("Console Output")
        self.sidebar.addItem("C2 Sessions")
        self.sidebar.addItem("Connection Analyser")
        self.sidebar.addItem("Findings")
        self.sidebar.addItem("Settings")
        self.sidebar.setFixedWidth(200)

        self.views_stack = QStackedWidget()
        self.views_stack.addWidget(QLabel("Projects View Placeholder"))
        self.views_stack.addWidget(QLabel("Host Graph View Placeholder"))
        #self.views_stack.addWidget(QLabel("Module Browser View Placeholder"))
        self.views_stack.addWidget(ModuleBrowserView())#edited on alazar branch
        self.views_stack.addWidget(QLabel("Console Output View Placeholder"))
        self.views_stack.addWidget(QLabel("C2 Sessions View Placeholder"))
        self.views_stack.addWidget(QLabel("Connection Analyser View Placeholder"))
        self.views_stack.addWidget(QLabel("Findings View Placeholder"))
        self.views_stack.addWidget(QLabel("Settings View Placeholder"))

        self.sidebar.currentRowChanged.connect(self.views_stack.setCurrentIndex)
        layout.addWidget(self.sidebar)
        layout.addWidget(self.views_stack)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
