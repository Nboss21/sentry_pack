"""
PyQt main application shell and navigation layout.
"""

#import sys
#from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QStackedWidget, QLabel
#from gui.views.module_browser_view import ModuleBrowserView
import sys
from gui.views.live_console_view import LiveConsoleView
from gui.views.projects_view import ProjectsView
from gui.views.host_graph_view import HostGraphView
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QStackedWidget,
    QWidget,
)
#from gui.views.target_detail_view import TargetDetailView
from gui.views.module_browser_view import ModuleBrowserView
from gui.views.target_detail_view import TargetDetailView
from gui.views.listeners_view import ListenersView
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
        self.sidebar.addItem("C2 Listeners")
        self.sidebar.addItem("C2 Sessions")
        self.sidebar.addItem("Connection Analyser")
        self.sidebar.addItem("Findings")
        self.sidebar.addItem("Settings")
        self.sidebar.setFixedWidth(200)

        self.views_stack = QStackedWidget()
        #self.views_stack.addWidget(QLabel("Projects View Placeholder"))
        self.projects_view = ProjectsView()
        self.views_stack.addWidget(self.projects_view)
        # self.target_detail_view = TargetDetailView()
        # self.views_stack.addWidget(self.target_detail_view)
        #self.views_stack.addWidget(QLabel("Host Graph View Placeholder"))
        
        # self.host_graph_view = HostGraphView()
        # self.views_stack.addWidget(self.host_graph_view)
        # self.projects_view.project_selected.connect(
        #     self.host_graph_view.set_project
        # )
        # self.target_detail_view = TargetDetailView()
        host_graph_container = QWidget()
        host_graph_layout = QHBoxLayout(host_graph_container)

        self.host_graph_view = HostGraphView()
        self.projects_view.project_selected.connect(
                    self.host_graph_view.set_project
                )
        self.target_detail_view = TargetDetailView()

        host_graph_layout.addWidget(self.host_graph_view, 2)
        host_graph_layout.addWidget(self.target_detail_view, 1)
        self.host_graph_view.target_selected.connect(
        self.target_detail_view.set_target
    )
        self.views_stack.addWidget(host_graph_container)
        #self.views_stack.addWidget(QLabel("Module Browser View Placeholder"))
        self.views_stack.addWidget(ModuleBrowserView())#edited on alazar branch
        #self.views_stack.addWidget(QLabel("Console Output View Placeholder"))
        self.live_console_view = LiveConsoleView()
        self.views_stack.addWidget(self.live_console_view)

        self.listeners_view = ListenersView()
        self.views_stack.addWidget(self.listeners_view)
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
