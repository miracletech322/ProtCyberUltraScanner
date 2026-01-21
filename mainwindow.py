from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QMdiSubWindow
from ui_mainwindow import Ui_MainWindow
from frontwindow import FrontWindow
from settingwindow import SettingWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        
        # Show frontwindow in mdiArea by default
        self.show_frontwindow()
    
    def show_frontwindow(self):
        """Create and show FrontWindow in the MDI area"""
        front_window = FrontWindow(self)
        # Pass reference to MainWindow so FrontWindow can show SettingWindow
        front_window.main_window = self
        sub_window = QMdiSubWindow()
        sub_window.setWidget(front_window)
        sub_window.setWindowFlags(Qt.FramelessWindowHint)
        self.ui.mdiArea.addSubWindow(sub_window)
        sub_window.showMaximized()
    
    def show_settingwindow(self):
        """Create and show SettingWindow in the MDI area"""
        setting_window = SettingWindow()
        sub_window = QMdiSubWindow()
        sub_window.setWidget(setting_window)
        sub_window.setWindowFlags(Qt.FramelessWindowHint)
        self.ui.mdiArea.addSubWindow(sub_window)
        sub_window.show()
