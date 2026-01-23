from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QMdiSubWindow
from ui_mainwindow import Ui_MainWindow
from frontwindow import FrontWindow
from settingwindow import SettingWindow
from scanwindow import ScanWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        
        # Store references to subwindows
        self.frontwindow_subwindow = None
        self.settingwindow_subwindow = None
        self.scanwindow_subwindow = None
        
        # Show frontwindow in mdiArea by default
        self.show_frontwindow()
    
    def show_frontwindow(self):
        """Create and show FrontWindow in the MDI area"""
        # Only create if it doesn't exist
        if self.frontwindow_subwindow is None:
            front_window = FrontWindow(self)
            # Pass reference to MainWindow so FrontWindow can show SettingWindow
            front_window.main_window = self
            sub_window = QMdiSubWindow()
            sub_window.setWidget(front_window)
            sub_window.setWindowFlags(Qt.FramelessWindowHint)
            self.ui.mdiArea.addSubWindow(sub_window)
            self.frontwindow_subwindow = sub_window
            # Prevent frontwindow from being closed - override closeEvent
            def prevent_close(event):
                event.ignore()
            sub_window.closeEvent = prevent_close
            sub_window.showMaximized()
        else:
            # If it exists, just show it
            self.frontwindow_subwindow.showMaximized()
            self.ui.mdiArea.setActiveSubWindow(self.frontwindow_subwindow)
    
    def show_settingwindow(self):
        """Create and show SettingWindow in the MDI area"""
        # Only create if it doesn't exist
        if self.settingwindow_subwindow is None:
            setting_window = SettingWindow()
            # Pass reference to MainWindow so SettingWindow can close itself and show frontwindow
            setting_window.main_window = self
            sub_window = QMdiSubWindow()
            sub_window.setWidget(setting_window)
            sub_window.setWindowFlags(Qt.FramelessWindowHint)
            self.ui.mdiArea.addSubWindow(sub_window)
            self.settingwindow_subwindow = sub_window
            # Connect close event to clear reference
            sub_window.destroyed.connect(lambda: setattr(self, 'settingwindow_subwindow', None))
            sub_window.showMaximized()
            self.ui.mdiArea.setActiveSubWindow(sub_window)
        else:
            # If it exists, just show it
            self.settingwindow_subwindow.showMaximized()
            self.ui.mdiArea.setActiveSubWindow(self.settingwindow_subwindow)
    
    def show_scanwindow(self, url=None, method=None, header_name=None, header_value=None, body=None):
        """Create and show ScanWindow in the MDI area"""
        # Close existing scanwindow if it exists to start a new scan
        if self.scanwindow_subwindow is not None:
            self.scanwindow_subwindow.close()
            self.scanwindow_subwindow = None
        
        # Create new scan window with parameters
        scan_window = ScanWindow(url=url, method=method, header_name=header_name, header_value=header_value, body=body)
        sub_window = QMdiSubWindow()
        sub_window.setWidget(scan_window)
        sub_window.setWindowFlags(Qt.FramelessWindowHint)
        self.ui.mdiArea.addSubWindow(sub_window)
        self.scanwindow_subwindow = sub_window
        # Connect close event to clear reference
        sub_window.destroyed.connect(lambda: setattr(self, 'scanwindow_subwindow', None))
        sub_window.showMaximized()
        self.ui.mdiArea.setActiveSubWindow(sub_window)
    
    def close_settingwindow_and_show_frontwindow(self):
        """Close settingwindow and show frontwindow"""
        if self.settingwindow_subwindow:
            self.settingwindow_subwindow.close()
            self.settingwindow_subwindow = None
        
        # Show frontwindow
        if self.frontwindow_subwindow:
            self.frontwindow_subwindow.showMaximized()
            self.ui.mdiArea.setActiveSubWindow(self.frontwindow_subwindow)
