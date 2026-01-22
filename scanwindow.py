from PySide6.QtWidgets import QWidget
from ui_scanwindow import Ui_ScanWindow

class ScanWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = Ui_ScanWindow()
        self.ui.setupUi(self)