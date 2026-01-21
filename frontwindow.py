import os
from pathlib import Path
from PySide6.QtCore import Qt, QFile, QTextStream
from PySide6.QtWidgets import QApplication, QWidget

from ui_frontwindow import Ui_FrontWindow

class FrontWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.ui = Ui_FrontWindow()
        self.ui.setupUi(self)
        self.load_stylesheet()
    
    def load_stylesheet(self):
        file = QFile(":/Resources/frontwindow.qss")
        if file.open(QFile.ReadOnly | QFile.Text):
            stream = QTextStream(file)
            stylesheet = stream.readAll()
            self.setStyleSheet(stylesheet)
            file.close()
