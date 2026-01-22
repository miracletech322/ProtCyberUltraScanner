import os
from pathlib import Path
from PySide6.QtCore import Qt, QFile, QTextStream
from PySide6.QtWidgets import QApplication, QWidget
from PySide6.QtGui import QIcon

from ui_frontwindow import Ui_FrontWindow

class FrontWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.ui = Ui_FrontWindow()
        self.ui.setupUi(self)
        self.main_window = None  # Will be set by MainWindow
        self.setup_toggle_buttons()
        self.setup_button_icons()
        self.setup_input_focus()
        self.setup_setting_button()
        self.load_stylesheet()
    
    def setup_toggle_buttons(self):
        """Configure btnURL and btnHTTP as toggle buttons"""
        # Make buttons checkable (toggle buttons)
        self.ui.btnURL.setCheckable(True)
        self.ui.btnHTTP.setCheckable(True)
        
        # Set default visibility: cmbRequest hidden, btnTool visible, widgetContent hidden (URL mode by default)
        self.ui.cmbRequest.setVisible(False)
        self.ui.btnTool.setVisible(True)
        self.ui.widgetContent.setVisible(False)
        
        # Set btnURL as checked by default
        self.ui.btnURL.setChecked(True)
        
        # Connect buttons to ensure only one is checked at a time
        self.ui.btnURL.toggled.connect(self.on_url_toggled)
        self.ui.btnHTTP.toggled.connect(self.on_http_toggled)
    
    def on_url_toggled(self, checked):
        """Handle URL button toggle"""
        if checked:
            self.ui.btnHTTP.setChecked(False)
            # URL active: cmbRequest hidden, btnTool visible, widgetContent hidden
            self.ui.cmbRequest.setVisible(False)
            self.ui.btnTool.setVisible(True)
            self.ui.widgetContent.setVisible(False)
        elif not self.ui.btnHTTP.isChecked():
            # If URL is unchecked and HTTP is also unchecked, keep URL checked
            self.ui.btnURL.setChecked(True)
    
    def on_http_toggled(self, checked):
        """Handle HTTP button toggle"""
        if checked:
            self.ui.btnURL.setChecked(False)
            # HTTP active: cmbRequest visible, btnTool hidden, widgetContent visible
            self.ui.cmbRequest.setVisible(True)
            self.ui.btnTool.setVisible(False)
            self.ui.widgetContent.setVisible(True)
        elif not self.ui.btnURL.isChecked():
            # If HTTP is unchecked and URL is also unchecked, keep HTTP checked
            self.ui.btnHTTP.setChecked(True)
    
    def setup_button_icons(self):
        """Set icons for buttons"""
        # Set settings icon for btnSetting
        self.ui.btnSetting.setIcon(QIcon(":/Resources/settings.png"))
        self.ui.btnSetting.setText("")  # Remove text, use icon only
        
        # Set tool icon for btnTool
        self.ui.btnTool.setIcon(QIcon(":/Resources/tool.png"))
    
    def setup_setting_button(self):
        """Setup setting button to show SettingWindow"""
        self.ui.btnSetting.clicked.connect(self.on_setting_clicked)
    
    def on_setting_clicked(self):
        """Handle setting button click - show SettingWindow in MDI area"""
        if self.main_window:
            self.main_window.show_settingwindow()
    
    def setup_input_focus(self):
        """Setup focus handling for input field to update widgetInput border"""
        # Connect focus signals to update widgetInput border color
        self.ui.edtURL.focusInEvent = lambda e: self._handle_focus_in(e)
        self.ui.edtURL.focusOutEvent = lambda e: self._handle_focus_out(e)
    
    def _handle_focus_in(self, event):
        """Handle focus in - change border to green"""
        from PySide6.QtWidgets import QLineEdit
        QLineEdit.focusInEvent(self.ui.edtURL, event)
        # Set property to trigger green border style
        self.ui.widgetInput.setProperty("hasFocus", True)
        self.ui.widgetInput.style().unpolish(self.ui.widgetInput)
        self.ui.widgetInput.style().polish(self.ui.widgetInput)
    
    def _handle_focus_out(self, event):
        """Handle focus out - change border back to gray"""
        from PySide6.QtWidgets import QLineEdit
        QLineEdit.focusOutEvent(self.ui.edtURL, event)
        # Remove property to trigger gray border style
        self.ui.widgetInput.setProperty("hasFocus", False)
        self.ui.widgetInput.style().unpolish(self.ui.widgetInput)
        self.ui.widgetInput.style().polish(self.ui.widgetInput)
    
    def load_stylesheet(self):
        file = QFile(":/Resources/frontwindow.qss")
        if file.open(QFile.ReadOnly | QFile.Text):
            stream = QTextStream(file)
            stylesheet = stream.readAll()
            self.setStyleSheet(stylesheet)
            file.close()
