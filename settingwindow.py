from PySide6.QtCore import QFile, QTextStream
from PySide6.QtWidgets import QWidget
from ui_settingwindow import Ui_SettingWindow

class SettingWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = Ui_SettingWindow()
        self.ui.setupUi(self)
        self.main_window = None  # Will be set by MainWindow
        self.setup_tab_widget()
        self.setup_toggle_buttons()
        self.setup_back_button()
        self.setup_advanced_settings()
        self.load_stylesheet()
    
    def setup_toggle_buttons(self):
        """Configure navigation buttons as toggle buttons"""
        # Make all navigation buttons checkable
        buttons = [
            self.ui.btnTests,
            self.ui.btnProxy,
            self.ui.btnAuthentication,
            self.ui.btnHTTP,
            self.ui.btnCrawler,
            self.ui.btnFormInputs,
            self.ui.btnTestVectors,
            self.ui.btnTechnologies
        ]
        
        for button in buttons:
            button.setCheckable(True)
            button.toggled.connect(lambda checked, btn=button: self.on_button_toggled(btn, checked))
        
        # Set btnTests as checked by default
        self.ui.btnTests.setChecked(True)
        
        # Set initial visibility: show basic buttons, hide advanced buttons
        self.ui.btnTests.setVisible(True)
        self.ui.btnProxy.setVisible(True)
        self.ui.btnAuthentication.setVisible(True)
        
        self.ui.btnHTTP.setVisible(False)
        self.ui.btnCrawler.setVisible(False)
        self.ui.btnFormInputs.setVisible(False)
        self.ui.btnTestVectors.setVisible(False)
        self.ui.btnTechnologies.setVisible(False)
    
    def on_button_toggled(self, button, checked):
        """Handle button toggle - ensure only one is checked at a time"""
        if checked:
            # Uncheck all other buttons
            buttons = [
                self.ui.btnTests,
                self.ui.btnProxy,
                self.ui.btnAuthentication,
                self.ui.btnHTTP,
                self.ui.btnCrawler,
                self.ui.btnFormInputs,
                self.ui.btnTestVectors,
                self.ui.btnTechnologies
            ]
            for btn in buttons:
                if btn != button:
                    btn.setChecked(False)
            
            # Switch to corresponding tab
            tab_map = {
                self.ui.btnTests: 0,
                self.ui.btnProxy: 1,
                self.ui.btnAuthentication: 2,
                self.ui.btnHTTP: 3,
                self.ui.btnCrawler: 4,
                self.ui.btnFormInputs: 5,
                self.ui.btnTestVectors: 6,
                self.ui.btnTechnologies: 7
            }
            if button in tab_map:
                self.ui.tabWidget.setCurrentIndex(tab_map[button])
        else:
            # If unchecked and no other button is checked, keep this one checked
            buttons = [
                self.ui.btnTests,
                self.ui.btnProxy,
                self.ui.btnAuthentication,
                self.ui.btnHTTP,
                self.ui.btnCrawler,
                self.ui.btnFormInputs,
                self.ui.btnTestVectors,
                self.ui.btnTechnologies
            ]
            if not any(btn.isChecked() for btn in buttons):
                button.setChecked(True)
    
    def setup_tab_widget(self):
        """Setup tab widget - hide the header bar"""
        self.ui.tabWidget.tabBar().setVisible(False)
    
    def setup_back_button(self):
        """Setup back button to close settingwindow and show frontwindow"""
        self.ui.btnBack.clicked.connect(self.on_back_clicked)
    
    def setup_advanced_settings(self):
        """Setup advanced settings checkbox to show/hide advanced buttons"""
        self.ui.checkAdvancedSettings.toggled.connect(self.on_advanced_settings_toggled)
    
    def on_advanced_settings_toggled(self, checked):
        """Handle advanced settings checkbox toggle"""
        # Show/hide advanced buttons based on checkbox state
        self.ui.btnHTTP.setVisible(checked)
        self.ui.btnCrawler.setVisible(checked)
        self.ui.btnFormInputs.setVisible(checked)
        self.ui.btnTestVectors.setVisible(checked)
        self.ui.btnTechnologies.setVisible(checked)
    
    def on_back_clicked(self):
        """Handle back button click - close settingwindow and show frontwindow"""
        if self.main_window:
            self.main_window.close_settingwindow_and_show_frontwindow()
    
    def load_stylesheet(self):
        """Load and apply the settingwindow.qss stylesheet"""
        file = QFile(":/Resources/settingwindow.qss")
        if file.open(QFile.ReadOnly | QFile.Text):
            stream = QTextStream(file)
            stylesheet = stream.readAll()
            self.setStyleSheet(stylesheet)
            file.close()