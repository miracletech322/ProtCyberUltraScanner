import json
import os
from PySide6.QtCore import QFile, QTextStream
from PySide6.QtWidgets import QWidget
from ui_settingwindow import Ui_SettingWindow

class SettingWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = Ui_SettingWindow()
        self.ui.setupUi(self)
        self.main_window = None  # Will be set by MainWindow
        self.settings_file = os.path.join(os.path.dirname(__file__), "settings.json")
        self._loading_settings = False  # Flag to prevent saving during load
        self.setup_tab_widget()
        self.setup_toggle_buttons()
        self.setup_back_button()
        self.setup_advanced_settings()
        self.setup_proxy_radio_buttons()
        self.setup_proxy_settings_save()
        self.load_settings()
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
    
    def setup_proxy_radio_buttons(self):
        """Setup proxy radio buttons to enable/disable proxy fields"""
        # Connect all proxy radio buttons to the handler
        self.ui.radProSystemProxy.toggled.connect(self.on_proxy_radio_toggled)
        self.ui.radProNoProxy.toggled.connect(self.on_proxy_radio_toggled)
        self.ui.radProHTTP.toggled.connect(self.on_proxy_radio_toggled)
        self.ui.radProSOCKS.toggled.connect(self.on_proxy_radio_toggled)
        
        # Set initial state (radProSystemProxy is checked by default, so fields should be disabled)
        self.on_proxy_radio_toggled()
    
    def on_proxy_radio_toggled(self):
        """Handle proxy radio button toggle - enable/disable proxy fields"""
        # If System Proxy or No Proxy is selected, disable the fields
        # Otherwise (HTTP or SOCKS), enable them
        if self.ui.radProSystemProxy.isChecked() or self.ui.radProNoProxy.isChecked():
            self.ui.edtProIP.setEnabled(False)
            self.ui.spnProPort.setEnabled(False)
            self.ui.edtProUsername.setEnabled(False)
            self.ui.edtProPassword.setEnabled(False)
        else:
            self.ui.edtProIP.setEnabled(True)
            self.ui.spnProPort.setEnabled(True)
            self.ui.edtProUsername.setEnabled(True)
            self.ui.edtProPassword.setEnabled(True)
    
    def setup_proxy_settings_save(self):
        """Connect proxy field changes to save settings automatically"""
        self.ui.edtProIP.textChanged.connect(self.save_proxy_settings)
        self.ui.spnProPort.valueChanged.connect(self.save_proxy_settings)
        self.ui.edtProUsername.textChanged.connect(self.save_proxy_settings)
        self.ui.edtProPassword.textChanged.connect(self.save_proxy_settings)
        # Also save when radio buttons change
        self.ui.radProSystemProxy.toggled.connect(self.save_proxy_settings)
        self.ui.radProNoProxy.toggled.connect(self.save_proxy_settings)
        self.ui.radProHTTP.toggled.connect(self.save_proxy_settings)
        self.ui.radProSOCKS.toggled.connect(self.save_proxy_settings)
    
    def save_proxy_settings(self):
        """Save proxy settings to JSON file"""
        # Don't save during loading
        if self._loading_settings:
            return
        
        settings = self.load_all_settings()
        
        # Determine which proxy type is selected
        proxy_type = "system"
        if self.ui.radProNoProxy.isChecked():
            proxy_type = "none"
        elif self.ui.radProHTTP.isChecked():
            proxy_type = "http"
        elif self.ui.radProSOCKS.isChecked():
            proxy_type = "socks"
        
        # Update proxy settings
        settings["proxy"] = {
            "type": proxy_type,
            "ip": self.ui.edtProIP.text(),
            "port": self.ui.spnProPort.value(),
            "username": self.ui.edtProUsername.text(),
            "password": self.ui.edtProPassword.text()
        }
        
        self.save_all_settings(settings)
    
    def load_settings(self):
        """Load all settings from JSON file"""
        self._loading_settings = True
        settings = self.load_all_settings()
        
        # Load proxy settings
        if "proxy" in settings:
            proxy_settings = settings["proxy"]
            
            # Set proxy type
            proxy_type = proxy_settings.get("type", "system")
            if proxy_type == "none":
                self.ui.radProNoProxy.setChecked(True)
            elif proxy_type == "http":
                self.ui.radProHTTP.setChecked(True)
            elif proxy_type == "socks":
                self.ui.radProSOCKS.setChecked(True)
            else:
                self.ui.radProSystemProxy.setChecked(True)
            
            # Load proxy field values
            self.ui.edtProIP.setText(proxy_settings.get("ip", ""))
            self.ui.spnProPort.setValue(proxy_settings.get("port", 0))
            self.ui.edtProUsername.setText(proxy_settings.get("username", ""))
            self.ui.edtProPassword.setText(proxy_settings.get("password", ""))
            
            # Update enabled state based on proxy type
            self.on_proxy_radio_toggled()
        
        # TODO: Add loading for other tab settings here as needed
        
        self._loading_settings = False
    
    def load_all_settings(self):
        """Load all settings from JSON file, return default dict if file doesn't exist"""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}
    
    def save_all_settings(self, settings):
        """Save all settings to JSON file"""
        try:
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=4, ensure_ascii=False)
        except IOError:
            pass  # Silently fail if we can't write the file
    
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