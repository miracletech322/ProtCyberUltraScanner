import json
import os
from PySide6.QtCore import QFile, QTextStream
from PySide6.QtWidgets import QWidget, QMessageBox, QTableWidgetItem, QAbstractItemView
from ui_settingwindow import Ui_SettingWindow

class SettingWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = Ui_SettingWindow()
        self.ui.setupUi(self)
        self.main_window = None  # Will be set by MainWindow
        self.settings_file = os.path.join(os.path.dirname(__file__), "settings.json")
        self._loading_settings = False  # Flag to prevent saving during load
        self.ui.tableTech.verticalHeader().setVisible(False)
        self.ui.tableTech.setColumnWidth(0, 250)
        self.ui.tableTech.setColumnWidth(1, 500)
        self.setup_tab_widget()
        self.setup_toggle_buttons()
        self.setup_back_button()
        self.setup_advanced_settings()
        self.setup_proxy_radio_buttons()
        self.setup_proxy_settings_save()
        self.setup_authentication_checkboxes()
        self.setup_authentication_settings_save()
        self.setup_http_defaults()
        self.setup_http_settings_save()
        self.setup_crawler_defaults()
        self.setup_crawler_checkboxes()
        self.setup_crawler_settings_save()
        self.setup_form_inputs_settings_save()
        self.setup_test_vectors_defaults()
        self.setup_test_vectors_settings_save()
        self.setup_technologies_table()
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
    
    def setup_authentication_checkboxes(self):
        """Setup authentication checkboxes to enable/disable authentication fields"""
        # Set initial state: all fields disabled by default
        self.ui.edtAuthUsername.setEnabled(False)
        self.ui.edtAuthPassword.setEnabled(False)
        self.ui.btnAuthLogin.setEnabled(False)
        
        # Connect checkAuthHTTP to enable/disable username and password fields
        self.ui.checkAuthHTTP.toggled.connect(self.on_auth_http_toggled)
        
        # Connect checkAuthManual to enable/disable login button
        self.ui.checkAuthManual.toggled.connect(self.on_auth_manual_toggled)
        
        # Set initial state based on checkbox states
        self.on_auth_http_toggled()
        self.on_auth_manual_toggled()
    
    def on_auth_http_toggled(self):
        """Handle checkAuthHTTP toggle - enable/disable username and password fields"""
        checked = self.ui.checkAuthHTTP.isChecked()
        self.ui.edtAuthUsername.setEnabled(checked)
        self.ui.edtAuthPassword.setEnabled(checked)
    
    def on_auth_manual_toggled(self):
        """Handle checkAuthManual toggle - enable/disable login button"""
        checked = self.ui.checkAuthManual.isChecked()
        self.ui.btnAuthLogin.setEnabled(checked)
    
    def setup_authentication_settings_save(self):
        """Connect authentication field changes to save settings automatically"""
        self.ui.edtAuthUsername.textChanged.connect(self.save_authentication_settings)
        self.ui.edtAuthPassword.textChanged.connect(self.save_authentication_settings)
        # Also save when checkboxes change
        self.ui.checkAuthHTTP.toggled.connect(self.save_authentication_settings)
        self.ui.checkAuthManual.toggled.connect(self.save_authentication_settings)
    
    def save_authentication_settings(self):
        """Save authentication settings to JSON file"""
        # Don't save during loading
        if self._loading_settings:
            return
        
        settings = self.load_all_settings()
        
        # Update authentication settings
        settings["authentication"] = {
            "http_enabled": self.ui.checkAuthHTTP.isChecked(),
            "manual_enabled": self.ui.checkAuthManual.isChecked(),
            "username": self.ui.edtAuthUsername.text(),
            "password": self.ui.edtAuthPassword.text()
        }
        
        self.save_all_settings(settings)
    
    def setup_http_defaults(self):
        """Set default values for HTTP tab fields"""
        # Set default values (will be overridden by load_settings if saved values exist)
        self.ui.spnHTimeout.setValue(60)
        self.ui.spnHParallel.setValue(4)
        self.ui.spnHMaxRequest.setValue(5)
        self.ui.edtHUserAgent.setText("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.3")
        self.ui.edtAdditionalCookies.setPlainText("")
        self.ui.edtAdditionalHTTP.setPlainText("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\nAccept-Language: en-US,en;q=0.5")
    
    def setup_http_settings_save(self):
        """Connect HTTP field changes to save settings automatically"""
        self.ui.spnHTimeout.valueChanged.connect(self.save_http_settings)
        self.ui.spnHParallel.valueChanged.connect(self.save_http_settings)
        self.ui.spnHMaxRequest.valueChanged.connect(self.save_http_settings)
        self.ui.edtHUserAgent.textChanged.connect(self.save_http_settings)
        self.ui.edtAdditionalCookies.textChanged.connect(self.save_http_settings)
        self.ui.edtAdditionalHTTP.textChanged.connect(self.save_http_settings)
    
    def save_http_settings(self):
        """Save HTTP settings to JSON file"""
        # Don't save during loading
        if self._loading_settings:
            return
        
        settings = self.load_all_settings()
        
        # Update HTTP settings
        settings["http"] = {
            "timeout": self.ui.spnHTimeout.value(),
            "parallel": self.ui.spnHParallel.value(),
            "max_request": self.ui.spnHMaxRequest.value(),
            "user_agent": self.ui.edtHUserAgent.text(),
            "additional_cookies": self.ui.edtAdditionalCookies.toPlainText(),
            "additional_http": self.ui.edtAdditionalHTTP.toPlainText()
        }
        
        self.save_all_settings(settings)
    
    def setup_crawler_defaults(self):
        """Set default values for Crawler tab fields"""
        # Set default values (will be overridden by load_settings if saved values exist)
        self.ui.spnCMaxDepth.setValue(5)
        self.ui.spnCMaxCount.setValue(70000)
        self.ui.edtCFileExclution.setText("*.7z,*.a3c,*.a52,*.aac,*.ac3,*.ace,*.acsm,*.am,*.apk,*.asf,*.asx,*.avi,*.azw3,*.azw4,*.bin,*.bmp,*.bz2,*.cab,*.cmd,*.conf,*.css,*.csv,*.divx,*.djvu,*.doc,*.docx,*.dts,*.dv,*.engine,*.eot,*.eps,*.epub,*.exe,*.fla,*.flac,*.flv,*.fvi,*.gif,*.gxf,*.gz,*.ice,*.ico,*.inc,*.info,*.install,*.iso,*.jar,*.jpe,*.jpeg,*.jpg,*.lang,*.m1v,*.m2ts,*.m2v,*.m4a,*.m4p,*.m4v,*.mdb,*.mid,*.midi,*.mka,*.mkv,*.mod,*.mov,*.movie,*.mp,*.mp1,*.mp2,*.mp3,*.mp4,*.mpeg,*.mpeg1,*.mpeg2,*.mpeg4,*.mpg,*.mpga,*.mpp,*.mpt,*.msi,*.mts,*.mtv,*.mxf,*.oga,*.ogg,*.ogm,*.ogv,*.ogx,*.oma,*.opus,*.pac,*.pcx,*.pdf,*.pgm,*.png,*.ppsx,*.ppt,*.pptx,*.profile,*.ps,*.psd,*.ram,*.rar,*.rb,*.res,*.rmf,*.rpm,*.save,*.scss,*.sh,*.spx,*.sql,*.svg,*.svn-base,*.svn-work,*.swf,*.tar,*.tbz2,*.tgz,*.tif,*.tiff,*.ts,*.tta,*.ttf,*.uff,*.vob,*.vox,*.vro,*.wav,*.wbmp,*.webm,*.wma,*.wmv,*.woff,*.xls,*.xlsx,*.xm,*.zip,*.abw,*.arc,*.azw,*.bz,*.csh,*.ics,*.mpkg,*.odp,*.ods,*.odt,*.otf,*.rtf,*.txt,*.vsd,*.weba,*.webp,*.woff2,*.xul,*.3gp,*.3g2,*.xcf,*.map")
        self.ui.edtCURLExclution.setPlainText("*sign?out*\n*log?out*\n*exit*\n*kill*\n*delete*\n*remove*\n*/.svn/+\n*/.git/+\n*/phpMyAdmin/+\n*/pgadmin/+\n*/roundcube/+\n*/%/%/%/%/%/%/%/%/%/%/%/%")
    
    def setup_crawler_checkboxes(self):
        """Setup crawler checkboxes to enable/disable crawler fields"""
        # Set checkboxes to checked by default
        self.ui.checkCMaxDepth.setChecked(True)
        self.ui.checkCMaxCount.setChecked(True)
        self.ui.checkCFileExclution.setChecked(True)
        self.ui.checkCEvaluate.setChecked(True)
        
        # Connect checkboxes to enable/disable fields
        self.ui.checkCMaxDepth.toggled.connect(self.on_crawler_max_depth_toggled)
        self.ui.checkCMaxCount.toggled.connect(self.on_crawler_max_count_toggled)
        self.ui.checkCFileExclution.toggled.connect(self.on_crawler_file_exclusion_toggled)
        
        # Connect scope combo box to handle visibility
        self.ui.cmbCScope.currentIndexChanged.connect(self.on_crawler_scope_changed)
        
        # Set initial state based on checkbox states
        self.on_crawler_max_depth_toggled()
        self.on_crawler_max_count_toggled()
        self.on_crawler_file_exclusion_toggled()
        self.on_crawler_scope_changed()
    
    def on_crawler_max_depth_toggled(self):
        """Handle checkCMaxDepth toggle - enable/disable max depth field"""
        checked = self.ui.checkCMaxDepth.isChecked()
        self.ui.spnCMaxDepth.setEnabled(checked)
    
    def on_crawler_max_count_toggled(self):
        """Handle checkCMaxCount toggle - enable/disable max count field"""
        checked = self.ui.checkCMaxCount.isChecked()
        self.ui.spnCMaxCount.setEnabled(checked)
    
    def on_crawler_file_exclusion_toggled(self):
        """Handle checkCFileExclution toggle - enable/disable file exclusion field"""
        checked = self.ui.checkCFileExclution.isChecked()
        self.ui.edtCFileExclution.setEnabled(checked)
    
    def on_crawler_scope_changed(self):
        """Handle cmbCScope change - show/hide fields based on scope selection"""
        scope_text = self.ui.cmbCScope.currentText()
        is_smart = (scope_text == "Smart")
        
        # When Smart is selected: show checkboxes, hide regex fields
        # When Manual is selected: hide checkboxes, show regex fields
        self.ui.checkCScanSubDomain.setVisible(is_smart)
        self.ui.checkCScanTargetURL.setVisible(is_smart)
        self.ui.labelCScopeRegex.setVisible(not is_smart)
        self.ui.edtCScopeRegex.setVisible(not is_smart)
    
    def setup_crawler_settings_save(self):
        """Connect crawler field changes to save settings automatically"""
        self.ui.spnCMaxDepth.valueChanged.connect(self.save_crawler_settings)
        self.ui.spnCMaxCount.valueChanged.connect(self.save_crawler_settings)
        self.ui.edtCFileExclution.textChanged.connect(self.save_crawler_settings)
        self.ui.edtCURLExclution.textChanged.connect(self.save_crawler_settings)
        self.ui.edtCScopeRegex.textChanged.connect(self.save_crawler_settings)
        # Also save when checkboxes change
        self.ui.checkCMaxDepth.toggled.connect(self.save_crawler_settings)
        self.ui.checkCMaxCount.toggled.connect(self.save_crawler_settings)
        self.ui.checkCFileExclution.toggled.connect(self.save_crawler_settings)
        self.ui.checkCEvaluate.toggled.connect(self.save_crawler_settings)
        self.ui.checkCScanSubDomain.toggled.connect(self.save_crawler_settings)
        self.ui.checkCScanTargetURL.toggled.connect(self.save_crawler_settings)
        # Note: cmbCScope.currentIndexChanged is connected in setup_crawler_checkboxes for visibility
        # We also need to save when scope changes - connect to save (both handlers will be called)
        self.ui.cmbCScope.currentIndexChanged.connect(self.save_crawler_settings)
    
    def save_crawler_settings(self):
        """Save crawler settings to JSON file"""
        # Don't save during loading
        if self._loading_settings:
            return
        
        settings = self.load_all_settings()
        
        # Update crawler settings
        settings["crawler"] = {
            "max_depth_enabled": self.ui.checkCMaxDepth.isChecked(),
            "max_depth": self.ui.spnCMaxDepth.value(),
            "max_count_enabled": self.ui.checkCMaxCount.isChecked(),
            "max_count": self.ui.spnCMaxCount.value(),
            "file_exclusion_enabled": self.ui.checkCFileExclution.isChecked(),
            "file_exclusion": self.ui.edtCFileExclution.text(),
            "evaluate_enabled": self.ui.checkCEvaluate.isChecked(),
            "url_exclusion": self.ui.edtCURLExclution.toPlainText(),
            "scan_subdomain": self.ui.checkCScanSubDomain.isChecked(),
            "scan_target_url": self.ui.checkCScanTargetURL.isChecked(),
            "scope": self.ui.cmbCScope.currentText(),
            "scope_regex": self.ui.edtCScopeRegex.text()
        }
        
        self.save_all_settings(settings)
    
    def setup_form_inputs_settings_save(self):
        """Connect form input field changes to save settings automatically"""
        self.ui.edtFUsername.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFPassword.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFEmail.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFFirstName.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFLastName.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFAddress.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFCity.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFState.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFZip.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFCountry.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFCompany.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFPhone.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFDay.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFMonth.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFYear.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFAge.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFPrefix.textChanged.connect(self.save_form_inputs_settings)
        self.ui.edtFLanguage.textChanged.connect(self.save_form_inputs_settings)
    
    def save_form_inputs_settings(self):
        """Save form inputs settings to JSON file"""
        # Don't save during loading
        if self._loading_settings:
            return
        
        settings = self.load_all_settings()
        
        # Update form inputs settings
        settings["form_inputs"] = {
            "username": self.ui.edtFUsername.text(),
            "password": self.ui.edtFPassword.text(),
            "email": self.ui.edtFEmail.text(),
            "first_name": self.ui.edtFFirstName.text(),
            "last_name": self.ui.edtFLastName.text(),
            "address": self.ui.edtFAddress.text(),
            "city": self.ui.edtFCity.text(),
            "state": self.ui.edtFState.text(),
            "zip": self.ui.edtFZip.text(),
            "country": self.ui.edtFCountry.text(),
            "company": self.ui.edtFCompany.text(),
            "phone": self.ui.edtFPhone.text(),
            "day": self.ui.edtFDay.text(),
            "month": self.ui.edtFMonth.text(),
            "year": self.ui.edtFYear.text(),
            "age": self.ui.edtFAge.text(),
            "prefix": self.ui.edtFPrefix.text(),
            "language": self.ui.edtFLanguage.text()
        }
        
        self.save_all_settings(settings)
    
    def setup_test_vectors_defaults(self):
        """Set default value for Test Vectors tab edtTParameter field"""
        # Set default value (will be overridden by load_settings if saved value exists)
        default_parameter = "*;;PHPSESSID;;Any;;*\n*;;__VIEWSTATE;;Any;;*\n*;;__EVENTTARGET;;POST;;*\n*;;__EVENTARGUMENT;;POST;;*\n*;;__VIEWSTATEGENERATOR;;POST;;*\n*;;__EVENTVALIDATION;;POST;;*\n*;;__VIEWSTATEENCRYPTED;;POST;;*\n*;;__VSTATE;;Any;;*\n*;;__VIEWSTATEFIELDCOUNT;;Any;;*\n*;;__COMPRESSEDVIEWSTATE;;Any;;*\n*;;__ASYNCPOST;;POST;;*\n*;;SCROLLPOSITION?;;QUERY;;*\n*;;LASTFOCUS?;;QUERY;;*\n*;;utm*;;Any;;*\n*;;_ga;;Any;;*\n*;;_gat;;Any;;*\n*;;__utm*;;Any;;*\n*;;submit*;;POST;;*\n*;;submit*;;QUERY;;*\n*;;_javax.faces.ViewState;;POST;;*\n*;;_javax.faces.ViewState;;POST;;*\n*;;org.apache.struts.taglib.html.TOKEN;;POST;;*\n*;;jsessionid;;Any;;*\n*;;cfid;;COOKIE;;*\n*;;cftoken;;COOKIE;;*\n*;;ASP.NET_SessionId;;Any;;*\n*;;ASPSESSIONID*;;Any;;*\n*;;SITESERVER;;Any;;*\n*;;*csrf*;;Any;;*\n*;;*token*;;Any;;*\n*;;*nonce*;;Any;;*\n*;;*;;*;;COOKIE;;[md5]\n*;;*;;*;;COOKIE;;[guid]\n*;;*;;*;;PATH;;[year]\n*;;*;;*;;Any;;[base64]\n*[seo]*;;*;;*;;QUERY;;*\n*[non-english]*;;*;;*;;QUERY;;*\n*/;;*;;path;;*"
        self.ui.edtTParameter.setPlainText(default_parameter)
    
    def setup_test_vectors_settings_save(self):
        """Connect test vectors checkbox and field changes to save settings automatically"""
        self.ui.checkTGET.toggled.connect(self.save_test_vectors_settings)
        self.ui.checkTPOST.toggled.connect(self.save_test_vectors_settings)
        self.ui.checkTCookie.toggled.connect(self.save_test_vectors_settings)
        self.ui.checkTHeader.toggled.connect(self.save_test_vectors_settings)
        self.ui.checkTURLPath.toggled.connect(self.save_test_vectors_settings)
        self.ui.edtTParameter.textChanged.connect(self.save_test_vectors_settings)
    
    def save_test_vectors_settings(self):
        """Save test vectors settings to JSON file"""
        # Don't save during loading
        if self._loading_settings:
            return
        
        settings = self.load_all_settings()
        
        # Update test vectors settings
        settings["test_vectors"] = {
            "get_enabled": self.ui.checkTGET.isChecked(),
            "post_enabled": self.ui.checkTPOST.isChecked(),
            "cookie_enabled": self.ui.checkTCookie.isChecked(),
            "header_enabled": self.ui.checkTHeader.isChecked(),
            "url_path_enabled": self.ui.checkTURLPath.isChecked(),
            "parameter": self.ui.edtTParameter.toPlainText()
        }
        
        self.save_all_settings(settings)
    
    def setup_technologies_table(self):
        """Setup Technologies table add/delete functionality"""
        # Connect add button
        self.ui.btnTechAdd.clicked.connect(self.on_tech_add_clicked)
        
        # Connect delete button
        self.ui.btnTechDelete.clicked.connect(self.on_tech_delete_clicked)
        
        # Set table properties
        self.ui.tableTech.setColumnCount(2)
        self.ui.tableTech.setHorizontalHeaderLabels(["Type", "URL"])
        self.ui.tableTech.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.ui.tableTech.setSelectionMode(QAbstractItemView.SingleSelection)
    
    def on_tech_add_clicked(self):
        """Handle add button click - add row with cmbTech and edtTechURL values"""
        tech_type = self.ui.cmbTech.currentText()
        tech_url = self.ui.edtTechURL.text()
        
        # Validate that URL is not empty
        if not tech_url.strip():
            QMessageBox.warning(self, "Warning", "Please enter a URL.")
            return
        
        # Add row to table
        row_count = self.ui.tableTech.rowCount()
        self.ui.tableTech.insertRow(row_count)
        
        # Set items
        self.ui.tableTech.setItem(row_count, 0, QTableWidgetItem(tech_type))
        self.ui.tableTech.setItem(row_count, 1, QTableWidgetItem(tech_url))
        
        # Initialize (clear) cmbTech and edtTechURL
        self.ui.cmbTech.setCurrentIndex(0)  # Reset to first item
        self.ui.edtTechURL.clear()
        
        # Save settings
        self.save_technologies_settings()
    
    def on_tech_delete_clicked(self):
        """Handle delete button click - confirm and delete selected row"""
        current_row = self.ui.tableTech.currentRow()
        
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a row to delete.")
            return
        
        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            "Are you sure you want to delete this row?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.ui.tableTech.removeRow(current_row)
            # Save settings
            self.save_technologies_settings()
    
    def save_technologies_settings(self):
        """Save technologies table data to JSON file"""
        # Don't save during loading
        if self._loading_settings:
            return
        
        settings = self.load_all_settings()
        
        # Collect all rows from table
        technologies = []
        for row in range(self.ui.tableTech.rowCount()):
            tech_type_item = self.ui.tableTech.item(row, 0)
            tech_url_item = self.ui.tableTech.item(row, 1)
            
            if tech_type_item and tech_url_item:
                technologies.append({
                    "type": tech_type_item.text(),
                    "url": tech_url_item.text()
                })
        
        # Update technologies settings
        settings["technologies"] = technologies
        
        self.save_all_settings(settings)
    
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
        
        # Load authentication settings
        if "authentication" in settings:
            auth_settings = settings["authentication"]
            
            # Load checkbox states
            self.ui.checkAuthHTTP.setChecked(auth_settings.get("http_enabled", False))
            self.ui.checkAuthManual.setChecked(auth_settings.get("manual_enabled", False))
            
            # Load authentication field values
            self.ui.edtAuthUsername.setText(auth_settings.get("username", ""))
            self.ui.edtAuthPassword.setText(auth_settings.get("password", ""))
            
            # Apply checkbox states (this will enable/disable fields appropriately)
            self.on_auth_http_toggled()
            self.on_auth_manual_toggled()
        
        # Load HTTP settings
        if "http" in settings:
            http_settings = settings["http"]
            
            # Load HTTP field values
            self.ui.spnHTimeout.setValue(http_settings.get("timeout", 60))
            self.ui.spnHParallel.setValue(http_settings.get("parallel", 4))
            self.ui.spnHMaxRequest.setValue(http_settings.get("max_request", 5))
            self.ui.edtHUserAgent.setText(http_settings.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.3"))
            self.ui.edtAdditionalCookies.setPlainText(http_settings.get("additional_cookies", ""))
            self.ui.edtAdditionalHTTP.setPlainText(http_settings.get("additional_http", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\nAccept-Language: en-US,en;q=0.5"))
        else:
            # If no saved settings, apply defaults
            self.setup_http_defaults()
        
        # Load crawler settings
        if "crawler" in settings:
            crawler_settings = settings["crawler"]
            
            # Load checkbox states (default to True for checkCMaxDepth, checkCMaxCount, checkCFileExclution, checkCEvaluate)
            self.ui.checkCMaxDepth.setChecked(crawler_settings.get("max_depth_enabled", True))
            self.ui.checkCMaxCount.setChecked(crawler_settings.get("max_count_enabled", True))
            self.ui.checkCFileExclution.setChecked(crawler_settings.get("file_exclusion_enabled", True))
            self.ui.checkCEvaluate.setChecked(crawler_settings.get("evaluate_enabled", True))
            self.ui.checkCScanSubDomain.setChecked(crawler_settings.get("scan_subdomain", False))
            self.ui.checkCScanTargetURL.setChecked(crawler_settings.get("scan_target_url", False))
            
            # Load field values
            self.ui.spnCMaxDepth.setValue(crawler_settings.get("max_depth", 5))
            self.ui.spnCMaxCount.setValue(crawler_settings.get("max_count", 70000))
            self.ui.edtCFileExclution.setText(crawler_settings.get("file_exclusion", "*.7z,*.a3c,*.a52,*.aac,*.ac3,*.ace,*.acsm,*.am,*.apk,*.asf,*.asx,*.avi,*.azw3,*.azw4,*.bin,*.bmp,*.bz2,*.cab,*.cmd,*.conf,*.css,*.csv,*.divx,*.djvu,*.doc,*.docx,*.dts,*.dv,*.engine,*.eot,*.eps,*.epub,*.exe,*.fla,*.flac,*.flv,*.fvi,*.gif,*.gxf,*.gz,*.ice,*.ico,*.inc,*.info,*.install,*.iso,*.jar,*.jpe,*.jpeg,*.jpg,*.lang,*.m1v,*.m2ts,*.m2v,*.m4a,*.m4p,*.m4v,*.mdb,*.mid,*.midi,*.mka,*.mkv,*.mod,*.mov,*.movie,*.mp,*.mp1,*.mp2,*.mp3,*.mp4,*.mpeg,*.mpeg1,*.mpeg2,*.mpeg4,*.mpg,*.mpga,*.mpp,*.mpt,*.msi,*.mts,*.mtv,*.mxf,*.oga,*.ogg,*.ogm,*.ogv,*.ogx,*.oma,*.opus,*.pac,*.pcx,*.pdf,*.pgm,*.png,*.ppsx,*.ppt,*.pptx,*.profile,*.ps,*.psd,*.ram,*.rar,*.rb,*.res,*.rmf,*.rpm,*.save,*.scss,*.sh,*.spx,*.sql,*.svg,*.svn-base,*.svn-work,*.swf,*.tar,*.tbz2,*.tgz,*.tif,*.tiff,*.ts,*.tta,*.ttf,*.uff,*.vob,*.vox,*.vro,*.wav,*.wbmp,*.webm,*.wma,*.wmv,*.woff,*.xls,*.xlsx,*.xm,*.zip,*.abw,*.arc,*.azw,*.bz,*.csh,*.ics,*.mpkg,*.odp,*.ods,*.odt,*.otf,*.rtf,*.txt,*.vsd,*.weba,*.webp,*.woff2,*.xul,*.3gp,*.3g2,*.xcf,*.map"))
            self.ui.edtCURLExclution.setPlainText(crawler_settings.get("url_exclusion", "*sign?out*\n*log?out*\n*exit*\n*kill*\n*delete*\n*remove*\n*/.svn/+\n*/.git/+\n*/phpMyAdmin/+\n*/pgadmin/+\n*/roundcube/+\n*/%/%/%/%/%/%/%/%/%/%/%/%"))
            self.ui.edtCScopeRegex.setText(crawler_settings.get("scope_regex", ""))
            
            # Load scope combo box
            scope_text = crawler_settings.get("scope", "Smart")
            index = self.ui.cmbCScope.findText(scope_text)
            if index >= 0:
                self.ui.cmbCScope.setCurrentIndex(index)
            
            # Apply checkbox states (this will enable/disable fields appropriately)
            self.on_crawler_max_depth_toggled()
            self.on_crawler_max_count_toggled()
            self.on_crawler_file_exclusion_toggled()
            
            # Apply scope visibility
            self.on_crawler_scope_changed()
        else:
            # If no saved settings, apply defaults
            self.setup_crawler_defaults()
            # Apply scope visibility for defaults
            self.on_crawler_scope_changed()
        
        # Load form inputs settings
        if "form_inputs" in settings:
            form_settings = settings["form_inputs"]
            
            # Load form input field values
            self.ui.edtFUsername.setText(form_settings.get("username", ""))
            self.ui.edtFPassword.setText(form_settings.get("password", ""))
            self.ui.edtFEmail.setText(form_settings.get("email", ""))
            self.ui.edtFFirstName.setText(form_settings.get("first_name", ""))
            self.ui.edtFLastName.setText(form_settings.get("last_name", ""))
            self.ui.edtFAddress.setText(form_settings.get("address", ""))
            self.ui.edtFCity.setText(form_settings.get("city", ""))
            self.ui.edtFState.setText(form_settings.get("state", ""))
            self.ui.edtFZip.setText(form_settings.get("zip", ""))
            self.ui.edtFCountry.setText(form_settings.get("country", ""))
            self.ui.edtFCompany.setText(form_settings.get("company", ""))
            self.ui.edtFPhone.setText(form_settings.get("phone", ""))
            self.ui.edtFDay.setText(form_settings.get("day", ""))
            self.ui.edtFMonth.setText(form_settings.get("month", ""))
            self.ui.edtFYear.setText(form_settings.get("year", ""))
            self.ui.edtFAge.setText(form_settings.get("age", ""))
            self.ui.edtFPrefix.setText(form_settings.get("prefix", ""))
            self.ui.edtFLanguage.setText(form_settings.get("language", ""))
        
        # Load test vectors settings
        if "test_vectors" in settings:
            test_vectors_settings = settings["test_vectors"]
            
            # Load checkbox states
            self.ui.checkTGET.setChecked(test_vectors_settings.get("get_enabled", False))
            self.ui.checkTPOST.setChecked(test_vectors_settings.get("post_enabled", False))
            self.ui.checkTCookie.setChecked(test_vectors_settings.get("cookie_enabled", False))
            self.ui.checkTHeader.setChecked(test_vectors_settings.get("header_enabled", False))
            self.ui.checkTURLPath.setChecked(test_vectors_settings.get("url_path_enabled", False))
            
            # Load parameter field value
            self.ui.edtTParameter.setPlainText(test_vectors_settings.get("parameter", "*;;PHPSESSID;;Any;;*\n*;;__VIEWSTATE;;Any;;*\n*;;__EVENTTARGET;;POST;;*\n*;;__EVENTARGUMENT;;POST;;*\n*;;__VIEWSTATEGENERATOR;;POST;;*\n*;;__EVENTVALIDATION;;POST;;*\n*;;__VIEWSTATEENCRYPTED;;POST;;*\n*;;__VSTATE;;Any;;*\n*;;__VIEWSTATEFIELDCOUNT;;Any;;*\n*;;__COMPRESSEDVIEWSTATE;;Any;;*\n*;;__ASYNCPOST;;POST;;*\n*;;SCROLLPOSITION?;;QUERY;;*\n*;;LASTFOCUS?;;QUERY;;*\n*;;utm*;;Any;;*\n*;;_ga;;Any;;*\n*;;_gat;;Any;;*\n*;;__utm*;;Any;;*\n*;;submit*;;POST;;*\n*;;submit*;;QUERY;;*\n*;;_javax.faces.ViewState;;POST;;*\n*;;_javax.faces.ViewState;;POST;;*\n*;;org.apache.struts.taglib.html.TOKEN;;POST;;*\n*;;jsessionid;;Any;;*\n*;;cfid;;COOKIE;;*\n*;;cftoken;;COOKIE;;*\n*;;ASP.NET_SessionId;;Any;;*\n*;;ASPSESSIONID*;;Any;;*\n*;;SITESERVER;;Any;;*\n*;;*csrf*;;Any;;*\n*;;*token*;;Any;;*\n*;;*nonce*;;Any;;*\n*;;*;;*;;COOKIE;;[md5]\n*;;*;;*;;COOKIE;;[guid]\n*;;*;;*;;PATH;;[year]\n*;;*;;*;;Any;;[base64]\n*[seo]*;;*;;*;;QUERY;;*\n*[non-english]*;;*;;*;;QUERY;;*\n*/;;*;;path;;*"))
        else:
            # If no saved settings, apply defaults
            self.setup_test_vectors_defaults()
        
        # Load technologies settings
        if "technologies" in settings:
            technologies = settings["technologies"]
            
            # Clear existing rows
            self.ui.tableTech.setRowCount(0)
            
            # Load technologies into table
            for tech in technologies:
                row_count = self.ui.tableTech.rowCount()
                self.ui.tableTech.insertRow(row_count)
                
                tech_type = tech.get("type", "")
                tech_url = tech.get("url", "")
                
                self.ui.tableTech.setItem(row_count, 0, QTableWidgetItem(tech_type))
                self.ui.tableTech.setItem(row_count, 1, QTableWidgetItem(tech_url))
        
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