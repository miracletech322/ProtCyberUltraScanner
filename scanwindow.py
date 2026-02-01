import json
import time
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from PySide6.QtWidgets import QWidget, QTreeWidgetItem, QFileDialog, QMessageBox
from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QIcon
from ui_scanwindow import Ui_ScanWindow
import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
try:
    from urllib3.util.retry import Retry
except ImportError:
    # Fallback if urllib3 is not available
    class Retry:
        def __init__(self, *args, **kwargs):
            pass

from search_engine_adapter import run_all_search_engines

class ScanWorker(QThread):
    """Worker thread for performing security scans"""
    progress = Signal(int)
    status_update = Signal(str)
    issue_found = Signal(dict)
    scan_complete = Signal(dict)
    
    def __init__(self, url, method=None, headers=None, body=None, settings=None):
        super().__init__()
        self.url = url
        self.method = method or "GET"
        self.headers = headers or {}
        self.body = body
        self.settings = settings or {}
        self.is_running = True
        self.is_paused = False
        self.start_time = None
        self.request_count = 0
        
    def run(self):
        """Perform the comprehensive security scan"""
        self.start_time = time.time()
        issues = []
        
        try:
            # Execute all SearchEngine modules in priority order
            self.status_update.emit(f"Scanning {self.url} with all SearchEngine modules...")
            result = run_all_search_engines(
                target_url=self.url,
                settings=self.settings,
                headers=self.headers,
                body=self.body,
                progress_cb=self.progress.emit,
                status_cb=self.status_update.emit,
            )

            issues.extend(result.issues)
            for issue in result.issues:
                self.issue_found.emit(issue)

            results = {
                "target": result.target,
                "risk": result.risk,
                "issues": result.issues,
                "duration": result.duration,
                "requests": result.requests,
                # Keep raw results for debugging/export if needed later
                "raw": result.raw,
            }

            self.scan_complete.emit(results)
            
        except Exception as e:
            import traceback
            self.status_update.emit(f"Scan error: {str(e)}")
            results = {
                "target": self.url,
                "risk": "Unknown",
                "issues": [],
                "duration": 0,
                "requests": self.request_count,
                "error": str(e)
            }
            self.scan_complete.emit(results)
    
    def calculate_risk_level(self, issues):
        """Calculate overall risk level"""
        high_count = sum(1 for issue in issues if issue.get("severity") == "High")
        medium_count = sum(1 for issue in issues if issue.get("severity") == "Medium")
        
        if high_count > 0:
            return f"{min(5, high_count + medium_count)}/5"
        elif medium_count > 0:
            return f"{min(3, medium_count)}/5"
        else:
            return "1/5"
    
    def format_headers(self, headers):
        """Format response headers for display"""
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])
    
    def format_response_body(self, response):
        """Format response body for display"""
        try:
            if response.text:
                return response.text[:1000]  # First 1000 chars
        except:
            pass
        return "[Binary or empty response]"


class ScanWindow(QWidget):
    def __init__(self, url=None, method=None, header_name=None, header_value=None, body=None):
        super().__init__()
        self.ui = Ui_ScanWindow()
        self.ui.setupUi(self)
        
        self.url = url
        self.method = method
        self.header_name = header_name
        self.header_value = header_value
        self.body = body
        
        self.scan_worker = None
        self.issues = []
        self.issue_groups = {}
        self.scan_results = None
        self.is_paused = False
        self.is_stopped = False
        self.main_window = None  # Will be set by MainWindow
        
        # Setup tree widget
        self.ui.treeWidget.setHeaderLabel("Found Issues")
        self.ui.treeWidget.itemSelectionChanged.connect(self.on_issue_selected)
        
        # Setup buttons
        self.setup_buttons()
        
        # Load settings and start scan
        self.load_settings_and_scan()
    
    def setup_buttons(self):
        """Setup button click handlers"""
        self.ui.pushButton.clicked.connect(self.on_report_clicked)  # Report button
        self.ui.pushButton_2.clicked.connect(self.on_pause_clicked)  # Pause button
        self.ui.pushButton_3.clicked.connect(self.on_stop_clicked)  # Stop/New button
    
    def load_settings_and_scan(self):
        """Load settings.json and start the scan"""
        try:
            with open("settings.json", "r") as f:
                settings = json.load(f)
        except Exception as e:
            settings = {}
        
        # Validate URL
        if not self.url:
            self.ui.labelTarget.setText("No URL provided")
            self.ui.labelLastRequest.setText("Error: No URL provided")
            return
        
        # Prepare headers
        headers = {}
        if self.header_name and self.header_value:
            headers[self.header_name] = self.header_value
        
        # Update UI with target
        self.ui.labelTarget.setText(self.url)
        
        # Start scan
        self.start_scan(settings, headers)
    
    def start_scan(self, settings, headers):
        """Start the security scan in a worker thread"""
        self.ui.labelRisk.setText("Scanning...")
        self.ui.labelIssue.setText("0")
        self.ui.labelDuration.setText("0s")
        self.ui.labelRequest.setText("0")
        self.ui.progressBar.setValue(0)
        self.ui.treeWidget.clear()
        self.ui.plainTextEdit.clear()
        
        # Create and start worker thread
        self.scan_worker = ScanWorker(
            url=self.url,
            method=self.method,
            headers=headers,
            body=self.body,
            settings=settings
        )
        self.scan_worker.progress.connect(self.update_progress)
        self.scan_worker.status_update.connect(self.update_status)
        self.scan_worker.issue_found.connect(self.add_issue)
        self.scan_worker.scan_complete.connect(self.on_scan_complete)
        self.scan_worker.start()
    
    def update_progress(self, value):
        """Update progress bar"""
        self.ui.progressBar.setValue(value)
    
    def update_status(self, status):
        """Update status label"""
        self.ui.labelLastRequest.setText(status)
    
    def add_issue(self, issue):
        """Add an issue to the tree widget"""
        self.issues.append(issue)
        title = issue.get("title", "Unknown Issue")
        severity = issue.get("severity", "Info")
        
        # Group issues by title
        if title not in self.issue_groups:
            item = QTreeWidgetItem(self.ui.treeWidget)
            item.setText(0, title)
            item.setData(0, Qt.UserRole, title)
            # Set icon based on severity (handle missing icons gracefully)
            try:
                if severity in ["High", "Medium"]:
                    icon = QIcon(":/Resources/warning.png")
                    if icon.isNull():
                        icon = QIcon()  # Empty icon if not found
                    item.setIcon(0, icon)
                else:
                    icon = QIcon(":/Resources/info.png")
                    if icon.isNull():
                        icon = QIcon()  # Empty icon if not found
                    item.setIcon(0, icon)
            except:
                pass  # Continue without icon if there's an error
            self.issue_groups[title] = {
                "item": item,
                "count": 0,
                "issues": []
            }
        
        # Add URL as child
        url_item = QTreeWidgetItem(self.issue_groups[title]["item"])
        url_item.setText(0, issue.get("url", ""))
        url_item.setData(0, Qt.UserRole, issue)
        
        self.issue_groups[title]["count"] += 1
        self.issue_groups[title]["issues"].append(issue)
        
        # Update count in parent item
        self.issue_groups[title]["item"].setText(0, f"{title} ({self.issue_groups[title]['count']})")
    
    def on_issue_selected(self):
        """Handle issue selection in tree widget"""
        selected_items = self.ui.treeWidget.selectedItems()
        if selected_items:
            item = selected_items[0]
            issue_data = item.data(0, Qt.UserRole)
            
            if isinstance(issue_data, dict):
                self.ui.plainTextEdit.setPlainText(self.format_issue_details(issue_data))
            elif isinstance(issue_data, str):
                # Parent item selected - show first issue from group
                title = issue_data
                if title in self.issue_groups and self.issue_groups[title]["issues"]:
                    first_issue = self.issue_groups[title]["issues"][0]
                    self.ui.plainTextEdit.setPlainText(self.format_issue_details(first_issue))

    def format_issue_details(self, issue_data):
        """Format issue details in a model-app-like structure."""
        details = []
        details.append(f"Severity: {issue_data.get('severity', 'Unknown')}")
        details.append(f"URL: {issue_data.get('url', '')}")

        description = issue_data.get('description', '')
        if description:
            details.append("\nDESCRIPTION")
            details.append(description)

        recommendation = issue_data.get("recommendation", "")
        if recommendation:
            details.append("\nRECOMMENDATION")
            details.append(recommendation)

        classification = issue_data.get("classification", {})
        if isinstance(classification, dict) and classification:
            details.append("\nCLASSIFICATIONS")
            for key, values in classification.items():
                if isinstance(values, list):
                    details.append(f"{key}: {', '.join(values)}")
                else:
                    details.append(f"{key}: {values}")

        references = issue_data.get("references", [])
        if references:
            details.append("\nREFERENCES")
            for ref in references:
                if isinstance(ref, dict):
                    title = ref.get("title", "")
                    url = ref.get("url", "")
                    details.append(f"- {title}: {url}".strip())
                else:
                    details.append(f"- {ref}")

        custom_fields = issue_data.get("customFields", {})
        if isinstance(custom_fields, dict) and custom_fields:
            details.append("\nCUSTOM FIELDS")
            for key, values in custom_fields.items():
                if isinstance(values, list):
                    details.append(f"{key}:")
                    for v in values[:50]:
                        details.append(f"  - {v}")
                    if len(values) > 50:
                        details.append(f"  ... ({len(values) - 50} more)")
                else:
                    details.append(f"{key}: {values}")

        http_pairs = issue_data.get("http", [])
        if http_pairs:
            details.append("\nREQUEST / RESPONSE")
            for pair in http_pairs[:3]:
                if isinstance(pair, dict):
                    req = pair.get("request", "")
                    resp = pair.get("response", "")
                    if req:
                        details.append(req)
                    if resp:
                        details.append(resp)
                    details.append("")

        request = issue_data.get('request', '')
        response = issue_data.get('response', '')
        if request or response:
            details.append("\nREQUEST / RESPONSE")
            if request:
                details.append(request)
            if response:
                details.append(response)

        return "\n".join(details)
    
    def on_scan_complete(self, results):
        """Handle scan completion"""
        # Store results for export
        self.scan_results = results
        
        # Update UI with results
        self.ui.labelTarget.setText(results.get("target", ""))
        self.ui.labelRisk.setText(results.get("risk", "0/5"))
        self.ui.labelIssue.setText(str(len(results.get("issues", []))))
        
        duration = results.get("duration", 0)
        self.ui.labelDuration.setText(f"{duration:.0f}\"")
        
        self.ui.labelRequest.setText(str(results.get("requests", 0)))
        self.ui.progressBar.setValue(100)
        self.ui.labelLastRequest.setText("Scan completed")
        
        # Expand all items
        self.ui.treeWidget.expandAll()
    
    def on_report_clicked(self):
        """Handle Report button click - export JSON file"""
        if not self.scan_results:
            QMessageBox.warning(self, "No Results", "Scan has not completed yet. Please wait for the scan to finish.")
            return
        
        # Get save file path
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                # Prepare export data in model-app format
                duration_seconds = float(self.scan_results.get("duration", 0) or 0.0)
                minutes = int(duration_seconds // 60)
                seconds = int(duration_seconds % 60)
                duration_str = f"{minutes}′ {seconds}″"

                export_data = {
                    "date": datetime.now().strftime("%a %b %d %Y"),
                    "duration": duration_str,
                    "issues": self.scan_results.get("issues", []),
                }
                
                # Write JSON file
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=4, ensure_ascii=False)
                
                QMessageBox.information(self, "Export Successful", f"Report exported successfully to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export report:\n{str(e)}")
    
    def on_pause_clicked(self):
        """Handle Pause button click - pause/resume scan"""
        if self.is_stopped:
            return
        
        if self.is_paused:
            # Resume scan
            self.is_paused = False
            self.ui.pushButton_2.setText("Pause")
            if self.scan_worker:
                self.scan_worker.is_paused = False
            self.ui.labelLastRequest.setText("Scan resumed...")
        else:
            # Pause scan
            self.is_paused = True
            self.ui.pushButton_2.setText("Resume")
            if self.scan_worker:
                self.scan_worker.is_paused = True
            self.ui.labelLastRequest.setText("Scan paused...")
    
    def on_stop_clicked(self):
        """Handle Stop/New button click"""
        if not self.is_stopped:
            # Stop the scan
            self.is_stopped = True
            self.is_paused = False
            self.ui.pushButton_2.setEnabled(False)  # Disable pause button
            
            if self.scan_worker:
                self.scan_worker.is_running = False
                self.scan_worker.is_paused = False
                self.scan_worker.terminate()
                self.scan_worker.wait(3000)  # Wait up to 3 seconds
            
            # Change button text to "New"
            self.ui.pushButton_3.setText("New")
            self.ui.labelLastRequest.setText("Scan stopped")
        else:
            # Close scanwindow and show frontwindow
            if self.main_window:
                if self.main_window.scanwindow_subwindow:
                    self.main_window.scanwindow_subwindow.close()
                    self.main_window.scanwindow_subwindow = None
                
                # Show frontwindow
                if self.main_window.frontwindow_subwindow:
                    self.main_window.frontwindow_subwindow.showMaximized()
                    self.main_window.ui.mdiArea.setActiveSubWindow(self.main_window.frontwindow_subwindow)