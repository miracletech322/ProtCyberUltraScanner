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

from scanner_engine import WebCrawler, VulnerabilityScanner

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
            # Load settings
            http_settings = self.settings.get("http", {})
            timeout = http_settings.get("timeout", 60)
            user_agent = http_settings.get("user_agent", "Mozilla/5.0")
            parallel = http_settings.get("parallel", 4)
            
            # Setup proxy
            proxy_settings = self.settings.get("proxy", {})
            proxies = None
            if proxy_settings.get("type") == "http" and proxy_settings.get("ip"):
                proxy_url = f"http://{proxy_settings.get('ip')}:{proxy_settings.get('port', 8080)}"
                if proxy_settings.get("username"):
                    proxy_url = f"http://{proxy_settings.get('username')}:{proxy_settings.get('password', '')}@{proxy_settings.get('ip')}:{proxy_settings.get('port', 8080)}"
                proxies = {"http": proxy_url, "https": proxy_url}
            elif proxy_settings.get("type") == "socks" and proxy_settings.get("ip"):
                proxy_url = f"socks5://{proxy_settings.get('ip')}:{proxy_settings.get('port', 1080)}"
                proxies = {"http": proxy_url, "https": proxy_url}
            
            # Setup session with retries
            session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=0.3,
                status_forcelist=[429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            # Setup authentication
            auth_settings = self.settings.get("authentication", {})
            auth = None
            if auth_settings.get("http_enabled"):
                username = auth_settings.get("username", "")
                password = auth_settings.get("password", "")
                if username:
                    auth = HTTPBasicAuth(username, password)
            
            # Prepare headers
            request_headers = {
                "User-Agent": user_agent
            }
            request_headers.update(self.headers)
            
            # Add additional headers from settings
            additional_http = http_settings.get("additional_http", "")
            if additional_http:
                for line in additional_http.split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        request_headers[key.strip()] = value.strip()
            
            # Add cookies from settings
            additional_cookies = http_settings.get("additional_cookies", "")
            if additional_cookies:
                for cookie in additional_cookies.split(";"):
                    if "=" in cookie:
                        key, value = cookie.split("=", 1)
                        session.cookies.set(key.strip(), value.strip())
            
            session.headers.update(request_headers)
            if proxies:
                session.proxies.update(proxies)
            
            # Initialize vulnerability scanner
            scanner = VulnerabilityScanner(
                self.settings,
                session,
                self.issue_found.emit,
                self.progress.emit,
                self.status_update.emit
            )
            
            # Step 1: Initial request and passive checks
            self.status_update.emit(f"Scanning {self.url}...")
            self.request_count += 1
            self.progress.emit(5)
            
            try:
                if self.method.upper() == "GET":
                    response = session.get(self.url, auth=auth, timeout=timeout, allow_redirects=True)
                elif self.method.upper() == "POST":
                    response = session.post(self.url, auth=auth, data=self.body, timeout=timeout, allow_redirects=True)
                elif self.method.upper() == "PUT":
                    response = session.put(self.url, auth=auth, data=self.body, timeout=timeout, allow_redirects=True)
                elif self.method.upper() == "PATCH":
                    response = session.patch(self.url, auth=auth, data=self.body, timeout=timeout, allow_redirects=True)
                elif self.method.upper() == "DELETE":
                    response = session.delete(self.url, auth=auth, timeout=timeout, allow_redirects=True)
                elif self.method.upper() == "HEAD":
                    response = session.head(self.url, auth=auth, timeout=timeout, allow_redirects=True)
                else:
                    response = session.get(self.url, auth=auth, timeout=timeout, allow_redirects=True)
                
                self.request_count += 1
                self.progress.emit(10)
                
                # Passive checks on initial URL
                self.status_update.emit("Running passive security checks...")
                passive_issues = []
                passive_issues.extend(scanner.test_web_server_info(self.url))
                passive_issues.extend(scanner.test_security_headers(self.url))
                passive_issues.extend(scanner.test_robots_txt(self.url))
                passive_issues.extend(scanner.test_sitemap(self.url))
                passive_issues.extend(scanner.test_cms_detection(self.url))
                passive_issues.extend(scanner.test_sensitive_data_disclosure(self.url))
                passive_issues.extend(scanner.test_directory_listing(self.url))
                
                for issue in passive_issues:
                    issues.append(issue)
                    self.issue_found.emit(issue)
                
                self.progress.emit(20)
                
                # Step 2: Web crawling (if enabled)
                crawler_settings = self.settings.get("crawler", {})
                urls_to_test = [self.url]
                
                if crawler_settings.get("evaluate_enabled", True):
                    self.status_update.emit("Crawling website...")
                    crawler = WebCrawler(
                        self.url,
                        self.settings,
                        session,
                        self.issue_found.emit,
                        self.progress.emit,
                        self.status_update.emit
                    )
                    discovered_urls = crawler.crawl()
                    urls_to_test.extend(discovered_urls[:50])  # Limit to 50 URLs for performance
                    self.request_count += len(discovered_urls)
                    self.progress.emit(40)
                
                # Step 3: Active vulnerability testing
                self.status_update.emit("Testing for vulnerabilities...")
                total_urls = len(urls_to_test)
                
                for idx, test_url in enumerate(urls_to_test[:20]):  # Limit to 20 URLs for performance
                    if not self.is_running:
                        break
                    
                    # Check if paused (wait while paused)
                    while self.is_paused and self.is_running:
                        time.sleep(0.1)
                    if not self.is_running:
                        break
                    
                    try:
                        # Parse URL for parameters
                        parsed = urlparse(test_url)
                        params = parse_qs(parsed.query)
                        # Convert list values to single values
                        params = {k: v[0] if v else "" for k, v in params.items()}
                        
                        # Determine method
                        test_method = self.method if test_url == self.url else "GET"
                        
                        # Test SQL Injection
                        sql_issues = scanner.test_sql_injection(test_url, params, test_method)
                        for issue in sql_issues:
                            issues.append(issue)
                            self.issue_found.emit(issue)
                        
                        # Test Blind SQL Injection
                        blind_sql_issues = scanner.test_blind_sql_injection(test_url, params, test_method)
                        for issue in blind_sql_issues:
                            issues.append(issue)
                            self.issue_found.emit(issue)
                        
                        # Test XSS
                        xss_issues = scanner.test_xss(test_url, params, test_method)
                        for issue in xss_issues:
                            issues.append(issue)
                            self.issue_found.emit(issue)
                        
                        # Test Path Traversal
                        path_traversal_issues = scanner.test_path_traversal(test_url, params, test_method)
                        for issue in path_traversal_issues:
                            issues.append(issue)
                            self.issue_found.emit(issue)
                        
                        # Test Command Injection
                        cmd_issues = scanner.test_command_injection(test_url, params, test_method)
                        for issue in cmd_issues:
                            issues.append(issue)
                            self.issue_found.emit(issue)
                        
                        # Test Open Redirect
                        redirect_issues = scanner.test_open_redirect(test_url, params, test_method)
                        for issue in redirect_issues:
                            issues.append(issue)
                            self.issue_found.emit(issue)
                        
                        # Test SSRF
                        ssrf_issues = scanner.test_ssrf(test_url, params, test_method)
                        for issue in ssrf_issues:
                            issues.append(issue)
                            self.issue_found.emit(issue)
                        
                        # Test File Inclusion
                        file_inclusion_issues = scanner.test_file_inclusion(test_url, params, test_method)
                        for issue in file_inclusion_issues:
                            issues.append(issue)
                            self.issue_found.emit(issue)
                        
                        self.request_count += len(params) * 7  # Approximate request count
                        progress_value = 40 + int((idx + 1) / min(20, total_urls) * 50)
                        self.progress.emit(progress_value)
                        
                    except Exception as e:
                        continue
                
                # Step 4: SSL/TLS and Brute Force tests
                self.status_update.emit("Testing SSL/TLS and authentication...")
                ssl_issues = scanner.test_ssl_tls(self.url)
                for issue in ssl_issues:
                    issues.append(issue)
                    self.issue_found.emit(issue)
                
                brute_force_issues = scanner.test_brute_force(self.url)
                for issue in brute_force_issues:
                    issues.append(issue)
                    self.issue_found.emit(issue)
                
                self.progress.emit(95)
                
            except requests.exceptions.RequestException as e:
                issues.append({
                    "title": "Connection Error",
                    "severity": "High",
                    "url": self.url,
                    "description": f"Failed to connect to target: {str(e)}",
                    "request": f"{self.method} {self.url}",
                    "response": None
                })
                self.issue_found.emit(issues[-1])
            
            # Calculate duration
            duration = time.time() - self.start_time
            
            # Prepare scan results
            risk_level = self.calculate_risk_level(issues)
            
            results = {
                "target": self.url,
                "risk": risk_level,
                "issues": issues,
                "duration": duration,
                "requests": self.request_count
            }
            
            self.progress.emit(100)
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
                # Display issue details
                details = []
                details.append(f"Severity: {issue_data.get('severity', 'Unknown')}")
                details.append(f"\nURL: {issue_data.get('url', '')}")
                details.append(f"\nDESCRIPTION")
                details.append(issue_data.get('description', ''))
                details.append(f"\n\nRequest:")
                details.append(issue_data.get('request', ''))
                details.append(f"\n\nResponse:")
                details.append(issue_data.get('response', ''))
                
                self.ui.plainTextEdit.setPlainText("\n".join(details))
            elif isinstance(issue_data, str):
                # Parent item selected - show first issue from group
                title = issue_data
                if title in self.issue_groups and self.issue_groups[title]["issues"]:
                    first_issue = self.issue_groups[title]["issues"][0]
                    details = []
                    details.append(f"Severity: {first_issue.get('severity', 'Unknown')}")
                    details.append(f"\nURL: {first_issue.get('url', '')}")
                    details.append(f"\nDESCRIPTION")
                    details.append(first_issue.get('description', ''))
                    details.append(f"\n\nRequest:")
                    details.append(first_issue.get('request', ''))
                    details.append(f"\n\nResponse:")
                    details.append(first_issue.get('response', ''))
                    
                    self.ui.plainTextEdit.setPlainText("\n".join(details))
    
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
                # Prepare export data
                export_data = {
                    "scan_info": {
                        "target": self.scan_results.get("target", ""),
                        "risk_level": self.scan_results.get("risk", "0/5"),
                        "total_issues": len(self.scan_results.get("issues", [])),
                        "duration_seconds": self.scan_results.get("duration", 0),
                        "total_requests": self.scan_results.get("requests", 0),
                        "scan_date": datetime.now().isoformat()
                    },
                    "issues": self.scan_results.get("issues", []),
                    "issue_summary": {}
                }
                
                # Create issue summary by severity
                for issue in self.scan_results.get("issues", []):
                    severity = issue.get("severity", "Unknown")
                    if severity not in export_data["issue_summary"]:
                        export_data["issue_summary"][severity] = 0
                    export_data["issue_summary"][severity] += 1
                
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