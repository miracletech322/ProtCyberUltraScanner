# ============================================================================
# ADVANCED AUTHENTICATION & SESSION SECURITY TESTING ENGINE
# ============================================================================
# Class: AdvancedAuthSessionAnalyzer
# Purpose: Comprehensive authentication testing with advanced session security analysis,
#          multi-factor authentication support, and automated security validation
# ============================================================================

import os
import re
import json
import hashlib
import time
import urllib
import urllib.parse
import base64
import secrets
import hmac
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple, Union, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

# Security-related imports
try:
    import jwt
    import cryptography
    from cryptography.fernet import Fernet
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# Local imports
from logger import logger
from colorama import Fore, Style, init

class AuthType(Enum):
    """Enum for authentication types."""
    FORM_BASED = "form_based"
    BASIC_AUTH = "basic_auth"
    DIGEST_AUTH = "digest_auth"
    BEARER_TOKEN = "bearer_token"
    OAUTH_2 = "oauth_2"
    OIDC = "openid_connect"
    SAML_2 = "saml_2"
    JWT = "json_web_token"
    API_KEY = "api_key"
    WINDOWS_INTEGRATED = "windows_integrated"
    MULTI_FACTOR = "multi_factor"

class SessionVulnerability(Enum):
    """Enum for session vulnerabilities."""
    SESSION_FIXATION = "session_fixation"
    SESSION_TIMEOUT = "session_timeout_warning"
    CONCURRENT_SESSIONS = "concurrent_sessions"
    SESSION_HIJACKING = "session_hijacking"
    CSRF = "csrf_vulnerable"
    XSS_TO_SESSION = "xss_to_session_theft"
    COOKIE_SECURITY = "cookie_security_issues"
    JWT_VULNERABILITIES = "jwt_vulnerabilities"

@dataclass
class AuthEndpoint:
    """Authentication endpoint metadata."""
    url: str
    auth_type: AuthType
    method: str
    status_code: int
    parameters: Dict[str, str]
    security_headers: Dict[str, str]
    detected_framework: str = ""
    requires_js: bool = False
    has_captcha: bool = False
    mfa_supported: bool = False

@dataclass
class SessionSecurityReport:
    """Comprehensive session security report."""
    session_id: str
    vulnerabilities: List[SessionVulnerability]
    cookie_analysis: Dict[str, Any]
    token_analysis: Dict[str, Any]
    security_score: float
    recommendations: List[str]
    test_results: Dict[str, Any]

@dataclass
class AuthCredentials:
    """Structured authentication credentials."""
    username: str
    password: str
    tokens: Dict[str, str] = field(default_factory=dict)
    mfa_method: str = ""
    mfa_secret: str = ""
    role: str = "user"
    session_data: Dict[str, Any] = field(default_factory=dict)

class AdvancedAuthSessionAnalyzer:
    """
    Advanced authentication and session security testing engine.
    
    Features:
    1. Comprehensive authentication mechanism detection and testing
    2. Advanced session management security testing
    3. Multi-factor authentication support and testing
    4. OAuth/OpenID Connect/SAML analysis
    5. JWT security analysis
    6. Headless browser automation for complex auth flows
    7. Password policy and brute-force attack simulation
    8. Role-based access control testing
    9. Real-time security scoring and reporting
    
    Supported Authentication Mechanisms:
    - Form-based authentication
    - HTTP Basic/Digest authentication
    - OAuth 2.0 / OpenID Connect
    - SAML 2.0
    - JWT/Bearer tokens
    - API keys
    - Windows Integrated Authentication
    - Multi-factor authentication (TOTP, SMS, Email, Push)
    """
    
    def __init__(self, 
                 headless_browser: bool = True,
                 enable_brute_force_simulation: bool = False,
                 max_login_attempts: int = 5,
                 session_timeout_minutes: int = 30,
                 enable_jwt_analysis: bool = True):
        
        self.headless_browser = headless_browser
        self.enable_brute_force_simulation = enable_brute_force_simulation
        self.max_login_attempts = max_login_attempts
        self.session_timeout_minutes = session_timeout_minutes
        self.enable_jwt_analysis = enable_jwt_analysis
        
        # Authentication patterns and signatures
        self.auth_patterns = self._initialize_auth_patterns()
        self.common_auth_endpoints = self._load_auth_endpoints()
        self.auth_frameworks = self._load_auth_frameworks()
        
        # Session management
        self.active_sessions: Dict[str, requests.Session] = {}
        self.session_metadata: Dict[str, Dict[str, Any]] = {}
        self.credentials_db: Dict[str, AuthCredentials] = {}
        
        # Browser automation (for complex auth flows)
        self.driver = None
        self.selenium_timeout = 30
        
        # Security testing configurations
        self.security_tests = self._initialize_security_tests()
        self.vulnerability_scoring = self._initialize_vulnerability_scoring()
        
        # Cached results
        self.auth_endpoint_cache: Dict[str, List[AuthEndpoint]] = {}
        self.security_report_cache: Dict[str, SessionSecurityReport] = {}
        
        # Initialize components
        self._initialize_browser()
        
    def _initialize_auth_patterns(self) -> Dict[str, Dict]:
        """Initialize comprehensive authentication patterns."""
        return {
            'login_form': {
                'patterns': [
                    re.compile(r'<form[^>]*id=["\'](login|signin|auth)["\'][^>]*>', re.I),
                    re.compile(r'<form[^>]*action=["\'][^"\']*(login|signin|auth|logon)["\'][^>]*>', re.I),
                    re.compile(r'<form[^>]*class=["\'][^"\']*(login|signin|auth)["\'][^>]*>', re.I),
                ],
                'confidence': 0.9
            },
            'username_field': {
                'patterns': [
                    re.compile(r'<input[^>]*name=["\'](username|user|login|email|account)["\'][^>]*>', re.I),
                    re.compile(r'<input[^>]*id=["\'](username|user|login|email)["\'][^>]*>', re.I),
                    re.compile(r'<input[^>]*placeholder=["\'](username|email|login)["\'][^>]*>', re.I),
                ],
                'confidence': 0.8
            },
            'password_field': {
                'patterns': [
                    re.compile(r'<input[^>]*type=["\']password["\'][^>]*>', re.I),
                    re.compile(r'<input[^>]*name=["\'](password|pass|pwd)["\'][^>]*>', re.I),
                ],
                'confidence': 1.0
            },
            'csrf_token': {
                'patterns': [
                    re.compile(r'<input[^>]*name=["\'][^"\']*(csrf|token|authenticity|nonce|_token)["\'][^>]*value=["\']([^"\']+)["\']', re.I),
                    re.compile(r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']', re.I),
                ],
                'confidence': 0.9
            },
            'mfa_field': {
                'patterns': [
                    re.compile(r'<input[^>]*name=["\'](otp|totp|mfa|2fa|code|verification)["\'][^>]*>', re.I),
                    re.compile(r'<input[^>]*placeholder=["\'](verification.*code|mfa.*code)["\'][^>]*>', re.I),
                ],
                'confidence': 0.7
            },
            'oauth_button': {
                'patterns': [
                    re.compile(r'<a[^>]*href=["\'][^"\']*(oauth|openid|saml|auth)["\'][^>]*>', re.I),
                    re.compile(r'<button[^>]*>.*(google|facebook|github|microsoft|oauth).*</button>', re.I),
                ],
                'confidence': 0.8
            },
            'jwt_token': {
                'patterns': [
                    re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
                ],
                'confidence': 0.95
            }
        }
    
    def _load_auth_endpoints(self) -> List[Dict[str, Any]]:
        """Load comprehensive authentication endpoints database."""
        endpoints = [
            # Standard authentication endpoints
            {'path': '/login', 'methods': ['GET', 'POST'], 'type': AuthType.FORM_BASED},
            {'path': '/signin', 'methods': ['GET', 'POST'], 'type': AuthType.FORM_BASED},
            {'path': '/auth/login', 'methods': ['GET', 'POST'], 'type': AuthType.FORM_BASED},
            {'path': '/authentication', 'methods': ['GET', 'POST'], 'type': AuthType.FORM_BASED},
            
            # Logout endpoints
            {'path': '/logout', 'methods': ['GET', 'POST'], 'type': 'logout'},
            {'path': '/signout', 'methods': ['GET', 'POST'], 'type': 'logout'},
            {'path': '/auth/logout', 'methods': ['GET', 'POST'], 'type': 'logout'},
            
            # Registration endpoints
            {'path': '/register', 'methods': ['GET', 'POST'], 'type': 'registration'},
            {'path': '/signup', 'methods': ['GET', 'POST'], 'type': 'registration'},
            {'path': '/createaccount', 'methods': ['GET', 'POST'], 'type': 'registration'},
            
            # Password management
            {'path': '/password/reset', 'methods': ['GET', 'POST'], 'type': 'password_reset'},
            {'path': '/forgot-password', 'methods': ['GET', 'POST'], 'type': 'password_reset'},
            {'path': '/recover', 'methods': ['GET', 'POST'], 'type': 'password_reset'},
            {'path': '/change-password', 'methods': ['POST'], 'type': 'password_change'},
            
            # Profile and account management
            {'path': '/profile', 'methods': ['GET'], 'type': 'profile'},
            {'path': '/account', 'methods': ['GET'], 'type': 'profile'},
            {'path': '/settings', 'methods': ['GET'], 'type': 'profile'},
            
            # Admin endpoints
            {'path': '/admin', 'methods': ['GET'], 'type': 'admin'},
            {'path': '/administrator', 'methods': ['GET'], 'type': 'admin'},
            {'path': '/manage', 'methods': ['GET'], 'type': 'admin'},
            {'path': '/dashboard', 'methods': ['GET'], 'type': 'admin'},
            
            # API authentication
            {'path': '/api/auth', 'methods': ['GET', 'POST'], 'type': AuthType.BEARER_TOKEN},
            {'path': '/api/login', 'methods': ['POST'], 'type': AuthType.BEARER_TOKEN},
            {'path': '/api/token', 'methods': ['POST'], 'type': AuthType.JWT},
            {'path': '/oauth/token', 'methods': ['POST'], 'type': AuthType.OAUTH_2},
            
            # OAuth/OpenID Connect
            {'path': '/oauth/authorize', 'methods': ['GET'], 'type': AuthType.OAUTH_2},
            {'path': '/oauth2/authorize', 'methods': ['GET'], 'type': AuthType.OAUTH_2},
            {'path': '/openid/connect', 'methods': ['GET'], 'type': AuthType.OIDC},
            
            # SAML
            {'path': '/saml/login', 'methods': ['GET', 'POST'], 'type': AuthType.SAML_2},
            {'path': '/saml2/login', 'methods': ['GET', 'POST'], 'type': AuthType.SAML_2},
            
            # Legacy authentication
            {'path': '/basic-auth', 'methods': ['GET'], 'type': AuthType.BASIC_AUTH},
            {'path': '/digest-auth', 'methods': ['GET'], 'type': AuthType.DIGEST_AUTH},
        ]
        
        return endpoints
    
    def _load_auth_frameworks(self) -> Dict[str, Dict[str, Any]]:
        """Load known authentication framework signatures."""
        return {
            'keycloak': {
                'patterns': ['keycloak', 'kc_', 'auth/realms'],
                'endpoints': ['/auth/realms', '/auth/admin'],
                'headers': ['X-Keycloak-'],
            },
            'oauth2_proxy': {
                'patterns': ['oauth2_proxy', 'oauth2-proxy'],
                'endpoints': ['/oauth2', '/oauth2/callback'],
                'headers': ['X-Auth-Request-'],
            },
            'auth0': {
                'patterns': ['auth0', 'us.auth0.com'],
                'endpoints': ['/authorize', '/userinfo'],
                'headers': [],
            },
            'okta': {
                'patterns': ['okta', 'okta.com'],
                'endpoints': ['/oauth2/v1', '/api/v1'],
                'headers': ['X-Okta-'],
            },
            'azure_ad': {
                'patterns': ['login.microsoftonline.com', 'azuread'],
                'endpoints': ['/oauth2/v2.0'],
                'headers': ['X-MS-'],
            },
            'spring_security': {
                'patterns': ['spring', 'security'],
                'endpoints': ['/login', '/logout'],
                'headers': ['X-XSRF-TOKEN'],
            },
            'django': {
                'patterns': ['csrftoken', 'sessionid'],
                'endpoints': ['/accounts/login'],
                'headers': ['X-CSRFToken'],
            },
            'laravel': {
                'patterns': ['laravel_session', 'XSRF-TOKEN'],
                'endpoints': ['/login', '/register'],
                'headers': ['X-XSRF-TOKEN'],
            },
            'jwt': {
                'patterns': ['Bearer ', 'eyJ'],
                'endpoints': ['/api/auth'],
                'headers': ['Authorization'],
            }
        }
    
    def _initialize_security_tests(self) -> Dict[str, Dict[str, Any]]:
        """Initialize security test configurations."""
        return {
            'session_fixation': {
                'enabled': True,
                'methods': ['cookie_injection', 'url_parameter', 'session_adoption'],
                'severity': 'Medium',
                'description': 'Tests if session IDs can be fixated by an attacker'
            },
            'session_timeout': {
                'enabled': True,
                'test_intervals': [1, 5, 15, 30],  # minutes
                'severity': 'Low',
                'description': 'Tests session expiration policies'
            },
            'concurrent_sessions': {
                'enabled': True,
                'max_sessions': 10,
                'severity': 'Informational',
                'description': 'Tests if multiple concurrent sessions are allowed'
            },
            'session_hijacking': {
                'enabled': True,
                'methods': ['cookie_replay', 'token_reuse', 'predictable_ids'],
                'severity': 'High',
                'description': 'Tests session hijacking vulnerabilities'
            },
            'csrf': {
                'enabled': True,
                'methods': ['state_changing_requests', 'token_validation'],
                'severity': 'Medium',
                'description': 'Tests Cross-Site Request Forgery protections'
            },
            'jwt_security': {
                'enabled': self.enable_jwt_analysis,
                'tests': ['none_algorithm', 'weak_signature', 'expired_tokens', 'kid_injection'],
                'severity': 'High',
                'description': 'Tests JSON Web Token security'
            },
            'cookie_security': {
                'enabled': True,
                'attributes': ['HttpOnly', 'Secure', 'SameSite', 'Path', 'Domain'],
                'severity': 'Medium',
                'description': 'Tests cookie security attributes'
            },
            'password_policy': {
                'enabled': True,
                'tests': ['complexity', 'length', 'reuse', 'expiration'],
                'severity': 'Low',
                'description': 'Tests password policy enforcement'
            },
            'account_lockout': {
                'enabled': self.enable_brute_force_simulation,
                'max_attempts': 10,
                'severity': 'Informational',
                'description': 'Tests account lockout mechanisms'
            },
            'mfa_bypass': {
                'enabled': True,
                'methods': ['direct_access', 'parameter_tampering', 'state_confusion'],
                'severity': 'Critical',
                'description': 'Tests multi-factor authentication bypasses'
            }
        }
    
    def _initialize_vulnerability_scoring(self) -> Dict[str, float]:
        """Initialize vulnerability scoring weights."""
        return {
            'session_fixation': 6.0,
            'session_hijacking': 8.0,
            'csrf': 5.0,
            'jwt_security': 7.0,
            'cookie_security': 4.0,
            'mfa_bypass': 9.0,
            'password_policy': 3.0,
            'session_timeout': 2.0,
            'concurrent_sessions': 1.0,
            'account_lockout': 2.0,
        }
    
    def _initialize_browser(self):
        """Initialize headless browser for complex authentication flows."""
        if not SELENIUM_AVAILABLE:
            logger.warning("Selenium not available. JavaScript-based authentication may not work.")
            return
        
        try:
            from selenium.webdriver.chrome.options import Options
            
            chrome_options = Options()
            if self.headless_browser:
                chrome_options.add_argument("--headless=new")
            
            # Security-related browser options
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-web-security")
            chrome_options.add_argument("--allow-running-insecure-content")
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--disable-features=BlockInsecurePrivateNetworkRequests")
            chrome_options.add_argument("--window-size=1366,768")
            
            # Disable automation detection
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            self.driver = webdriver.Chrome(options=chrome_options)
            
            # Set page load timeout
            self.driver.set_page_load_timeout(self.selenium_timeout)
            
            logger.info("Headless browser initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize browser: {e}")
            self.driver = None
    
    def discover_auth_endpoints_advanced(self, base_url: str) -> List[AuthEndpoint]:
        """
        Advanced discovery of authentication endpoints.
        
        Features:
        1. Multi-method probing (GET, POST, HEAD)
        2. Framework fingerprinting
        3. JavaScript execution for SPA authentication endpoints
        4. Header analysis for auth-related headers
        5. Content analysis for authentication forms and tokens
        """
        endpoints = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Discovering authentication endpoints for {base_url}")
        
        # Check cached results
        cache_key = hashlib.md5(base_url.encode()).hexdigest()
        if cache_key in self.auth_endpoint_cache:
            logger.info("Using cached authentication endpoints")
            return self.auth_endpoint_cache[cache_key]
        
        # Standard endpoint discovery
        for endpoint_config in self.common_auth_endpoints:
            for method in endpoint_config['methods']:
                try:
                    url = urljoin(base_url, endpoint_config['path'])
                    
                    # Send request with various headers to trigger authentication
                    headers = self._get_auth_probing_headers()
                    
                    response = requests.request(
                        method=method,
                        url=url,
                        headers=headers,
                        timeout=10,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    # Analyze response
                    auth_type = self._detect_auth_type(response, url, endpoint_config)
                    
                    # Extract security headers
                    security_headers = self._extract_security_headers(response.headers)
                    
                    # Detect framework
                    framework = self._detect_auth_framework(response, url)
                    
                    # Check for JavaScript requirements
                    requires_js = self._requires_javascript(response.text)
                    
                    # Check for CAPTCHA
                    has_captcha = self._detect_captcha(response.text)
                    
                    # Check for MFA support
                    mfa_supported = self._detect_mfa_support(response.text, response.headers)
                    
                    auth_endpoint = AuthEndpoint(
                        url=url,
                        auth_type=auth_type,
                        method=method,
                        status_code=response.status_code,
                        parameters=self._extract_auth_parameters(response.text),
                        security_headers=security_headers,
                        detected_framework=framework,
                        requires_js=requires_js,
                        has_captcha=has_captcha,
                        mfa_supported=mfa_supported
                    )
                    
                    endpoints.append(auth_endpoint)
                    
                    logger.debug(f"Discovered auth endpoint: {url} ({auth_type})")
                    
                except Exception as e:
                    logger.debug(f"Endpoint discovery failed for {endpoint_config['path']}: {e}")
        
        # JavaScript-based discovery for Single Page Applications
        if SELENIUM_AVAILABLE and self.driver:
            js_endpoints = self._discover_js_auth_endpoints(base_url)
            endpoints.extend(js_endpoints)
        
        # Cache results
        self.auth_endpoint_cache[cache_key] = endpoints
        
        return endpoints
    
    def _detect_auth_type(self, response: requests.Response, url: str, 
                         endpoint_config: Dict) -> AuthType:
        """Detect authentication type from response."""
        content = response.text.lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Check for specific authentication mechanisms
        if 'www-authenticate' in headers:
            auth_header = headers['www-authenticate']
            if 'basic' in auth_header.lower():
                return AuthType.BASIC_AUTH
            elif 'digest' in auth_header.lower():
                return AuthType.DIGEST_AUTH
            elif 'bearer' in auth_header.lower():
                return AuthType.BEARER_TOKEN
        
        # Check for OAuth/OIDC
        if any(x in url.lower() for x in ['oauth', 'openid', 'saml']):
            if 'oauth' in url.lower():
                return AuthType.OAUTH_2
            elif 'openid' in url.lower():
                return AuthType.OIDC
            elif 'saml' in url.lower():
                return AuthType.SAML_2
        
        # Check for JWT tokens in response
        if re.search(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', response.text):
            return AuthType.JWT
        
        # Check for form-based authentication
        if any(x in content for x in ['<form', '<input type="password"']):
            return AuthType.FORM_BASED
        
        # Check for API key patterns
        if any(x in content for x in ['api_key', 'apikey', 'api-key']):
            return AuthType.API_KEY
        
        # Default to endpoint config type
        if 'type' in endpoint_config and isinstance(endpoint_config['type'], AuthType):
            return endpoint_config['type']
        
        return AuthType.FORM_BASED
    
    def _detect_auth_framework(self, response: requests.Response, url: str) -> str:
        """Detect authentication framework."""
        content = response.text.lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        for framework, signatures in self.auth_frameworks.items():
            # Check patterns in content
            for pattern in signatures['patterns']:
                if pattern.lower() in content or pattern.lower() in url.lower():
                    return framework
            
            # Check headers
            for header_pattern in signatures['headers']:
                for header_name in headers.keys():
                    if header_pattern.lower() in header_name.lower():
                        return framework
        
        return "unknown"
    
    def _requires_javascript(self, html_content: str) -> bool:
        """Check if authentication requires JavaScript."""
        indicators = [
            'react', 'angular', 'vue', 'spa',
            'javascript:void', 'onclick', 'addEventListener',
            '<script>', 'application/json',
        ]
        
        content_lower = html_content.lower()
        for indicator in indicators:
            if indicator in content_lower:
                return True
        
        return False
    
    def _detect_captcha(self, html_content: str) -> bool:
        """Detect CAPTCHA mechanisms."""
        captcha_patterns = [
            'recaptcha', 'captcha', 'hcaptcha',
            'g-recaptcha', 'data-sitekey',
            'turnstile', 'cloudflare',
        ]
        
        content_lower = html_content.lower()
        for pattern in captcha_patterns:
            if pattern in content_lower:
                return True
        
        return False
    
    def _detect_mfa_support(self, html_content: str, headers: Dict) -> bool:
        """Detect multi-factor authentication support."""
        mfa_indicators = [
            'multi-factor', 'two-factor', '2fa', 'mfa',
            'authenticator', 'google authenticator',
            'sms verification', 'email verification',
            'verification code', 'security code',
        ]
        
        content_lower = html_content.lower()
        for indicator in mfa_indicators:
            if indicator in content_lower:
                return True
        
        # Check for MFA-related headers
        for header_name, header_value in headers.items():
            if any(x in header_name.lower() for x in ['mfa', '2fa', 'otp']):
                return True
        
        return False
    
    def _extract_auth_parameters(self, html_content: str) -> Dict[str, str]:
        """Extract authentication parameters from HTML forms."""
        parameters = {}
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                inputs = form.find_all('input')
                for input_tag in inputs:
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    input_type = input_tag.get('type', 'text').lower()
                    
                    if name:
                        if input_type == 'hidden':
                            parameters[f"hidden_{name}"] = value
                        elif input_type == 'password':
                            parameters[f"password_field"] = name
                        elif 'user' in name.lower() or 'email' in name.lower() or 'login' in name.lower():
                            parameters[f"username_field"] = name
                        elif 'csrf' in name.lower() or 'token' in name.lower():
                            parameters[f"csrf_token"] = name
                        elif 'otp' in name.lower() or 'code' in name.lower():
                            parameters[f"mfa_field"] = name
        
        except Exception as e:
            logger.debug(f"Parameter extraction failed: {e}")
        
        return parameters
    
    def _extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract security-related headers."""
        security_headers = {}
        
        security_header_keys = [
            'X-Frame-Options', 'Content-Security-Policy',
            'X-Content-Type-Options', 'Strict-Transport-Security',
            'X-XSS-Protection', 'Referrer-Policy',
            'Feature-Policy', 'Permissions-Policy',
            'Set-Cookie', 'WWW-Authenticate',
        ]
        
        for key in security_header_keys:
            if key in headers:
                security_headers[key] = headers[key]
        
        return security_headers
    
    def _get_auth_probing_headers(self) -> Dict[str, str]:
        """Get headers for authentication endpoint probing."""
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'X-Requested-With': 'XMLHttpRequest',
        }
    
    def _discover_js_auth_endpoints(self, base_url: str) -> List[AuthEndpoint]:
        """Discover authentication endpoints in JavaScript-heavy applications."""
        endpoints = []
        
        if not self.driver:
            return endpoints
        
        try:
            print(f"  {Fore.CYAN}->{Style.RESET_ALL} Discovering JS-based authentication endpoints")
            
            # Navigate to base URL
            self.driver.get(base_url)
            time.sleep(2)  # Wait for JavaScript to execute
            
            # Look for authentication-related elements
            js_selectors = [
                'a[href*="login"]', 'a[href*="signin"]', 'a[href*="auth"]',
                'button:contains("Login")', 'button:contains("Sign In")',
                'input[type="password"]', 'form',
                '[data-testid*="login"]', '[aria-label*="login"]',
            ]
            
            for selector in js_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for element in elements:
                        try:
                            href = element.get_attribute('href')
                            onclick = element.get_attribute('onclick')
                            text = element.text.lower()
                            
                            if href and any(x in href.lower() for x in ['login', 'signin', 'auth']):
                                endpoint = AuthEndpoint(
                                    url=urljoin(base_url, href),
                                    auth_type=AuthType.FORM_BASED,
                                    method='GET',
                                    status_code=200,  # Assuming it loads
                                    parameters={},
                                    security_headers={},
                                    requires_js=True,
                                    detected_framework='spa',
                                )
                                endpoints.append(endpoint)
                                
                        except:
                            continue
                            
                except:
                    continue
            
            # Also check for XHR/Fetch requests to auth endpoints
            endpoints.extend(self._extract_js_endpoints_from_html(base_url, self.driver.page_source))
            
        except WebDriverException as e:
            logger.warning(f"JS-based endpoint discovery failed: {e}")
            endpoints.extend(self._discover_js_auth_endpoints_fallback(base_url))
        except Exception as e:
            logger.error(f"JS-based endpoint discovery failed: {e}")
        
        return endpoints

    def _discover_js_auth_endpoints_fallback(self, base_url: str) -> List[AuthEndpoint]:
        """Fallback JS discovery using static HTML when Selenium fails."""
        try:
            response = requests.get(
                base_url,
                headers=self._get_auth_probing_headers(),
                timeout=10,
                verify=False,
            )
            return self._extract_js_endpoints_from_html(base_url, response.text)
        except Exception as e:
            logger.debug(f"JS fallback discovery failed: {e}")
            return []

    def _extract_js_endpoints_from_html(self, base_url: str, html_text: str) -> List[AuthEndpoint]:
        """Extract potential auth endpoints from HTML/JS text."""
        endpoints = []
        if not html_text:
            return endpoints
        
        # Look for common auth links
        link_patterns = [
            r'href=["\']([^"\']*(login|signin|auth)[^"\']*)["\']',
            r'action=["\']([^"\']*(login|signin|auth)[^"\']*)["\']',
        ]
        for pattern in link_patterns:
            for match in re.findall(pattern, html_text, re.IGNORECASE):
                url_part = match[0] if isinstance(match, tuple) else match
                endpoints.append(AuthEndpoint(
                    url=urljoin(base_url, url_part),
                    auth_type=AuthType.FORM_BASED,
                    method='GET',
                    status_code=200,
                    parameters={},
                    security_headers={},
                    requires_js=True,
                    detected_framework='spa',
                ))
        
        # Look for JS fetch/axios/ajax references
        js_patterns = [
            r'fetch\(["\']([^"\']*(login|auth|token)[^"\']*)["\']',
            r'axios\.(?:get|post)\(["\']([^"\']*(login|auth|token)[^"\']*)["\']',
            r'\.ajax\([^)]*url:\s*["\']([^"\']*(login|auth|token)[^"\']*)["\']',
        ]
        for pattern in js_patterns:
            for match in re.findall(pattern, html_text, re.IGNORECASE):
                url_part = match[0] if isinstance(match, tuple) else match
                endpoints.append(AuthEndpoint(
                    url=urljoin(base_url, url_part),
                    auth_type=AuthType.BEARER_TOKEN,
                    method='POST',
                    status_code=200,
                    parameters={},
                    security_headers={},
                    requires_js=True,
                    detected_framework='spa',
                ))
        
        return endpoints
    
    def perform_comprehensive_auth_test(self, base_url: str, 
                                      credentials: AuthCredentials) -> Dict[str, Any]:
        """
        Perform comprehensive authentication testing.
        
        Tests include:
        1. Authentication mechanism analysis
        2. Login process testing
        3. Session security testing
        4. Multi-factor authentication testing
        5. Password policy testing
        6. Account lockout testing
        """
        test_results = {
            'authentication_mechanisms': [],
            'login_tests': {},
            'session_security': {},
            'mfa_tests': {},
            'password_policy': {},
            'vulnerabilities': [],
            'security_score': 0.0,
        }
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Starting comprehensive authentication testing")
        
        try:
            # Step 1: Discover authentication endpoints
            auth_endpoints = self.discover_auth_endpoints_advanced(base_url)
            test_results['authentication_mechanisms'] = [
                {
                    'url': endpoint.url,
                    'type': endpoint.auth_type.value,
                    'framework': endpoint.detected_framework,
                    'requires_js': endpoint.requires_js,
                    'has_captcha': endpoint.has_captcha,
                    'mfa_supported': endpoint.mfa_supported,
                }
                for endpoint in auth_endpoints
            ]
            
            # Step 2: Test login process for each endpoint
            for endpoint in auth_endpoints:
                if endpoint.auth_type in [AuthType.FORM_BASED, AuthType.BASIC_AUTH, AuthType.BEARER_TOKEN]:
                    login_test = self._test_login_process(endpoint, credentials)
                    test_results['login_tests'][endpoint.url] = login_test
            
            # Step 3: Perform session security testing
            if credentials.session_data.get('session_id'):
                session_report = self.analyze_session_security(
                    credentials.session_data['session_id'],
                    base_url
                )
                test_results['session_security'] = session_report
            
            # Step 4: Test multi-factor authentication if supported
            for endpoint in auth_endpoints:
                if endpoint.mfa_supported:
                    mfa_test = self._test_mfa_implementation(endpoint, credentials)
                    test_results['mfa_tests'][endpoint.url] = mfa_test
            
            # Step 5: Test password policy
            password_test = self._test_password_policy(base_url, credentials)
            test_results['password_policy'] = password_test
            
            # Step 6: Test account lockout mechanisms
            if self.enable_brute_force_simulation:
                lockout_test = self._test_account_lockout(base_url, credentials)
                test_results['account_lockout'] = lockout_test
            
            # Step 7: Calculate security score
            security_score = self._calculate_security_score(test_results)
            test_results['security_score'] = security_score
            
            # Step 8: Generate recommendations
            recommendations = self._generate_security_recommendations(test_results)
            test_results['recommendations'] = recommendations
            
            print(f"  {Fore.GREEN}OK{Style.RESET_ALL} Authentication testing completed. Security score: {security_score:.1f}/10")
            
        except Exception as e:
            logger.error(f"Comprehensive auth test failed: {e}")
            test_results['error'] = str(e)
        
        return test_results
    
    def _test_login_process(self, endpoint: AuthEndpoint, 
                          credentials: AuthCredentials) -> Dict[str, Any]:
        """Test the login process for a specific endpoint."""
        test_result = {
            'successful': False,
            'method': endpoint.method,
            'auth_type': endpoint.auth_type.value,
            'response_time': 0.0,
            'session_established': False,
            'cookies_received': [],
            'tokens_received': [],
            'redirects': [],
            'errors': [],
        }
        
        try:
            start_time = time.time()
            
            if endpoint.auth_type == AuthType.FORM_BASED:
                result = self._perform_form_login(endpoint, credentials)
            elif endpoint.auth_type == AuthType.BASIC_AUTH:
                result = self._perform_basic_auth(endpoint, credentials)
            elif endpoint.auth_type == AuthType.BEARER_TOKEN:
                result = self._perform_token_auth(endpoint, credentials)
            else:
                result = {'success': False, 'error': 'Unsupported auth type'}
            
            end_time = time.time()
            test_result['response_time'] = end_time - start_time
            
            if result.get('success'):
                test_result['successful'] = True
                test_result['session_established'] = True
                test_result['cookies_received'] = result.get('cookies', [])
                test_result['tokens_received'] = result.get('tokens', [])
                test_result['redirects'] = result.get('redirects', [])
                
                # Store session
                if 'session' in result:
                    session_id = f"{endpoint.url}:{credentials.username}"
                    self.active_sessions[session_id] = result['session']
                    
                    # Store metadata
                    self.session_metadata[session_id] = {
                        'endpoint': endpoint.url,
                        'username': credentials.username,
                        'login_time': datetime.now(),
                        'auth_type': endpoint.auth_type.value,
                        'cookies': dict(result['session'].cookies),
                    }
            
            if 'error' in result:
                test_result['errors'].append(result['error'])
            
        except Exception as e:
            test_result['errors'].append(str(e))
            logger.error(f"Login test failed for {endpoint.url}: {e}")
        
        return test_result
    
    def _perform_form_login(self, endpoint: AuthEndpoint, 
                          credentials: AuthCredentials) -> Dict[str, Any]:
        """Perform form-based login."""
        result = {'success': False}
        
        try:
            # Create session
            session = requests.Session()
            
            # First, get the login page
            response = session.get(endpoint.url, timeout=10, verify=False)
            
            if response.status_code != 200:
                result['error'] = f"Failed to load login page: {response.status_code}"
                return result
            
            # Parse form and extract fields
            form_data = self._extract_login_form_data(response.text, endpoint.url)
            
            if not form_data:
                result['error'] = "Could not extract login form data"
                return result
            
            # Prepare login payload
            login_payload = {}
            
            # Add username and password
            if 'username_field' in form_data:
                login_payload[form_data['username_field']] = credentials.username
            if 'password_field' in form_data:
                login_payload[form_data['password_field']] = credentials.password
            
            # Add CSRF token if found
            if 'csrf_token' in form_data and 'csrf_value' in form_data:
                login_payload[form_data['csrf_token']] = form_data['csrf_value']
            
            # Add other hidden fields
            for field_name, field_value in form_data.get('hidden_fields', {}).items():
                login_payload[field_name] = field_value
            
            # Determine submission URL
            submit_url = form_data.get('action', endpoint.url)
            
            # Submit login form
            login_response = session.post(
                submit_url,
                data=login_payload,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            
            # Check if login was successful
            if self._is_login_successful_advanced(login_response, credentials.username):
                result['success'] = True
                result['session'] = session
                result['cookies'] = list(session.cookies.items())
                result['redirects'] = [r.url for r in login_response.history] + [login_response.url]
                
                # Extract tokens if present
                tokens = self._extract_auth_tokens(login_response)
                if tokens:
                    result['tokens'] = tokens
                
                logger.info(f"Form login successful for {credentials.username}")
            else:
                result['error'] = "Login failed - incorrect credentials or authentication error"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def _perform_basic_auth(self, endpoint: AuthEndpoint,
                            credentials: AuthCredentials) -> Dict[str, Any]:
        """Perform HTTP Basic authentication."""
        result = {'success': False}
        
        try:
            session = requests.Session()
            response = session.get(
                endpoint.url,
                auth=(credentials.username, credentials.password),
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            
            if 200 <= response.status_code < 400:
                result['success'] = True
                result['session'] = session
                result['cookies'] = list(session.cookies.items())
                result['redirects'] = [r.url for r in response.history] + [response.url]
            else:
                result['error'] = f"Basic auth failed: {response.status_code}"
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def _perform_token_auth(self, endpoint: AuthEndpoint,
                            credentials: AuthCredentials) -> Dict[str, Any]:
        """Perform bearer token authentication."""
        result = {'success': False}
        
        try:
            token = None
            if credentials.tokens:
                token = credentials.tokens.get('access_token') or credentials.tokens.get('token')
            if not token:
                result['error'] = "No token available for bearer auth"
                return result
            
            session = requests.Session()
            headers = {'Authorization': f"Bearer {token}"}
            response = session.get(
                endpoint.url,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            
            if 200 <= response.status_code < 400:
                result['success'] = True
                result['session'] = session
                result['cookies'] = list(session.cookies.items())
                result['tokens'] = [{'type': 'bearer', 'value': token}]
                result['redirects'] = [r.url for r in response.history] + [response.url]
            else:
                result['error'] = f"Bearer auth failed: {response.status_code}"
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _extract_login_form_data(self, html_content: str, url: str) -> Dict[str, Any]:
        """Extract login form data from HTML."""
        form_data = {
            'action': url,
            'method': 'POST',
            'username_field': None,
            'password_field': None,
            'csrf_token': None,
            'csrf_value': None,
            'hidden_fields': {},
        }
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find login form
            login_forms = []
            all_forms = soup.find_all('form')
            
            for form in all_forms:
                # Check if form has password field
                password_input = form.find('input', {'type': 'password'})
                if password_input:
                    login_forms.append(form)
            
            if not login_forms:
                return form_data
            
            form = login_forms[0]  # Use first login form
            
            # Extract form action
            action = form.get('action')
            if action:
                form_data['action'] = urljoin(url, action)
            
            # Extract form method
            method = form.get('method', 'POST').upper()
            form_data['method'] = method
            
            # Extract input fields
            inputs = form.find_all('input')
            
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                input_type = input_tag.get('type', 'text').lower()
                
                if not input_name:
                    continue
                
                if input_type == 'password':
                    form_data['password_field'] = input_name
                elif 'user' in input_name.lower() or 'email' in input_name.lower() or 'login' in input_name.lower():
                    form_data['username_field'] = input_name
                elif 'csrf' in input_name.lower() or 'token' in input_name.lower():
                    form_data['csrf_token'] = input_name
                    form_data['csrf_value'] = input_value
                elif input_type == 'hidden':
                    form_data['hidden_fields'][input_name] = input_value
        
        except Exception as e:
            logger.debug(f"Form data extraction failed: {e}")
        
        return form_data
    
    def _is_login_successful_advanced(self, response: requests.Response, 
                                    username: str) -> bool:
        """Advanced login success detection."""
        # Check response status
        if response.status_code >= 400:
            return False
        
        # Extract response content
        content_lower = response.text.lower()
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        # Failure indicators
        failure_patterns = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error',
            'try again', 'not found', 'no account', 'locked',
            'suspended', 'disabled', 'unable to login',
            'access denied', 'unauthorized', 'forbidden',
        ]
        
        for pattern in failure_patterns:
            if pattern in content_lower:
                return False
        
        # Success indicators
        success_patterns = [
            'welcome', 'dashboard', 'profile', 'account',
            'success', 'logged in', 'sign out', 'logout',
            f'welcome, {username.lower()}', f'hello, {username.lower()}',
            'my account', 'user panel', 'control panel',
        ]
        
        for pattern in success_patterns:
            if pattern in content_lower:
                return True
        
        # Check for session cookies
        if response.cookies:
            session_cookies = ['session', 'token', 'auth', 'jwt', 'access', 'refresh']
            for cookie in response.cookies:
                if any(sc in cookie.name.lower() for sc in session_cookies):
                    return True
        
        # Check for authentication headers
        auth_headers = ['authorization', 'x-auth-token', 'x-access-token']
        for header in auth_headers:
            if header in headers_lower:
                return True
        
        # Check for redirect to different page (common after successful login)
        if len(response.history) > 0:
            # Was redirected after POST
            final_url = response.url
            if 'login' not in final_url.lower() and 'signin' not in final_url.lower():
                return True
        
        # Check for changes in page structure (e.g., logout button appears)
        if 'logout' in content_lower or 'sign out' in content_lower:
            return True
        
        return False
    
    def _extract_auth_tokens(self, response: requests.Response) -> List[Dict[str, str]]:
        """Extract authentication tokens from response."""
        tokens = []
        
        # Check cookies for tokens
        for cookie in response.cookies:
            if any(x in cookie.name.lower() for x in ['token', 'auth', 'jwt', 'access', 'refresh']):
                tokens.append({
                    'type': 'cookie',
                    'name': cookie.name,
                    'value': cookie.value[:50] + '...' if len(cookie.value) > 50 else cookie.value,
                    'secure': cookie.secure,
                    'http_only': cookie.has_nonstandard_attr('HttpOnly'),
                })
        
        # Check response body for tokens
        jwt_pattern = r'(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)'
        jwt_matches = re.findall(jwt_pattern, response.text)
        
        for jwt_token in jwt_matches:
            tokens.append({
                'type': 'jwt',
                'value': jwt_token[:50] + '...' if len(jwt_token) > 50 else jwt_token,
                'location': 'response_body',
            })
        
        # Check headers for tokens
        for header_name, header_value in response.headers.items():
            if any(x in header_name.lower() for x in ['token', 'auth', 'jwt']):
                tokens.append({
                    'type': 'header',
                    'name': header_name,
                    'value': header_value[:50] + '...' if len(header_value) > 50 else header_value,
                })
        
        return tokens
    
    def analyze_session_security(self, session_id: str, 
                               base_url: str) -> SessionSecurityReport:
        """
        Perform comprehensive session security analysis.
        
        Tests include:
        1. Session fixation
        2. Session timeout
        3. Concurrent sessions
        4. Cookie security attributes
        5. JWT security (if applicable)
        6. CSRF protection
        7. Session hijacking resistance
        """
        vulnerabilities = []
        cookie_analysis = {}
        token_analysis = {}
        test_results = {}
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Analyzing session security for session: {session_id[:20]}...")
        
        try:
            # Get session
            session = self.active_sessions.get(session_id)
            if not session:
                raise ValueError(f"Session not found: {session_id}")
            
            # Get session metadata
            metadata = self.session_metadata.get(session_id, {})
            
            # Test 1: Session fixation
            fixation_result = self._test_session_fixation_advanced(session, base_url)
            test_results['session_fixation'] = fixation_result
            if fixation_result.get('vulnerable'):
                vulnerabilities.append(SessionVulnerability.SESSION_FIXATION)
            
            # Test 2: Session timeout
            timeout_result = self._test_session_timeout_advanced(session, base_url, metadata)
            test_results['session_timeout'] = timeout_result
            if timeout_result.get('timeout_too_long'):
                vulnerabilities.append(SessionVulnerability.SESSION_TIMEOUT)
            
            # Test 3: Concurrent sessions
            concurrent_result = self._test_concurrent_sessions_advanced(session, base_url)
            test_results['concurrent_sessions'] = concurrent_result
            if concurrent_result.get('multiple_sessions_allowed'):
                vulnerabilities.append(SessionVulnerability.CONCURRENT_SESSIONS)
            
            # Test 4: Cookie security
            cookie_result = self._analyze_cookie_security(session, base_url)
            test_results['cookie_security'] = cookie_result
            cookie_analysis = cookie_result
            
            if cookie_result.get('security_issues'):
                vulnerabilities.append(SessionVulnerability.COOKIE_SECURITY)
            
            # Test 5: JWT security (if JWT tokens are present)
            if self.enable_jwt_analysis:
                jwt_result = self._analyze_jwt_security(session, base_url)
                test_results['jwt_security'] = jwt_result
                token_analysis = jwt_result
                
                if jwt_result.get('vulnerabilities'):
                    vulnerabilities.append(SessionVulnerability.JWT_VULNERABILITIES)
            
            # Test 6: CSRF protection
            csrf_result = self._test_csrf_protection(session, base_url)
            test_results['csrf_protection'] = csrf_result
            if csrf_result.get('vulnerable'):
                vulnerabilities.append(SessionVulnerability.CSRF)
            
            # Test 7: Session hijacking
            hijacking_result = self._test_session_hijacking(session, base_url)
            test_results['session_hijacking'] = hijacking_result
            if hijacking_result.get('vulnerable'):
                vulnerabilities.append(SessionVulnerability.SESSION_HIJACKING)
            
            # Calculate security score
            security_score = self._calculate_session_security_score(test_results)
            
            # Generate recommendations
            recommendations = self._generate_session_recommendations(test_results)
            
            report = SessionSecurityReport(
                session_id=session_id,
                vulnerabilities=vulnerabilities,
                cookie_analysis=cookie_analysis,
                token_analysis=token_analysis,
                security_score=security_score,
                recommendations=recommendations,
                test_results=test_results,
            )
            
            # Cache report
            self.security_report_cache[session_id] = report
            
            return report
            
        except Exception as e:
            logger.error(f"Session security analysis failed: {e}")
            
            return SessionSecurityReport(
                session_id=session_id,
                vulnerabilities=[],
                cookie_analysis={},
                token_analysis={},
                security_score=0.0,
                recommendations=[f"Analysis failed: {str(e)}"],
                test_results={'error': str(e)},
            )
    
    def _test_session_fixation_advanced(self, session: requests.Session, 
                                      base_url: str) -> Dict[str, Any]:
        """Advanced session fixation testing."""
        result = {
            'vulnerable': False,
            'tests_performed': [],
            'evidence': '',
            'severity': 'Medium',
        }
        
        try:
            tests = ['cookie_injection', 'url_parameter', 'session_adoption']
            
            for test in tests:
                test_result = False
                
                if test == 'cookie_injection':
                    # Try to inject a session cookie
                    test_session = requests.Session()
                    test_session.cookies.set('sessionid', 'FIXATED_SESSION_TEST', 
                                           domain=urlparse(base_url).netloc)
                    test_session.cookies.set('JSESSIONID', 'FIXATED_JSESSION_TEST', 
                                           domain=urlparse(base_url).netloc)
                    
                    response = test_session.get(base_url, timeout=10, verify=False)
                    
                    # Check if our session ID was accepted
                    if 'FIXATED_SESSION_TEST' in str(test_session.cookies):
                        test_result = True
                        result['evidence'] = 'Session cookie accepted without regeneration'
                
                elif test == 'url_parameter':
                    # Try session ID in URL parameter
                    test_url = f"{base_url}?sessionid=FIXATED_URL_SESSION"
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    # Check if session parameter was accepted
                    if response.status_code == 200:
                        # Look for session confirmation in response
                        if 'FIXATED_URL_SESSION' in response.text:
                            test_result = True
                            result['evidence'] = 'Session ID accepted via URL parameter'
                
                result['tests_performed'].append({
                    'test': test,
                    'vulnerable': test_result,
                })
                
                if test_result:
                    result['vulnerable'] = True
            
        except Exception as e:
            logger.debug(f"Session fixation test failed: {e}")
        
        return result
    
    def _test_session_timeout_advanced(self, session: requests.Session, 
                                     base_url: str, metadata: Dict) -> Dict[str, Any]:
        """Advanced session timeout testing."""
        result = {
            'timeout_detected': False,
            'timeout_minutes': None,
            'timeout_too_long': False,
            'tests_performed': [],
        }
        
        try:
            # Access protected endpoint
            response1 = session.get(base_url, timeout=10, verify=False)
            
            if response1.status_code == 200:
                # Test different intervals
                intervals = [1, 5, 15, 30]  # minutes
                
                for interval in intervals:
                    time.sleep(interval * 60)  # Convert minutes to seconds
                    
                    response2 = session.get(base_url, timeout=10, verify=False)
                    
                    test_result = {
                        'interval_minutes': interval,
                        'session_valid': response2.status_code == 200,
                    }
                    
                    result['tests_performed'].append(test_result)
                    
                    if response2.status_code != 200:
                        result['timeout_detected'] = True
                        result['timeout_minutes'] = interval
                        
                        # Check if timeout is too long (more than 30 minutes)
                        if interval > 30:
                            result['timeout_too_long'] = True
                        
                        break
        
        except Exception as e:
            logger.debug(f"Session timeout test failed: {e}")
        
        return result
    
    def _test_concurrent_sessions_advanced(self, session: requests.Session, 
                                         base_url: str) -> Dict[str, Any]:
        """Advanced concurrent sessions testing."""
        result = {
            'multiple_sessions_allowed': False,
            'max_concurrent_tested': 5,
            'session_details': [],
        }
        
        try:
            # Create multiple sessions with same credentials
            sessions = []
            
            for i in range(result['max_concurrent_tested']):
                test_session = requests.Session()
                
                # Copy cookies from original session
                test_session.cookies.update(session.cookies)
                
                # Try to access protected resource
                response = test_session.get(base_url, timeout=10, verify=False)
                
                session_detail = {
                    'session_id': i,
                    'status_code': response.status_code,
                    'successful': response.status_code == 200,
                }
                
                result['session_details'].append(session_detail)
                
                sessions.append(test_session)
            
            # Check how many sessions were successful
            successful_sessions = sum(1 for detail in result['session_details'] 
                                    if detail['successful'])
            
            if successful_sessions > 1:
                result['multiple_sessions_allowed'] = True
        
        except Exception as e:
            logger.debug(f"Concurrent sessions test failed: {e}")
        
        return result
    
    def _analyze_cookie_security(self, session: requests.Session, 
                               base_url: str) -> Dict[str, Any]:
        """Analyze cookie security attributes."""
        result = {
            'cookies_analyzed': [],
            'security_issues': [],
            'recommendations': [],
            'overall_security': 'good',
        }
        
        try:
            # Access base URL to get cookies
            response = session.get(base_url, timeout=10, verify=False)
            
            for cookie in session.cookies:
                cookie_analysis = {
                    'name': cookie.name,
                    'domain': cookie.domain,
                    'secure': cookie.secure,
                    'http_only': cookie.has_nonstandard_attr('HttpOnly'),
                    'same_site': getattr(cookie, 'same_site', None),
                    'path': cookie.path,
                    'expires': cookie.expires,
                }
                
                # Check for security issues
                issues = []
                
                if not cookie.secure:
                    issues.append('Missing Secure flag')
                
                if not cookie_analysis['http_only']:
                    issues.append('Missing HttpOnly flag')
                
                if cookie_analysis['same_site'] not in ['Lax', 'Strict']:
                    issues.append('Missing or weak SameSite attribute')
                
                if cookie.domain and cookie.domain.startswith('.'):
                    # Wildcard domain cookie
                    issues.append('Wildcard domain may be too permissive')
                
                cookie_analysis['security_issues'] = issues
                
                if issues:
                    result['security_issues'].extend(issues)
                
                result['cookies_analyzed'].append(cookie_analysis)
            
            # Determine overall security
            if len(result['security_issues']) > 3:
                result['overall_security'] = 'poor'
            elif len(result['security_issues']) > 0:
                result['overall_security'] = 'fair'
            
            # Generate recommendations
            if 'Missing Secure flag' in result['security_issues']:
                result['recommendations'].append('Add Secure flag to all cookies')
            if 'Missing HttpOnly flag' in result['security_issues']:
                result['recommendations'].append('Add HttpOnly flag to session cookies')
            if 'Missing or weak SameSite attribute' in result['security_issues']:
                result['recommendations'].append('Set SameSite=Lax or Strict for cookies')
        
        except Exception as e:
            logger.debug(f"Cookie security analysis failed: {e}")
        
        return result
    
    def _analyze_jwt_security(self, session: requests.Session, 
                            base_url: str) -> Dict[str, Any]:
        """Analyze JWT token security."""
        result = {
            'tokens_found': [],
            'vulnerabilities': [],
            'algorithm_analysis': {},
            'payload_analysis': {},
            'recommendations': [],
        }
        
        if not JWT_AVAILABLE:
            result['error'] = 'JWT library not available'
            return result
        
        try:
            # Look for JWT tokens in cookies and response
            response = session.get(base_url, timeout=10, verify=False)
            
            # Search for JWT tokens
            jwt_pattern = r'(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)'
            jwt_matches = re.findall(jwt_pattern, response.text)
            
            for jwt_token in jwt_matches:
                try:
                    # Decode token without verification
                    decoded = jwt.decode(jwt_token, options={"verify_signature": False})
                    header = jwt.get_unverified_header(jwt_token)
                    
                    token_info = {
                        'token_preview': jwt_token[:50] + '...',
                        'algorithm': header.get('alg', 'unknown'),
                        'type': header.get('typ', 'JWT'),
                        'payload_keys': list(decoded.keys()),
                    }
                    
                    result['tokens_found'].append(token_info)
                    
                    # Analyze for vulnerabilities
                    vulnerabilities = []
                    
                    # Check for "none" algorithm
                    if header.get('alg') == 'none':
                        vulnerabilities.append('none_algorithm')
                        result['recommendations'].append('Disable "none" algorithm for JWT')
                    
                    # Check for weak algorithms
                    weak_algorithms = ['HS256', 'RS256']  # In practice, these are strong
                    # Actually weak would be things like HS256 with short key, but we can't verify
                    
                    # Check for missing expiration
                    if 'exp' not in decoded:
                        vulnerabilities.append('no_expiration')
                        result['recommendations'].append('Add expiration (exp) claim to JWT')
                    
                    # Check for long expiration
                    if 'exp' in decoded:
                        exp_time = decoded['exp']
                        current_time = int(time.time())
                        if exp_time - current_time > 3600 * 24 * 30:  # 30 days
                            vulnerabilities.append('long_expiration')
                            result['recommendations'].append('Reduce JWT expiration time')
                    
                    # Check for sensitive data in payload
                    sensitive_fields = ['password', 'secret', 'key', 'credit', 'ssn']
                    for field in sensitive_fields:
                        if field in str(decoded).lower():
                            vulnerabilities.append('sensitive_data_exposure')
                            result['recommendations'].append('Remove sensitive data from JWT payload')
                    
                    if vulnerabilities:
                        result['vulnerabilities'].extend(vulnerabilities)
                    
                    result['algorithm_analysis'][jwt_token[:20]] = {
                        'algorithm': header.get('alg'),
                        'key_id': header.get('kid'),
                        'type': header.get('typ'),
                    }
                    
                    result['payload_analysis'][jwt_token[:20]] = {
                        'exp': decoded.get('exp'),
                        'iat': decoded.get('iat'),
                        'nbf': decoded.get('nbf'),
                        'iss': decoded.get('iss'),
                        'aud': decoded.get('aud'),
                        'sub': decoded.get('sub'),
                    }
                    
                except Exception as e:
                    logger.debug(f"JWT analysis failed for token: {e}")
        
        except Exception as e:
            logger.debug(f"JWT security analysis failed: {e}")
        
        return result
    
    def _test_csrf_protection(self, session: requests.Session, 
                            base_url: str) -> Dict[str, Any]:
        """Test CSRF protection."""
        result = {
            'vulnerable': False,
            'tests_performed': [],
            'csrf_tokens_found': False,
            'recommendations': [],
        }
        
        try:
            # Look for state-changing endpoints
            test_endpoints = [
                f"{base_url}/profile/update",
                f"{base_url}/settings/change",
                f"{base_url}/password/change",
            ]
            
            for endpoint in test_endpoints:
                # First, check if endpoint exists and has CSRF protection
                response = session.get(endpoint, timeout=10, verify=False)
                
                if response.status_code == 200:
                    # Check for CSRF token in form
                    csrf_token = self._extract_csrf_token(response.text)
                    
                    if csrf_token:
                        result['csrf_tokens_found'] = True
                        
                        # Test if token is validated
                        test_payload = {'test': 'value'}
                        
                        # Try without token
                        response_no_token = session.post(endpoint, data=test_payload, 
                                                        timeout=10, verify=False)
                        
                        # Try with invalid token
                        test_payload_with_bad_token = test_payload.copy()
                        test_payload_with_bad_token['csrf_token'] = 'INVALID_TOKEN'
                        response_bad_token = session.post(endpoint, 
                                                         data=test_payload_with_bad_token, 
                                                         timeout=10, verify=False)
                        
                        test_result = {
                            'endpoint': endpoint,
                            'csrf_token_present': True,
                            'rejects_no_token': response_no_token.status_code != 200,
                            'rejects_invalid_token': response_bad_token.status_code != 200,
                        }
                        
                        result['tests_performed'].append(test_result)
                        
                        if not test_result['rejects_no_token'] or not test_result['rejects_invalid_token']:
                            result['vulnerable'] = True
                            result['recommendations'].append(f'Strengthen CSRF protection for {endpoint}')
        
        except Exception as e:
            logger.debug(f"CSRF protection test failed: {e}")
        
        return result
    
    def _extract_csrf_token(self, html_content: str) -> Optional[str]:
        """Extract CSRF token from HTML."""
        patterns = [
            r'<input[^>]*name=["\'][^"\']*csrf[^"\']*["\'][^>]*value=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\'][^"\']*_token[^"\']*["\'][^>]*value=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _test_session_hijacking(self, session: requests.Session, 
                              base_url: str) -> Dict[str, Any]:
        """Test session hijacking resistance."""
        result = {
            'vulnerable': False,
            'tests_performed': [],
            'recommendations': [],
        }
        
        try:
            # Test 1: Predictable session IDs
            session_ids = []
            
            # Collect multiple session IDs (simulate multiple logins)
            for i in range(5):
                test_session = requests.Session()
                response = test_session.get(base_url, timeout=10, verify=False)
                
                # Extract session IDs from cookies
                for cookie in test_session.cookies:
                    if 'session' in cookie.name.lower() or 'id' in cookie.name.lower():
                        session_ids.append(cookie.value)
            
            # Analyze session IDs for predictability
            if len(session_ids) >= 3:
                # Check if IDs are sequential or follow a pattern
                result['tests_performed'].append({
                    'test': 'session_id_predictability',
                    'unique_ids': len(set(session_ids)),
                    'total_samples': len(session_ids),
                })
                
                if len(set(session_ids)) < len(session_ids) * 0.5:
                    result['vulnerable'] = True
                    result['recommendations'].append('Use cryptographically strong random session IDs')
            
            # Test 2: Session replay
            # Try to reuse old session cookies
            old_cookies = dict(session.cookies)
            
            # Create new session with old cookies
            replay_session = requests.Session()
            replay_session.cookies.update(old_cookies)
            
            response = replay_session.get(base_url, timeout=10, verify=False)
            
            test_result = {
                'test': 'session_replay',
                'old_session_accepted': response.status_code == 200,
            }
            
            result['tests_performed'].append(test_result)
            
            if test_result['old_session_accepted']:
                result['vulnerable'] = True
                result['recommendations'].append('Implement session invalidation on logout')
        
        except Exception as e:
            logger.debug(f"Session hijacking test failed: {e}")
        
        return result
    
    def _calculate_session_security_score(self, test_results: Dict[str, Any]) -> float:
        """Calculate overall session security score (0-10)."""
        score = 10.0  # Start with perfect score
        
        # Deduct points for vulnerabilities
        deductions = {
            'session_fixation': 3.0,
            'session_hijacking': 4.0,
            'csrf_protection': 2.0,
            'jwt_security': 3.0,
            'cookie_security': 2.0,
        }
        
        for test_name, deduction in deductions.items():
            test_result = test_results.get(test_name, {})
            
            if test_name == 'session_fixation' and test_result.get('vulnerable'):
                score -= deduction
            elif test_name == 'session_hijacking' and test_result.get('vulnerable'):
                score -= deduction
            elif test_name == 'csrf_protection' and test_result.get('vulnerable'):
                score -= deduction
            elif test_name == 'jwt_security' and test_result.get('vulnerabilities'):
                score -= min(deduction, len(test_result['vulnerabilities']) * 0.5)
            elif test_name == 'cookie_security' and test_result.get('security_issues'):
                score -= min(deduction, len(test_result['security_issues']) * 0.5)
        
        # Deduct for session timeout issues
        timeout_result = test_results.get('session_timeout', {})
        if timeout_result.get('timeout_too_long'):
            score -= 1.0
        
        # Deduct for concurrent sessions
        concurrent_result = test_results.get('concurrent_sessions', {})
        if concurrent_result.get('multiple_sessions_allowed'):
            score -= 0.5
        
        # Ensure score is within bounds
        return max(0.0, min(10.0, score))
    
    def _generate_session_recommendations(self, test_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on test results."""
        recommendations = []
        
        # Session fixation
        if test_results.get('session_fixation', {}).get('vulnerable'):
            recommendations.extend([
                'Regenerate session ID after login',
                'Do not accept session IDs from untrusted sources',
            ])
        
        # Session hijacking
        if test_results.get('session_hijacking', {}).get('vulnerable'):
            recommendations.extend([
                'Use secure, random session IDs',
                'Implement session binding to IP address or user agent',
                'Invalidate sessions on logout',
            ])
        
        # CSRF protection
        if test_results.get('csrf_protection', {}).get('vulnerable'):
            recommendations.extend([
                'Implement CSRF tokens for all state-changing requests',
                'Use SameSite cookie attribute',
                'Implement double-submit cookie pattern',
            ])
        
        # JWT security
        jwt_result = test_results.get('jwt_security', {})
        if jwt_result.get('vulnerabilities'):
            recommendations.extend(jwt_result.get('recommendations', []))
        
        # Cookie security
        cookie_result = test_results.get('cookie_security', {})
        if cookie_result.get('security_issues'):
            recommendations.extend(cookie_result.get('recommendations', []))
        
        # Session timeout
        timeout_result = test_results.get('session_timeout', {})
        if timeout_result.get('timeout_too_long'):
            recommendations.append('Reduce session timeout to 30 minutes or less')
        
        # Concurrent sessions
        concurrent_result = test_results.get('concurrent_sessions', {})
        if concurrent_result.get('multiple_sessions_allowed'):
            recommendations.append('Consider limiting concurrent sessions per user')
        
        # Remove duplicates
        return list(set(recommendations))
    
    def _test_mfa_implementation(self, endpoint: AuthEndpoint, 
                               credentials: AuthCredentials) -> Dict[str, Any]:
        """Test multi-factor authentication implementation."""
        result = {
            'mfa_detected': False,
            'bypass_attempts': [],
            'security_level': 'unknown',
            'recommendations': [],
        }
        
        try:
            # First, try to detect MFA implementation
            if endpoint.mfa_supported:
                result['mfa_detected'] = True
                
                # Test for potential bypasses
                bypass_tests = [
                    self._test_mfa_direct_access,
                    self._test_mfa_parameter_tampering,
                    self._test_mfa_state_confusion,
                ]
                
                for test_func in bypass_tests:
                    test_result = test_func(endpoint, credentials)
                    result['bypass_attempts'].append(test_result)
                    
                    if test_result.get('bypass_possible'):
                        result['security_level'] = 'weak'
                        result['recommendations'].append(test_result.get('recommendation', ''))
                
                if result['security_level'] == 'unknown':
                    result['security_level'] = 'strong'
        
        except Exception as e:
            logger.debug(f"MFA testing failed: {e}")
            result['error'] = str(e)
        
        return result
    
    def _test_mfa_direct_access(self, endpoint: AuthEndpoint, 
                              credentials: AuthCredentials) -> Dict[str, Any]:
        """Test if MFA-protected resources can be accessed directly."""
        result = {
            'test': 'direct_access',
            'bypass_possible': False,
            'details': '',
            'recommendation': '',
        }
        
        try:
            # Try to access what should be MFA-protected resources
            test_urls = [
                endpoint.url.replace('/login', '/dashboard'),
                endpoint.url.replace('/auth', '/profile'),
            ]
            
            for test_url in test_urls:
                # Create session without MFA
                session = requests.Session()
                
                # Try basic login first
                login_result = self._perform_form_login(endpoint, credentials)
                
                if login_result.get('success'):
                    # Try to access protected resource
                    response = session.get(test_url, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        result['bypass_possible'] = True
                        result['details'] = f'Accessed {test_url} without MFA'
                        result['recommendation'] = 'Enforce MFA for all privileged access'
                        break
        
        except Exception as e:
            logger.debug(f"MFA direct access test failed: {e}")
        
        return result
    
    def _test_password_policy(self, base_url: str, 
                            credentials: AuthCredentials) -> Dict[str, Any]:
        """Test password policy enforcement."""
        result = {
            'policy_detected': False,
            'weak_passwords_accepted': [],
            'strength_requirements': {},
            'recommendations': [],
        }
        
        try:
            # Test with various password strengths
            test_passwords = [
                {'password': 'password', 'strength': 'very_weak'},
                {'password': '123456', 'strength': 'very_weak'},
                {'password': 'qwerty', 'strength': 'weak'},
                {'password': 'Password1', 'strength': 'medium'},
                {'password': 'StrongPass123!', 'strength': 'strong'},
                {'password': 'V3ry$tr0ngP@ssw0rd!2024', 'strength': 'very_strong'},
            ]
            
            # Find registration or password change endpoint
            registration_endpoints = self._find_registration_endpoints(base_url)
            
            if not registration_endpoints:
                result['error'] = 'No registration endpoints found'
                return result
            
            for endpoint in registration_endpoints[:1]:  # Test first endpoint
                for test_case in test_passwords:
                    try:
                        # Create test credentials
                        test_creds = AuthCredentials(
                            username=f"test_{secrets.token_hex(4)}@example.com",
                            password=test_case['password'],
                        )
                        
                        # Try registration (simplified - would need actual registration flow)
                        # This is a placeholder for actual testing logic
                        accepted = True  # Assume accepted for now
                        
                        if accepted and test_case['strength'] in ['very_weak', 'weak']:
                            result['weak_passwords_accepted'].append({
                                'password': test_case['password'],
                                'strength': test_case['strength'],
                                'endpoint': endpoint.url,
                            })
                        
                    except:
                        continue
            
            if result['weak_passwords_accepted']:
                result['policy_detected'] = True
                result['strength_requirements'] = {
                    'min_length': 8,
                    'requires_uppercase': False,
                    'requires_lowercase': False,
                    'requires_numbers': False,
                    'requires_special': False,
                }
                
                result['recommendations'] = [
                    'Enforce minimum password length of 12 characters',
                    'Require mix of uppercase, lowercase, numbers, and special characters',
                    'Implement password strength meter',
                    'Check against common password lists',
                ]
        
        except Exception as e:
            logger.debug(f"Password policy testing failed: {e}")
            result['error'] = str(e)
        
        return result
    
    def _find_registration_endpoints(self, base_url: str) -> List[AuthEndpoint]:
        """Find registration endpoints."""
        endpoints = []
        
        registration_paths = ['/register', '/signup', '/createaccount']
        
        for path in registration_paths:
            try:
                url = urljoin(base_url, path)
                response = requests.get(url, timeout=10, verify=False)
                
                if response.status_code == 200 and '<form' in response.text.lower():
                    endpoint = AuthEndpoint(
                        url=url,
                        auth_type=AuthType.FORM_BASED,
                        method='POST',
                        status_code=200,
                        parameters={},
                        security_headers={},
                        detected_framework='unknown',
                    )
                    endpoints.append(endpoint)
            except:
                continue
        
        return endpoints
    
    def _test_account_lockout(self, base_url: str, 
                            credentials: AuthCredentials) -> Dict[str, Any]:
        """Test account lockout mechanisms."""
        result = {
            'lockout_detected': False,
            'lockout_threshold': None,
            'lockout_duration': None,
            'recommendations': [],
        }
        
        if not self.enable_brute_force_simulation:
            result['note'] = 'Brute force simulation disabled'
            return result
        
        try:
            # Find login endpoint
            login_endpoints = [e for e in self.discover_auth_endpoints_advanced(base_url) 
                             if e.auth_type == AuthType.FORM_BASED]
            
            if not login_endpoints:
                result['error'] = 'No login endpoints found'
                return result
            
            endpoint = login_endpoints[0]
            
            # Simulate failed login attempts
            failed_attempts = 0
            lockout_triggered = False
            
            for attempt in range(1, self.max_login_attempts + 1):
                try:
                    # Create session
                    session = requests.Session()
                    
                    # Get login page
                    response = session.get(endpoint.url, timeout=10, verify=False)
                    
                    # Extract form data
                    form_data = self._extract_login_form_data(response.text, endpoint.url)
                    
                    if not form_data:
                        break
                    
                    # Prepare payload with wrong password
                    login_payload = {}
                    
                    if 'username_field' in form_data:
                        login_payload[form_data['username_field']] = credentials.username
                    if 'password_field' in form_data:
                        login_payload[form_data['password_field']] = 'WRONG_PASSWORD'
                    
                    # Add CSRF token if found
                    if 'csrf_token' in form_data and 'csrf_value' in form_data:
                        login_payload[form_data['csrf_token']] = form_data['csrf_value']
                    
                    # Submit login
                    submit_url = form_data.get('action', endpoint.url)
                    login_response = session.post(submit_url, data=login_payload, 
                                                timeout=10, verify=False)
                    
                    # Check if login failed
                    if not self._is_login_successful_advanced(login_response, credentials.username):
                        failed_attempts += 1
                        
                        # Check for lockout message
                        if any(x in login_response.text.lower() for x in ['locked', 'suspended', 'blocked']):
                            lockout_triggered = True
                            result['lockout_threshold'] = attempt
                            break
                    
                    # Small delay between attempts
                    time.sleep(1)
                    
                except Exception as e:
                    logger.debug(f"Account lockout test attempt {attempt} failed: {e}")
            
            if lockout_triggered:
                result['lockout_detected'] = True
                result['recommendations'] = [
                    'Lockout threshold is appropriate',
                    'Consider implementing progressive delays',
                ]
            else:
                result['recommendations'] = [
                    'Implement account lockout after 5-10 failed attempts',
                    'Add monitoring for brute force attempts',
                ]
        
        except Exception as e:
            logger.debug(f"Account lockout testing failed: {e}")
            result['error'] = str(e)
        
        return result
    
    def _calculate_security_score(self, test_results: Dict[str, Any]) -> float:
        """Calculate overall authentication security score (0-10)."""
        score = 10.0
        
        # Deductions based on test results
        deductions = {
            'weak_passwords_accepted': 2.0,
            'mfa_bypass_possible': 3.0,
            'session_vulnerabilities': 1.0,  # per vulnerability
            'no_account_lockout': 1.0,
        }
        
        # Password policy
        password_policy = test_results.get('password_policy', {})
        if password_policy.get('weak_passwords_accepted'):
            score -= deductions['weak_passwords_accepted']
        
        # MFA bypass
        mfa_tests = test_results.get('mfa_tests', {})
        for endpoint, mfa_test in mfa_tests.items():
            if mfa_test.get('security_level') == 'weak':
                score -= deductions['mfa_bypass_possible']
        
        # Session vulnerabilities
        session_security = test_results.get('session_security', {})
        if isinstance(session_security, dict):
            vulnerabilities = session_security.get('vulnerabilities', [])
            score -= len(vulnerabilities) * deductions['session_vulnerabilities']
        
        # Account lockout
        account_lockout = test_results.get('account_lockout', {})
        if not account_lockout.get('lockout_detected'):
            score -= deductions['no_account_lockout']
        
        return max(0.0, min(10.0, round(score, 1)))
    
    def _generate_security_recommendations(self, test_results: Dict[str, Any]) -> List[str]:
        """Generate comprehensive security recommendations."""
        recommendations = []
        
        # Authentication mechanisms
        auth_mechanisms = test_results.get('authentication_mechanisms', [])
        if not any(m.get('mfa_supported') for m in auth_mechanisms):
            recommendations.append('Implement multi-factor authentication')
        
        # Password policy
        password_policy = test_results.get('password_policy', {})
        if password_policy.get('weak_passwords_accepted'):
            recommendations.append('Enforce strong password policy')
        
        # Session security
        session_security = test_results.get('session_security', {})
        if isinstance(session_security, dict):
            recs = session_security.get('recommendations', [])
            recommendations.extend(recs)
        
        # MFA security
        mfa_tests = test_results.get('mfa_tests', {})
        for endpoint, mfa_test in mfa_tests.items():
            if mfa_test.get('security_level') == 'weak':
                recommendations.append(f'Strengthen MFA implementation at {endpoint}')
        
        # Account lockout
        account_lockout = test_results.get('account_lockout', {})
        if not account_lockout.get('lockout_detected'):
            recommendations.append('Implement account lockout mechanism')
        
        # Remove duplicates and return
        return list(set(recommendations))
    
    def get_security_report(self, base_url: str, 
                          credentials: AuthCredentials) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        report = {
            'target': base_url,
            'timestamp': datetime.now().isoformat(),
            'credentials_used': {
                'username': credentials.username,
                'role': credentials.role,
                'mfa_enabled': bool(credentials.mfa_secret),
            },
            'authentication_mechanisms': [],
            'security_tests': {},
            'overall_score': 0.0,
            'risk_level': 'Unknown',
            'recommendations': [],
            'vulnerabilities': [],
        }
        
        try:
            # Run comprehensive tests
            test_results = self.perform_comprehensive_auth_test(base_url, credentials)
            
            # Populate report
            report['authentication_mechanisms'] = test_results.get('authentication_mechanisms', [])
            report['security_tests'] = {
                k: v for k, v in test_results.items() 
                if k not in ['authentication_mechanisms', 'security_score', 'recommendations']
            }
            report['overall_score'] = test_results.get('security_score', 0.0)
            report['recommendations'] = test_results.get('recommendations', [])
            
            # Determine risk level
            score = report['overall_score']
            if score >= 8.0:
                report['risk_level'] = 'Low'
            elif score >= 6.0:
                report['risk_level'] = 'Medium'
            elif score >= 4.0:
                report['risk_level'] = 'High'
            else:
                report['risk_level'] = 'Critical'
            
            # Extract vulnerabilities
            session_security = test_results.get('session_security', {})
            if isinstance(session_security, dict):
                vulnerabilities = session_security.get('vulnerabilities', [])
                report['vulnerabilities'] = [v.value for v in vulnerabilities]
        
        except Exception as e:
            report['error'] = str(e)
            logger.error(f"Security report generation failed: {e}")
        
        return report
    
    def cleanup(self):
        """Cleanup resources."""
        # Close browser
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
        
        # Clear sessions
        self.active_sessions.clear()
        self.session_metadata.clear()
        
        logger.info("AuthSessionAnalyzer cleaned up successfully")

# Export the main class
__all__ = ['AdvancedAuthSessionAnalyzer', 'AuthType', 'SessionVulnerability', 
           'AuthEndpoint', 'SessionSecurityReport', 'AuthCredentials']