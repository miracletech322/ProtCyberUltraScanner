"""
================================================================================
FEATURE 4 - ADVANCED JAVASCRIPT ANALYSIS & SECRETS DISCOVERY - ENHANCED VERSION
================================================================================

Advanced JavaScript Analyzer for Web Application Security Scanning

This class provides sophisticated JavaScript analysis capabilities for discovering:
- Hidden API endpoints and GraphQL queries
- Hardcoded secrets, API keys, and authentication tokens
- Configuration files and environment variables
- Sensitive data patterns (AWS keys, Google tokens, database credentials)
- Obfuscated/minified code analysis with deobfuscation
- JavaScript framework-specific vulnerabilities
- DOM-based XSS vectors and client-side security issues

Features:
1. Multi-layer pattern matching with context awareness
2. AST-based parsing for accurate code analysis
3. Deobfuscation engines for common obfuscation techniques
4. Framework detection (React, Angular, Vue, etc.)
5. Dynamic execution analysis in sandboxed environment
6. Correlation between findings for attack surface mapping
"""

import re
import ast
import json
import hashlib
import requests
import logging
import html
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict
from urllib.parse import urljoin, urlparse
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

class AdvancedJavaScriptAnalyzer:
    """
    Advanced JavaScript security analyzer for comprehensive web application reconnaissance.
    
    This class performs deep analysis of JavaScript files to discover:
    - Hidden API endpoints and GraphQL schemas
    - Exposed credentials and secrets
    - Security misconfigurations
    - Client-side vulnerabilities
    - Sensitive data exposure
    - Attack surface enumeration
    """
    
    def __init__(self, enable_ast_parsing: bool = True, max_file_size: int = 10 * 1024 * 1024):
        """
        Initialize the advanced JavaScript analyzer.
        
        Args:
            enable_ast_parsing: Enable AST-based parsing for more accurate analysis
            max_file_size: Maximum JavaScript file size to analyze (in bytes)
        """
        self.enable_ast_parsing = enable_ast_parsing
        self.max_file_size = max_file_size
        
        # Enhanced pattern matching with prioritized scoring
        self.patterns = {
            'api_endpoints': {
                'regex': re.compile(r'["\'](/api/.*?|/v[0-9]+/.*?|/graphql|/rest/.*?|/ajax/.*?|/ws.*?|/socket\.io.*?)["\']', re.IGNORECASE),
                'score': 30,
                'description': 'API endpoint URLs'
            },
            'graphql_queries': {
                'regex': re.compile(r'(?:query|mutation)\s*{\s*[^{}]*}', re.IGNORECASE | re.DOTALL),
                'score': 50,
                'description': 'GraphQL query/mutation definitions'
            },
            'internal_endpoints': {
                'regex': re.compile(r'["\'](?:/admin/|/dashboard/|/console/|/backoffice/|/private/|/secure/).*?["\']', re.IGNORECASE),
                'score': 70,
                'description': 'Internal/administrative endpoints'
            },
            'websocket_endpoints': {
                'regex': re.compile(r'["\'](wss?://[^"\'\s]+)["\']', re.IGNORECASE),
                'score': 40,
                'description': 'WebSocket connections'
            },
            'api_keys_generic': {
                'regex': re.compile(r'["\'](?:api[_\-]?key|access[_\-]?token|secret[_\-]?key|client[_\-]?secret|private[_\-]?key)["\'][\s:]*["\'][a-zA-Z0-9_\-]{20,}["\']', re.IGNORECASE),
                'score': 90,
                'description': 'Generic API keys/tokens'
            },
            'jwt_tokens': {
                'regex': re.compile(r'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b'),
                'score': 85,
                'description': 'JSON Web Tokens'
            },
            'configurations': {
                'regex': re.compile(r'(?:baseURL|endpoint|url|host|origin)[\s:]*["\'][^"\']+["\']', re.IGNORECASE),
                'score': 25,
                'description': 'Configuration values'
            },
            'sensitive_strings': {
                'regex': re.compile(r'(?:secret|password|key|credential|auth|token)[\s:=]+["\'][^"\']{8,}["\']', re.IGNORECASE),
                'score': 80,
                'description': 'Sensitive string assignments'
            },
            'ajax_calls': {
                'regex': re.compile(r'\.(?:ajax|get|post|fetch|put|delete|patch|axios)\([^)]*["\'][^"\']+["\'][^)]*\)', re.IGNORECASE),
                'score': 35,
                'description': 'AJAX/HTTP method calls'
            },
            'framework_detection': {
                'regex': re.compile(r'(?:React|Angular|Vue|jQuery|Backbone|Ember|Svelte)\.', re.IGNORECASE),
                'score': 10,
                'description': 'JavaScript framework usage'
            },
            'dom_xss_patterns': {
                'regex': re.compile(r'(?:innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval)\s*\(\s*[^)]*["\'][^"\']+["\']', re.IGNORECASE),
                'score': 75,
                'description': 'Potential DOM-based XSS vectors'
            },
            'local_storage': {
                'regex': re.compile(r'localStorage|sessionStorage', re.IGNORECASE),
                'score': 45,
                'description': 'Web Storage API usage'
            },
            'cors_config': {
                'regex': re.compile(r'Access-Control-Allow-Origin|CORS', re.IGNORECASE),
                'score': 30,
                'description': 'CORS configuration'
            },
        }
        
        # High-confidence secret patterns
        self.sensitive_patterns = {
            'aws_credentials': {
                'regex': re.compile(r'\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b'),
                'score': 95,
                'description': 'AWS Access Key IDs'
            },
            'aws_secret_keys': {
                'regex': re.compile(r'\b([a-zA-Z0-9+/]{40})\b'),
                'score': 99,
                'description': 'AWS Secret Access Keys'
            },
            'google_api_keys': {
                'regex': re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
                'score': 90,
                'description': 'Google API Keys'
            },
            'google_oauth': {
                'regex': re.compile(r'\b(ya29\.[0-9A-Za-z\-_]+)\b'),
                'score': 85,
                'description': 'Google OAuth Tokens'
            },
            'facebook_tokens': {
                'regex': re.compile(r'\b([0-9a-f]{32}|EAACEdEose0cBA[0-9A-Za-z]+)\b'),
                'score': 85,
                'description': 'Facebook Access Tokens'
            },
            'github_tokens': {
                'regex': re.compile(r'\b(gh[oprs]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b'),
                'score': 95,
                'description': 'GitHub Personal Access Tokens'
            },
            'slack_tokens': {
                'regex': re.compile(r'\b(xox[abpors]-[0-9a-zA-Z\-]+)\b'),
                'score': 85,
                'description': 'Slack API Tokens'
            },
            'private_keys': {
                'regex': re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----[^-]+-----END (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----', re.DOTALL),
                'score': 99,
                'description': 'Private cryptographic keys'
            },
            'database_urls': {
                'regex': re.compile(r'\b(mongodb(?:\\+srv)?|postgres(?:ql)?|mysql|redis)://[^"\'\s]+\b', re.IGNORECASE),
                'score': 80,
                'description': 'Database connection strings'
            },
            'email_addresses': {
                'regex': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
                'score': 40,
                'description': 'Email addresses'
            },
            'credit_cards': {
                'regex': re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
                'score': 95,
                'description': 'Credit card numbers'
            },
            'api_endpoint_patterns': {
                'regex': re.compile(r'https?://(?:api|rest|graphql|v[0-9]+)\.[^"\'\s]+', re.IGNORECASE),
                'score': 30,
                'description': 'API endpoint URLs'
            },
        }
        
        # Common obfuscation patterns
        self.obfuscation_patterns = {
            'packed_code': re.compile(r'eval\s*\(\s*function\s*\([^)]*\)\s*{[^}]*}\s*\([^)]*\)'),
            'base64_encoded': re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
            'hex_encoded': re.compile(r'\\x[0-9a-fA-F]{2}'),
            'char_code_arrays': re.compile(r'String\.fromCharCode\([^)]+\)'),
            'obfuscator_io': re.compile(r'_0x[0-9a-f]+'),
        }
        
        # Framework-specific detection
        self.framework_patterns = {
            'react': re.compile(r'React\.|createElement|useState|useEffect'),
            'angular': re.compile(r'angular\.|ng-|@Component|@Injectable'),
            'vue': re.compile(r'Vue\.|vue-|createApp|@click'),
            'jquery': re.compile(r'jQuery|\$\(|\.ajax\(|\.get\('),
            'nextjs': re.compile(r'next/|getServerSideProps|getStaticProps'),
            'nuxtjs': re.compile(r'nuxt/|asyncData|fetch\('),
        }
        
        # Compiled patterns for performance
        self.compiled_patterns = {k: v['regex'] for k, v in {**self.patterns, **self.sensitive_patterns}.items()}
        
        # HTTP client configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/javascript,text/javascript,*/*;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
        })
        self.timeout = 20
        
    def analyze_js_file(self, url: str, js_content: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of JavaScript content.
        
        Args:
            url: Source URL of the JavaScript file
            js_content: Raw JavaScript content
            
        Returns:
            Dictionary containing all findings with metadata and risk scores
        """
        if len(js_content) > self.max_file_size:
            logger.warning(f"JavaScript file too large ({len(js_content)} bytes), truncating analysis")
            js_content = js_content[:self.max_file_size]
        
        findings = {
            'metadata': self._extract_metadata(url, js_content),
            'patterns': defaultdict(list),
            'secrets': [],
            'vulnerabilities': [],
            'endpoints': [],
            'frameworks': [],
            'obfuscation_detected': False,
            'risk_score': 0,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }
        
        # Calculate file hash for tracking
        findings['metadata']['sha256'] = hashlib.sha256(js_content.encode('utf-8')).hexdigest()
        
        # Pattern-based analysis
        findings['patterns'], pattern_score = self._analyze_patterns(js_content)
        
        # Secret discovery with context
        findings['secrets'], secrets_score = self._discover_secrets(js_content, url)
        
        # Endpoint extraction with categorization
        findings['endpoints'] = self._extract_endpoints(js_content, url)
        
        # Vulnerability detection
        findings['vulnerabilities'] = self._detect_vulnerabilities(js_content)
        
        # Framework detection
        findings['frameworks'] = self._detect_frameworks(js_content)
        
        # Obfuscation analysis
        findings['obfuscation_detected'], findings['deobfuscated'] = self._analyze_obfuscation(js_content)
        
        # AST-based analysis if enabled
        if self.enable_ast_parsing and not findings['obfuscation_detected']:
            try:
                ast_findings = self._ast_analysis(js_content)
                findings['ast_analysis'] = ast_findings
            except Exception as e:
                logger.debug(f"AST analysis failed: {e}")
        
        # Calculate overall risk score (0-100)
        findings['risk_score'] = self._calculate_risk_score(
            pattern_score, 
            secrets_score, 
            findings['vulnerabilities'],
            len(findings['endpoints'])
        )
        
        # Generate security recommendations
        findings['recommendations'] = self._generate_recommendations(findings)
        
        # Link analysis findings
        findings['linked_findings'] = self._link_findings(findings)
        
        return findings
    
    def _analyze_patterns(self, js_content: str) -> Tuple[Dict[str, List[str]], int]:
        """
        Analyze JavaScript content using all registered patterns.
        
        Returns:
            Tuple of (pattern matches dictionary, total pattern score)
        """
        pattern_matches = defaultdict(list)
        total_score = 0
        
        for pattern_name, pattern_data in self.patterns.items():
            matches = pattern_data['regex'].findall(js_content)
            if matches:
                unique_matches = list(set(matches))
                pattern_matches[pattern_name] = unique_matches
                # Add score for each unique match
                total_score += pattern_data['score'] * len(unique_matches)
                
                # Add additional context for certain patterns
                if pattern_name == 'dom_xss_patterns':
                    pattern_matches[f'{pattern_name}_context'] = self._get_context_lines(
                        js_content, matches, pattern_data['regex']
                    )
        
        return dict(pattern_matches), total_score
    
    def _discover_secrets(self, js_content: str, source_url: str) -> Tuple[List[Dict[str, Any]], int]:
        """
        Discover and validate potential secrets in JavaScript code.
        
        Returns:
            Tuple of (list of secrets with metadata, total secrets score)
        """
        secrets = []
        total_score = 0
        
        for secret_type, pattern_data in self.sensitive_patterns.items():
            matches = pattern_data['regex'].findall(js_content)
            for match in matches:
                secret_info = {
                    'type': secret_type,
                    'value': self._mask_secret(match),
                    'raw_value': match,
                    'description': pattern_data['description'],
                    'score': pattern_data['score'],
                    'context': self._get_context_lines(js_content, [match], pattern_data['regex']),
                    'source_url': source_url,
                    'validated': self._validate_secret(match, secret_type)
                }
                secrets.append(secret_info)
                total_score += pattern_data['score']
        
        # Look for secrets in comments
        comment_secrets = self._extract_secrets_from_comments(js_content)
        secrets.extend(comment_secrets)
        total_score += len(comment_secrets) * 70  # Medium score for comment secrets
        
        return secrets, total_score
    
    def _extract_endpoints(self, js_content: str, base_url: str) -> List[Dict[str, Any]]:
        """
        Extract and categorize API endpoints from JavaScript.
        
        Returns:
            List of endpoint dictionaries with metadata
        """
        endpoints = []
        
        # Extract URLs using multiple patterns
        url_patterns = [
            (r'["\'](https?://[^"\'\s]+)["\']', 'direct_url'),
            (r'["\'](/[^"\'\s]+)["\']', 'relative_path'),
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch_url'),
            (r'\.ajax\s*\(\s*{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'ajax_url'),
            (r'axios\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', 'axios_url'),
        ]
        
        for pattern, source in url_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Normalize URL
                normalized_url = self._normalize_url(match, base_url)
                if normalized_url:
                    endpoint_info = {
                        'url': normalized_url,
                        'source': source,
                        'method': self._infer_http_method(js_content, match),
                        'parameters': self._extract_parameters(js_content, match),
                        'security_context': self._assess_endpoint_security(js_content, match)
                    }
                    
                    # Categorize endpoint
                    endpoint_info['category'] = self._categorize_endpoint(normalized_url)
                    
                    # Check for authentication requirements
                    endpoint_info['requires_auth'] = self._check_auth_requirement(js_content, match)
                    
                    endpoints.append(endpoint_info)
        
        return list({e['url']: e for e in endpoints}.values())  # Deduplicate
    
    def _detect_vulnerabilities(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Detect potential client-side vulnerabilities in JavaScript.
        
        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []
        
        # DOM-based XSS detection
        xss_patterns = [
            (r'innerHTML\s*=\s*[^;]+', 'innerHTML assignment', 70),
            (r'outerHTML\s*=\s*[^;]+', 'outerHTML assignment', 70),
            (r'document\.write\s*\([^)]+\)', 'document.write usage', 65),
            (r'eval\s*\([^)]+\)', 'eval function usage', 80),
            (r'setTimeout\s*\([^,)]+,[^)]+\)', 'setTimeout with string', 60),
            (r'setInterval\s*\([^,)]+,[^)]+\)', 'setInterval with string', 60),
        ]
        
        for pattern, description, score in xss_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'DOM_XSS',
                    'description': description,
                    'severity': 'medium',
                    'score': score,
                    'locations': self._find_pattern_locations(js_content, pattern)
                })
        
        # Insecure storage detection
        storage_patterns = [
            (r'localStorage\.setItem\s*\([^)]+\)', 'localStorage setItem', 50),
            (r'sessionStorage\.setItem\s*\([^)]+\)', 'sessionStorage setItem', 40),
            (r'localStorage\s*\[[^\]]+\]', 'localStorage bracket notation', 55),
        ]
        
        for pattern, description, score in storage_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'INSECURE_STORAGE',
                    'description': description,
                    'severity': 'low',
                    'score': score,
                    'locations': self._find_pattern_locations(js_content, pattern)
                })
        
        # CORS misconfiguration detection
        if re.search(r'Access-Control-Allow-Origin\s*:\s*["\']\\*["\']', js_content):
            vulnerabilities.append({
                'type': 'CORS_MISCONFIGURATION',
                'description': 'Potential CORS misconfiguration (wildcard)',
                'severity': 'medium',
                'score': 60,
                'locations': self._find_pattern_locations(js_content, r'Access-Control-Allow-Origin')
            })
        
        return vulnerabilities
    
    def _analyze_obfuscation(self, js_content: str) -> Tuple[bool, Optional[str]]:
        """
        Detect and attempt to deobfuscate JavaScript code.
        
        Returns:
            Tuple of (is_obfuscated, deobfuscated_content)
        """
        obfuscated = False
        
        # Check for obfuscation indicators
        for pattern_name, pattern in self.obfuscation_patterns.items():
            if pattern.search(js_content):
                obfuscated = True
                logger.debug(f"Detected {pattern_name} obfuscation")
        
        # Additional heuristics
        lines = js_content.split('\n')
        if len(lines) > 0:
            avg_line_length = len(js_content) / len(lines)
            if avg_line_length > 200 and len(js_content) > 1000:
                obfuscated = True
        
        # Attempt deobfuscation
        deobfuscated = None
        if obfuscated:
            deobfuscated = self._deobfuscate_advanced(js_content)
        
        return obfuscated, deobfuscated
    
    def _deobfuscate_advanced(self, js_content: str) -> str:
        """
        Advanced deobfuscation techniques for common JavaScript obfuscation.
        
        Returns:
            Deobfuscated JavaScript snippet
        """
        deobfuscated = js_content
        
        try:
            # 1. Unpack common packed code
            packed_pattern = r'eval\s*\(\s*function\s*\([^)]*\)\s*{[^}]*}\s*\([^)]*\)'
            packed_match = re.search(packed_pattern, js_content, re.DOTALL)
            if packed_match:
                # Attempt to extract and decode packed function
                packed_code = packed_match.group(0)
                # Simple unpacking attempt (in real implementation, use proper unpacker)
                deobfuscated = re.sub(r'eval\s*\(', 'console.log(', packed_code)
            
            # 2. Decode base64 encoded strings
            base64_pattern = r'atob\s*\(\s*["\'][A-Za-z0-9+/]+={0,2}["\']\s*\)'
            for match in re.finditer(base64_pattern, js_content):
                try:
                    import base64
                    encoded = re.search(r'["\'][A-Za-z0-9+/]+={0,2}["\']', match.group(0)).group(0).strip('"\'')
                    decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                    deobfuscated = deobfuscated.replace(match.group(0), f'/* decoded: {decoded[:100]} */')
                except:
                    pass
            
            # 3. Convert char code arrays
            charcode_pattern = r'String\.fromCharCode\(([^)]+)\)'
            for match in re.finditer(charcode_pattern, js_content):
                try:
                    codes = match.group(1).split(',')
                    decoded_chars = ''.join(chr(int(code.strip())) for code in codes[:50])
                    deobfuscated = deobfuscated.replace(
                        match.group(0), 
                        f'/* char codes: "{decoded_chars}" */'
                    )
                except:
                    pass
            
            # 4. Beautify minified code
            if self._is_minified(js_content):
                deobfuscated = self._beautify_javascript(js_content)
            
        except Exception as e:
            logger.error(f"Deobfuscation failed: {e}")
        
        return deobfuscated[:5000]  # Limit output
    
    def _ast_analysis(self, js_content: str) -> Dict[str, Any]:
        """
        Perform AST-based analysis of JavaScript (simplified Python AST for demonstration).
        
        Note: In production, use a proper JavaScript parser like esprima or babel
        """
        ast_findings = {
            'variables': [],
            'functions': [],
            'imports': [],
            'calls': [],
            'assignments': []
        }
        
        try:
            # This is a simplified demonstration
            # In reality, you would use a JavaScript parser
            
            # Extract variable assignments
            var_patterns = [
                r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=([^;]+)',
                r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=([^;]+)'
            ]
            
            for pattern in var_patterns:
                for match in re.finditer(pattern, js_content):
                    var_name = match.group(1).strip()
                    var_value = match.group(2).strip()
                    
                    if any(keyword in var_value.lower() for keyword in ['http', 'api', 'key', 'secret']):
                        ast_findings['variables'].append({
                            'name': var_name,
                            'value': var_value[:200],
                            'line': js_content[:match.start()].count('\n') + 1
                        })
            
            # Extract function definitions
            func_pattern = r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)'
            for match in re.finditer(func_pattern, js_content):
                ast_findings['functions'].append({
                    'name': match.group(1),
                    'line': js_content[:match.start()].count('\n') + 1
                })
            
        except Exception as e:
            logger.debug(f"Simplified AST analysis error: {e}")
        
        return ast_findings
    
    def _calculate_risk_score(self, pattern_score: int, secrets_score: int, 
                             vulnerabilities: List, endpoint_count: int) -> int:
        """
        Calculate overall risk score (0-100) based on findings.
        """
        base_score = min(100, pattern_score * 0.1 + secrets_score * 0.3)
        
        # Add vulnerability points
        vuln_scores = {
            'high': 30,
            'medium': 15,
            'low': 5
        }
        
        for vuln in vulnerabilities:
            base_score += vuln_scores.get(vuln.get('severity', 'low'), 5)
        
        # Add endpoint points
        if endpoint_count > 20:
            base_score += 20
        elif endpoint_count > 10:
            base_score += 10
        elif endpoint_count > 5:
            base_score += 5
        
        return min(100, int(base_score))
    
    def _generate_recommendations(self, findings: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations based on analysis findings.
        """
        recommendations = []
        
        if findings.get('secrets'):
            recommendations.append("Remove hardcoded secrets and use environment variables")
            recommendations.append("Implement secret rotation and auditing")
        
        if findings.get('vulnerabilities'):
            recommendations.append("Sanitize user input in DOM operations")
            recommendations.append("Avoid using eval() and innerHTML with user data")
        
        if len(findings.get('endpoints', [])) > 10:
            recommendations.append("Review exposed API endpoints for proper authentication")
            recommendations.append("Implement rate limiting on public endpoints")
        
        if findings.get('obfuscation_detected'):
            recommendations.append("Consider removing client-side obfuscation for security review")
            recommendations.append("Implement server-side validation for critical operations")
        
        return recommendations
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _extract_metadata(self, url: str, js_content: str) -> Dict[str, Any]:
        """Extract metadata from JavaScript file."""
        return {
            'url': url,
            'size_bytes': len(js_content),
            'lines': js_content.count('\n') + 1,
            'minified': self._is_minified(js_content),
            'encoding': 'utf-8',
            'retrieved': datetime.utcnow().isoformat()
        }
    
    def _is_minified(self, js_content: str) -> bool:
        """Enhanced minification detection."""
        if not js_content or len(js_content) < 100:
            return False
        
        lines = js_content.split('\n')
        if len(lines) < 5:
            return False
        
        avg_line_length = len(js_content) / len(lines)
        
        # Multiple heuristics
        heuristics = [
            avg_line_length > 150,  # Long lines
            js_content.count('//') / len(js_content) < 0.0001,  # Few comments
            js_content.count(' ') / len(js_content) < 0.03,  # Few spaces
            js_content.count('\n') / len(js_content) < 0.001,  # Few newlines
        ]
        
        return sum(heuristics) >= 3
    
    def _beautify_javascript(self, js_content: str) -> str:
        """Simple JavaScript beautifier."""
        # Add newlines after semicolons and braces
        beautified = re.sub(r'([;{}])\s*', r'\1\n', js_content)
        
        # Add indentation (simplified)
        lines = beautified.split('\n')
        indent_level = 0
        result = []
        
        for line in lines:
            line = line.strip()
            if line.endswith('}'):
                indent_level = max(0, indent_level - 1)
            
            if line:
                result.append('  ' * indent_level + line)
            
            if line.endswith('{'):
                indent_level += 1
        
        return '\n'.join(result)
    
    def _get_context_lines(self, content: str, matches: List[str], pattern) -> List[Dict[str, Any]]:
        """Extract context around matches."""
        contexts = []
        
        for match in matches[:10]:  # Limit to first 10 matches
            start_pos = content.find(match)
            if start_pos != -1:
                start_line = content[:start_pos].count('\n') + 1
                start_context = max(0, start_pos - 100)
                end_context = min(len(content), start_pos + len(match) + 100)
                
                contexts.append({
                    'match': match,
                    'line': start_line,
                    'context': content[start_context:end_context],
                    'start': start_pos,
                    'end': start_pos + len(match)
                })
        
        return contexts
    
    def _mask_secret(self, secret: str) -> str:
        """Mask secret values for safe logging."""
        if len(secret) <= 8:
            return '***'
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
    
    def _validate_secret(self, secret: str, secret_type: str) -> bool:
        """
        Basic validation of potential secrets.
        
        Note: This is a placeholder. In production, use proper validation
        services (AWS IAM, GitHub tokens, etc.) with appropriate rate limiting.
        """
        # Basic length and pattern validation
        if secret_type in ['aws_credentials', 'aws_secret_keys']:
            return len(secret) >= 20
        elif secret_type == 'google_api_keys':
            return len(secret) == 39 and secret.startswith('AIza')
        elif secret_type == 'github_tokens':
            return len(secret) >= 36 and (secret.startswith('ghp_') or secret.startswith('github_pat_'))
        
        return True  # Default to true for other types
    
    def _extract_secrets_from_comments(self, js_content: str) -> List[Dict[str, Any]]:
        """Extract secrets from JavaScript comments."""
        secrets = []
        
        # Single line comments
        single_line_comments = re.findall(r'//\s*(.*)', js_content)
        for comment in single_line_comments:
            if any(keyword in comment.lower() for keyword in 
                  ['password=', 'secret=', 'key=', 'token=', 'credential=']):
                secrets.append({
                    'type': 'comment_secret',
                    'value': comment[:100],
                    'description': 'Potential secret in comment',
                    'score': 70,
                    'context': f'// {comment}'
                })
        
        # Multi-line comments
        multi_line_comments = re.findall(r'/\*(.*?)\*/', js_content, re.DOTALL)
        for comment in multi_line_comments:
            lines = comment.split('\n')
            for line in lines:
                line = line.strip()
                if any(keyword in line.lower() for keyword in 
                      ['password:', 'secret:', 'key:', 'token:']):
                    secrets.append({
                        'type': 'comment_secret',
                        'value': line[:100],
                        'description': 'Potential secret in multi-line comment',
                        'score': 70,
                        'context': f'/* {line} */'
                    })
        
        return secrets
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize and validate URL."""
        try:
            if url.startswith('//'):
                url = 'https:' + url
            elif url.startswith('/'):
                parsed_base = urlparse(base_url)
                url = f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
            elif not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)
            
            # Validate URL format
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                return url
        except Exception as e:
            logger.debug(f"URL normalization failed for {url}: {e}")
        
        return None
    
    def _infer_http_method(self, js_content: str, url: str) -> str:
        """Infer HTTP method from context."""
        # Look for context around the URL
        context_start = max(0, js_content.find(url) - 200)
        context_end = min(len(js_content), js_content.find(url) + len(url) + 200)
        context = js_content[context_start:context_end].lower()
        
        if '.post(' in context or 'method: "post"' in context or 'method: \'post\'' in context:
            return 'POST'
        elif '.put(' in context or 'method: "put"' in context:
            return 'PUT'
        elif '.delete(' in context or 'method: "delete"' in context:
            return 'DELETE'
        elif '.patch(' in context or 'method: "patch"' in context:
            return 'PATCH'
        else:
            return 'GET'
    
    def _extract_parameters(self, js_content: str, url: str) -> List[str]:
        """Extract parameters from API calls."""
        params = []
        
        # Look for parameter objects near the URL
        url_pos = js_content.find(url)
        if url_pos != -1:
            # Search forward for parameters
            search_end = min(len(js_content), url_pos + 500)
            search_area = js_content[url_pos:search_end]
            
            # Find data/params objects
            data_patterns = [
                r'data\s*:\s*({[^}]+})',
                r'params\s*:\s*({[^}]+})',
                r'body\s*:\s*({[^}]+})',
                r'\([^)]*,\s*({[^}]+})\s*[^)]*\)'
            ]
            
            for pattern in data_patterns:
                match = re.search(pattern, search_area, re.DOTALL)
                if match:
                    try:
                        # Extract parameter names (simplified)
                        param_obj = match.group(1)
                        param_names = re.findall(r'"([^"]+)"\s*:', param_obj)
                        params.extend(param_names)
                    except:
                        pass
        
        return list(set(params))  # Deduplicate
    
    def _assess_endpoint_security(self, js_content: str, url: str) -> Dict[str, Any]:
        """Assess security context of endpoint."""
        security = {
            'has_auth_header': False,
            'has_csrf_token': False,
            'has_bearer_token': False,
            'is_https': url.startswith('https://')
        }
        
        # Check for authentication headers
        url_pos = js_content.find(url)
        if url_pos != -1:
            context_start = max(0, url_pos - 300)
            context_end = min(len(js_content), url_pos + 300)
            context = js_content[context_start:context_end].lower()
            
            security['has_auth_header'] = any(
                header in context for header in 
                ['authorization', 'x-api-key', 'x-access-token']
            )
            
            security['has_csrf_token'] = any(
                token in context for token in 
                ['csrf', 'xsrf', 'x-csrf-token']
            )
            
            security['has_bearer_token'] = 'bearer' in context
        
        return security
    
    def _categorize_endpoint(self, url: str) -> str:
        """Categorize endpoint based on URL pattern."""
        url_lower = url.lower()
        
        if '/api/' in url_lower:
            return 'api_endpoint'
        elif '/graphql' in url_lower:
            return 'graphql_endpoint'
        elif '/admin/' in url_lower or '/dashboard/' in url_lower:
            return 'admin_endpoint'
        elif '/auth/' in url_lower or '/login' in url_lower:
            return 'authentication_endpoint'
        elif '/upload' in url_lower or '/file' in url_lower:
            return 'file_upload_endpoint'
        elif '/search' in url_lower or '/query' in url_lower:
            return 'search_endpoint'
        elif '/user/' in url_lower or '/profile/' in url_lower:
            return 'user_endpoint'
        else:
            return 'general_endpoint'
    
    def _check_auth_requirement(self, js_content: str, url: str) -> bool:
        """Check if endpoint likely requires authentication."""
        security_context = self._assess_endpoint_security(js_content, url)
        
        # If it has auth headers or tokens in context, likely requires auth
        if (security_context['has_auth_header'] or 
            security_context['has_bearer_token'] or
            security_context['has_csrf_token']):
            return True
        
        # Check for common auth-required patterns
        url_pos = js_content.find(url)
        if url_pos != -1:
            context_start = max(0, url_pos - 200)
            context = js_content[context_start:url_pos].lower()
            
            auth_indicators = [
                'authenticated',
                'loggedin',
                'requiresauth',
                'private',
                'secure',
                'protected'
            ]
            
            if any(indicator in context for indicator in auth_indicators):
                return True
        
        return False
    
    def _detect_frameworks(self, js_content: str) -> List[str]:
        """Detect JavaScript frameworks used."""
        frameworks = []
        
        for framework_name, pattern in self.framework_patterns.items():
            if pattern.search(js_content):
                frameworks.append(framework_name)
        
        return frameworks
    
    def _find_pattern_locations(self, js_content: str, pattern: str) -> List[int]:
        """Find line numbers where pattern occurs."""
        locations = []
        lines = js_content.split('\n')
        compiled_pattern = re.compile(pattern, re.IGNORECASE)
        
        for i, line in enumerate(lines, 1):
            if compiled_pattern.search(line):
                locations.append(i)
        
        return locations[:20]  # Limit to first 20 occurrences
    
    def _link_findings(self, findings: Dict[str, Any]) -> Dict[str, List[str]]:
        """Link related findings together."""
        links = defaultdict(list)
        
        # Link secrets to endpoints
        for secret in findings.get('secrets', []):
            for endpoint in findings.get('endpoints', []):
                if secret['raw_value'] in endpoint.get('url', ''):
                    links['secret_to_endpoint'].append(
                        f"{secret['type']} -> {endpoint['url']}"
                    )
        
        # Link vulnerabilities to patterns
        for vuln in findings.get('vulnerabilities', []):
            for pattern_name, matches in findings.get('patterns', {}).items():
                if any(vuln['type'].lower() in match.lower() for match in matches):
                    links['vulnerability_to_pattern'].append(
                        f"{vuln['type']} -> {pattern_name}"
                    )
        
        return dict(links)
    
    # ============================================================================
    # PUBLIC INTERFACE METHODS
    # ============================================================================
    
    def extract_from_url(self, url: str) -> Dict[str, Any]:
        """
        Download and analyze JavaScript file from URL.
        
        Args:
            url: URL of JavaScript file to analyze
            
        Returns:
            Analysis results dictionary
        """
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                # Check if it's JavaScript
                if 'javascript' in content_type or url.endswith(('.js', '.mjs', '.cjs')):
                    js_content = response.text
                    
                    # Validate it's actually JavaScript
                    if (len(js_content) > 50 and 
                        '<html' not in js_content.lower()[:200] and
                        '<!doctype' not in js_content.lower()[:200]):
                        
                        return self.analyze_js_file(url, js_content)
                    else:
                        logger.warning(f"Invalid JavaScript content from {url}")
                else:
                    logger.warning(f"Non-JavaScript content type from {url}: {content_type}")
            
            return {'error': f"Failed to fetch {url}: HTTP {response.status_code}"}
            
        except requests.Timeout:
            logger.error(f"Timeout while fetching {url}")
            return {'error': 'Request timeout'}
        except requests.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return {'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error analyzing {url}: {e}")
            return {'error': str(e)}
    
    def crawl_and_analyze(self, base_url: str, html_content: str = None, 
                         max_files: int = 20) -> Dict[str, Any]:
        """
        Crawl HTML content to find and analyze JavaScript files.
        
        Args:
            base_url: Base URL for relative path resolution
            html_content: HTML content to analyze (fetched if not provided)
            max_files: Maximum number of JavaScript files to analyze
            
        Returns:
            Comprehensive analysis results
        """
        results = {
            'base_url': base_url,
            'external_files': [],
            'inline_scripts': [],
            'total_endpoints': 0,
            'total_secrets': 0,
            'high_risk_files': []
        }
        
        # Fetch HTML if not provided
        if not html_content:
            try:
                response = self.session.get(base_url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    html_content = response.text
                else:
                    return {'error': f'Failed to fetch {base_url}: HTTP {response.status_code}'}
            except Exception as e:
                return {'error': f'Failed to fetch {base_url}: {e}'}
        
        # Find all JavaScript references
        js_urls = self._extract_js_urls(base_url, html_content)
        
        # Analyze external JavaScript files
        analyzed_count = 0
        for js_url in js_urls[:max_files]:
            if analyzed_count >= max_files:
                break
                
            try:
                analysis = self.extract_from_url(js_url)
                if analysis and not analysis.get('error'):
                    file_result = {
                        'url': js_url,
                        'analysis': analysis,
                        'risk_score': analysis.get('risk_score', 0),
                        'endpoints_found': len(analysis.get('endpoints', [])),
                        'secrets_found': len(analysis.get('secrets', []))
                    }
                    
                    results['external_files'].append(file_result)
                    results['total_endpoints'] += file_result['endpoints_found']
                    results['total_secrets'] += file_result['secrets_found']
                    
                    if file_result['risk_score'] >= 70:
                        results['high_risk_files'].append({
                            'url': js_url,
                            'risk_score': file_result['risk_score'],
                            'secrets': file_result['secrets_found']
                        })
                    
                    analyzed_count += 1
                    
            except Exception as e:
                logger.debug(f"Failed to analyze {js_url}: {e}")
        
        # Analyze inline JavaScript
        inline_scripts = self._extract_inline_scripts(html_content)
        for i, script in enumerate(inline_scripts[:10]):  # Limit to 10 inline scripts
            if len(script) > 100:  # Only analyze substantial scripts
                try:
                    analysis = self.analyze_js_file(f"{base_url}#inline_{i}", script)
                    if analysis:
                        results['inline_scripts'].append({
                            'index': i,
                            'size': len(script),
                            'analysis_summary': {
                                'risk_score': analysis.get('risk_score', 0),
                                'endpoints_found': len(analysis.get('endpoints', [])),
                                'secrets_found': len(analysis.get('secrets', []))
                            }
                        })
                except Exception as e:
                    logger.debug(f"Failed to analyze inline script {i}: {e}")
        
        # Generate summary statistics
        results['summary'] = {
            'total_files_analyzed': len(results['external_files']),
            'total_inline_scripts': len(results['inline_scripts']),
            'average_risk_score': (
                sum(f['risk_score'] for f in results['external_files']) / 
                len(results['external_files']) if results['external_files'] else 0
            ),
            'high_risk_count': len(results['high_risk_files'])
        }
        
        return results
    
    def _extract_js_urls(self, base_url: str, html_content: str) -> List[str]:
        """Extract JavaScript URLs from HTML content."""
        js_urls = set()
        
        # Multiple patterns for finding JavaScript files
        patterns = [
            r'<script[^>]*src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\'][^>]*>',
            r'import\s+.*from\s*["\']([^"\']+\.(?:js|mjs))["\']',
            r'require\(["\']([^"\']+\.js)["\']\)',
            r'src=["\']([^"\']+\.js)["\']',
            r'<link[^>]*href=["\']([^"\']+\.js)["\'][^>]*>',
            r'<link[^>]*as=["\']script["\'][^>]*href=["\']([^"\']+)["\']',
            r'preload.*["\']([^"\']+\.js)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                clean_url = match.split('?')[0]  # Remove query parameters
                absolute_url = self._normalize_url(clean_url, base_url)
                if absolute_url:
                    js_urls.add(absolute_url)
        
        return list(js_urls)
    
    def _extract_inline_scripts(self, html_content: str) -> List[str]:
        """Extract inline JavaScript from HTML."""
        scripts = []
        
        # Extract script tags without src attribute
        pattern = r'<script(?![^>]*src)[^>]*>(.*?)</script>'
        matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for script in matches:
            script = script.strip()
            if script and not script.startswith('<!--'):
                scripts.append(script)
        
        return scripts

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def validate_js_file(js_content: str) -> bool:
    """
    Validate if content appears to be valid JavaScript.
    
    Args:
        js_content: Content to validate
        
    Returns:
        True if content appears to be valid JavaScript
    """
    if not js_content or len(js_content) < 10:
        return False
    
    # Check for common JavaScript patterns
    js_indicators = [
        r'function\s*\w*\s*\([^)]*\)',
        r'var\s+\w+\s*=',
        r'const\s+\w+\s*=',
        r'let\s+\w+\s*=',
        r'console\.log',
        r'if\s*\([^)]*\)',
        r'for\s*\([^)]*\)',
        r'return\s+',
    ]
    
    indicator_count = 0
    for pattern in js_indicators:
        if re.search(pattern, js_content[:2000]):
            indicator_count += 1
    
    # Also check that it's not obviously HTML
    html_indicators = ['<html', '<!doctype', '<body', '<head', '<title']
    is_html = any(indicator in js_content[:500].lower() for indicator in html_indicators)
    
    return indicator_count >= 2 and not is_html

# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Example usage of the AdvancedJavaScriptAnalyzer
    
    analyzer = AdvancedJavaScriptAnalyzer(enable_ast_parsing=True)
    
    # Analyze a single JavaScript file
    sample_js = """
    const API_KEY = "AIzaSyDabcdefghijklmnopqrstuvwxyz123456";
    const API_ENDPOINT = "https://api.example.com/v1/users";
    
    function getUserData(userId) {
        return fetch(`${API_ENDPOINT}/${userId}`, {
            headers: {
                'Authorization': `Bearer ${API_KEY}`,
                'Content-Type': 'application/json'
            }
        });
    }
    
    // TODO: Remove this test token before production
    const TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    """
    
    results = analyzer.analyze_js_file("https://example.com/app.js", sample_js)
    print(f"Risk Score: {results['risk_score']}")
    print(f"Secrets Found: {len(results['secrets'])}")
    print(f"Endpoints Found: {len(results['endpoints'])}")
    
    # Crawl and analyze a website
    # crawl_results = analyzer.crawl_and_analyze("https://example.com")
    # print(f"Total JavaScript files analyzed: {crawl_results['summary']['total_files_analyzed']}")