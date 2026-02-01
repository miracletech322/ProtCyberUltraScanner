# ============================================================================
# ADVANCED CLOUD INFRASTRUCTURE SECURITY SCANNER
# ============================================================================
"""
CloudSecurityScannerPro - Advanced Cloud Infrastructure Security Assessment
----------------------------------------------------------------------------
A comprehensive cloud security scanner for detecting misconfigurations,
exposed services, and vulnerabilities across multiple cloud platforms.

Key Capabilities:
- Multi-cloud provider detection and analysis (AWS, Azure, GCP, Oracle, DigitalOcean)
- Cloud storage misconfiguration assessment (S3, Blob Storage, Cloud Storage)
- Instance metadata service exposure testing
- Kubernetes cluster security analysis
- Database exposure detection
- Cloud-specific vulnerability scanning
- Container and serverless platform security
- Cloud-native application security testing
- Compliance framework mapping (CIS, NIST, PCI-DSS)
- Automated remediation recommendations
- Integration with cloud provider APIs for deeper analysis
"""

from typing import Dict, List, Optional, Set, Tuple, Any
import requests
import re
import socket
import json
import time
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
import ipaddress
import concurrent.futures
import threading
from dataclasses import dataclass, field
from colorama import Fore, Style, init
import logging
from collections import defaultdict
import boto3  # For AWS API interactions (if available)
from botocore.exceptions import ClientError, NoCredentialsError
import dns.resolver  # For DNS-based cloud detection
import ssl
import OpenSSL  # For certificate inspection

# Initialize colorama
init(autoreset=True)
logger = logging.getLogger(__name__)

# ============================================================================
# SUPPORTING CLASSES AND DATA STRUCTURES
# ============================================================================

@dataclass
class CloudService:
    """Data class representing a cloud service discovery."""
    service_type: str
    service_type_specific: str = ""
    provider: str
    url: str
    status: str = "unknown"
    security_issues: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    severity: str = "info"
    
@dataclass
class CloudFinding:
    """Standardized cloud security finding."""
    check_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    provider: str
    service: str
    evidence: str
    remediation: str
    compliance: List[str] = field(default_factory=list)  # CIS, NIST, PCI-DSS, etc.
    resource_id: str = ""
    region: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

class CloudProviderDetector:
    """Advanced cloud provider detection with multiple techniques."""
    
    def __init__(self):
        # Extended cloud patterns including CDN, PaaS, and SaaS
        self.cloud_patterns = {
            'aws': [
                r'\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com',
                r'\.execute-api\.[a-z0-9-]+\.amazonaws\.com',
                r'\.cloudfront\.net',
                r'\.elasticbeanstalk\.com',
                r'\.amazonaws\.com',
                r'\.rds\.amazonaws\.com',
                r'\.elasticache\.amazonaws\.com',
                r'\.lambda-url\.(?:[a-z0-9-]+)\.on\.aws',
                r'\.appsync-api\.(?:[a-z0-9-]+)\.amazonaws\.com',
            ],
            'azure': [
                r'\.blob\.core\.windows\.net',
                r'\.azurewebsites\.net',
                r'\.database\.windows\.net',
                r'\.cloudapp\.azure\.com',
                r'\.azure-api\.net',
                r'\.servicebus\.windows\.net',
                r'\.redis\.cache\.windows\.net',
                r'\.azurecontainer\.io',
                r'\.azurestaticapps\.net',
            ],
            'gcp': [
                r'\.storage\.googleapis\.com',
                r'\.appspot\.com',
                r'\.cloudfunctions\.net',
                r'\.run\.app',
                r'\.googleapis\.com',
                r'\.pkg\.dev',  # Artifact Registry
                r'\.cloud\.google\.com',
                r'\.firebaseapp\.com',
                r'\.web\.app',
            ],
            'digitalocean': [
                r'\.digitaloceanspaces\.com',
                r'\.ondigitalocean\.app',
                r'\.nyc3\.digitaloceanspaces\.com',
                r'\.ams3\.digitaloceanspaces\.com',
                r'\.sgp1\.digitaloceanspaces\.com',
            ],
            'oracle': [
                r'\.objectstorage\.[a-z0-9-]+\.oraclecloud\.com',
                r'\.compute\.oraclecloud\.com',
                r'\.oraclecloud\.com',
            ],
            'ibm': [
                r'\.cloud\.ibm\.com',
                r'\.appdomain\.cloud',
                r'\.bluemix\.net',
            ],
            'alibaba': [
                r'\.oss-[a-z0-9-]+\.aliyuncs\.com',
                r'\.alicloudapi\.com',
                r'\.aliyuncs\.com',
            ],
            'heroku': [
                r'\.herokuapp\.com',
                r'\.herokudns\.com',
            ],
            'vercel': [
                r'\.vercel\.app',
                r'\.now\.sh',
            ],
            'netlify': [
                r'\.netlify\.app',
                r'\.netlify\.com',
            ],
            'cloudflare': [
                r'\.cloudflare\.com',
                r'\.workers\.dev',
                r'\.pages\.dev',
            ],
            'firebase': [
                r'\.firebaseapp\.com',
                r'\.web\.app',
                r'\.firebaseio\.com',
            ],
        }
        
        # DNS-based detection patterns
        self.dns_patterns = {
            'aws': [
                r'^s3-website-[a-z0-9-]+\.amazonaws\.com$',
                r'^cloudfront\.net$',
            ],
            'azure': [
                r'\.trafficmanager\.net$',
                r'\.azurefd\.net$',
            ],
            'gcp': [
                r'\.googleusercontent\.com$',
                r'\.googlehosted\.com$',
            ]
        }
        
        # IP range detection (well-known cloud IP ranges)
        self.cloud_ip_ranges = {
            'aws': [
                '3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8',
                '23.0.0.0/8', '34.0.0.0/8', '35.0.0.0/8',
                '52.0.0.0/8', '54.0.0.0/8', '99.0.0.0/8',
            ],
            'azure': [
                '13.64.0.0/11', '13.104.0.0/14', '20.0.0.0/8',
                '23.96.0.0/13', '40.0.0.0/8', '51.0.0.0/8',
                '52.0.0.0/8', '65.52.0.0/14',
            ],
            'gcp': [
                '8.34.0.0/15', '8.35.0.0/16', '23.236.0.0/15',
                '23.251.0.0/16', '34.0.0.0/8', '35.184.0.0/13',
                '104.154.0.0/15', '107.167.160.0/19',
            ],
            'cloudflare': [
                '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
                '104.16.0.0/12', '108.162.192.0/18', '131.0.72.0/22',
            ]
        }
        
        # HTTP header signatures
        self.header_signatures = {
            'aws': ['x-amz-', 'x-amzn-', 'server: awselb/', 'x-amz-request-id'],
            'azure': ['x-ms-', 'server: microsoft-iis/', 'x-aspnet-version'],
            'gcp': ['server: google frontend', 'x-cloud-trace-context', 'x-guploader-uploadid'],
            'cloudflare': ['server: cloudflare', 'cf-ray', 'cf-cache-status'],
            'akamai': ['x-akamai-', 'server: akamai'],
            'fastly': ['x-fastly-', 'server: fastly'],
        }
    
    def detect_provider(self, url: str, response: Optional[requests.Response] = None) -> Dict:
        """
        Advanced cloud provider detection using multiple techniques.
        
        Returns:
            Dictionary with provider details including confidence level
        """
        detection_results = {
            'primary_provider': None,
            'secondary_providers': [],
            'confidence': 0,
            'techniques': [],
            'details': {}
        }
        
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        if not hostname:
            return detection_results
        
        # Technique 1: URL pattern matching
        for provider, patterns in self.cloud_patterns.items():
            for pattern in patterns:
                if re.search(pattern, hostname, re.IGNORECASE):
                    if not detection_results['primary_provider']:
                        detection_results['primary_provider'] = provider
                        detection_results['confidence'] += 30
                    else:
                        detection_results['secondary_providers'].append(provider)
                    detection_results['techniques'].append(f'url_pattern:{pattern}')
                    detection_results['details']['matched_pattern'] = pattern
                    break
        
        # Technique 2: DNS resolution and IP range checking
        try:
            ip_address = socket.gethostbyname(hostname)
            
            for provider, ip_ranges in self.cloud_ip_ranges.items():
                for ip_range in ip_ranges:
                    if ipaddress.ip_address(ip_address) in ipaddress.ip_network(ip_range):
                        detection_results['primary_provider'] = provider
                        detection_results['confidence'] += 40
                        detection_results['techniques'].append(f'ip_range:{ip_range}')
                        detection_results['details']['ip_address'] = ip_address
                        break
        except:
            pass
        
        # Technique 3: HTTP header analysis
        if response:
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            for provider, header_patterns in self.header_signatures.items():
                for pattern in header_patterns:
                    if ':' in pattern:
                        header, value_pattern = pattern.split(':', 1)
                        header = header.strip()
                        value_pattern = value_pattern.strip()
                        
                        if header in headers_lower:
                            if value_pattern in headers_lower[header]:
                                detection_results['primary_provider'] = provider
                                detection_results['confidence'] += 30
                                detection_results['techniques'].append(f'header:{pattern}')
                                detection_results['details']['matched_header'] = pattern
                                break
                    else:
                        # Just header name check
                        if any(pattern in h for h in headers_lower.keys()):
                            detection_results['primary_provider'] = provider
                            detection_results['confidence'] += 20
                            detection_results['techniques'].append(f'header_name:{pattern}')
                            break
        
        # Technique 4: SSL certificate inspection
        provider_from_cert = self._detect_from_certificate(hostname)
        if provider_from_cert:
            detection_results['primary_provider'] = provider_from_cert
            detection_results['confidence'] += 25
            detection_results['techniques'].append('ssl_certificate')
            detection_results['details']['certificate_provider'] = provider_from_cert
        
        # Normalize confidence
        detection_results['confidence'] = min(100, detection_results['confidence'])
        
        return detection_results
    
    def _detect_from_certificate(self, hostname: str) -> Optional[str]:
        """Detect cloud provider from SSL certificate."""
        try:
            cert = ssl.get_server_certificate((hostname, 443), timeout=5)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Check certificate issuer
            issuer = x509.get_issuer()
            issuer_str = str(issuer)
            
            if 'Amazon' in issuer_str:
                return 'aws'
            elif 'Microsoft' in issuer_str or 'Azure' in issuer_str:
                return 'azure'
            elif 'Google' in issuer_str:
                return 'gcp'
            elif 'CloudFlare' in issuer_str:
                return 'cloudflare'
                
        except:
            pass
        
        return None

# ============================================================================
# MAIN ADVANCED CLOUD SECURITY SCANNER CLASS
# ============================================================================

class CloudSecurityScannerPro:
    """
    Advanced Cloud Infrastructure Security Scanner
    
    Enhanced Features:
    1. Multi-cloud provider detection with confidence scoring
    2. Comprehensive cloud storage security assessment
    3. Instance metadata service testing with SSRF exploitation checks
    4. Kubernetes and container orchestration security
    5. Database and cache service exposure detection
    6. Serverless platform security (AWS Lambda, Azure Functions, GCP Cloud Functions)
    7. CDN and edge computing security
    8. Cloud-native application security testing
    9. Compliance mapping (CIS, NIST, PCI-DSS, HIPAA, GDPR)
    10. Automated remediation recommendations
    11. Integration with cloud provider APIs (optional)
    12. Rate limiting and stealth scanning techniques
    13. Evidence collection and reporting
    14. Custom check plugins
    15. Historical scanning and trend analysis
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the advanced cloud security scanner.
        
        Args:
            config: Configuration dictionary for scanner behavior
        """
        self.features = {
            'multi_cloud_detection': 'Advanced multi-cloud provider identification',
            'storage_security': 'Cloud storage misconfiguration scanning',
            'metadata_service': 'Instance metadata exposure testing',
            'container_security': 'Kubernetes and container security',
            'database_security': 'Database and cache service exposure',
            'serverless_security': 'Serverless platform security',
            'cdn_security': 'CDN and edge computing security',
            'compliance_mapping': 'Compliance framework mapping',
            'api_integration': 'Cloud provider API integration',
            'remediation_guidance': 'Automated remediation recommendations',
            'evidence_collection': 'Comprehensive evidence gathering',
            'rate_limiting': 'Intelligent rate limiting',
            'stealth_scanning': 'Stealth scanning techniques',
            'plugin_system': 'Extensible plugin architecture',
            'trend_analysis': 'Historical scanning and trends',
        }
        
        # Enhanced configuration
        self.config = {
            'max_threads': 10,
            'timeout': 15,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CloudSecurityScanner/2.0',
            'verify_ssl': False,
            'rate_limit_delay': (0.5, 2.0),
            'aws_access_key': None,
            'aws_secret_key': None,
            'aws_region': 'us-east-1',
            'azure_connection_string': None,
            'gcp_credentials': None,
            'enable_api_scanning': False,
            'stealth_mode': False,
            'compliance_frameworks': ['CIS', 'NIST', 'PCI-DSS'],
            'output_dir': './cloud_scan_results',
            'save_evidence': True,
            'max_retries': 3,
            'custom_checks': [],
            'dns_resolution': True,
            'port_scanning': True,
            'vulnerability_scanning': True,
            'crawling_depth': 2,
        }
        
        if config:
            self.config.update(config)
        
        # Initialize components
        self.detector = CloudProviderDetector()
        self.provider = None
        self.detection_confidence = 0
        
        # Data structures
        self.discovered_services: List[CloudService] = []
        self.security_findings: List[CloudFinding] = []
        self.compliance_violations: Dict[str, List] = defaultdict(list)
        self.scan_metadata: Dict = {}
        
        # Statistics
        self.stats = {
            'services_scanned': 0,
            'security_checks_performed': 0,
            'findings_by_severity': defaultdict(int),
            'scan_duration': 0,
            'start_time': None,
            'end_time': None,
        }
        
        # Cloud provider clients (initialized if credentials provided)
        self.aws_client = None
        self.azure_client = None
        self.gcp_client = None
        
        self._initialize_clients()
        
        logger.info(f"CloudSecurityScannerPro initialized with {len(self.features)} advanced features")
    
    def _initialize_clients(self):
        """Initialize cloud provider clients if credentials are available."""
        # AWS client
        if self.config['aws_access_key'] and self.config['aws_secret_key']:
            try:
                session = boto3.Session(
                    aws_access_key_id=self.config['aws_access_key'],
                    aws_secret_access_key=self.config['aws_secret_key'],
                    region_name=self.config['aws_region']
                )
                self.aws_client = {
                    's3': session.client('s3'),
                    'ec2': session.client('ec2'),
                    'rds': session.client('rds'),
                    'iam': session.client('iam'),
                    'cloudfront': session.client('cloudfront'),
                }
                logger.info("AWS client initialized")
            except Exception as e:
                logger.error(f"Failed to initialize AWS client: {e}")
        
        # Azure and GCP clients would be initialized similarly
        # (Implementation depends on SDK availability)
    
    def comprehensive_cloud_scan(self, target: str) -> Dict:
        """
        Perform comprehensive cloud security assessment.
        
        Args:
            target: URL or domain to scan
            
        Returns:
            Comprehensive scan results
        """
        print(f"\n{Fore.GREEN}[*]{Style.RESET_ALL} Starting comprehensive cloud security scan")
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Target: {target}")
        
        self.stats['start_time'] = datetime.now()
        
        try:
            # Step 1: Initial reconnaissance and provider detection
            print(f"{Fore.YELLOW}[~]{Style.RESET_ALL} Performing cloud provider detection...")
            provider_info = self._perform_initial_recon(target)
            
            self.provider = provider_info.get('primary_provider')
            self.detection_confidence = provider_info.get('confidence', 0)
            
            if self.provider:
                print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Detected provider: {self.provider} (confidence: {self.detection_confidence}%)")
            else:
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Cloud provider not detected, performing generic checks")
            
            # Step 2: Service discovery
            print(f"{Fore.YELLOW}[~]{Style.RESET_ALL} Discovering cloud services...")
            discovered_services = self.discover_cloud_services(target)
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Discovered {len(discovered_services)} cloud services")
            
            # Step 3: Run security checks
            print(f"{Fore.YELLOW}[~]{Style.RESET_ALL} Running security checks...")
            security_results = self.run_security_checks(target, discovered_services)
            
            # Step 4: API-based checks (if enabled and credentials available)
            if self.config['enable_api_scanning'] and self.provider:
                print(f"{Fore.YELLOW}[~]{Style.RESET_ALL} Performing API-based security checks...")
                api_results = self.perform_api_based_checks(target)
                security_results.extend(api_results)
            
            # Step 5: Compliance mapping
            print(f"{Fore.YELLOW}[~]{Style.RESET_ALL} Mapping to compliance frameworks...")
            compliance_results = self.map_to_compliance(security_results)
            
            # Step 6: Generate remediation recommendations
            print(f"{Fore.YELLOW}[~]{Style.RESET_ALL} Generating remediation recommendations...")
            remediation = self.generate_remediation_recommendations(security_results)
            
            # Step 7: Compile results
            self.stats['end_time'] = datetime.now()
            self.stats['scan_duration'] = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
            
            results = {
                'target': target,
                'scan_timestamp': self.stats['start_time'].isoformat(),
                'scan_duration_seconds': self.stats['scan_duration'],
                'cloud_provider': {
                    'provider': self.provider,
                    'confidence': self.detection_confidence,
                    'detection_details': provider_info,
                },
                'discovered_services': [
                    {
                        'type': s.service_type,
                        'provider': s.provider,
                        'url': s.url,
                        'status': s.status,
                        'security_issues': len(s.security_issues),
                    }
                    for s in discovered_services
                ],
                'security_assessment': {
                    'total_findings': len(security_results),
                    'findings_by_severity': dict(self.stats['findings_by_severity']),
                    'findings': security_results,
                    'risk_score': self.calculate_risk_score(security_results),
                },
                'compliance': compliance_results,
                'remediation': remediation,
                'statistics': self.stats,
                'recommendations': self.generate_summary_recommendations(security_results),
                'evidence': self.collect_evidence() if self.config['save_evidence'] else {},
            }
            
            # Step 8: Export results
            self.export_results(results)
            
            # Step 9: Print summary
            self._print_scan_summary(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Comprehensive scan failed: {e}")
            raise
    
    def _perform_initial_recon(self, target: str) -> Dict:
        """Perform initial reconnaissance and provider detection."""
        # Make initial request for header analysis
        try:
            response = requests.get(
                target,
                timeout=self.config['timeout'],
                verify=self.config['verify_ssl'],
                headers={'User-Agent': self.config['user_agent']}
            )
        except:
            response = None
        
        # Detect cloud provider
        provider_info = self.detector.detect_provider(target, response)
        
        # Additional reconnaissance
        recon_data = {
            'dns_records': self._get_dns_records(target),
            'open_ports': self._scan_ports(target) if self.config['port_scanning'] else [],
            'technologies': self._detect_technologies(target, response),
            'certificate_info': self._get_certificate_info(target),
        }
        
        provider_info['recon_data'] = recon_data
        return provider_info
    
    def _get_dns_records(self, domain: str) -> Dict:
        """Retrieve DNS records for domain analysis."""
        records = {}
        
        if not self.config['dns_resolution']:
            return records
        
        try:
            parsed = urlparse(domain)
            domain_name = parsed.hostname or domain
            
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain_name, record_type)
                    records[record_type] = [str(r) for r in answers]
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"DNS resolution failed: {e}")
        
        return records
    
    def _scan_ports(self, target: str) -> List[Dict]:
        """Scan common cloud service ports."""
        common_ports = {
            # Database ports
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            6379: 'Redis',
            9200: 'Elasticsearch',
            9042: 'Cassandra',
            # Cloud services
            443: 'HTTPS',
            80: 'HTTP',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            3000: 'Node.js',
            5000: 'Flask/Docker',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            465: 'SMTPS',
            587: 'SMTP-Submission',
        }
        
        open_ports = []
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                sock.close()
                
                if result == 0:
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'open'
                    })
            except:
                continue
        
        return open_ports
    
    def _detect_technologies(self, url: str, response: Optional[requests.Response]) -> List[str]:
        """Detect technologies used by the target."""
        technologies = set()
        
        if response:
            headers = response.headers
            
            # Check for cloud-specific headers
            for header, value in headers.items():
                header_lower = header.lower()
                value_lower = str(value).lower()
                
                # Server header
                if header_lower == 'server':
                    technologies.add(f"Server: {value}")
                
                # X-Powered-By
                elif header_lower == 'x-powered-by':
                    technologies.add(f"Powered by: {value}")
                
                # Framework detection from headers
                if 'django' in value_lower:
                    technologies.add('Django')
                elif 'express' in value_lower:
                    technologies.add('Express.js')
                elif 'flask' in value_lower:
                    technologies.add('Flask')
                elif 'rails' in value_lower:
                    technologies.add('Ruby on Rails')
                elif 'asp.net' in value_lower:
                    technologies.add('ASP.NET')
                elif 'php' in value_lower:
                    technologies.add('PHP')
            
            # Check for technologies in response body
            if response.text:
                body_lower = response.text.lower()
                
                tech_patterns = {
                    'React': ['react', 'react-dom'],
                    'Vue.js': ['vue', 'vue.js'],
                    'Angular': ['angular', 'ng-'],
                    'jQuery': ['jquery'],
                    'Bootstrap': ['bootstrap'],
                    'WordPress': ['wp-content', 'wordpress'],
                    'Laravel': ['laravel'],
                    'Spring': ['spring framework'],
                }
                
                for tech, patterns in tech_patterns.items():
                    if any(pattern in body_lower for pattern in patterns):
                        technologies.add(tech)
        
        return list(technologies)
    
    def _get_certificate_info(self, url: str) -> Dict:
        """Get SSL certificate information."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or url
            
            cert = ssl.get_server_certificate((hostname, 443), timeout=5)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            cert_info = {
                'subject': dict(x509.get_subject().get_components()),
                'issuer': dict(x509.get_issuer().get_components()),
                'version': x509.get_version(),
                'serial_number': str(x509.get_serial_number()),
                'not_before': x509.get_notBefore().decode('utf-8'),
                'not_after': x509.get_notAfter().decode('utf-8'),
                'signature_algorithm': x509.get_signature_algorithm().decode('utf-8'),
                'has_expired': x509.has_expired(),
            }
            
            # Check for wildcard certificate
            subject = cert_info['subject']
            if b'CN' in subject:
                cn = subject[b'CN'].decode('utf-8')
                cert_info['is_wildcard'] = cn.startswith('*')
                cert_info['common_name'] = cn
            
            return cert_info
            
        except Exception as e:
            logger.debug(f"Certificate inspection failed: {e}")
            return {}
    
    def discover_cloud_services(self, target: str) -> List[CloudService]:
        """
        Discover cloud services associated with the target.
        
        Args:
            target: URL or domain to scan
            
        Returns:
            List of discovered cloud services
        """
        services = []
        parsed_target = urlparse(target)
        base_domain = parsed_target.hostname or target
        
        # Common cloud service patterns to check
        service_patterns = [
            # AWS Services
            (r'(?:[a-z0-9.-]+\.)?s3(?:-[a-z0-9-]+)?\.amazonaws\.com', 'AWS S3', 'storage'),
            (r'\.cloudfront\.net', 'AWS CloudFront', 'cdn'),
            (r'\.execute-api\.[a-z0-9-]+\.amazonaws\.com', 'AWS API Gateway', 'api'),
            (r'\.elasticbeanstalk\.com', 'AWS Elastic Beanstalk', 'paas'),
            (r'\.rds\.amazonaws\.com', 'AWS RDS', 'database'),
            (r'\.lambda-url\.[a-z0-9-]+\.on\.aws', 'AWS Lambda', 'serverless'),
            
            # Azure Services
            (r'\.blob\.core\.windows\.net', 'Azure Blob Storage', 'storage'),
            (r'\.azurewebsites\.net', 'Azure App Service', 'paas'),
            (r'\.database\.windows\.net', 'Azure SQL Database', 'database'),
            (r'\.cloudapp\.azure\.com', 'Azure Cloud Service', 'compute'),
            (r'\.azure-api\.net', 'Azure API Management', 'api'),
            
            # GCP Services
            (r'\.storage\.googleapis\.com', 'GCP Cloud Storage', 'storage'),
            (r'\.appspot\.com', 'GCP App Engine', 'paas'),
            (r'\.cloudfunctions\.net', 'GCP Cloud Functions', 'serverless'),
            (r'\.run\.app', 'GCP Cloud Run', 'containers'),
            
            # Other Providers
            (r'\.digitaloceanspaces\.com', 'DigitalOcean Spaces', 'storage'),
            (r'\.herokuapp\.com', 'Heroku', 'paas'),
            (r'\.firebaseapp\.com', 'Firebase', 'paas'),
            (r'\.netlify\.app', 'Netlify', 'cdn'),
            (r'\.vercel\.app', 'Vercel', 'cdn'),
        ]
        
        # Check for services in DNS records
        dns_records = self._get_dns_records(target)
        cname_records = dns_records.get('CNAME', [])
        
        all_domains_to_check = [base_domain] + cname_records
        
        for domain in all_domains_to_check:
            for pattern, service_name, service_type in service_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    # Determine provider
                    provider = 'Unknown'
                    for prov, prov_patterns in self.detector.cloud_patterns.items():
                        if any(re.search(p, domain, re.IGNORECASE) for p in prov_patterns):
                            provider = prov.upper()
                            break
                    
                    service_url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
                    
                    service = CloudService(
                        service_type=service_type,
                        provider=provider,
                        url=service_url,
                        service_type_specific=service_name,
                        metadata={'discovery_method': 'dns_pattern'}
                    )
                    
                    services.append(service)
        
        # Also check for common cloud service subdomains
        common_subdomains = [
            's3', 'storage', 'cdn', 'api', 'app', 'www',
            'assets', 'media', 'static', 'uploads', 'files',
            'admin', 'dashboard', 'console', 'manager',
        ]
        
        for subdomain in common_subdomains:
            test_domain = f"{subdomain}.{base_domain}"
            
            # Try to resolve and check
            try:
                socket.gethostbyname(test_domain)
                
                # Check if it responds to HTTP/HTTPS
                for scheme in ['https', 'http']:
                    test_url = f"{scheme}://{test_domain}"
                    try:
                        response = requests.head(
                            test_url,
                            timeout=3,
                            verify=self.config['verify_ssl']
                        )
                        
                        if response.status_code < 400:
                            # Determine service type based on subdomain and response
                            service_type = self._infer_service_type(subdomain, response)
                            provider = self.detector.detect_provider(test_url, response).get('primary_provider', 'Unknown')
                            
                            service = CloudService(
                                service_type=service_type,
                                provider=provider.upper() if provider else 'Unknown',
                                url=test_url,
                                status=str(response.status_code),
                                metadata={
                                    'discovery_method': 'subdomain_scan',
                                    'subdomain': subdomain,
                                    'response_headers': dict(response.headers)
                                }
                            )
                            
                            services.append(service)
                            break
                            
                    except:
                        continue
                        
            except:
                continue
        
        return services
    
    def _infer_service_type(self, subdomain: str, response: requests.Response) -> str:
        """Infer service type from subdomain and response."""
        subdomain_lower = subdomain.lower()
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        if 's3' in subdomain_lower or 'storage' in subdomain_lower:
            if 'x-amz-' in str(headers_lower):
                return 'storage'
        
        if 'cdn' in subdomain_lower or 'assets' in subdomain_lower or 'static' in subdomain_lower:
            if any(h in headers_lower for h in ['x-cache', 'cf-cache-status', 'cdn-cache']):
                return 'cdn'
        
        if 'api' in subdomain_lower:
            return 'api'
        
        if 'app' in subdomain_lower:
            return 'application'
        
        return 'web'
    
    def run_security_checks(self, target: str, services: List[CloudService]) -> List[Dict]:
        """
        Run comprehensive security checks on discovered services.
        
        Args:
            target: Original target URL
            services: List of discovered cloud services
            
        Returns:
            List of security findings
        """
        all_findings = []
        
        # Run checks on each service
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            future_to_service = {}
            
            for service in services:
                future = executor.submit(self._check_service_security, service)
                future_to_service[future] = service
            
            for future in concurrent.futures.as_completed(future_to_service):
                service = future_to_service[future]
                try:
                    findings = future.result(timeout=30)
                    all_findings.extend(findings)
                    
                    # Update service with findings
                    service.security_issues = findings
                    if findings:
                        max_severity = max((f.get('severity', 'info') for f in findings), 
                                         key=lambda s: ['info', 'low', 'medium', 'high', 'critical'].index(s))
                        service.severity = max_severity
                        
                except Exception as e:
                    logger.error(f"Security check failed for {service.url}: {e}")
        
        # Run target-specific checks
        target_findings = self._check_target_security(target)
        all_findings.extend(target_findings)
        
        # Run provider-specific checks
        if self.provider:
            provider_findings = self._run_provider_specific_checks(target)
            all_findings.extend(provider_findings)
        
        # Update statistics
        for finding in all_findings:
            severity = finding.get('severity', 'info')
            self.stats['findings_by_severity'][severity] += 1
        
        self.stats['services_scanned'] = len(services)
        self.stats['security_checks_performed'] = len(all_findings)
        
        return all_findings
    
    def _check_service_security(self, service: CloudService) -> List[Dict]:
        """Run security checks on a specific service."""
        findings = []
        
        # Determine check types based on service type
        if service.service_type == 'storage':
            findings.extend(self.check_cloud_storage(service.url))
        
        elif service.service_type == 'cdn':
            findings.extend(self.check_cdn_security(service.url))
        
        elif service.service_type == 'api':
            findings.extend(self.check_api_security(service.url))
        
        elif service.service_type == 'database':
            findings.extend(self.check_database_exposure(service.url))
        
        elif service.service_type == 'application' or service.service_type == 'web':
            findings.extend(self.check_web_application_security(service.url))
        
        # Common checks for all services
        findings.extend(self.check_common_vulnerabilities(service.url))
        
        return findings
    
    def _check_target_security(self, target: str) -> List[Dict]:
        """Run target-specific security checks."""
        findings = []
        
        print(f"{Fore.YELLOW}[~]{Style.RESET_ALL} Running target-specific security checks...")
        
        # Check for metadata service exposure
        findings.extend(self.check_metadata_services())
        
        # Check for Kubernetes exposure
        findings.extend(self.check_kubernetes_exposure(target))
        
        # Check for container registry exposure
        findings.extend(self.check_container_registry_exposure(target))
        
        # Check for serverless function exposure
        findings.extend(self.check_serverless_exposure(target))
        
        # Check for CI/CD pipeline exposure
        findings.extend(self.check_ci_cd_exposure(target))
        
        return findings
    
    def _run_provider_specific_checks(self, target: str) -> List[Dict]:
        """Run provider-specific security checks."""
        findings = []
        
        if self.provider == 'aws':
            findings.extend(self.check_aws_specific_security(target))
        
        elif self.provider == 'azure':
            findings.extend(self.check_azure_specific_security(target))
        
        elif self.provider == 'gcp':
            findings.extend(self.check_gcp_specific_security(target))
        
        return findings
    
    def check_cloud_storage(self, url: str) -> List[Dict]:
        """
        Advanced cloud storage security check.
        
        Supports: AWS S3, Azure Blob Storage, GCP Cloud Storage
        """
        findings = []
        provider = self.detector.detect_provider(url).get('primary_provider')
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Checking cloud storage: {url}")
        
        # Test for public access with multiple methods
        access_tests = [
            # Root access
            {'url': url, 'method': 'GET', 'description': 'Root access'},
            
            # List objects
            {'url': f"{url.rstrip('/')}/?list-type=2", 'method': 'GET', 'description': 'List objects'},
            
            # Get bucket location
            {'url': f"{url.rstrip('/')}/?location", 'method': 'GET', 'description': 'Bucket location'},
            
            # HEAD request
            {'url': url, 'method': 'HEAD', 'description': 'HEAD request'},
        ]
        
        public_accessible = False
        
        for test in access_tests:
            try:
                if test['method'] == 'GET':
                    response = requests.get(
                        test['url'],
                        timeout=10,
                        verify=self.config['verify_ssl'],
                        headers={'User-Agent': self.config['user_agent']}
                    )
                else:  # HEAD
                    response = requests.head(
                        test['url'],
                        timeout=10,
                        verify=self.config['verify_ssl'],
                        headers={'User-Agent': self.config['user_agent']}
                    )
                
                # Analyze response
                if response.status_code == 200:
                    public_accessible = True
                    
                    finding = {
                        'check_id': 'CLOUD-STORAGE-001',
                        'title': 'Public Cloud Storage Access',
                        'description': f'Cloud storage is publicly accessible via {test["description"]}',
                        'severity': 'high',
                        'provider': provider or 'unknown',
                        'service': 'cloud_storage',
                        'evidence': f'HTTP {test["method"]} {test["url"]} returned 200 OK',
                        'remediation': 'Configure bucket policies to restrict public access',
                        'compliance': ['CIS-1.4', 'NIST-800-53-AC-3'],
                        'resource_id': url,
                        'details': {
                            'test_method': test['method'],
                            'test_url': test['url'],
                            'response_code': response.status_code,
                            'response_headers': dict(response.headers),
                        }
                    }
                    
                    # Check for directory listing
                    if 'ListBucketResult' in response.text or 'EnumerationResults' in response.text:
                        finding['severity'] = 'critical'
                        finding['title'] = 'Public Cloud Storage with Directory Listing'
                        finding['description'] = 'Cloud storage allows public directory listing'
                        finding['compliance'].extend(['PCI-DSS-1.2.1', 'GDPR-Article-32'])
                    
                    findings.append(finding)
                    break  # Found public access
                
                elif response.status_code in [403, 404]:
                    # Access properly restricted
                    finding = {
                        'check_id': 'CLOUD-STORAGE-002',
                        'title': 'Cloud Storage Access Restricted',
                        'description': f'Cloud storage access is properly restricted',
                        'severity': 'info',
                        'provider': provider or 'unknown',
                        'service': 'cloud_storage',
                        'evidence': f'HTTP {test["method"]} returned {response.status_code}',
                        'remediation': 'No action required',
                        'resource_id': url,
                    }
                    findings.append(finding)
                
            except Exception as e:
                logger.debug(f"Storage check failed for {test['url']}: {e}")
        
        # If publicly accessible, check for sensitive files
        if public_accessible:
            findings.extend(self._check_storage_for_sensitive_data(url))
        
        # Check for misconfigured CORS
        findings.extend(self._check_storage_cors(url))
        
        # Check for server-side encryption
        findings.extend(self._check_storage_encryption(url, provider))
        
        return findings
    
    def _check_storage_for_sensitive_data(self, url: str) -> List[Dict]:
        """Check storage for potentially sensitive files."""
        findings = []
        
        # Common sensitive file patterns
        sensitive_patterns = {
            'credentials': [r'\.env', r'config\.', r'secret', r'password', r'key'],
            'backups': [r'\.bak', r'backup', r'dump', r'\.sql'],
            'logs': [r'\.log', r'access_log', r'error_log'],
            'configurations': [r'\.config', r'\.ini', r'\.conf', r'\.yml', r'\.yaml'],
            'ssh_keys': [r'\.pem', r'\.key', r'\.ppk', r'id_rsa', r'id_dsa'],
        }
        
        try:
            # Try to list objects
            list_url = f"{url.rstrip('/')}/?list-type=2"
            response = requests.get(list_url, timeout=10, verify=self.config['verify_ssl'])
            
            if response.status_code == 200 and 'ListBucketResult' in response.text:
                # Parse XML response
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.text)
                
                # Extract keys (filenames)
                keys = [elem.text for elem in root.iter('{http://s3.amazonaws.com/doc/2006-03-01/}Key')]
                
                for key in keys[:50]:  # Limit to first 50 files
                    for file_type, patterns in sensitive_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, key, re.IGNORECASE):
                                findings.append({
                                    'check_id': 'CLOUD-STORAGE-003',
                                    'title': f'Sensitive {file_type.title()} File Found',
                                    'description': f'Storage contains potentially sensitive file: {key}',
                                    'severity': 'high',
                                    'service': 'cloud_storage',
                                    'evidence': f'File path: {key}',
                                    'remediation': 'Remove sensitive files from public storage or restrict access',
                                    'compliance': ['CIS-1.5', 'NIST-800-53-SI-4'],
                                    'resource_id': url,
                                    'details': {
                                        'file_path': key,
                                        'file_type': file_type,
                                        'matched_pattern': pattern,
                                    }
                                })
                                break
        
        except Exception as e:
            logger.debug(f"Sensitive file check failed: {e}")
        
        return findings
    
    def _check_storage_cors(self, url: str) -> List[Dict]:
        """Check for misconfigured CORS on cloud storage."""
        findings = []
        
        try:
            # Test CORS with different origins
            test_origins = [
                'https://evil.com',
                'http://attacker.local',
                'null',
                '*',
            ]
            
            for origin in test_origins:
                response = requests.options(
                    url,
                    timeout=10,
                    verify=self.config['verify_ssl'],
                    headers={
                        'Origin': origin,
                        'Access-Control-Request-Method': 'GET',
                        'Access-Control-Request-Headers': 'X-Requested-With',
                    }
                )
                
                if 'access-control-allow-origin' in response.headers:
                    allowed_origin = response.headers['access-control-allow-origin']
                    
                    if allowed_origin == '*' or allowed_origin == origin:
                        findings.append({
                            'check_id': 'CLOUD-STORAGE-004',
                            'title': 'Misconfigured CORS Policy',
                            'description': f'Storage allows CORS from origin: {allowed_origin}',
                            'severity': 'medium',
                            'service': 'cloud_storage',
                            'evidence': f'CORS allows origin: {allowed_origin}',
                            'remediation': 'Restrict CORS to specific trusted origins',
                            'compliance': ['CIS-2.1', 'OWASP-API-8'],
                            'resource_id': url,
                            'details': {
                                'allowed_origin': allowed_origin,
                                'test_origin': origin,
                            }
                        })
                        break
        
        except Exception as e:
            logger.debug(f"CORS check failed: {e}")
        
        return findings
    
    def check_metadata_services(self) -> List[Dict]:
        """Check for exposed cloud metadata services."""
        findings = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Checking cloud metadata services")
        
        # AWS EC2 Metadata Service
        aws_metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
        ]
        
        for url in aws_metadata_urls:
            try:
                response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                
                if response.status_code == 200:
                    findings.append({
                        'check_id': 'METADATA-001',
                        'title': 'AWS EC2 Metadata Service Exposed',
                        'description': 'EC2 metadata service is accessible and can expose sensitive information',
                        'severity': 'critical',
                        'provider': 'AWS',
                        'service': 'compute',
                        'evidence': f'Metadata endpoint accessible: {url}',
                        'remediation': 'Restrict access to metadata service using IMDSv2, security groups, or host-based firewalls',
                        'compliance': ['CIS-4.1', 'NIST-800-53-SC-7'],
                        'details': {
                            'endpoint': url,
                            'response_sample': response.text[:500],
                        }
                    })
                    
                    # Check for IAM credentials
                    if 'iam/security-credentials' in url and response.text.strip():
                        role_name = response.text.strip().split('\n')[0]
                        if role_name:
                            findings.append({
                                'check_id': 'METADATA-002',
                                'title': 'AWS IAM Role Credentials Exposed',
                                'description': f'IAM role credentials accessible for role: {role_name}',
                                'severity': 'critical',
                                'provider': 'AWS',
                                'service': 'compute',
                                'evidence': f'IAM role found: {role_name}',
                                'remediation': 'Implement IMDSv2 with required token and restrict instance profile permissions',
                                'compliance': ['CIS-4.2', 'PCI-DSS-7.2.1'],
                            })
                    break
                    
            except:
                continue
        
        # Azure Metadata Service
        try:
            response = requests.get(
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                timeout=5,
                headers={'Metadata': 'true'}
            )
            
            if response.status_code == 200:
                findings.append({
                    'check_id': 'METADATA-003',
                    'title': 'Azure Metadata Service Exposed',
                    'description': 'Azure instance metadata service is accessible',
                    'severity': 'critical',
                    'provider': 'Azure',
                    'service': 'compute',
                    'evidence': 'Azure metadata endpoint accessible',
                    'remediation': 'Use network security groups to restrict metadata service access',
                    'compliance': ['CIS-3.1', 'NIST-800-53-AC-6'],
                })
        except:
            pass
        
        # GCP Metadata Service
        try:
            response = requests.get(
                'http://metadata.google.internal/computeMetadata/v1/',
                timeout=5,
                headers={'Metadata-Flavor': 'Google'}
            )
            
            if response.status_code == 200:
                findings.append({
                    'check_id': 'METADATA-004',
                    'title': 'GCP Metadata Service Exposed',
                    'description': 'GCP instance metadata service is accessible',
                    'severity': 'critical',
                    'provider': 'GCP',
                    'service': 'compute',
                    'evidence': 'GCP metadata endpoint accessible',
                    'remediation': 'Configure firewall rules to block external metadata access',
                    'compliance': ['CIS-6.1', 'NIST-800-53-SC-7'],
                })
        except:
            pass
        
        # Check for SSRF vulnerabilities that could access metadata
        findings.extend(self._check_ssrf_to_metadata())
        
        return findings
    
    def _check_ssrf_to_metadata(self) -> List[Dict]:
        """Check for SSRF vulnerabilities that could access metadata services."""
        findings = []
        
        # Common SSRF test payloads targeting metadata
        metadata_endpoints = [
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/metadata/instance',
        ]
        
        # This would typically be integrated with a web vulnerability scanner
        # For now, just return a placeholder finding if we suspect SSRF
        if self.config.get('vulnerability_scanning', False):
            findings.append({
                'check_id': 'METADATA-005',
                'title': 'Potential SSRF to Metadata Service',
                'description': 'Application may be vulnerable to SSRF attacks that could access cloud metadata',
                'severity': 'high',
                'provider': 'multi',
                'service': 'application',
                'evidence': 'SSRF testing recommended',
                'remediation': 'Implement strict input validation and URL filtering to prevent SSRF',
                'compliance': ['OWASP-API-8', 'CIS-1.2'],
            })
        
        return findings
    
    def check_kubernetes_exposure(self, target: str) -> List[Dict]:
        """Check for exposed Kubernetes components."""
        findings = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Checking Kubernetes exposure")
        
        # Common Kubernetes endpoints
        k8s_endpoints = [
            '/api', '/apis', '/healthz', '/version',
            '/metrics', '/debug/pprof', '/logs',
            '/api/v1/namespaces', '/api/v1/pods',
            '/apis/apps/v1/deployments',
            '/apis/extensions/v1beta1/ingresses',
            '/apis/networking.k8s.io/v1/ingresses',
            '/apis/rbac.authorization.k8s.io/v1/clusterroles',
            '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings',
            '/api/v1/services',
            '/api/v1/configmaps',
            '/api/v1/secrets',
            '/dashboard', '/ui', '/k8s',
            '/kubernetes', '/kube', '/kubeapi',
        ]
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else f"https://{parsed.path}"
        
        for endpoint in k8s_endpoints:
            test_url = base_url.rstrip('/') + endpoint
            
            try:
                response = requests.get(
                    test_url,
                    timeout=5,
                    verify=self.config['verify_ssl'],
                    headers={'User-Agent': self.config['user_agent']}
                )
                
                if response.status_code == 200:
                    # Check for Kubernetes-specific responses
                    response_lower = response.text.lower()
                    
                    # API endpoints
                    if '/api' in endpoint or '/apis' in endpoint:
                        if any(marker in response_lower for marker in ['kubernetes', 'kind:', 'apiversion:', 'apiVersion:']):
                            findings.append({
                                'check_id': 'K8S-001',
                                'title': 'Kubernetes API Exposed',
                                'description': 'Kubernetes API server is publicly accessible',
                                'severity': 'critical',
                                'provider': 'kubernetes',
                                'service': 'container_orchestration',
                                'evidence': f'Kubernetes API accessible at: {test_url}',
                                'remediation': 'Restrict access to Kubernetes API using network policies, RBAC, and API server flags',
                                'compliance': ['CIS-K8S-1.2.1', 'NIST-800-190'],
                                'details': {
                                    'endpoint': endpoint,
                                    'response_code': response.status_code,
                                }
                            })
                            break
                    
                    # Dashboard
                    elif any(dash in endpoint.lower() for dash in ['dashboard', 'ui']):
                        if any(marker in response_lower for marker in ['kubernetes', 'dashboard', 'kubernetes-dashboard']):
                            findings.append({
                                'check_id': 'K8S-002',
                                'title': 'Kubernetes Dashboard Exposed',
                                'description': 'Kubernetes dashboard is publicly accessible',
                                'severity': 'critical',
                                'provider': 'kubernetes',
                                'service': 'container_orchestration',
                                'evidence': f'Kubernetes dashboard accessible at: {test_url}',
                                'remediation': 'Disable or secure the Kubernetes dashboard, use kubectl proxy instead',
                                'compliance': ['CIS-K8S-1.2.3', 'NIST-800-190'],
                            })
                            break
                    
                    # Metrics endpoint
                    elif '/metrics' in endpoint:
                        if 'prometheus' in response_lower or 'metrics' in response_lower:
                            findings.append({
                                'check_id': 'K8S-003',
                                'title': 'Kubernetes Metrics Exposed',
                                'description': 'Kubernetes metrics endpoint is publicly accessible',
                                'severity': 'high',
                                'provider': 'kubernetes',
                                'service': 'container_orchestration',
                                'evidence': f'Metrics endpoint accessible at: {test_url}',
                                'remediation': 'Restrict access to metrics endpoints using network policies',
                                'compliance': ['CIS-K8S-1.2.4'],
                            })
                
            except:
                continue
        
        # Check for common Kubernetes service ports
        k8s_ports = [6443, 8443, 8080, 8001, 10250, 10255, 2379, 2380, 9090]
        
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        
        for port in k8s_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))
                sock.close()
                
                if result == 0:
                    findings.append({
                        'check_id': 'K8S-004',
                        'title': f'Kubernetes Port {port} Exposed',
                        'description': f'Kubernetes service port {port} is open and accessible',
                        'severity': 'medium' if port > 10000 else 'high',
                        'provider': 'kubernetes',
                        'service': 'container_orchestration',
                        'evidence': f'Port {port} is open on {hostname}',
                        'remediation': f'Close port {port} or restrict access using firewall rules',
                        'compliance': ['CIS-K8S-1.1.1'],
                    })
            except:
                continue
        
        return findings
    
    def check_database_exposure(self, url: str) -> List[Dict]:
        """Check for exposed database services with enhanced detection."""
        findings = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Checking database exposure: {url}")
        
        parsed = urlparse(url)
        hostname = parsed.hostname or url
        
        # Database port scanning with service fingerprinting
        database_ports = {
            3306: {'name': 'MySQL', 'tests': ['SELECT 1', 'SHOW DATABASES']},
            5432: {'name': 'PostgreSQL', 'tests': ['SELECT 1']},
            27017: {'name': 'MongoDB', 'tests': ['{"ping": 1}']},
            6379: {'name': 'Redis', 'tests': ['PING', 'INFO']},
            9200: {'name': 'Elasticsearch', 'tests': ['GET /']},
            9042: {'name': 'Cassandra', 'tests': ['SELECT * FROM system.local']},
            1433: {'name': 'Microsoft SQL Server', 'tests': ['SELECT 1']},
            1521: {'name': 'Oracle Database', 'tests': ['SELECT 1 FROM DUAL']},
            5984: {'name': 'CouchDB', 'tests': ['GET /']},
            8086: {'name': 'InfluxDB', 'tests': ['GET /ping']},
            11211: {'name': 'Memcached', 'tests': ['stats']},
            2638: {'name': 'Sybase', 'tests': ['SELECT 1']},
        }
        
        for port, db_info in database_ports.items():
            try:
                # Test TCP connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                
                if result == 0:
                    # Service is open, attempt to identify
                    finding = {
                        'check_id': 'DB-001',
                        'title': f'Database Service Exposed: {db_info["name"]}',
                        'description': f'{db_info["name"]} database is accessible on port {port}',
                        'severity': 'critical',
                        'service': 'database',
                        'evidence': f'Port {port} ({db_info["name"]}) is open and accessible',
                        'remediation': f'Restrict access to {db_info["name"]} using firewall rules, VPC, or security groups',
                        'compliance': ['CIS-3.1', 'PCI-DSS-1.2', 'GDPR-Article-32'],
                        'details': {
                            'port': port,
                            'service': db_info['name'],
                            'host': hostname,
                        }
                    }
                    
                    # Try to determine if authentication is required
                    try:
                        if db_info['name'] == 'MySQL':
                            import pymysql
                            conn = pymysql.connect(
                                host=hostname,
                                port=port,
                                user='root',
                                password='',
                                connect_timeout=2
                            )
                            conn.close()
                            finding['description'] += ' (No authentication required)'
                            finding['severity'] = 'critical'
                        elif db_info['name'] == 'Redis':
                            import redis
                            r = redis.Redis(host=hostname, port=port, socket_timeout=2)
                            r.ping()
                            finding['description'] += ' (No authentication required)'
                            finding['severity'] = 'critical'
                    except:
                        finding['description'] += ' (Authentication may be required)'
                        finding['severity'] = 'high'
                    
                    findings.append(finding)
                
                sock.close()
                    
            except Exception as e:
                logger.debug(f"Database check failed for port {port}: {e}")
        
        # Check for cloud-managed database exposure
        cloud_db_patterns = {
            'aws': [
                (r'\.rds\.amazonaws\.com', 'AWS RDS'),
                (r'\.aurora\.amazonaws\.com', 'AWS Aurora'),
                (r'\.docdb\.amazonaws\.com', 'AWS DocumentDB'),
                (r'\.elasticache\.amazonaws\.com', 'AWS ElastiCache'),
            ],
            'azure': [
                (r'\.database\.windows\.net', 'Azure SQL Database'),
                (r'\.redis\.cache\.windows\.net', 'Azure Cache for Redis'),
                (r'\.cosmos\.azure\.com', 'Azure Cosmos DB'),
            ],
            'gcp': [
                (r'\.cloudsql\.googleapis\.com', 'GCP Cloud SQL'),
                (r'\.datastore\.googleapis\.com', 'GCP Datastore'),
                (r'\.firestore\.googleapis\.com', 'GCP Firestore'),
            ],
        }
        
        for provider, patterns in cloud_db_patterns.items():
            for pattern, service_name in patterns:
                if re.search(pattern, hostname, re.IGNORECASE):
                    findings.append({
                        'check_id': 'DB-002',
                        'title': f'Cloud-Managed Database Exposed: {service_name}',
                        'description': f'{service_name} endpoint is publicly accessible',
                        'severity': 'high',
                        'provider': provider.upper(),
                        'service': 'database',
                        'evidence': f'{service_name} endpoint: {hostname}',
                        'remediation': 'Configure network access controls and firewall rules for cloud database',
                        'compliance': ['CIS-3.2', 'NIST-800-53-SC-7'],
                        'details': {
                            'service': service_name,
                            'endpoint': hostname,
                        }
                    })
        
        return findings
    
    def check_cdn_security(self, url: str) -> List[Dict]:
        """Check CDN security configurations."""
        findings = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Checking CDN security: {url}")
        
        try:
            response = requests.get(
                url,
                timeout=10,
                verify=self.config['verify_ssl'],
                headers={'User-Agent': self.config['user_agent']}
            )
            
            headers = response.headers
            
            # Check for security headers
            security_headers = {
                'Content-Security-Policy': 'medium',
                'X-Frame-Options': 'medium',
                'X-Content-Type-Options': 'low',
                'Strict-Transport-Security': 'high',
                'Referrer-Policy': 'low',
            }
            
            for header, severity in security_headers.items():
                if header not in headers:
                    findings.append({
                        'check_id': 'CDN-001',
                        'title': f'Missing Security Header: {header}',
                        'description': f'CDN response missing {header} security header',
                        'severity': severity,
                        'service': 'cdn',
                        'evidence': f'{header} header not present in response',
                        'remediation': f'Configure CDN to include {header} header',
                        'compliance': ['CIS-2.1', 'OWASP-SM-001'],
                    })
            
            # Check for cache control headers
            if 'cache-control' not in headers:
                findings.append({
                    'check_id': 'CDN-002',
                    'title': 'Missing Cache Control',
                    'description': 'CDN response missing cache-control headers',
                    'severity': 'low',
                    'service': 'cdn',
                    'evidence': 'cache-control header not present',
                    'remediation': 'Configure appropriate cache-control headers',
                })
            
            # Check for origin exposure
            if 'server' in headers and 'cloudflare' not in headers['server'].lower():
                # Server header may expose origin information
                findings.append({
                    'check_id': 'CDN-003',
                    'title': 'Origin Server Information Exposure',
                    'description': f'Server header may expose origin information: {headers["server"]}',
                    'severity': 'low',
                    'service': 'cdn',
                    'evidence': f'Server header: {headers["server"]}',
                    'remediation': 'Configure CDN to remove or modify server header',
                })
        
        except Exception as e:
            logger.debug(f"CDN check failed: {e}")
        
        return findings
    
    def check_api_security(self, url: str) -> List[Dict]:
        """Check API security configurations."""
        findings = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Checking API security: {url}")
        
        # Check for API documentation exposure
        api_docs_endpoints = [
            '/swagger', '/swagger-ui', '/api-docs',
            '/openapi', '/redoc', '/docs',
            '/graphql', '/graphiql', '/playground',
            '/api/v1/docs', '/api/docs',
            '/rest-api/docs', '/api/explorer',
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for endpoint in api_docs_endpoints:
            test_url = base_url.rstrip('/') + endpoint
            
            try:
                response = requests.get(
                    test_url,
                    timeout=5,
                    verify=self.config['verify_ssl']
                )
                
                if response.status_code == 200:
                    response_lower = response.text.lower()
                    
                    if any(marker in response_lower for marker in ['swagger', 'openapi', 'api', 'documentation', 'graphql', 'graphiql']):
                        findings.append({
                            'check_id': 'API-001',
                            'title': 'API Documentation Exposed',
                            'description': f'API documentation accessible at {endpoint}',
                            'severity': 'medium',
                            'service': 'api',
                            'evidence': f'API documentation found at: {test_url}',
                            'remediation': 'Restrict access to API documentation in production environments',
                            'compliance': ['OWASP-API-6', 'CIS-1.3'],
                            'details': {
                                'endpoint': endpoint,
                                'content_type': response.headers.get('content-type', ''),
                            }
                        })
                        break
                        
            except:
                continue
        
        # Check for common API vulnerabilities
        findings.extend(self._check_api_vulnerabilities(url))
        
        return findings
    
    def _check_api_vulnerabilities(self, url: str) -> List[Dict]:
        """Check for common API vulnerabilities."""
        findings = []
        
        # Check for lack of rate limiting
        try:
            # Send multiple rapid requests
            responses = []
            for i in range(10):
                response = requests.get(url, timeout=3)
                responses.append(response.status_code)
                time.sleep(0.1)
            
            # If all succeeded, might lack rate limiting
            if all(code < 400 for code in responses):
                findings.append({
                    'check_id': 'API-002',
                    'title': 'Potential Lack of Rate Limiting',
                    'description': 'API may not have rate limiting enabled',
                    'severity': 'medium',
                    'service': 'api',
                    'evidence': '10 rapid requests all succeeded',
                    'remediation': 'Implement rate limiting to prevent abuse',
                    'compliance': ['OWASP-API-4', 'CIS-2.5'],
                })
        except:
            pass
        
        # Check for CORS misconfiguration
        try:
            response = requests.options(
                url,
                headers={
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'GET',
                }
            )
            
            if 'access-control-allow-origin' in response.headers:
                if response.headers['access-control-allow-origin'] == '*':
                    findings.append({
                        'check_id': 'API-003',
                        'title': 'Overly Permissive CORS',
                        'description': 'API allows CORS from any origin (*)',
                        'severity': 'medium',
                        'service': 'api',
                        'evidence': 'CORS allows * origin',
                        'remediation': 'Restrict CORS to specific trusted origins',
                        'compliance': ['OWASP-API-8'],
                    })
        except:
            pass
        
        return findings
    
    def check_web_application_security(self, url: str) -> List[Dict]:
        """Check web application security."""
        findings = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Checking web application security: {url}")
        
        try:
            response = requests.get(
                url,
                timeout=10,
                verify=self.config['verify_ssl'],
                headers={'User-Agent': self.config['user_agent']}
            )
            
            # Check for security headers
            headers_to_check = {
                'Content-Security-Policy': ('Missing CSP header', 'medium'),
                'X-Frame-Options': ('Missing X-Frame-Options', 'medium'),
                'X-Content-Type-Options': ('Missing X-Content-Type-Options', 'low'),
                'Strict-Transport-Security': ('Missing HSTS header', 'high'),
                'Referrer-Policy': ('Missing Referrer-Policy', 'low'),
            }
            
            for header, (description, severity) in headers_to_check.items():
                if header not in response.headers:
                    findings.append({
                        'check_id': 'WEB-001',
                        'title': description,
                        'description': f'Web application missing {header} security header',
                        'severity': severity,
                        'service': 'web_application',
                        'evidence': f'{header} header not present',
                        'remediation': f'Add {header} header with appropriate value',
                        'compliance': ['CIS-2.1', 'OWASP-SM-001'],
                    })
            
            # Check for sensitive information in response
            response_text = response.text.lower()
            sensitive_patterns = [
                (r'password\s*[:=]', 'Password exposure in response'),
                (r'api[_-]?key\s*[:=]', 'API key exposure'),
                (r'secret\s*[:=]', 'Secret exposure'),
                (r'token\s*[:=]', 'Token exposure'),
                (r'aws_[a-z_]+', 'AWS credential pattern'),
                (r'sql\s+syntax', 'SQL error exposure'),
                (r'stack\s+trace', 'Stack trace exposure'),
            ]
            
            for pattern, description in sensitive_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    findings.append({
                        'check_id': 'WEB-002',
                        'title': 'Sensitive Information Exposure',
                        'description': description,
                        'severity': 'high',
                        'service': 'web_application',
                        'evidence': f'Pattern "{pattern}" found in response',
                        'remediation': 'Remove sensitive information from responses, use proper error handling',
                        'compliance': ['CIS-1.4', 'PCI-DSS-3.2'],
                    })
                    break
        
        except Exception as e:
            logger.debug(f"Web application check failed: {e}")
        
        return findings
    
    def check_common_vulnerabilities(self, url: str) -> List[Dict]:
        """Check for common vulnerabilities across all service types."""
        findings = []
        
        # Check for HTTP methods
        try:
            response = requests.options(url, timeout=5)
            
            if 'allow' in response.headers:
                methods = response.headers['allow'].upper().split(',')
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                
                for method in dangerous_methods:
                    if method in methods:
                        findings.append({
                            'check_id': 'COMMON-001',
                            'title': f'Dangerous HTTP Method Enabled: {method}',
                            'description': f'{method} method is enabled and may be abused',
                            'severity': 'medium',
                            'service': 'generic',
                            'evidence': f'HTTP {method} method allowed',
                            'remediation': f'Disable {method} method if not required',
                            'compliance': ['OWASP-ASVS-5.1'],
                        })
        except:
            pass
        
        # Check for directory traversal
        traversal_payloads = [
            '../../../../etc/passwd',
            '..\\..\\..\\..\\windows\\win.ini',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            # Try to inject into query parameters
            base_url = url.split('?')[0]
            params = parse_qs(parsed.query)
            
            for param_name in params:
                for payload in traversal_payloads[:2]:  # Limit to 2 tests
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    # Reconstruct URL
                    from urllib.parse import urlencode
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{base_url}?{test_query}"
                    
                    try:
                        response = requests.get(test_url, timeout=5)
                        
                        if 'root:' in response.text or '[extensions]' in response.text:
                            findings.append({
                                'check_id': 'COMMON-002',
                                'title': 'Potential Directory Traversal',
                                'description': f'Directory traversal possible via parameter: {param_name}',
                                'severity': 'high',
                                'service': 'generic',
                                'evidence': f'Traversal payload successful: {payload}',
                                'remediation': 'Implement strict input validation and path traversal protection',
                                'compliance': ['CIS-1.1', 'OWASP-ASVS-5.3'],
                            })
                            break
                    except:
                        continue
        
        return findings
    
    def check_aws_specific_security(self, target: str) -> List[Dict]:
        """AWS-specific security checks."""
        findings = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Running AWS-specific security checks")
        
        # Check for AWS-specific patterns
        aws_patterns = [
            (r'\.s3-website-[a-z0-9-]+\.amazonaws\.com', 'AWS S3 Website Hosting'),
            (r'\.elb\.amazonaws\.com', 'AWS Elastic Load Balancer'),
            (r'\.elasticbeanstalk\.com', 'AWS Elastic Beanstalk'),
            (r'\.amazonaws\.com\.cn', 'AWS China'),
        ]
        
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        
        for pattern, service in aws_patterns:
            if re.search(pattern, hostname, re.IGNORECASE):
                findings.append({
                    'check_id': 'AWS-001',
                    'title': f'AWS Service Detected: {service}',
                    'description': f'{service} endpoint is publicly accessible',
                    'severity': 'info',
                    'provider': 'AWS',
                    'service': 'aws_service',
                    'evidence': f'AWS pattern matched: {pattern}',
                    'remediation': 'Ensure proper security configuration for AWS service',
                })
        
        # If AWS client is available, run API-based checks
        if self.aws_client and self.config['enable_api_scanning']:
            findings.extend(self._run_aws_api_checks(target))
        
        return findings
    
    def _run_aws_api_checks(self, target: str) -> List[Dict]:
        """Run AWS API-based security checks."""
        findings = []
        
        try:
            # This is a placeholder for actual AWS API checks
            # In a real implementation, this would call AWS APIs to check:
            # - S3 bucket policies
            # - IAM policies
            # - Security group rules
            # - CloudTrail logging
            # - etc.
            
            # Example: Check S3 buckets
            if 's3' in self.aws_client:
                try:
                    response = self.aws_client['s3'].list_buckets()
                    for bucket in response['Buckets']:
                        bucket_name = bucket['Name']
                        
                        # Check bucket ACL
                        try:
                            acl = self.aws_client['s3'].get_bucket_acl(Bucket=bucket_name)
                            for grant in acl['Grants']:
                                if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                    findings.append({
                                        'check_id': 'AWS-API-001',
                                        'title': 'AWS S3 Bucket Public Access',
                                        'description': f'S3 bucket {bucket_name} has public ACL',
                                        'severity': 'high',
                                        'provider': 'AWS',
                                        'service': 's3',
                                        'evidence': f'Bucket {bucket_name} grants AllUsers permission',
                                        'remediation': 'Remove public ACL from S3 bucket',
                                        'compliance': ['CIS-2.1.1'],
                                    })
                        except:
                            pass
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"AWS API checks failed: {e}")
        
        return findings
    
    def check_azure_specific_security(self, target: str) -> List[Dict]:
        """Azure-specific security checks."""
        findings = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Running Azure-specific security checks")
        
        # Similar pattern to AWS checks
        # Would include Azure-specific checks and API integration
        
        return findings
    
    def check_gcp_specific_security(self, target: str) -> List[Dict]:
        """GCP-specific security checks."""
        findings = []
        
        print(f"  {Fore.CYAN}->{Style.RESET_ALL} Running GCP-specific security checks")
        
        # Similar pattern to AWS checks
        # Would include GCP-specific checks and API integration
        
        return findings
    
    def perform_api_based_checks(self, target: str) -> List[Dict]:
        """Perform API-based security checks if credentials are available."""
        findings = []
        
        # This would integrate with cloud provider APIs for deeper inspection
        # Implementation depends on available credentials and SDKs
        
        return findings
    
    def map_to_compliance(self, findings: List[Dict]) -> Dict:
        """Map findings to compliance frameworks."""
        compliance_mapping = {
            'CIS': [],
            'NIST-800-53': [],
            'PCI-DSS': [],
            'GDPR': [],
            'HIPAA': [],
            'ISO-27001': [],
        }
        
        for finding in findings:
            if 'compliance' in finding:
                for framework in finding['compliance']:
                    if framework.startswith('CIS'):
                        compliance_mapping['CIS'].append(finding['check_id'])
                    elif 'NIST' in framework:
                        compliance_mapping['NIST-800-53'].append(finding['check_id'])
                    elif 'PCI' in framework:
                        compliance_mapping['PCI-DSS'].append(finding['check_id'])
                    elif 'GDPR' in framework:
                        compliance_mapping['GDPR'].append(finding['check_id'])
                    elif 'HIPAA' in framework:
                        compliance_mapping['HIPAA'].append(finding['check_id'])
                    elif 'ISO' in framework:
                        compliance_mapping['ISO-27001'].append(finding['check_id'])
        
        # Count violations
        compliance_summary = {}
        for framework, violations in compliance_mapping.items():
            compliance_summary[framework] = {
                'violations_count': len(violations),
                'violations': list(set(violations))[:10],  # Unique violations, limit to 10
            }
        
        self.compliance_violations = compliance_mapping
        
        return compliance_summary
    
    def generate_remediation_recommendations(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation recommendations."""
        recommendations = []
        
        # Group findings by service and severity
        by_service = defaultdict(list)
        for finding in findings:
            if finding['severity'] in ['critical', 'high']:
                by_service[finding.get('service', 'general')].append(finding)
        
        # Generate recommendations
        for service, service_findings in by_service.items():
            if service_findings:
                critical_count = sum(1 for f in service_findings if f['severity'] == 'critical')
                high_count = sum(1 for f in service_findings if f['severity'] == 'high')
                
                recommendations.append({
                    'service': service,
                    'priority': 'high' if critical_count > 0 else 'medium',
                    'critical_issues': critical_count,
                    'high_issues': high_count,
                    'recommendations': [
                        f['remediation'] for f in service_findings[:3]  # Top 3 recommendations
                    ],
                    'related_findings': [f['check_id'] for f in service_findings[:5]],
                })
        
        # Sort by priority
        recommendations.sort(key=lambda x: 0 if x['priority'] == 'high' else 1)
        
        return recommendations
    
    def generate_summary_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate high-level summary recommendations."""
        recommendations = []
        
        # Count findings by category
        categories = defaultdict(int)
        for finding in findings:
            if finding['severity'] in ['critical', 'high']:
                categories[finding.get('service', 'general')] += 1
        
        # Generate recommendations
        if categories.get('cloud_storage', 0) > 0:
            recommendations.append("Review and secure cloud storage configurations (S3, Blob Storage, etc.)")
        
        if categories.get('database', 0) > 0:
            recommendations.append("Secure database access and implement proper authentication")
        
        if categories.get('container_orchestration', 0) > 0:
            recommendations.append("Harden Kubernetes/container orchestration security")
        
        if any(f['severity'] == 'critical' for f in findings):
            recommendations.append("Address critical vulnerabilities immediately to prevent compromise")
        
        if len(recommendations) == 0 and findings:
            recommendations.append("Review all security findings and implement appropriate controls")
        
        return recommendations
    
    def calculate_risk_score(self, findings: List[Dict]) -> int:
        """Calculate overall risk score (0-100)."""
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0,
        }
        
        total_score = 0
        for finding in findings:
            severity = finding.get('severity', 'info')
            total_score += severity_weights.get(severity, 0)
        
        # Normalize to 0-100 scale
        max_possible = len(findings) * 10
        if max_possible == 0:
            return 0
        
        risk_score = min(100, (total_score / max_possible) * 100)
        
        return int(risk_score)
    
    def collect_evidence(self) -> Dict:
        """Collect evidence from the scan."""
        evidence = {
            'scan_timestamp': self.stats['start_time'].isoformat() if self.stats['start_time'] else None,
            'target_provider': self.provider,
            'detection_confidence': self.detection_confidence,
            'services_discovered': [
                {
                    'url': s.url,
                    'type': s.service_type,
                    'provider': s.provider,
                    'findings_count': len(s.security_issues),
                }
                for s in self.discovered_services
            ],
            'findings_summary': {
                'total': self.stats['security_checks_performed'],
                'by_severity': dict(self.stats['findings_by_severity']),
            },
            'compliance_violations': dict(self.compliance_violations),
        }
        
        return evidence
    
    def export_results(self, results: Dict):
        """Export scan results to JSON file."""
        import os
        import json
        from datetime import datetime
        
        # Create output directory
        os.makedirs(self.config['output_dir'], exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target = results['target'].replace('://', '_').replace('/', '_').replace('.', '_')
        filename = f"cloud_scan_{target}_{timestamp}.json"
        filepath = os.path.join(self.config['output_dir'], filename)
        
        # Save results
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Cloud scan results exported to: {filepath}")
        
        # Also generate a summary report
        summary = {
            'scan_summary': {
                'target': results['target'],
                'scan_date': timestamp,
                'duration_seconds': results['scan_duration_seconds'],
                'cloud_provider': results['cloud_provider']['provider'],
                'risk_score': results['security_assessment']['risk_score'],
                'total_findings': results['security_assessment']['total_findings'],
                'critical_findings': results['security_assessment']['findings_by_severity'].get('critical', 0),
                'high_findings': results['security_assessment']['findings_by_severity'].get('high', 0),
            },
            'top_recommendations': results['recommendations'],
        }
        
        summary_file = filepath.replace('.json', '_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return filepath
    
    def _print_scan_summary(self, results: Dict):
        """Print scan summary to console."""
        print(f"\n{'='*70}")
        print(f"CLOUD SECURITY SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"Target: {results['target']}")
        print(f"Cloud Provider: {results['cloud_provider']['provider'] or 'Not detected'}")
        print(f"Scan Duration: {results['scan_duration_seconds']:.2f} seconds")
        print(f"\nDiscoveries:")
        print(f"  Services Found: {len(results['discovered_services'])}")
        print(f"  Security Findings: {results['security_assessment']['total_findings']}")
        print(f"  Risk Score: {results['security_assessment']['risk_score']}/100")
        
        findings_by_severity = results['security_assessment']['findings_by_severity']
        if findings_by_severity:
            print(f"\nFindings by Severity:")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = findings_by_severity.get(severity, 0)
                if count > 0:
                    severity_color = {
                        'critical': Fore.RED,
                        'high': Fore.YELLOW,
                        'medium': Fore.CYAN,
                        'low': Fore.GREEN,
                        'info': Fore.WHITE,
                    }.get(severity, Fore.WHITE)
                    
                    print(f"  {severity_color}{severity.title():10}{Style.RESET_ALL}: {count}")
        
        if results['recommendations']:
            print(f"\nTop Recommendations:")
            for i, rec in enumerate(results['recommendations'][:5], 1):
                print(f"  {i}. {rec}")
        
        print(f"{'='*70}")


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Initialize the advanced cloud security scanner
    scanner = CloudSecurityScannerPro({
        'max_threads': 8,
        'timeout': 20,
        'enable_api_scanning': False,  # Set to True if you have cloud credentials
        'output_dir': './cloud_scans',
        'compliance_frameworks': ['CIS', 'NIST', 'PCI-DSS'],
    })
    
    # Run comprehensive scan
    target_url = "https://example.com"  # Replace with actual target
    results = scanner.comprehensive_cloud_scan(target_url)
    
    # Access results
    print(f"\nScan completed. Results saved to: ./cloud_scans/")
    print(f"Risk Level: {'High' if results['security_assessment']['risk_score'] > 70 else 'Medium' if results['security_assessment']['risk_score'] > 30 else 'Low'}")
    
    # List critical findings
    critical_findings = [
        f for f in results['security_assessment']['findings'] 
        if f['severity'] == 'critical'
    ]
    
    if critical_findings:
        print(f"\n{Fore.RED}CRITICAL FINDINGS:{Style.RESET_ALL}")
        for finding in critical_findings[:3]:  # Show top 3
            print(f"  • {finding['title']}")