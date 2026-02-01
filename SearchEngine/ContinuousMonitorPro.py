# ============================================================================
# ADVANCED CONTINUOUS SECURITY MONITORING & ALERTING PLATFORM
# ============================================================================
"""
ContinuousMonitorPro - Advanced Security Monitoring & Alerting Platform
-----------------------------------------------------------------------
An enterprise-grade continuous security monitoring system with real-time
threat detection, automated response, and comprehensive compliance tracking.

Key Capabilities:
- Multi-engine scanning with adaptive scheduling
- Real-time vulnerability change detection
- Advanced anomaly detection using machine learning
- Multi-channel alerting (Email, Slack, Teams, SMS, Webhook, PagerDuty)
- Automated remediation workflows
- Compliance tracking and reporting
- Historical trend analysis and forecasting
- Security posture dashboard
- Integration with SIEM/SOAR platforms
- Asset inventory and dependency tracking
- Threat intelligence integration
- Performance monitoring and resource optimization
"""

from typing import Dict, List, Optional, Set, Tuple, Any, Callable
import os
import json
import hashlib
import time
import threading
import schedule
import asyncio
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from enum import Enum
import logging
from colorama import Fore, Style, init
import sqlite3
from contextlib import contextmanager
import pickle
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import aiohttp
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import jwt
import redis
import psutil
import yaml

# Initialize colorama
init(autoreset=True)
logger = logging.getLogger(__name__)

# ============================================================================
# SUPPORTING CLASSES AND DATA STRUCTURES
# ============================================================================

class ScanPriority(Enum):
    """Priority levels for scanning."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ROUTINE = "routine"

class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"      # Immediate action required
    HIGH = "high"              # Action required within 24 hours
    MEDIUM = "medium"          # Action required within week
    LOW = "low"                # Informational
    INFO = "info"              # General information

@dataclass
class ScanJob:
    """Data class representing a scan job."""
    job_id: str
    target: str
    scan_type: str
    priority: ScanPriority
    schedule: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.now)
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    """Standardized scan result."""
    scan_id: str
    job_id: str
    target: str
    scan_type: str
    timestamp: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    success: bool = True
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    raw_data: Optional[bytes] = None

@dataclass
class SecurityAlert:
    """Security alert data structure."""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    source: str
    target: str
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    resolved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

@dataclass
class TrendAnalysis:
    """Trend analysis results."""
    period_days: int
    start_date: datetime
    end_date: datetime
    metrics_summary: Dict[str, Any]
    trends: Dict[str, str]  # increasing, decreasing, stable
    forecasts: Dict[str, Any]
    anomalies: List[Dict[str, Any]]
    recommendations: List[str]

class DatabaseManager:
    """Advanced database manager for monitoring data."""
    
    def __init__(self, db_path: str = "monitoring_data.db"):
        self.db_path = db_path
        self._init_database()
        self._redis_client = None
        
    def _init_database(self):
        """Initialize SQLite database with schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scan jobs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_jobs (
                job_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                priority TEXT NOT NULL,
                schedule_json TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                last_run TIMESTAMP,
                next_run TIMESTAMP,
                enabled BOOLEAN DEFAULT 1,
                config_json TEXT,
                metadata_json TEXT
            )
        ''')
        
        # Scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                duration_seconds REAL,
                success BOOLEAN,
                error_message TEXT,
                metrics_json TEXT,
                findings_json TEXT,
                summary_json TEXT,
                FOREIGN KEY (job_id) REFERENCES scan_jobs (job_id)
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                acknowledged BOOLEAN DEFAULT 0,
                resolved BOOLEAN DEFAULT 0,
                metadata_json TEXT,
                evidence_json TEXT,
                recommendations_json TEXT
            )
        ''')
        
        # Metrics table for time series data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                tags_json TEXT
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_job_id ON scan_results(job_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
        
        conn.commit()
        conn.close()
        
    def get_redis_client(self):
        """Get Redis client for caching."""
        if self._redis_client is None:
            try:
                self._redis_client = redis.Redis(
                    host='localhost',
                    port=6379,
                    db=0,
                    decode_responses=True
                )
                self._redis_client.ping()  # Test connection
            except:
                self._redis_client = None
                logger.warning("Redis not available, using in-memory cache")
        
        return self._redis_client
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

class AnomalyDetector:
    """Machine learning-based anomaly detector."""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.models = {}
        self.training_data = defaultdict(list)
        
    def train_model(self, target: str, metric: str, values: List[float]):
        """Train anomaly detection model for specific metric."""
        if len(values) < 10:
            return None
            
        # Prepare data
        X = np.array(values).reshape(-1, 1)
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        model.fit(X_scaled)
        
        key = f"{target}:{metric}"
        self.models[key] = model
        self.training_data[key] = values
        
        return model
    
    def detect_anomalies(self, target: str, metric: str, values: List[float], 
                         timestamps: List[datetime]) -> List[Dict]:
        """Detect anomalies in time series data."""
        key = f"{target}:{metric}"
        
        if key not in self.models:
            # Train model if not exists
            model = self.train_model(target, metric, values)
            if model is None:
                return []
        else:
            model = self.models[key]
        
        # Prepare data for prediction
        X = np.array(values).reshape(-1, 1)
        X_scaled = self.scaler.transform(X)
        
        # Predict anomalies
        predictions = model.predict(X_scaled)
        anomaly_scores = model.decision_function(X_scaled)
        
        anomalies = []
        for i, (pred, score, value, ts) in enumerate(zip(predictions, anomaly_scores, values, timestamps)):
            if pred == -1:  # Anomaly
                anomalies.append({
                    'timestamp': ts,
                    'metric': metric,
                    'value': value,
                    'anomaly_score': float(score),
                    'severity': self._determine_anomaly_severity(abs(score)),
                    'description': f'Anomaly detected in {metric}: {value:.2f}',
                })
        
        return anomalies
    
    def _determine_anomaly_severity(self, score: float) -> str:
        """Determine severity based on anomaly score."""
        if score > 0.3:
            return 'critical'
        elif score > 0.2:
            return 'high'
        elif score > 0.1:
            return 'medium'
        else:
            return 'low'

# ============================================================================
# MAIN ADVANCED CONTINUOUS MONITORING CLASS
# ============================================================================

class ContinuousMonitorPro:
    """
    Advanced Continuous Security Monitoring & Alerting Platform
    
    Enhanced Features:
    1. Multi-engine scanning with plugin architecture
    2. Intelligent scheduling with dynamic priority adjustment
    3. Real-time change detection with ML-based anomaly detection
    4. Comprehensive multi-channel alerting system
    5. Automated remediation workflows and playbooks
    6. Advanced compliance tracking and reporting
    7. Historical trend analysis with forecasting
    8. Security posture dashboard and reporting
    9. Integration with external systems (SIEM, SOAR, ITSM)
    10. Asset inventory and dependency mapping
    11. Threat intelligence integration
    12. Performance monitoring and auto-scaling
    13. Multi-tenancy support with RBAC
    14. API for external integration
    15. Advanced caching and optimization
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the advanced monitoring platform.
        
        Args:
            config: Configuration dictionary
        """
        self.features = {
            'multi_engine_scanning': 'Support for multiple scanning engines',
            'intelligent_scheduling': 'Dynamic priority-based scheduling',
            'real_time_detection': 'Real-time change and anomaly detection',
            'multi_channel_alerting': 'Email, Slack, Teams, SMS, Webhook, PagerDuty',
            'automated_remediation': 'Automated remediation workflows',
            'compliance_tracking': 'Compliance tracking and reporting',
            'trend_analysis': 'Advanced trend analysis and forecasting',
            'dashboard': 'Real-time security dashboard',
            'siem_integration': 'SIEM/SOAR platform integration',
            'asset_management': 'Asset inventory and dependency tracking',
            'threat_intelligence': 'Threat intelligence integration',
            'performance_monitoring': 'System performance monitoring',
            'multi_tenancy': 'Multi-tenant support with RBAC',
            'api': 'REST API for external integration',
            'caching': 'Advanced caching and optimization',
        }
        
        # Enhanced configuration
        self.config = {
            'database_path': 'monitoring_data.db',
            'redis_enabled': True,
            'redis_host': 'localhost',
            'redis_port': 6379,
            'redis_db': 0,
            
            'scheduling': {
                'max_concurrent_scans': 10,
                'default_scan_interval': 86400,  # 24 hours in seconds
                'retry_failed_interval': 3600,   # 1 hour
                'adaptive_scheduling': True,
                'priority_weighting': {
                    'critical': 10,
                    'high': 7,
                    'medium': 4,
                    'low': 2,
                    'routine': 1,
                }
            },
            
            'alerting': {
                'channels': ['console', 'email'],
                'severity_threshold': 'medium',
                'throttling_enabled': True,
                'throttling_window': 300,  # 5 minutes
                'max_alerts_per_window': 10,
                'email_settings': None,
                'slack_webhook': None,
                'teams_webhook': None,
                'sms_gateway': None,
                'pagerduty_api_key': None,
                'webhook_urls': [],
            },
            
            'compliance': {
                'frameworks': ['OWASP', 'CIS', 'NIST', 'PCI-DSS', 'GDPR', 'HIPAA'],
                'auto_mapping': True,
                'reporting_interval': 7,  # days
            },
            
            'monitoring': {
                'trend_analysis_days': 30,
                'anomaly_detection_enabled': True,
                'forecasting_enabled': True,
                'baseline_period_days': 7,
                'change_threshold_percent': 10,
            },
            
            'performance': {
                'resource_monitoring': True,
                'auto_scaling': True,
                'max_memory_percent': 80,
                'max_cpu_percent': 70,
                'cache_size': 10000,
            },
            
            'api': {
                'enabled': False,
                'host': '0.0.0.0',
                'port': 8000,
                'auth_required': True,
                'jwt_secret': None,
            },
            
            'storage': {
                'retention_days': 365,
                'compression_enabled': True,
                'backup_enabled': True,
                'backup_interval': 7,  # days
            },
            
            'plugins': [],
            'scan_engines': ['web', 'cloud', 'infrastructure', 'api'],
        }
        
        if config:
            self._deep_update(self.config, config)
        
        # Initialize components
        self.db = DatabaseManager(self.config['database_path'])
        self.anomaly_detector = AnomalyDetector() if self.config['monitoring']['anomaly_detection_enabled'] else None
        
        # Data structures
        self.scan_jobs: Dict[str, ScanJob] = {}
        self.active_scans: Dict[str, threading.Thread] = {}
        self.scan_queue = deque()
        self.alert_history: List[SecurityAlert] = []
        self.metrics_cache = defaultdict(deque)
        self.compliance_status: Dict[str, Any] = {}
        
        # Performance monitoring
        self.performance_metrics = {
            'scans_completed': 0,
            'scans_failed': 0,
            'alerts_sent': 0,
            'avg_scan_duration': 0,
            'system_load': 0,
            'memory_usage': 0,
            'cache_hit_rate': 0,
        }
        
        # Threading and concurrency
        self.scheduler_thread = None
        self.monitoring_thread = None
        self.alert_thread = None
        self.running = False
        
        # Alert manager
        self.alert_manager = AdvancedAlertManager(self.config['alerting'])
        
        # Plugin system
        self.plugins = {}
        self._load_plugins()
        
        # API server (if enabled)
        self.api_server = None
        if self.config['api']['enabled']:
            self._start_api_server()
        
        # Load existing data
        self._load_existing_data()
        
        logger.info(f"ContinuousMonitorPro initialized with {len(self.features)} advanced features")
    
    def _deep_update(self, target: Dict, source: Dict):
        """Recursively update nested dictionaries."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_update(target[key], value)
            else:
                target[key] = value
    
    def _load_plugins(self):
        """Load and initialize plugins."""
        for plugin_path in self.config['plugins']:
            try:
                # This would dynamically import plugins
                # For now, it's a placeholder
                plugin_name = os.path.basename(plugin_path).replace('.py', '')
                self.plugins[plugin_name] = None
                logger.info(f"Loaded plugin: {plugin_name}")
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_path}: {e}")
    
    def _load_existing_data(self):
        """Load existing data from database."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Load scan jobs
                cursor.execute("SELECT * FROM scan_jobs WHERE enabled = 1")
                for row in cursor.fetchall():
                    job = ScanJob(
                        job_id=row['job_id'],
                        target=row['target'],
                        scan_type=row['scan_type'],
                        priority=ScanPriority(row['priority']),
                        schedule=json.loads(row['schedule_json']),
                        created_at=datetime.fromisoformat(row['created_at']),
                        last_run=datetime.fromisoformat(row['last_run']) if row['last_run'] else None,
                        next_run=datetime.fromisoformat(row['next_run']) if row['next_run'] else None,
                        enabled=bool(row['enabled']),
                        config=json.loads(row['config_json']) if row['config_json'] else {},
                        metadata=json.loads(row['metadata_json']) if row['metadata_json'] else {},
                    )
                    self.scan_jobs[job.job_id] = job
                
                logger.info(f"Loaded {len(self.scan_jobs)} scan jobs from database")
                
        except Exception as e:
            logger.error(f"Failed to load existing data: {e}")
    
    def _start_api_server(self):
        """Start REST API server."""
        try:
            # This would start a FastAPI/Flask server
            # For now, it's a placeholder
            logger.info("API server would start here")
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")
    
    def start_monitoring(self):
        """Start the monitoring platform."""
        if self.running:
            logger.warning("Monitoring already running")
            return
        
        self.running = True
        
        # Start scheduler thread
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        # Start alert thread
        self.alert_thread = threading.Thread(target=self._alert_processing_loop, daemon=True)
        self.alert_thread.start()
        
        # Start performance monitoring
        if self.config['performance']['resource_monitoring']:
            perf_thread = threading.Thread(target=self._performance_monitoring_loop, daemon=True)
            perf_thread.start()
        
        logger.info("Continuous monitoring platform started")
    
    def stop_monitoring(self):
        """Stop the monitoring platform."""
        self.running = False
        
        # Wait for threads to finish
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        if self.alert_thread:
            self.alert_thread.join(timeout=5)
        
        # Save state
        self._save_state()
        
        logger.info("Continuous monitoring platform stopped")
    
    def _scheduler_loop(self):
        """Main scheduling loop."""
        while self.running:
            try:
                now = datetime.now()
                
                # Check for scans due
                for job in self.scan_jobs.values():
                    if not job.enabled:
                        continue
                    
                    if job.next_run and job.next_run <= now:
                        # Add to queue
                        self.scan_queue.append(job.job_id)
                        
                        # Update next run time
                        job.next_run = self._calculate_next_run(job)
                        
                        # Save updated job
                        self._save_scan_job(job)
                
                # Process scan queue
                self._process_scan_queue()
                
                # Sleep for a bit
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                time.sleep(5)
    
    def _calculate_next_run(self, job: ScanJob) -> datetime:
        """Calculate next run time for a job."""
        schedule = job.schedule
        
        if schedule.get('type') == 'cron':
            # Parse cron expression
            cron_expr = schedule.get('expression', '0 2 * * *')
            # This would use a cron parser library
            # For now, assume daily at 2 AM
            next_run = datetime.now().replace(hour=2, minute=0, second=0, microsecond=0)
            next_run += timedelta(days=1)
            
        elif schedule.get('type') == 'interval':
            interval_seconds = schedule.get('interval_seconds', 86400)
            next_run = datetime.now() + timedelta(seconds=interval_seconds)
            
        elif schedule.get('type') == 'adaptive':
            # Adaptive scheduling based on risk level and historical data
            base_interval = self.config['scheduling']['default_scan_interval']
            
            # Adjust based on priority
            priority_factor = self.config['scheduling']['priority_weighting'].get(job.priority.value, 1)
            adjusted_interval = base_interval / priority_factor
            
            # Further adjust based on recent findings
            recent_findings = self._get_recent_findings_for_target(job.target, hours=24)
            if recent_findings:
                # More frequent scans if vulnerabilities found
                vulnerability_factor = min(0.5, len(recent_findings) / 10)
                adjusted_interval *= (1 - vulnerability_factor)
            
            next_run = datetime.now() + timedelta(seconds=int(adjusted_interval))
            
        else:
            # Default: daily at 2 AM
            next_run = datetime.now().replace(hour=2, minute=0, second=0, microsecond=0)
            next_run += timedelta(days=1)
        
        return next_run
    
    def _get_recent_findings_for_target(self, target: str, hours: int = 24) -> List[Dict]:
        """Get recent findings for a target."""
        try:
            cutoff = datetime.now() - timedelta(hours=hours)
            
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT findings_json FROM scan_results 
                    WHERE target = ? AND timestamp >= ? 
                    ORDER BY timestamp DESC LIMIT 5
                """, (target, cutoff.isoformat()))
                
                findings = []
                for row in cursor.fetchall():
                    if row['findings_json']:
                        findings.extend(json.loads(row['findings_json']))
                
                return findings
                
        except Exception as e:
            logger.error(f"Failed to get recent findings: {e}")
            return []
    
    def _process_scan_queue(self):
        """Process scan queue with concurrency control."""
        max_concurrent = self.config['scheduling']['max_concurrent_scans']
        
        # Remove finished scans
        self.active_scans = {jid: thread for jid, thread in self.active_scans.items() if thread.is_alive()}
        
        # Start new scans if under limit
        while self.scan_queue and len(self.active_scans) < max_concurrent:
            job_id = self.scan_queue.popleft()
            
            if job_id in self.scan_jobs:
                job = self.scan_jobs[job_id]
                
                # Start scan in separate thread
                scan_thread = threading.Thread(
                    target=self._execute_scan,
                    args=(job,),
                    daemon=True
                )
                scan_thread.start()
                
                self.active_scans[job_id] = scan_thread
                
                # Update job
                job.last_run = datetime.now()
                self._save_scan_job(job)
    
    def _execute_scan(self, job: ScanJob):
        """Execute a scan job."""
        scan_id = hashlib.sha256(
            f"{job.job_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        logger.info(f"Starting scan {scan_id} for {job.target} (type: {job.scan_type})")
        
        start_time = time.time()
        success = False
        error_message = None
        metrics = {}
        findings = []
        summary = {}
        
        try:
            # Execute appropriate scanner based on type
            if job.scan_type == 'web':
                result = self._run_web_scan(job)
            elif job.scan_type == 'cloud':
                result = self._run_cloud_scan(job)
            elif job.scan_type == 'infrastructure':
                result = self._run_infrastructure_scan(job)
            elif job.scan_type == 'api':
                result = self._run_api_scan(job)
            else:
                result = self._run_generic_scan(job)
            
            success = result.get('success', False)
            findings = result.get('findings', [])
            summary = result.get('summary', {})
            metrics = result.get('metrics', {})
            
        except Exception as e:
            error_message = str(e)
            logger.error(f"Scan {scan_id} failed: {e}")
            success = False
        
        duration = time.time() - start_time
        
        # Create scan result
        scan_result = ScanResult(
            scan_id=scan_id,
            job_id=job.job_id,
            target=job.target,
            scan_type=job.scan_type,
            timestamp=datetime.now(),
            duration_seconds=duration,
            success=success,
            error_message=error_message,
            metrics=metrics,
            findings=findings,
            summary=summary,
        )
        
        # Save result
        self._save_scan_result(scan_result)
        
        # Update performance metrics
        self.performance_metrics['scans_completed'] += 1
        if not success:
            self.performance_metrics['scans_failed'] += 1
        
        # Update average scan duration (moving average)
        prev_avg = self.performance_metrics['avg_scan_duration']
        scan_count = self.performance_metrics['scans_completed']
        self.performance_metrics['avg_scan_duration'] = (
            (prev_avg * (scan_count - 1) + duration) / scan_count
        )
        
        # Perform change detection
        if success and findings:
            changes = self.detect_changes(job.target, findings)
            if changes:
                self._process_changes(job, changes)
        
        # Update metrics cache
        self._update_metrics_cache(job.target, scan_result)
        
        logger.info(f"Scan {scan_id} completed in {duration:.2f}s (success: {success})")
    
    def _run_web_scan(self, job: ScanJob) -> Dict:
        """Run web vulnerability scan."""
        # This would integrate with the web scanner from previous features
        # For now, simulate scan results
        
        import random
        
        # Simulate scan findings
        vulnerabilities = [
            'SQL Injection',
            'Cross-Site Scripting (XSS)',
            'Insecure Direct Object References',
            'Security Misconfiguration',
            'Sensitive Data Exposure',
            'Broken Authentication',
            'Cross-Site Request Forgery (CSRF)',
            'Using Components with Known Vulnerabilities',
            'Insufficient Logging & Monitoring',
        ]
        
        findings = []
        num_findings = random.randint(0, 5)
        
        for i in range(num_findings):
            vuln = random.choice(vulnerabilities)
            severity = random.choice(['critical', 'high', 'medium', 'low'])
            
            findings.append({
                'id': f"WEB-{random.randint(1000, 9999)}",
                'name': vuln,
                'severity': severity,
                'description': f'Potential {vuln} vulnerability detected',
                'url': f'{job.target}/vulnerable-endpoint-{i}',
                'confidence': random.choice(['high', 'medium', 'low']),
                'remediation': f'Implement {vuln} protection measures',
                'cvss_score': random.uniform(0, 10),
                'timestamp': datetime.now().isoformat(),
            })
        
        summary = {
            'total_vulnerabilities': len(findings),
            'critical_count': len([f for f in findings if f['severity'] == 'critical']),
            'high_count': len([f for f in findings if f['severity'] == 'high']),
            'medium_count': len([f for f in findings if f['severity'] == 'medium']),
            'low_count': len([f for f in findings if f['severity'] == 'low']),
            'risk_score': sum(f.get('cvss_score', 0) for f in findings) / max(len(findings), 1),
        }
        
        metrics = {
            'pages_scanned': random.randint(10, 100),
            'requests_made': random.randint(100, 1000),
            'scan_depth': random.randint(1, 5),
            'authentication_used': random.choice([True, False]),
        }
        
        return {
            'success': True,
            'findings': findings,
            'summary': summary,
            'metrics': metrics,
        }
    
    def _run_cloud_scan(self, job: ScanJob) -> Dict:
        """Run cloud infrastructure scan."""
        # This would integrate with the cloud scanner from previous features
        
        import random
        
        findings = []
        cloud_issues = [
            'Public S3 Bucket',
            'Exposed EC2 Metadata',
            'Overly Permissive IAM Policies',
            'Unencrypted RDS Instances',
            'Security Group Misconfiguration',
            'CloudTrail Logging Disabled',
            'Publicly Accessible Database',
            'Missing Multi-Factor Authentication',
            'Default Security Credentials',
        ]
        
        num_findings = random.randint(0, 7)
        
        for i in range(num_findings):
            issue = random.choice(cloud_issues)
            severity = random.choice(['critical', 'high', 'medium'])
            
            findings.append({
                'id': f"CLOUD-{random.randint(1000, 9999)}",
                'name': issue,
                'severity': severity,
                'description': f'Cloud security issue: {issue}',
                'resource': f'aws-resource-{i}',
                'region': random.choice(['us-east-1', 'us-west-2', 'eu-west-1']),
                'remediation': f'Configure appropriate security controls for {issue}',
                'timestamp': datetime.now().isoformat(),
            })
        
        summary = {
            'total_issues': len(findings),
            'critical_count': len([f for f in findings if f['severity'] == 'critical']),
            'high_count': len([f for f in findings if f['severity'] == 'high']),
            'medium_count': len([f for f in findings if f['severity'] == 'medium']),
            'cloud_provider': 'aws',  # Would detect from target
        }
        
        return {
            'success': True,
            'findings': findings,
            'summary': summary,
            'metrics': {'resources_scanned': random.randint(5, 50)},
        }
    
    def _run_infrastructure_scan(self, job: ScanJob) -> Dict:
        """Run infrastructure/network scan."""
        # This would integrate with network scanning tools
        
        import random
        
        findings = []
        network_issues = [
            'Open Port 22 (SSH)',
            'Open Port 3389 (RDP)',
            'Outdated SSL/TLS Version',
            'Weak Cipher Suites',
            'Missing Security Headers',
            'Server Information Disclosure',
            'Directory Listing Enabled',
            'Default Credentials',
            'Missing Security Patches',
        ]
        
        num_findings = random.randint(0, 6)
        
        for i in range(num_findings):
            issue = random.choice(network_issues)
            severity = 'high' if 'Port' in issue else 'medium'
            
            findings.append({
                'id': f"INFRA-{random.randint(1000, 9999)}",
                'name': issue,
                'severity': severity,
                'description': f'Infrastructure vulnerability: {issue}',
                'port': random.randint(1, 65535) if 'Port' in issue else None,
                'protocol': random.choice(['TCP', 'UDP']),
                'remediation': f'Close unnecessary ports and secure services',
                'timestamp': datetime.now().isoformat(),
            })
        
        summary = {
            'total_vulnerabilities': len(findings),
            'open_ports': random.randint(0, 20),
            'services_detected': random.randint(1, 10),
            'tls_issues': len([f for f in findings if 'SSL' in f['name'] or 'TLS' in f['name']]),
        }
        
        return {
            'success': True,
            'findings': findings,
            'summary': summary,
            'metrics': {'ports_scanned': 1000, 'hosts_scanned': 1},
        }
    
    def _run_api_scan(self, job: ScanJob) -> Dict:
        """Run API security scan."""
        import random
        
        findings = []
        api_issues = [
            'Broken Object Level Authorization',
            'Broken Authentication',
            'Excessive Data Exposure',
            'Lack of Resources & Rate Limiting',
            'Broken Function Level Authorization',
            'Mass Assignment',
            'Security Misconfiguration',
            'Injection',
            'Improper Assets Management',
            'Insufficient Logging & Monitoring',
        ]
        
        num_findings = random.randint(0, 4)
        
        for i in range(num_findings):
            issue = random.choice(api_issues)
            severity = random.choice(['high', 'medium', 'low'])
            
            findings.append({
                'id': f"API-{random.randint(1000, 9999)}",
                'name': issue,
                'severity': severity,
                'description': f'API security issue: {issue}',
                'endpoint': f'{job.target}/api/v1/endpoint-{i}',
                'method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
                'remediation': f'Implement proper {issue.replace(" ", "_").lower()} controls',
                'timestamp': datetime.now().isoformat(),
            })
        
        summary = {
            'total_issues': len(findings),
            'endpoints_tested': random.randint(5, 50),
            'authentication_bypass_possible': random.choice([True, False]),
            'rate_limiting_implemented': random.choice([True, False]),
        }
        
        return {
            'success': True,
            'findings': findings,
            'summary': summary,
            'metrics': {'requests_made': random.randint(100, 1000)},
        }
    
    def _run_generic_scan(self, job: ScanJob) -> Dict:
        """Run generic scan for unknown types."""
        return {
            'success': False,
            'findings': [],
            'summary': {'error': 'Unknown scan type'},
            'metrics': {},
        }
    
    def _save_scan_job(self, job: ScanJob):
        """Save scan job to database."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if exists
                cursor.execute("SELECT job_id FROM scan_jobs WHERE job_id = ?", (job.job_id,))
                exists = cursor.fetchone() is not None
                
                job_data = {
                    'job_id': job.job_id,
                    'target': job.target,
                    'scan_type': job.scan_type,
                    'priority': job.priority.value,
                    'schedule_json': json.dumps(job.schedule),
                    'created_at': job.created_at.isoformat(),
                    'last_run': job.last_run.isoformat() if job.last_run else None,
                    'next_run': job.next_run.isoformat() if job.next_run else None,
                    'enabled': 1 if job.enabled else 0,
                    'config_json': json.dumps(job.config) if job.config else None,
                    'metadata_json': json.dumps(job.metadata) if job.metadata else None,
                }
                
                if exists:
                    # Update
                    placeholders = ', '.join(f"{k} = ?" for k in job_data.keys() if k != 'job_id')
                    values = list(job_data.values())[1:] + [job.job_id]
                    cursor.execute(f"UPDATE scan_jobs SET {placeholders} WHERE job_id = ?", values)
                else:
                    # Insert
                    placeholders = ', '.join('?' * len(job_data))
                    columns = ', '.join(job_data.keys())
                    cursor.execute(f"INSERT INTO scan_jobs ({columns}) VALUES ({placeholders})", list(job_data.values()))
                
                # Update cache
                self.scan_jobs[job.job_id] = job
                
        except Exception as e:
            logger.error(f"Failed to save scan job {job.job_id}: {e}")
    
    def _save_scan_result(self, result: ScanResult):
        """Save scan result to database."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                result_data = {
                    'scan_id': result.scan_id,
                    'job_id': result.job_id,
                    'target': result.target,
                    'scan_type': result.scan_type,
                    'timestamp': result.timestamp.isoformat(),
                    'duration_seconds': result.duration_seconds,
                    'success': 1 if result.success else 0,
                    'error_message': result.error_message,
                    'metrics_json': json.dumps(result.metrics) if result.metrics else None,
                    'findings_json': json.dumps(result.findings) if result.findings else None,
                    'summary_json': json.dumps(result.summary) if result.summary else None,
                }
                
                # Insert or replace
                placeholders = ', '.join('?' * len(result_data))
                columns = ', '.join(result_data.keys())
                cursor.execute(f"INSERT OR REPLACE INTO scan_results ({columns}) VALUES ({placeholders})", 
                              list(result_data.values()))
                
                # Also store metrics for trend analysis
                self._store_metrics_from_scan(result)
                
        except Exception as e:
            logger.error(f"Failed to save scan result {result.scan_id}: {e}")
    
    def _store_metrics_from_scan(self, result: ScanResult):
        """Store metrics from scan result for time series analysis."""
        try:
            timestamp = result.timestamp
            target = result.target
            
            metrics_to_store = [
                ('risk_score', result.summary.get('risk_score', 0)),
                ('total_vulnerabilities', result.summary.get('total_vulnerabilities', 0)),
                ('critical_count', result.summary.get('critical_count', 0)),
                ('high_count', result.summary.get('high_count', 0)),
                ('medium_count', result.summary.get('medium_count', 0)),
                ('low_count', result.summary.get('low_count', 0)),
                ('scan_duration', result.duration_seconds),
            ]
            
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                for metric_name, metric_value in metrics_to_store:
                    cursor.execute("""
                        INSERT INTO metrics (target, metric_name, metric_value, timestamp, tags_json)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        target,
                        metric_name,
                        metric_value,
                        timestamp.isoformat(),
                        json.dumps({'scan_type': result.scan_type, 'scan_id': result.scan_id}),
                    ))
                
        except Exception as e:
            logger.error(f"Failed to store metrics from scan: {e}")
    
    def _update_metrics_cache(self, target: str, result: ScanResult):
        """Update in-memory metrics cache."""
        cache_key = target
        
        # Store recent metrics (last 1000 points)
        if cache_key not in self.metrics_cache:
            self.metrics_cache[cache_key] = deque(maxlen=1000)
        
        metric_point = {
            'timestamp': result.timestamp,
            'risk_score': result.summary.get('risk_score', 0),
            'total_vulnerabilities': result.summary.get('total_vulnerabilities', 0),
            'critical_count': result.summary.get('critical_count', 0),
            'high_count': result.summary.get('high_count', 0),
            'scan_duration': result.duration_seconds,
        }
        
        self.metrics_cache[cache_key].append(metric_point)
    
    def detect_changes(self, target: str, new_findings: List[Dict]) -> List[Dict]:
        """
        Detect changes between current and previous scans.
        
        Args:
            target: Target being scanned
            new_findings: Latest scan findings
            
        Returns:
            List of detected changes
        """
        changes = []
        
        try:
            # Get previous scan results
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT findings_json FROM scan_results 
                    WHERE target = ? AND success = 1 
                    ORDER BY timestamp DESC LIMIT 5
                """, (target,))
                
                previous_results = cursor.fetchall()
                if len(previous_results) < 2:
                    # Not enough history
                    return changes
                
                # Get most recent previous scan
                most_recent_previous = json.loads(previous_results[1]['findings_json']) if previous_results[1]['findings_json'] else []
                
                # Create sets for comparison
                prev_finding_keys = set()
                for finding in most_recent_previous:
                    key = self._get_finding_key(finding)
                    if key:
                        prev_finding_keys.add(key)
                
                new_finding_keys = set()
                for finding in new_findings:
                    key = self._get_finding_key(finding)
                    if key:
                        new_finding_keys.add(key)
                
                # Detect new findings
                new_findings_set = new_finding_keys - prev_finding_keys
                if new_findings_set:
                    changes.append({
                        'type': 'new_vulnerabilities',
                        'target': target,
                        'count': len(new_findings_set),
                        'severity': self._get_max_severity_from_keys(new_findings_set, new_findings),
                        'details': f'Found {len(new_findings_set)} new vulnerabilities',
                        'vulnerability_ids': list(new_findings_set)[:10],  # Limit output
                        'timestamp': datetime.now().isoformat(),
                    })
                
                # Detect resolved findings
                resolved_findings_set = prev_finding_keys - new_finding_keys
                if resolved_findings_set:
                    changes.append({
                        'type': 'resolved_vulnerabilities',
                        'target': target,
                        'count': len(resolved_findings_set),
                        'details': f'{len(resolved_findings_set)} vulnerabilities resolved',
                        'vulnerability_ids': list(resolved_findings_set)[:10],
                        'timestamp': datetime.now().isoformat(),
                    })
                
                # Detect severity changes
                severity_changes = self._detect_severity_changes(most_recent_previous, new_findings)
                if severity_changes:
                    changes.extend(severity_changes)
                
                # Anomaly detection
                if self.anomaly_detector:
                    anomalies = self._detect_anomalies(target, new_findings)
                    if anomalies:
                        changes.extend(anomalies)
        
        except Exception as e:
            logger.error(f"Change detection failed for {target}: {e}")
        
        return changes
    
    def _get_finding_key(self, finding: Dict) -> str:
        """Create a unique key for a finding."""
        try:
            # Use vulnerability ID if available
            if 'id' in finding:
                return finding['id']
            
            # Otherwise create a key from name and location
            name = finding.get('name', 'unknown')
            location = finding.get('url') or finding.get('endpoint') or finding.get('resource', 'unknown')
            return f"{name}:{location}"
        except:
            return ""
    
    def _get_max_severity_from_keys(self, finding_keys: Set[str], findings: List[Dict]) -> str:
        """Get maximum severity from a set of finding keys."""
        severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        max_severity = 'low'
        max_value = 0
        
        # Create mapping from key to finding
        finding_map = {}
        for finding in findings:
            key = self._get_finding_key(finding)
            if key:
                finding_map[key] = finding
        
        for key in finding_keys:
            if key in finding_map:
                severity = finding_map[key].get('severity', 'low')
                value = severity_map.get(severity, 0)
                if value > max_value:
                    max_value = value
                    max_severity = severity
        
        return max_severity
    
    def _detect_severity_changes(self, prev_findings: List[Dict], new_findings: List[Dict]) -> List[Dict]:
        """Detect changes in vulnerability severity."""
        changes = []
        
        # Create mapping from finding key to finding
        prev_map = {}
        for finding in prev_findings:
            key = self._get_finding_key(finding)
            if key:
                prev_map[key] = finding
        
        new_map = {}
        for finding in new_findings:
            key = self._get_finding_key(finding)
            if key:
                new_map[key] = finding
        
        # Check for severity changes
        for key in set(prev_map.keys()) & set(new_map.keys()):
            prev_severity = prev_map[key].get('severity', 'low')
            new_severity = new_map[key].get('severity', 'low')
            
            if prev_severity != new_severity:
                severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
                
                prev_order = severity_order.get(prev_severity, 0)
                new_order = severity_order.get(new_severity, 0)
                
                if new_order > prev_order:
                    # Severity increased
                    changes.append({
                        'type': 'severity_increased',
                        'vulnerability_key': key,
                        'previous_severity': prev_severity,
                        'new_severity': new_severity,
                        'details': f'Severity increased from {prev_severity} to {new_severity}',
                        'severity': 'warning',
                    })
                elif new_order < prev_order:
                    # Severity decreased
                    changes.append({
                        'type': 'severity_decreased',
                        'vulnerability_key': key,
                        'previous_severity': prev_severity,
                        'new_severity': new_severity,
                        'details': f'Severity decreased from {prev_severity} to {new_severity}',
                        'severity': 'info',
                    })
        
        return changes
    
    def _detect_anomalies(self, target: str, findings: List[Dict]) -> List[Dict]:
        """Detect anomalies in scan results."""
        anomalies = []
        
        if not self.anomaly_detector:
            return anomalies
        
        try:
            # Get historical metrics
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT metric_value, timestamp FROM metrics 
                    WHERE target = ? AND metric_name = 'total_vulnerabilities'
                    ORDER BY timestamp DESC LIMIT 100
                """, (target,))
                
                historical_data = cursor.fetchall()
                
                if len(historical_data) >= 10:
                    values = [row['metric_value'] for row in historical_data]
                    timestamps = [datetime.fromisoformat(row['timestamp']) for row in historical_data]
                    
                    # Reverse to chronological order
                    values.reverse()
                    timestamps.reverse()
                    
                    # Detect anomalies
                    detected_anomalies = self.anomaly_detector.detect_anomalies(
                        target, 'total_vulnerabilities', values, timestamps
                    )
                    
                    # Check if current scan is anomalous
                    current_count = len(findings)
                    if detected_anomalies and timestamps:
                        # Compare with most recent anomaly detection
                        last_value = values[-1]
                        if abs(current_count - last_value) > last_value * 0.5:  # 50% change
                            anomalies.append({
                                'type': 'anomaly_detected',
                                'target': target,
                                'metric': 'vulnerability_count',
                                'expected_range': f'{last_value * 0.5:.1f} - {last_value * 1.5:.1f}',
                                'actual_value': current_count,
                                'details': f'Vulnerability count anomaly: expected around {last_value}, got {current_count}',
                                'severity': 'warning',
                            })
        
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
        
        return anomalies
    
    def _process_changes(self, job: ScanJob, changes: List[Dict]):
        """Process detected changes and create alerts."""
        significant_changes = [
            c for c in changes 
            if c.get('severity') in ['warning', 'critical'] or 
               c['type'] in ['new_vulnerabilities', 'severity_increased', 'anomaly_detected']
        ]
        
        if not significant_changes:
            return
        
        # Create alert
        alert_id = hashlib.sha256(
            f"{job.target}{datetime.now().isoformat()}{len(changes)}".encode()
        ).hexdigest()[:16]
        
        # Determine overall severity
        severities = [c.get('severity', 'info') for c in significant_changes]
        severity_map = {'critical': 4, 'warning': 3, 'info': 2, 'low': 1}
        max_severity_value = max(severity_map.get(s, 0) for s in severities)
        overall_severity = next(
            (k for k, v in severity_map.items() if v == max_severity_value),
            AlertSeverity.INFO
        )
        
        # Create alert title and description
        title = f"Security Changes Detected for {job.target}"
        description = f"Found {len(significant_changes)} significant security changes"
        
        alert = SecurityAlert(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=AlertSeverity(overall_severity),
            source=f"scan_{job.scan_type}",
            target=job.target,
            timestamp=datetime.now(),
            metadata={
                'job_id': job.job_id,
                'scan_type': job.scan_type,
                'total_changes': len(changes),
                'significant_changes': len(significant_changes),
            },
            evidence={
                'changes': significant_changes,
                'scan_summary': job.metadata.get('last_scan_summary', {}),
            },
            recommendations=[
                'Review the detected changes',
                'Prioritize remediation based on severity',
                'Update security controls as needed',
            ],
        )
        
        # Send alert
        self.alert_manager.send_alert(alert)
        
        # Store alert
        self._save_alert(alert)
        self.alert_history.append(alert)
        
        # Update performance metrics
        self.performance_metrics['alerts_sent'] += 1
    
    def _save_alert(self, alert: SecurityAlert):
        """Save alert to database."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                alert_data = {
                    'alert_id': alert.alert_id,
                    'title': alert.title,
                    'description': alert.description,
                    'severity': alert.severity.value,
                    'source': alert.source,
                    'target': alert.target,
                    'timestamp': alert.timestamp.isoformat(),
                    'acknowledged': 1 if alert.acknowledged else 0,
                    'resolved': 1 if alert.resolved else 0,
                    'metadata_json': json.dumps(alert.metadata) if alert.metadata else None,
                    'evidence_json': json.dumps(alert.evidence) if alert.evidence else None,
                    'recommendations_json': json.dumps(alert.recommendations) if alert.recommendations else None,
                }
                
                placeholders = ', '.join('?' * len(alert_data))
                columns = ', '.join(alert_data.keys())
                cursor.execute(f"INSERT INTO alerts ({columns}) VALUES ({placeholders})", 
                              list(alert_data.values()))
                
        except Exception as e:
            logger.error(f"Failed to save alert {alert.alert_id}: {e}")
    
    def _monitoring_loop(self):
        """Continuous monitoring loop."""
        while self.running:
            try:
                # Check for compliance violations
                self._check_compliance()
                
                # Check for overdue scans
                self._check_overdue_scans()
                
                # Clean up old data
                self._cleanup_old_data()
                
                # Sleep
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(5)
    
    def _check_compliance(self):
        """Check compliance against configured frameworks."""
        frameworks = self.config['compliance']['frameworks']
        
        for framework in frameworks:
            compliance_status = self._assess_compliance(framework)
            self.compliance_status[framework] = compliance_status
            
            # Check for compliance violations
            if compliance_status.get('compliance_score', 100) < 80:
                # Create compliance alert
                self._create_compliance_alert(framework, compliance_status)
    
    def _assess_compliance(self, framework: str) -> Dict:
        """Assess compliance with a specific framework."""
        # This would implement framework-specific compliance checks
        # For now, return simulated results
        
        import random
        
        controls = {
            'OWASP': [
                'A1:2017-Injection',
                'A2:2017-Broken Authentication',
                'A3:2017-Sensitive Data Exposure',
                'A4:2017-XML External Entities (XXE)',
                'A5:2017-Broken Access Control',
                'A6:2017-Security Misconfiguration',
                'A7:2017-Cross-Site Scripting (XSS)',
                'A8:2017-Insecure Deserialization',
                'A9:2017-Using Components with Known Vulnerabilities',
                'A10:2017-Insufficient Logging & Monitoring',
            ],
            'CIS': [
                'CIS Control 1: Inventory and Control of Hardware Assets',
                'CIS Control 2: Inventory and Control of Software Assets',
                'CIS Control 3: Continuous Vulnerability Management',
                'CIS Control 4: Controlled Use of Administrative Privileges',
                'CIS Control 5: Secure Configuration for Hardware and Software',
                'CIS Control 6: Maintenance, Monitoring and Analysis of Audit Logs',
                'CIS Control 7: Email and Web Browser Protections',
                'CIS Control 8: Malware Defenses',
                'CIS Control 9: Limitation and Control of Network Ports',
                'CIS Control 10: Data Recovery Capabilities',
            ],
            'PCI-DSS': [
                'Requirement 1: Install and maintain a firewall configuration',
                'Requirement 2: Do not use vendor-supplied defaults',
                'Requirement 3: Protect stored cardholder data',
                'Requirement 4: Encrypt transmission of cardholder data',
                'Requirement 5: Protect all systems against malware',
                'Requirement 6: Develop and maintain secure systems',
                'Requirement 7: Restrict access to cardholder data',
                'Requirement 8: Identify and authenticate access',
                'Requirement 9: Restrict physical access to cardholder data',
                'Requirement 10: Track and monitor all access',
                'Requirement 11: Regularly test security systems',
                'Requirement 12: Maintain a policy that addresses information security',
            ],
        }
        
        framework_controls = controls.get(framework, [])
        if not framework_controls:
            return {'compliance_score': 100, 'status': 'compliant'}
        
        # Simulate compliance assessment
        passed = random.randint(len(framework_controls) // 2, len(framework_controls))
        failed = len(framework_controls) - passed
        
        compliance_score = (passed / len(framework_controls)) * 100
        
        return {
            'framework': framework,
            'compliance_score': compliance_score,
            'total_controls': len(framework_controls),
            'passed_controls': passed,
            'failed_controls': failed,
            'status': 'compliant' if compliance_score >= 80 else 'non-compliant',
            'last_assessment': datetime.now().isoformat(),
        }
    
    def _create_compliance_alert(self, framework: str, compliance_status: Dict):
        """Create alert for compliance violations."""
        if compliance_status.get('compliance_score', 100) >= 80:
            return
        
        alert_id = hashlib.sha256(
            f"compliance_{framework}_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        score = compliance_status['compliance_score']
        failed = compliance_status.get('failed_controls', 0)
        
        alert = SecurityAlert(
            alert_id=alert_id,
            title=f"Compliance Violation: {framework}",
            description=f"{framework} compliance score is {score:.1f}% ({failed} controls failed)",
            severity=AlertSeverity.HIGH if score < 70 else AlertSeverity.MEDIUM,
            source="compliance_monitor",
            target="all",
            timestamp=datetime.now(),
            metadata=compliance_status,
            recommendations=[
                f"Review failed {framework} controls",
                "Implement remediation measures",
                "Schedule compliance re-assessment",
            ],
        )
        
        # Send alert
        self.alert_manager.send_alert(alert)
        self._save_alert(alert)
    
    def _check_overdue_scans(self):
        """Check for overdue scans and create alerts."""
        now = datetime.now()
        
        for job in self.scan_jobs.values():
            if not job.enabled:
                continue
            
            if job.next_run and job.next_run < now:
                # Scan is overdue
                overdue_minutes = (now - job.next_run).total_seconds() / 60
                
                if overdue_minutes > 60:  # More than 1 hour overdue
                    alert_id = hashlib.sha256(
                        f"overdue_{job.job_id}_{now.isoformat()}".encode()
                    ).hexdigest()[:16]
                    
                    alert = SecurityAlert(
                        alert_id=alert_id,
                        title=f"Overdue Scan: {job.target}",
                        description=f"Scheduled {job.scan_type} scan is {overdue_minutes:.0f} minutes overdue",
                        severity=AlertSeverity.MEDIUM,
                        source="scheduler",
                        target=job.target,
                        timestamp=now,
                        metadata={
                            'job_id': job.job_id,
                            'scan_type': job.scan_type,
                            'scheduled_time': job.next_run.isoformat() if job.next_run else None,
                            'overdue_minutes': overdue_minutes,
                        },
                        recommendations=[
                            "Check scanner availability",
                            "Verify target accessibility",
                            "Review scan schedule",
                        ],
                    )
                    
                    self.alert_manager.send_alert(alert)
                    self._save_alert(alert)
    
    def _cleanup_old_data(self):
        """Clean up old data based on retention policy."""
        retention_days = self.config['storage']['retention_days']
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Delete old scan results
                cursor.execute("DELETE FROM scan_results WHERE timestamp < ?", 
                             (cutoff_date.isoformat(),))
                
                # Delete old metrics
                cursor.execute("DELETE FROM metrics WHERE timestamp < ?",
                             (cutoff_date.isoformat(),))
                
                # Delete old alerts (keep for longer)
                alert_cutoff = datetime.now() - timedelta(days=retention_days * 2)
                cursor.execute("DELETE FROM alerts WHERE timestamp < ? AND resolved = 1",
                             (alert_cutoff.isoformat(),))
                
                deleted_rows = cursor.rowcount
                if deleted_rows > 0:
                    logger.info(f"Cleaned up {deleted_rows} old records")
                    
        except Exception as e:
            logger.error(f"Data cleanup failed: {e}")
    
    def _alert_processing_loop(self):
        """Process alerts and send notifications."""
        while self.running:
            try:
                # Check for unsent alerts
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT * FROM alerts 
                        WHERE resolved = 0 
                        ORDER BY timestamp DESC LIMIT 10
                    """)
                    
                    alerts_to_process = cursor.fetchall()
                    
                    for row in alerts_to_process:
                        # Convert row to SecurityAlert
                        alert = SecurityAlert(
                            alert_id=row['alert_id'],
                            title=row['title'],
                            description=row['description'],
                            severity=AlertSeverity(row['severity']),
                            source=row['source'],
                            target=row['target'],
                            timestamp=datetime.fromisoformat(row['timestamp']),
                            acknowledged=bool(row['acknowledged']),
                            resolved=bool(row['resolved']),
                            metadata=json.loads(row['metadata_json']) if row['metadata_json'] else {},
                            evidence=json.loads(row['evidence_json']) if row['evidence_json'] else {},
                            recommendations=json.loads(row['recommendations_json']) if row['recommendations_json'] else [],
                        )
                        
                        # Send via alert manager
                        self.alert_manager.send_alert(alert)
                        
                        # Mark as acknowledged
                        cursor.execute("UPDATE alerts SET acknowledged = 1 WHERE alert_id = ?",
                                     (alert.alert_id,))
                
                # Sleep
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Alert processing loop error: {e}")
                time.sleep(5)
    
    def _performance_monitoring_loop(self):
        """Monitor system performance."""
        while self.running:
            try:
                # Monitor system resources
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Update performance metrics
                self.performance_metrics.update({
                    'system_load': cpu_percent,
                    'memory_usage': memory.percent,
                    'disk_usage': disk.percent,
                    'active_threads': threading.active_count(),
                    'queue_size': len(self.scan_queue),
                    'active_scans': len(self.active_scans),
                })
                
                # Check for resource exhaustion
                if cpu_percent > self.config['performance']['max_cpu_percent']:
                    logger.warning(f"High CPU usage: {cpu_percent}%")
                
                if memory.percent > self.config['performance']['max_memory_percent']:
                    logger.warning(f"High memory usage: {memory.percent}%")
                    
                    # Adjust scheduling if auto-scaling enabled
                    if self.config['performance']['auto_scaling']:
                        self._adjust_scheduling_for_performance()
                
                # Log performance metrics periodically
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    logger.info(f"Performance metrics: CPU={cpu_percent}%, Memory={memory.percent}%, "
                              f"Active scans={len(self.active_scans)}, Queue={len(self.scan_queue)}")
                
                # Sleep
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                time.sleep(5)
    
    def _adjust_scheduling_for_performance(self):
        """Adjust scheduling based on system performance."""
        # Reduce concurrent scans if system is under heavy load
        current_max = self.config['scheduling']['max_concurrent_scans']
        
        if self.performance_metrics['memory_usage'] > 90:
            new_max = max(1, current_max // 2)
            self.config['scheduling']['max_concurrent_scans'] = new_max
            logger.warning(f"Reduced max concurrent scans from {current_max} to {new_max}")
        
        elif self.performance_metrics['memory_usage'] < 50 and current_max < 10:
            # Increase if resources are available
            new_max = min(20, current_max * 2)
            self.config['scheduling']['max_concurrent_scans'] = new_max
            logger.info(f"Increased max concurrent scans from {current_max} to {new_max}")
    
    def _save_state(self):
        """Save current state to disk."""
        try:
            state = {
                'scan_jobs': {jid: asdict(job) for jid, job in self.scan_jobs.items()},
                'performance_metrics': self.performance_metrics,
                'last_save': datetime.now().isoformat(),
            }
            
            with open('monitoring_state.json', 'w') as f:
                json.dump(state, f, indent=2, default=str)
            
            logger.info("Monitoring state saved")
            
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def add_scan_job(self, target: str, scan_type: str, schedule: Dict, 
                     priority: ScanPriority = ScanPriority.MEDIUM,
                     config: Optional[Dict] = None) -> str:
        """
        Add a new scan job.
        
        Args:
            target: Target to scan
            scan_type: Type of scan (web, cloud, infrastructure, api)
            schedule: Schedule configuration
            priority: Scan priority
            config: Additional scan configuration
            
        Returns:
            Job ID
        """
        job_id = hashlib.sha256(
            f"{target}{scan_type}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        job = ScanJob(
            job_id=job_id,
            target=target,
            scan_type=scan_type,
            priority=priority,
            schedule=schedule,
            next_run=self._calculate_next_run_from_schedule(schedule),
            config=config or {},
            metadata={
                'created_by': 'system',
                'last_modified': datetime.now().isoformat(),
            },
        )
        
        # Save to database
        self._save_scan_job(job)
        
        logger.info(f"Added scan job {job_id} for {target} ({scan_type})")
        
        return job_id
    
    def _calculate_next_run_from_schedule(self, schedule: Dict) -> datetime:
        """Calculate next run time from schedule configuration."""
        now = datetime.now()
        
        if schedule.get('type') == 'immediate':
            return now
        
        elif schedule.get('type') == 'daily':
            hour = schedule.get('hour', 2)
            minute = schedule.get('minute', 0)
            
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run < now:
                next_run += timedelta(days=1)
            
            return next_run
        
        elif schedule.get('type') == 'weekly':
            day = schedule.get('day', 0)  # 0 = Monday
            hour = schedule.get('hour', 2)
            minute = schedule.get('minute', 0)
            
            days_ahead = (day - now.weekday()) % 7
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            next_run += timedelta(days=days_ahead)
            
            if next_run < now:
                next_run += timedelta(weeks=1)
            
            return next_run
        
        elif schedule.get('type') == 'cron':
            # Parse cron expression
            cron_expr = schedule.get('expression', '0 2 * * *')
            # Simplified cron parser (would use a library in production)
            if cron_expr == '0 2 * * *':
                next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
                if next_run < now:
                    next_run += timedelta(days=1)
                return next_run
            else:
                # Default to daily at 2 AM
                next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
                if next_run < now:
                    next_run += timedelta(days=1)
                return next_run
        
        else:
            # Default: daily at 2 AM
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if next_run < now:
                next_run += timedelta(days=1)
            return next_run
    
    def get_scan_results(self, target: Optional[str] = None, 
                         days: int = 7, 
                         limit: int = 100) -> List[Dict]:
        """
        Get scan results.
        
        Args:
            target: Filter by target
            days: Number of days to look back
            limit: Maximum number of results
            
        Returns:
            List of scan results
        """
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                cutoff_date = datetime.now() - timedelta(days=days)
                
                if target:
                    cursor.execute("""
                        SELECT * FROM scan_results 
                        WHERE target = ? AND timestamp >= ? 
                        ORDER BY timestamp DESC LIMIT ?
                    """, (target, cutoff_date.isoformat(), limit))
                else:
                    cursor.execute("""
                        SELECT * FROM scan_results 
                        WHERE timestamp >= ? 
                        ORDER BY timestamp DESC LIMIT ?
                    """, (cutoff_date.isoformat(), limit))
                
                results = []
                for row in cursor.fetchall():
                    result = {
                        'scan_id': row['scan_id'],
                        'job_id': row['job_id'],
                        'target': row['target'],
                        'scan_type': row['scan_type'],
                        'timestamp': row['timestamp'],
                        'duration_seconds': row['duration_seconds'],
                        'success': bool(row['success']),
                        'error_message': row['error_message'],
                        'metrics': json.loads(row['metrics_json']) if row['metrics_json'] else {},
                        'findings': json.loads(row['findings_json']) if row['findings_json'] else [],
                        'summary': json.loads(row['summary_json']) if row['summary_json'] else {},
                    }
                    results.append(result)
                
                return results
                
        except Exception as e:
            logger.error(f"Failed to get scan results: {e}")
            return []
    
    def get_security_dashboard(self) -> Dict[str, Any]:
        """
        Get security dashboard data.
        
        Returns:
            Dashboard data including metrics, alerts, and trends
        """
        dashboard = {
            'overview': self._get_dashboard_overview(),
            'alerts': self._get_recent_alerts(limit=10),
            'scans': self._get_recent_scans(limit=10),
            'trends': self._get_security_trends(days=30),
            'compliance': self.compliance_status,
            'performance': self.performance_metrics,
        }
        
        return dashboard
    
    def _get_dashboard_overview(self) -> Dict[str, Any]:
        """Get dashboard overview metrics."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Total scans
                cursor.execute("SELECT COUNT(*) as count FROM scan_results")
                total_scans = cursor.fetchone()['count']
                
                # Successful scans
                cursor.execute("SELECT COUNT(*) as count FROM scan_results WHERE success = 1")
                successful_scans = cursor.fetchone()['count']
                
                # Total alerts
                cursor.execute("SELECT COUNT(*) as count FROM alerts")
                total_alerts = cursor.fetchone()['count']
                
                # Unresolved alerts
                cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE resolved = 0")
                unresolved_alerts = cursor.fetchone()['count']
                
                # Average risk score (last 30 days)
                cutoff_date = datetime.now() - timedelta(days=30)
                cursor.execute("""
                    SELECT AVG(metric_value) as avg_risk FROM metrics 
                    WHERE metric_name = 'risk_score' AND timestamp >= ?
                """, (cutoff_date.isoformat(),))
                avg_risk = cursor.fetchone()['avg_risk'] or 0
                
                return {
                    'total_scans': total_scans,
                    'success_rate': (successful_scans / total_scans * 100) if total_scans > 0 else 0,
                    'total_alerts': total_alerts,
                    'unresolved_alerts': unresolved_alerts,
                    'avg_risk_score': float(avg_risk),
                    'active_jobs': len(self.scan_jobs),
                    'queue_size': len(self.scan_queue),
                    'uptime_seconds': (datetime.now() - self._get_start_time()).total_seconds(),
                }
                
        except Exception as e:
            logger.error(f"Failed to get dashboard overview: {e}")
            return {}
    
    def _get_start_time(self) -> datetime:
        """Get platform start time."""
        # This would track actual start time
        # For now, return a fixed time
        return datetime.now() - timedelta(hours=24)
    
    def _get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """Get recent alerts."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM alerts 
                    ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
                
                alerts = []
                for row in cursor.fetchall():
                    alert = {
                        'id': row['alert_id'],
                        'title': row['title'],
                        'severity': row['severity'],
                        'target': row['target'],
                        'timestamp': row['timestamp'],
                        'acknowledged': bool(row['acknowledged']),
                        'resolved': bool(row['resolved']),
                    }
                    alerts.append(alert)
                
                return alerts
                
        except Exception as e:
            logger.error(f"Failed to get recent alerts: {e}")
            return []
    
    def _get_recent_scans(self, limit: int = 10) -> List[Dict]:
        """Get recent scans."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT scan_id, target, scan_type, timestamp, duration_seconds, 
                           success, summary_json 
                    FROM scan_results 
                    ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
                
                scans = []
                for row in cursor.fetchall():
                    summary = json.loads(row['summary_json']) if row['summary_json'] else {}
                    scan = {
                        'id': row['scan_id'],
                        'target': row['target'],
                        'type': row['scan_type'],
                        'timestamp': row['timestamp'],
                        'duration': row['duration_seconds'],
                        'success': bool(row['success']),
                        'vulnerabilities': summary.get('total_vulnerabilities', 0),
                        'risk_score': summary.get('risk_score', 0),
                    }
                    scans.append(scan)
                
                return scans
                
        except Exception as e:
            logger.error(f"Failed to get recent scans: {e}")
            return []
    
    def _get_security_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get security trends."""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get daily metrics
                cursor.execute("""
                    SELECT 
                        DATE(timestamp) as date,
                        AVG(CASE WHEN metric_name = 'risk_score' THEN metric_value END) as avg_risk,
                        AVG(CASE WHEN metric_name = 'total_vulnerabilities' THEN metric_value END) as avg_vulns,
                        COUNT(DISTINCT scan_id) as scan_count
                    FROM metrics 
                    LEFT JOIN scan_results ON metrics.tags_json LIKE '%' || scan_results.scan_id || '%'
                    WHERE metrics.timestamp >= ?
                    GROUP BY DATE(timestamp)
                    ORDER BY date
                """, (cutoff_date.isoformat(),))
                
                daily_data = []
                for row in cursor.fetchall():
                    daily_data.append({
                        'date': row['date'],
                        'avg_risk': float(row['avg_risk'] or 0),
                        'avg_vulnerabilities': float(row['avg_vulns'] or 0),
                        'scan_count': row['scan_count'],
                    })
                
                # Calculate trends
                if len(daily_data) >= 2:
                    first_day = daily_data[0]
                    last_day = daily_data[-1]
                    
                    risk_change = last_day['avg_risk'] - first_day['avg_risk']
                    vuln_change = last_day['avg_vulnerabilities'] - first_day['avg_vulnerabilities']
                    
                    risk_trend = 'increasing' if risk_change > 0.1 else 'decreasing' if risk_change < -0.1 else 'stable'
                    vuln_trend = 'increasing' if vuln_change > 0.1 else 'decreasing' if vuln_change < -0.1 else 'stable'
                    
                else:
                    risk_trend = 'stable'
                    vuln_trend = 'stable'
                
                return {
                    'period_days': days,
                    'daily_data': daily_data,
                    'risk_trend': risk_trend,
                    'vulnerability_trend': vuln_trend,
                    'scan_frequency': len(daily_data) / days if days > 0 else 0,
                }
                
        except Exception as e:
            logger.error(f"Failed to get security trends: {e}")
            return {'period_days': days, 'error': str(e)}
    
    def run_trend_analysis(self, target: str, days: int = 30) -> TrendAnalysis:
        """
        Run advanced trend analysis.
        
        Args:
            target: Target to analyze
            days: Analysis period in days
            
        Returns:
            Trend analysis results
        """
        start_date = datetime.now() - timedelta(days=days)
        end_date = datetime.now()
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get metrics for the period
                cursor.execute("""
                    SELECT metric_name, metric_value, timestamp 
                    FROM metrics 
                    WHERE target = ? AND timestamp >= ?
                    ORDER BY timestamp
                """, (target, start_date.isoformat()))
                
                metrics_data = defaultdict(list)
                timestamps = []
                
                for row in cursor.fetchall():
                    metric_name = row['metric_name']
                    metric_value = row['metric_value']
                    timestamp = datetime.fromisoformat(row['timestamp'])
                    
                    metrics_data[metric_name].append(metric_value)
                    if metric_name == 'risk_score':  # Use risk score timestamps
                        timestamps.append(timestamp)
                
                # Calculate summary statistics
                metrics_summary = {}
                for metric_name, values in metrics_data.items():
                    if values:
                        metrics_summary[metric_name] = {
                            'min': min(values),
                            'max': max(values),
                            'avg': sum(values) / len(values),
                            'count': len(values),
                            'std_dev': np.std(values) if len(values) > 1 else 0,
                        }
                
                # Detect trends
                trends = {}
                if 'risk_score' in metrics_data:
                    risk_values = metrics_data['risk_score']
                    if len(risk_values) >= 2:
                        # Simple linear regression for trend
                        x = list(range(len(risk_values)))
                        y = risk_values
                        
                        # Calculate slope
                        n = len(x)
                        sum_x = sum(x)
                        sum_y = sum(y)
                        sum_xy = sum(x[i] * y[i] for i in range(n))
                        sum_x2 = sum(x_i * x_i for x_i in x)
                        
                        try:
                            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
                            
                            if slope > 0.05:
                                trends['risk_score'] = 'increasing'
                            elif slope < -0.05:
                                trends['risk_score'] = 'decreasing'
                            else:
                                trends['risk_score'] = 'stable'
                        except:
                            trends['risk_score'] = 'unknown'
                
                # Detect anomalies
                anomalies = []
                if self.anomaly_detector and 'total_vulnerabilities' in metrics_data:
                    vuln_values = metrics_data['total_vulnerabilities']
                    if len(vuln_values) >= 10:
                        detected_anomalies = self.anomaly_detector.detect_anomalies(
                            target, 'total_vulnerabilities', vuln_values, timestamps[:len(vuln_values)]
                        )
                        anomalies = detected_anomalies[:5]  # Limit to 5
                
                # Generate forecasts (simplified)
                forecasts = {}
                if 'risk_score' in metrics_data and len(metrics_data['risk_score']) >= 5:
                    risk_values = metrics_data['risk_score']
                    # Simple moving average forecast
                    last_values = risk_values[-5:]
                    forecasts['risk_score_next'] = sum(last_values) / len(last_values)
                    forecasts['confidence'] = 'medium'
                
                # Generate recommendations
                recommendations = []
                avg_risk = metrics_summary.get('risk_score', {}).get('avg', 0)
                
                if avg_risk > 70:
                    recommendations.extend([
                        "High risk score detected. Prioritize remediation efforts.",
                        "Consider increasing scan frequency for this target.",
                        "Review critical and high severity findings immediately.",
                    ])
                elif avg_risk > 40:
                    recommendations.extend([
                        "Moderate risk score. Continue regular monitoring.",
                        "Address medium severity findings within the next week.",
                        "Consider implementing additional security controls.",
                    ])
                else:
                    recommendations.extend([
                        "Low risk score. Maintain current security posture.",
                        "Continue regular monitoring and scanning.",
                        "Consider expanding test coverage to new areas.",
                    ])
                
                if anomalies:
                    recommendations.append("Anomalies detected in vulnerability counts. Investigate root causes.")
                
                if trends.get('risk_score') == 'increasing':
                    recommendations.append("Risk score is trending upward. Investigate causes and implement countermeasures.")
                
                analysis = TrendAnalysis(
                    period_days=days,
                    start_date=start_date,
                    end_date=end_date,
                    metrics_summary=metrics_summary,
                    trends=trends,
                    forecasts=forecasts,
                    anomalies=anomalies,
                    recommendations=recommendations,
                )
                
                return analysis
                
        except Exception as e:
            logger.error(f"Trend analysis failed for {target}: {e}")
            
            # Return empty analysis
            return TrendAnalysis(
                period_days=days,
                start_date=start_date,
                end_date=end_date,
                metrics_summary={},
                trends={},
                forecasts={},
                anomalies=[],
                recommendations=[f"Analysis failed: {str(e)}"],
            )
    
    def export_report(self, format: str = 'json', days: int = 30) -> str:
        """
        Export monitoring report.
        
        Args:
            format: Report format (json, html, pdf, csv)
            days: Report period in days
            
        Returns:
            Path to exported report file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{timestamp}.{format}"
        filepath = os.path.join('reports', filename)
        
        os.makedirs('reports', exist_ok=True)
        
        # Generate report data
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'period_days': days,
            'dashboard': self.get_security_dashboard(),
            'scan_jobs': [asdict(job) for job in self.scan_jobs.values()],
            'recent_alerts': self._get_recent_alerts(limit=50),
            'compliance_status': self.compliance_status,
            'performance_metrics': self.performance_metrics,
        }
        
        try:
            if format == 'json':
                with open(filepath, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
            
            elif format == 'html':
                # Generate HTML report
                html_content = self._generate_html_report(report_data)
                with open(filepath, 'w') as f:
                    f.write(html_content)
            
            elif format == 'csv':
                # Generate CSV for scan results
                scan_results = self.get_scan_results(days=days, limit=1000)
                df = pd.DataFrame(scan_results)
                df.to_csv(filepath, index=False)
            
            else:
                # Default to JSON
                with open(filepath, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
            
            logger.info(f"Report exported to {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            return ""
    
    def _generate_html_report(self, report_data: Dict) -> str:
        """Generate HTML report."""
        # Simplified HTML report generation
        # In production, would use a template engine like Jinja2
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Monitoring Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #555; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
                .card {{ background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background: white; border-radius: 3px; }}
                .critical {{ color: #dc3545; }}
                .high {{ color: #fd7e14; }}
                .medium {{ color: #ffc107; }}
                .low {{ color: #28a745; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Security Monitoring Report</h1>
            <p>Generated: {report_data['generated_at']}</p>
            <p>Period: {report_data['period_days']} days</p>
            
            <h2>Overview</h2>
            <div class="card">
        """
        
        # Add metrics
        overview = report_data['dashboard']['overview']
        if overview:
            html += f"""
                <div class="metric">Total Scans: <strong>{overview.get('total_scans', 0)}</strong></div>
                <div class="metric">Success Rate: <strong>{overview.get('success_rate', 0):.1f}%</strong></div>
                <div class="metric">Avg Risk Score: <strong>{overview.get('avg_risk_score', 0):.1f}</strong></div>
                <div class="metric">Active Jobs: <strong>{overview.get('active_jobs', 0)}</strong></div>
                <div class="metric">Unresolved Alerts: <strong>{overview.get('unresolved_alerts', 0)}</strong></div>
            """
        
        html += """
            </div>
            
            <h2>Recent Alerts</h2>
            <table>
                <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Target</th>
                    <th>Status</th>
                </tr>
        """
        
        # Add alerts table
        for alert in report_data['recent_alerts'][:10]:
            severity_class = alert.get('severity', 'low')
            html += f"""
                <tr>
                    <td>{alert.get('timestamp', '')}</td>
                    <td class="{severity_class}">{severity_class.upper()}</td>
                    <td>{alert.get('title', '')}</td>
                    <td>{alert.get('target', '')}</td>
                    <td>{'Resolved' if alert.get('resolved') else 'Acknowledged' if alert.get('acknowledged') else 'New'}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <h2>Compliance Status</h2>
            <table>
                <tr>
                    <th>Framework</th>
                    <th>Score</th>
                    <th>Status</th>
                    <th>Failed Controls</th>
                </tr>
        """
        
        # Add compliance table
        for framework, status in report_data['compliance_status'].items():
            score = status.get('compliance_score', 0)
            status_text = status.get('status', 'unknown')
            failed = status.get('failed_controls', 0)
            
            html += f"""
                <tr>
                    <td>{framework}</td>
                    <td>{score:.1f}%</td>
                    <td>{status_text}</td>
                    <td>{failed}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <h2>Performance Metrics</h2>
            <div class="card">
        """
        
        # Add performance metrics
        perf = report_data['performance_metrics']
        html += f"""
                <div class="metric">CPU Usage: <strong>{perf.get('system_load', 0):.1f}%</strong></div>
                <div class="metric">Memory Usage: <strong>{perf.get('memory_usage', 0):.1f}%</strong></div>
                <div class="metric">Queue Size: <strong>{perf.get('queue_size', 0)}</strong></div>
                <div class="metric">Active Scans: <strong>{perf.get('active_scans', 0)}</strong></div>
                <div class="metric">Alerts Sent: <strong>{perf.get('alerts_sent', 0)}</strong></div>
            </div>
        </body>
        </html>
        """
        
        return html

class AdvancedAlertManager:
    """Advanced alert manager with multiple channels and smart routing."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.channels = self._initialize_channels()
        self.alert_throttle = {}
        
    def _initialize_channels(self) -> Dict[str, Any]:
        """Initialize alert channels."""
        channels = {}
        
        # Console channel (always available)
        channels['console'] = ConsoleAlertChannel()
        
        # Email channel
        if self.config.get('email_settings'):
            try:
                channels['email'] = EmailAlertChannel(self.config['email_settings'])
            except Exception as e:
                logger.error(f"Email channel initialization failed: {e}")
        
        # Slack channel
        if self.config.get('slack_webhook'):
            try:
                channels['slack'] = SlackAlertChannel(self.config['slack_webhook'])
            except Exception as e:
                logger.error(f"Slack channel initialization failed: {e}")
        
        # Microsoft Teams channel
        if self.config.get('teams_webhook'):
            try:
                channels['teams'] = TeamsAlertChannel(self.config['teams_webhook'])
            except Exception as e:
                logger.error(f"Teams channel initialization failed: {e}")
        
        # SMS channel
        if self.config.get('sms_gateway'):
            try:
                channels['sms'] = SMSAlertChannel(self.config['sms_gateway'])
            except Exception as e:
                logger.error(f"SMS channel initialization failed: {e}")
        
        # PagerDuty channel
        if self.config.get('pagerduty_api_key'):
            try:
                channels['pagerduty'] = PagerDutyAlertChannel(self.config['pagerduty_api_key'])
            except Exception as e:
                logger.error(f"PagerDuty channel initialization failed: {e}")
        
        # Webhook channels
        for webhook_url in self.config.get('webhook_urls', []):
            try:
                name = hashlib.md5(webhook_url.encode()).hexdigest()[:8]
                channels[f'webhook_{name}'] = WebhookAlertChannel(webhook_url)
            except Exception as e:
                logger.error(f"Webhook channel initialization failed: {e}")
        
        logger.info(f"Initialized {len(channels)} alert channels")
        return channels
    
    def send_alert(self, alert: SecurityAlert):
        """
        Send alert through appropriate channels.
        
        Args:
            alert: Security alert to send
        """
        # Check throttling
        if self._should_throttle(alert):
            logger.warning(f"Alert throttled for target {alert.target}")
            return
        
        # Determine which channels to use based on severity
        channels_to_use = self._determine_channels_for_severity(alert.severity)
        
        # Send through each channel
        results = []
        for channel_name in channels_to_use:
            if channel_name in self.channels:
                try:
                    channel = self.channels[channel_name]
                    result = channel.send(alert)
                    results.append((channel_name, result))
                    
                    if result:
                        logger.debug(f"Alert sent via {channel_name}")
                    else:
                        logger.warning(f"Alert failed via {channel_name}")
                        
                except Exception as e:
                    logger.error(f"Alert channel {channel_name} failed: {e}")
        
        # Update throttle counter
        self._update_throttle(alert)
        
        return results
    
    def _should_throttle(self, alert: SecurityAlert) -> bool:
        """Check if alert should be throttled."""
        if not self.config.get('throttling_enabled', True):
            return False
        
        throttle_window = self.config.get('throttling_window', 300)  # 5 minutes
        max_alerts = self.config.get('max_alerts_per_window', 10)
        
        now = time.time()
        throttle_key = f"{alert.target}:{alert.severity.value}"
        
        if throttle_key not in self.alert_throttle:
            self.alert_throttle[throttle_key] = {
                'count': 0,
                'window_start': now,
            }
        
        throttle_info = self.alert_throttle[throttle_key]
        
        # Reset if window has passed
        if now - throttle_info['window_start'] > throttle_window:
            throttle_info['count'] = 0
            throttle_info['window_start'] = now
        
        # Check if limit exceeded
        if throttle_info['count'] >= max_alerts:
            return True
        
        return False
    
    def _update_throttle(self, alert: SecurityAlert):
        """Update throttle counter."""
        throttle_key = f"{alert.target}:{alert.severity.value}"
        
        if throttle_key not in self.alert_throttle:
            self.alert_throttle[throttle_key] = {
                'count': 0,
                'window_start': time.time(),
            }
        
        self.alert_throttle[throttle_key]['count'] += 1
    
    def _determine_channels_for_severity(self, severity: AlertSeverity) -> List[str]:
        """Determine which channels to use based on severity."""
        severity_config = {
            AlertSeverity.CRITICAL: ['console', 'pagerduty', 'sms', 'slack', 'teams', 'email'],
            AlertSeverity.HIGH: ['console', 'slack', 'teams', 'email'],
            AlertSeverity.MEDIUM: ['console', 'slack', 'email'],
            AlertSeverity.LOW: ['console', 'email'],
            AlertSeverity.INFO: ['console'],
        }
        
        return severity_config.get(severity, ['console'])


class AlertChannel:
    """Base class for alert channels."""
    
    def send(self, alert: SecurityAlert) -> bool:
        """Send alert through this channel."""
        raise NotImplementedError


class ConsoleAlertChannel(AlertChannel):
    """Console alert channel."""
    
    def send(self, alert: SecurityAlert) -> bool:
        try:
            # Format severity with color
            severity_colors = {
                AlertSeverity.CRITICAL: Fore.RED,
                AlertSeverity.HIGH: Fore.YELLOW,
                AlertSeverity.MEDIUM: Fore.CYAN,
                AlertSeverity.LOW: Fore.GREEN,
                AlertSeverity.INFO: Fore.WHITE,
            }
            
            color = severity_colors.get(alert.severity, Fore.WHITE)
            
            print(f"\n{'='*80}")
            print(f"{color}🚨 ALERT: {alert.title}{Style.RESET_ALL}")
            print(f"{'='*80}")
            print(f"Severity: {color}{alert.severity.value.upper()}{Style.RESET_ALL}")
            print(f"Target: {alert.target}")
            print(f"Time: {alert.timestamp}")
            print(f"Description: {alert.description}")
            
            if alert.recommendations:
                print(f"\nRecommendations:")
                for rec in alert.recommendations:
                    print(f"  • {rec}")
            
            print(f"{'='*80}\n")
            
            return True
            
        except Exception as e:
            logger.error(f"Console alert failed: {e}")
            return False


class EmailAlertChannel(AlertChannel):
    """Email alert channel."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.smtp_server = config.get('smtp_server')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username')
        self.password = config.get('password')
        self.from_addr = config.get('from_addr')
        self.to_addrs = config.get('to_addrs', [])
    
    def send(self, alert: SecurityAlert) -> bool:
        try:
            if not all([self.smtp_server, self.username, self.password, self.from_addr, self.to_addrs]):
                logger.warning("Email configuration incomplete")
                return False
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.title}"
            msg['From'] = self.from_addr
            msg['To'] = ', '.join(self.to_addrs)
            
            # Create HTML content
            html = f"""
            <html>
            <body>
                <h2>Security Alert: {alert.title}</h2>
                <p><strong>Severity:</strong> {alert.severity.value.upper()}</p>
                <p><strong>Target:</strong> {alert.target}</p>
                <p><strong>Time:</strong> {alert.timestamp}</p>
                <p><strong>Description:</strong> {alert.description}</p>
                
                <h3>Recommendations:</h3>
                <ul>
            """
            
            for rec in alert.recommendations:
                html += f"<li>{rec}</li>"
            
            html += """
                </ul>
                
                <hr>
                <p><em>This is an automated alert from the Continuous Security Monitoring System.</em></p>
            </body>
            </html>
            """
            
            # Attach HTML part
            msg.attach(MIMEText(html, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            logger.info(f"Email alert sent for {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
            return False


class SlackAlertChannel(AlertChannel):
    """Slack alert channel."""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send(self, alert: SecurityAlert) -> bool:
        try:
            # Prepare Slack message
            severity_colors = {
                AlertSeverity.CRITICAL: '#ff0000',
                AlertSeverity.HIGH: '#ff9900',
                AlertSeverity.MEDIUM: '#ffcc00',
                AlertSeverity.LOW: '#36a64f',
                AlertSeverity.INFO: '#439fe0',
            }
            
            payload = {
                'attachments': [
                    {
                        'color': severity_colors.get(alert.severity, '#439fe0'),
                        'title': alert.title,
                        'text': alert.description,
                        'fields': [
                            {
                                'title': 'Severity',
                                'value': alert.severity.value.upper(),
                                'short': True,
                            },
                            {
                                'title': 'Target',
                                'value': alert.target,
                                'short': True,
                            },
                            {
                                'title': 'Time',
                                'value': alert.timestamp.isoformat(),
                                'short': True,
                            },
                        ],
                        'footer': 'Security Monitoring System',
                        'ts': alert.timestamp.timestamp(),
                    }
                ]
            }
            
            # Add recommendations if available
            if alert.recommendations:
                payload['attachments'][0]['fields'].append({
                    'title': 'Recommendations',
                    'value': '\n'.join([f'• {r}' for r in alert.recommendations[:3]]),
                    'short': False,
                })
            
            # Send to Slack webhook
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
            return False


class TeamsAlertChannel(AlertChannel):
    """Microsoft Teams alert channel."""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send(self, alert: SecurityAlert) -> bool:
        try:
            # Prepare Teams message card
            card = {
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                'themeColor': self._get_theme_color(alert.severity),
                'title': alert.title,
                'text': alert.description,
                'sections': [
                    {
                        'facts': [
                            {'name': 'Severity', 'value': alert.severity.value.upper()},
                            {'name': 'Target', 'value': alert.target},
                            {'name': 'Time', 'value': alert.timestamp.isoformat()},
                        ]
                    }
                ],
            }
            
            # Add recommendations
            if alert.recommendations:
                card['sections'].append({
                    'title': 'Recommendations',
                    'text': '\n'.join([f'• {r}' for r in alert.recommendations[:3]]),
                })
            
            # Send to Teams webhook
            response = requests.post(
                self.webhook_url,
                json=card,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Teams alert failed: {e}")
            return False
    
    def _get_theme_color(self, severity: AlertSeverity) -> str:
        """Get theme color for Teams card."""
        colors = {
            AlertSeverity.CRITICAL: 'FF0000',
            AlertSeverity.HIGH: 'FF9900',
            AlertSeverity.MEDIUM: 'FFCC00',
            AlertSeverity.LOW: '36A64F',
            AlertSeverity.INFO: '439FE0',
        }
        return colors.get(severity, '439FE0')


class SMSAlertChannel(AlertChannel):
    """SMS alert channel."""
    
    def __init__(self, gateway_config: Dict):
        self.gateway_config = gateway_config
    
    def send(self, alert: SecurityAlert) -> bool:
        # SMS implementation would depend on the gateway
        # This is a placeholder
        logger.info(f"SMS alert prepared for {alert.alert_id}")
        return False


class PagerDutyAlertChannel(AlertChannel):
    """PagerDuty alert channel."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.api_url = 'https://events.pagerduty.com/v2/enqueue'
    
    def send(self, alert: SecurityAlert) -> bool:
        try:
            # Map severity to PagerDuty severity
            severity_map = {
                AlertSeverity.CRITICAL: 'critical',
                AlertSeverity.HIGH: 'error',
                AlertSeverity.MEDIUM: 'warning',
                AlertSeverity.LOW: 'info',
                AlertSeverity.INFO: 'info',
            }
            
            payload = {
                'routing_key': self.api_key,
                'event_action': 'trigger',
                'payload': {
                    'summary': alert.title,
                    'source': alert.source,
                    'severity': severity_map.get(alert.severity, 'info'),
                    'timestamp': alert.timestamp.isoformat(),
                    'custom_details': {
                        'description': alert.description,
                        'target': alert.target,
                        'recommendations': alert.recommendations,
                    },
                },
            }
            
            response = requests.post(
                self.api_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            return response.status_code == 202
            
        except Exception as e:
            logger.error(f"PagerDuty alert failed: {e}")
            return False


class WebhookAlertChannel(AlertChannel):
    """Generic webhook alert channel."""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send(self, alert: SecurityAlert) -> bool:
        try:
            # Convert alert to dict
            alert_dict = asdict(alert)
            
            # Convert datetime to string
            for key, value in alert_dict.items():
                if isinstance(value, datetime):
                    alert_dict[key] = value.isoformat()
                elif isinstance(value, AlertSeverity):
                    alert_dict[key] = value.value
            
            response = requests.post(
                self.webhook_url,
                json=alert_dict,
                timeout=10
            )
            
            return response.status_code in [200, 201, 202]
            
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")
            return False


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Initialize the advanced monitoring platform
    monitor = ContinuousMonitorPro({
        'alerting': {
            'channels': ['console', 'email', 'slack'],
            'email_settings': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': 'security@example.com',
                'password': 'password',
                'from_addr': 'security@example.com',
                'to_addrs': ['admin@example.com'],
            },
            'slack_webhook': 'https://hooks.slack.com/services/XXX/XXX/XXX',
        },
        'scheduling': {
            'max_concurrent_scans': 5,
            'adaptive_scheduling': True,
        },
        'monitoring': {
            'anomaly_detection_enabled': True,
            'trend_analysis_days': 30,
        },
    })
    
    # Start monitoring
    monitor.start_monitoring()
    
    print(f"\n{Fore.GREEN}[*]{Style.RESET_ALL} Continuous Monitoring Platform Started")
    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Features available: {len(monitor.features)}")
    
    # Add some scan jobs
    web_scan_job = monitor.add_scan_job(
        target='https://example.com',
        scan_type='web',
        schedule={'type': 'daily', 'hour': 2, 'minute': 0},
        priority=ScanPriority.MEDIUM,
        config={'scan_depth': 2, 'max_urls': 50},
    )
    
    cloud_scan_job = monitor.add_scan_job(
        target='https://cloud.example.com',
        scan_type='cloud',
        schedule={'type': 'weekly', 'day': 0, 'hour': 3, 'minute': 0},  # Monday 3 AM
        priority=ScanPriority.HIGH,
    )
    
    print(f"\n{Fore.GREEN}[*]{Style.RESET_ALL} Added scan jobs:")
    print(f"  • Web scan: {web_scan_job}")
    print(f"  • Cloud scan: {cloud_scan_job}")
    
    # Run for a while to collect data
    print(f"\n{Fore.YELLOW}[~]{Style.RESET_ALL} Running for 30 seconds to collect data...")
    time.sleep(30)
    
    # Get dashboard
    print(f"\n{Fore.GREEN}[*]{Style.RESET_ALL} Getting security dashboard...")
    dashboard = monitor.get_security_dashboard()
    
    if dashboard['overview']:
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Dashboard Overview:")
        print(f"  Total Scans: {dashboard['overview'].get('total_scans', 0)}")
        print(f"  Success Rate: {dashboard['overview'].get('success_rate', 0):.1f}%")
        print(f"  Avg Risk Score: {dashboard['overview'].get('avg_risk_score', 0):.1f}")
        print(f"  Unresolved Alerts: {dashboard['overview'].get('unresolved_alerts', 0)}")
    
    # Run trend analysis
    print(f"\n{Fore.GREEN}[*]{Style.RESET_ALL} Running trend analysis...")
    trends = monitor.run_trend_analysis('https://example.com', days=30)
    
    print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Trend Analysis:")
    print(f"  Period: {trends.period_days} days")
    print(f"  Risk Trend: {trends.trends.get('risk_score', 'unknown')}")
    
    if trends.recommendations:
        print(f"  Recommendations:")
        for rec in trends.recommendations[:3]:
            print(f"    • {rec}")
    
    # Export report
    print(f"\n{Fore.GREEN}[*]{Style.RESET_ALL} Exporting report...")
    report_path = monitor.export_report(format='json', days=7)
    if report_path:
        print(f"{Fore.CYAN}[+]{Style.RESET_ALL} Report exported to: {report_path}")
    
    # Stop monitoring
    print(f"\n{Fore.GREEN}[*]{Style.RESET_ALL} Stopping monitoring...")
    monitor.stop_monitoring()
    
    print(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} Continuous Monitoring Platform Stopped")