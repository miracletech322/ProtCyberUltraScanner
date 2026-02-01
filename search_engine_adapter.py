"""
Adapter layer between the UI scan workflow (`scanwindow.ScanWorker`) and the
new `SearchEngine` codebase.

Goal: keep the existing UI contract (issue dicts emitted to the tree) while
delegating scanning to SearchEngine implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple


ProgressCb = Callable[[int], None]
StatusCb = Callable[[str], None]


@dataclass
class SearchRunResult:
    """Normalized result returned to the UI layer."""

    target: str
    risk: str
    issues: List[Dict[str, Any]]
    duration: float
    requests: int
    raw: Optional[Dict[str, Any]] = None


def _map_severity(sev: Optional[str]) -> str:
    """Map SearchEngine severities to UI severities."""
    if not sev:
        return "Info"
    s = str(sev).strip().lower()
    if s in {"critical", "high"}:
        return "High"
    if s in {"medium", "med"}:
        return "Medium"
    if s in {"low"}:
        return "Low"
    return "Info"


def _issue_from_finding(finding: Dict[str, Any], fallback_url: str) -> Dict[str, Any]:
    title = finding.get("title") or finding.get("type") or "Finding"
    url = finding.get("url") or finding.get("endpoint") or finding.get("resource_id") or fallback_url
    severity = _map_severity(finding.get("severity"))

    evidence = finding.get("evidence") or finding.get("details") or ""
    description = finding.get("description") or evidence or ""
    remediation = finding.get("remediation") or ""
    if remediation:
        description = f"{description}\n\nRemediation: {remediation}".strip()

    return {
        "title": str(title),
        "severity": severity,
        "url": str(url),
        "description": description,
        "request": "",   # SearchEngine findings typically don't include raw HTTP request
        "response": "",  # SearchEngine findings typically don't include raw HTTP response
        "classification": finding.get("classification", {}),
        "customFields": finding.get("customFields", {}),
        "recommendation": finding.get("recommendation", remediation),
        "references": finding.get("references", []),
        "http": finding.get("http", []),
    }


def _sanitize_for_json(value: Any) -> Any:
    """Convert non-serializable objects into JSON-safe structures."""
    if isinstance(value, dict):
        return {str(k): _sanitize_for_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_json(v) for v in value]
    if isinstance(value, tuple):
        return [_sanitize_for_json(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _scan_result_from_issue(issue: Dict[str, Any]):
    """Convert a UI issue dict into a ScanResult for ML post-processing."""
    from scan_result import ScanResult

    return ScanResult(
        url_tested=issue.get("url", ""),
        vulnerability_type=issue.get("title", ""),
        severity=issue.get("severity", "Info"),
        confidence=0.5,
        evidence=issue.get("description", "") or "",
        response_code=None,
        response_time=None,
        response_size=None,
        response_body=issue.get("response", ""),
        payload_used=None,
        parameter_tested=None,
        error_message=None,
        parameters_tested=[],
    )


def run_searchengine_smartcrawler(
    *,
    target_url: str,
    settings: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """
    Run SearchEngine's SmartCrawlerPro and normalize its output.

    Notes:
    - This is currently the integration path used by the UI.
    - We intentionally keep dependencies minimal (SmartCrawlerPro only needs
      `requests` + `colorama`; Playwright is optional).
    """
    if status_cb:
        status_cb("Initializing SearchEngine (SmartCrawlerPro)...")
    if progress_cb:
        progress_cb(5)

    # Import here so the app can still launch even if other SearchEngine modules
    # have optional dependencies not installed.
    from SearchEngine.AdvancedSmartCrawlerPro import SmartCrawlerPro

    http_settings = settings.get("http", {})
    crawler_settings = settings.get("crawler", {})
    proxy_settings = settings.get("proxy", {})

    proxy = None
    if proxy_settings.get("type") == "http" and proxy_settings.get("ip"):
        proxy_url = f"http://{proxy_settings.get('ip')}:{proxy_settings.get('port', 8080)}"
        if proxy_settings.get("username"):
            proxy_url = (
                f"http://{proxy_settings.get('username')}:{proxy_settings.get('password', '')}"
                f"@{proxy_settings.get('ip')}:{proxy_settings.get('port', 8080)}"
            )
        proxy = proxy_url
    elif proxy_settings.get("type") == "socks" and proxy_settings.get("ip"):
        proxy = f"socks5://{proxy_settings.get('ip')}:{proxy_settings.get('port', 1080)}"

    crawler_config: Dict[str, Any] = {
        "timeout": int(http_settings.get("timeout", 45)),
        "user_agent": http_settings.get("user_agent") or "Mozilla/5.0",
        "threads": int(http_settings.get("parallel", 4)),
        # Map existing crawler settings where possible
        "max_depth": int(crawler_settings.get("max_depth", 5)),
        "max_pages": int(crawler_settings.get("max_count", 500)),
        # Respect verify_ssl default from SearchEngine (False) unless user wants HTTPS-only
        "verify_ssl": False,
        "proxy": proxy,
    }

    if status_cb:
        status_cb("SearchEngine: performing recon + crawl...")
    if progress_cb:
        progress_cb(20)

    crawler = SmartCrawlerPro(crawler_config)

    # SearchEngine doesn't currently accept custom headers/body for the initial request path,
    # so those are not applied yet. We'll add support once we decide the canonical engine API.
    _ = headers, body  # keep signature stable for future improvements

    if progress_cb:
        progress_cb(40)
    if status_cb:
        status_cb("SearchEngine: running vulnerability scan...")

    raw_results = crawler.crawl_with_intelligence(target_url)

    if progress_cb:
        progress_cb(90)
    if status_cb:
        status_cb("SearchEngine: normalizing results...")

    findings = raw_results.get("vulnerability_details") or []
    issues = [_issue_from_finding(f, target_url) for f in findings if isinstance(f, dict)]

    # Add a "Target Information" issue similar to the model report.
    try:
        import ssl
        import socket
        import requests
        from urllib.parse import urlparse

        response = requests.get(target_url, timeout=10, verify=False)
        server_banner = response.headers.get("Server", "")
        cookies = [c.name for c in response.cookies] if response.cookies else []

        https_versions = []
        parsed = urlparse(target_url)
        if parsed.scheme == "https":
            try:
                with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                        if ssock.version():
                            https_versions.append(ssock.version())
            except Exception:
                pass

        api_endpoints = raw_results.get("api_endpoints") or []
        target_issue = {
            "title": "Target Information",
            "severity": "Info",
            "url": target_url.rstrip("/"),
            "description": "High-level target metadata and discovered assets.",
            "customFields": {
                "API Endpoints": api_endpoints,
                "Cookies": cookies,
                "HTTPS": https_versions,
                "Server Banner": [server_banner] if server_banner else [],
                "Services": ["HTTPS"] if parsed.scheme == "https" else [],
            },
            "classification": {},
            "request": "",
            "response": "",
        }
        issues.insert(0, target_issue)
    except Exception:
        pass

    # Add Missing Security Headers issue with affected URLs if available
    try:
        missing_headers = [k for k, v in (raw_results.get("security_headers") or {}).items() if v == "MISSING"]
        affected_urls = raw_results.get("discovered_urls") or []
        if missing_headers:
            issues.append({
                "title": "Missing Security Headers",
                "severity": "Medium",
                "url": target_url,
                "description": f"Missing recommended headers: {', '.join(missing_headers)}",
                "customFields": {
                    "Affected URLs": affected_urls,
                },
                "classification": {
                    "cwe": ["CWE-16"],
                    "owasp": ["OWASP 2021-A5", "OWASP 2017-A6", "OWASP 2013-A5", "OWASP 2010-A6"],
                    "wasc": ["WASC-15"],
                },
                "request": "",
                "response": "",
            })
    except Exception:
        pass

    # Also expose missing-security-headers and similar findings if present
    extra_findings = crawler.security_findings if hasattr(crawler, "security_findings") else []
    for f in extra_findings:
        if isinstance(f, dict):
            issues.append(_issue_from_finding(f, target_url))

    # Risk mapping: UI expects something like "X/5"
    high = sum(1 for i in issues if i.get("severity") == "High")
    medium = sum(1 for i in issues if i.get("severity") == "Medium")
    if high > 0:
        risk = f"{min(5, high + medium)}/5"
    elif medium > 0:
        risk = f"{min(3, medium)}/5"
    else:
        risk = "1/5"

    duration = float(raw_results.get("duration") or 0.0)

    if progress_cb:
        progress_cb(100)
    if status_cb:
        status_cb("SearchEngine scan completed")

    return SearchRunResult(
        target=target_url,
        risk=risk,
        issues=issues,
        duration=duration,
        requests=int(raw_results.get("crawl_stats", {}).get("visited_urls", 0) or 0),
        raw=raw_results,
    )


def run_scanner_engine_blackbox(
    *,
    target_url: str,
    settings: Dict[str, Any],
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Run legacy black-box scanner engine for fuzzing and form testing."""
    if status_cb:
        status_cb("Initializing legacy black-box scanner...")
    if progress_cb:
        progress_cb(5)

    from scanner_engine import run_blackbox_scan

    result = run_blackbox_scan(
        target_url=target_url,
        settings=settings,
        issue_callback=None,
        progress_callback=progress_cb,
        status_callback=status_cb,
    )

    issues = result.get("issues", [])
    duration = float(result.get("duration") or 0.0)
    return SearchRunResult(
        target=target_url,
        risk="1/5" if not issues else "3/5",
        issues=issues,
        duration=duration,
        requests=0,
        raw=result,
    )


def run_searchengine_api_analyzer(
    *,
    target_url: str,
    settings: Dict[str, Any],
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Run SearchEngine's AdvancedAPISecurityAnalyzer and normalize its output."""
    if status_cb:
        status_cb("Initializing SearchEngine (AdvancedAPISecurityAnalyzer)...")
    if progress_cb:
        progress_cb(5)

    try:
        from SearchEngine.AdvancedAPISecurityAnalyzer import AdvancedAPISecurityAnalyzer
    except Exception as e:
        issue = {
            "title": "SearchEngine API Analyzer unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedAPISecurityAnalyzer: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    http_settings = settings.get("http", {})
    timeout = int(http_settings.get("timeout", 30))
    parallel = int(http_settings.get("parallel", 4))

    analyzer = AdvancedAPISecurityAnalyzer(
        max_concurrent_scans=max(1, parallel),
        timeout_seconds=max(5, timeout),
    )

    if status_cb:
        status_cb("SearchEngine: discovering endpoints + testing APIs...")
    if progress_cb:
        progress_cb(20)

    report = analyzer.perform_comprehensive_api_security_scan(target_url)

    if progress_cb:
        progress_cb(90)
    if status_cb:
        status_cb("SearchEngine: normalizing API results...")

    issues: List[Dict[str, Any]] = []
    for tr in getattr(report, "test_results", []) or []:
        try:
            issues.append({
                "title": f"{getattr(tr, 'vulnerability', 'API Issue')}",
                "severity": _map_severity(getattr(tr, "severity", None)),
                "url": getattr(tr, "endpoint", target_url),
                "description": (getattr(tr, "description", "") or "") + (
                    f"\n\nEvidence: {getattr(tr, 'evidence', '')}" if getattr(tr, "evidence", None) else ""
                ) + (
                    f"\n\nRemediation: {getattr(tr, 'remediation', '')}" if getattr(tr, "remediation", None) else ""
                ),
                "request": "",
                "response": "",
            })
        except Exception:
            continue

    # Risk mapping: use report.risk_level if present, otherwise fall back to issues count
    risk = "Unknown"
    try:
        level = str(getattr(report, "risk_level", "") or "").strip()
        if level:
            # Normalize common labels into the UI's 1-5 format
            if level.lower() in {"critical", "high"}:
                risk = "5/5"
            elif level.lower() in {"medium"}:
                risk = "3/5"
            elif level.lower() in {"low"}:
                risk = "2/5"
            else:
                risk = "1/5"
        else:
            risk = "1/5"
    except Exception:
        risk = "Unknown"

    if progress_cb:
        progress_cb(100)
    if status_cb:
        status_cb("SearchEngine API scan completed")

    return SearchRunResult(
        target=target_url,
        risk=risk,
        issues=issues,
        duration=0.0,
        requests=int(getattr(report, "endpoints_tested", 0) or 0),
        raw={"report": getattr(report, "__dict__", {})},
    )


def run_searchengine_js_analyzer(
    *,
    target_url: str,
    settings: Dict[str, Any],
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Run SearchEngine's AdvancedJavaScriptAnalyzer and normalize its output."""
    if status_cb:
        status_cb("Initializing SearchEngine (AdvancedJavaScriptAnalyzer)...")
    if progress_cb:
        progress_cb(5)

    try:
        from SearchEngine.AdvancedJavaScriptAnalyzer import AdvancedJavaScriptAnalyzer
    except Exception as e:
        issue = {
            "title": "JavaScript analyzer unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedJavaScriptAnalyzer: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    analyzer = AdvancedJavaScriptAnalyzer()
    results = analyzer.crawl_and_analyze(target_url)

    issues: List[Dict[str, Any]] = []
    if results.get("error"):
        issues.append({
            "title": "JavaScript analysis error",
            "severity": "Medium",
            "url": target_url,
            "description": results.get("error", ""),
            "request": "",
            "response": "",
        })
    else:
        for file_result in results.get("external_files", []):
            analysis = file_result.get("analysis", {})
            secrets = analysis.get("secrets", [])
            endpoints = analysis.get("endpoints", [])
            risk_score = analysis.get("risk_score", 0)

            if secrets:
                issues.append({
                    "title": "Potential Secrets in JavaScript",
                    "severity": "High" if risk_score >= 70 else "Medium",
                    "url": file_result.get("url", target_url),
                    "description": f"Secrets found: {len(secrets)}",
                    "request": "",
                    "response": "",
                })
            if endpoints:
                issues.append({
                    "title": "JavaScript Discovered Endpoints",
                    "severity": "Info",
                    "url": file_result.get("url", target_url),
                    "description": f"Endpoints found: {len(endpoints)}",
                    "request": "",
                    "response": "",
                })

    return SearchRunResult(
        target=target_url,
        risk="1/5" if not issues else "2/5",
        issues=issues,
        duration=0.0,
        requests=len(results.get("external_files", [])),
        raw=results,
    )


def run_searchengine_auth_analyzer(
    *,
    target_url: str,
    settings: Dict[str, Any],
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Run SearchEngine's AdvancedAuthSessionAnalyzer and normalize its output."""
    if status_cb:
        status_cb("Initializing SearchEngine (AdvancedAuthSessionAnalyzer)...")
    if progress_cb:
        progress_cb(5)

    try:
        from SearchEngine.AdvancedAuthSessionAnalyzer import AdvancedAuthSessionAnalyzer, AuthCredentials
    except Exception as e:
        issue = {
            "title": "Auth/session analyzer unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedAuthSessionAnalyzer: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    auth_settings = settings.get("authentication", {})
    credentials = AuthCredentials(
        username=auth_settings.get("username", ""),
        password=auth_settings.get("password", ""),
        session_data={},
    )

    analyzer = AdvancedAuthSessionAnalyzer(headless_browser=True, enable_brute_force_simulation=False)
    results = analyzer.perform_comprehensive_auth_test(target_url, credentials)

    issues: List[Dict[str, Any]] = []
    for vuln in results.get("vulnerabilities", []):
        issues.append(_issue_from_finding(vuln, target_url))

    if not issues and results.get("error"):
        issues.append({
            "title": "Auth test error",
            "severity": "Medium",
            "url": target_url,
            "description": results.get("error", ""),
            "request": "",
            "response": "",
        })

    return SearchRunResult(
        target=target_url,
        risk="1/5" if not issues else "3/5",
        issues=issues,
        duration=0.0,
        requests=0,
        raw=results,
    )


def run_searchengine_subdomain_discovery(
    *,
    target_url: str,
    settings: Dict[str, Any],
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Run SearchEngine's AdvancedSubdomainHunter and normalize its output."""
    if status_cb:
        status_cb("Initializing SearchEngine (AdvancedSubdomainHunter)...")
    if progress_cb:
        progress_cb(5)

    try:
        import asyncio
        from urllib.parse import urlparse
        from SearchEngine.AdvancedSubDomainDiscovery import AdvancedSubdomainHunter
    except Exception as e:
        issue = {
            "title": "Subdomain discovery unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedSubdomainHunter: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    parsed = urlparse(target_url)
    domain = parsed.hostname or parsed.path

    hunter = AdvancedSubdomainHunter(max_concurrent=50, enable_passive=True, enable_active=True, enable_ml=False)
    results = asyncio.run(hunter.enumerate_subdomains(domain=domain, techniques=None, max_subdomains=500, enable_scan=True))

    issues: List[Dict[str, Any]] = []
    for vuln in results.vulnerabilities:
        issues.append(_issue_from_finding(vuln, domain))

    # Add takeover findings from subdomain records
    for subdomain, record in results.subdomains.items():
        if getattr(record, "takeover_vulnerable", False):
            issues.append({
                "title": "Potential Subdomain Takeover",
                "severity": "High",
                "url": f"https://{subdomain}",
                "description": f"Service: {record.takeover_service or 'unknown'}",
                "request": "",
                "response": "",
            })

    return SearchRunResult(
        target=domain,
        risk="1/5" if not issues else "3/5",
        issues=issues,
        duration=float(results.statistics.get("enumeration_time", 0) or 0),
        requests=int(results.statistics.get("total_subdomains", 0) or 0),
        raw={"statistics": results.statistics},
    )


def run_searchengine_infrastructure_intel(
    *,
    target_url: str,
    settings: Dict[str, Any],
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Run SearchEngine's AdvancedInfrastructureDetector and normalize its output."""
    if status_cb:
        status_cb("Initializing SearchEngine (Infrastructure Intelligence)...")
    if progress_cb:
        progress_cb(5)

    try:
        from SearchEngine.AdvancedInfrastructureIntelligenceEngine import AdvancedInfrastructureDetector
    except Exception as e:
        issue = {
            "title": "Infrastructure intelligence unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedInfrastructureDetector: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    detector = AdvancedInfrastructureDetector({})
    report = detector.perform_comprehensive_infrastructure_analysis(target_url)
    vulnerabilities = report.get("vulnerabilities", [])

    issues = [_issue_from_finding(v, target_url) for v in vulnerabilities if isinstance(v, dict)]

    return SearchRunResult(
        target=target_url,
        risk="1/5" if not issues else "3/5",
        issues=issues,
        duration=0.0,
        requests=0,
        raw=report,
    )


def run_searchengine_evasion_framework(
    *,
    target_url: str,
    settings: Dict[str, Any],
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Run SearchEngine's AdvancedEvasionFramework WAF analysis."""
    if status_cb:
        status_cb("Initializing SearchEngine (Evasion Framework)...")
    if progress_cb:
        progress_cb(5)

    try:
        from SearchEngine.AdvancedEvasionFramework import analyze_waf_behavior
    except Exception as e:
        issue = {
            "title": "Evasion framework unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedEvasionFramework: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    results = analyze_waf_behavior(target_url, max_requests=30)
    issues = [{
        "title": "WAF Behavior Analysis",
        "severity": "Info" if results.get("waf_detected") else "Medium",
        "url": target_url,
        "description": f"Detected: {results.get('waf_name') or 'None'}\n"
                       f"Blocks: {len(results.get('block_patterns', []))}",
        "request": "",
        "response": "",
    }]

    return SearchRunResult(
        target=target_url,
        risk="1/5",
        issues=issues,
        duration=0.0,
        requests=len(results.get("block_patterns", [])),
        raw=results,
    )


def run_searchengine_false_positive_detector(
    *,
    target_url: str,
    issues: List[Dict[str, Any]],
) -> SearchRunResult:
    """Run AdvancedFalsePositiveDetector on existing issues."""
    try:
        from SearchEngine.AdvancedFalsePositiveDetector import AdvancedFalsePositiveDetector
    except Exception as e:
        issue = {
            "title": "False positive detector unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedFalsePositiveDetector: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    detector = AdvancedFalsePositiveDetector(enable_xai=False, use_ensemble=False)
    fp_issues: List[Dict[str, Any]] = []

    for issue in issues:
        result = detector.predict_with_explanation(_scan_result_from_issue(issue))
        fp_issues.append({
            "title": "False Positive Analysis",
            "severity": "Info",
            "url": issue.get("url", target_url),
            "description": f"Prediction: {result.get('prediction')} (confidence: {result.get('confidence', 0):.2f})",
            "request": "",
            "response": "",
        })

    return SearchRunResult(target=target_url, risk="1/5", issues=fp_issues, duration=0.0, requests=len(fp_issues), raw=None)


def run_searchengine_ml_false_positive_detector(
    *,
    target_url: str,
    issues: List[Dict[str, Any]],
) -> SearchRunResult:
    """Run AdvancedMLFalsePositiveDetection on existing issues."""
    try:
        from SearchEngine.AdvancedMLFalsePositiveDetection import AdvancedFalsePositiveDetector
    except Exception as e:
        issue = {
            "title": "ML false positive detector unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedMLFalsePositiveDetection: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    detector = AdvancedFalsePositiveDetector(enable_shap=False)
    scan_results = [_scan_result_from_issue(i) for i in issues]
    predictions = detector.batch_predict_with_explanations(scan_results)

    ml_issues = [{
        "title": "ML False Positive Analysis",
        "severity": "Info",
        "url": pred.get("url", target_url) if isinstance(pred, dict) else target_url,
        "description": f"Prediction: {pred.get('prediction')} (confidence: {pred.get('confidence', 0):.2f})",
        "request": "",
        "response": "",
    } for pred in predictions if isinstance(pred, dict)]

    return SearchRunResult(target=target_url, risk="1/5", issues=ml_issues, duration=0.0, requests=len(ml_issues), raw=None)


def run_searchengine_analytics(
    *,
    target_url: str,
    issues: List[Dict[str, Any]],
) -> SearchRunResult:
    """Run AdvancedAnalyticsEngine on existing issues."""
    try:
        from SearchEngine.AdvancedAnalyticsEngine import AdvancedAnalyticsEngine
    except Exception as e:
        issue = {
            "title": "Analytics engine unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedAnalyticsEngine: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    class Vulnerability:
        def __init__(self, idx: int, issue: Dict[str, Any]):
            self.vulnerability_id = f"UI-{idx}"
            self.name = issue.get("title", "")
            self.severity = issue.get("severity", "Info")
            self.category = "Generic"
            self.cvss_score = 5.0
            self.confidence = 0.5
            self.evidence = issue.get("description", "")
            self.status = "confirmed"
            self.url_tested = issue.get("url", target_url)

    vulnerabilities = [Vulnerability(i, issue) for i, issue in enumerate(issues)]
    engine = AdvancedAnalyticsEngine()
    report = engine.perform_comprehensive_compliance_analysis(vulnerabilities)

    issues_out = [{
        "title": "Compliance Analysis",
        "severity": "Info",
        "url": target_url,
        "description": f"Overall compliance score: {report.get('overall_compliance_score', 0):.2f}",
        "request": "",
        "response": "",
    }]

    return SearchRunResult(target=target_url, risk="1/5", issues=issues_out, duration=0.0, requests=0, raw=report)


def run_searchengine_performance_optimizer(
    *,
    target_url: str,
    settings: Dict[str, Any],
) -> SearchRunResult:
    """Run AdvancedPerformanceOptimizer diagnostics."""
    try:
        from SearchEngine.AdvancedPerformanceOptimizer import AdvancedPerformanceOptimizer, optimize_for_throughput
    except Exception as e:
        issue = {
            "title": "Performance optimizer unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import AdvancedPerformanceOptimizer: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    optimizer = AdvancedPerformanceOptimizer()
    optimizer.optimize_memory(aggressive=False)
    stats = optimizer.get_performance_stats()
    recommended_connections = optimize_for_throughput(
        target_rps=stats.get("throughput", {}).get("current_rps", 10),
        current_rps=stats.get("throughput", {}).get("current_rps", 10),
        current_connections=stats.get("connections", {}).get("active", 10),
    )

    issues = [{
        "title": "Performance Optimization",
        "severity": "Info",
        "url": target_url,
        "description": f"Recommended connections: {recommended_connections}",
        "request": "",
        "response": "",
    }]

    return SearchRunResult(target=target_url, risk="1/5", issues=issues, duration=0.0, requests=0, raw=stats)


def run_searchengine_continuous_monitor(
    *,
    target_url: str,
    settings: Dict[str, Any],
) -> SearchRunResult:
    """Run ContinuousMonitorPro trend analysis (non-blocking)."""
    try:
        from SearchEngine.ContinuousMonitorPro import ContinuousMonitorPro
    except Exception as e:
        issue = {
            "title": "Continuous monitor unavailable",
            "severity": "High",
            "url": target_url,
            "description": f"Failed to import ContinuousMonitorPro: {e}",
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    monitor = ContinuousMonitorPro()
    trend = monitor.run_trend_analysis(target_url, days=30)

    issues = [{
        "title": "Trend Analysis",
        "severity": "Info",
        "url": target_url,
        "description": f"Risk trend: {trend.get('risk_trend', 'unknown')}",
        "request": "",
        "response": "",
    }]

    return SearchRunResult(target=target_url, risk="1/5", issues=issues, duration=0.0, requests=0, raw=trend)


def run_searchengine_cloud_scanner(
    *,
    target_url: str,
    settings: Dict[str, Any],
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Run SearchEngine's CloudSecurityScannerPro (best-effort; heavy optional deps)."""
    if status_cb:
        status_cb("Initializing SearchEngine (CloudSecurityScannerPro)...")
    if progress_cb:
        progress_cb(5)

    try:
        from SearchEngine.CloudSecurityScannerPro import CloudSecurityScannerPro
    except Exception as e:
        issue = {
            "title": "Cloud scanner unavailable",
            "severity": "High",
            "url": target_url,
            "description": (
                "CloudSecurityScannerPro has additional dependencies (e.g. boto3, dnspython, pyOpenSSL).\n"
                f"Import failed: {e}"
            ),
            "request": "",
            "response": "",
        }
        return SearchRunResult(target=target_url, risk="Unknown", issues=[issue], duration=0.0, requests=0, raw=None)

    http_settings = settings.get("http", {})
    timeout = int(http_settings.get("timeout", 20))

    scanner = CloudSecurityScannerPro({
        "timeout": max(5, timeout),
        "max_threads": int(http_settings.get("parallel", 4)),
        "enable_api_scanning": False,
    })

    if progress_cb:
        progress_cb(20)
    if status_cb:
        status_cb("SearchEngine: running cloud scan...")

    raw = scanner.comprehensive_cloud_scan(target_url)

    if progress_cb:
        progress_cb(90)
    if status_cb:
        status_cb("SearchEngine: normalizing cloud results...")

    findings = (raw.get("security_assessment", {}) or {}).get("findings") or []
    issues = [_issue_from_finding(f, target_url) for f in findings if isinstance(f, dict)]

    risk = "Unknown"
    try:
        score = int((raw.get("security_assessment", {}) or {}).get("risk_score") or 0)
        if score >= 80:
            risk = "5/5"
        elif score >= 50:
            risk = "4/5"
        elif score >= 25:
            risk = "3/5"
        elif score > 0:
            risk = "2/5"
        else:
            risk = "1/5"
    except Exception:
        risk = "Unknown"

    if progress_cb:
        progress_cb(100)
    if status_cb:
        status_cb("SearchEngine cloud scan completed")

    return SearchRunResult(
        target=target_url,
        risk=risk,
        issues=issues,
        duration=float(raw.get("scan_duration_seconds") or 0.0),
        requests=int((raw.get("statistics", {}) or {}).get("security_checks_performed") or 0),
        raw=raw,
    )


def run_selected_search_engine(
    *,
    engine: str,
    target_url: str,
    settings: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Dispatch to the selected engine (Option B)."""
    key = (engine or "").strip().lower()
    if key in {"api", "api_analyzer", "advancedapi"}:
        return run_searchengine_api_analyzer(
            target_url=target_url,
            settings=settings,
            progress_cb=progress_cb,
            status_cb=status_cb,
        )
    if key in {"cloud", "cloud_scanner"}:
        return run_searchengine_cloud_scanner(
            target_url=target_url,
            settings=settings,
            progress_cb=progress_cb,
            status_cb=status_cb,
        )
    return run_searchengine_smartcrawler(
        target_url=target_url,
        settings=settings,
        headers=headers,
        body=body,
        progress_cb=progress_cb,
        status_cb=status_cb,
    )


def run_all_search_engines(
    *,
    target_url: str,
    settings: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    progress_cb: Optional[ProgressCb] = None,
    status_cb: Optional[StatusCb] = None,
) -> SearchRunResult:
    """Execute all SearchEngine modules sequentially in priority order."""
    engines: List[Tuple[str, Callable[[], SearchRunResult]]] = [
        ("SmartCrawlerPro", lambda: run_searchengine_smartcrawler(
            target_url=target_url,
            settings=settings,
            headers=headers,
            body=body,
            progress_cb=None,
            status_cb=None,
        )),
        ("LegacyBlackBoxScanner", lambda: run_scanner_engine_blackbox(
            target_url=target_url,
            settings=settings,
            progress_cb=None,
            status_cb=None,
        )),
        ("AdvancedJavaScriptAnalyzer", lambda: run_searchengine_js_analyzer(
            target_url=target_url,
            settings=settings,
        )),
        ("AdvancedAPISecurityAnalyzer", lambda: run_searchengine_api_analyzer(
            target_url=target_url,
            settings=settings,
        )),
        ("AdvancedAuthSessionAnalyzer", lambda: run_searchengine_auth_analyzer(
            target_url=target_url,
            settings=settings,
        )),
        ("AdvancedSubdomainDiscovery", lambda: run_searchengine_subdomain_discovery(
            target_url=target_url,
            settings=settings,
        )),
        ("AdvancedInfrastructureIntelligence", lambda: run_searchengine_infrastructure_intel(
            target_url=target_url,
            settings=settings,
        )),
        ("AdvancedEvasionFramework", lambda: run_searchengine_evasion_framework(
            target_url=target_url,
            settings=settings,
        )),
        ("CloudSecurityScannerPro", lambda: run_searchengine_cloud_scanner(
            target_url=target_url,
            settings=settings,
        )),
        ("AdvancedFalsePositiveDetector", None),  # post-processing
        ("AdvancedMLFalsePositiveDetection", None),  # post-processing
        ("AdvancedAnalyticsEngine", None),  # post-processing
        ("AdvancedPerformanceOptimizer", lambda: run_searchengine_performance_optimizer(
            target_url=target_url,
            settings=settings,
        )),
        ("ContinuousMonitorPro", lambda: run_searchengine_continuous_monitor(
            target_url=target_url,
            settings=settings,
        )),
    ]

    all_issues: List[Dict[str, Any]] = []
    raw_engines: Dict[str, Any] = {}
    total_duration = 0.0
    total_requests = 0

    total = len(engines)
    for idx, (name, runner) in enumerate(engines, start=1):
        if status_cb:
            status_cb(f"Running {name} ({idx}/{total})...")
        if progress_cb:
            progress_cb(int((idx - 1) / total * 100))

        if runner:
            try:
                result = runner()
                raw_engines[name] = result.raw
                all_issues.extend(result.issues)
                total_duration += float(result.duration or 0.0)
                total_requests += int(result.requests or 0)
            except Exception as e:
                raw_engines[name] = {"error": str(e)}
                all_issues.append({
                    "title": f"{name} execution error",
                    "severity": "Medium",
                    "url": target_url,
                    "description": f"{name} failed: {e}",
                    "request": "",
                    "response": "",
                })
        else:
            # Deferred steps (false-positive + analytics)
            if name == "AdvancedFalsePositiveDetector":
                try:
                    result = run_searchengine_false_positive_detector(
                        target_url=target_url,
                        issues=all_issues,
                    )
                    raw_engines[name] = result.raw
                    all_issues.extend(result.issues)
                    total_duration += float(result.duration or 0.0)
                    total_requests += int(result.requests or 0)
                except Exception as e:
                    raw_engines[name] = {"error": str(e)}
                    all_issues.append({
                        "title": f"{name} execution error",
                        "severity": "Medium",
                        "url": target_url,
                        "description": f"{name} failed: {e}",
                        "request": "",
                        "response": "",
                    })
            elif name == "AdvancedMLFalsePositiveDetection":
                try:
                    result = run_searchengine_ml_false_positive_detector(
                        target_url=target_url,
                        issues=all_issues,
                    )
                    raw_engines[name] = result.raw
                    all_issues.extend(result.issues)
                    total_duration += float(result.duration or 0.0)
                    total_requests += int(result.requests or 0)
                except Exception as e:
                    raw_engines[name] = {"error": str(e)}
                    all_issues.append({
                        "title": f"{name} execution error",
                        "severity": "Medium",
                        "url": target_url,
                        "description": f"{name} failed: {e}",
                        "request": "",
                        "response": "",
                    })
            elif name == "AdvancedAnalyticsEngine":
                try:
                    result = run_searchengine_analytics(
                        target_url=target_url,
                        issues=all_issues,
                    )
                    raw_engines[name] = result.raw
                    all_issues.extend(result.issues)
                    total_duration += float(result.duration or 0.0)
                    total_requests += int(result.requests or 0)
                except Exception as e:
                    raw_engines[name] = {"error": str(e)}
                    all_issues.append({
                        "title": f"{name} execution error",
                        "severity": "Medium",
                        "url": target_url,
                        "description": f"{name} failed: {e}",
                        "request": "",
                        "response": "",
                    })

    if progress_cb:
        progress_cb(100)
    if status_cb:
        status_cb("All SearchEngine modules completed")

    # Risk mapping: reuse the existing scoring logic
    high = sum(1 for i in all_issues if i.get("severity") == "High")
    medium = sum(1 for i in all_issues if i.get("severity") == "Medium")
    if high > 0:
        risk = f"{min(5, high + medium)}/5"
    elif medium > 0:
        risk = f"{min(3, medium)}/5"
    else:
        risk = "1/5"

    return SearchRunResult(
        target=target_url,
        risk=risk,
        issues=all_issues,
        duration=total_duration,
        requests=total_requests,
        raw={"engines": _sanitize_for_json(raw_engines)},
    )

