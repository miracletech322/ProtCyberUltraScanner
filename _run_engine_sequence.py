import json
import sys
from search_engine_adapter import (
    run_searchengine_smartcrawler,
    run_searchengine_js_analyzer,
    run_searchengine_api_analyzer,
    run_searchengine_auth_analyzer,
    run_searchengine_subdomain_discovery,
    run_searchengine_infrastructure_intel,
    run_searchengine_evasion_framework,
    run_searchengine_cloud_scanner,
    run_searchengine_false_positive_detector,
    run_searchengine_ml_false_positive_detector,
    run_searchengine_analytics,
    run_searchengine_performance_optimizer,
    run_searchengine_continuous_monitor,
)

TARGET_URL = "https://www.transavia.com/"
SETTINGS = {
    "http": {"timeout": 20, "parallel": 1, "user_agent": "Mozilla/5.0"},
    "crawler": {"max_depth": 1, "max_count": 10},
    "proxy": {"type": "none"},
}

results = {
    "target_url": TARGET_URL,
    "engines": [],
}

issues = []


def run_step(name, fn):
    print(f"=== Running {name} ===")
    res = fn()
    issues.extend(res.issues or [])
    results["engines"].append({
        "name": name,
        "issues": len(res.issues or []),
        "requests": res.requests,
        "duration": res.duration,
        "error": None,
    })
    print(f"{name} OK: {len(res.issues or [])} issues")


try:
    run_step("SmartCrawlerPro", lambda: run_searchengine_smartcrawler(
        target_url=TARGET_URL,
        settings=SETTINGS,
        headers=None,
        body=None,
        progress_cb=None,
        status_cb=None,
    ))

    run_step("AdvancedJavaScriptAnalyzer", lambda: run_searchengine_js_analyzer(
        target_url=TARGET_URL,
        settings=SETTINGS,
    ))

    run_step("AdvancedAPISecurityAnalyzer", lambda: run_searchengine_api_analyzer(
        target_url=TARGET_URL,
        settings=SETTINGS,
    ))

    run_step("AdvancedAuthSessionAnalyzer", lambda: run_searchengine_auth_analyzer(
        target_url=TARGET_URL,
        settings=SETTINGS,
    ))

    run_step("AdvancedSubdomainDiscovery", lambda: run_searchengine_subdomain_discovery(
        target_url=TARGET_URL,
        settings=SETTINGS,
    ))

    run_step("AdvancedInfrastructureIntelligence", lambda: run_searchengine_infrastructure_intel(
        target_url=TARGET_URL,
        settings=SETTINGS,
    ))

    run_step("AdvancedEvasionFramework", lambda: run_searchengine_evasion_framework(
        target_url=TARGET_URL,
        settings=SETTINGS,
    ))

    run_step("CloudSecurityScannerPro", lambda: run_searchengine_cloud_scanner(
        target_url=TARGET_URL,
        settings=SETTINGS,
    ))

    run_step("AdvancedFalsePositiveDetector", lambda: run_searchengine_false_positive_detector(
        target_url=TARGET_URL,
        issues=issues,
    ))

    run_step("AdvancedMLFalsePositiveDetection", lambda: run_searchengine_ml_false_positive_detector(
        target_url=TARGET_URL,
        issues=issues,
    ))

    run_step("AdvancedAnalyticsEngine", lambda: run_searchengine_analytics(
        target_url=TARGET_URL,
        issues=issues,
    ))

    run_step("AdvancedPerformanceOptimizer", lambda: run_searchengine_performance_optimizer(
        target_url=TARGET_URL,
        settings=SETTINGS,
    ))

    run_step("ContinuousMonitorPro", lambda: run_searchengine_continuous_monitor(
        target_url=TARGET_URL,
        settings=SETTINGS,
    ))

except Exception as exc:
    error_name = results["engines"][-1]["name"] if results["engines"] else "(startup)"
    print(f"ERROR in {error_name}: {exc}")
    results["error"] = f"{error_name}: {exc}"
    with open("_engine_sequence.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    raise

with open("_engine_sequence.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("All engines completed")
