import argparse
import json
import os
from datetime import datetime
from typing import Any, Dict, List

from search_engine_adapter import run_all_search_engines, _sanitize_for_json


def load_settings(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_report(path: str, result: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_sanitize_for_json(result), f, indent=2, ensure_ascii=False)


def write_pdf_report(path: str, result: Dict[str, Any]) -> None:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except Exception:
        return

    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter
    y = height - 40

    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Scan Report")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"Target: {result.get('target', '')}")
    y -= 14
    c.drawString(40, y, f"Risk: {result.get('risk', '')}")
    y -= 14
    c.drawString(40, y, f"Issues: {len(result.get('issues', []))}")
    y -= 20

    for issue in result.get("issues", [])[:50]:
        if y < 80:
            c.showPage()
            y = height - 40
        c.setFont("Helvetica-Bold", 9)
        c.drawString(40, y, f"{issue.get('severity', 'Info')} - {issue.get('title', '')}")
        y -= 12
        c.setFont("Helvetica", 8)
        c.drawString(40, y, f"URL: {issue.get('url', '')}")
        y -= 12
        desc = issue.get("description", "")
        if desc:
            c.drawString(40, y, f"Desc: {desc[:120]}")
            y -= 12

    c.save()


def run_scan(targets: List[str], settings: Dict[str, Any], output_dir: str, pdf: bool) -> None:
    os.makedirs(output_dir, exist_ok=True)
    for target in targets:
        result = run_all_search_engines(
            target_url=target,
            settings=settings,
            headers=None,
            body=None,
            progress_cb=None,
            status_cb=None,
        )
        data = {
            "target": result.target,
            "risk": result.risk,
            "issues": result.issues,
            "duration": result.duration,
            "requests": result.requests,
            "raw": result.raw,
            "generated_at": datetime.now().isoformat(),
        }
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{target.replace('https://', '').replace('http://', '').replace('/', '_')}_{ts}"
        json_path = os.path.join(output_dir, f"{base}.json")
        write_json_report(json_path, data)

        if pdf:
            pdf_path = os.path.join(output_dir, f"{base}.pdf")
            write_pdf_report(pdf_path, data)


def main() -> None:
    parser = argparse.ArgumentParser(description="SmartScanner CLI")
    parser.add_argument("targets", nargs="*", help="Target URLs to scan")
    parser.add_argument("--config", default="settings.json", help="Path to settings JSON")
    parser.add_argument("--output", default="crawl_results", help="Output directory")
    parser.add_argument("--pdf", action="store_true", help="Generate PDF report if reportlab is installed")
    args = parser.parse_args()

    if not args.targets:
        raise SystemExit("No targets provided.")

    settings = load_settings(args.config)
    run_scan(args.targets, settings, args.output, args.pdf)


if __name__ == "__main__":
    main()
