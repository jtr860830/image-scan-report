#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import markdown
from jinja2 import Environment, FileSystemLoader
from weasyprint import CSS, HTML

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"


_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def extract_context(data: dict) -> dict:
    report = data.get("report", {})
    vulnerabilities = sorted(
        report.get("vulnerabilities", []),
        key=lambda v: (_SEVERITY_ORDER.get(v.get("severity"), 3), v.get("name", "")),
    )
    now = datetime.now(timezone.utc)
    return {
        # image metadata
        "registry": report.get("registry", ""),
        "repository": report.get("repository", ""),
        "tag": report.get("tag", ""),
        "image_id": report.get("image_id", ""),
        "base_os": report.get("base_os", ""),
        "digest": report.get("digest", ""),
        "size_mb": round(report.get("size", 0) / 1_048_576, 1),
        "created_at": report.get("created_at", ""),
        "report_date": now.strftime("%Y-%m-%d"),
        "report_datetime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cvedb_version": report.get("cvedb_version", ""),
        "cvedb_create_time": report.get("cvedb_create_time", ""),
        # vulnerabilities (sorted High → Medium → Low)
        "vulnerabilities": vulnerabilities,
        "cve_high": [v for v in vulnerabilities if v.get("severity") == "High"],
        "cve_medium": [v for v in vulnerabilities if v.get("severity") == "Medium"],
        "cve_low": [v for v in vulnerabilities if v.get("severity") == "Low"],
    }


def render_pdf(input_path: str, output_path: str) -> None:
    with open(input_path) as f:
        data = json.load(f)

    ctx = extract_context(data)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    md_content = env.get_template("report.md.j2").render(**ctx)

    html_body = markdown.markdown(md_content, extensions=["tables", "fenced_code"])
    html = f"<html><body>{html_body}</body></html>"

    HTML(string=html).write_pdf(
        output_path,
        stylesheets=[CSS(filename=str(STATIC_DIR / "print.css"))],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", default="/mnt/scan_result.json")
    parser.add_argument("-o", "--output", default="/mnt/report.pdf")
    args = parser.parse_args()
    render_pdf(args.input, args.output)


if __name__ == "__main__":
    main()
